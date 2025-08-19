from abc import abstractmethod, ABC, abstractproperty
from random import Random, SystemRandom
from typing import override

from tls13_spec import CipherSuite
from tls_crypto import get_hash_alg, get_cipher_alg, derive_secret, hkdf_expand_label


class TrustedParty(ABC):
    _computed: bool = False
    _csuite: CipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256

    @abstractproperty
    def verifier_output(self): ...

    @abstractproperty
    def prover_output(self): ...

    @abstractmethod
    def compute(self) -> None: ...

class HandshakeSecretTrustedParty(TrustedParty):
    verifier_input: list[bytes]|None = None
    prover_input: tuple[int, bytes]|None = None
    _verifier_output: None = None
    _prover_output: tuple[list[bytes], bytes, bytes] # ([dummy master secrets], CHTS, SHTS)

    @override
    def compute(self) -> None:
        if not self.verifier_input or not self.prover_input:
            raise AttributeError('missing inputs')

        index, hash_val = self.prover_input
        real_hs_secret = self.verifier_input[index]

        hash_alg = get_hash_alg(self._csuite)
        chts = derive_secret(hash_alg, real_hs_secret, b'c hs traffic', hash_val)
        shts = derive_secret(hash_alg, real_hs_secret, b's hs traffic', hash_val)

        redacted_secs = [sec if i!=index else b'\x00'*32 for (i, sec) in enumerate(self.verifier_input)]
        self._prover_output = (redacted_secs, chts, shts)

        self._computed = True

    @override
    @property
    def verifier_output(self) -> None:
        if not self._computed:
            raise AttributeError('need to run compute first')
        return self._verifier_output

    @override
    @property
    def prover_output(self) -> tuple[list[bytes], bytes, bytes]:
        if not self._computed:
            raise AttributeError('need to run compute first')
        return self._prover_output

class MasterSecretTrustedParty(TrustedParty):
    verifier_input: list[bytes]|None = None
    prover_input: tuple[int, bytes]|None = None
    # verifier outputs of form (client key share, client iv, server key share, server key iv, commit(P's c key share), commit(P's s key share))
    _verifier_output: tuple[bytes, bytes, bytes, bytes, bytes, bytes]
    # prover outputs of form ([dummy secrets], client key share, client iv, server key share, server iv)
    _prover_output: tuple[list[bytes], bytes, bytes, bytes, bytes]
    rgen: Random|None = None


    @override
    def compute(self) -> None:
        if not self.verifier_input or not self.prover_input:
            raise AttributeError('missing inputs')

        index, hash_val = self.prover_input
        real_secret = self.verifier_input[index]

        hash_alg = get_hash_alg(self._csuite)
        cipher = get_cipher_alg(self._csuite)

        cats = derive_secret(hash_alg, real_secret, b'c ap traffic', hash_val)
        ckey = hkdf_expand_label(hash_alg, cats, b'key', b'', cipher.key_length)
        civ = hkdf_expand_label(hash_alg, cats, b'iv', b'', cipher.iv_length)

        sats = derive_secret(hash_alg, real_secret, b's ap traffic', hash_val)
        skey = hkdf_expand_label(hash_alg, sats, b'key', b'', cipher.key_length)
        siv = hkdf_expand_label(hash_alg, sats, b'iv', b'', cipher.iv_length)

        if self.rgen is None:
            self.rgen = SystemRandom()

        # secret share the keys
        v_ckey_share = self.rgen.randbytes(cipher.key_length)
        v_skey_share = self.rgen.randbytes(cipher.key_length)
        p_ckey_share = bytes(a ^ b for a, b in zip(ckey, v_ckey_share))
        p_skey_share = bytes(a ^ b for a, b in zip(skey, v_skey_share))

        # TODO: add commitment
        v_skey_commit = b'\x00'*32
        v_ckey_commit = b'\x00'*32

        redacted_msecs = [sec if i!=index else b'\x00'*32 for (i, sec) in enumerate(self.verifier_input)]

        self._prover_output = (redacted_msecs, p_ckey_share, civ, p_skey_share, siv)
        self._verifier_output = (v_ckey_share, civ, v_skey_share, siv, v_skey_commit, v_ckey_commit)
        self._computed = True

    @override
    @property
    def verifier_output(self) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
        if not self._computed:
            raise AttributeError('need to run compute first')
        return self._verifier_output

    @override
    @property
    def prover_output(self) -> tuple[list[bytes], bytes, bytes, bytes, bytes]:
        if not self._computed:
            raise AttributeError('need to run compute first')
        return self._prover_output

class EncryptionTrustedParty(TrustedParty):
    verifier_input: bytes # key share
    prover_input: tuple[bytes, bytes] # (key share, plaintext)
    public_input: tuple[bytes, bytes] # IV, additional data
    _verifier_output: None
    _prover_output: bytes # ciphertext

    @override
    def compute(self) -> None:
        iv, adata = self.public_input
        p_key_share, ptext = self.prover_input
        cipher = get_cipher_alg(self._csuite)
        assert len(self.verifier_input) == len(p_key_share) == cipher.key_length
        assert len(iv) == cipher.iv_length

        key = bytes(a ^ b for a, b in zip(self.verifier_input, p_key_share))

        # assumes counter is zero. This might be wrong...
        ctext = cipher.encrypt(key, iv, ptext, adata)

        self._prover_output = ctext
        self._computed = True

    @override
    @property
    def verifier_output(self) -> None:
        if not self._computed:
            raise AttributeError('need to run compute first')
        return self._verifier_output

    @override
    @property
    def prover_output(self) -> bytes:
        if not self._computed:
            raise AttributeError('need to run compute first')
        return self._prover_output