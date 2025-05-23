"""Cryptographic algorithms and primitives used for TLS.

Includes ciphers, hashes, KDF, key exchange, and signatures,
as well as X509 certificate generation.

Most of these are actually implemented by the python cryptography library;
this module just provides the "glue code" to give a consistent interface
for how they are used in TLS.
"""

from datetime import timedelta, datetime
from collections import namedtuple
from random import Random
from secrets import SystemRandom

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, SECP384R1, SECP521R1
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
import pyhpke

from tls_common import *
from spec import Struct, Bounded, Raw, kwdict, Sequence
from tls13_spec import (
    NamedGroup,
    SignatureScheme,
    CipherSuite,
    HkdfLabel,
    HpkeKemId,
    HpkeKdfId,
    HpkeAeadId,
    ECHConfig,
)

#TODO this should go away, just experimenting...
from dataclasses import is_dataclass, fields
def to_json(x):
    if isinstance(x, (int, float, str)):
        return x
    if isinstance(x, bytes):
        return x.hex()
    if is_dataclass(x):
        d = {}
        for fld in fields(x):
            d[fld.name] = to_json(getattr(x, fld.name))
        return d
    if isinstance(x, Mapping):
        d = {}
        for k,v in x.items():
            if not isinstance(k, str):
                raise ValueError(f'json dict keys must be strings; got "{k}"')
            d[k] = to_json(v)
        return d
    if isinstance(x, Iterable):
        return [to_json(y) for y in x]
    raise ValueError(f'could not convert to json: "{x}"')
def from_json(o,cls=Any):
    if issubclass(cls, (int, float, str)):
        return cls(o)
    if issubclass(cls, bytes):
        return bytes.fromhex(o)
    if is_dataclass(cls):
        d = {}
        for fld in fields(cls):
            d[fld.name] = from_json(o[fld.name], fld.type)
        return cls(**d)
    return o

CertSecrets = Struct(
    sig_alg = SignatureScheme,
    private_key = Bounded(4, Raw),
    cert_der = Bounded(4, Raw),
)

EchSecrets = Struct(
    config = ECHConfig,
    private_key = Bounded(4, Raw),
)

ServerSecrets = Struct(
    cert = CertSecrets,
    eches = Bounded(4, Sequence(EchSecrets)),
)

class _XKex:
    """Key exchange support in X* groups using python cryptography module."""
    def __init__(self, PrivateKey, PublicKey, genlen):
        self._get_private = PrivateKey.from_private_bytes
        self._get_public = PublicKey.from_public_bytes
        self._genlen = genlen

    def gen_private(self, rgen):
        return self._get_private(rgen.randbytes(self._genlen)).private_bytes_raw()

    def get_public(self, private):
        return self._get_private(private).public_key().public_bytes_raw()

    def exchange(self, private, public):
        return self._get_private(private).exchange(self._get_public(public))


def get_kex_alg(group):
    """Given a NamedGroup, returns an object to do key exchange.
    The returned object kex will have:
        kex.gen_private(rgen) -> private
        kex.get_public(private) -> public
        kex.exchange(private, public) -> shared_secret
    """
    match group:
        case NamedGroup.X25519:
            return _XKex(X25519PrivateKey, X25519PublicKey, 32)
        case NamedGroup.X448:
            return _XKex(X448PrivateKey, X448PublicKey, 56)
        case _:
            raise ValueError(f"no implementation for key exchange in {group}")


DEFAULT_KEX_GROUPS = (
    NamedGroup.X25519,
    NamedGroup.SECP256R1,
    NamedGroup.X448,
    NamedGroup.SECP521R1,
    NamedGroup.SECP384R1,
    NamedGroup.FFDHE2048,
    NamedGroup.FFDHE3072,
    NamedGroup.FFDHE4096,
    NamedGroup.FFDHE6144,
    NamedGroup.FFDHE8192,
)


class _PycaSig:
    def __init__(self, **sig_options):
        self._sig_options = sig_options

    def gen_private(self, rgen: Random) -> bytes:
        return pyca_to_bytes(self._gen_private_pyca(rgen))

    def get_public(self, privkey):
        return pyca_to_bytes(
            pyca_from_bytes(privkey, private=True).public_key())

    def sign(self, privkey, data):
        key = pyca_from_bytes(privkey, private=True)
        return key.sign(
            data = data,
            **self._sig_options
        )

    def verify(self, pubkey, signature, data):
        pk = pyca_from_bytes(pubkey)
        try:
            pk.verify(
                signature = signature,
                data      = data,
                **self._sig_options
            )
        except InvalidSignature:
            return False
        return True


class _PycaECDSA(_PycaSig):
    def __init__(self, curve, hash_alg, gen_bits: int):
        super().__init__(
            signature_algorithm = ECDSA(hash_alg(), deterministic_signing=True),
        )
        self._curve = curve
        self._gen_bits = gen_bits

    def _gen_private_pyca(self, rgen: Random) -> bytes:
        for _ in range(128):
            try:
                return ec.derive_private_key(rgen.randrange(2**self._gen_bits), self._curve())
            except ValueError:
                continue # try again
        raise ValueError("failed EC private key generation 128 times")


class _PycaEdDSA(_PycaSig):
    def __init__(self, KeyClass, keylen: int):
        super().__init__()
        self._KeyClass = KeyClass
        self._keylen = keylen

    def _gen_private_pyca(self, rgen: Random) -> bytes:
        return self._KeyClass.generate(rgen.randbytes(self._keylen))


class _PycaRSA(_PycaSig):
    @classmethod
    def pss(cls, hash_alg):
        return cls(hash_alg=hash_alg, pad=crypto_padding.PSS(
            mgf         = crypto_padding.MGF1(hash_alg()),
            salt_length = crypto_padding.PSS.DIGEST_LENGTH,
        ))

    @classmethod
    def pkcs(cls, hash_alg):
        return cls(hash_alg=hash_alg, pad=crypto_padding.PKCS1v15())

    def __init__(self, hash_alg, pad):
        super().__init__(
            padding   = pad,
            algorithm = hash_alg(),
        )

    def _gen_private_pyca(self, rgen: Random) -> bytes:
        # XXX doesn't actually use rgen!!
        return rsa.generate_private_key(
            public_exponent = 65537,
            key_size        = 4096,
        )


def pyca_to_bytes(key):
    if hasattr(key, 'private_bytes'):
        return key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    else:
        return key.public_bytes(Encoding.DER,
                                PublicFormat.SubjectPublicKeyInfo)

def pyca_from_bytes(raw, private=False):
    if private:
        return load_pem_private_key(raw, None)
    else:
        return load_der_public_key(raw)

def extract_x509_pubkey(raw_cert):
    """Given a DER-encoded certificate, extracts bytes of the public key."""
    return pyca_to_bytes(x509.load_der_x509_certificate(raw_cert).public_key())

def get_sig_alg(scheme):
    """Given a SignatureScheme, returns an object to do digital signature verification.
    The returned object sigscheme will have:
        sigscheme.gen_private() -> privkey
        sigscheme.get_public(privkey) -> pubkey
        sigscheme.sign(privkey, data) -> bytes
        sigscheme.verify(pubkey, signature, data) -> bool
            (*** note we are using a return value here instead of exceptions
                 as is more typical in secure implementations!)
    """
    match scheme:
        case SignatureScheme.ECDSA_SECP256R1_SHA256:
            return _PycaECDSA(SECP256R1, SHA256, 256)
        case SignatureScheme.ECDSA_SECP384R1_SHA384:
            return _PycaECDSA(SECP384R1, SHA384, 384)
        case SignatureScheme.ECDSA_SECP521R1_SHA512:
            return _PycaECDSA(SECP521R1, SHA512, 512)

        case SignatureScheme.ED25519:
            return _PycaEdDSA(Ed25519PrivateKey, 32)
        case SignatureScheme.ED448:
            return _PycaEdDSA(Ed448PrivateKey, 57)

        case (SignatureScheme.RSA_PSS_RSAE_SHA256 | SignatureScheme.RSA_PSS_PSS_SHA256):
            return _PycaRSA.pss(SHA256)
        case (SignatureScheme.RSA_PSS_RSAE_SHA384 | SignatureScheme.RSA_PSS_PSS_SHA384):
            return _PycaRSA.pss(SHA384)
        case (SignatureScheme.RSA_PSS_RSAE_SHA512 | SignatureScheme.RSA_PSS_PSS_SHA512):
            return _PycaRSA.pss(SHA512)

        case SignatureScheme.RSA_PKCS1_SHA256:
            return _PycaRSA.pkcs(SHA256)
        case SignatureScheme.RSA_PKCS1_SHA384:
            return _PycaRSA.pkcs(SHA384)
        case SignatureScheme.RSA_PKCS1_SHA512:
            return _PycaRSA.pkcs(SHA512)

        case _:
            raise ValueError(f"no implementation for signatures in {scheme}")


DEFAULT_SIGNATURE_SCHEMES = (
	SignatureScheme.ECDSA_SECP256R1_SHA256,
	SignatureScheme.ECDSA_SECP384R1_SHA384,
	SignatureScheme.ECDSA_SECP521R1_SHA512,
	SignatureScheme.ED25519,
	SignatureScheme.ED448,
	SignatureScheme.RSA_PSS_PSS_SHA256,
	SignatureScheme.RSA_PSS_PSS_SHA384,
	SignatureScheme.RSA_PSS_PSS_SHA512,
	SignatureScheme.RSA_PSS_RSAE_SHA256,
	SignatureScheme.RSA_PSS_RSAE_SHA384,
	SignatureScheme.RSA_PSS_RSAE_SHA512,
	SignatureScheme.RSA_PKCS1_SHA256,
	SignatureScheme.RSA_PKCS1_SHA384,
	SignatureScheme.RSA_PKCS1_SHA512,
)


class _PycaHash:
    def __init__(self, hash_alg):
        self._hash_alg = hash_alg

    @property
    def digest_size(self):
        return self._hash_alg.digest_size

    def hasher(self, msg=b''):
        return _PycaHasher(Hash(self._hash_alg), msg)

    def hmac_hash(self, key, msg):
        # rfc2104
        h = HMAC(key=key, algorithm=self._hash_alg)
        h.update(msg)
        return h.finalize()

    def hkdf_expand(self, prk, info, length):
        # rfc5869
        h = HKDFExpand(algorithm=self._hash_alg, length=length, info=info)
        return h.derive(key_material=prk)


class _PycaHasher:
    def __init__(self, hash_obj, msg):
        self._hash_obj = hash_obj
        if msg: self._hash_obj.update(msg)

    def update(self, msg):
        self._hash_obj.update(msg)

    def digest(self):
        return self._hash_obj.copy().finalize()


def get_hash_alg(cipher_suite):
    """Given a CipherSuite, returns an object to do hashing.
    The returned object hash will have the following:
        hash.digest_size : int
        hash.hasher(msg[*]=b'') -> hash_object
        hash_object.update(msg[*]) -> None
        hash_object.digest() -> bytes[digest_size]
        hash.hmac_hash(key[key_size], msg[*]) -> bytes[digest_size]
        hash.hkdf_expand(prk[*], info[*], length) -> bytes[length]
    (All values are bytes, with sizes as specified in [] when relevant.)
    """
    match cipher_suite:
        case (CipherSuite.TLS_AES_128_GCM_SHA256
              | CipherSuite.TLS_CHACHA20_POLY1305_SHA256
              | CipherSuite.TLS_AES_128_CCM_SHA256
              | CipherSuite.TLS_AES_128_CCM_8_SHA256):
            return _PycaHash(SHA256())
        case CipherSuite.TLS_AES_256_GCM_SHA384:
            return _PycaHash(SHA384())
        case _:
            raise ValueError(f"no hash implementation for cipher suite {cipher_suite}")


class _PycaAead:
    def __init__(self, cipher_alg, key_len, iv_len=12, tag_len=16):
        self._cipher_alg = cipher_alg
        self._key_len = key_len
        self._iv_len = iv_len
        self._tag_len = tag_len

    @property
    def key_length(self):
        return self._key_len

    @property
    def iv_length(self):
        return self._iv_len

    def ctext_size(self, ptext_size):
        return ptext_size + self._tag_len

    def encrypt(self, key, iv, ptext, adata):
        return self._cipher_alg(key).encrypt(iv, ptext, adata)

    def decrypt(self, key, iv, ctext, adata):
        return self._cipher_alg(key).decrypt(iv, ctext, adata)


def get_cipher_alg(cipher_suite):
    """Given a CipherSuite, returns an object to do encryption.
    The returned object cipher will have the following:
        cipher.key_length  : int
        cipher.iv_length   : int
        cipher.ctext_size(ptext_size: int) -> int
        cipher.encrypt(key[key_length], iv[iv_length], ptext[ptext_size], adata[*])
            -> ctext[ctext_size(ptext_size)]
        cipher.decrypt(key[key_length], iv[iv_length], ctext[*], adata[*]) -> ptext[*]
    (All values are bytes, with sizes as specified in [] when relevant.)
    """
    match cipher_suite:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
            return _PycaAead(AESGCM, 16)
        case CipherSuite.TLS_AES_256_GCM_SHA384:
            return _PycaAead(AESGCM, 32)
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return _PycaAead(ChaCha20Poly1305, 32)
        case CipherSuite.TLS_AES_128_CCM_SHA256:
            return _PycaAead(AESCCM, 16)
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
            return _PycaAead(AESCCM, 16, tag_len=8)
        case _:
            raise ValueError(f"no cipher implementation for cipher suite {cipher_suite}")


DEFAULT_CIPHER_SUITES = (
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.LEGACY_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
)


def _get_pyhpke_cs(
    kem_id = pyhpke.KEMId.DHKEM_X25519_HKDF_SHA256,
    kdf_id = pyhpke.KDFId.HKDF_SHA256,
    aead_id = pyhpke.AEADId.CHACHA20_POLY1305,
) -> pyhpke.CipherSuite:
    return pyhpke.CipherSuite.new(kem_id, kdf_id, aead_id)

_Pyhpke_Keypair = Struct(
    private = Bounded(2, Raw),
    public  = Bounded(2, Raw),
)

class _Pyhpke_Kem:
    def __init__(self, kem_id: pyhpke.KEMId):
        self._kem = _get_pyhpke_cs(kem_id=kem_id).kem

    def gen_private(self, rgen: Random) -> bytes:
        keypair = self._kem.derive_key_pair(rgen.randbytes(64))
        return _Pyhpke_Keypair.pack(
            private = keypair.private_key.to_private_bytes(),
            public  = keypair.public_key.to_public_bytes(),
        )

    def get_public(self, private: bytes) -> bytes:
        return _Pyhpke_Keypair.unpack(private).public


def get_kem_alg(kem_id: HpkeKemId) -> _Pyhpke_Kem:
    """Given a kem_id, returns an object to do key encapsulation.
    The returned object kex will have:
        kem.gen_private(rgen) -> private
        kem.get_public(private) -> public
    """
    return _Pyhpke_Kem(pyhpke.KEMId(int(kem_id)))

DEFAULT_KEM = HpkeKemId.DHKEM_X25519_HKDF_SHA256


# TODO cipher suites
DEFAULT_HPKE_CSUITES = [
    (HpkeKdfId.HKDF_SHA256, HpkeAeadId.AES_256_GCM),
    (HpkeKdfId.HKDF_SHA256, HpkeAeadId.CHACHA20_POLY1305),
]


class StreamCipher:
    def __init__(self, cipher, hash_alg, secret):
        self._cipher = cipher
        # rfc8446, sect 7.3
        self._key = hkdf_expand_label(
            hash_alg = hash_alg,
            secret   = secret,
            label    = b'key',
            cont     = b'',
            length   = self._cipher.key_length,
            )
        self._iv = hkdf_expand_label(
            hash_alg = hash_alg,
            secret   = secret,
            label    = b'iv',
            cont     = b'',
            length   = self._cipher.iv_length,
            )
        logger.info(f'started StreamCipher with key {self._key.hex()} and iv {self._iv.hex()}')
        self._counter = 0

    def _next_nonce(self):
        nonce = bytes(a ^ b for a,b in
                      zip(self._iv, self._counter.to_bytes(len(self._iv))))
        self._counter += 1
        return nonce

    def encrypt(self, ptext, adata):
        assert self._key is not None, "need to rekey before encrypting"
        return self._cipher.encrypt(
            key   = self._key,
            iv    = self._next_nonce(),
            ptext = ptext,
            adata = adata,
            )

    def decrypt(self, ctext, adata):
        assert self._key is not None, "need to rekey before decrypting"
        return self._cipher.decrypt(
            key   = self._key,
            iv    = self._next_nonce(),
            ctext = ctext,
            adata = adata,
            )


def hkdf_extract(hash_alg, salt, ikm):
    # rfc5869
    return hash_alg.hmac_hash(key=salt, msg=ikm)

def hkdf_expand_label(hash_alg, secret, label, cont, length):
    # rfc8446 sect 7.1
    info = HkdfLabel.pack({
        'length'  : length,
        'label'   : b'tls13 ' + label,
        'context' : cont,
    })
    return hash_alg.hkdf_expand(prk=secret, info=info, length=length)

def derive_secret(hash_alg, secret, label, msg_digest):
    # rfc8446 sect 7.1
    return hkdf_expand_label(hash_alg, secret=secret, label=label,
                             cont=msg_digest, length=hash_alg.digest_size)


def gen_cert(name: str, sig_alg: SignatureScheme, rgen: Random) -> Struct: #CertSecrets
    """Generates a new self-signed X509 certificate.

    A fresh signature keypair is generated and the private key
    is returned in a bytes encoding.

    The cert is valid for 10 years.

    Returns a CertSecrets tuple."""
    sigscheme = get_sig_alg(sig_alg)
    private_key = sigscheme.gen_private(rgen)
    # https://github.com/pyca/cryptography/blob/main/src/cryptography/x509/base.py#L847-L848
    serialno = rgen.randrange(2**(20*8-1))
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .not_valid_before(datetime(year=2025,month=1,day=1))
        .not_valid_after(datetime(year=2035,month=1,day=1))
        .serial_number(serialno)
        .public_key(pyca_from_bytes(sigscheme.get_public(private_key)))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None), critical=True)
        .sign(private_key=pyca_from_bytes(private_key, private=True), algorithm=SHA256()))
    return CertSecrets.prepack(
        sig_alg = sig_alg,
        private_key = private_key,
        cert_der = cert.public_bytes(Encoding.DER),
    )


def gen_ech_config(
    public_name: str,
    config_id: int,
    maximum_name_length: int,
    kem_id: HpkeKemId,
    cipher_suites: Iterable[tuple[HpkeKdfId,HpkeAeadId]],
    rgen: Random,
) -> Struct: #EchSecrets
    """Generates an ECHConfig struct and corresponding private key."""
    kem = get_kem_alg(kem_id)
    seckey = kem.gen_private(rgen)
    pubkey = kem.get_public(seckey)
    config = ECHConfig.prepack(
        version = 0xfe0d,
        contents = kwdict(
            key_config = kwdict(
                config_id = config_id,
                kem_id = kem_id,
                public_key = pubkey,
                cipher_suites = cipher_suites,
            ),
            maximum_name_length = maximum_name_length,
            public_name = public_name,
            extensions = [],
        ),
    )
    return EchSecrets.prepack(config=config, private_key=seckey)


def gen_server_secrets(
    name: str ='localhost',
    sig_alg: SignatureScheme = DEFAULT_SIGNATURE_SCHEMES[0],
    config_id: int|None = None, # default, choose randomly
    maximum_name_length: int = 128,
    kem_id: HpkeKemId = DEFAULT_KEM,
    cipher_suites: Iterable[tuple[HpkeKdfId,HpkeAeadId]] = DEFAULT_HPKE_CSUITES,
    rgen: Random|None = None, # default, SystemRandom
) -> ServerSecrets:
    """Generates a fresh certificate and ECH config."""
    if rgen is None:
        rgen = SystemRandom()
    if config_id is None:
        config_id = rgen.randrange(2**8)

    return ServerSecrets.prepack(
        cert = gen_cert(name, sig_alg, rgen),
        eches = [gen_ech_config(name, config_id, maximum_name_length, kem_id, cipher_suites, rgen)],
    )
