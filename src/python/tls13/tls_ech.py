from typing import override, BinaryIO, Self
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cached_property
import enum

from tls13.spec import LimitReader, UnpackError
from tls13.tls_common import *
from tls13.tls13_spec import (
    HandshakeTypes,
    ClientHelloHandshake,
    ClientHelloHandshakeData,
    ServerHelloHandshake,

    ECHClientHelloType,
    OuterECHClientHello,
    InnerECHClientHello,
    ECHConfigVariant,
    Draft24ECHConfig,
    Draft24ECHConfigData,

    ExtensionType,
    ClientExtensionVariant,
    EncryptedClientHelloClientExtension,
    ServerNameClientExtension,

    HpkeSymmetricCipherSuite,

    EchSecrets,
    EchKeyConfig,
)
from tls13.tls_crypto import (
    HpkeAlg,
    ContextS,
    get_hpke_alg,
    get_hash_alg,
    hkdf_extract,
    hkdf_expand_label,
)
from tls13.tls_keycalc import HandshakeTranscript

class EchType(enum.Enum):
    NONE  = enum.auto()
    INNER = enum.auto()
    OUTER = enum.auto()

def get_ech_type(chello: ClientHelloHandshake) -> EchType:
    for ext in chello.data.extensions.uncreate():
        match ext:
            case EncryptedClientHelloClientExtension() as eche:
                match eche.data.variant:
                    case OuterECHClientHello():
                        return EchType.OUTER
                    case InnerECHClientHello():
                        return EchType.INNER
                    case _:
                        raise ValueError(f"got unrecognized eche type {eche.data.selector}")
    return EchType.NONE

def encode_inner(
    chello: ClientHelloHandshake,
    padding:int=0,
    outer_extensions:Iterable[ExtensionType]=()
) -> bytes:
    if get_ech_type(chello) != EchType.INNER:
        raise ValueError("expected inner chello")
    if outer_extensions:
        raise TlsTODO("no support for OuterExtensions extension yet")
    ch_nosid = chello.data.replace(session_id = b'')
    encoded_ch = ClientHelloHandshakeData.pack(ch_nosid)
    return encoded_ch + b'\x00'*padding


def _hpke_alg_info(config: ECHConfigVariant) -> bytes:
    """Produces the 'info' field for calling setup_base_*()."""
    return b'tls ech' + b'\x00' + config.pack()


@dataclass
class _EchExtBuilder:
    orig: ClientHelloHandshake
    exts: tuple[ClientExtensionVariant, ...] = field(init=False)
    ech: OuterECHClientHello = field(init=False)
    index: int = field(init=False)

    def __post_init__(self) -> None:
        self.exts = tuple(self.orig.data.extensions.uncreate())
        for index, ext in enumerate(self.exts):
            match ext:
                case EncryptedClientHelloClientExtension() as ech_ext:
                    match ech_ext.data.variant:
                        case OuterECHClientHello() as oech:
                            self.ech = oech
                            self.index = index
                            break
        else:
            raise ValueError("no outer ECH extension found in original client hello")

    def fill(self, payload: bytes|None) -> ClientHelloHandshake:
        if payload is None:
            payload = b'\x00' * len(self.ech.data.payload)
        assert len(self.ech.data.payload) == len(payload), "payload length should match original"
        filled_ech = EncryptedClientHelloClientExtension.create(self.ech.replace(payload=payload))
        new_exts = self.exts[:self.index] + (filled_ech,) + self.exts[self.index+1:]
        return self.orig.replace(extensions=new_exts)


@dataclass
class OuterPrep:
    config: ECHConfigVariant
    inner_ch: ClientHelloHandshake

    def __post_init__(self) -> None:
        if get_ech_type(self.inner_ch) != EchType.INNER:
            raise ValueError("OuterPrep must be given INNER type client hello")

    @cached_property
    def _cdata(self) -> Draft24ECHConfigData:
        match self.config:
            case Draft24ECHConfig() as cfg:
                return cfg.data
        raise ValueError(f"unknown ECH config type {self.config.selector}")

    @cached_property
    def sesid(self) -> bytes:
        return self.inner_ch.data.session_id

    @property
    def outer_sni(self) -> str:
        return self._cdata.public_name

    @cached_property
    def padding(self) -> int:
        inner_sni = None
        for ext in self.inner_ch.data.extensions:
            match ext.variant:
                case ServerNameClientExtension() as sni_ext:
                    inner_sni = sni_ext.data[0].host_name
                    return max(0, self._cdata.maximum_name_length - len(inner_sni))
        else:
            logger.warning("no SNI found in inner client hello")
            return self._cdata.maximum_name_length + 7

    @cached_property
    def encoded_inner(self) -> bytes:
        return encode_inner(self.inner_ch, self.padding)

    @cached_property
    def cipher_suite(self) -> HpkeSymmetricCipherSuite:
        return self._cdata.key_config.cipher_suites[0]

    @cached_property
    def _hpke_alg(self) -> HpkeAlg:
        return get_hpke_alg(
            kem_id = self._cdata.key_config.kem_id,
            csuite = self.cipher_suite,
        )

    @cached_property
    def _hpke_setup(self) -> tuple[bytes, ContextS]:
        return self._hpke_alg.setup_base_s(
            pubkey_r = self._cdata.key_config.public_key,
            info = _hpke_alg_info(self.config),
        )

    @property
    def enc_key(self) -> bytes:
        return self._hpke_setup[0]

    @property
    def _enc_context(self) -> ContextS:
        return self._hpke_setup[1]

    @cached_property
    def payload_length(self) -> int:
        return self._hpke_alg.ctext_size(len(self.encoded_inner))

    @cached_property
    def dummy_ext(self) -> EncryptedClientHelloClientExtension:
        return EncryptedClientHelloClientExtension.create(
            OuterECHClientHello.create(
                cipher_suite = self.cipher_suite.uncreate(),
                config_id = self._cdata.key_config.config_id,
                enc = self.enc_key,
                payload = b'\x00' * self.payload_length,
            )
        )

    def fill_outer(self, outer_ch: ClientHelloHandshake) -> ClientHelloHandshake:
        """Given a complete outer clienthello with a dummy ECH extension,
        fills in the extension ciphertext to complete it."""

        builder = _EchExtBuilder(outer_ch)

        if len(builder.ech.data.payload) != self.payload_length or any(builder.ech.data.payload):
            raise ValueError(f"expected outer ECH payload to be all zeros of length {self.payload_length}")

        # compute the AEAD ciphertext
        # NB ClientHelloHandshakeData omits 4-byte hs header as required
        aad = ClientHelloHandshakeData.pack(outer_ch.data)
        ct = self._enc_context.seal(aad=aad, pt=self.encoded_inner)
        if len(ct) != self.payload_length:
            raise ValueError("expected ct length to be {self.payload_length} byt got {len(ct)}")

        # rebuild the client hello with the ciphertext
        return builder.fill(ct)


def decode_inner(encoded: bytes, outer: ClientHelloHandshake) -> ClientHelloHandshake:
    if get_ech_type(outer) != EchType.OUTER:
        raise ValueError("expected outer to be an outer client hello")
    rdr = LimitReader.from_raw(encoded)
    chdata = ClientHelloHandshakeData.unpack_from(rdr)
    assert rdr.limit is not None
    pad = rdr.read(rdr.limit)
    if any(pad):
        raise UnpackError(encoded, f"padding should be all zero bytes, but got {pad.hex()}")
    if any(ext.selector == ExtensionType.ECH_OUTER_EXTENSIONS for ext in chdata.extensions):
        raise TlsTODO("no support for decoding inner ECH with OuterExtensions yet")
    ch_withsid = chdata.replace(session_id = outer.data.session_id)
    inner = ClientHelloHandshake.create(*ch_withsid.uncreate())
    if get_ech_type(inner) != EchType.INNER:
        raise ValueError("decoded client hello should have type inner")
    return inner


def try_get_inner(outer: ClientHelloHandshake, secrets: Iterable[EchSecrets]) -> ClientHelloHandshake|None:
    """Given a CH message received by the server, along with the server ECH secrets,
    attempts to decrypt and decode the inner client hello."""

    builder = _EchExtBuilder(outer)

    for esec in secrets:
        match esec.config:
            case Draft24ECHConfig(data=config):
                if config.key_config.config_id == builder.ech.data.config_id:
                    logger.info(f"Matching ECH config with id {builder.ech.data.config_id} found by server")
                    break
            case _:
                logger.warning(f"Ignoring unsupported ECH config {esec.config}")
    else:
        logger.info(f"Server secrets have no config id {builder.ech.data.config_id}; ECH rejected")
        return None

    if builder.ech.data.cipher_suite not in config.key_config.cipher_suites:
        logger.warning(f"client-selected ECH cipher suite mismatch")
        return None

    hpke_alg = get_hpke_alg(
        kem_id = config.key_config.kem_id,
        csuite = builder.ech.data.cipher_suite,
    )

    #TODO error check for bad key
    enc_context = hpke_alg.setup_base_r(
        enc = builder.ech.data.enc,
        privkey_r = esec.private_key,
        info = _hpke_alg_info(esec.config),
    )

    aad = ClientHelloHandshakeData.pack(builder.fill(payload=None).data)

    #TODO error check for bad key
    ptext = enc_context.open(
        aad = aad,
        ct = builder.ech.data.payload,
    )

    return decode_inner(encoded=ptext, outer=outer)


def _ech_conf(chello_inner: ClientHelloHandshake, shello: ServerHelloHandshake) -> bytes:
    hash_alg = get_hash_alg(shello.data.cipher_suite)

    sr2 = shello.data.server_random[:-8] + b'\x00'*8
    shello2 = shello.replace(server_random = sr2)

    hst = HandshakeTranscript()
    hst.hash_alg = hash_alg
    hst.add(hs=chello_inner, from_client=True)
    hst.add(hs=shello2, from_client=False)

    derived_secret = hkdf_extract(
        hash_alg = hash_alg,
        salt     = b'\x00'*hash_alg.digest_size,
        ikm      = chello_inner.data.client_random,
    )
    return hkdf_expand_label(
        hash_alg = hash_alg,
        secret   = derived_secret,
        label    = b'ech accept confirmation',
        cont     = hst[HandshakeTypes.SERVER_HELLO,False],
        length   = 8,
    )

def set_shello_ech(chello_inner: ClientHelloHandshake, shello: ServerHelloHandshake) -> ServerHelloHandshake:
    """Modifies the server_random field in the SH to indicate ECH acceptance."""
    return shello.replace(
        server_random = shello.data.server_random[:-8] + _ech_conf(chello_inner, shello))

def server_accepts_ech(chello_inner: ClientHelloHandshake, shello: ServerHelloHandshake) -> bool:
    if get_ech_type(chello_inner) != EchType.INNER:
        raise ValueError("must use inner client hello to check ech acceptance")
    return shello.data.server_random[-8:] == _ech_conf(chello_inner, shello)
