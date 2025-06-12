from typing import override, BinaryIO, Self
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
import enum

from spec import LimitReader, UnpackError
from tls_common import *
from tls13_spec import (
    ClientHelloHandshake,
    ClientHelloHandshakeData,

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

    ClientSecrets,
    HpkeSymmetricCipherSuite,
)
from tls_crypto import (
    HpkeAlg,
    ContextS,
    get_hpke_alg,
)

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

@dataclass
class OuterPrep:
    config: ECHConfigVariant
    inner_ch: ClientHelloHandshake
    _inner_secrets: ClientSecrets

    def __post_init__(self) -> None:
        if get_ech_type(self.inner_ch) != EchType.INNER:
            raise ValueError("OuterPrep must be given INNER type client hello")

    @cached_property
    def _cdata(self) -> Draft24ECHConfigData:
        match self.config:
            case Draft24ECHConfig() as cfg:
                return cfg.data
        raise ValueError(f"unknown ECH config type {self.config.selector}")

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
            info = b'tls ech' + b'\x00' + self.config.pack(),
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

    @cached_property
    def secrets(self) -> ClientSecrets:
        return self._inner_secrets.replace(inner_ch = self.inner_ch.uncreate())

    def fill_outer(self, outer_ch: ClientHelloHandshake) -> ClientHelloHandshake:
        """Given a complete outer clienthello with a dummy ECH extension,
        fills in the extension ciphertext to complete it."""
        if get_ech_type(outer_ch) != EchType.OUTER:
            raise ValueError("fill_outer needs an outer client hello")

        # extract the ECH extension from the outer hello
        ext_list: list[ClientExtensionVariant] = list(outer_ch.data.extensions.uncreate())
        for index, ext in enumerate(ext_list):
            match ext:
                case EncryptedClientHelloClientExtension() as ech_ext:
                    match ech_ext.data.variant:
                        case OuterECHClientHello() as oech_ext:
                            break
        else:
            assert False, "no outer ECH extension found but we already checked with get_ech_type"

        if len(oech_ext.data.payload) != self.payload_length or any(oech_ext.data.payload):
            raise ValueError(f"expected outer ECH payload to be all zeros of length {self.payload_length}")

        # compute the AEAD ciphertext
        # NB ClientHelloHandshakeData omits 4-byte hs header as required
        aad = ClientHelloHandshakeData.pack(outer_ch.data)
        ct = self._enc_context.seal(aad=aad, pt=self.encoded_inner)
        if len(ct) != self.payload_length:
            raise ValueError("expected ct length to be {self.payload_length} byt got {len(ct)}")

        # rebuild the client hello with the ciphertext
        filled_ext = EncryptedClientHelloClientExtension.create(
            oech_ext.replace(payload=ct))
        ext_list[index] = filled_ext
        return outer_ch.replace(extensions=ext_list)


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
