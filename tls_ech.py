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
    ECHConfigVariant,
    Draft24ECHConfig,
    Draft24ECHConfigData,

    ExtensionType,
    EncryptedClientHelloClientExtension,
    ServerNameClientExtension,

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
    for ext in chello.data.extensions:
        match ext.variant:
            case EncryptedClientHelloClientExtension() as eche:
                match eche.data.selector:
                    case ECHClientHelloType.OUTER:
                        return EchType.OUTER
                    case ECHClientHelloType.INNER:
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
    inner_ch: ClientHelloHandshake
    config: ECHConfigVariant

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
