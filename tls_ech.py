from typing import override, BinaryIO, Self
from collections.abc import Iterable
import enum

from spec import LimitReader, UnpackError
from tls_common import *
from tls13_spec import (
    ClientHelloHandshake,
    ClientHelloHandshakeData,
    ECHClientHelloType,
    ExtensionType,
    EncryptedClientHelloClientExtension,
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
