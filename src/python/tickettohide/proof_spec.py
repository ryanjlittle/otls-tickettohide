
# XXX AUTO-GENERATED - DO NOT EDIT! XXX
from typing import Self, override, BinaryIO, ClassVar, Any
from collections.abc import Iterable
import enum
import dataclasses
from dataclasses import dataclass
import tls13
from tls13 import spec
from tls13.spec import *
import tls13.tls13_spec
from tls13.tls_common import *
from tickettohide.proof_common import *

class BoundedString(tls13.spec.String, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class Uint8(spec._Integral):
    _BYTE_LENGTH = 1

class B8String(BoundedString):
    _LENGTH_TYPES = (Uint8, )

class BoundedRaw(tls13.spec.Raw, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B8Raw(BoundedRaw):
    _LENGTH_TYPES = (Uint8, )

class SeqKeyShareEntry(spec._Sequence[tls13.tls13_spec.KeyShareEntry]):
    _ITEM_TYPE = tls13.tls13_spec.KeyShareEntry

    @classmethod
    def create(cls, items: Iterable[tls13.tls13_spec.KeyShareEntry]) -> Self:
        return cls(item for item in items)

    def uncreate(self) -> Iterable[tls13.tls13_spec.KeyShareEntry]:
        for item in self:
            yield item

class BoundedSeqKeyShareEntry(SeqKeyShareEntry, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class Uint16(spec._Integral):
    _BYTE_LENGTH = 2

class B16SeqKeyShareEntry(BoundedSeqKeyShareEntry):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class ClientHelloValues(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('hostname','ticket_info','binder_key','kex_shares',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B8String,tls13.tls13_spec.TicketInfo,B8Raw,B16SeqKeyShareEntry,)
    hostname: B8String
    ticket_info: tls13.tls13_spec.TicketInfo
    binder_key: B8Raw
    kex_shares: B16SeqKeyShareEntry

    def replace(self, hostname:str|None=None, ticket_info:tls13.tls13_spec.TicketInfo|None=None, binder_key:bytes|None=None, kex_shares:Iterable[tls13.tls13_spec.KeyShareEntry]|None=None) -> Self:
        return type(self)((self.hostname if hostname is None else B8String.create(hostname)), (self.ticket_info if ticket_info is None else ticket_info), (self.binder_key if binder_key is None else B8Raw.create(binder_key)), (self.kex_shares if kex_shares is None else B16SeqKeyShareEntry.create(kex_shares)))

    @classmethod
    def create(cls,hostname:str,ticket_info:tls13.tls13_spec.TicketInfo,binder_key:bytes,kex_shares:Iterable[tls13.tls13_spec.KeyShareEntry]) -> Self:
        return cls(hostname=B8String.create(hostname), ticket_info=ticket_info, binder_key=B8Raw.create(binder_key), kex_shares=B16SeqKeyShareEntry.create(kex_shares))

    def uncreate(self) -> tuple[str, tls13.tls13_spec.TicketInfo, bytes, Iterable[tls13.tls13_spec.KeyShareEntry]]:
        return (self.hostname.uncreate(), self.ticket_info, self.binder_key.uncreate(), self.kex_shares.uncreate())

class ProverMsgTypes(enum.IntEnum):
    KEX_SHARES = 1

    def parent(self) -> 'ProverMsgType':
        return ProverMsgType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ProverMsgType(spec._NamedConstBase[ProverMsgTypes]):
    _T = ProverMsgTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    KEX_SHARES: 'ProverMsgType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class VerifierMsgTypes(enum.IntEnum):
    TICKETS = 1
    APP_KEY_SHARES = 2
    OK = 97
    HANDSHAKE_SECRETS = 98
    MASTER_SECRETS = 99

    def parent(self) -> 'VerifierMsgType':
        return VerifierMsgType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class VerifierMsgType(spec._NamedConstBase[VerifierMsgTypes]):
    _T = VerifierMsgTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    TICKETS: 'VerifierMsgType'
    APP_KEY_SHARES: 'VerifierMsgType'
    OK: 'VerifierMsgType'
    HANDSHAKE_SECRETS: 'VerifierMsgType'
    MASTER_SECRETS: 'VerifierMsgType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class B16Raw(BoundedRaw):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class KexSharesProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('group','pubkey',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (tls13.tls13_spec.NamedGroup,B16Raw,)
    group: tls13.tls13_spec.NamedGroup
    pubkey: B16Raw

    def replace(self, group:tls13.tls13_spec.NamedGroup|None=None, pubkey:bytes|None=None) -> Self:
        return type(self)((self.group if group is None else group), (self.pubkey if pubkey is None else B16Raw.create(pubkey)))

    @classmethod
    def create(cls,group:tls13.tls13_spec.NamedGroup,pubkey:bytes) -> Self:
        return cls(group=group, pubkey=B16Raw.create(pubkey))

    def uncreate(self) -> tuple[tls13.tls13_spec.NamedGroup, bytes]:
        return (self.group, self.pubkey.uncreate())

class SeqKexSharesProverMsgData(spec._Sequence[KexSharesProverMsgData]):
    _ITEM_TYPE = KexSharesProverMsgData

    @classmethod
    def create(cls, items: Iterable[tuple[tls13.tls13_spec.NamedGroup,bytes]]) -> Self:
        return cls(KexSharesProverMsgData.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[tls13.tls13_spec.NamedGroup,bytes]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqKexSharesProverMsgData(SeqKexSharesProverMsgData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqKexSharesProverMsgData(BoundedSeqKexSharesProverMsgData):
    _LENGTH_TYPES = (Uint16, )

class SeqB16SeqKexSharesProverMsgData(spec._Sequence[B16SeqKexSharesProverMsgData]):
    _ITEM_TYPE = B16SeqKexSharesProverMsgData

    @classmethod
    def create(cls, items: Iterable[Iterable[tuple[tls13.tls13_spec.NamedGroup,bytes]]]) -> Self:
        return cls(B16SeqKexSharesProverMsgData.create(item) for item in items)

    def uncreate(self) -> Iterable[Iterable[tuple[tls13.tls13_spec.NamedGroup,bytes]]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqB16SeqKexSharesProverMsgData(SeqB16SeqKexSharesProverMsgData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqB16SeqKexSharesProverMsgData(BoundedSeqB16SeqKexSharesProverMsgData):
    _LENGTH_TYPES = (Uint16, )

class KexSharesProverMsg(spec._SpecificSelectee[ProverMsgTypes, B16SeqB16SeqKexSharesProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B16SeqB16SeqKexSharesProverMsgData
    _SELECTOR = ProverMsgTypes.KEX_SHARES

    @classmethod
    def create(cls, items:Iterable[Iterable[tuple[tls13.tls13_spec.NamedGroup,bytes]]]) -> Self:
        return cls(data=B16SeqB16SeqKexSharesProverMsgData.create(items))

    def uncreate(self) -> Iterable[Iterable[tuple[tls13.tls13_spec.NamedGroup,bytes]]]:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)


ProverMsgVariant = KexSharesProverMsg

class ProverMsg(spec._Select[ProverMsgTypes]):
    _SELECT_TYPE = ProverMsgType
    _GENERIC_TYPE = None
    _SELECTEES = {ProverMsgTypes.KEX_SHARES:KexSharesProverMsg}

    def __init__(self, value: ProverMsgVariant) -> None:
        super().__init__(value)
        self._value: ProverMsgVariant = value

    @property
    def variant(self) -> ProverMsgVariant:
        return self._value

    @classmethod
    def create(cls, variant: ProverMsgVariant) -> Self:
        return cls(variant)

    def uncreate(self) -> ProverMsgVariant:
        return self.variant

class SeqClientHelloValues(spec._Sequence[ClientHelloValues]):
    _ITEM_TYPE = ClientHelloValues

    @classmethod
    def create(cls, items: Iterable[tuple[str,tls13.tls13_spec.TicketInfo,bytes,Iterable[tls13.tls13_spec.KeyShareEntry]]]) -> Self:
        return cls(ClientHelloValues.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[str,tls13.tls13_spec.TicketInfo,bytes,Iterable[tls13.tls13_spec.KeyShareEntry]]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqClientHelloValues(SeqClientHelloValues, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqClientHelloValues(BoundedSeqClientHelloValues):
    _LENGTH_TYPES = (Uint16, )

class TicketsVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16SeqClientHelloValues]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16SeqClientHelloValues
    _SELECTOR = VerifierMsgTypes.TICKETS

    @classmethod
    def create(cls, items:Iterable[tuple[str,tls13.tls13_spec.TicketInfo,bytes,Iterable[tls13.tls13_spec.KeyShareEntry]]]) -> Self:
        return cls(data=B16SeqClientHelloValues.create(items))

    def uncreate(self) -> Iterable[tuple[str,tls13.tls13_spec.TicketInfo,bytes,Iterable[tls13.tls13_spec.KeyShareEntry]]]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

@dataclass(frozen=True)
class AppKeySharesVerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('server_key_share','client_key_share',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B8Raw,B8Raw,)
    server_key_share: B8Raw
    client_key_share: B8Raw

    def replace(self, server_key_share:bytes|None=None, client_key_share:bytes|None=None) -> Self:
        return type(self)((self.server_key_share if server_key_share is None else B8Raw.create(server_key_share)), (self.client_key_share if client_key_share is None else B8Raw.create(client_key_share)))

    @classmethod
    def create(cls,server_key_share:bytes,client_key_share:bytes) -> Self:
        return cls(server_key_share=B8Raw.create(server_key_share), client_key_share=B8Raw.create(client_key_share))

    def uncreate(self) -> tuple[bytes, bytes]:
        return (self.server_key_share.uncreate(), self.client_key_share.uncreate())

class BoundedAppKeySharesVerifierMsgData(AppKeySharesVerifierMsgData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16AppKeySharesVerifierMsgData(BoundedAppKeySharesVerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class AppKeySharesVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16AppKeySharesVerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16AppKeySharesVerifierMsgData
    _SELECTOR = VerifierMsgTypes.APP_KEY_SHARES

    @classmethod
    def create(cls, server_key_share:bytes, client_key_share:bytes) -> Self:
        return cls(data=B16AppKeySharesVerifierMsgData.create(server_key_share, client_key_share))

    def uncreate(self) -> tuple[bytes,bytes]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

    def replace(self, server_key_share: bytes|None=None, client_key_share: bytes|None=None) -> Self:
        orig_server_key_share, orig_client_key_share = self.uncreate()
        return self.create((orig_server_key_share if server_key_share is None else server_key_share), (orig_client_key_share if client_key_share is None else client_key_share))

class BoundedUint8(tls13.tls13_spec.Uint8, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16Uint8(BoundedUint8):
    _LENGTH_TYPES = (Uint16, )

class OkVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16Uint8]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16Uint8
    _SELECTOR = VerifierMsgTypes.OK

    @classmethod
    def create(cls, value:int) -> Self:
        return cls(data=B16Uint8.create(value))

    def uncreate(self) -> int:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

@dataclass(frozen=True)
class MasterSecretsVerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('secret',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B8Raw,)
    secret: B8Raw

    def replace(self, secret:bytes|None=None) -> Self:
        return type(self)((self.secret if secret is None else B8Raw.create(secret)))

    @classmethod
    def create(cls,secret:bytes) -> Self:
        return cls(secret=B8Raw.create(secret))

    def uncreate(self) -> bytes:
        return (self.secret.uncreate())

class SeqMasterSecretsVerifierMsgData(spec._Sequence[MasterSecretsVerifierMsgData]):
    _ITEM_TYPE = MasterSecretsVerifierMsgData

    @classmethod
    def create(cls, items: Iterable[bytes]) -> Self:
        return cls(MasterSecretsVerifierMsgData.create(item) for item in items)

    def uncreate(self) -> Iterable[bytes]:
        for item in self:
            yield item.uncreate()

class BoundedSeqMasterSecretsVerifierMsgData(SeqMasterSecretsVerifierMsgData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqMasterSecretsVerifierMsgData(BoundedSeqMasterSecretsVerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class HandshakeSecretsVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16SeqMasterSecretsVerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16SeqMasterSecretsVerifierMsgData
    _SELECTOR = VerifierMsgTypes.HANDSHAKE_SECRETS

    @classmethod
    def create(cls, items:Iterable[bytes]) -> Self:
        return cls(data=B16SeqMasterSecretsVerifierMsgData.create(items))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

class MasterSecretsVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16SeqMasterSecretsVerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16SeqMasterSecretsVerifierMsgData
    _SELECTOR = VerifierMsgTypes.MASTER_SECRETS

    @classmethod
    def create(cls, items:Iterable[bytes]) -> Self:
        return cls(data=B16SeqMasterSecretsVerifierMsgData.create(items))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)


VerifierMsgVariant = TicketsVerifierMsg | AppKeySharesVerifierMsg | OkVerifierMsg | HandshakeSecretsVerifierMsg | MasterSecretsVerifierMsg

class VerifierMsg(spec._Select[VerifierMsgTypes]):
    _SELECT_TYPE = VerifierMsgType
    _GENERIC_TYPE = None
    _SELECTEES = {VerifierMsgTypes.TICKETS:TicketsVerifierMsg, VerifierMsgTypes.APP_KEY_SHARES:AppKeySharesVerifierMsg, VerifierMsgTypes.OK:OkVerifierMsg, VerifierMsgTypes.HANDSHAKE_SECRETS:HandshakeSecretsVerifierMsg, VerifierMsgTypes.MASTER_SECRETS:MasterSecretsVerifierMsg}

    def __init__(self, value: VerifierMsgVariant) -> None:
        super().__init__(value)
        self._value: VerifierMsgVariant = value

    @property
    def variant(self) -> VerifierMsgVariant:
        return self._value

    @classmethod
    def create(cls, variant: VerifierMsgVariant) -> Self:
        return cls(variant)

    def uncreate(self) -> VerifierMsgVariant:
        return self.variant

_enum_types: list[type[spec._NamedConstBase[Any]]] = [ProverMsgType, VerifierMsgType]
def _set_enum_constants() -> None:
    for etype in _enum_types:
        for enum_val in etype._T:
            setattr(etype, enum_val.name, etype.create(enum_val.value))
_set_enum_constants()
