
# XXX AUTO-GENERATED - DO NOT EDIT! XXX
from typing import Self, override, BinaryIO, ClassVar, Any
from collections.abc import Iterable
import enum
import dataclasses
from dataclasses import dataclass
import spec
from spec import *
import tls13_spec
from tls_common import *
from proof_common import *

class Uint8(spec._Integral):
    _BYTE_LENGTH = 1

class ProverMsgTypes(enum.IntEnum):
    SERVER_HANDSHAKE_TX = 1
    HASH_1S = 2
    HASH_4S = 3
    COMMITMENT = 4
    KEX_SHARES = 5
    PROOF = 6
    CLIENT_RANDOMS = 7

    def parent(self) -> 'ProverMsgType':
        return ProverMsgType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ProverMsgType(spec._NamedConstBase[ProverMsgTypes]):
    _T = ProverMsgTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    SERVER_HANDSHAKE_TX: 'ProverMsgType'
    HASH_1S: 'ProverMsgType'
    HASH_4S: 'ProverMsgType'
    COMMITMENT: 'ProverMsgType'
    KEX_SHARES: 'ProverMsgType'
    PROOF: 'ProverMsgType'
    CLIENT_RANDOMS: 'ProverMsgType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class VerifierMsgTypes(enum.IntEnum):
    KEX_SHARES_PHASE_1 = 1
    HANDSHAKE_KEYS = 2
    APPLICATION_KEYS = 3
    KEX_SHARE_PHASE_2 = 4
    KEX_SECRETS = 5
    MASTER_SECRETS = 99

    def parent(self) -> 'VerifierMsgType':
        return VerifierMsgType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class VerifierMsgType(spec._NamedConstBase[VerifierMsgTypes]):
    _T = VerifierMsgTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    KEX_SHARES_PHASE_1: 'VerifierMsgType'
    HANDSHAKE_KEYS: 'VerifierMsgType'
    APPLICATION_KEYS: 'VerifierMsgType'
    KEX_SHARE_PHASE_2: 'VerifierMsgType'
    KEX_SECRETS: 'VerifierMsgType'
    MASTER_SECRETS: 'VerifierMsgType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

@dataclass(frozen=True)
class ServerHandshakeTxProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('server_hello','encrypted_extensions','certificate','cert_verify','server_finished',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,)
    server_hello: tls13_spec.Record
    encrypted_extensions: tls13_spec.Record
    certificate: tls13_spec.Record
    cert_verify: tls13_spec.Record
    server_finished: tls13_spec.Record

    def replace(self, server_hello:tls13_spec.Record|None=None, encrypted_extensions:tls13_spec.Record|None=None, certificate:tls13_spec.Record|None=None, cert_verify:tls13_spec.Record|None=None, server_finished:tls13_spec.Record|None=None) -> Self:
        return type(self)((self.server_hello if server_hello is None else server_hello), (self.encrypted_extensions if encrypted_extensions is None else encrypted_extensions), (self.certificate if certificate is None else certificate), (self.cert_verify if cert_verify is None else cert_verify), (self.server_finished if server_finished is None else server_finished))

    @classmethod
    def create(cls,server_hello:tls13_spec.Record,encrypted_extensions:tls13_spec.Record,certificate:tls13_spec.Record,cert_verify:tls13_spec.Record,server_finished:tls13_spec.Record) -> Self:
        return cls(server_hello=server_hello, encrypted_extensions=encrypted_extensions, certificate=certificate, cert_verify=cert_verify, server_finished=server_finished)

    def uncreate(self) -> tuple[tls13_spec.Record, tls13_spec.Record, tls13_spec.Record, tls13_spec.Record, tls13_spec.Record]:
        return (self.server_hello, self.encrypted_extensions, self.certificate, self.cert_verify, self.server_finished)

class SeqServerHandshakeTxProverMsgData(spec._Sequence[ServerHandshakeTxProverMsgData]):
    _ITEM_TYPE = ServerHandshakeTxProverMsgData

    @classmethod
    def create(cls, items: Iterable[tuple[tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record]]) -> Self:
        return cls(ServerHandshakeTxProverMsgData.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqServerHandshakeTxProverMsgData(SeqServerHandshakeTxProverMsgData, Spec):
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

class Uint24(spec._Integral):
    _BYTE_LENGTH = 3

class B24SeqServerHandshakeTxProverMsgData(BoundedSeqServerHandshakeTxProverMsgData):
    _LENGTH_TYPES = (Uint24, )

class ServerHandshakeTxProverMsg(spec._SpecificSelectee[ProverMsgTypes, B24SeqServerHandshakeTxProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B24SeqServerHandshakeTxProverMsgData
    _SELECTOR = ProverMsgTypes.SERVER_HANDSHAKE_TX

    @classmethod
    def create(cls, items:Iterable[tuple[tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record]]) -> Self:
        return cls(data=B24SeqServerHandshakeTxProverMsgData.create(items))

    def uncreate(self) -> Iterable[tuple[tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record,tls13_spec.Record]]:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)

class F32Raw(spec._FixRaw):
    _BYTE_LENGTH = 32

class SeqF32Raw(spec._Sequence[F32Raw]):
    _ITEM_TYPE = F32Raw

    @classmethod
    def create(cls, items: Iterable[bytes]) -> Self:
        return cls(F32Raw.create(item) for item in items)

    def uncreate(self) -> Iterable[bytes]:
        for item in self:
            yield item.uncreate()

@dataclass(frozen=True)
class Hash1SProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('hashes',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SeqF32Raw,)
    hashes: SeqF32Raw

    def replace(self, hashes:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.hashes if hashes is None else SeqF32Raw.create(hashes)))

    @classmethod
    def create(cls,hashes:Iterable[bytes]) -> Self:
        return cls(hashes=SeqF32Raw.create(hashes))

    def uncreate(self) -> Iterable[bytes]:
        return (self.hashes.uncreate())

class BoundedHash1SProverMsgData(Hash1SProverMsgData, Spec):
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

class B24Hash1SProverMsgData(BoundedHash1SProverMsgData):
    _LENGTH_TYPES = (Uint24, )

class Hash1SProverMsg(spec._SpecificSelectee[ProverMsgTypes, B24Hash1SProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B24Hash1SProverMsgData
    _SELECTOR = ProverMsgTypes.HASH_1S

    @classmethod
    def create(cls, hashes:Iterable[bytes]) -> Self:
        return cls(data=B24Hash1SProverMsgData.create(hashes))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)

@dataclass(frozen=True)
class Hash4SProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('hashes',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SeqF32Raw,)
    hashes: SeqF32Raw

    def replace(self, hashes:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.hashes if hashes is None else SeqF32Raw.create(hashes)))

    @classmethod
    def create(cls,hashes:Iterable[bytes]) -> Self:
        return cls(hashes=SeqF32Raw.create(hashes))

    def uncreate(self) -> Iterable[bytes]:
        return (self.hashes.uncreate())

class BoundedHash4SProverMsgData(Hash4SProverMsgData, Spec):
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

class B24Hash4SProverMsgData(BoundedHash4SProverMsgData):
    _LENGTH_TYPES = (Uint24, )

class Hash4SProverMsg(spec._SpecificSelectee[ProverMsgTypes, B24Hash4SProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B24Hash4SProverMsgData
    _SELECTOR = ProverMsgTypes.HASH_4S

    @classmethod
    def create(cls, hashes:Iterable[bytes]) -> Self:
        return cls(data=B24Hash4SProverMsgData.create(hashes))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)

@dataclass(frozen=True)
class CommitmentProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('commitment',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (spec.Raw,)
    commitment: spec.Raw

    def replace(self, commitment:bytes|None=None) -> Self:
        return type(self)((self.commitment if commitment is None else spec.Raw.create(commitment)))

    @classmethod
    def create(cls,commitment:bytes) -> Self:
        return cls(commitment=spec.Raw.create(commitment))

    def uncreate(self) -> bytes:
        return (self.commitment.uncreate())

class BoundedCommitmentProverMsgData(CommitmentProverMsgData, Spec):
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

class B24CommitmentProverMsgData(BoundedCommitmentProverMsgData):
    _LENGTH_TYPES = (Uint24, )

class CommitmentProverMsg(spec._SpecificSelectee[ProverMsgTypes, B24CommitmentProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B24CommitmentProverMsgData
    _SELECTOR = ProverMsgTypes.COMMITMENT

    @classmethod
    def create(cls, commitment:bytes) -> Self:
        return cls(data=B24CommitmentProverMsgData.create(commitment))

    def uncreate(self) -> bytes:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)

@dataclass(frozen=True)
class KexSharesProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('kex_shares',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SeqF32Raw,)
    kex_shares: SeqF32Raw

    def replace(self, kex_shares:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.kex_shares if kex_shares is None else SeqF32Raw.create(kex_shares)))

    @classmethod
    def create(cls,kex_shares:Iterable[bytes]) -> Self:
        return cls(kex_shares=SeqF32Raw.create(kex_shares))

    def uncreate(self) -> Iterable[bytes]:
        return (self.kex_shares.uncreate())

class BoundedKexSharesProverMsgData(KexSharesProverMsgData, Spec):
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

class B24KexSharesProverMsgData(BoundedKexSharesProverMsgData):
    _LENGTH_TYPES = (Uint24, )

class KexSharesProverMsg(spec._SpecificSelectee[ProverMsgTypes, B24KexSharesProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B24KexSharesProverMsgData
    _SELECTOR = ProverMsgTypes.KEX_SHARES

    @classmethod
    def create(cls, kex_shares:Iterable[bytes]) -> Self:
        return cls(data=B24KexSharesProverMsgData.create(kex_shares))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)

@dataclass(frozen=True)
class ProofProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('proof',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (spec.Raw,)
    proof: spec.Raw

    def replace(self, proof:bytes|None=None) -> Self:
        return type(self)((self.proof if proof is None else spec.Raw.create(proof)))

    @classmethod
    def create(cls,proof:bytes) -> Self:
        return cls(proof=spec.Raw.create(proof))

    def uncreate(self) -> bytes:
        return (self.proof.uncreate())

class BoundedProofProverMsgData(ProofProverMsgData, Spec):
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

class B24ProofProverMsgData(BoundedProofProverMsgData):
    _LENGTH_TYPES = (Uint24, )

class ProofProverMsg(spec._SpecificSelectee[ProverMsgTypes, B24ProofProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B24ProofProverMsgData
    _SELECTOR = ProverMsgTypes.PROOF

    @classmethod
    def create(cls, proof:bytes) -> Self:
        return cls(data=B24ProofProverMsgData.create(proof))

    def uncreate(self) -> bytes:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)

@dataclass(frozen=True)
class ClientRandomsProverMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('cli_randoms',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SeqF32Raw,)
    cli_randoms: SeqF32Raw

    def replace(self, cli_randoms:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.cli_randoms if cli_randoms is None else SeqF32Raw.create(cli_randoms)))

    @classmethod
    def create(cls,cli_randoms:Iterable[bytes]) -> Self:
        return cls(cli_randoms=SeqF32Raw.create(cli_randoms))

    def uncreate(self) -> Iterable[bytes]:
        return (self.cli_randoms.uncreate())

class BoundedClientRandomsProverMsgData(ClientRandomsProverMsgData, Spec):
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

class B24ClientRandomsProverMsgData(BoundedClientRandomsProverMsgData):
    _LENGTH_TYPES = (Uint24, )

class ClientRandomsProverMsg(spec._SpecificSelectee[ProverMsgTypes, B24ClientRandomsProverMsgData]):
    _SELECT_TYPE = ProverMsgType
    _DATA_TYPE = B24ClientRandomsProverMsgData
    _SELECTOR = ProverMsgTypes.CLIENT_RANDOMS

    @classmethod
    def create(cls, cli_randoms:Iterable[bytes]) -> Self:
        return cls(data=B24ClientRandomsProverMsgData.create(cli_randoms))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'ProverMsg':
        return ProverMsg(self)


ProverMsgVariant = ServerHandshakeTxProverMsg | Hash1SProverMsg | Hash4SProverMsg | CommitmentProverMsg | KexSharesProverMsg | ProofProverMsg | ClientRandomsProverMsg

class ProverMsg(spec._Select[ProverMsgTypes]):
    _SELECT_TYPE = ProverMsgType
    _GENERIC_TYPE = None
    _SELECTEES = {ProverMsgTypes.SERVER_HANDSHAKE_TX:ServerHandshakeTxProverMsg, ProverMsgTypes.HASH_1S:Hash1SProverMsg, ProverMsgTypes.HASH_4S:Hash4SProverMsg, ProverMsgTypes.COMMITMENT:CommitmentProverMsg, ProverMsgTypes.KEX_SHARES:KexSharesProverMsg, ProverMsgTypes.PROOF:ProofProverMsg, ProverMsgTypes.CLIENT_RANDOMS:ClientRandomsProverMsg}

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

class BoundedSeqF32Raw(SeqF32Raw, Spec):
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

class B16SeqF32Raw(BoundedSeqF32Raw):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class KexSharesPhase1VerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('kex_shares',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B16SeqF32Raw,)
    kex_shares: B16SeqF32Raw

    def replace(self, kex_shares:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.kex_shares if kex_shares is None else B16SeqF32Raw.create(kex_shares)))

    @classmethod
    def create(cls,kex_shares:Iterable[bytes]) -> Self:
        return cls(kex_shares=B16SeqF32Raw.create(kex_shares))

    def uncreate(self) -> Iterable[bytes]:
        return (self.kex_shares.uncreate())

class BoundedKexSharesPhase1VerifierMsgData(KexSharesPhase1VerifierMsgData, Spec):
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

class B16KexSharesPhase1VerifierMsgData(BoundedKexSharesPhase1VerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class KexSharesPhase1VerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16KexSharesPhase1VerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16KexSharesPhase1VerifierMsgData
    _SELECTOR = VerifierMsgTypes.KEX_SHARES_PHASE_1

    @classmethod
    def create(cls, kex_shares:Iterable[bytes]) -> Self:
        return cls(data=B16KexSharesPhase1VerifierMsgData.create(kex_shares))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

@dataclass(frozen=True)
class HandshakeKeysVerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('chts','shts',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (F32Raw,F32Raw,)
    chts: F32Raw
    shts: F32Raw

    def replace(self, chts:bytes|None=None, shts:bytes|None=None) -> Self:
        return type(self)((self.chts if chts is None else F32Raw.create(chts)), (self.shts if shts is None else F32Raw.create(shts)))

    @classmethod
    def create(cls,chts:bytes,shts:bytes) -> Self:
        return cls(chts=F32Raw.create(chts), shts=F32Raw.create(shts))

    def uncreate(self) -> tuple[bytes, bytes]:
        return (self.chts.uncreate(), self.shts.uncreate())

class SeqHandshakeKeysVerifierMsgData(spec._Sequence[HandshakeKeysVerifierMsgData]):
    _ITEM_TYPE = HandshakeKeysVerifierMsgData

    @classmethod
    def create(cls, items: Iterable[tuple[bytes,bytes]]) -> Self:
        return cls(HandshakeKeysVerifierMsgData.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[bytes,bytes]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqHandshakeKeysVerifierMsgData(SeqHandshakeKeysVerifierMsgData, Spec):
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

class B16SeqHandshakeKeysVerifierMsgData(BoundedSeqHandshakeKeysVerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class HandshakeKeysVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16SeqHandshakeKeysVerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16SeqHandshakeKeysVerifierMsgData
    _SELECTOR = VerifierMsgTypes.HANDSHAKE_KEYS

    @classmethod
    def create(cls, items:Iterable[tuple[bytes,bytes]]) -> Self:
        return cls(data=B16SeqHandshakeKeysVerifierMsgData.create(items))

    def uncreate(self) -> Iterable[tuple[bytes,bytes]]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

@dataclass(frozen=True)
class ApplicationKeysVerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('cats','sats',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (F32Raw,F32Raw,)
    cats: F32Raw
    sats: F32Raw

    def replace(self, cats:bytes|None=None, sats:bytes|None=None) -> Self:
        return type(self)((self.cats if cats is None else F32Raw.create(cats)), (self.sats if sats is None else F32Raw.create(sats)))

    @classmethod
    def create(cls,cats:bytes,sats:bytes) -> Self:
        return cls(cats=F32Raw.create(cats), sats=F32Raw.create(sats))

    def uncreate(self) -> tuple[bytes, bytes]:
        return (self.cats.uncreate(), self.sats.uncreate())

class SeqApplicationKeysVerifierMsgData(spec._Sequence[ApplicationKeysVerifierMsgData]):
    _ITEM_TYPE = ApplicationKeysVerifierMsgData

    @classmethod
    def create(cls, items: Iterable[tuple[bytes,bytes]]) -> Self:
        return cls(ApplicationKeysVerifierMsgData.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[bytes,bytes]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqApplicationKeysVerifierMsgData(SeqApplicationKeysVerifierMsgData, Spec):
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

class B16SeqApplicationKeysVerifierMsgData(BoundedSeqApplicationKeysVerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class ApplicationKeysVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16SeqApplicationKeysVerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16SeqApplicationKeysVerifierMsgData
    _SELECTOR = VerifierMsgTypes.APPLICATION_KEYS

    @classmethod
    def create(cls, items:Iterable[tuple[bytes,bytes]]) -> Self:
        return cls(data=B16SeqApplicationKeysVerifierMsgData.create(items))

    def uncreate(self) -> Iterable[tuple[bytes,bytes]]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

@dataclass(frozen=True)
class KexSharePhase2VerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('kex_share',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (F32Raw,)
    kex_share: F32Raw

    def replace(self, kex_share:bytes|None=None) -> Self:
        return type(self)((self.kex_share if kex_share is None else F32Raw.create(kex_share)))

    @classmethod
    def create(cls,kex_share:bytes) -> Self:
        return cls(kex_share=F32Raw.create(kex_share))

    def uncreate(self) -> bytes:
        return (self.kex_share.uncreate())

class BoundedKexSharePhase2VerifierMsgData(KexSharePhase2VerifierMsgData, Spec):
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

class B16KexSharePhase2VerifierMsgData(BoundedKexSharePhase2VerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class KexSharePhase2VerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16KexSharePhase2VerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16KexSharePhase2VerifierMsgData
    _SELECTOR = VerifierMsgTypes.KEX_SHARE_PHASE_2

    @classmethod
    def create(cls, kex_share:bytes) -> Self:
        return cls(data=B16KexSharePhase2VerifierMsgData.create(kex_share))

    def uncreate(self) -> bytes:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

@dataclass(frozen=True)
class KexSecretsVerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('kex_secrets',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SeqF32Raw,)
    kex_secrets: SeqF32Raw

    def replace(self, kex_secrets:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.kex_secrets if kex_secrets is None else SeqF32Raw.create(kex_secrets)))

    @classmethod
    def create(cls,kex_secrets:Iterable[bytes]) -> Self:
        return cls(kex_secrets=SeqF32Raw.create(kex_secrets))

    def uncreate(self) -> Iterable[bytes]:
        return (self.kex_secrets.uncreate())

class BoundedKexSecretsVerifierMsgData(KexSecretsVerifierMsgData, Spec):
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

class B16KexSecretsVerifierMsgData(BoundedKexSecretsVerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class KexSecretsVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16KexSecretsVerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16KexSecretsVerifierMsgData
    _SELECTOR = VerifierMsgTypes.KEX_SECRETS

    @classmethod
    def create(cls, kex_secrets:Iterable[bytes]) -> Self:
        return cls(data=B16KexSecretsVerifierMsgData.create(kex_secrets))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)

class BoundedRaw(spec.Raw, Spec):
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

class SeqB8Raw(spec._Sequence[B8Raw]):
    _ITEM_TYPE = B8Raw

    @classmethod
    def create(cls, items: Iterable[bytes]) -> Self:
        return cls(B8Raw.create(item) for item in items)

    def uncreate(self) -> Iterable[bytes]:
        for item in self:
            yield item.uncreate()

@dataclass(frozen=True)
class MasterSecretsVerifierMsgData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('secrets',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SeqB8Raw,)
    secrets: SeqB8Raw

    def replace(self, secrets:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.secrets if secrets is None else SeqB8Raw.create(secrets)))

    @classmethod
    def create(cls,secrets:Iterable[bytes]) -> Self:
        return cls(secrets=SeqB8Raw.create(secrets))

    def uncreate(self) -> Iterable[bytes]:
        return (self.secrets.uncreate())

class BoundedMasterSecretsVerifierMsgData(MasterSecretsVerifierMsgData, Spec):
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

class B16MasterSecretsVerifierMsgData(BoundedMasterSecretsVerifierMsgData):
    _LENGTH_TYPES = (Uint16, )

class MasterSecretsVerifierMsg(spec._SpecificSelectee[VerifierMsgTypes, B16MasterSecretsVerifierMsgData]):
    _SELECT_TYPE = VerifierMsgType
    _DATA_TYPE = B16MasterSecretsVerifierMsgData
    _SELECTOR = VerifierMsgTypes.MASTER_SECRETS

    @classmethod
    def create(cls, secrets:Iterable[bytes]) -> Self:
        return cls(data=B16MasterSecretsVerifierMsgData.create(secrets))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

    def parent(self) -> 'VerifierMsg':
        return VerifierMsg(self)


VerifierMsgVariant = KexSharesPhase1VerifierMsg | HandshakeKeysVerifierMsg | ApplicationKeysVerifierMsg | KexSharePhase2VerifierMsg | KexSecretsVerifierMsg | MasterSecretsVerifierMsg

class VerifierMsg(spec._Select[VerifierMsgTypes]):
    _SELECT_TYPE = VerifierMsgType
    _GENERIC_TYPE = None
    _SELECTEES = {VerifierMsgTypes.KEX_SHARES_PHASE_1:KexSharesPhase1VerifierMsg, VerifierMsgTypes.HANDSHAKE_KEYS:HandshakeKeysVerifierMsg, VerifierMsgTypes.APPLICATION_KEYS:ApplicationKeysVerifierMsg, VerifierMsgTypes.KEX_SHARE_PHASE_2:KexSharePhase2VerifierMsg, VerifierMsgTypes.KEX_SECRETS:KexSecretsVerifierMsg, VerifierMsgTypes.MASTER_SECRETS:MasterSecretsVerifierMsg}

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
