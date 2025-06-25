""""
Specifications for messages sent over the network between the prover and verifier, allowing messages to be converted
to and from Python objects. based on the framework in spec.py. These specs are all unique to the TLS attestation
protocol, and don't depend on the format of TLS.
"""

from enum import IntEnum

from spec import Struct, Bounded, Raw, Sequence, Select, ParseError, Spec, force_write, force_read, FixedSize
from tls13_spec import Handshake, _FixedEnum, Record


class BoundedSequence(Spec):
    """For sequences where each element has the same length"""

    def __init__(self, elemlenlen, listlenlen, typ):
        self._elemlenlen = elemlenlen
        self._listlenlen = listlenlen
        self._inner = typ

    def prepack(self, obj, *args):
        if args:
            items = [obj] + args
        else:
            items = obj
        return [self._inner.prepack(item) for item in items]

    def _pack(self, items):
        raw = [self._inner.pack(item) for item in items]
        self._listlen = len(raw)
        self._elemlen = len(raw[0])
        if any([len(elem) != self._elemlen for elem in raw[1:]]):
            raise ParseError("elements must all be the same length")
        return b''.join(self._inner.pack(item) for item in items)

    def _pack_to(self, dest, obj):
        raw = self._pack(obj)
        force_write(dest, self._listlen.to_bytes(self._listlenlen))
        force_write(dest, self._elemlen.to_bytes(self._elemlenlen))
        force_write(dest, raw)

    def _unpack_from(self, src):
        try:
            listlen = int.from_bytes(force_read(src, self._listlenlen))
        except ValueError as e:
            raise ParseError("could not read BoundedSequence list length") from e
        try:
            elemlen = int.from_bytes(force_read(src, self._elemlenlen))
        except ValueError as e:
            raise ParseError("could not read BoundedSequence element length") from e
        result = []
        try:
            for _ in range(listlen):
                raw = force_read(src, elemlen)
                result.append(self._inner._unpack(raw))
        except ValueError as e:
            raise ParseError(f"could not read element in BoundedSequence") from e
        return result


class ProverMsgType(IntEnum, metaclass=_FixedEnum, bytelen=1):
    # TODO: refactor these types. Should have one thing for hash arrays, one thing for single hashes, etc
    SERVER_HANDSHAKE_TX = 1
    HASH_1              = 2
    HASH_4              = 3
    COMMITMENT          = 4
    DH_SHARES           = 5
    PROOF               = 6
    CLIENT_RANDOM       = 7

class VerifierMsgType(IntEnum, metaclass=_FixedEnum, bytelen=1):
    DH_SHARE_PHASE_1  = 1
    HANDSHAKE_KEYS    = 2
    APPLICATION_KEYS  = 3
    DH_SHARE_PHASE_2  = 4
    DH_SECRETS        = 5
    DH_SECRET_PHASE_2 = 6
    MASTER_SECRETS    = 99 # for testing purposes only!

def _prover_msg_spec(typ):
    bodylen = 1
    match typ:
        case ProverMsgType.SERVER_HANDSHAKE_TX:
            bodyspec = Sequence(Bounded(2, Struct(
                server_hello=Record,
                encrypted_extensions=Record,
                certificate=Record,
                cert_verify=Record,
                server_finished=Record
            )))
            bodylen = 2
        case ProverMsgType.HASH_1 | ProverMsgType.HASH_4:
            return BoundedSequence(1, 1, Raw)
        case ProverMsgType.COMMITMENT | ProverMsgType.CLIENT_RANDOM | ProverMsgType.PROOF:
            bodyspec = Struct(val = Raw)
        case ProverMsgType.DH_SHARES:
            bodyspec = BoundedSequence(1, 1, Raw)
        case _:
            raise ParseError(f'unsupported message type {typ}')
    return Bounded(bodylen, bodyspec)

def _verifier_msg_spec(typ):
    bodylen = 1
    match typ:
        case VerifierMsgType.DH_SHARE_PHASE_1 | VerifierMsgType.DH_SECRET_PHASE_2:
            return BoundedSequence(1, 1, Raw)
        case VerifierMsgType.HANDSHAKE_KEYS:
            bodyspec = Sequence(Struct(chts = FixedSize(32), shts = FixedSize(32)))
        case VerifierMsgType.APPLICATION_KEYS:
            bodyspec = Sequence(Struct(cats = FixedSize(32), sats = FixedSize(32)))
        case VerifierMsgType.DH_SHARE_PHASE_2:
            bodyspec = Raw
        case VerifierMsgType.MASTER_SECRETS:
            return BoundedSequence(1, 1, Raw)
        case _:
            raise ParseError(f'unsupported message type {typ}')
    return Bounded(bodylen, bodyspec)

ProverMsg = Select(
    typ = ProverMsgType,
    body = _prover_msg_spec
)

VerifierMsg = Select(
    typ = VerifierMsgType,
    body = _verifier_msg_spec
)

