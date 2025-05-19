""""
Specifications for messages sent over the network between the prover and verifier, allowing messages to be converted
to and from Python objects. based on the framework in spec.py. These specs are all unique to the TLS attestation
protocol, and don't depend on the format of TLS.
"""

from enum import IntEnum

from spec import Struct, Bounded, Raw, Sequence, Select, ParseError
from tls13_spec import Handshake, _FixedEnum


class ProverMsgType(IntEnum, metaclass=_FixedEnum, bytelen=1):
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

def _prover_msg_spec(type):
    bodylen = 1
    match type:
        case ProverMsgType.SERVER_HANDSHAKE_TX:
            bodyspec = Struct(
                server_hello=Handshake,
                encrypted_extensions=Handshake,
                certificate=Handshake,
                cert_verify=Handshake,
                server_finished=Handshake
            )
            bodylen = 2
        case ProverMsgType.HASH_1 | ProverMsgType.HASH_4 | ProverMsgType.COMMITMENT | ProverMsgType.CLIENT_RANDOM | ProverMsgType.PROOF:
            bodyspec = Raw
        case ProverMsgType.DH_SHARES:
            bodyspec = Raw # todo
        case _:
            raise ParseError(f'unsupported message type {type}')
    return Bounded(bodylen, bodyspec)

def _verifier_msg_spec(type):
    bodylen = 1
    match type:
        case VerifierMsgType.DH_SHARE_PHASE_1 | VerifierMsgType.DH_SECRET_PHASE_2:
            bodyspec = Raw
        case VerifierMsgType.HANDSHAKE_KEYS:
            bodyspec = Struct(chts = Raw, shts = Raw)
        case VerifierMsgType.APPLICATION_KEYS:
            bodyspec = Struct(cats = Raw, sats = Raw)
        case VerifierMsgType.DH_SECRET_PHASE_2:
            bodyspec = Sequence(Struct(secret = Raw))
        case _:
            raise ParseError(f'unsupported message type {type}')
    return Bounded(bodylen, bodyspec)

ProverMsg = Select(
    type = ProverMsgType,
    body = _prover_msg_spec
)

VerifierMsg = Select(
    type = VerifierMsgType,
    body = _verifier_msg_spec
)