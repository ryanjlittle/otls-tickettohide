from enum import IntEnum

from proof_common import VerifierError
from proof_connections import ProverConnection
from proof_spec import TicketsVerifierMsg, KexSharesProverMsg, \
    HandshakeSecretsVerifierMsg, MasterSecretsVerifierMsg, CommitmentsProverMsg, AppKeySharesVerifierMsg
from prover_crypto import DEFAULT_PROVER_CLIENT_OPTIONS
from tls13_spec import ClientOptions
from tls_common import *
from tls_server import ServerID
from verifier_crypto import VerifierCryptoManager


class VerifierState(IntEnum):
    INIT              = 0
    GET_TICKETS       = 1
    CONNECT           = 2
    WAIT_KEX_SHARES   = 3
    WAIT_2PC_HS_HKDF  = 4
    WAIT_2PC_APP_HKDF = 5
    WAIT_2PC_ENC      = 6
    WAIT_COMMITMENT   = 7
    WAIT_PROOF        = 8
    DONE              = 9

    def __str__(self):
        return self.name

    def next(self):
        try:
            return VerifierState(self + 1)
        except ValueError:
            raise StopIteration('no next state')


class Verifier:
    servers: list[ServerID]
    prover_conn: ProverConnection
    crypto_manager: VerifierCryptoManager
    options: ClientOptions = DEFAULT_PROVER_CLIENT_OPTIONS
    state: VerifierState = VerifierState.INIT
    rseed: int|None = None

    def __init__(self,
                 servers: list[ServerID],
                 prover_host: str = 'localhost',
                 prover_port: int = 9000,
                 options: ClientOptions = DEFAULT_PROVER_CLIENT_OPTIONS,
                 rseed: int|None = None
        ) -> None:
        self.servers = servers
        self.prover_conn = ProverConnection(prover_host, prover_port)
        self.crypto_manager = VerifierCryptoManager(servers, options, rseed)
        self.options = options
        self.state = VerifierState.INIT

    def __enter__(self) -> Self:
        self.prover_conn.create_socket()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.prover_conn.close()

    def increment_state(self) -> None:
        self.state = self.state.next()
        logger.info(f'incremented state, now in {self.state}')

    @property
    def handler(self) -> dict[VerifierState, Callable]:
        return {
            VerifierState.INIT              : self.preprocess,
            VerifierState.GET_TICKETS       : self.get_tickets,
            VerifierState.CONNECT           : self.connect,
            VerifierState.WAIT_KEX_SHARES   : self.process_kex_shares,
            VerifierState.WAIT_2PC_HS_HKDF  : self.twopc_handshake_hkdf,
            VerifierState.WAIT_2PC_APP_HKDF : self.twopc_application_hkdf,
            VerifierState.WAIT_2PC_ENC      : self.twopc_encryption,
            VerifierState.WAIT_COMMITMENT   : self.process_commitment,
            VerifierState.WAIT_PROOF        : self.process_proof
        }

    def run(self):
        assert self.state == VerifierState.INIT
        while self.state < VerifierState.DONE:
            self.handler[self.state]()
        logger.info('verifier finished')

    def preprocess(self) -> None:
        assert self.state == VerifierState.INIT
        # TODO: we'll do MPC preprocessing here later
        self.increment_state()

    def get_tickets(self) -> None:
        assert self.state == VerifierState.GET_TICKETS
        self.crypto_manager.obtain_tickets()
        logger.info('verifier obtained all tickets')
        self.increment_state()

    def connect(self) -> None:
        assert self.state == VerifierState.CONNECT
        self.prover_conn.connect()

        hostnames = [serv.hostname for serv in self.servers]
        tickets = self.crypto_manager.redacted_tickets
        binder_keys = self.crypto_manager.binder_keys
        kex_shares = self.crypto_manager.kex_shares

        msg = TicketsVerifierMsg.create(list(zip(hostnames, tickets, binder_keys, kex_shares)))
        self.prover_conn.send_msg(msg)

        self.increment_state()

    def process_kex_shares(self) -> None:

        assert self.state == VerifierState.WAIT_KEX_SHARES
        msg = self.prover_conn.recv_msg()
        if not isinstance(msg, KexSharesProverMsg):
            raise VerifierError(f'received unexpected message type: {msg.typ}')

        shares = [[share.uncreate() for share in shares] for shares in msg.data]
        self.crypto_manager.key_exchange(shares)
        self.increment_state()

    def twopc_handshake_hkdf(self) -> None:
        assert self.state == VerifierState.WAIT_2PC_HS_HKDF
        # TODO: replace this with actual MPC
        hs_secrets = self.crypto_manager.handshake_secrets
        msg = HandshakeSecretsVerifierMsg.create(hs_secrets)
        self.prover_conn.send_msg(msg)
        self.increment_state()

    def twopc_application_hkdf(self) -> None:
        assert self.state == VerifierState.WAIT_2PC_APP_HKDF
        # TODO: replace this with actual MPC
        master_secrets = self.crypto_manager.master_secrets
        msg = MasterSecretsVerifierMsg.create(master_secrets)
        self.prover_conn.send_msg(msg)
        self.increment_state()

    def twopc_encryption(self) -> None:
        assert self.state == VerifierState.WAIT_2PC_ENC
        # TODO: replace this with actual MPC
        self.increment_state()

    def process_commitment(self) -> None:
        assert self.state == VerifierState.WAIT_COMMITMENT
        msg = self.prover_conn.recv_msg()
        if not isinstance(msg, CommitmentsProverMsg):
            raise VerifierError(f'received unexpected message type: {msg.typ}')

        self.crypto_manager.query_commitment = msg.data.query_commitment
        self.crypto_manager.response_commitments = [commit.uncreate() for commit in msg.data.response_commitments]

        # TODO: replace with real shares generated via MPC
        client_key_share = b'\x00'*32
        server_key_share = b'\x00'*32

        msg = AppKeySharesVerifierMsg.create(client_key_share=client_key_share, server_key_share=server_key_share)
        self.prover_conn.send_msg(msg)

        self.increment_state()

    def process_proof(self) -> None:
        assert self.state == VerifierState.WAIT_PROOF
        # TODO
        self.increment_state()