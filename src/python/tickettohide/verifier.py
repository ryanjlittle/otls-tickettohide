from enum import IntEnum

from tls13.tls13_spec import ClientOptions
from tls13.tls_common import *
from tls13.tls_server import ServerID

from tickettohide.mpc_tls import VerifierMPC
from tickettohide.proof_common import VerifierError
from tickettohide.proof_connections import ProverConnection
from tickettohide.proof_spec import TicketsVerifierMsg, KexSharesProverMsg
from tickettohide.prover_crypto import DEFAULT_PROVER_CLIENT_OPTIONS
from tickettohide.verifier_crypto import VerifierCryptoManager


class VerifierState(IntEnum):
    INIT              = 0
    GET_TICKETS       = 1
    CONNECT           = 2
    WAIT_KEX_SHARES   = 3
    MPC_HS_HKDF       = 4
    MPC_APP_HKDF      = 5
    MPC_ENC           = 6
    REVEAL_AND_PROVE  = 7
    FINALIZE          = 8
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
    mpc_manager: VerifierMPC
    options: ClientOptions = DEFAULT_PROVER_CLIENT_OPTIONS
    state: VerifierState = VerifierState.INIT
    rseed: int|None = None

    def __init__(self,
                 servers: list[ServerID],
                 prover_host: str = 'localhost',
                 prover_port: int = 8000,
                 mpc_port: int = 8001,
                 options: ClientOptions = DEFAULT_PROVER_CLIENT_OPTIONS,
                 rseed: int|None = None
        ) -> None:
        self.servers = servers
        self.prover_conn = ProverConnection(prover_host, prover_port)
        self.crypto_manager = VerifierCryptoManager(servers, options, rseed)
        self.mpc_manager = VerifierMPC(len(servers), mpc_port)
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
            VerifierState.MPC_HS_HKDF       : self.twopc_handshake_hkdf,
            VerifierState.MPC_APP_HKDF      : self.twopc_application_hkdf,
            VerifierState.MPC_ENC           : self.twopc_encryption,
            VerifierState.REVEAL_AND_PROVE  : self.reveal_and_prove,
            VerifierState.FINALIZE          : self.finalize,
        }

    def run(self):
        assert self.state == VerifierState.INIT
        while self.state < VerifierState.DONE:
            self.handler[self.state]()
        logger.info('verifier finished')

    def preprocess(self) -> None:
        assert self.state == VerifierState.INIT
        # self.mpc_manager.begin()
        self.increment_state()

    def get_tickets(self) -> None:
        assert self.state == VerifierState.GET_TICKETS
        self.crypto_manager.obtain_tickets()
        logger.info('verifier obtained all tickets')
        self.increment_state()

    def connect(self) -> None:
        assert self.state == VerifierState.CONNECT
        self.prover_conn.connect()
        self.mpc_manager.begin()

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
        assert self.state == VerifierState.MPC_HS_HKDF

        self.mpc_manager.wait_until_connected()
        self.mpc_manager.compute_handshake_secrets(self.crypto_manager.handshake_secrets)

        # Trusted party version

        #hs_secrets = self.crypto_manager.handshake_secrets
        #msg = HandshakeSecretsVerifierMsg.create(hs_secrets)
        #self.prover_conn.send_msg(msg)
        self.increment_state()

    def twopc_application_hkdf(self) -> None:
        assert self.state == VerifierState.MPC_APP_HKDF

        self.mpc_manager.compute_master_secrets(self.crypto_manager.master_secrets)

        # Trusted party version

        # master_secrets = self.crypto_manager.master_secrets
        # msg = MasterSecretsVerifierMsg.create(master_secrets)
        # self.prover_conn.send_msg(msg)

        self.increment_state()

    def twopc_encryption(self) -> None:
        assert self.state == VerifierState.MPC_ENC

        self.mpc_manager.compute_encryption()

        self.increment_state()

    def reveal_and_prove(self) -> None:
        assert self.state == VerifierState.REVEAL_AND_PROVE
        self.mpc_manager.reveal_and_prove()
        self.increment_state()

    def finalize(self) -> None:
        assert self.state == VerifierState.FINALIZE
        exit_code = self.mpc_manager.finish()
        if exit_code != 0:
            raise VerifierError(f'Low-level verifier failed with exit code {exit_code}')
        self.increment_state()
