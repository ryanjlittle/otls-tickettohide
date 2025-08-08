from enum import IntEnum

from mpc_tls import HandshakeSecretTrustedParty, MasterSecretTrustedParty
from proof_common import *
from proof_connections import VerifierConnection
from proof_spec import TicketsVerifierMsg, KexSharesProverMsg, HandshakeSecretsVerifierMsg, MasterSecretsVerifierMsg
from prover_crypto import ProverSecrets, ProverCryptoManager
from tls_common import *
from tls_server import ServerID


class ProverState(IntEnum):
    INIT              = 0
    GET_ECH           = 1
    WAIT_TICKETS      = 2
    WAIT_SH           = 3
    WAIT_2PC_HS_HKDF  = 4
    WAIT_2PC_APP_HKDF = 5
    WAIT_2PC_ENC      = 6
    WAIT_RESPONSE     = 7
    WAIT_KEY_SHARES   = 8
    DONE              = 9

    def __str__(self):
        return self.name

    def next(self):
        try:
            return ProverState(self + 1)
        except ValueError:
            raise StopIteration('no next state')


class Prover:
    servers: list[ServerID]
    secrets: ProverSecrets
    verifier_connection: VerifierConnection
    crypto_manager: ProverCryptoManager
    state: ProverState = ProverState.INIT
    rseed: int|None = None

    def __init__(self,
                 servers: list[ServerID],
                 secrets: ProverSecrets,
                 hostname: str = 'localhost',
                 port: int = 9000,
                 rseed: int|None = None,
                 ) -> None:
        self.servers = servers
        self.secrets = secrets
        self.rseed = rseed
        self.verifier_connection = VerifierConnection(hostname, port)
        self.crypto_manager = ProverCryptoManager(servers, secrets, rseed)

    def __enter__(self) -> Self:
        self.crypto_manager.create_sockets()
        self.verifier_connection.create_socket()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.crypto_manager.close_sockets()
        self.verifier_connection.close()

    @property
    def listening(self) -> bool:
        return self.verifier_connection.listening

    def increment_state(self):
        self.state = self.state.next()

    @property
    def handler(self) -> dict[ProverState, Callable]:
        return {
            ProverState.INIT                : self.preprocess,
            ProverState.GET_ECH             : self.get_ech_configs,
            ProverState.WAIT_TICKETS        : self.process_tickets,
            ProverState.WAIT_SH             : self.process_sh,
            ProverState.WAIT_2PC_HS_HKDF    : self.twopc_handshake_hkdf,
            ProverState.WAIT_2PC_APP_HKDF   : self.twopc_application_hkdf,
            ProverState.WAIT_2PC_ENC        : self.twopc_encryption,
            ProverState.WAIT_RESPONSE       : self.process_response,
            ProverState.WAIT_KEY_SHARES     : self.process_key_share,
        }


    def run(self) -> None:
        assert self.state == ProverState.INIT
        while self.state < ProverState.DONE:
            self.handler[self.state]()
        logger.info('prover finished')

    def preprocess(self) -> None:
        assert self.state == ProverState.INIT
        # TODO: we'll do MPC preprocessing here later
        self.increment_state()

    def get_ech_configs(self) -> None:
        assert self.state == ProverState.GET_ECH
        self.crypto_manager.obtain_ech_configs()
        logger.info('prover obtained all ECH configs')

        self.increment_state()
        self.verifier_connection.listen()

    def process_tickets(self) -> None:
        assert self.state == ProverState.WAIT_TICKETS
        msg = self.verifier_connection.recv_msg()
        if not isinstance(msg, TicketsVerifierMsg):
            raise ProverError(f'received unexpected message type: {msg.typ}')

        self.crypto_manager.build_ech_configs(list(msg.data))
        self.increment_state()

    def process_sh(self) -> None:
        assert self.state == ProverState.WAIT_SH
        self.crypto_manager.send_and_recv_hellos()

        kex_shares = self.crypto_manager.server_key_shares
        msg = KexSharesProverMsg.create(kex_shares)
        self.verifier_connection.send_msg(msg)

        self.increment_state()

    def twopc_handshake_hkdf(self) -> None:
        assert self.state == ProverState.WAIT_2PC_HS_HKDF
        # TODO: replace with actual MPC
        msg = self.verifier_connection.recv_msg()
        if not isinstance(msg, HandshakeSecretsVerifierMsg):
            raise ProverError(f'received unexpected message type: {msg.typ}')
        trusted_party = HandshakeSecretTrustedParty()
        hash_val = self.crypto_manager.real_server_handshake_hash
        trusted_party.prover_input = (self.secrets.index, hash_val)
        trusted_party.verifier_input = list(msg.data.uncreate())
        trusted_party.compute()
        handshake_secs, chts, shts = trusted_party.prover_output

        self.crypto_manager.set_dummy_handshake_secets(handshake_secs)
        self.crypto_manager.set_chts_shts(chts, shts)

        self.crypto_manager.finish_handshakes()

        self.increment_state()

    def twopc_application_hkdf(self) -> None:
        assert self.state == ProverState.WAIT_2PC_APP_HKDF
        # TODO: replace with actual MPC
        msg = self.verifier_connection.recv_msg()
        if not isinstance(msg, MasterSecretsVerifierMsg):
            raise ProverError(f'received unexpected message type: {msg.typ}')
        trusted_party = MasterSecretTrustedParty()
        hash_val = self.crypto_manager.real_server_application_hash
        trusted_party.prover_input = (self.secrets.index, hash_val)
        trusted_party.verifier_input = list(msg.data.uncreate())
        trusted_party.compute()
        secrets, ck_share, civ, sk_share, siv = trusted_party.prover_output

        # check received master secrets against locally computed values
        computed_secrets = self.crypto_manager.dummy_master_secrets
        for i, (received_sec, comptued_sec) in enumerate(zip(secrets, computed_secrets)):
            if i == self.secrets.index:
                continue
            if received_sec != comptued_sec:
                raise ProverError('received master secret mismatch')

        logger.info('dummy master secrets verified')

        self.increment_state()

    def twopc_encryption(self) -> None:
        assert self.state == ProverState.WAIT_2PC_ENC
        self.increment_state()

    def process_response(self) -> None:
        assert self.state == ProverState.WAIT_RESPONSE
        self.increment_state()

    def process_key_share(self) -> None:
        assert self.state == ProverState.WAIT_KEY_SHARES
        self.increment_state()
