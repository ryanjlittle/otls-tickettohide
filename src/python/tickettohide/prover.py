from enum import IntEnum

from tls13.tls13_spec import ContentType, RecordHeader
from tls13.tls_common import *
from tls13.tls_crypto import get_cipher_alg
from tls13.tls_records import InnerPlaintext, DEFAULT_LEGACY_VERSION
from tls13.tls_server import ServerID

from tickettohide.mpc_tls import ProverMPC
from tickettohide.proof_common import *
from tickettohide.proof_connections import VerifierConnection
from tickettohide.proof_spec import TicketsVerifierMsg, KexSharesProverMsg
from tickettohide.prover_crypto import ProverSecrets, ProverCryptoManager


class ProverState(IntEnum):
    INIT              = 0
    GET_ECH           = 1
    WAIT_TICKETS      = 2
    WAIT_SH           = 3
    MPC_HS_HKDF       = 4
    MPC_APP_HKDF      = 5
    MPC_ENC           = 6
    WAIT_RESPONSE     = 7
    REVEAL_AND_PROVE  = 8
    DECRYPT_ALL       = 9
    DONE              = 10

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
    mpc_manager: ProverMPC
    state: ProverState = ProverState.INIT
    rseed: int|None = None
    verifier_client_key_share: bytes # TODO: this is for testing only
    verifier_server_key_share: bytes # TODO: this is for testing only

    def __init__(self,
                 servers: list[ServerID],
                 secrets: ProverSecrets,
                 hostname: str = 'localhost',
                 port: int = 8000,
                 mpc_port: int = 8001,
                 rseed: int|None = None,
                 ) -> None:
        self.servers = servers
        self.secrets = secrets
        self.rseed = rseed
        self.verifier_connection = VerifierConnection(hostname, port)
        self.crypto_manager = ProverCryptoManager(servers, secrets, rseed)
        self.mpc_manager = ProverMPC(len(servers), mpc_port)

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
        logger.info(f'incremented state, now in {self.state}')

    @property
    def handler(self) -> dict[ProverState, Callable]:
        return {
            ProverState.INIT             : self.preprocess,
            ProverState.GET_ECH          : self.get_ech_configs,
            ProverState.WAIT_TICKETS     : self.process_tickets,
            ProverState.WAIT_SH          : self.process_sh,
            ProverState.MPC_HS_HKDF      : self.twopc_handshake_hkdf,
            ProverState.MPC_APP_HKDF     : self.twopc_application_hkdf,
            ProverState.MPC_ENC          : self.twopc_encryption,
            ProverState.WAIT_RESPONSE    : self.process_response,
            ProverState.REVEAL_AND_PROVE : self.reveal_and_prove,
            ProverState.DECRYPT_ALL      : self.decrypt_all,
        }


    def run(self) -> None:
        assert self.state == ProverState.INIT
        while self.state < ProverState.DONE:
            self.handler[self.state]()
        logger.info('prover finished')

    def preprocess(self) -> None:
        assert self.state == ProverState.INIT
        self.mpc_manager.begin()
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
        if len(list(msg.data)) != len(self.servers):
            raise ProverError(f'received {len(list(msg.data))} tickets, expected {len(self.servers)}')

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
        assert self.state == ProverState.MPC_HS_HKDF

        self.mpc_manager.wait_until_connected()
        transcript_hash = self.crypto_manager.real_server_handshake_hash
        chts, shts, dummy_secrets = self.mpc_manager.compute_handshake_secrets(self.secrets.index, transcript_hash)


        # Trusted party version

        # msg = self.verifier_connection.recv_msg()
        # if not isinstance(msg, HandshakeSecretsVerifierMsg):
        #     raise ProverError(f'received unexpected message type: {msg.typ}')
        # trusted_party = HandshakeSecretTrustedParty()
        # hash_val = self.crypto_manager.real_server_handshake_hash
        # trusted_party.prover_input = (self.secrets.index, hash_val)
        # trusted_party.verifier_input = list(msg.data.uncreate())
        # trusted_party.compute()
        # dummy_secrets, chts, shts = trusted_party.prover_output

        logger.info('computed handshake keys')

        self.crypto_manager.set_dummy_handshake_secets(dummy_secrets)
        self.crypto_manager.set_chts_shts(chts, shts)
        self.crypto_manager.finish_handshakes()
        logger.info('handshake secrets verified')

        self.increment_state()

    def twopc_application_hkdf(self) -> None:
        assert self.state == ProverState.MPC_APP_HKDF

        transcript_hash = self.crypto_manager.real_server_application_hash
        dummy_secrets = self.mpc_manager.compute_master_secrets(transcript_hash)
        # Trusted party version

        # msg = self.verifier_connection.recv_msg()
        # if not isinstance(msg, MasterSecretsVerifierMsg):
        #     raise ProverError(f'received unexpected message type: {msg.typ}')
        # trusted_party = MasterSecretTrustedParty()
        # hash_val = self.crypto_manager.real_server_application_hash
        # trusted_party.prover_input = (self.secrets.index, hash_val)
        # trusted_party.verifier_input = list(msg.data.uncreate())
        # trusted_party.compute()
        # secrets, ck_share, civ, sk_share, siv = trusted_party.prover_output
        # self.crypto_manager.set_application_key_shares(ck_share, civ, sk_share, siv)
        #
        # # TODO: testing only, remove these
        # vck_share, civ1, vsk_share, siv1, commit1, commit2 = trusted_party.verifier_output
        # self.verifier_client_key_share = vck_share
        # self.verifier_server_key_share = vsk_share

        # check received master secrets against locally computed values
        computed_secrets = self.crypto_manager.dummy_master_secrets
        for i, (received_sec, computed_sec) in enumerate(zip(dummy_secrets, computed_secrets)):
            if i == self.secrets.index:
                continue
            if received_sec != computed_sec:
                raise ProverError('received master secret mismatch')

        logger.info('dummy master secrets verified')
        self.increment_state()

    def twopc_encryption(self) -> None:
        assert self.state == ProverState.MPC_ENC

        # TODO: replace with actual MPC
        query = self.secrets.queries[self.secrets.index]
        plaintext = InnerPlaintext.create(
                payload = query,
                typ     = ContentType.APPLICATION_DATA,
                padding = 0,
        ).pack()
        header = RecordHeader.create(
            typ = ContentType.APPLICATION_DATA,
            version = DEFAULT_LEGACY_VERSION,
            size = get_cipher_alg(self.crypto_manager.ciphersuite).ctext_size(len(plaintext))
        ).pack()

        ciphertext = self.mpc_manager.compute_encryption(plaintext, header)

        # Trused party version

        # trusted_party = EncryptionTrustedParty()
        # trusted_party.prover_input = (self.crypto_manager.client_key_share, plaintext)
        # trusted_party.verifier_input = self.verifier_client_key_share
        # trusted_party.public_input = (self.crypto_manager.client_key_iv, header)
        # trusted_party.compute()
        # ciphertext = trusted_party.prover_output

        raw = header + ciphertext
        self.crypto_manager.send_queries(raw)
        logger.info('sent queries to all servers')
        self.increment_state()

    def process_response(self) -> None:
        assert self.state == ProverState.WAIT_RESPONSE
        self.crypto_manager.recv_responses()
        logger.info('received responses from all servers')

        # query_commitment = self.crypto_manager.query_commitment
        # response_commitments = self.crypto_manager.response_commitments
        #
        # msg = CommitmentsProverMsg.create(query_commitment, response_commitments)
        # self.verifier_connection.send_msg(msg)
        self.increment_state()

    def reveal_and_prove(self) -> None:
        assert self.state == ProverState.REVEAL_AND_PROVE
        self.mpc_manager.reveal_and_prove()
        client_key, client_iv, server_key, server_iv = self.mpc_manager.get_keys()
        self.crypto_manager.set_application_keys(client_key, client_iv, server_key, server_iv)
        self.increment_state()

    def decrypt_all(self) -> None:
        assert self.state == ProverState.DECRYPT_ALL
        # msg = self.verifier_connection.recv_msg()
        # if not isinstance(msg, AppKeySharesVerifierMsg):
        #     raise ProverError(f'received unexpected message type: {msg.typ}')

        #verifier_client_key_share = msg.data.client_key_share
        #verifier_server_key_share = msg.data.server_key_share
        # TODO: replace the shares with the real shares from the verifier's message (commented out above)
        # self.crypto_manager.reconstruct_application_keys(self.verifier_client_key_share, self.verifier_server_key_share)

        self.crypto_manager.decrypt_real_server_responses()
        logger.info('decryption of real server succeeded')
        for client in self.crypto_manager.clients:
            logger.info(f'record received from server {client.server.hostname}:{client.server.port} {client.handshake.rreader.transcript.records[-1].record.payload}')
        self.increment_state()
