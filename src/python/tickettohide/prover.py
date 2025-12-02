import os
from enum import IntEnum
from time import perf_counter
import csv

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
    benchmark_file: str|None
    verifier_connection: VerifierConnection
    crypto_manager: ProverCryptoManager
    mpc_manager: ProverMPC
    state: ProverState = ProverState.INIT
    rseed: int|None = None
    perf_times: dict[str, float]

    def __init__(self,
                 servers: list[ServerID],
                 secrets: ProverSecrets,
                 benchmark_file: str|None = None,
                 hostname: str = 'localhost',
                 port: int = 8000,
                 mpc_port: int = 8001,
                 rseed: int|None = None,
                 ) -> None:
        self.servers = servers
        self.secrets = secrets
        self.benchmark_file = benchmark_file
        self.rseed = rseed
        self.perf_times = dict()
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

        self.perf_times["START"] = perf_counter()
        self.verifier_connection.listen()
        self.perf_times["CONNECTED"] = perf_counter()

        while self.state < ProverState.DONE:
            self.handler[self.state]()

        self.perf_times["DONE"] = perf_counter()
        logger.info('prover finished')

        total_time = self.perf_times["DONE"] - self.perf_times["CONNECTED"]
        preproc_time = self.perf_times["MPC_PREPROC_END"] - self.perf_times["MPC_PREPROC_START"]
        hs_mpc_time = self.perf_times["MPC_HS_KEY_END"] - self.perf_times["MPC_HS_KEY_START"]
        app_mpc_time = self.perf_times["MPC_APP_KEY_END"] - self.perf_times["MPC_APP_KEY_START"]
        enc_time = self.perf_times["MPC_ENC_END"] - self.perf_times["MPC_ENC_START"]
        izk_time = self.perf_times["IZK_END"] - self.perf_times["IZK_START"]
        ech_time = self.perf_times["GET_ECH_END"] - self.perf_times["GET_ECH_START"]
        ticket_time = self.perf_times["RECVD_TICKETS"] - self.perf_times["WAIT_TICKETS"]
        hellos_time = self.perf_times["RECV_SH_END"] - self.perf_times["SEND_CH_START"]
        req_res_time = self.perf_times["RECV_RES_END"] - self.perf_times["SEND_REQ_START"]
        local_time = total_time - preproc_time - hs_mpc_time - app_mpc_time - enc_time - izk_time - ech_time - ticket_time - hellos_time - req_res_time

        print("Time spent in each phase")
        print(f'  Obtaining ECH configs:     {ech_time:.8f} s')
        print(f'  MPC Preprocessing:         {preproc_time:.8f} s')
        print(f'  Awaiting verifier tickets: {ticket_time:.8f} s')
        print(f'  Sending/receiving CH/SH:   {hellos_time:.8f} s')
        print(f'  MPC HS key computation:    {hs_mpc_time:.8f} s')
        print(f'  MPC main key computation:  {app_mpc_time:.8f} s')
        print(f'  MPC encryption:            {enc_time:.8f} s')
        print(f'  IZK:                       {izk_time:.8f} s')
        print(f'  Sending/receiving req/res: {req_res_time:.8f} s')

        print(f'  Local computation:         {local_time:.8f} s')
        print(f'  -------------------------')
        print(f'  Total time:                {total_time:.8f} s')

        # Append row to CSV file
        if self.benchmark_file:
            file_exists = os.path.isfile(self.benchmark_file)
            row = [len(self.servers), ech_time, preproc_time, ticket_time, hellos_time, hs_mpc_time, app_mpc_time, enc_time, izk_time, req_res_time, local_time, total_time]
            with open(self.benchmark_file, mode="a", newline="") as file:
                writer = csv.writer(file)
                if not file_exists:
                    # write headers
                    writer.writerow(["num_servers", "ech", "preprocessing", "wait_tickets", "wait_hellos", "mpc_hs_key", "mpc_app_key", "mpc_enc", "izk", "req_req", "local", "total"])
                writer.writerow(row)


    def preprocess(self) -> None:
        assert self.state == ProverState.INIT
        self.mpc_manager.begin()
        self.perf_times["MPC_PREPROC_START"] = perf_counter()
        self.mpc_manager.wait_until_connected()
        self.perf_times["MPC_PREPROC_END"] = perf_counter()
        self.increment_state()

    def get_ech_configs(self) -> None:
        assert self.state == ProverState.GET_ECH
        self.perf_times["GET_ECH_START"] = perf_counter()
        self.crypto_manager.obtain_ech_configs()
        self.perf_times["GET_ECH_END"] = perf_counter()

        logger.info('prover obtained all ECH configs')

        self.increment_state()
        # self.verifier_connection.listen()

    def process_tickets(self) -> None:
        assert self.state == ProverState.WAIT_TICKETS
        self.perf_times["WAIT_TICKETS"] = perf_counter()
        msg = self.verifier_connection.recv_msg()
        self.perf_times["RECVD_TICKETS"] = perf_counter()

        if not isinstance(msg, TicketsVerifierMsg):
            raise ProverError(f'received unexpected message type: {msg.typ}')
        if len(list(msg.data)) != len(self.servers):
            raise ProverError(f'received {len(list(msg.data))} tickets, expected {len(self.servers)}')

        self.crypto_manager.build_ech_configs(list(msg.data))
        self.increment_state()

    def process_sh(self) -> None:
        assert self.state == ProverState.WAIT_SH
        self.perf_times["SEND_CH_START"] = perf_counter()
        self.crypto_manager.send_and_recv_hellos()
        self.perf_times["RECV_SH_END"] = perf_counter()

        kex_shares = self.crypto_manager.server_key_shares
        msg = KexSharesProverMsg.create(kex_shares)
        self.verifier_connection.send_msg(msg)
        self.increment_state()

    def twopc_handshake_hkdf(self) -> None:
        assert self.state == ProverState.MPC_HS_HKDF

        # self.mpc_manager.wait_until_connected()

        transcript_hash = self.crypto_manager.real_server_handshake_hash
        self.perf_times["MPC_HS_KEY_START"] = perf_counter()
        chts, shts, dummy_secrets = self.mpc_manager.compute_handshake_secrets(self.secrets.index, transcript_hash)
        self.perf_times["MPC_HS_KEY_END"] = perf_counter()

        logger.info('computed handshake keys')

        self.crypto_manager.set_dummy_handshake_secets(dummy_secrets)
        self.crypto_manager.set_chts_shts(chts, shts)

        self.perf_times["FINISH_HS_START"] = perf_counter()
        self.crypto_manager.finish_handshakes()
        self.perf_times["FINISH_HS_END"] = perf_counter()
        logger.info('handshake secrets verified')

        self.increment_state()

    def twopc_application_hkdf(self) -> None:
        assert self.state == ProverState.MPC_APP_HKDF

        transcript_hash = self.crypto_manager.real_server_application_hash
        self.perf_times["MPC_APP_KEY_START"] = perf_counter()
        dummy_secrets = self.mpc_manager.compute_master_secrets(transcript_hash)
        self.perf_times["MPC_APP_KEY_END"] = perf_counter()

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

        self.perf_times["MPC_ENC_START"] = perf_counter()
        ciphertext = self.mpc_manager.compute_encryption(plaintext, header)
        self.perf_times["MPC_ENC_END"] = perf_counter()

        raw = header + ciphertext
        self.perf_times["SEND_REQ_START"] = perf_counter()
        self.crypto_manager.send_queries(raw)
        logger.info('sent queries to all servers')
        self.increment_state()

    def process_response(self) -> None:
        assert self.state == ProverState.WAIT_RESPONSE
        self.crypto_manager.recv_responses()
        self.perf_times["RECV_RES_END"] = perf_counter()
        logger.info('received responses from all servers')

        self.increment_state()

    def reveal_and_prove(self) -> None:
        assert self.state == ProverState.REVEAL_AND_PROVE
        self.perf_times["IZK_START"] = perf_counter()
        self.mpc_manager.reveal_and_prove()
        client_key, client_iv, server_key, server_iv = self.mpc_manager.get_keys()
        self.perf_times["IZK_END"] = perf_counter()
        self.crypto_manager.set_application_keys(client_key, client_iv, server_key, server_iv)
        self.increment_state()

    def decrypt_all(self) -> None:
        assert self.state == ProverState.DECRYPT_ALL

        self.crypto_manager.decrypt_real_server_responses()
        logger.info('decryption of real server succeeded')
        for client in self.crypto_manager.clients:
            logger.info(f'record received from server {client.server.hostname}:{client.server.port} {client.handshake.rreader.transcript.records[-1].record.payload}')
        self.increment_state()
