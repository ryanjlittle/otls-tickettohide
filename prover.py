"""
Abstract base class for prover. Must be concretely instantiated by a child class that defines the client/server
interaction protocol and the predicate to be proved on the response.
"""
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from enum import IntEnum

from proof_common import *
from proof_connections import VerifierConnection, obtain_tickets
from proof_crypto import ProverClientPhase1
from proof_spec import VerifierMsgType, VerifierMsg, ProverMsgType
from tls13_spec import CipherSuite, NamedGroup
from tls_common import *


class ProverState(IntEnum):
    INIT                 = 0
    WAIT_VER_DH_PHASE_1  = 1
    WAIT_SH_PHASE_1      = 2
    WAIT_HS_KEYS         = 3
    WAIT_APP_KEYS        = 4
    WAIT_TICKET          = 5
    PHASE_1_DONE         = 6
    WAIT_2PC_HKDF        = 7
    WAIT_VER_DH_PHASE_2  = 8
    WAIT_SH_PHASE_2      = 9
    WAIT_VER_SECRETS     = 10
    WAIT_SERV_APP_DATA   = 11
    WAIT_2PC_TLS         = 12
    WAIT_VER_DH_SECRET   = 13
    DONE                 = 14

    def __str__(self):
        return self.name

    def next(self):
        try:
            return ProverState(self + 1)
        except ValueError:
            raise StopIteration('no next state')


class Prover(ABC):
    def __init__(self, server_ids, real_idx, query_secret, host='localhost', port=0, ciphersuite=CipherSuite.TLS_AES_128_GCM_SHA256, group=NamedGroup.X25519, rseed=None):
        self._server_ids = server_ids
        self._real_idx = real_idx
        self._query_secret = query_secret
        self.host = host
        self._pport = port
        self.port = port if port != 0 else None # If port 0 is specified, the real port will be dynamically assigned later
        self._ciphersuite = ciphersuite
        self._group = group
        self._rseed = rseed
        self._num_servers = len(server_ids)

        self._clients = [ProverClientPhase1(sid, ciphersuite, group, rseed) for sid in self._server_ids]
        self._verifier_connection = VerifierConnection(self.host, self._pport)

        self.listening = False
        self._state = ProverState.INIT

    @property
    def handler(self):
        return {
            ProverState.INIT                 : self._begin,
            ProverState.WAIT_VER_DH_PHASE_1  : self._process_ver_dh_phase_1,
            ProverState.WAIT_SH_PHASE_1      : self._process_sh_phase_1,
            ProverState.WAIT_HS_KEYS         : self._process_hs_keys,
            ProverState.WAIT_APP_KEYS        : self._process_app_keys,
            ProverState.WAIT_TICKET          : self._process_ticket,
            ProverState.PHASE_1_DONE         : self._gen_dummy_secrets,
            ProverState.WAIT_2PC_HKDF        : self._2pc_HKDF,
            ProverState.WAIT_VER_DH_PHASE_2  : self._process_ver_dh_phase_2,
            ProverState.WAIT_SH_PHASE_2      : self._process_sh_phase_2,
            ProverState.WAIT_VER_SECRETS     : self._process_ver_secrets,
            ProverState.WAIT_SERV_APP_DATA   : self._process_server_response,
            ProverState.WAIT_2PC_TLS         : self._2pc_TLS,
            ProverState.WAIT_VER_DH_SECRET   : self._process_ver_dh_secret
        }

    def close_all(self):
        for client in self._clients:
            client.close()
        self._verifier_connection.close()

    def listen(self):
        if self.listening:
            raise ProverError('already listening')
        self._verifier_connection.bind()
        self.port = self._verifier_connection.port
        self.listening = True
        self._verifier_connection.accept()

    def run(self):
        assert self._state == ProverState.INIT
        while self._state < ProverState.DONE:
            self.handler[self._state]()
        self.close_all()
        logger.info('prover finished')

    def _increment_state(self):
        self._state = self._state.next()

    def _begin(self):
        assert self._state == ProverState.INIT
        if len(self._server_ids) == 0:
            raise ProverError('no serverIDs specified')
        with ThreadPoolExecutor() as executor:
            self._dummy_tickets = list(executor.map(obtain_tickets, self._server_ids))
        logger.info('obtained dummy tickets')
        self._increment_state()
        self.listen()

    def _process_ver_dh_phase_1(self):
        assert self._state == ProverState.WAIT_VER_DH_PHASE_1
        msg = self._verifier_connection.recv_msg()
        if msg.typ != VerifierMsgType.DH_SHARE_PHASE_1:
            raise ProverError(f'received unexpected message from verifier.')
        dh_shares = msg.body
        logger.info(f'received Diffie-Hellman shares from verifier: {dh_shares}')
        for (client, share) in zip(self._clients, dh_shares):
            client.set_kex_share(share)

        self._increment_state()

    def _process_sh_phase_1(self):
        assert self._state == ProverState.WAIT_SH_PHASE_1

        with ThreadPoolExecutor(thread_name_prefix='prover') as executor:
            futures = [executor.submit(client.send_and_recv_hellos) for client in self._clients]
            for f in futures:
                f.result()

        transcripts = [client.get_encrypted_server_msgs() for client in self._clients]
        hashes = [client.get_hash1() for client in self._clients]

        self._verifier_connection.send_msg(ProverMsgType.SERVER_HANDSHAKE_TX, transcripts)
        self._verifier_connection.send_msg(ProverMsgType.HASH_1, hashes)
        self._increment_state()

    def _process_hs_keys(self):
        assert self._state == ProverState.WAIT_HS_KEYS

        msg = self._verifier_connection.recv_msg()
        if msg.typ != VerifierMsgType.HANDSHAKE_KEYS:
            raise ProverError(f'received unexpected message from verifier.')

        hs_secrets = msg.body
        hashes = []
        for (client, (chts, shts)) in zip(self._clients, hs_secrets):
            client.set_handshake_secrets(chts, shts)
            client.send_client_finished()
            hashes.append(client.get_hash4())

        self._verifier_connection.send_msg(ProverMsgType.HASH_4, hashes)
        self._increment_state()

    def _process_app_keys(self):
        assert self._state == ProverState.WAIT_APP_KEYS

        msg = self._verifier_connection.recv_msg()
        if msg.typ != VerifierMsgType.APPLICATION_KEYS:
            raise ProverError(f'received unexpected message from verifier.')

        app_secrets = msg.body

        for (client, (chts, shts)) in zip(self._clients, app_secrets):
            client.set_application_secrets(chts, shts)

        self._increment_state()

    def _process_ticket(self):
        assert self._state == ProverState.WAIT_TICKET

        for client in self._clients:
            client.process_ticket()
            # TODO: remove this
            client.send(b'ping')
            resp = client.recv(128)
            logger.info(f'got response: {resp}')

        self._increment_state()

    def _gen_dummy_secrets(self):
        assert self._state == ProverState.PHASE_1_DONE
        self._increment_state()

    def _2pc_HKDF(self):
        assert self._state == ProverState.WAIT_2PC_HKDF
        self._increment_state()

    def _process_ver_dh_phase_2(self):
        assert self._state == ProverState.WAIT_VER_DH_PHASE_2
        self._increment_state()

    def _process_sh_phase_2(self):
        assert self._state == ProverState.WAIT_SH_PHASE_2
        self._increment_state()

    def _process_ver_secrets(self):
        assert self._state == ProverState.WAIT_VER_SECRETS
        self._increment_state()

    def _process_server_response(self):
        assert self._state == ProverState.WAIT_SERV_APP_DATA
        self._increment_state()

    def _2pc_TLS(self):
        assert self._state == ProverState.WAIT_2PC_TLS
        self._increment_state()

    def _process_ver_dh_secret(self):
        assert self._state == ProverState.WAIT_VER_DH_SECRET
        self._increment_state()

    @abstractmethod
    def run_protocol(self):
        pass

    @abstractmethod
    def make_proof(self):
        pass

class HttpsProver(Prover):
    def run_protocol(self):
        pass
    def make_proof(self):
        pass