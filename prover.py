"""
Abstract base class for prover. Must be concretely instantiated by a child class that defines the client/server
interaction protocol and the predicate to be proved on the response.
"""
from abc import ABC, abstractmethod
from enum import IntEnum
from threading import Thread

from proof_common import *
from proof_connections import ServerConnection, VerifierConnection
from proof_spec import VerifierMsgType
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
    def __init__(self, server_ids, real_idx, query_secret, host='localhost', port=0, rseed=None):
        self._server_ids = server_ids
        self._real_idx = real_idx
        self._query_secret = query_secret
        self.host = host
        self._pport = port
        self.port = port if port != 0 else None # If port 0 is specified, the real port will be dynamically assigned later
        self._rseed = rseed
        self.listening = False
        self._server_connections = [ServerConnection(sid) for sid in self._server_ids]
        self._verifier_connection = VerifierConnection(self.host, self._pport)
        #self._dummy_connections = [ServerConnection(sid) for sid in server_ids]
        #self._verifier_connection = VerifierConnection()

        self._state = ProverState.INIT
        self._handler = {
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
        # self.twopc_connection = TwoPCClient(serverIDs[real_idx])


    def close_all(self):
        for conn in self._server_connections:
            conn.close()
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
            self._handler[self._state]()
        self.close_all()

    def _obtain_dummy_tickets(self):
        threads = []
        task = lambda conn: conn.obtain_ticket()
        for (i, conn) in enumerate(self._server_connections):
            tname = f'dc{i}'
            t = Thread(name=tname, target=task, args=(conn,))
            t.start()
            threads.append(t)
        logger.info('launched dummy connections')
        for t in threads:
            t.join()

    def _open_ver_socket(self):
        pass

    @abstractmethod
    def run_protocol(self):
        pass

    @abstractmethod
    def make_proof(self):
        pass

    def _increment_state(self):
        self._state = self._state.next()

    def _begin(self):
        assert self._state == ProverState.INIT
        if len(self._server_ids) == 0:
            raise ProverError('no serverIDs specified')
        self._obtain_dummy_tickets()
        self.listen()
        self._increment_state()

    def _process_ver_dh_phase_1(self):
        assert self._state == ProverState.WAIT_VER_DH_PHASE_1
        dh_share = self._verifier_connection.recv_msg(VerifierMsgType.DH_SHARE_PHASE_1)
        logger.info(f'received Diffie-Hellman share from verifier: {dh_share}')
        self._increment_state()

    def _process_sh_phase_1(self):
        assert self._state == ProverState.WAIT_SH_PHASE_1

    def _process_hs_keys(self):
        assert self._state == ProverState.WAIT_HS_KEYS

    def _process_app_keys(self):
        assert self._state == ProverState.WAIT_APP_KEYS

    def _process_ticket(self):
        assert self._state == ProverState.WAIT_TICKET

    def _gen_dummy_secrets(self):
        assert self._state == ProverState.PHASE_1_DONE

    def _2pc_HKDF(self):
        assert self._state == ProverState.WAIT_2PC_HKDF

    def _process_ver_dh_phase_2(self):
        assert self._state == ProverState.WAIT_VER_DH_PHASE_2

    def _process_sh_phase_2(self):
        assert self._state == ProverState.WAIT_SH_PHASE_2

    def _process_ver_secrets(self):
        assert self._state == ProverState.WAIT_VER_SECRETS

    def _process_server_response(self):
        assert self._state == ProverState.WAIT_SERV_APP_DATA

    def _2pc_TLS(self):
        assert self._state == ProverState.WAIT_2PC_TLS

    def _process_ver_dh_secret(self):
        assert self._state == ProverState.WAIT_VER_DH_SECRET


class HttpsProver(Prover):
    def run_protocol(self):
        pass
    def make_proof(self):
        pass