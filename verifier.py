"""
Abstract base class for verifier. Must be concretely instantiated by a child class that defines the client/server
interaction protocol and the predicate to be verified on the response.
"""

from abc import ABC, abstractmethod
from enum import IntEnum
from random import Random

from proof_connections import ProverConnection
from proof_crypto import VerifierCrypto
from proof_spec import VerifierMsgType
from tls13_spec import CipherSuite, NamedGroup
from tls_common import *
from tls_crypto import get_kex_alg


class VerifierState(IntEnum):
    INIT            = 0
    CONNECTED       = 1
    WAIT_HASH_1     = 2
    WAIT_HASH_4     = 3
    WAIT_2PC_HKDF   = 4
    WAIT_COMMITMENT = 5
    WAIT_PROOF      = 6
    DONE            = 7

    def __str__(self):
        return self.name

    def next(self):
        try:
            return VerifierState(self + 1)
        except ValueError:
            raise StopIteration('no next state')


class Verifier(ABC):
    def __init__(self, server_ids, prover_host, prover_port, ciphersuite=CipherSuite.TLS_AES_128_GCM_SHA256, group=NamedGroup.X25519, rseed=None):
        self._serverIDs = server_ids
        self._prover_host = prover_host
        self._prover_port = prover_port
        self._ciphersuite = ciphersuite
        self._group = group
        self._rgen = Random(rseed)
        self._num_servers = len(server_ids)

        self._prover_conn = ProverConnection(self._prover_host, self._prover_port)
        self._crypto_manager = VerifierCrypto(self._num_servers, ciphersuite, group, self._rgen)

        self._state = VerifierState.INIT

    @property
    def handler(self):
        return {
            VerifierState.INIT: self._connect,
            VerifierState.CONNECTED: self._send_dh_phase_1,
            VerifierState.WAIT_HASH_1 : self._process_hash_1,
            VerifierState.WAIT_HASH_4: self._process_hash_4,
            VerifierState.WAIT_2PC_HKDF: self._2pc_hkdf,
            VerifierState.WAIT_COMMITMENT: self._process_commitment,
            VerifierState.WAIT_PROOF: self._verify_proof
        }

    def _close_all(self):
        self._prover_conn.close()

    def _increment_state(self):
        self._state = self._state.next()

    def _connect(self):
        assert self._state == VerifierState.INIT
        self._prover_conn.connect()
        self._increment_state()

    def _send_dh_phase_1(self):
        assert self._state == VerifierState.CONNECTED
        self._crypto_manager.gen_secrets()
        self._prover_conn.send_msg(VerifierMsgType.DH_SHARE_PHASE_1, self._crypto_manager.dh_shares)
        self._increment_state()

    def _process_hash_1(self):
        assert self._state == VerifierState.WAIT_HASH_1
        self._increment_state()

    def _process_hash_4(self):
        assert  self._state == VerifierState.WAIT_HASH_4
        self._increment_state()

    def _2pc_hkdf(self):
        assert self._state == VerifierState.WAIT_2PC_HKDF
        self._increment_state()

    def _process_commitment(self):
        assert self._state == VerifierState.WAIT_COMMITMENT
        self._increment_state()

    def _verify_proof(self):
        assert self._state == VerifierState.WAIT_PROOF
        self._increment_state()

    def run(self):
        assert self._state == VerifierState.INIT
        while self._state < VerifierState.DONE:
            self.handler[self._state]()
        self._close_all()
        logger.info('verifier finished')

    @abstractmethod
    def run_protocol(self):
        pass

    @abstractmethod
    def verify_proof(self):
        pass

class HttpsVerifier(Verifier):
    def run_protocol(self):
        pass
    def verify_proof(self):
        pass