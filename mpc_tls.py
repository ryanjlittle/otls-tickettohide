from proof_crypto import PartialHandshakeTranscript
from tls13_spec import HandshakeType, CipherSuite
from tls_crypto import get_hash_alg
from tls_keycalc import KeyCalc


class TrustedParty:
    '''Class for testing. Takes in raw inputs and directly computes functions'''

    CIPHERSUITE = CipherSuite.TLS_AES_128_GCM_SHA256

    def __init__(self):
        self.master_secrets = []
        self.server_idx = None
        self.ticket_nonce = None
        self.hash1 = None
        self.hash4 = None
        self.hash5 = None

        hash_alg = get_hash_alg(self.CIPHERSUITE)

        trans_initial = PartialHandshakeTranscript()
        trans_resumption = PartialHandshakeTranscript()
        trans_initial.hash_alg = hash_alg
        trans_resumption.hash_alg = hash_alg

        self.key_calc_initial = KeyCalc(trans_initial)
        self.key_calc_resumption = KeyCalc(trans_resumption)
        self.key_calc_initial.hash_alg = hash_alg
        self.key_calc_resumption.hash_alg = hash_alg

    def compute_binder_key(self):
        assert self.server_idx is not None, 'server_idx not specified'
        assert self.master_secrets is not None, 'master_secrets not specified'
        assert self.hash5 is not None, 'hash5 not specified'
        assert self.ticket_nonce is not None, 'ticket_nonce not specified'

        self.key_calc_initial.master_secret = self.master_secrets[self.server_idx]
        self.key_calc_initial._hs_trans.set_hash(HandshakeType.FINISHED, self.hash5, from_client=True)
        psk = self.key_calc_initial.ticket_secret(self.ticket_nonce)
        self.key_calc_resumption.psk = psk

        return self.key_calc_resumption.binder_key

    def compute_application_keys(self):
        assert self.hash1 is not None, 'hash1 not specified'

        self.key_calc_resumption._hs_trans.set_hash(HandshakeType.SERVER_HELLO, self.hash1)
        chts = self.key_calc_resumption.client_handshake_traffic_secret
        shts = self.key_calc_resumption.server_handshake_traffic_secret

        return chts, shts

    def compute_traffic_keys(self):
        assert self.hash4 is not None, 'hash4 not specified'

        self.key_calc_resumption._hs_trans.set_hash(HandshakeType.FINISHED, self.hash4, False)
        cats = self.key_calc_resumption.client_appllication_traffic_secret
        sats = self.key_calc_resumption.server_application_traffic_secret

        return cats, sats
