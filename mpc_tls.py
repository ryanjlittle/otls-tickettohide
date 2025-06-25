from proof_crypto import PartialHandshakeTranscript
from tls13_spec import HandshakeType, CipherSuite, RecordHeader, ContentType, Version
from tls_crypto import get_hash_alg, StreamCipher, get_cipher_alg
from tls_keycalc import KeyCalc


class TrustedParty:
    '''Class for testing. Takes in raw inputs and directly computes functions'''

    ciphersuite = CipherSuite.TLS_AES_128_GCM_SHA256

    def __init__(self):
        self.enc_cipher = None
        self.dec_cipher = None

        self.master_secrets = []
        self.server_idx = None
        self.ticket_nonce = None
        self.hash1 = None
        self.hash4 = None
        self.hash5 = None

        self.hash_alg = get_hash_alg(self.ciphersuite)
        self.cipher_alg = get_cipher_alg(self.ciphersuite)

        trans_initial = PartialHandshakeTranscript()
        trans_resumption = PartialHandshakeTranscript()
        trans_initial.hash_alg = self.hash_alg
        trans_resumption.hash_alg = self.hash_alg

        self.key_calc_initial = KeyCalc(trans_initial)
        self.key_calc_resumption = KeyCalc(trans_resumption)
        self.key_calc_initial.hash_alg = self.hash_alg
        self.key_calc_resumption.hash_alg = self.hash_alg

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
        self.cats = self.key_calc_resumption.client_appllication_traffic_secret
        self.sats = self.key_calc_resumption.server_application_traffic_secret

        return self.cats, self.sats

    def encrypt(self, ptext, header=None):
        assert self.cats is not None, 'must compute traffic keys first'

        if self.enc_cipher is None:
            self.enc_cipher = StreamCipher(self.cipher_alg, self.hash_alg, self.cats)

        if header is None:
            header = RecordHeader.pack(
                typ  = ContentType.APPLICATION_DATA,
                vers = Version.TLS_1_2,
                size = self.cipher_alg.ctext_size(len(ptext))
            )

        return self.enc_cipher.encrypt(ptext, header)

    def decrypt(self, ctext, header):
        assert self.sats is not None, 'must compute traffic keys first'

        if self.dec_cipher is None:
            self.dec_cipher = StreamCipher(self.cipher_alg, self.hash_alg, self.sats)

        return self.enc_cipher.decrypt(ctext, header)