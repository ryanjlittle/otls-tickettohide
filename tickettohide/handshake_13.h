#ifndef _HAND_SHAKE_13_
#define _HAND_SHAKE_13_

#include "protocol/handshake.h"
#include "prf_13.h"
#include "constants.h"
#include "tth_utils.h"

using namespace emp;
using namespace std;


template <typename IO>
class Handshake_13 {
public:
    IO* io;
    IO* io_opt;
    HMAC_SHA256_TTH hs_hmac;
    HMAC_SHA256_TTH app_hmac;
    PRF_13 prf;
    E2F<IO>* e2f = nullptr;
    BIGNUM* q;
    BN_CTX* ctx;

    BIGNUM* ta_primus;
    BIGNUM* tb_client;

    Integer zk_pms;
    Integer zk_index;
    Integer zk_hash_1;
    Integer zk_hash_2;
    BIGNUM* bn_pms;

    int num_servers;
    unsigned char* hs_hash_buf;
    unsigned char* app_hash_buf;
    uint8_t index = 0;
    vector<unsigned char*> hs_secs_buf, master_secs_buf;

    Integer chts, shts;
    string chts_revealed;
    string shts_revealed;

    Integer index_gc;
    vector<string> dummy_hs_secs_revealed;
    vector<string> dummy_master_secs_revealed;

    Integer client_write_key;
    Integer server_write_key;
    Integer client_write_iv;
    Integer server_write_iv;
    string client_iv_revealed;
    string server_iv_revealed;

    Integer master_key;
    unsigned char client_ufin[finished_msg_length];
    unsigned char server_ufin[finished_msg_length];
    bool ENABLE_ROUNDS_OPT = false;
    Handshake_13(IO* io, IO* io_opt, COT<IO>* ot, int num_servers, bool ENABLE_ROUNDS_OPT = false)
        : io(io) {
        this->io_opt = io_opt;
        this->num_servers = num_servers;
        ctx = BN_CTX_new();
        q = BN_new();
        bn_pms = BN_new();
        ta_primus = BN_new();
        tb_client = BN_new();
        this->ENABLE_ROUNDS_OPT = ENABLE_ROUNDS_OPT;
    }
    ~Handshake_13() {
        BN_CTX_free(ctx);
        BN_free(q);
        BN_free(bn_pms);
        BN_free(ta_primus);
        BN_free(tb_client);

        delete[] hs_hash_buf;
        for (unsigned char* x : hs_secs_buf) {
            delete x;
        }
    }

    inline void set_prover_handshake_secrets(const uint8_t index, unsigned char* hash_in) {
        // initialize prover inputs
        hs_hash_buf = hash_in;
        reverse(hs_hash_buf, hs_hash_buf + hash_len);
        this->index = index;

        // initialize verifier's inputs to all zero bytes
        hs_secs_buf = vector<unsigned char*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            hs_secs_buf[i] = new unsigned char[hash_len];
            memset(hs_secs_buf[i], 0, hash_len);
        }
    }

    inline void set_verifier_handshake_secrets(const vector<unsigned char*> hs_secrets) {
        // initialize verifier inputs
        hs_secs_buf = vector<unsigned char*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            hs_secs_buf[i] = hs_secrets[i];
            reverse(hs_secs_buf[i], hs_secs_buf[i] + hash_len);
        }

        // initialize prover's inputs to all zero
        hs_hash_buf = new unsigned char[hash_len];
        memset(hs_hash_buf, 0, hash_len);
    }

    inline void set_prover_application_secrets(unsigned char* hash_in) {
        // initialize prover input
        app_hash_buf = hash_in;
        reverse(app_hash_buf, app_hash_buf + hash_len);


        // initialize verifier inputs to all zero
        master_secs_buf = vector<unsigned char*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            master_secs_buf[i] = new unsigned char[hash_len];
            memset(master_secs_buf[i], 0, hash_len);
        }
    }

    inline void set_verifier_application_secrets(const vector<unsigned char*> master_secs) {
        // initialize verifier inputs
        master_secs_buf = vector<unsigned char*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            master_secs_buf[i] = master_secs[i];
            reverse(master_secs_buf[i], master_secs_buf[i] + hash_len);
        }

        // initialize prover's input to all zero
        app_hash_buf = new unsigned char[hash_len];
        memset(app_hash_buf, 0, hash_len);
    }

    inline void compute_handshake_secrets() {
        // commit to index and hash
        switch_to_zk();
        zk_index = Integer(index_len*8, index, ALICE);
        zk_hash_1 = Integer(hash_len*8, hs_hash_buf, ALICE);
        sync_zk_gc<IO>();
        switch_to_gc();

        // feed inputs into GC
        index_gc = Integer(index_len*8, index, ALICE);
        Integer session_hash = Integer(hash_len*8, hs_hash_buf, ALICE);
        vector<Integer> hs_secs(num_servers);
        for (int i = 0; i < num_servers; i++) {
            hs_secs[i] = Integer(hash_len*8, hs_secs_buf[i], BOB);
        }

        // select real handshake secret and dummy secrets
        Integer real_hs_sec(hash_len*8, 0);
        vector<Integer> dummy_hs_secs(num_servers);
        Integer zero = Integer(hash_len*8, 0);
        for (int i = 0; i < num_servers; i++) {
            Bit sel = index_gc.equal(Integer(index_len*8, i)); // sel = 1 if i == index
            real_hs_sec = real_hs_sec.select(sel, hs_secs[i]); // real_hs_sec unchanged if sel=0, set to hs_sec[i] if sel=1
            dummy_hs_secs[i] = hs_secs[i].select(sel, zero); // set to hs_sec[i] if sel=0, or zero if sel=1
        }

        // compute CHTS and SHTS from real handshake secret
        //prf.init(hs_hmac, real_hs_sec);
        prf.compute_chts_shts(chts, shts, real_hs_sec, session_hash);

        // reveal outputs to prover (Alice)
        chts_revealed = chts.reveal<string>(ALICE);
        shts_revealed = shts.reveal<string>(ALICE);
        dummy_hs_secs_revealed = vector<string>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            dummy_hs_secs_revealed[i] = dummy_hs_secs[i].reveal<string>(ALICE);
        }
    }

    inline void compute_application_keys() {
        // commit to prover's hash
        switch_to_zk();
        zk_hash_2 = Integer(hash_len*8, app_hash_buf, ALICE);
        sync_zk_gc<IO>();
        switch_to_gc();

        // feed inputs into GC
        Integer session_hash = Integer(hash_len*8, app_hash_buf, ALICE);
        vector<Integer> master_secs(num_servers);
        for (int i = 0; i < num_servers; i++) {
            master_secs[i] = Integer(hash_len*8, master_secs_buf[i], BOB);
        }

        // select real master secret and dummy secrets
        Integer real_master_sec(hash_len*8, 0);
        vector<Integer> dummy_master_secs(num_servers);
        Integer zero = Integer(hash_len*8, 0);
        for (int i = 0; i < num_servers; i++) {
            Bit sel = index_gc.equal(Integer(index_len*8, i)); // sel = 1 if i == index
            real_master_sec = real_master_sec.select(sel, master_secs[i]); // real_master_sec unchanged if sel=0, set to master_secs[i] if sel=1
            dummy_master_secs[i] = master_secs[i].select(sel, zero); // set to master_secs[i] if sel=0, or zero if sel=1
        }

        // compute keys
        prf.compute_application_keys(client_write_key,
                                     client_write_iv,
                                     server_write_key,
                                     server_write_iv,
                                     real_master_sec,
                                     session_hash
        );

        // reveal dummy secrets to prover (Alice)
        dummy_master_secs_revealed = vector<string>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            dummy_master_secs_revealed[i] = dummy_master_secs[i].reveal<string>(ALICE);
        }

        // reveal IVs to both parties
        client_iv_revealed = client_write_iv.reveal<string>(PUBLIC);
        server_iv_revealed = server_write_iv.reveal<string>(PUBLIC);
    }



    inline void compute_master_key(const BIGNUM* pms,
                                   const unsigned char* rc,
                                   size_t rc_len,
                                   const unsigned char* rs,
                                   size_t rs_len) {
        size_t len = BN_num_bytes(q);
        size_t pms_len = BN_num_bytes(pms);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0, len);
        BN_bn2bin(pms, buf + (len - pms_len));
        reverse(buf, buf + len);
        Integer pmsa, pmsb;

        // commit the IT-MAC of zk_2 in addmod.
        switch_to_zk();
        zk_pms = Integer(len * 8, buf, ALICE);
        sync_zk_gc<IO>();
        switch_to_gc();

        pmsa = Integer(len * 8, buf, ALICE);
        pmsb = Integer(len * 8, buf, BOB);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        prf.init(app_hmac, pmsbits);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, master_key, master_key_length * 8, pmsbits, master_key_label,
                            master_key_label_length, seed, seed_len, true, true);
        } else {
            prf.opt_rounds_compute(hs_hmac, master_key, master_key_length * 8, pmsbits,
                                   master_key_label, master_key_label_length, seed, seed_len,
                                   true, true);
        }

        delete[] seed;
        delete[] buf;
    }

    // This extends the master key generation, chose one of them when integrating TLS.
    inline void compute_extended_master_key(const BIGNUM* pms,
                                            const unsigned char* session_hash,
                                            size_t hash_len) {
        size_t len = BN_num_bytes(q);
        size_t pms_len = BN_num_bytes(pms);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0, len);
        BN_bn2bin(pms, buf + (len - pms_len));
        reverse(buf, buf + len);
        Integer pmsa, pmsb;

        // commit the IT-MAC of zk_2 in addmod.
        switch_to_zk();
        zk_pms = Integer(len * 8, buf, ALICE);
        sync_zk_gc<IO>();
        switch_to_gc();

        pmsa = Integer(len * 8, buf, ALICE);
        pmsb = Integer(len * 8, buf, BOB);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        prf.init(app_hmac, pmsbits);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, master_key, extended_master_key_length * 8, pmsbits,
                            extended_master_key_label, extended_master_key_label_length,
                            session_hash, hash_len, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, master_key, extended_master_key_length * 8, pmsbits,
                                   extended_master_key_label, extended_master_key_label_length,
                                   session_hash, hash_len, true, true);
        }
        delete[] buf;
    }

    inline void compute_expansion_keys(const unsigned char* rc,
                                       size_t rc_len,
                                       const unsigned char* rs,
                                       size_t rs_len) {
        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rs, rs_len);
        memcpy(seed + rs_len, rc, rc_len);

        Integer key;
        prf.init(app_hmac, master_key);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, key, expansion_key_length * 8, master_key,
                            key_expansion_label, key_expansion_label_length, seed, seed_len,
                            true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, key, expansion_key_length * 8, master_key,
                                   key_expansion_label, key_expansion_label_length, seed,
                                   seed_len, true, true);
        }

        extract_integer(client_write_key, key, 0, key_length * 8);
        extract_integer(server_write_key, key, key_length * 8, key_length * 8);

        extract_integer(client_write_iv, key, key_length * 8 * 2, iv_length * 8);
        extract_integer(server_write_iv, key, key_length * 8 * 2 + iv_length * 8,
                        iv_length * 8);
        delete[] seed;
    }

    inline void compute_client_finished_msg(const unsigned char* label,
                                            size_t label_len,
                                            const unsigned char* tau,
                                            size_t tau_len) {
        Integer ufin_int;
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, ufin_int, finished_msg_length * 8, master_key, label,
                            label_len, tau, tau_len, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, ufin_int, finished_msg_length * 8, master_key, label,
                                   label_len, tau, tau_len, true, true);
        }
        ufin_int.reveal<unsigned char>((unsigned char*)client_ufin, PUBLIC);
    }

    inline void compute_server_finished_msg(const unsigned char* label,
                                            size_t label_len,
                                            const unsigned char* tau,
                                            size_t tau_len) {
        Integer ufin_int;
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, ufin_int, finished_msg_length * 8, master_key, label,
                            label_len, tau, tau_len, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, ufin_int, finished_msg_length * 8, master_key, label,
                                   label_len, tau, tau_len, true, true);
        }
        ufin_int.reveal<unsigned char>((unsigned char*)server_ufin, PUBLIC);
    }

    inline void encrypt_client_finished_msg(AEAD<IO>* aead_c,
                                            unsigned char* ctxt,
                                            unsigned char* tag,
                                            const unsigned char* ufinc,
                                            size_t ufinc_len,
                                            const unsigned char* aad,
                                            size_t aad_len,
                                            const unsigned char* iv,
                                            size_t iv_len,
                                            int party) {
        aead_c->encrypt(io, ctxt, tag, ufinc, ufinc_len, aad, aad_len, iv, iv_len, party);
    }

    // The ufins string is computed by primus and client, need to check the equality with the decrypted string
    inline bool decrypt_server_finished_msg(AEAD<IO>* aead_s,
                                            unsigned char* msg,
                                            const unsigned char* ctxt,
                                            size_t ctxt_len,
                                            const unsigned char* tag,
                                            const unsigned char* aad,
                                            size_t aad_len,
                                            const unsigned char* iv,
                                            size_t iv_len,
                                            int party) {
        return aead_s->decrypt(io, msg, ctxt, ctxt_len, tag, aad, aad_len, iv, iv_len, party);
    }

    inline bool decrypt_and_check_server_finished_msg(AEAD<IO>* aead_s,
                                                      const unsigned char* ctxt,
                                                      const unsigned char* tag,
                                                      const unsigned char* aad,
                                                      size_t aad_len,
                                                      const unsigned char* iv,
                                                      size_t iv_len,
                                                      int party) {
        unsigned char* msg = new unsigned char[finished_msg_length];
        bool res1 = aead_s->decrypt(io, msg, ctxt, finished_msg_length, tag, aad, aad_len, iv,
                                    iv_len, party);

        bool res2 = (memcmp(msg, server_ufin, finished_msg_length) == 0);
        delete[] msg;
        return res1 & res2;
    }

    // ALICE knows pms, which is the entire value, not a share.
    inline void prove_master_key(Integer& ms,
                                 const BIGNUM* pms,
                                 const unsigned char* rc,
                                 size_t rc_len,
                                 const unsigned char* rs,
                                 size_t rs_len,
                                 int party) {
        size_t len = BN_num_bytes(q);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0, len);

        if (party == ALICE)
            BN_mod_sub(bn_pms, pms, bn_pms, q, ctx);

        size_t pms_len = BN_num_bytes(bn_pms);
        BN_bn2bin(bn_pms, buf + (len - pms_len));
        reverse(buf, buf + len);
        Integer z1(len * 8, buf, PUBLIC);

        Integer pmsbits;
        addmod(pmsbits, z1, zk_pms, q);

        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        prf.init(app_hmac, pmsbits);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, ms, master_key_length * 8, pmsbits, master_key_label,
                            master_key_label_length, seed, seed_len, true, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, ms, master_key_length * 8, pmsbits, master_key_label,
                                   master_key_label_length, seed, seed_len, true, true, true);
        }

        delete[] seed;
        delete[] buf;
    }

    // ALICE knows pms, which is the entire value, not a share.
    inline void prove_extended_master_key(Integer& ms,
                                          const BIGNUM* pms,
                                          const unsigned char* session_hash,
                                          size_t hash_len,
                                          int party) {
        size_t len = BN_num_bytes(q);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0, len);

        if (party == ALICE)
            BN_mod_sub(bn_pms, pms, bn_pms, q, ctx);

        size_t pms_len = BN_num_bytes(bn_pms);
        BN_bn2bin(bn_pms, buf + (len - pms_len));
        reverse(buf, buf + len);
        Integer z1(len * 8, buf, PUBLIC);

        Integer pmsbits;
        addmod(pmsbits, z1, zk_pms, q);

        prf.init(app_hmac, pmsbits);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, ms, extended_master_key_length * 8, pmsbits,
                            extended_master_key_label, extended_master_key_label_length,
                            session_hash, hash_len, true, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, ms, extended_master_key_length * 8, pmsbits,
                                   extended_master_key_label, extended_master_key_label_length,
                                   session_hash, hash_len, true, true, true);
        }

        delete[] buf;
    }

    inline void prove_expansion_keys(Integer& key_c,
                                     Integer& key_s,
                                     Integer& iv_c,
                                     Integer& iv_s,
                                     const Integer& ms,
                                     const unsigned char* rc,
                                     size_t rc_len,
                                     const unsigned char* rs,
                                     size_t rs_len,
                                     int party) {
        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rs, rs_len);
        memcpy(seed + rs_len, rc, rc_len);

        Integer key;
        prf.init(app_hmac, ms);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, key, expansion_key_length * 8, ms, key_expansion_label,
                            key_expansion_label_length, seed, seed_len, true, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, key, expansion_key_length * 8, ms,
                                   key_expansion_label, key_expansion_label_length, seed,
                                   seed_len, true, true, true);
        }

        extract_integer(key_c, key, 0, key_length * 8);
        extract_integer(key_s, key, key_length * 8, key_length * 8);

        extract_integer(iv_c, key, key_length * 8 * 2, iv_length * 8);
        extract_integer(iv_s, key, key_length * 8 * 2 + iv_length * 8, iv_length * 8);

        delete[] seed;
    }

    inline void prove_client_finished_msg(const Integer& ms,
                                          const unsigned char* label,
                                          size_t label_len,
                                          const unsigned char* tau,
                                          size_t tau_len,
                                          int party) {
        Integer ufin;
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, ufin, finished_msg_length * 8, ms, label, label_len, tau,
                            tau_len, true, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, ufin, finished_msg_length * 8, ms, label, label_len,
                                   tau, tau_len, true, true, true);
        }
        check_zero<IO>(ufin, client_ufin, finished_msg_length, party);
    }

    inline void prove_server_finished_msg(const Integer& ms,
                                          const unsigned char* label,
                                          size_t label_len,
                                          const unsigned char* tau,
                                          size_t tau_len,
                                          int party) {
        Integer ufin;
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(app_hmac, ufin, finished_msg_length * 8, ms, label, label_len, tau,
                            tau_len, true, true, true);
        } else {
            prf.opt_rounds_compute(app_hmac, ufin, finished_msg_length * 8, ms, label, label_len,
                                   tau, tau_len, true, true, true);
        }
        check_zero<IO>(ufin, server_ufin, finished_msg_length, party);
    }

    inline void prove_enc_dec_finished_msg(AEAD_Proof<IO>* aead_proof,
                                           Integer& z0,
                                           const unsigned char* ctxt,
                                           size_t ctxt_len,
                                           const unsigned char* iv,
                                           size_t iv_len) {
        // Dummy variable.
        Integer msg;
        aead_proof->prove_aead(msg, z0, ctxt, ctxt_len, iv, iv_len);
    }

    inline void handshake_check(int party) {
        prf.prf_check<IO>(party);
        app_hmac.sha256_check<IO>(party);
    }
};

class HandShake13Offline {
   public:
    HMAC_SHA256_Offline hmac;
    PRFOffline prf;
    BIGNUM* q;
    BN_CTX* ctx;

    Integer master_key;
    Integer client_write_key;
    Integer server_write_key;
    Integer client_write_iv;
    Integer server_write_iv;

    unsigned char client_ufin[finished_msg_length];
    unsigned char server_ufin[finished_msg_length];

    bool ENABLE_ROUNDS_OPT = false;
    HandShake13Offline(EC_GROUP* group, bool ENABLE_ROUNDS_OPT = false) {
        q = BN_new();
        ctx = BN_CTX_new();
        EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
        this->ENABLE_ROUNDS_OPT = ENABLE_ROUNDS_OPT;
    }
    ~HandShake13Offline() {
        BN_CTX_free(ctx);
        BN_free(q);
    }

    inline void compute_master_key() {
        size_t len = BN_num_bytes(q);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0x00, len);
        Integer pmsa, pmsb;
        pmsa = Integer(len * 8, buf, ALICE);
        pmsb = Integer(len * 8, buf, BOB);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        prf.init(hmac, pmsbits);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(hmac, master_key, master_key_length * 8, pmsbits, true, true);
        } else {
            prf.opt_rounds_compute(hmac, master_key, master_key_length * 8, pmsbits,
                                   master_key_label_length + 2 * random_length, true, true);
        }

        delete[] buf;
    }

    inline void compute_extended_master_key() {
        size_t len = BN_num_bytes(q);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0x00, len);
        Integer pmsa, pmsb;
        pmsa = Integer(len * 8, buf, ALICE);
        pmsb = Integer(len * 8, buf, BOB);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        prf.init(hmac, pmsbits);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(hmac, master_key, extended_master_key_length * 8, pmsbits, true,
                            true);
        } else {
            prf.opt_rounds_compute(hmac, master_key, extended_master_key_length * 8, pmsbits,
                                   extended_master_key_label_length + session_hash_length,
                                   true, true);
        }
        delete[] buf;
    }

    inline void compute_expansion_keys() {
        Integer key;
        prf.init(hmac, master_key);
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(hmac, key, expansion_key_length * 8, master_key, true, true);
        } else {
            prf.opt_rounds_compute(hmac, key, expansion_key_length * 8, master_key,
                                   key_expansion_label_length + 2 * random_length, true, true);
        }
        extract_integer(client_write_key, key, 0, key_length * 8);
        extract_integer(server_write_key, key, key_length * 8, key_length * 8);

        extract_integer(client_write_iv, key, key_length * 8 * 2, iv_length * 8);
        extract_integer(server_write_iv, key, key_length * 8 * 2 + iv_length * 8,
                        iv_length * 8);
    }

    inline void compute_client_finished_msg() {
        Integer ufin_int;
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(hmac, ufin_int, finished_msg_length * 8, master_key, true, true);

        } else {
            prf.opt_rounds_compute(hmac, ufin_int, finished_msg_length * 8, master_key,
                                   client_finished_label_length + session_hash_length, true,
                                   true);
        }
        ufin_int.reveal<unsigned char>((unsigned char*)client_ufin, PUBLIC);
    }

    inline void compute_server_finished_msg() {
        Integer ufin_int;
        if (!ENABLE_ROUNDS_OPT) {
            prf.opt_compute(hmac, ufin_int, finished_msg_length * 8, master_key, true, true);
        } else {
            prf.opt_rounds_compute(hmac, ufin_int, finished_msg_length * 8, master_key,
                                   server_finished_label_length + session_hash_length, true,
                                   true);
        }
        ufin_int.reveal<unsigned char>((unsigned char*)server_ufin, PUBLIC);
    }

    inline void encrypt_client_finished_msg(AEADOffline* aead_c_offline, size_t ufinc_len) {
        aead_c_offline->encrypt(ufinc_len);
    }

    inline void decrypt_server_finished_msg(AEADOffline* aead_s_offline, size_t ufins_len) {
        aead_s_offline->decrypt(ufins_len);
    }
};

#endif
