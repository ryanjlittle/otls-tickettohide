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

    Integer zk_pms;
    Integer zk_index;
    Integer zk_hash_1;
    Integer zk_hash_2;

    int num_servers;
    unsigned char* hs_hash_buf;
    unsigned char* app_hash_buf;
    uint8_t index = 0;
    vector<unsigned char*> hs_secs_buf, master_secs_buf;
    vector<uint32_t*> hs_hmac_inner_hash_buf, hs_hmac_outer_hash_buf;
    vector<uint32_t*> app_hmac_inner_hash_buf, app_hmac_outer_hash_buf;
    uint32_t* chts_hmac_internal_hash, *shts_hmac_internal_hash;
    uint32_t* cats_hmac_internal_hash, *sats_hmac_internal_hash;

    Integer chts, shts, cats, sats;
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
        this->ENABLE_ROUNDS_OPT = ENABLE_ROUNDS_OPT;
    }
    ~Handshake_13() {
        delete[] hs_hash_buf;
        delete[] app_hash_buf;
        delete[] chts_hmac_internal_hash;
        delete[] shts_hmac_internal_hash;
        delete[] cats_hmac_internal_hash;
        delete[] sats_hmac_internal_hash;

        for (unsigned char* sec : hs_secs_buf) {
            delete[] sec;
        }
        for (unsigned char* sec : master_secs_buf) {
            delete[] sec;
        }
        for (uint32_t* hash : hs_hmac_inner_hash_buf) {
            delete[] hash;
        }
        for (uint32_t* hash : hs_hmac_outer_hash_buf) {
            delete[] hash;
        }
        for (uint32_t* hash : app_hmac_inner_hash_buf) {
            delete[] hash;
        }
        for (uint32_t* hash : app_hmac_outer_hash_buf) {
            delete[] hash;
        }
    }

    inline void set_prover_handshake_secrets(const uint8_t index, const unsigned char* hash_in) {
        // initialize prover inputs
        hs_hash_buf = new unsigned char[HASH_LEN];
        memcpy(hs_hash_buf, hash_in, HASH_LEN);
        reverse(hs_hash_buf, hs_hash_buf + HASH_LEN);
        this->index = index;
        chts_hmac_internal_hash = new uint32_t[HASH_LEN/4];
        shts_hmac_internal_hash = new uint32_t[HASH_LEN/4];

        // initialize verifier's inputs to all zero bytes
        hs_secs_buf = vector<unsigned char*>(num_servers);
        hs_hmac_inner_hash_buf = vector<uint32_t*>(num_servers);
        hs_hmac_outer_hash_buf = vector<uint32_t*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            hs_secs_buf[i] = new unsigned char[HASH_LEN];
            memset(hs_secs_buf[i], 0, HASH_LEN);
            hs_hmac_inner_hash_buf[i] = new uint32_t[HASH_LEN/4];
            hs_hmac_outer_hash_buf[i] = new uint32_t[HASH_LEN/4];
            memset(hs_hmac_inner_hash_buf[i], 0, HASH_LEN/4);
            memset(hs_hmac_outer_hash_buf[i], 0, HASH_LEN/4);
        }
    }

    inline void set_verifier_handshake_secrets(const vector<const unsigned char*> hs_secrets) {
        // initialize verifier inputs
        hs_secs_buf = vector<unsigned char*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            hs_secs_buf[i] = new unsigned char[HASH_LEN];
            memcpy(hs_secs_buf[i], hs_secrets[i], HASH_LEN);
            reverse(hs_secs_buf[i], hs_secs_buf[i] + HASH_LEN);
        }

        // compute partial hash for HMAC computation
        hs_hmac_inner_hash_buf = vector<uint32_t*>(num_servers);
        hs_hmac_outer_hash_buf = vector<uint32_t*>(num_servers);
        for (int i=0; i<num_servers; i++) {
            HMAC_SHA256_local local_hmac;
            local_hmac.init(hs_secrets[i], HASH_LEN);

            hs_hmac_inner_hash_buf[i] = new uint32_t[HASH_LEN/4];
            hs_hmac_outer_hash_buf[i] = new uint32_t[HASH_LEN/4];
            local_hmac.compute_inner_key_hash(hs_hmac_inner_hash_buf[i]);
            local_hmac.compute_outer_key_hash(hs_hmac_outer_hash_buf[i]);
        }

        // initialize prover's inputs to all zero
        hs_hash_buf = new unsigned char[HASH_LEN];
        memset(hs_hash_buf, 0, HASH_LEN);
        chts_hmac_internal_hash = new uint32_t[HASH_LEN/4];
        shts_hmac_internal_hash = new uint32_t[HASH_LEN/4];
        memset(chts_hmac_internal_hash, 0, HASH_LEN/4);
        memset(shts_hmac_internal_hash, 0, HASH_LEN/4);
    }

    inline void set_prover_application_secrets(const unsigned char* hash_in) {
        // initialize prover input
        app_hash_buf = new unsigned char[HASH_LEN];
        memcpy(app_hash_buf, hash_in, HASH_LEN);
        reverse(app_hash_buf, app_hash_buf + HASH_LEN);
        cats_hmac_internal_hash = new uint32_t[HASH_LEN/4];
        sats_hmac_internal_hash = new uint32_t[HASH_LEN/4];

        // initialize verifier inputs to all zero
        master_secs_buf = vector<unsigned char*>(num_servers);
        app_hmac_inner_hash_buf = vector<uint32_t*>(num_servers);
        app_hmac_outer_hash_buf = vector<uint32_t*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            master_secs_buf[i] = new unsigned char[HASH_LEN];
            memset(master_secs_buf[i], 0, HASH_LEN);
            app_hmac_inner_hash_buf[i] = new uint32_t[HASH_LEN/4];
            app_hmac_outer_hash_buf[i] = new uint32_t[HASH_LEN/4];
            memset(app_hmac_inner_hash_buf[i], 0, HASH_LEN/4);
            memset(app_hmac_outer_hash_buf[i], 0, HASH_LEN/4);
        }
    }

    inline void set_verifier_application_secrets(const vector<const unsigned char*> master_secs) {
        // initialize verifier inputs
        master_secs_buf = vector<unsigned char*>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            master_secs_buf[i] = new unsigned char[HASH_LEN];
            memcpy(master_secs_buf[i], master_secs[i], HASH_LEN);
            reverse(master_secs_buf[i], master_secs_buf[i] + HASH_LEN);
        }

        // compute partial hash for HMAC computation
        app_hmac_inner_hash_buf = vector<uint32_t*>(num_servers);
        app_hmac_outer_hash_buf = vector<uint32_t*>(num_servers);
        for (int i=0; i<num_servers; i++) {
            HMAC_SHA256_local local_hmac;
            local_hmac.init(master_secs[i], HASH_LEN);

            app_hmac_inner_hash_buf[i] = new uint32_t[HASH_LEN/4];
            app_hmac_outer_hash_buf[i] = new uint32_t[HASH_LEN/4];
            local_hmac.compute_inner_key_hash(app_hmac_inner_hash_buf[i]);
            local_hmac.compute_outer_key_hash(app_hmac_outer_hash_buf[i]);
        }

        // initialize prover's input to all zero
        app_hash_buf = new unsigned char[HASH_LEN];
        memset(app_hash_buf, 0, HASH_LEN);
        cats_hmac_internal_hash = new uint32_t[HASH_LEN/4];
        sats_hmac_internal_hash = new uint32_t[HASH_LEN/4];
        memset(cats_hmac_internal_hash, 0, HASH_LEN/4);
        memset(sats_hmac_internal_hash, 0, HASH_LEN/4);
    }

    inline void handshake_secret_setup_prover() {
        // receive internal HMAC hashes
        for (uint32_t* hash : hs_hmac_inner_hash_buf) {
            for (int i = 0; i < HASH_LEN; i++) {
                io->recv_data(&hash[i], sizeof(uint32_t));
            }
        }
        prf.compute_internal_chts_hash(chts_hmac_internal_hash, hs_hash_buf, hs_hmac_inner_hash_buf[index]);
        prf.compute_internal_shts_hash(shts_hmac_internal_hash, hs_hash_buf, hs_hmac_inner_hash_buf[index]);
    }

    inline void handshake_secret_setup_verifier() {
        // send internal HMAC hashes in the clear to the prover
        for (uint32_t* hash : hs_hmac_inner_hash_buf) {
            for (int i = 0; i < HASH_LEN; i++) {
                io->send_data(&hash[i], sizeof(uint32_t));
            }
        }
    }

    inline void application_secret_setup_prover() {
        // receive internal HMAC hashes
        for (uint32_t* hash : app_hmac_inner_hash_buf) {
            for (int i = 0; i < HASH_LEN; i++) {
                io->recv_data(&hash[i], sizeof(uint32_t));
            }
        }
        prf.compute_internal_cats_hash(cats_hmac_internal_hash, app_hash_buf, app_hmac_inner_hash_buf[index]);
        prf.compute_internal_sats_hash(sats_hmac_internal_hash, app_hash_buf, app_hmac_inner_hash_buf[index]);
    }

    inline void application_secret_setup_verifier() {
        // send internal HMAC hashes in the clear to the prover
        for (uint32_t* hash : app_hmac_inner_hash_buf) {
            for (int i = 0; i < HASH_LEN; i++) {
                io->send_data(&hash[i], sizeof(uint32_t));
            }
        }
    }

    inline void compute_handshake_secrets(int party) {
        // commit to index and hash
        switch_to_zk();
        zk_index = Integer(INDEX_LEN*8, index, PROVER);
        zk_hash_1 = Integer(HASH_LEN*8, hs_hash_buf, PROVER);
        sync_zk_gc<IO>();
        switch_to_gc();

        if (party == VERIFIER) {
            handshake_secret_setup_verifier();
        } else if (party == PROVER) {
            handshake_secret_setup_prover();
        }

        // feed inputs into GC
        index_gc = Integer(INDEX_LEN*8, index, PROVER);
        Integer session_hash = Integer(HASH_LEN*8, hs_hash_buf, PROVER);
        Integer chts_internal_hash_gc = Integer(HASH_LEN*8, chts_hmac_internal_hash, PROVER);
        Integer shts_internal_hash_gc = Integer(HASH_LEN*8, shts_hmac_internal_hash, PROVER);
        vector<Integer> hs_secs(num_servers);
        vector<Integer> outer_hashes(num_servers);
        for (int i = 0; i < num_servers; i++) {
            hs_secs[i] = Integer(HASH_LEN*8, hs_secs_buf[i], VERIFIER);
            outer_hashes[i] = Integer(HASH_LEN*8, hs_hmac_outer_hash_buf[i], VERIFIER);
        }

        // select real handshake secret and hash, as well and dummy secrets + hashes
        Integer real_hs_sec(HASH_LEN*8, 0);
        Integer outer_hash(HASH_LEN*8, 0);
        vector<Integer> dummy_hs_secs(num_servers);
        vector<Integer> dummy_hashes(num_servers);
        Integer zero = Integer(HASH_LEN*8, 0);
        for (int i = 0; i < num_servers; i++) {
            Bit sel = index_gc.equal(Integer(INDEX_LEN*8, i)); // sel = 1 if i == index
            real_hs_sec = real_hs_sec.select(sel, hs_secs[i]); // real_hs_sec unchanged if sel=0, set to hs_sec[i] if sel=1
            dummy_hs_secs[i] = hs_secs[i].select(sel, zero); // set to hs_sec[i] if sel=0, or zero if sel=1
            outer_hash = outer_hash.select(sel, outer_hashes[i]);
            dummy_hashes[i] = outer_hashes[i].select(sel, zero);
        }

        // compute CHTS and SHTS from real handshake secret
        //prf.compute_chts_shts(chts, shts, real_hs_sec, session_hash);
        prf.compute_chts_shts_opt(chts, shts, outer_hash, chts_internal_hash_gc, shts_internal_hash_gc);

        // reveal outputs to prover
        chts_revealed = chts.reveal<string>(PROVER);
        shts_revealed = shts.reveal<string>(PROVER);
        dummy_hs_secs_revealed = vector<string>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            dummy_hs_secs_revealed[i] = dummy_hs_secs[i].reveal<string>(PROVER);
        }
        io->flush();
    }

    inline void compute_application_keys(int party) {
        // commit to prover's hash
        switch_to_zk();
        zk_hash_2 = Integer(HASH_LEN*8, app_hash_buf, PROVER);
        sync_zk_gc<IO>();
        switch_to_gc();

        if (party == VERIFIER) {
            application_secret_setup_verifier();
        } else if (party == PROVER) {
            application_secret_setup_prover();
        }

        // feed inputs into GC
        Integer session_hash = Integer(HASH_LEN*8, app_hash_buf, PROVER);
        Integer cats_internal_hash_gc = Integer(HASH_LEN*8, cats_hmac_internal_hash, PROVER);
        Integer sats_internal_hash_gc = Integer(HASH_LEN*8, sats_hmac_internal_hash, PROVER);
        vector<Integer> master_secs(num_servers);
        vector<Integer> outer_hashes(num_servers);
        for (int i = 0; i < num_servers; i++) {
            master_secs[i] = Integer(HASH_LEN*8, master_secs_buf[i], VERIFIER);
            outer_hashes[i] = Integer(HASH_LEN*8, app_hmac_outer_hash_buf[i], VERIFIER);
        }

        // select real master secret and hash, and dummy secrets
        Integer real_master_sec(HASH_LEN*8, 0);
        Integer outer_hash(HASH_LEN*8, 0);
        vector<Integer> dummy_master_secs(num_servers);
        vector<Integer> dummy_outer_hashes(num_servers);
        Integer zero = Integer(HASH_LEN*8, 0);
        for (int i = 0; i < num_servers; i++) {
            Bit sel = index_gc.equal(Integer(INDEX_LEN*8, i)); // sel = 1 if i == index
            real_master_sec = real_master_sec.select(sel, master_secs[i]); // real_master_sec unchanged if sel=0, set to master_secs[i] if sel=1
            dummy_master_secs[i] = master_secs[i].select(sel, zero); // set to master_secs[i] if sel=0, or zero if sel=1
            outer_hash = outer_hash.select(sel, outer_hashes[i]);
            dummy_outer_hashes[i] = outer_hashes[i].select(sel, zero);
        }

        // compute keys
        //prf.compute_cats_sats(cats, sats, real_master_sec, session_hash);
        prf.compute_cats_sats_opt(cats, sats, outer_hash, cats_internal_hash_gc, sats_internal_hash_gc);
        prf.compute_application_keys(client_write_key,
                                     client_write_iv,
                                     server_write_key,
                                     server_write_iv,
                                     cats,
                                     sats
        );

        // reveal dummy secrets to prover
        dummy_master_secs_revealed = vector<string>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            dummy_master_secs_revealed[i] = dummy_master_secs[i].reveal<string>(PROVER);
        }

        // reveal IVs to both parties
        client_iv_revealed = client_write_iv.reveal<string>(PUBLIC);
        server_iv_revealed = server_write_iv.reveal<string>(PUBLIC);
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
        pmsa = Integer(len * 8, buf, PROVER);
        pmsb = Integer(len * 8, buf, VERIFIER);

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
        pmsa = Integer(len * 8, buf, PROVER);
        pmsb = Integer(len * 8, buf, VERIFIER);

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
