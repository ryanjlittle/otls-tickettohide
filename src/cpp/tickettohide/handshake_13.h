#ifndef _HAND_SHAKE_13_
#define _HAND_SHAKE_13_

#include "protocol/handshake.h"
#include "prf_13.h"
#include "constants.h"

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

    int num_servers;
    unsigned char* hs_hash_buf;
    unsigned char* app_hash_buf;
    uint8_t index = 0;
    vector<unsigned char*> hs_secs_buf, master_secs_buf;
    vector<uint32_t*> hs_hmac_inner_hash_buf, hs_hmac_outer_hash_buf;
    vector<uint32_t*> app_hmac_inner_hash_buf, app_hmac_outer_hash_buf;
    uint32_t* chts_hmac_internal_hash, *shts_hmac_internal_hash;
    uint32_t* cats_hmac_internal_hash, *sats_hmac_internal_hash;
    vector<Integer> hs_secs_gc;
    vector<Integer> master_secs_gc;
    vector<Integer> outer_hash_hs_gcs;
    vector<Integer> outer_hash_app_gcs;

    Integer chts, shts, cats, sats;
    string chts_revealed;
    string shts_revealed;

    Integer index_gc;
    vector<string> dummy_hs_secs_revealed;
    vector<string> dummy_master_secs_revealed;

    Integer master_key;
    Integer client_write_key;
    Integer server_write_key;
    Integer client_write_iv;
    Integer server_write_iv;
    string client_iv_revealed;
    string server_iv_revealed;
    unsigned char* client_iv_bytes_revealed;
    unsigned char* server_iv_bytes_revealed;

    unsigned char client_ufin[finished_msg_length];
    unsigned char server_ufin[finished_msg_length];

    Integer zk_index;
    Integer zk_chts_hash;
    Integer zk_shts_hash;
    Integer zk_cats_hash;
    Integer zk_sats_hash;
    Integer zk_client_iv;
    Integer zk_server_iv;
    Integer zk_client_key;
    Integer zk_server_key;

    Handshake_13(IO* io, IO* io_opt, COT<IO>* ot, int num_servers, bool ENABLE_ROUNDS_OPT = false)
        : io(io) {
        this->io_opt = io_opt;
        this->num_servers = num_servers;
    }
    ~Handshake_13() {
        delete[] hs_hash_buf;
        delete[] app_hash_buf;
        delete[] chts_hmac_internal_hash;
        delete[] shts_hmac_internal_hash;
        delete[] cats_hmac_internal_hash;
        delete[] sats_hmac_internal_hash;
        delete[] client_iv_bytes_revealed;
        delete[] server_iv_bytes_revealed;

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
            for (int i = 0; i < HASH_LEN/4; i++) {
                io->recv_data(&hash[i], sizeof(uint32_t));
            }
        }
        prf.compute_internal_chts_hash(chts_hmac_internal_hash, hs_hash_buf, hs_hmac_inner_hash_buf[index]);
        prf.compute_internal_shts_hash(shts_hmac_internal_hash, hs_hash_buf, hs_hmac_inner_hash_buf[index]);
    }

    inline void handshake_secret_setup_verifier() {
        // send internal HMAC hashes in the clear to the prover
        for (uint32_t* hash : hs_hmac_inner_hash_buf) {
            for (int i = 0; i < HASH_LEN/4; i++) {
                io->send_data(&hash[i], sizeof(uint32_t));
            }
        }
    }

    inline void application_secret_setup_prover() {
        // receive internal HMAC hashes
        for (uint32_t* hash : app_hmac_inner_hash_buf) {
            for (int i = 0; i < HASH_LEN/4; i++) {
                io->recv_data(&hash[i], sizeof(uint32_t));
            }
        }
        prf.compute_internal_cats_hash(cats_hmac_internal_hash, app_hash_buf, app_hmac_inner_hash_buf[index]);
        prf.compute_internal_sats_hash(sats_hmac_internal_hash, app_hash_buf, app_hmac_inner_hash_buf[index]);
    }

    inline void application_secret_setup_verifier() {
        // send internal HMAC hashes in the clear to the prover
        for (uint32_t* hash : app_hmac_inner_hash_buf) {
            for (int i = 0; i < HASH_LEN/4; i++) {
                io->send_data(&hash[i], sizeof(uint32_t));
            }
        }
    }

    inline void compute_handshake_secrets(int party) {
        if (party == VERIFIER) {
            handshake_secret_setup_verifier();
        } else if (party == PROVER) {
            handshake_secret_setup_prover();
        }

        // commit to prover inputs
        switch_to_zk();
        zk_index = Integer(INDEX_LEN*8, index, PROVER);
        zk_chts_hash = Integer(HASH_LEN*8, chts_hmac_internal_hash, PROVER);
        zk_shts_hash = Integer(HASH_LEN*8, shts_hmac_internal_hash, PROVER);
        sync_zk_gc<IO>();
        switch_to_gc();

        // feed inputs into GC
        index_gc = Integer(INDEX_LEN*8, index, PROVER);
        // Integer session_hash = Integer(HASH_LEN*8, hs_hash_buf, PROVER);
        Integer chts_internal_hash_gc(HASH_LEN*8, chts_hmac_internal_hash, PROVER);
        Integer shts_internal_hash_gc(HASH_LEN*8, shts_hmac_internal_hash, PROVER);

        hs_secs_gc = vector<Integer>(num_servers);
        outer_hash_hs_gcs = vector<Integer>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            hs_secs_gc[i] = Integer(HASH_LEN*8, hs_secs_buf[i], VERIFIER);
            outer_hash_hs_gcs[i] = Integer(HASH_LEN*8, hs_hmac_outer_hash_buf[i], VERIFIER);
        }

        // select real handshake secret and hash, as well and dummy secrets + hashes
        Integer real_hs_sec(HASH_LEN*8, 0);
        Integer outer_hash(HASH_LEN*8, 0);
        vector<Integer> dummy_hs_secs(num_servers);
        vector<Integer> dummy_hashes(num_servers);
        Integer zero = Integer(HASH_LEN*8, 0);
        for (int i = 0; i < num_servers; i++) {
            Bit sel = index_gc.equal(Integer(INDEX_LEN*8, i)); // sel = 1 if i == index
            real_hs_sec = real_hs_sec.select(sel, hs_secs_gc[i]); // real_hs_sec unchanged if sel=0, set to hs_sec[i] if sel=1
            dummy_hs_secs[i] = hs_secs_gc[i].select(sel, zero); // set to hs_sec[i] if sel=0, or zero if sel=1
            outer_hash = outer_hash.select(sel, outer_hash_hs_gcs[i]);
            dummy_hashes[i] = outer_hash_hs_gcs[i].select(sel, zero);
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
        if (party == VERIFIER) {
            application_secret_setup_verifier();
        } else if (party == PROVER) {
            application_secret_setup_prover();
        }

        // commit to prover's hash
        switch_to_zk();
        zk_cats_hash = Integer(HASH_LEN*8, cats_hmac_internal_hash, PROVER);
        zk_sats_hash = Integer(HASH_LEN*8, sats_hmac_internal_hash, PROVER);
        sync_zk_gc<IO>();
        switch_to_gc();

        // feed inputs into GC
        Integer cats_internal_hash_gc = Integer(HASH_LEN*8, cats_hmac_internal_hash, PROVER);
        Integer sats_internal_hash_gc = Integer(HASH_LEN*8, sats_hmac_internal_hash, PROVER);
        // Integer session_hash = Integer(HASH_LEN*8, app_hash_buf, PROVER);
        master_secs_gc = vector<Integer>(num_servers);
        outer_hash_app_gcs = vector<Integer>(num_servers);
        for (int i = 0; i < num_servers; i++) {
            master_secs_gc[i] = Integer(HASH_LEN*8, master_secs_buf[i], VERIFIER);
            outer_hash_app_gcs[i] = Integer(HASH_LEN*8, app_hmac_outer_hash_buf[i], VERIFIER);
        }

        // select real master secret and hash, and dummy secrets
        Integer real_master_sec(HASH_LEN*8, 0);
        Integer outer_hash(HASH_LEN*8, 0);
        vector<Integer> dummy_master_secs(num_servers);
        vector<Integer> dummy_outer_hashes(num_servers);
        Integer zero = Integer(HASH_LEN*8, 0);
        for (int i = 0; i < num_servers; i++) {
            Bit sel = index_gc.equal(Integer(INDEX_LEN*8, i)); // sel = 1 if i == index
            real_master_sec = real_master_sec.select(sel, master_secs_gc[i]); // real_master_sec unchanged if sel=0, set to master_secs[i] if sel=1
            dummy_master_secs[i] = master_secs_gc[i].select(sel, zero); // set to master_secs[i] if sel=0, or zero if sel=1
            outer_hash = outer_hash.select(sel, outer_hash_app_gcs[i]);
            dummy_outer_hashes[i] = outer_hash_app_gcs[i].select(sel, zero);
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

        client_iv_bytes_revealed = new unsigned char[IV_LEN];
        server_iv_bytes_revealed = new unsigned char[IV_LEN];
        client_write_iv.reveal((unsigned char*) client_iv_bytes_revealed, PUBLIC);
        server_write_iv.reveal((unsigned char*) server_iv_bytes_revealed, PUBLIC);
    }

    inline void prove_handshake_secrets(
        Integer& chts_zk,
        Integer& shts_zk,
        const vector<unsigned char*> &handshake_secrets,
        const vector<uint32_t*> &outer_hashes
        ) {

        Integer real_hs_sec(HASH_LEN*8, 0);
        Integer outer_hash(HASH_LEN*8, 0);
        vector<Integer> dummy_hs_secs(num_servers);
        vector<Integer> dummy_hashes(num_servers);
        Integer zero = Integer(HASH_LEN*8, 0);

        vector<Integer> hs_secs_zk(num_servers);

        for (int i = 0; i < num_servers; i++) {
            Integer hs_sec_zk(HASH_LEN*8, handshake_secrets[i], PUBLIC);
            Integer counter(INDEX_LEN*8, i, PUBLIC);
            Integer outer_hash_zk(HASH_LEN*8, outer_hashes[i], PUBLIC);

            Bit sel = zk_index.equal(counter);
            real_hs_sec = real_hs_sec.select(sel, hs_sec_zk);
            dummy_hs_secs[i] = hs_sec_zk.select(sel, zero);
            outer_hash = outer_hash.select(sel, outer_hash_zk);
            dummy_hashes[i] = outer_hash_zk.select(sel, zero);
        }

        prf.compute_chts_shts_opt(chts_zk, shts_zk, outer_hash, zk_chts_hash, zk_shts_hash);
    }

    inline void prove_application_keys(
        vector<unsigned char*> master_secs,
        const vector<uint32_t*> &outer_hashes,
        int party
    ) {
        // select real master secret and hash, and dummy secrets
        Integer real_master_sec(HASH_LEN*8, 0);
        Integer outer_hash(HASH_LEN*8, 0);
        vector<Integer> dummy_master_secs(num_servers);
        vector<Integer> dummy_outer_hashes(num_servers);
        Integer zero = Integer(HASH_LEN*8, 0);
        for (int i = 0; i < num_servers; i++) {
            Integer master_sec_zk(HASH_LEN*8, master_secs[i], PUBLIC);
            Integer counter(INDEX_LEN*8, i, PUBLIC);
            Integer outer_hash_zk(HASH_LEN*8, outer_hashes[i], PUBLIC);

            Bit sel = zk_index.equal(Integer(INDEX_LEN*8, i));
            real_master_sec = real_master_sec.select(sel, master_sec_zk);
            dummy_master_secs[i] = master_sec_zk.select(sel, zero);
            outer_hash = outer_hash.select(sel, outer_hash_zk);
            dummy_outer_hashes[i] = master_sec_zk.select(sel, zero);
        }
        Integer zk_cats;
        Integer zk_sats;
        prf.compute_cats_sats_opt(zk_cats, zk_sats, outer_hash, zk_cats_hash, zk_sats_hash);

        prf.compute_application_keys(zk_client_key,
                                     zk_client_iv,
                                     zk_server_key,
                                     zk_server_iv,
                                     zk_cats,
                                     zk_sats,
                                     true
        );

        check_zero<IO>(zk_client_iv, client_iv_bytes_revealed, IV_LEN, party);
        check_zero<IO>(zk_server_iv, server_iv_bytes_revealed, IV_LEN, party);
    }
};

#endif
