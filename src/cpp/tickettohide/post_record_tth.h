#ifndef OTLS_POST_RECORD_TTH_H
#define OTLS_POST_RECORD_TTH_H

#include "aead_13_izk.h"
#include "emp-tool/emp-tool.h"
#include "handshake_13.h"

template <typename IO>
class PostRecordTTH {
   public:
    IO* io;
    Handshake_13<IO>* hs = nullptr;
    AEAD_13<IO>* aead = nullptr;
    AEAD_13_Proof<IO>* aead_proof = nullptr;
    int num_servers;
    int party;

    vector<unsigned char*> hs_secs;
    vector<uint32_t*> hs_hmac_inner_hashes;
    vector<uint32_t*> hs_hmac_outer_hashes;
    vector<unsigned char*> master_secs;
    vector<uint32_t*> app_hmac_inner_hashes;
    vector<uint32_t*> app_hmac_outer_hashes;

    Integer chts;
    Integer shts;


    PostRecordTTH(IO* io,
               Handshake_13<IO>* hs,
               AEAD_13<IO>* aead,
               int num_servers,
               int party) {
        this->io = io;
        this->hs = hs;
        this->aead = aead;
        this->num_servers = num_servers;
        this->party = party;
    }

    ~PostRecordTTH() {
        delete aead_proof;
        if (party == PROVER) {
            for (unsigned char* hs_sec : hs_secs) {
                delete[] hs_sec;
            }
            for (unsigned char* master_sec : master_secs) {
                delete[] master_sec;
            }
            for (uint32_t* hash : hs_hmac_inner_hashes) {
                delete[] hash;
            }
            for (uint32_t* hash : hs_hmac_outer_hashes) {
                delete[] hash;
            }
            for (uint32_t* hash : app_hmac_inner_hashes) {
                delete[] hash;
            }
            for (uint32_t* hash : app_hmac_outer_hashes) {
                delete[] hash;
            }
        }
    }

    inline void reveal_verifier_secrets() {
        if (party == VERIFIER) {
            hs_secs = hs->hs_secs_buf;
            master_secs = hs->master_secs_buf;
            hs_hmac_inner_hashes = hs->hs_hmac_inner_hash_buf;
            hs_hmac_outer_hashes = hs->hs_hmac_outer_hash_buf;
            app_hmac_inner_hashes = hs->app_hmac_inner_hash_buf;
            app_hmac_outer_hashes = hs->app_hmac_outer_hash_buf;

            for (unsigned char* hs_sec : hs_secs) {
                io->send_data(hs_sec, HASH_LEN);
            }
            for (unsigned char* master_sec : master_secs) {
                io->send_data(master_sec, HASH_LEN);
            }
            // key shares

        } else if (party == PROVER) {
            hs_secs.resize(num_servers);
            master_secs.resize(num_servers);

            for (int i = 0; i < num_servers; i++) {
                hs_secs[i] = new unsigned char[HASH_LEN];
                io->recv_data(hs_secs[i], HASH_LEN);
                reverse(hs_secs[i], hs_secs[i] + HASH_LEN);
            }
            for (int i = 0; i < num_servers; i++) {
                master_secs[i] = new unsigned char[HASH_LEN];
                io->recv_data(master_secs[i], HASH_LEN);
                reverse(master_secs[i], master_secs[i] + HASH_LEN);
            }

            // compute and verify partial hash for HMAC computation
            hs_hmac_outer_hashes.resize(num_servers);
            hs_hmac_inner_hashes.resize(num_servers);
            app_hmac_outer_hashes.resize(num_servers);
            app_hmac_inner_hashes.resize(num_servers);
            for (int i=0; i < num_servers; i++) {
                HMAC_SHA256_local hs_hmac;
                HMAC_SHA256_local app_hmac;
                hs_hmac.init(hs_secs[i], HASH_LEN);
                app_hmac.init(master_secs[i], HASH_LEN);

                hs_hmac_inner_hashes[i] = new uint32_t[HASH_LEN/4];
                hs_hmac_outer_hashes[i] = new uint32_t[HASH_LEN/4];
                app_hmac_inner_hashes[i] = new uint32_t[HASH_LEN/4];
                app_hmac_outer_hashes[i] = new uint32_t[HASH_LEN/4];
                hs_hmac.compute_inner_key_hash(hs_hmac_inner_hashes[i]);
                hs_hmac.compute_outer_key_hash(hs_hmac_outer_hashes[i]);
                app_hmac.compute_inner_key_hash(app_hmac_inner_hashes[i]);
                app_hmac.compute_outer_key_hash(app_hmac_outer_hashes[i]);

                if (memcmp(hs_hmac_inner_hashes[i], hs->hs_hmac_inner_hash_buf[i], HASH_LEN/4) != 0) {
                    error("Handshake secret and inner HMAC hash are not consistent");
                }
                if (memcmp(app_hmac_inner_hashes[i], hs->app_hmac_inner_hash_buf[i], HASH_LEN/4) != 0) {
                    error("Application secret and inner HMAC hash are not consistent");
                }
                reverse(master_secs[i], master_secs[i] + HASH_LEN);
                reverse(hs_secs[i], hs_secs[i] + HASH_LEN);
            }
        }
    }

    inline void prove_and_check_chts_shts() {
        // call a function in hs to prove chts and shts computations
        hs->prove_handshake_secrets(chts, shts, hs_secs, hs_hmac_outer_hashes);
    }

    inline void prove_and_check_master_sec() {
        // check that the real server's master sec was computed correctly
        hs->prove_application_keys(master_secs, app_hmac_outer_hashes, party);
        aead_proof = new AEAD_13_Proof<IO>(aead, hs->zk_client_key, hs->zk_client_iv, party);
    }

    inline void prove_record_client(Integer& z0,
                                    const unsigned char* ctxt,
                                    size_t ctxt_len,
                                    const unsigned char* iv,
                                    size_t iv_len) {
        // prove record was encrypted correctly
        aead_proof->prove_aead(z0, ctxt, ctxt_len, iv, iv_len);
    }
};

#endif