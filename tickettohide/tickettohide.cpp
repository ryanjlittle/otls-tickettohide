#include "aead_13.h"
#include "backend/backend.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include "handshake_13.h"
#include "protocol/com_conv.h"
#include "protocol/post_record.h"
#include <iostream>

using namespace std;
using namespace emp;

const size_t QUERY_BYTE_LEN = 2 * 1024;
const size_t RESPONSE_BYTE_LEN = 2 * 1024;

const int threads = 2;

template <typename IO>
void full_protocol(IO* io, IO* io_opt, COT<IO>* cot, int num_servers, int party) {

    Handshake_13<NetIO>* hs = new Handshake_13<NetIO>(io, io_opt, cot, num_servers);

    /* =========================================================================
    *  MPC CHTS/SHTS computation
    *
    *  Prover inputs index of real server and transcript hash, verifier inputs a
    *  list of handshake secrets. Under MPC, they compute the CHTS and SHTS
    *  corresponding to the prover's selected server. These values are revealed
    *  to the prover, as well as all the other verifier's input secrets that
    *  were unused.
    * ======================================================================= */

    if (party == PROVER) {
        // take in inputs
        int index;
        cin >> index;
        if (index < 0 || index >= num_servers) {
            throw runtime_error("Invalid server index");
        }
        string hash_hex;
        cin >> hash_hex;
        if (hash_hex.size() != HASH_LEN*2) {
            throw runtime_error("Invalid hash length");
        }
        unsigned char* hash_bytes = new unsigned char[HASH_LEN];
        hex_str_to_bytes(hash_bytes, hash_hex);
        hs->set_prover_handshake_secrets(index, hash_bytes);
        delete[] hash_bytes;
    } else if (party == VERIFIER) {
        vector<const unsigned char*> hs_secs;
        string hs_sec_hex;
        hs_secs.reserve(num_servers);
        for (int i = 0; i < num_servers; i++) {
            cin >> hs_sec_hex;
            if (hs_sec_hex.size() != HASH_LEN*2) {
                throw runtime_error("Invalid secret length");
            }
            unsigned char* hs_sec_bytes = new unsigned char[HASH_LEN];
            hex_str_to_bytes(hs_sec_bytes, hs_sec_hex);
            hs_secs.push_back(hs_sec_bytes);
            //delete[] hs_sec_bytes;

            // cin >> hs_sec_hex;
            // hs_secs.push_back((unsigned char*) hs_sec_hex.data());
        }
        hs->set_verifier_handshake_secrets(hs_secs);
        for (auto sec : hs_secs) {
            delete[] sec;
        }
    }

    hs->compute_handshake_secrets(party);

    // write prover's outputs to console
    if (party == PROVER) {
        print_bin_str_as_hex_reversed(hs->chts_revealed);
        print_bin_str_as_hex_reversed(hs->shts_revealed);
        for (string dummy_sec : hs->dummy_hs_secs_revealed) {
            print_bin_str_as_hex_reversed(dummy_sec);
        }
    }

    /* ========================================================================
    *  MPC key derivation
    *
    *  Prover inputs transcript hash, verifier inputs a list of master secrets.
    *  Under MPC, they compute the client and server AES keys and IVs
    *  corresponding to the prover's selected server (which they inputted in the
    *  prior stage). The keys are kept secret, the IVs are revealed to both
    *  parties. Additionally, the prover learns the all the verifier's unused
    *  master secrets.
    * ======================================================================= */

    // take in inputs
    if (party == PROVER) {
        string hash_hex;
        cin >> hash_hex;
        if (hash_hex.size() != HASH_LEN*2) {
            throw runtime_error("Invalid hash length");
        }
        unsigned char* hash_bytes = new unsigned char[HASH_LEN];
        hex_str_to_bytes(hash_bytes, hash_hex);
        hs->set_prover_application_secrets(hash_bytes);
        delete[] hash_bytes;
        // string hash_hex;
        // cin >> hash_hex;
        // hs->set_prover_application_secrets((unsigned char*) hash_hex.data());
    } else if (party == VERIFIER) {
        vector<const unsigned char*> master_secs;
        string msec_hex;
        master_secs.reserve(num_servers);
        for (int i = 0; i < num_servers; i++) {
            cin >> msec_hex;
            if (msec_hex.size() != HASH_LEN*2) {
                throw runtime_error("Invalid secret length");
            }
            unsigned char* msec_bytes = new unsigned char[HASH_LEN];
            hex_str_to_bytes(msec_bytes, msec_hex);
            master_secs.push_back(msec_bytes);
            //delete[] msec_bytes;

            // cin >> msec_hex;
            // master_secs.push_back((unsigned char*) msec_hex.data());
        }
        hs->set_verifier_application_secrets(master_secs);
        for (auto sec : master_secs) {
            delete[] sec;
        }
    }

    hs->compute_application_keys(party);

    // write prover's outputs to console
    if (party == PROVER) {
        for (string dummy_sec : hs->dummy_master_secs_revealed) {
            print_bin_str_as_hex_reversed(dummy_sec);
        }
    }

    /* ========================================================================
    *  MPC AES-GCM encryption
    *
    *  Prover inputs a plaintext and additional data for an AES-GCM encryption.
    *  Using the client key and IV computed in the previous stage, computes the
    *  ciphertext and authentication tag under MPC. Both are revealed to (only)
    *  the prover.
    * ======================================================================= */

    uint64_t ptext_len, adata_len;
    unsigned char* ptext;
    unsigned char* adata;

    if (party == PROVER) {
        // take in inputs
        string ptext_hex, adata_hex;
        cin >> ptext_hex;
        cin >> adata_hex;

        if (ptext_hex.size() % 2 != 0) {
            throw runtime_error("Invalid plaintext");
        }
        if (adata_hex.size() % 2 != 0) {
            throw runtime_error("Invalid additional data");
        }
        ptext_len = ptext_hex.size() / 2;
        adata_len = adata_hex.size() / 2;
        ptext = new unsigned char[ptext_len];
        adata = new unsigned char[adata_len];
        hex_str_to_bytes(ptext, ptext_hex);
        hex_str_to_bytes(adata, adata_hex);
        // memcpy(ptext, ptext_hex.data(), ptext_len);
        // memcpy(adata, adata_hex.data(), adata_len);

        // send lengths to verifier
        io->send_data(&ptext_len, sizeof(uint64_t));
        io->send_data(&adata_len, sizeof(uint64_t));
    } else if (party == VERIFIER) {
        // receive lengths from prover
        io->recv_data(&ptext_len, sizeof(uint64_t));
        io->recv_data(&adata_len, sizeof(uint64_t));

        ptext = new unsigned char[ptext_len];
        adata = new unsigned char[adata_len];
        memset(ptext, 0, ptext_len);
        memset(adata, 0, adata_len);
    }

    AEAD_13<IO> aead_c = AEAD_13<IO>(io,
                                     io_opt,
                                     cot,
                                     hs->client_write_key,
                                     hs->client_write_iv,
                                     party);

    unsigned char* ctxt = new unsigned char[ptext_len];
    unsigned char* tag = new unsigned char[TAG_LEN];

    aead_c.encrypt(io,
                   ctxt,
                   tag,
                   ptext,
                   ptext_len,
                   adata,
                   adata_len);

    // write tag and ciphertext to prover's console
    if (party == PROVER) {
        unsigned char* ctxt_and_tag = new unsigned char[ptext_len + TAG_LEN];
        memcpy(ctxt_and_tag, ctxt, ptext_len);
        memcpy(ctxt_and_tag + ptext_len, tag, TAG_LEN);
        print_as_hex(ctxt_and_tag, ptext_len + TAG_LEN);
        delete[] ctxt_and_tag;
    }

    // TODO: post-record

    // reveal all keys to prover
    string client_key = hs->client_write_key.reveal<string>(PROVER);
    string client_iv = hs->client_write_iv.reveal<string>(PROVER);
    string server_key = hs->server_write_key.reveal<string>(PROVER);
    string server_iv = hs->server_write_iv.reveal<string>(PROVER);
    if (party == PROVER) {
        print_bin_str_as_hex_reversed(client_key);
        print_bin_str_as_hex_reversed(client_iv);
        print_bin_str_as_hex_reversed(server_key);
        print_bin_str_as_hex_reversed(server_iv);
    }

    delete hs;
    delete[] ptext;
    delete[] adata;
    delete[] ctxt;
    delete[] tag;

    //
    // BIGNUM* pms = BN_new();
    // BIGNUM* full_pms = BN_new();
    // hs->compute_pms_online(pms, V, party);
    //
    // //hs->compute_master_key(pms, rc, 32, rs, 32);
    //
    // // Use session_hash instead of rc!
    // hs->compute_extended_master_key(pms, rc, 32);
    //
    // hs->compute_expansion_keys(rc, 32, rs, 32);
    //
    // hs->compute_client_finished_msg(client_finished_label, client_finished_label_length, tau_c,
    //                                 32);
    // hs->compute_server_finished_msg(server_finished_label, server_finished_label_length, tau_s,
    //                                 32);
    //
    // // padding the last 8 bytes of iv_c and iv_s according to TLS!
    // unsigned char iv_c_oct[8], iv_s_oct[8];
    // memset(iv_c_oct, 0x11, 8);
    // memset(iv_s_oct, 0x22, 8);
    // AEAD<IO>* aead_c = new AEAD<IO>(io, io_opt, cot, hs->client_write_key, hs->client_write_iv);
    // AEAD<IO>* aead_s = new AEAD<IO>(io, io_opt, cot, hs->server_write_key, hs->server_write_iv);
    //
    // Record<IO>* rd = new Record<IO>;
    //
    // unsigned char* finc_ctxt = new unsigned char[finished_msg_length];
    // unsigned char* finc_tag = new unsigned char[tag_length];
    // unsigned char* msg = new unsigned char[finished_msg_length];
    //
    // // Use correct message instead of hs->client_ufin!
    // hs->encrypt_client_finished_msg(aead_c, finc_ctxt, finc_tag, hs->client_ufin, 12, aad,
    //                                 aad_len, iv_c_oct, 8, party);
    //
    // // Use correct ciphertext instead of finc_ctxt!
    // hs->decrypt_server_finished_msg(aead_s, msg, finc_ctxt, finished_msg_length, finc_tag, aad,
    //                                 aad_len, iv_s_oct, 8, party);
    // cout << "handshake time: " << emp::time_from(start) << " us" << endl;
    //
    // unsigned char* cctxt = new unsigned char[QUERY_BYTE_LEN];
    // unsigned char* ctag = new unsigned char[tag_length];
    //
    // unsigned char* sctxt = new unsigned char[RESPONSE_BYTE_LEN];
    // unsigned char* stag = new unsigned char[tag_length];
    // start = emp::clock_start();
    //
    // // the client encrypts the first message, and sends to the server.
    // rd->encrypt(aead_c, io, cctxt, ctag, cmsg, QUERY_BYTE_LEN, aad, aad_len, iv_c_oct, 8, party);
    // cout << "record time: " << emp::time_from(start) << " us" << endl;
    // // prove handshake in post-record phase.
    // start = emp::clock_start();
    // switch_to_zk();

    // The following fails to compile since we haven't defined a PostRecord constructor that takes in a Handshake13

    // PostRecord<IO>* prd = new PostRecord<IO>(io, hs, aead_c, aead_s, rd, party);
    // prd->reveal_pms(Ts);
    // // Use correct finc_ctxt, fins_ctxt, iv_c, iv_s according to TLS!
    // prd->prove_and_check_handshake_step1(rc, 32, rs, 32, tau_c, 32, tau_s, 32,
    //                                      rc, 32, true);
    // prd->prove_and_check_handshake_step2(finc_ctxt, finished_msg_length,
    //                                      iv_c_oct, 8);
    // prd->prove_and_check_handshake_step3(finc_ctxt, finished_msg_length,
    //                                      iv_s_oct, 8);
    // Integer prd_cmsg, prd_cmsg2, prd_smsg, prd_smsg2, prd_cz0, prd_c2z0, prd_sz0, prd_s2z0;
    // prd->prove_record_client(prd_cmsg, prd_cz0, cctxt, QUERY_BYTE_LEN, iv_c_oct, 8);
    // prd->prove_record_server_last(prd_smsg2, prd_s2z0, cctxt, RESPONSE_BYTE_LEN, iv_s_oct, 8);
    //
    // // Use correct finc_ctxt and fins_ctxt!
    // prd->finalize_check(finc_ctxt, finc_tag, 12, aad, finc_ctxt, finc_tag, 12, aad, {prd_cz0},
    //                     {cctxt}, {ctag}, {QUERY_BYTE_LEN}, {aad}, 1, {prd_sz0}, {sctxt},
    //                     {stag}, {RESPONSE_BYTE_LEN}, {aad}, 1, aad_len);
    //
    // sync_zk_gc<IO>();
    // switch_to_gc();
    // cout << "post record: " << emp::time_from(start) << " us" << endl;
    // EC_POINT_free(V);
    // EC_POINT_free(Tc);
    // BN_free(t);
    // BN_free(ts);
    // BN_free(pms);
    // BN_free(full_pms);
    // EC_POINT_free(Ts);

    //delete hs;
    // delete[] finc_ctxt;
    // delete[] finc_tag;
    // delete[] msg;
    // delete[] cmsg;
    // delete[] smsg;

    // delete aead_c;
    // delete aead_s;
    // delete rd;
    // delete prd;
}

inline void parse_args(const char *const *arg, int *party, int *servers, int *port) {
    *party = atoi (arg[1]);
    *servers = atoi (arg[2]);
    *port = atoi (arg[3]);
}


int main(int argc, char** argv) {
    int port, party, num_servers;
    parse_args(argv, &party, &num_servers, &port);

    NetIO* io_opt = new NetIO(party == PROVER ? nullptr : "127.0.0.1", port + threads);

    NetIO* io[threads];
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++) {
        io[i] = new NetIO(party == PROVER ? nullptr : "127.0.0.1", port + i);
        ios[i] = new BoolIO<NetIO>(io[i], party == PROVER);
    }

    //auto start = emp::clock_start();
    setup_protocol<NetIO>(io[0], ios, threads, party);

    auto prot = (PrimusParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    full_protocol<NetIO>(io[0], io_opt, cot, num_servers, party);


    //cout << "total time: " << emp::time_from(start) << " us" << endl;
    //cout << "gc AND gates: " << dec << gc_circ_buf->num_and() << endl;
    //cout << "zk AND gates: " << dec << zk_circ_buf->num_and() << endl;

    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    delete io_opt;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
    return 0;
}
