#include "aead_13.h"
#include "backend/backend.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include "handshake_13.h"
#include "post_record_tth.h"
#include "tth_utils.h"
#include "protocol/com_conv.h"

#include <iostream>

using namespace std;
using namespace emp;

const size_t QUERY_BYTE_LEN = 2 * 1024;
const size_t RESPONSE_BYTE_LEN = 2 * 1024;

const int threads = 1;

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

    AEAD_13<IO>* aead_c = new AEAD_13<IO>(io,
                                     io_opt,
                                     cot,
                                     hs->client_write_key,
                                     hs->client_write_iv,
                                     party);

    unsigned char* ctxt = new unsigned char[ptext_len];
    unsigned char* tag = new unsigned char[TAG_LEN];

    aead_c->encrypt(io,
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

    /* ========================================================================
    *  Proof of correct garbling
    *
    *  Prover uses an interactive ZK proof to convince the verifier they garbled
    *  all circuits correctly.
    * ======================================================================= */

    // wait for prover and verifier ok to continue
    string ok_msg;
    cin >> ok_msg;
    if (ok_msg != "ok") {
        error("Received unexpected message (expected \"ok\")");
    }

    switch_to_zk();
    PostRecordTTH<IO>* prd = new PostRecordTTH<IO>(io, hs, aead_c, num_servers, party);
    Integer tag_z0;

    prd->reveal_verifier_secrets();
    prd->prove_and_check_chts_shts();
    prd->prove_and_check_master_sec();
    prd->prove_record_client(tag_z0, ctxt, ptext_len, hs->client_iv_bytes_revealed, IV_LEN);

    sync_zk_gc<IO>();
    switch_to_gc();

    // Print opened keys to prover's terminal
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
    delete aead_c;
    delete prd;
    delete[] ptext;
    delete[] adata;
    delete[] ctxt;
    delete[] tag;
}

inline void parse_args(const char *const *arg, int *party, int *servers,
                       int *port, const char **address) {
    *party = atoi(arg[1]);
    *servers = atoi(arg[2]);
    *port   = atoi(arg[3]);
    if (arg[4]) {
        *address = arg[4];
    } else {
        *address = "127.0.0.1";
    }
}


int main(int argc, char** argv) {
    int port, party, num_servers;
    const char* address;

    parse_args(argv, &party, &num_servers, &port, &address);

    NetIO* io_opt = new NetIO(party == PROVER ? nullptr : address, port + threads);

    NetIO* io[threads];
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++) {
        io[i] = new NetIO(party == PROVER ? nullptr : address, port + i);
        ios[i] = new BoolIO<NetIO>(io[i], party == PROVER);
    }

    // auto start = emp::clock_start();
    setup_protocol<NetIO>(io[0], ios, threads, party);


    auto prot = (PrimusParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;

    // auto setup_time = emp::time_from(start);
    // cout << "setup time: " << setup_time << " us" << endl;

    full_protocol<NetIO>(io[0], io_opt, cot, num_servers, party);

    // auto run_time = emp::time_from(start) - setup_time;
    // cout << "run time: " << run_time << " us" << endl;

    // cout << "total time: " << emp::time_from(start) << " us" << endl;
    // cout << "gc AND gates: " << dec << gc_circ_buf->num_and() << endl;
    // cout << "zk AND gates: " << dec << zk_circ_buf->num_and() << endl;

    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    // cout << "comm: " << (getComm(io, threads, io_opt) * 1.0) / 1024 << " KBytes" << endl;

    delete io_opt;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
    return 0;
}
