#include "backend/backend.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include "protocol/aead.h"
#include "protocol/com_conv.h"
#include "protocol/post_record.h"
#include "protocol/record.h"
#include "handshake_13.h"
#include <iostream>
#if defined(__linux__)
#include <sys/time.h>
#include <sys/resource.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/resource.h>
#include <mach/mach.h>
#endif
#include "test/io_utils.h"

using namespace std;
using namespace emp;

const size_t QUERY_BYTE_LEN = 2 * 1024;
const size_t RESPONSE_BYTE_LEN = 2 * 1024;

const int threads = 1;

template <typename IO>
void full_protocol(IO* io, IO* io_opt, COT<IO>* cot, int num_servers, int party) {

    Handshake_13<NetIO>* hs = new Handshake_13<NetIO>(io, io_opt, cot, num_servers);

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    unsigned char* ufinc = new unsigned char[finished_msg_length];
    unsigned char* ufins = new unsigned char[finished_msg_length];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    unsigned char* cmsg = new unsigned char[QUERY_BYTE_LEN];
    unsigned char* smsg = new unsigned char[RESPONSE_BYTE_LEN];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);
    memset(cmsg, 0x55, QUERY_BYTE_LEN);
    memset(smsg, 0x66, QUERY_BYTE_LEN);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);
    auto start = emp::clock_start();

    if (party == BOB) {
        vector<BIGNUM*> hs_secs;
        string hex_str;
        hs_secs.reserve(num_servers);
        for (int i = 0; i < num_servers; i++) {
            cin >> hex_str;
            BIGNUM* hs_sec = BN_new();
            BN_hex2bn(&hs_sec, hex_str.c_str());
            hs_secs.push_back(hs_sec);
        }
        // TODO: need to free these values at some point
        // for (BIGNUM* hs_sec : hs_secs) {
        //     BN_free(hs_sec);
        // }

        hs->set_verifier_handshake_secrets(hs_secs);
    } else {
        int index;
        cin >> index;
        if (index < 0 || index >= num_servers) {
            throw runtime_error("Invalid server index");
        }
        string hex_str;
        cin >> hex_str;
        BIGNUM* hash_val = BN_new();
        BN_hex2bn(&hash_val, hex_str.c_str());

        hs->set_prover_handshake_secrets(index, hash_val);
    }

    hs->compute_handshake_secrets();
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

    delete hs;
    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    // delete[] finc_ctxt;
    // delete[] finc_tag;
    // delete[] msg;
    delete[] cmsg;
    delete[] smsg;

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
    std::cout << "THIS IS RUNNING TICKET TO HIDE PROGRAM :)" << std::endl;
    int port, party, num_servers;
    parse_args(argv, &party, &num_servers, &port);

    NetIO* io_opt = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + threads);

    NetIO* io[threads];
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++) {
        io[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);
        ios[i] = new BoolIO<NetIO>(io[i], party == ALICE);
    }

    auto start = emp::clock_start();
    setup_protocol<NetIO>(io[0], ios, threads, party);
    cout << "setup time: " << emp::time_from(start) << " us" << endl;
    auto prot = (PrimusParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    full_protocol<NetIO>(io[0], io_opt, cot, num_servers, party);
    cout << "total time: " << emp::time_from(start) << " us" << endl;

    cout << "gc AND gates: " << dec << gc_circ_buf->num_and() << endl;
    cout << "zk AND gates: " << dec << zk_circ_buf->num_and() << endl;
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

#if defined(__linux__)
    struct rusage rusage;
    if (!getrusage(RUSAGE_SELF, &rusage))
        std::cout << "[Linux]Peak resident set size: " << (size_t)rusage.ru_maxrss
                  << std::endl;
    else
        std::cout << "[Linux]Query RSS failed" << std::endl;
#elif defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) ==
        KERN_SUCCESS)
        std::cout << "[Mac]Peak resident set size: " << (size_t)info.resident_size_max
                  << std::endl;
    else
        std::cout << "[Mac]Query RSS failed" << std::endl;
#endif
    cout << "comm: " << (getComm(io, threads, io_opt) * 1.0) / 1024 << " KBytes" << endl;
    delete io_opt;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
    return 0;
}
