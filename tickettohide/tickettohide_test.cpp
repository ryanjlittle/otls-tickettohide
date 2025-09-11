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

const int num_servers = 4;

/* secrets */
int p_index = 0;
unsigned char hash_1[] = {0x86, 0x16, 0x2e, 0x86, 0x7a, 0x0f, 0x6a, 0x41, 0xb9, 0x62, 0x0e, 0x00, 0x49, 0xfd, 0x86, 0x17, 0x31, 0xac, 0xc2, 0x3b, 0x77, 0x38, 0x2a, 0x9c, 0xf2, 0x82, 0x8a, 0xea, 0x19, 0x49, 0xe7, 0x2d};
unsigned char hs_sec_1[] = {0x1d, 0xfc, 0x47, 0x02, 0x68, 0x1f, 0xfb, 0x47, 0x3f, 0x93, 0x29, 0x7d, 0xa8, 0x80, 0x47, 0x64, 0xb9, 0x1a, 0x54, 0xf3, 0xd0, 0xde, 0x15, 0xb0, 0x69, 0x0a, 0x02, 0xd2, 0x1f, 0x03, 0x5d, 0x07};
unsigned char hs_sec_2[] = {0x1b, 0x4a, 0xde, 0x27, 0x7a, 0x16, 0x15, 0x2d, 0xf1, 0x4f, 0x9f, 0xb5, 0x15, 0x15, 0x78, 0x97, 0xc3, 0xfc, 0xf5, 0x7c, 0xe8, 0xdf, 0xdd, 0x3a, 0x84, 0x83, 0x27, 0x06, 0x82, 0x32, 0x55, 0x7d};
unsigned char chts[] = {0x5c, 0x20, 0x0b, 0x33, 0xec, 0xde, 0xac, 0xf4, 0x44, 0xe5, 0x73, 0xda, 0xf5, 0x35, 0x9c, 0x37, 0x2c, 0xb8, 0x56, 0xbc, 0x1e, 0x89, 0x33, 0xa6, 0xde, 0xd1, 0xe7, 0x74, 0x41, 0xc3, 0x39, 0x63};
unsigned char shts[] = {0x75, 0x67, 0x43, 0x94, 0x5b, 0xad, 0x68, 0xe3, 0xbf, 0xed, 0x26, 0xc5, 0x56, 0x75, 0x1b, 0xb5, 0x06, 0x37, 0x4a, 0xa2, 0xb9, 0xfe, 0x8e, 0x5f, 0x5d, 0xa5, 0xb8, 0xa5, 0x7b, 0x29, 0xc3, 0xe4};
unsigned char hash_2[] = {0x81, 0xaf, 0xbf, 0x07, 0x79, 0xa2, 0xdb, 0xb5, 0xae, 0xf0, 0xa8, 0xbb, 0xef, 0x2e, 0x2e, 0x89, 0xe6, 0xeb, 0x91, 0x3c, 0xbc, 0x33, 0x12, 0x04, 0x2d, 0x72, 0xa4, 0xec, 0xbf, 0x68, 0x92, 0x51};
unsigned char m_sec_1[] = {0x13, 0xe5, 0x75, 0x87, 0x70, 0x49, 0xf3, 0x59, 0x6e, 0x4b, 0xb9, 0xb7, 0xd2, 0x6f, 0x88, 0x19, 0x49, 0x78, 0xdd, 0xe3, 0xae, 0x99, 0x6e, 0xdc, 0x4c, 0xaa, 0x1f, 0xbd, 0x22, 0xf0, 0xd9, 0xfe};
unsigned char m_sec_2[] = {0x33, 0xfc, 0xec, 0x4c, 0xdd, 0x71, 0xfe, 0xf2, 0xe3, 0x1c, 0x5d, 0x71, 0x83, 0xd2, 0xa9, 0x3f, 0xbf, 0xea, 0x67, 0xcf, 0x1a, 0xfc, 0xc9, 0x64, 0x76, 0x5c, 0x85, 0x6e, 0xe9, 0xc6, 0x22, 0xa0};
unsigned char cats[] = {0x37, 0x9d, 0x35, 0x58, 0xe7, 0xe0, 0x74, 0x41, 0x46, 0x58, 0x60, 0xd1, 0xdc, 0x39, 0xed, 0x8a, 0x53, 0x46, 0x81, 0xae, 0x8e, 0x37, 0x75, 0xa7, 0xf8, 0xb8, 0x55, 0x62, 0xf0, 0xef, 0xbd, 0x7b};
unsigned char client_key[] = {0xf4, 0xec, 0x27, 0xe0, 0xd3, 0x2f, 0x03, 0xbe, 0x65, 0x9a, 0x55, 0x33, 0x5a, 0x9a, 0x4e, 0x53};
unsigned char client_iv[] = {0xf0, 0xd8, 0x02, 0xc8, 0xe8, 0xdf, 0x23, 0xfa, 0xf7, 0x27, 0x0b, 0xbe};
unsigned char sats[] = {0xf4, 0xa1, 0x25, 0xe5, 0x99, 0xac, 0x17, 0x63, 0x72, 0x85, 0x17, 0x8b, 0x1b, 0xbb, 0x83, 0x56, 0x65, 0x10, 0x23, 0xc9, 0xf6, 0x44, 0x52, 0x4f, 0xc3, 0xd3, 0xac, 0x12, 0xea, 0x1d, 0x22, 0xda};
unsigned char server_key[] = {0x65, 0xd5, 0x8f, 0x3f, 0x6b, 0x8a, 0xd1, 0x9b, 0x6f, 0xa7, 0xef, 0xc1, 0x5a, 0x6b, 0x6a, 0x8f};
unsigned char server_iv[] = {0x1c, 0xc5, 0x9e, 0x7a, 0x6c, 0xd4, 0xc8, 0x8f, 0xe5, 0x45, 0x94, 0xa5};

template <typename IO>
void test_protocol(IO* io, IO* io_opt, COT<IO>* cot, int num_servers, int party) {

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
        vector<unsigned char*> hs_secs;
        hs_secs.push_back(hs_sec_1);
        hs_secs.push_back(hs_sec_2);
        hs_secs.push_back(hs_sec_2);
        hs_secs.push_back(hs_sec_2);
        hs->set_verifier_handshake_secrets(hs_secs);
    } else {
        hs->set_prover_handshake_secrets(p_index, hash_1);
    }

    hs->compute_handshake_secrets();

    std::cout << "CHTS: ";
    print_hex_string_reversed(hs->chts_revealed);
    std::cout << std::endl;
    std::cout << "SHTS: ";
    print_hex_string_reversed(hs->shts_revealed);
    std::cout << std::endl;

    if (party == BOB) {
        vector<unsigned char*> master_secs;
        master_secs.push_back(m_sec_1);
        master_secs.push_back(m_sec_2);
        master_secs.push_back(m_sec_2);
        master_secs.push_back(m_sec_2);
        hs->set_verifier_application_secrets(master_secs);
    } else {
        hs -> set_prover_application_secrets(hash_2);
    }

    hs->compute_application_keys();

    std::cout << "Client key: ";
    print_hex_string_reversed(hs->client_write_key.reveal<string>());
    std::cout << "Client IV: ";
    print_hex_string_reversed(hs->client_iv_revealed);
    std::cout << "Server key: ";
    print_hex_string_reversed(hs->server_write_key.reveal<string>());
    std::cout << "Server IV: ";
    print_hex_string_reversed(hs->server_iv_revealed);

    // AEAD<IO>* aead_c = new AEAD<IO>(io, io_opt, cot, hs->client_write_key, hs->client_write_iv);
    // AEAD<IO>* aead_s = new AEAD<IO>(io, io_opt, cot, hs->server_write_key, hs->server_write_iv);
    //
    // Record<IO>* rd = new Record<IO>;
    //
    // // encrypts the query message
    // unsigned char* cctxt = new unsigned char[QUERY_BYTE_LEN];
    // unsigned char* ctag = new unsigned char[tag_length];
    // rd->encrypt(aead_c, io, cctxt, ctag, cmsg, QUERY_BYTE_LEN, aad, aad_len, iv_c_oct, 8, party);


}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
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
    test_protocol<NetIO>(io[0], io_opt, cot, num_servers, party);
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
