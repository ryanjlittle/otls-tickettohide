#include "protocol/aead.h"
#include "emp-tool/emp-tool.h"
#include "cipher/utils.h"
#include "backend/backend.h"

void convert(int party) {
    Integer a(256, 10, ALICE);
    block* b = new block[2];
    if (party == ALICE) {
        for (int i = 0; i < 256; i++) {
            cout << getLSB(a[i].bit);
        }
        cout << endl;
    }
    cout << "a reveal: " << a.reveal<string>() << endl;
    integer_to_block(b, a);
    if (party == ALICE)
        cout << b[0] << " " << b[1] << endl;

    unsigned char* c = new unsigned char[32];
    integer_to_chars(c, a);
    if (party == ALICE) {
        cout << "c: ";
        for (int i = 0; i < 32; i++) {
            cout << hex << (int)c[i];
        }
        cout << dec << endl;
    }
    delete[] b;
    delete[] c;
}

void aead_encrypt_test(
  NetIO* io, NetIO* io_opt, COT<NetIO>* ot, int party, bool sec_type = false) {
    unsigned char keyc[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    reverse(keyc, keyc + 16);
    Integer key(128, keyc, ALICE);

    unsigned char msg[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
                           0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
                           0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
                           0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                           0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a,
                           0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    size_t msg_len = sizeof(msg);
    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    unsigned char iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                          0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    size_t iv_len = sizeof(iv);

    unsigned char fixed_iv_oct[4];
    memcpy(fixed_iv_oct, iv, 4);
    reverse(fixed_iv_oct, fixed_iv_oct + 4);
    Integer fixed_iv(4 * 8, fixed_iv_oct, PUBLIC);

    unsigned char* ctxt = new unsigned char[msg_len];
    unsigned char tag[16];

    auto start = emp::clock_start();
    AEAD<NetIO> aead(io, io_opt, ot, key, fixed_iv);
    aead.encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len, iv + 4, iv_len - 4, party, sec_type);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    cout << "tag: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)tag[i];
    }
    cout << endl;

    cout << "ctxt: ";
    for (size_t i = 0; i < msg_len; i++) {
        cout << hex << (int)ctxt[i];
    }
    cout << endl;

    delete[] ctxt;
}

void aead_decrypt_test(
  NetIO* io, NetIO* io_opt, COT<NetIO>* ot, int party, bool sec_type = false) {
    unsigned char keyc[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    reverse(keyc, keyc + 16);
    Integer key(128, keyc, ALICE);

    unsigned char msg[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t msg_len = sizeof(msg);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    unsigned char iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                          0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    size_t iv_len = sizeof(iv);

    unsigned char fixed_iv_oct[4];
    memcpy(fixed_iv_oct, iv, 4);
    reverse(fixed_iv_oct, fixed_iv_oct + 4);
    Integer fixed_iv(4 * 8, fixed_iv_oct, PUBLIC);

    unsigned char ctxt[] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72,
                            0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f,
                            0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
                            0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
                            0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3,
                            0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};

    size_t ctxt_len = sizeof(ctxt);

    unsigned char tag[] = {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
                           0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

    auto start = emp::clock_start();
    AEAD<NetIO> aead(io, io_opt, ot, key, fixed_iv);
    bool res =
      aead.decrypt(io, msg, ctxt, ctxt_len, tag, aad, aad_len, iv + 4, iv_len - 4, party, sec_type);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    if (party == ALICE) {
        cout << "ALICE res: " << res << endl;
        cout << "ALICE msg: ";
        for (size_t i = 0; i < msg_len; i++) {
            cout << hex << (int)msg[i];
        }
        cout << endl;

    } else {
        cout << "BOB res: " << res << endl;
        cout << "BOB msg: ";
        for (size_t i = 0; i < msg_len; i++) {
            cout << hex << (int)msg[i];
        }
        cout << endl;
    }
}

int threads = 4;
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

    setup_protocol(io[0], ios, threads, party);
    auto prot = (PrimusParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;

    aead_encrypt_test(io[0], io_opt, cot, party);
    aead_decrypt_test(io[0], io_opt, cot, party, true);
    convert(party);
    cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;
    finalize_protocol();
    size_t totalCounter = 0;
    for (int i = 0; i < threads; i++) {
        totalCounter += io[i]->counter;
    }
    totalCounter += io_opt->counter;
    cout << totalCounter << endl;

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
    delete io_opt;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
}
