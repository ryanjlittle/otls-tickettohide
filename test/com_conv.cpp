#include "protocol/com_conv.h"
#include "backend/backend.h"
#include "emp-zk/emp-zk.h"
#include "emp-ot/emp-ot.h"
#include <iostream>
#include "backend/switch.h"

using namespace std;
using namespace emp;

template <typename IO>
void com_conv_test(
  IO* io, COT<IO>* cot, block Delta, int party, Integer& input, size_t array_len) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_copy(q, EC_GROUP_get0_order(group));

    BIGNUM* sa = BN_new();
    BIGNUM* sb = BN_new();
    BIGNUM* s = BN_new();
    if (party == ALICE) {
        BN_rand_range(sa, EC_GROUP_get0_order(group));
        send_bn(io, sa);
        recv_bn(io, sb);
    } else {
        BN_rand_range(sb, EC_GROUP_get0_order(group));
        recv_bn(io, sa);
        send_bn(io, sb);
    }
    BN_mod_add(s, sa, sb, EC_GROUP_get0_order(group), ctx);
    EC_POINT* h = EC_POINT_new(group);
    EC_POINT_mul(group, h, s, NULL, NULL, ctx);

    vector<block> raw(array_len);
    for (size_t i = 0; i < raw.size(); i++)
        raw[i] = input[i].bit;

    size_t batch_size = 255;
    size_t chunk_len = (array_len + batch_size - 1) / batch_size;
    vector<EC_POINT*> coms;
    vector<BIGNUM*> rnds;

    coms.resize(chunk_len);
    rnds.resize(chunk_len);

    for (size_t i = 0; i < chunk_len; i++) {
        coms[i] = EC_POINT_new(group);
        rnds[i] = BN_new();
    }
    size_t comm = io->counter;
    ComConv<IO> conv(io, cot, q, Delta);
    PedersenComm pc(h, group);

    if (party == BOB) {
        auto start = emp::clock_start();
        bool res = conv.compute_com_send(coms, raw, pc, batch_size);
        if (res) {
            cout << "BOB check passed" << endl;
        } else {
            cout << "BOB check failed" << endl;
        }
        cout << "BOB time: " << emp::time_from(start) << " us" << endl;
        cout << "BOB comm: " << io->counter - comm << " bytes" << endl;
    } else {
        auto start = emp::clock_start();
        bool res = conv.compute_com_recv(coms, rnds, raw, pc, batch_size);
        if (res) {
            cout << "ALICE check passed" << endl;
        } else {
            cout << "ALICE check failed" << endl;
        }
        cout << "ALICE time: " << emp::time_from(start) << " us" << endl;
        cout << "ALICE comms: " << io->counter - comm << " bytes" << endl;
    }

    for (size_t i = 0; i < chunk_len; i++) {
        EC_POINT_free(coms[i]);
        BN_free(rnds[i]);
    }
}

const int threads = 4;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io[threads];
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++) {
        io[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);
        ios[i] = new BoolIO<NetIO>(io[i], party == ALICE);
    }

    setup_protocol<NetIO>(io[0], ios, threads, party);

    switch_to_zk();

    IKNP<NetIO>* cot = ((PrimusParty<NetIO>*)(gc_prot_buf))->ot;
    FerretCOT<NetIO>* fcot;
    if (party == ALICE) {
        fcot = ((ZKProver<NetIO>*)(zk_prot_buf))->ostriple->ferret;
    } else {
        fcot = ((ZKVerifier<NetIO>*)(zk_prot_buf))->ostriple->ferret;
    }

    size_t array_len = 4 * 1024 * 8;
    PRG prg;
    unsigned char* val = new unsigned char[array_len / 8];
    prg.random_data(val, array_len / 8);
    Integer input(array_len, val, ALICE);
    ios[0]->flush();

    com_conv_test<NetIO>(io[0], cot, fcot->Delta, party, input, array_len);
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
    return 0;
}
