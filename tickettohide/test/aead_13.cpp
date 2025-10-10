#include "tickettohide/aead_13.h"
#include "../tth_utils.h"

void test_aead(NetIO* io, NetIO* io_opt, IKNP<NetIO>* ot, int party) {
  unsigned char keyc[] = {0x2b, 0x82, 0x97, 0xb7, 0x12, 0x6b, 0x6b, 0x95,
                          0xa1, 0x6d, 0xe0, 0xb3, 0x73, 0x0a, 0x1a, 0x7e};
  reverse(keyc, keyc + 16);
  Integer key(128, keyc, PROVER);

  // unsigned char msg[] = {0x14, 0x00, 0x00, 0x20, 0x54, 0x0e, 0x76, 0x69,
  //                        0xf4, 0x07, 0x3b, 0xe8, 0xe0, 0x97, 0x52, 0x41,
  //                        0xd3, 0xe2, 0x24, 0x74, 0x67, 0x3a, 0x98, 0xa7,
  //                        0x8d, 0x56, 0x91, 0xfe, 0xa4, 0x36, 0x17, 0x18,
  //                        0x68, 0x93, 0xbc, 0xfa, 0x16};
  // size_t msg_len = sizeof(msg);
  size_t msg_len = 1024;
  unsigned char msg[1024];
  memset(msg, 0xff, msg_len);

  unsigned char aad[] = {0x17, 0x03, 0x03, 0x00, 0x35};
  size_t aad_len = sizeof(aad);

  unsigned char iv[] = {0xe8, 0xb0, 0x22, 0xae, 0xd0, 0xe9, 0x35, 0x76, 0x80,
                        0x9c, 0xfc, 0x43};
  size_t iv_len = sizeof(iv);
  reverse(iv, iv + iv_len);

  unsigned char expected_ctext[] = {0xa5, 0x7c, 0x89, 0xf9, 0xa5, 0x6c, 0xb7, 0xdc,
                                    0xb6, 0xe8, 0x51, 0xef, 0x97, 0x38, 0xbe, 0x83,
                                    0xd7, 0xfd, 0x32, 0xbd, 0x21, 0x03, 0x00, 0x68,
                                    0xa3, 0xdd, 0xc3, 0xa8, 0x64, 0xd5, 0x78, 0x76,
                                    0x07, 0x7d, 0x79, 0x0e, 0x61};
  unsigned char expected_tag[] = {0x5e, 0x3e, 0x72, 0xc4, 0x1e, 0xa0, 0x9d, 0x3b,
                                  0x88, 0xac, 0x00, 0xe8, 0x84, 0x2c, 0xa5, 0x38};

  unsigned char fixed_iv_oct[4];
  memcpy(fixed_iv_oct, iv, 4);
  reverse(fixed_iv_oct, fixed_iv_oct + 4);
  Integer fixed_iv(4 * 8, fixed_iv_oct, PUBLIC);
  Integer full_iv(12*8, iv, PUBLIC);

  unsigned char* ctxt = new unsigned char[msg_len];
  unsigned char tag[16];

  if (party == VERIFIER) {
    memset(msg, 0, msg_len);
  }

  auto start = emp::clock_start();
  //AEAD<NetIO> aead(io, io_opt, ot, key, fixed_iv);
  //aead.encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len, iv + 4, iv_len - 4, party, true);

  // AEAD_13<NetIO> aead(io, io_opt, ot, key, full_iv);
  // aead.encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len, iv, iv_len, party);
  string iv_str(reinterpret_cast<char*>(iv), iv_len);
  AEAD_13<NetIO> aead(io, io_opt, ot, key, full_iv, party);
  aead.encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len);

  cout << "time: " << emp::time_from(start) << " us" << endl;

  cout << "ctxt: ";
  for (size_t i = 0; i < msg_len; i++) {
    cout << hex << (int) ctxt[i];
  }
  cout << endl;
  cout << "tag: ";
  for (int i = 0; i < 16; i++) {
    cout << hex << (int) tag[i];
  }
  cout << endl;

  aead.encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len);

  cout << "ctxt: ";
  for (size_t i = 0; i < msg_len; i++) {
    cout << hex << (int) ctxt[i];
  }
  cout << endl;
  cout << "tag: ";
  for (int i = 0; i < 16; i++) {
    cout << hex << (int) tag[i];
  }
  cout << endl;

  delete[] ctxt;
}


int threads = 4;

int main(int argc, char** argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  NetIO* io_opt = new NetIO(party == PROVER ? nullptr : "127.0.0.1", port + threads);

  NetIO* io[threads];
  BoolIO<NetIO>* ios[threads];
  for (int i = 0; i < threads; i++) {
    io[i] = new NetIO(party == PROVER ? nullptr : "127.0.0.1", port + i);
    ios[i] = new BoolIO<NetIO>(io[i], party == PROVER);
  }

  auto start = emp::clock_start();
  setup_protocol<NetIO>(io[0], ios, threads, party);
  cout << "setup time: " << emp::time_from(start) << " us" << endl;
  auto prot = (PrimusParty<NetIO>*)(ProtocolExecution::prot_exec);
  IKNP<NetIO>* cot = prot->ot;

  test_aead(io[0], io_opt, cot, party);

  cout << "gc AND gates: " << dec << gc_circ_buf->num_and() << endl;
  cout << "zk AND gates: " << dec << zk_circ_buf->num_and() << endl;
  finalize_protocol();
}