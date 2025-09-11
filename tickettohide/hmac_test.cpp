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


void test_loading_val() {
  //const unsigned char val[] = {0x86, 0x16, 0x2e, 0x86, 0x7a, 0x0f, 0x6a, 0x41, 0xb9, 0x62, 0x0e, 0x00, 0x49, 0xfd, 0x86, 0x17, 0x31, 0xac, 0xc2, 0x3b, 0x77, 0x38, 0x2a, 0x9c, 0xf2, 0x82, 0x8a, 0xea, 0x19, 0x49, 0xe7, 0x2d};
  const unsigned char val[] = {0xf5, 0xa1};
  int byte_len = 2;
  BIGNUM* val_bn = BN_bin2bn(val, sizeof(val), nullptr);
  std::cout << "value stored in bignum: " << BN_bn2hex(val_bn) << std::endl;
  unsigned char* buf = new unsigned char[byte_len];
  BN_bn2bin(val_bn, buf);
  //reverse(buf, buf + byte_len);

  std::cout << "value stored in buffer: ";
  for (int i = 0; i < byte_len; i++) {
    // print as 2-digit hex
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
  }
  std::cout << std::endl;

  Integer val_Int = Integer(byte_len*8, buf, ALICE);
  string res = val_Int.reveal<string>();
  std::cout << "value of revealed GC wires: ";
  print_hex_string(res);
}

void test_hmac() {
  HMAC_SHA256_TTH hmac;
  int keylen = 256;

  const unsigned char key_raw[] = {0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const unsigned char msg_raw[] = {0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  Integer key(keylen, key_raw, BOB);
  Integer msg(keylen, msg_raw, ALICE);
  // BIGNUM* key_bn = BN_new();
  // key_bn = BN_bin2bn(key_raw, 32, nullptr);
  // BIGNUM* msg_bn = BN_bin2bn(msg_raw, 32, nullptr);
  // std::cout << "key bignum: " << BN_bn2hex(key_bn) << std::endl;
  // std::cout << "msg bignum: " << BN_bn2hex(msg_bn) << std::endl;
  // Integer key = Integer(keylen, key_bn, BOB);
  // Integer msg = Integer(keylen, msg_bn, ALICE);
  Integer result;

  auto x = key.reveal<string>();
  std::cout << "key: ";
  print_hex_string(x);

  hmac.init(key);
  hmac.tth_opt_hmac_sha256(result, msg, hash_len);

  auto out = result.reveal<string>(PUBLIC);
  std::cout << "hmac result: ";
  print_hex_string(out);
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

  auto start = emp::clock_start();
  setup_protocol<NetIO>(io[0], ios, threads, party);
  cout << "setup time: " << emp::time_from(start) << " us" << endl;
  auto prot = (PrimusParty<NetIO>*)(ProtocolExecution::prot_exec);
  IKNP<NetIO>* cot = prot->ot;

  //test_loading_val();
  test_hmac();
}