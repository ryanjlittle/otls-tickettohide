#include "../handshake_13.h"
#include "backend/backend.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include "protocol/aead.h"
#include "protocol/com_conv.h"
#include "protocol/post_record.h"
#include "protocol/record.h"
#include <iostream>
#if defined(__linux__)
#include <sys/time.h>
#include <sys/resource.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/resource.h>
#include <mach/mach.h>
#endif
#include "../aead_13.h"
#include "test/io_utils.h"

using namespace std;
using namespace emp;


void test_loading_val() {
  const unsigned char val[] = {0xf5, 0xa1};
  int byte_len = 2;
  BIGNUM* val_bn = BN_bin2bn(val, sizeof(val), nullptr);
  std::cout << "value stored in bignum: " << BN_bn2hex(val_bn) << std::endl;
  unsigned char* buf = new unsigned char[byte_len];
  BN_bn2bin(val_bn, buf);

  std::cout << "value stored in buffer: ";
  for (int i = 0; i < byte_len; i++) {
    // print as 2-digit hex
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
  }
  std::cout << std::endl;

  Integer val_Int = Integer(byte_len*8, buf, PROVER);
  string res = val_Int.reveal<string>();
  std::cout << "value of revealed GC wires: ";
  print_as_hex(res);
}

void test_hmac() {
  HMAC_SHA256_TTH hmac;
  int keylen = 256;

  const unsigned char key_raw[] = {0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const unsigned char msg_raw[] = {0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  Integer key(keylen, key_raw, VERIFIER);
  Integer msg(keylen, msg_raw, PROVER);
  Integer result;

  auto x = key.reveal<string>();
  std::cout << "key: ";
  print_as_hex(x);

  hmac.init(key);
  hmac.hmac_sha256_tth(result, msg, HASH_LEN);

  auto out = result.reveal<string>(PUBLIC);
  std::cout << "hmac result: ";
  print_as_hex(out);
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

  setup_protocol<NetIO>(io[0], ios, threads, party);


  //test_loading_val();
  test_hmac();
}