#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#include <cstddef>
#include <string>

size_t hash_len = 32; // SHA256
size_t key_len = 16; // AES-128
size_t iv_len = 12; // AES-128 GCM

size_t index_len = 1; // index is 1 byte

 std::string chts_label = "tls13 c hs traffic";
const std::string shts_label = "tls13 s hs traffic";
const std::string cats_label = "tls13 c ap traffic";
const std::string sats_label = "tls13 s ap traffic";

unsigned char key_derivation_msg[] = {0x00, 0x10, 0x09, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x01};
size_t key_derivation_msg_len = sizeof(key_derivation_msg);
const std::string key_label = "tls13 key";

unsigned char iv_derivation_msg[] = {0x00, 0x0c, 0x08, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x69, 0x76, 0x00, 0x01};
size_t iv_derivation_msg_len = sizeof(iv_derivation_msg);
const std::string iv_label = "tls13 iv";

#endif