#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#include <cstddef>
#include <string>

static constexpr int PROVER = 1;
const static int VERIFIER = 2;

size_t HASH_LEN = 32; // SHA256
size_t KEY_LEN = 16;
size_t IV_LEN = 12; // AES-128 GCM
size_t TAG_LEN = 16; // AES-128 GCM
size_t SHA256_INPUT_LEN = 64;

size_t INDEX_LEN = 1; // index is 1 byte

std::string CHTS_LABEL = "tls13 c hs traffic";
const std::string SHTS_LABEL = "tls13 s hs traffic";
const std::string CATS_LABEL = "tls13 c ap traffic";
const std::string SATS_LABEL = "tls13 s ap traffic";

unsigned char KEY_DERIVATION_MSG[] = {0x00, 0x10, 0x09, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x01};
size_t KEY_DERIVATION_MSG_LEN = sizeof(KEY_DERIVATION_MSG);
const std::string KEY_LABEL = "tls13 key";

unsigned char IV_DERIVATION_MSG[] = {0x00, 0x0c, 0x08, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x69, 0x76, 0x00, 0x01};
size_t IV_DERIVATION_MSG_LEN = sizeof(IV_DERIVATION_MSG);
const std::string IV_LABEL = "tls13 iv";

#endif