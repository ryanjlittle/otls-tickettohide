#ifndef OTLS_HMAC_SHA256_TTH_H
#define OTLS_HMAC_SHA256_TTH_H

#include "cipher/hmac_sha256.h"

class HMAC_SHA256_TTH : public HMAC_SHA256 {
    public:
    Integer ZEROS = Integer(CHUNKLEN, 0, PUBLIC);

    void hmac_sha256_tth(Integer& res,
                             Integer msg,
                             size_t len,
                             bool reuse_in_hash_flag = false,
                             bool reuse_out_hash_flag = false,
                             bool zk_flag = false) {
      Integer* tmp = new Integer[DIGLEN];
      hmac_sha256(tmp, msg);
      concat(res, tmp, VALLEN);
      delete[] tmp;
    }

    void hmac_sha256_tth_opt(Integer& res, Integer msg, Integer outer_key_hash) {
      SHA256 sha;

      // prepend the input with zeros to the right length, since the prover_hash
      // is actually the second block in the Merkle-Damgard chain
      Integer extended_msg = msg;
      reverse_concat(extended_msg, &ZEROS, 1);

      // pad the input (prover's hash) according to sha256 padding specs.
      Integer padded_msg;
      sha.padding(padded_msg, extended_msg);
      // remove the zeros we appended before
      Integer processed_msg;
      extract_integer(processed_msg, padded_msg, CHUNKLEN, CHUNKLEN);
      Integer* chunked_msg = new Integer[CHUNKLEN/WORDLEN];

      // slice inputs into 32-bit chunks
      for (int i = 0; i < CHUNKLEN/WORDLEN; i++) {
        extract_integer(chunked_msg[i], processed_msg, i * WORDLEN, WORDLEN);
      }
      Integer* dig = new Integer[DIGLEN];
      for (int i = 0; i < DIGLEN; i++) {
        extract_integer(dig[i], outer_key_hash, i * WORDLEN, WORDLEN);
      }

      sha.chunk_compress(dig, chunked_msg);
      concat(res, dig, DIGLEN);
      delete[] dig;
      delete[] chunked_msg;
    }
};

class HMAC_SHA256_local : public HMAC_SHA256 {
    public:
    unsigned char* o_key_pad_local;
    unsigned char* i_key_pad_local;
    bool initialized = false;

    const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    inline void init(const unsigned char* key, size_t key_len) {
        refresh();
        SHA256_call = 0;
        initialized = true;

        unsigned char* padded_key = new unsigned char[KLEN];
        assert(key_len <= KLEN); // we can implement key hashing later
        memcpy(padded_key, key, key_len);
        memset(padded_key + key_len, 0, KLEN - key_len);

        o_key_pad_local = new unsigned char[KLEN];
        i_key_pad_local = new unsigned char[KLEN];
        for (int i = 0; i < KLEN; i++) {
            o_key_pad_local[i] = padded_key[i] ^ 0x5c;
            i_key_pad_local[i] = padded_key[i] ^ 0x36;
        }

        delete[] padded_key;
    }

    ~HMAC_SHA256_local() {
        if (initialized) {
            delete[] o_key_pad_local;
            delete[] i_key_pad_local;
        }
    }

    inline void compute_inner_key_hash(uint32_t* hash_out) {
        uint32_t digest[8];
        memcpy(digest, iv, 8);
        plain_chunk_compress(digest, i_key_pad_local);
        memcpy(hash_out, digest, 8);
    }

    inline void compute_outer_key_hash(uint32_t* hash_out) {
        uint32_t digest[8];
        memcpy(digest, iv, 8);
        plain_chunk_compress(digest, o_key_pad_local);
        memcpy(hash_out, digest, 8);
        reverse(hash_out, hash_out + 8);
    }

    inline void compute_internal_hash(uint32_t* hash_out, uint32_t* hash_in, string info) {
        // pad info according to SHA256 spec
        uint64_t unpadded_len = info.size()*8 + CHUNKLEN; // add CHUNKLEN because info is really the second Merkle-Damgard block
        info.push_back(0x80);
        while (info.size() % 64 != 56) {
            info.push_back(0x00);
        }
        for (int i = 0; i < 8; i++) {
            info.push_back(static_cast<unsigned char>(unpadded_len >> (56 - 8 * i)) & 0xff);
        }

        unsigned char* info_cstr = new unsigned char[CHUNKLEN/8];
        memcpy(info_cstr, info.c_str(), CHUNKLEN/8);
        uint32_t digest[WORDLEN];
        memcpy(digest, hash_in, WORDLEN);

        plain_chunk_compress(digest, info_cstr);
        memcpy(hash_out, digest, WORDLEN);
        reverse(hash_out, hash_out + DIGLEN);
        delete[] info_cstr;
    }
};

#endif
