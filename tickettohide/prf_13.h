#ifndef _TLSPRF_13_H_
#define _TLSPRF_13_H_

#include "cipher/prf.h"
#include "hmac_sha256_tth.h"
#include "constants.h"

using namespace emp;

class PRF_13 {
   public:
    size_t hmac_calls_num = 0;

    // should check consistency of zk_sec_M and pub_M;
    vector<Integer> zk_sec_M;
    vector<uint32_t*> pub_M;
    size_t zk_pos = 0;

    PRF_13() {};

    ~PRF_13() {
        for (size_t i = 0; i < pub_M.size(); i++) {
            if (pub_M[i] != nullptr) {
                delete[] pub_M[i];
            }
        }
        pub_M.clear();
    };

    inline void init(HMAC_SHA256_TTH& hmac, const Integer secret) {
        hmac.init(secret);
        hmac_calls_num = 0;
    }



    inline void derive_secret(HMAC_SHA256_TTH& hmac,
                              Integer& result,
                              const string label,
                              const Integer session_hash,
                              size_t hash_len) {
        // rfc8446, section 7.1
        size_t label_len = label.length();

        Integer out_len_16_gc(16, hash_len, PUBLIC);
        Integer label_len_gc(8, label_len, PUBLIC);
        Integer label_gc = str_to_int(label, PUBLIC);
        Integer context_len_8_gc(8, hash_len, PUBLIC);
        Integer counter(8, 1, PUBLIC);

        Integer arr[6] = {out_len_16_gc, label_len_gc, label_gc, context_len_8_gc, session_hash, counter};
        Integer info;
        concat(info, arr, 6);
        hmac.tth_opt_hmac_sha256(result, info, hash_len);
    }

    inline void hkdf_expand(HMAC_SHA256_TTH& hmac,
                                  Integer& result,
                                  unsigned char* info,
                                  size_t info_len,
                                  size_t out_length) {
        // rfc 5869
        assert(out_length*8 <= hmac.DIGLEN*hmac.WORDLEN); // ensures we only need to compute 1 block. this is not required by the rfc spec, but should always be the case for our purposes

        // TODO: pass the right flags to use their optimization
        Integer* tmp = new Integer[hmac.DIGLEN];
        hmac.opt_hmac_sha256(tmp, info, info_len, false, false);
        concat(result, tmp, hmac.DIGLEN);
        result.bits.erase(result.bits.begin(), result.bits.end() - out_length*8);
        delete[] tmp;
    }

    inline void compute_chts_shts(Integer& chts,
                              Integer& shts,
                              const Integer &hs_secret,
                              const Integer &session_hash) {
        HMAC_SHA256_TTH hmac;
        hmac.init(hs_secret);
        derive_secret(hmac, chts, chts_label, session_hash, hash_len);
        derive_secret(hmac, shts, shts_label, session_hash, hash_len);
    }

    inline void compute_application_keys(Integer& client_key,
                                         Integer& client_iv,
                                         Integer& server_key,
                                         Integer& server_iv,
                                         const Integer& master_secret,
                                         const Integer& session_hash) {
        // compute CATS and SATS
        HMAC_SHA256_TTH hmac_ms, hmac_cats, hmac_sats;
        hmac_ms.init(master_secret);
        Integer cats, sats;
        derive_secret(hmac_ms, cats, cats_label, session_hash, hash_len);
        derive_secret(hmac_ms, sats, sats_label, session_hash, hash_len);

        // TODO: remove, testing
        string msec_str = master_secret.reveal<string>();
        std::cout<< "master secret: ";
        print_hex_string_reversed(msec_str);
        std::cout << "hash: ";
        print_hex_string_reversed(session_hash.reveal<string>());
        string cats_str = cats.reveal<string>();
        std::cout << "CATS: ";
        print_hex_string_reversed(cats_str);
        string sats_str = sats.reveal<string>();
        std::cout << "SATS: ";
        print_hex_string_reversed(sats_str);

        // compute keys and IV for client and server
        hmac_cats.init(cats);
        hmac_sats.init(sats);
        hkdf_expand(hmac_cats, client_key, key_derivation_msg, key_derivation_msg_len, key_len);
        hkdf_expand(hmac_cats, client_iv, iv_derivation_msg, iv_derivation_msg_len, iv_len);
        hkdf_expand(hmac_sats, server_key, key_derivation_msg, key_derivation_msg_len, key_len);
        hkdf_expand(hmac_sats, server_iv, iv_derivation_msg, iv_derivation_msg_len, iv_len);
    }

    inline void phash(HMAC_SHA256& hmac,
                      Integer& res,
                      size_t bitlen,
                      const Integer secret,
                      const Integer seed) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        Integer* tmp = new Integer[hmac.DIGLEN];

        A[0] = seed;
        for (size_t i = 1; i < blks + 1; i++) {
            hmac.hmac_sha256(tmp, A[i - 1]);
            hmac_calls_num++;
            concat(A[i], tmp, hmac.DIGLEN);

            Integer As;
            concat(As, &A[i], 1);
            concat(As, &seed, 1);

            hmac.hmac_sha256(tmp, As);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }

        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        delete[] A;
        delete[] tmp;
    }

    inline void opt_phash(HMAC_SHA256& hmac,
                          Integer& res,
                          size_t bitlen,
                          const Integer secret,
                          const unsigned char* seed,
                          size_t seedlen,
                          bool reuse_in_hash_flag = false,
                          bool reuse_out_hash_flag = false,
                          bool zk_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        vector<unsigned char*> A;
        vector<size_t> hashlen;
        A.resize(blks + 1);
        A[0] = new unsigned char[seedlen];
        memcpy(A[0], seed, seedlen);
        hashlen.push_back(seedlen);

        Integer* tmp = new Integer[hmac.DIGLEN];
        uint32_t* tmpd = new uint32_t[hmac.DIGLEN];

        unsigned char* As = new unsigned char[32 + seedlen];
        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_hmac_sha256(tmp, A[i - 1], hashlen[i - 1], reuse_in_hash_flag,
                                 reuse_out_hash_flag, zk_flag);
            hmac_calls_num++;
            A[i] = new unsigned char[32];

            Integer tmpInt;
            reverse_concat(tmpInt, tmp, hmac.DIGLEN);

            if (!zk_flag) {
                // in the gc setting, store the revealed M values.
                tmpInt.reveal<uint32_t>((uint32_t*)tmpd, PUBLIC);

                pub_M.push_back(nullptr);
                pub_M.back() = new uint32_t[hmac.DIGLEN];
                memcpy(pub_M.back(), tmpd, hmac.DIGLEN * sizeof(uint32_t));
            } else {
                // in the zk setting, store the zk shares of M. Reuse the stored public M value.
                zk_sec_M.push_back(tmpInt);
                memcpy(tmpd, pub_M[zk_pos++], hmac.DIGLEN * sizeof(uint32_t));
            }

            for (int j = 0, k = 0; j < hmac.DIGLEN; j++, k += 4) {
                A[i][k] = (tmpd[j] >> 24);
                A[i][k + 1] = (tmpd[j] >> 16);
                A[i][k + 2] = (tmpd[j] >> 8);
                A[i][k + 3] = tmpd[j];
            }
            hashlen.push_back(32);

            memcpy(As, A[i], 32);
            memcpy(As + 32, seed, seedlen);

            hmac.opt_hmac_sha256(tmp, As, 32 + seedlen, reuse_in_hash_flag,
                                 reuse_out_hash_flag, zk_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        for (size_t i = 0; i < blks + 1; i++) {
            delete[] A[i];
        }

        delete[] As;
        delete[] tmp;
        delete[] tmpd;
    }

    inline void opt_rounds_phash(HMAC_SHA256& hmac,
                                 Integer& res,
                                 size_t bitlen,
                                 const Integer secret,
                                 const unsigned char* seed,
                                 size_t seedlen,
                                 bool reuse_in_hash_flag = false,
                                 bool reuse_out_hash_flag = false,
                                 bool zk_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        Integer* tmp = new Integer[hmac.DIGLEN];
        unsigned char* rseed = new unsigned char[seedlen];
        memcpy(rseed, seed, seedlen);
        reverse(rseed, rseed + seedlen);
        A[0] = Integer(8 * seedlen, rseed, ALICE);

        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_rounds_hmac_sha256(tmp, A[i - 1], reuse_in_hash_flag,
                                        reuse_out_hash_flag);
            hmac_calls_num++;

            concat(A[i], &tmp[0], hmac.DIGLEN);

            Integer As;
            concat(As, &A[i], 1);
            concat(As, &A[0], 1);

            hmac.opt_rounds_hmac_sha256(tmp, As, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        delete[] A;
        delete[] tmp;
        delete[] rseed;
    }

    inline void compute(HMAC_SHA256& hmac,
                        Integer& res,
                        size_t bitlen,
                        const Integer secret,
                        const Integer label,
                        const Integer seed) {
        Integer label_seed;
        concat(label_seed, &label, 1);
        concat(label_seed, &seed, 1);
        phash(hmac, res, bitlen, secret, label_seed);
    }

    inline void opt_compute(HMAC_SHA256& hmac,
                            Integer& res,
                            size_t bitlen,
                            const Integer secret,
                            const unsigned char* label,
                            size_t labellen,
                            const unsigned char* seed, // (hash)
                            size_t seedlen,
                            bool reuse_in_hash_flag = false,
                            bool reuse_out_hash_flag = false,
                            bool zk_flag = false) {
        unsigned char* label_seed = new unsigned char[labellen + seedlen];
        memcpy(label_seed, label, labellen);
        memcpy(label_seed + labellen, seed, seedlen);
        opt_phash(hmac, res, bitlen, secret, label_seed, labellen + seedlen,
                  reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);

        delete[] label_seed;
    }

    inline void opt_rounds_compute(HMAC_SHA256& hmac,
                                   Integer& res,
                                   size_t bitlen,
                                   const Integer secret,
                                   const unsigned char* label,
                                   size_t labellen,
                                   const unsigned char* seed,
                                   size_t seedlen,
                                   bool reuse_in_hash_flag = false,
                                   bool reuse_out_hash_flag = false,
                                   bool zk_flag = false) {
        unsigned char* label_seed = new unsigned char[labellen + seedlen];
        memcpy(label_seed, label, labellen);
        memcpy(label_seed + labellen, seed, seedlen);
        opt_rounds_phash(hmac, res, bitlen, secret, label_seed, labellen + seedlen,
                         reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);
    }

    inline size_t hmac_calls() { return hmac_calls_num; }

    template <typename IO>
    inline void prf_check(int party) {
        if (pub_M.size() != zk_sec_M.size())
            error("length of M is not consistent!\n");
        for (size_t i = 0; i < pub_M.size(); i++)
            check_zero<IO>(zk_sec_M[i], pub_M[i], 8, party);
    }
};

class PRF_13_Offline {
   public:
    PRF_13_Offline() {};
    ~PRF_13_Offline() {};
    size_t hmac_calls_num = 0;

    inline void init(HMAC_SHA256_Offline& hmac, const Integer secret) {
        hmac.init(secret);
        hmac_calls_num = 0;
    }

    inline void opt_phash(HMAC_SHA256_Offline& hmac,
                          Integer& res,
                          size_t bitlen,
                          const Integer secret,
                          bool reuse_in_hash_flag = false,
                          bool reuse_out_hash_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;

        Integer* tmp = new Integer[hmac.DIGLEN];
        uint32_t* tmpd = new uint32_t[hmac.DIGLEN];

        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_hmac_sha256(tmp, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;

            // in the gc setting, store the revealed M values.
            Integer tmpInt;
            reverse_concat(tmpInt, tmp, hmac.DIGLEN);
            tmpInt.reveal<uint32_t>((uint32_t*)tmpd, PUBLIC);

            hmac.opt_hmac_sha256(tmp, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        delete[] tmp;
        delete[] tmpd;
    }

    inline void opt_rounds_phash(HMAC_SHA256_Offline& hmac,
                                 Integer& res,
                                 size_t bitlen,
                                 const Integer secret,
                                 size_t seedlen,
                                 bool reuse_in_hash_flag = false,
                                 bool reuse_out_hash_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        A[0] = Integer(8 * seedlen, 0, ALICE);

        Integer* tmp = new Integer[hmac.DIGLEN];

        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_rounds_hmac_sha256(tmp, A[i - 1], reuse_in_hash_flag,
                                        reuse_out_hash_flag);
            hmac_calls_num++;

            concat(A[i], &tmp[0], hmac.VALLEN);

            Integer As;
            concat(As, &A[i], 1);
            concat(As, &A[0], 1);

            hmac.opt_rounds_hmac_sha256(tmp, As, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        delete[] A;
        delete[] tmp;
    }

    inline void opt_compute(HMAC_SHA256_Offline& hmac,
                            Integer& res,
                            size_t bitlen,
                            const Integer secret,
                            bool reuse_in_hash_flag = false,
                            bool reuse_out_hash_flag = false) {
        opt_phash(hmac, res, bitlen, secret, reuse_in_hash_flag, reuse_out_hash_flag);
    }
    inline void opt_rounds_compute(HMAC_SHA256_Offline& hmac,
                                   Integer& res,
                                   size_t bitlen,
                                   const Integer secret,
                                   size_t seedlen,
                                   bool reuse_in_hash_flag = false,
                                   bool reuse_out_hash_flag = false) {
        opt_rounds_phash(hmac, res, bitlen, secret, seedlen, reuse_in_hash_flag,
                         reuse_out_hash_flag);
    }
};

#endif
