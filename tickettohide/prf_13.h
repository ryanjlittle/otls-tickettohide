#ifndef _TLSPRF_13_H_
#define _TLSPRF_13_H_

#include "cipher/prf.h"
#include "hmac_sha256_tth.h"
#include "constants.h"

using namespace emp;

class PRF_13 : public PRF {
public:
    size_t hmac_calls_num = 0;

    // should check consistency of zk_sec_M and pub_M;
    vector<Integer> zk_sec_M;
    vector<uint32_t*> pub_M;
    size_t zk_pos = 0;

    PRF_13() {}

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

    inline void gen_info_string(string* info, unsigned char* transcript_hash, const string label) {
        uint16_t out_len = HASH_LEN;
        uint8_t label_len = label.size();
        uint8_t context_len = HASH_LEN;
        uint8_t counter = 1;

        // rfc8446, section 7.1
        info->clear();
        info->push_back((out_len >> 8) & 0xff);
        info->push_back((out_len & 0xff));
        info->push_back(label_len);
        info->append(label);
        info->push_back(context_len);
        // append hash in reverse byte order because we store the transcript hash little-endian
        for (int i = HASH_LEN-1; i >= 0; i--) {
            info->push_back(transcript_hash[i]);
        }
        info->push_back(counter);
    }

    inline void gen_chts_info_string(unsigned char* info, unsigned char* transcript_hash) {
        string info_str;
        gen_info_string(&info_str, transcript_hash, CHTS_LABEL);
        memcpy(info, info_str.c_str(), info_str.size());
    }

    inline void gen_shts_info_string(unsigned char* info, unsigned char* transcript_hash) {
        string info_str;
        gen_info_string(&info_str, transcript_hash, SHTS_LABEL);
        memcpy(info, info_str.c_str(), info_str.size());
    }

    inline void compute_internal_chts_hash(uint32_t* res, unsigned char* transcript_hash, uint32_t* inner_hash) {
        string info_str;
        gen_info_string(&info_str, transcript_hash, CHTS_LABEL);
        HMAC_SHA256_local local_hmac;
        local_hmac.compute_internal_hash(res, inner_hash, info_str);
    }

    inline void compute_internal_shts_hash(uint32_t* res, unsigned char* transcript_hash, uint32_t* inner_hash) {
        string info_str;
        gen_info_string(&info_str, transcript_hash, SHTS_LABEL);
        HMAC_SHA256_local local_hmac;
        local_hmac.compute_internal_hash(res, inner_hash, info_str);
    }

    inline void compute_internal_cats_hash(uint32_t* res, unsigned char* transcript_hash, uint32_t* inner_hash) {
        string info_str;
        gen_info_string(&info_str, transcript_hash, CATS_LABEL);
        HMAC_SHA256_local local_hmac;
        local_hmac.compute_internal_hash(res, inner_hash, info_str);
    }

    inline void compute_internal_sats_hash(uint32_t* res, unsigned char* transcript_hash, uint32_t* inner_hash) {
        string info_str;
        gen_info_string(&info_str, transcript_hash, SATS_LABEL);
        HMAC_SHA256_local local_hmac;
        local_hmac.compute_internal_hash(res, inner_hash, info_str);
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
        hmac.hmac_sha256_tth(result, info, hash_len);
    }

    inline void hkdf_expand(HMAC_SHA256& hmac,
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
                              const Integer& hs_secret,
                              const Integer& session_hash) {
        HMAC_SHA256_TTH hmac;
        hmac.init(hs_secret);
        derive_secret(hmac, chts, CHTS_LABEL, session_hash, HASH_LEN);
        derive_secret(hmac, shts, SHTS_LABEL, session_hash, HASH_LEN);
    }

    inline void compute_chts_shts_opt(Integer& chts,
                              Integer& shts,
                              Integer& outer_hash,
                              Integer& chts_hash,
                              Integer& shts_hash) {
        HMAC_SHA256_TTH hmac;
        hmac.hmac_sha256_tth_opt(chts, chts_hash, outer_hash);
        hmac.hmac_sha256_tth_opt(shts, shts_hash, outer_hash);
    }

    inline void compute_cats_sats(Integer& cats,
        Integer& sats,
        const Integer& app_secret,
        const Integer& session_hash) {
        HMAC_SHA256_TTH hmac;
        hmac.init(app_secret);
        derive_secret(hmac, cats, CATS_LABEL, session_hash, HASH_LEN);
        derive_secret(hmac, sats, SATS_LABEL, session_hash, HASH_LEN);
    }

    inline void compute_cats_sats_opt(Integer& cats,
                          Integer& sats,
                          Integer& outer_hash,
                          Integer& cats_hash,
                          Integer& sats_hash) {
        HMAC_SHA256_TTH hmac;
        hmac.hmac_sha256_tth_opt(cats, cats_hash, outer_hash);
        hmac.hmac_sha256_tth_opt(sats, sats_hash, outer_hash);
    }

    inline void compute_application_keys(Integer& client_key,
                                         Integer& client_iv,
                                         Integer& server_key,
                                         Integer& server_iv,
                                         Integer& cats,
                                         Integer& sats) {

        // compute keys and IV for client and server
        HMAC_SHA256 hmac_cats, hmac_sats;
        hmac_cats.init(cats);
        hmac_sats.init(sats);
        hkdf_expand(hmac_cats, client_key, KEY_DERIVATION_MSG, KEY_DERIVATION_MSG_LEN, KEY_LEN);
        hkdf_expand(hmac_cats, client_iv, IV_DERIVATION_MSG, IV_DERIVATION_MSG_LEN, IV_LEN);
        hkdf_expand(hmac_sats, server_key, KEY_DERIVATION_MSG, KEY_DERIVATION_MSG_LEN, KEY_LEN);
        hkdf_expand(hmac_sats, server_iv, IV_DERIVATION_MSG, IV_DERIVATION_MSG_LEN, IV_LEN);
    }

    inline void compute_application_keys_OLD(Integer& client_key,
                                         Integer& client_iv,
                                         Integer& server_key,
                                         Integer& server_iv,
                                         Integer& master_secret,
                                         const Integer& session_hash) {
        // compute CATS and SATS
        HMAC_SHA256_TTH hmac_ms, hmac_cats, hmac_sats;
        hmac_ms.init(master_secret);
        Integer cats, sats;
        derive_secret(hmac_ms, cats, CATS_LABEL, session_hash, HASH_LEN);
        derive_secret(hmac_ms, sats, SATS_LABEL, session_hash, HASH_LEN);

        // TODO: remove, testing
        string msec_str = master_secret.reveal<string>();
        std::cout<< "master secret: ";
        print_bin_str_as_hex_reversed(msec_str);
        std::cout << "hash: ";
        print_bin_str_as_hex_reversed(session_hash.reveal<string>());
        string cats_str = cats.reveal<string>();
        std::cout << "CATS: ";
        print_bin_str_as_hex_reversed(cats_str);
        string sats_str = sats.reveal<string>();
        std::cout << "SATS: ";
        print_bin_str_as_hex_reversed(sats_str);

        // compute keys and IV for client and server
        hmac_cats.init(cats);
        hmac_sats.init(sats);
        hkdf_expand(hmac_cats, client_key, KEY_DERIVATION_MSG, KEY_DERIVATION_MSG_LEN, KEY_LEN);
        hkdf_expand(hmac_cats, client_iv, IV_DERIVATION_MSG, IV_DERIVATION_MSG_LEN, IV_LEN);
        hkdf_expand(hmac_sats, server_key, KEY_DERIVATION_MSG, KEY_DERIVATION_MSG_LEN, KEY_LEN);
        hkdf_expand(hmac_sats, server_iv, IV_DERIVATION_MSG, IV_DERIVATION_MSG_LEN, IV_LEN);
    }
};

class PRF_13_Offline {
   // public:
   //  PRF_13_Offline() {};
   //  ~PRF_13_Offline() {};
   //  size_t hmac_calls_num = 0;
   //
   //  inline void init(HMAC_SHA256_Offline& hmac, const Integer secret) {
   //      hmac.init(secret);
   //      hmac_calls_num = 0;
   //  }
   //
   //  inline void opt_phash(HMAC_SHA256_Offline& hmac,
   //                        Integer& res,
   //                        size_t bitlen,
   //                        const Integer secret,
   //                        bool reuse_in_hash_flag = false,
   //                        bool reuse_out_hash_flag = false) {
   //      size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
   //
   //      Integer* tmp = new Integer[hmac.DIGLEN];
   //      uint32_t* tmpd = new uint32_t[hmac.DIGLEN];
   //
   //      for (size_t i = 1; i < blks + 1; i++) {
   //          hmac.opt_hmac_sha256(tmp, reuse_in_hash_flag, reuse_out_hash_flag);
   //          hmac_calls_num++;
   //
   //          // in the gc setting, store the revealed M values.
   //          Integer tmpInt;
   //          reverse_concat(tmpInt, tmp, hmac.DIGLEN);
   //          tmpInt.reveal<uint32_t>((uint32_t*)tmpd, PUBLIC);
   //
   //          hmac.opt_hmac_sha256(tmp, reuse_in_hash_flag, reuse_out_hash_flag);
   //          hmac_calls_num++;
   //          concat(res, tmp, hmac.DIGLEN);
   //      }
   //      res.bits.erase(res.bits.begin(),
   //                     res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);
   //
   //      delete[] tmp;
   //      delete[] tmpd;
   //  }
   //
   //  inline void opt_rounds_phash(HMAC_SHA256_Offline& hmac,
   //                               Integer& res,
   //                               size_t bitlen,
   //                               const Integer secret,
   //                               size_t seedlen,
   //                               bool reuse_in_hash_flag = false,
   //                               bool reuse_out_hash_flag = false) {
   //      size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
   //      Integer* A = new Integer[blks + 1];
   //      A[0] = Integer(8 * seedlen, 0, PROVER);
   //
   //      Integer* tmp = new Integer[hmac.DIGLEN];
   //
   //      for (size_t i = 1; i < blks + 1; i++) {
   //          hmac.opt_rounds_hmac_sha256(tmp, A[i - 1], reuse_in_hash_flag,
   //                                      reuse_out_hash_flag);
   //          hmac_calls_num++;
   //
   //          concat(A[i], &tmp[0], hmac.VALLEN);
   //
   //          Integer As;
   //          concat(As, &A[i], 1);
   //          concat(As, &A[0], 1);
   //
   //          hmac.opt_rounds_hmac_sha256(tmp, As, reuse_in_hash_flag, reuse_out_hash_flag);
   //          hmac_calls_num++;
   //          concat(res, tmp, hmac.DIGLEN);
   //      }
   //      res.bits.erase(res.bits.begin(),
   //                     res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);
   //
   //      delete[] A;
   //      delete[] tmp;
   //  }
   //
   //  inline void opt_compute(HMAC_SHA256_Offline& hmac,
   //                          Integer& res,
   //                          size_t bitlen,
   //                          const Integer secret,
   //                          bool reuse_in_hash_flag = false,
   //                          bool reuse_out_hash_flag = false) {
   //      opt_phash(hmac, res, bitlen, secret, reuse_in_hash_flag, reuse_out_hash_flag);
   //  }
   //  inline void opt_rounds_compute(HMAC_SHA256_Offline& hmac,
   //                                 Integer& res,
   //                                 size_t bitlen,
   //                                 const Integer secret,
   //                                 size_t seedlen,
   //                                 bool reuse_in_hash_flag = false,
   //                                 bool reuse_out_hash_flag = false) {
   //      opt_rounds_phash(hmac, res, bitlen, secret, seedlen, reuse_in_hash_flag,
   //                       reuse_out_hash_flag);
   //  }
};

#endif
