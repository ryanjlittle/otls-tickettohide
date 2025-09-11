#ifndef OTLS_HMAC_SHA256_TTH_H
#define OTLS_HMAC_SHA256_TTH_H

#include "cipher/hmac_sha256.h"

class HMAC_SHA256_TTH : public HMAC_SHA256 {
    public:

    void tth_opt_hmac_sha256(Integer& res,
                             Integer msg,
                             size_t len,
                             bool reuse_in_hash_flag = false,
                             bool reuse_out_hash_flag = false,
                             bool zk_flag = false) {
      // TODO: implement our optimization. For now, just compute all in 2PC
      Integer* tmp = new Integer[DIGLEN];

      hmac_sha256(tmp, msg);
      concat(res, tmp, VALLEN);
    }
};

#endif
