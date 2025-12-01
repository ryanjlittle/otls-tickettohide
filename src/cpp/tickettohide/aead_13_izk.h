#ifndef _AEAD_13_IZK_
#define _AEAD_13_IZK_

#include "aead_13.h"
#include "protocol/aead.h"
#include "protocol/aead_izk.h"

using namespace emp;

template <typename IO>
class AEAD_13_Proof : public AEAD_Proof<IO> {
   public:

    uint8_t tls_counter = 0; // counts ciphertexts
    uint32_t aes_counter = 1; // counts blocks within a ciphertext

    // `key` and `iv` are client(server) write key and iv respectively derived from master secret.
    // Note the length of `key` is 16-bytes and the length of `iv` is 4-bytes.
    AEAD_13_Proof(AEAD_13<IO>* aead, Integer& key, Integer& iv, int party)
    : AEAD_Proof<IO>(aead, key, iv, party){
        this->set_nonce(iv);
    }

    ~AEAD_13_Proof() {}

    inline Integer computeH() {
        Integer in(128, 0, PUBLIC);
        return computeAES_KS(this->expanded_key, in);
    }

    inline Integer inc(Integer& counter, size_t s) {
        if (counter.size() < s) {
            error("invalid length s!");
        }
        Integer msb = counter, lsb = counter;
        msb.bits.erase(msb.bits.begin(), msb.bits.begin() + s);
        lsb.bits.erase(lsb.bits.begin() + s, lsb.bits.end());
        lsb = lsb + Integer(s, 1, PUBLIC);

        concat(msb, &lsb, 1);
        return msb;
    }

    inline void set_nonce(Integer& iv) {
        assert(iv.bits.size() == 8*12);
        aes_counter = 1;
        Integer counter_gc = Integer(32, this->aes_counter, PUBLIC);
        this->nonce = iv;
        concat(this->nonce, &counter_gc, 1);
    }

    inline void inc_iv() {
        uint8_t counter_diff = tls_counter ^ (tls_counter + 1);
        tls_counter++;
        Integer counter_diff_gc = Integer(8, counter_diff, PUBLIC);
        Integer new_nonce;
        extract_integer(new_nonce, this->nonce, 0, 8*12);

        for (int i=0; i<8; i++) {
            new_nonce.bits[i] ^= counter_diff_gc.bits[i];
        }
        set_nonce(new_nonce);
    }

    void prove_aead(Integer& tag_z0,
                    const unsigned char* ctxt,
                    size_t ctxt_len,
                    const unsigned char* iv,
                    size_t iv_len) {
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;
        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;

        Integer nonce_gc(iv_len * 8, iv, PUBLIC);
        set_nonce(nonce_gc);

        Integer Z;
        this->gctr(Z, 1 + ctr_len);

        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());
        tag_z0 = Z0;

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        assert(this->aead->gc_z0.size() != 0 && this->aead->zk_z0.size() != 0);
        itmac_hom_add_check<IO>(Z0, this->aead->zk_z0.front(), this->party, this->aead->gc_z0.front());

        // remove the front elements in deque
        this->aead->gc_z0.pop_front();
        this->aead->zk_z0.pop_front();

        assert(this->aead->gc_z.size() != 0 && this->aead->zk_z.size() != 0);
        itmac_hom_add_check<IO>(Z, this->aead->zk_z.front(), this->party, this->aead->gc_z.front(), this->aead->z_len.front());

        // remove the front elements in deque
        this->aead->z_len.pop_front();
        this->aead->zk_z.pop_front();
        delete[] this->aead->gc_z.front();
        this->aead->gc_z.pop_front();

        inc_iv();
    }
};

#endif
