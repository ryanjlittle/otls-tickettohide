#ifndef _AEAD_13_
#define _AEAD_13_

#include "protocol/aead.h"
#include "constants.h"

using namespace emp;

template <typename IO>
class AEAD_13 : public AEAD<IO> {
    public:

    int party;
    uint8_t tls_counter = 0; // counts ciphertexts
    uint32_t aes_counter = 1; // counts blocks within a ciphertext

    AEAD_13(IO* io, IO* io_opt, COT<IO>* ot, Integer& key, Integer &iv, int party)
        : AEAD<IO>(io, io_opt, ot, key, iv) {
        this->party = party;
        this->set_nonce(iv);
    }

    inline void set_nonce(Integer& iv) {
        assert(iv.bits.size() == 8*12);
        this->aes_counter = 1;
        Integer counter_gc = Integer(32, this->aes_counter, PUBLIC);
        this->nonce = iv;
        concat(this->nonce, &counter_gc, 1);
    }

    // increments the nonce. Replaces inc() method to replace integer addition with XORs
    // inline void inc_nonce() {
    //     uint32_t counter_diff = aes_counter ^ (aes_counter + 1);
    //     aes_counter++;
    //     Integer counter_diff_gc = Integer(32, &counter_diff, PUBLIC);
    //     for (int i=0; i<32; i++) {
    //         this->nonce.bits[i] ^= counter_diff_gc.bits[i];
    //     }
    // }

    // updates the IV for a new record. This is different from updating the nonce.
    // the IV is the first 12 bytes of the nonce, and is updated with each new TLS record.
    // the nonce is a full 16 bytes block, and is updated on each new AES block
    inline void inc_iv() {
        uint8_t counter_diff = tls_counter ^ (tls_counter + 1);
        tls_counter++;
        Integer counter_diff_gc = Integer(8, counter_diff, PUBLIC);
        Integer new_nonce;
        extract_integer(new_nonce, this->nonce, 0, 8*12);
        //new_nonce ^= counter_diff_gc;


        for (int i=0; i<8; i++) {
            new_nonce.bits[i] ^= counter_diff_gc.bits[i];
        }


        // aes_counter = 1;
        set_nonce(new_nonce);

    }

    inline void gctr(Integer& res, size_t m) {

        Integer tmp(128, 0, PUBLIC);
        for (size_t i = 0; i < m; i++) {
            Integer content = this->nonce;
            tmp = computeAES_KS(this->expanded_key, content);

            concat(res, &tmp, 1);
            this->nonce = this->inc(this->nonce, 32);
        }
    }

     // overrides base function to make output revealed only to Prover
    inline void encrypt(IO* io,
                        unsigned char* ctxt,
                        unsigned char* tag,
                        const unsigned char* msg,
                        uint64_t msg_len,
                        const unsigned char* aad,
                        uint64_t aad_len) {

        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;
        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        Integer Z;
        this->gctr(Z, 1 + ctr_len); // compute encryptions of counter

        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());
        block z0 = integer_to_block(Z0);
        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        // store xor share z0;
        this->gc_z0.push_back(z0);

        // commit PROVER's share of z0 and Z using izk.
        switch_to_zk();
        this->zk_z0.push_back(Integer(8 * sizeof(block), &z0, PROVER));
        this->zk_z.push_back(Z); // not sure if this is right
        sync_zk_gc<IO>();
        switch_to_gc();

        // reveal Z to prover
        unsigned char* z = new unsigned char[msg_len];
        Z.reveal(z, PROVER);
        if (party == VERIFIER)
            memset(z, 0, msg_len);

        // compute ciphertext
        reverse(z, z + msg_len);
        for (size_t i = 0; i < msg_len; i++)
            ctxt[i] = msg[i] ^ z[i];

        delete[] z;
        inc_iv();

        // Now compute the tag.
        size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;
        size_t len = u / 8 + msg_len + v / 8 + aad_len + 16;

        unsigned char* x = new unsigned char[len];

        unsigned char ilen[8], mlen[8];
        for (int i = 0; i < 8; i++) {
            /* must be 64 bits */
            ilen[i] = (8 * aad_len) >> (7 - i) * 8;
            mlen[i] = (8 * msg_len) >> (7 - i) * 8;
        }

        memcpy(x, aad, aad_len);
        memset(x + aad_len, 0, v / 8);
        memcpy(x + aad_len + v / 8, ctxt, msg_len);
        memset(x + aad_len + v / 8 + msg_len, 0, u / 8);
        memcpy(x + aad_len + v / 8 + msg_len + u / 8, ilen, 8);
        memcpy(x + aad_len + v / 8 + msg_len + u / 8 + 8, mlen, 8);

        reverse(x, x + len);
        block* xblk = (block*)x;

        block out = zero_block;
        this->obv_ghash(out, xblk, (8 * len) / 128, party);

        out ^= z0;

        if (party == VERIFIER) {
            io->send_block(&out, 1);
            io->flush();
        } else {
            block out_recv = zero_block;
            io->recv_block(&out_recv, 1);
            out ^= out_recv;
        }

        memcpy(tag, (unsigned char*)&out, 16);
        reverse(tag, tag + 16);
        delete[] x;
    }
};

#endif