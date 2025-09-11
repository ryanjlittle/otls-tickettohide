#ifndef _AEAD_
#define _AEAD_

#include "emp-tool/emp-tool.h"
#include "backend/ole_f2k.h"
#include "cipher/utils.h"
#include "backend/switch.h"
#include "backend/commitment.h"
#include <deque>

using namespace emp;

template <typename IO>
class AEAD {
   public:
    IO* io_opt;
    Integer expanded_key;
    Integer nonce;
    Integer fixed_iv;

    // xor and zk share of h, for izk to check consistency
    block gc_h;
    Integer zk_h;

    // xor and zk share of z0, for izk to check consistency
    deque<block> gc_z0;
    deque<Integer> zk_z0;

    // xor and zk share of z, for izk to check consistency
    deque<unsigned char*> gc_z;
    deque<Integer> zk_z;
    deque<uint64_t> z_len;

    // opened z values and related length. Only for the case sec_type == false
    deque<unsigned char*> open_z;
    deque<uint64_t> open_len;

    // These are the multiplicative shares h^n for h = AES(key,0)
    vector<block> mul_hs;

    OLEF2K<IO>* ole = nullptr;
    // `key` and `iv` are client(server) write key and iv respectively derived from master secret.
    // Note the length of `key` is 16-bytes and the length of `iv` is 4-bytes.
    AEAD(IO* io, IO* io_opt, COT<IO>* ot, Integer& key, Integer& iv) {
        ole = new OLEF2K<IO>(io, ot);
        this->io_opt = io_opt;
        this->fixed_iv = iv;
        expanded_key = computeKS(key);
        Integer H = computeH();

        // transfer gc share of H into xor share locally.
        block h = integer_to_block(H);
        gc_h = h;

        // compute A2M;
        if (!cmpBlock(&ot->Delta, &zero_block, 1)) {
            PRG prg;
            block r = zero_block;
            prg.random_block(&r);
            mul_hs.push_back(invBlock(r));

            block rh = zero_block;
            ole->compute(&rh, &r, 1);

            rh = rh ^ mulBlock(r, h);
            io->send_block(&rh, 1);
        } else {
            block rh = zero_block;
            ole->compute(&rh, &h, 1);

            block mh = zero_block;
            io->recv_block(&mh, 1);

            mul_hs.push_back(rh ^ mh);
        }
        // commit ALICE's share of h using izk.
        switch_to_zk();
        zk_h = Integer(8 * sizeof(block), &gc_h, ALICE);
        sync_zk_gc<IO>();
        switch_to_gc();
    }
    ~AEAD() {
        if (ole != nullptr)
            delete ole;
        for (size_t i = 0; i < gc_z.size(); i++) {
            if (gc_z[i] != nullptr)
                delete[] gc_z[i];
        }
        for (size_t i = 0; i < open_z.size(); i++) {
            if (open_z[i] != nullptr)
                delete[] open_z[i];
        }
    }

    inline Integer computeH() {
        Integer in(128, 0, PUBLIC);
        return computeAES_KS(expanded_key, in);
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

    inline void gctr(Integer& res, size_t m) {
        Integer tmp(128, 0, PUBLIC);
        for (size_t i = 0; i < m; i++) {
            Integer content = nonce;
            tmp = computeAES_KS(expanded_key, content);

            concat(res, &tmp, 1);
            nonce = inc(nonce, 32);
        }
    }

    // `iv_len` should be 8, the `iv` derived from master secret
    // will be concated with this iv to form the full iv, the 
    // length of which is 12-bytes.
    inline void set_nonce(const unsigned char* iv,
                          size_t iv_len,
                          bool ENABLE_ONLINE_OFFLINE = true) {
        assert(iv_len == 8);

        unsigned char* riv = new unsigned char[iv_len];
        memcpy(riv, iv, iv_len);
        reverse(riv, riv + iv_len);
        Integer variable_iv;
        if (ENABLE_ONLINE_OFFLINE)
            variable_iv = Integer(64, riv, ALICE);
        else
            variable_iv = Integer(64, riv, PUBLIC);

        delete[] riv;

        Integer ONE = Integer(32, 1, PUBLIC);

        nonce = fixed_iv;
        concat(nonce, &variable_iv, 1);
        concat(nonce, &ONE, 1);
    }

    // The in blocks are known to one or two parties.
    inline void obv_ghash(block& out, const block* in, size_t len, int party) {
        block h = mul_hs[0];
        while (mul_hs.size() < len)
            mul_hs.push_back(mulBlock(h, mul_hs.back()));

        vector<block> blks;
        if (party == ALICE) {
            for (size_t i = 0; i < len; i++)
                blks.push_back(mulBlock(in[i], mul_hs[i]));
        } else {
            for (size_t i = 0; i < len; i++)
                blks.push_back(mul_hs[i]);
        }

        vector<block> outs;
        outs.resize(len);
        ole->compute(outs.data(), blks.data(), len);

        out = zero_block;
        for (size_t i = 0; i < len; i++) {
            out = out ^ outs[i];
        }
    }

    // AEAD encryption, sec_type indicates the input message is open (false) or secret (true).
    inline void encrypt(IO* io,
                        unsigned char* ctxt,
                        unsigned char* tag,
                        const unsigned char* msg,
                        uint64_t msg_len,
                        const unsigned char* aad,
                        uint64_t aad_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        int party,
                        bool sec_type = false) {


        // u = 128 * ceil(msg_len/128) - 8*msg_len
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;

        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        set_nonce(iv, iv_len);
        Integer Z;

        gctr(Z, 1 + ctr_len);
        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());
        block z0 = integer_to_block(Z0);

        // store xor share z0;
        gc_z0.push_back(z0);

        // commit ALICE's share of z0 using izk.
        switch_to_zk();
        zk_z0.push_back(Integer(8 * sizeof(block), &z0, ALICE));
        sync_zk_gc<IO>();
        switch_to_gc();

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[msg_len];
        if (!sec_type) {
            // message is public
            Z.reveal<unsigned char>((unsigned char*)z, PUBLIC);

            // store opened z for consistency check
            open_z.push_back(nullptr);
            open_z.back() = new unsigned char[msg_len];
            memcpy(open_z.back(), z, msg_len);

            // store the length of z for consistency check.
            open_len.push_back(msg_len);

            reverse(z, z + msg_len);
            for (size_t i = 0; i < msg_len; i++)
                ctxt[i] = msg[i] ^ z[i];
        } else {
            // message is secret
            integer_to_chars(z, Z);

            // store xor share of z
            gc_z.push_back(nullptr);
            gc_z.back() = new unsigned char[msg_len];
            memcpy(gc_z.back(), z, msg_len);
            reverse(gc_z.back(), gc_z.back() + msg_len);
            z_len.push_back(msg_len);

            // commit ALICE's xor share of z using izk.
            switch_to_zk();
            zk_z.push_back(Integer(8 * msg_len, gc_z.back(), ALICE));
            sync_zk_gc<IO>();
            switch_to_gc();

            if (party == ALICE) {
                // ALICE computes msg ^ z_A, sends it to BOB.
                for (size_t i = 0; i < msg_len; i++)
                    ctxt[i] = msg[i] ^ z[i];
                io->send_data(ctxt, msg_len);

                // ALICE receives ctxt
                io->recv_data(ctxt, msg_len);
            } else {
                // BOB receives msg ^ z_A, computes msg ^ z_A ^ z_B = ctxt
                io->recv_data(ctxt, msg_len);
                for (size_t i = 0; i < msg_len; i++)
                    ctxt[i] = ctxt[i] ^ z[i];

                // BOB sends ctxt
                io->send_data(ctxt, msg_len);
            }
        }
        delete[] z;

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
        obv_ghash(out, xblk, (8 * len) / 128, party);

        out ^= z0;

        if (party == BOB) {
            block out_recv = zero_block;
            io->send_block(&out, 1);
            io->flush();
            io_opt->recv_block(&out_recv, 1);

            out ^= out_recv;
        } else {
            block out_recv = zero_block;
            io_opt->send_block(&out, 1);
            io_opt->flush();
            io->recv_block(&out_recv, 1);

            out ^= out_recv;
        }

        memcpy(tag, (unsigned char*)&out, 16);
        reverse(tag, tag + 16);
        delete[] x;
    }

    // AEAD decryption, sec_type indicates the input message is open (false) or secret (true).
    inline bool decrypt(IO* io,
                        unsigned char* msg,
                        const unsigned char* ctxt,
                        uint64_t ctxt_len,
                        const unsigned char* tag,
                        const unsigned char* aad,
                        uint64_t aad_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        int party,
                        bool sec_type = false) {
        // u = 128 * ceil(ctxt_len/128) - 8*ctxt_len
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;

        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;

        bool res = false;

        set_nonce(iv, iv_len);

        Integer Z;
        gctr(Z, 1 + ctr_len);

        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());
        block z0 = integer_to_block(Z0);

        // store xor share z0;
        gc_z0.push_back(z0);

        // commit ALICE's share of z0 using izk.
        switch_to_zk();
        zk_z0.push_back(Integer(8 * sizeof(block), &z0, ALICE));
        sync_zk_gc<IO>();
        switch_to_gc();

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[ctxt_len];

        if (!sec_type) {
            // message is public
            Z.reveal<unsigned char>((unsigned char*)z, PUBLIC);

            // store opened z for consistency check
            // In our protocol, the parties use different instance to encrypt and decrypt.
            // We use the same buffer to store data in encryption and decryption.
            open_z.push_back(nullptr);
            open_z.back() = new unsigned char[ctxt_len];
            memcpy(open_z.back(), z, ctxt_len);

            // store the length of z for consistency check.
            open_len.push_back(ctxt_len);

            reverse(z, z + ctxt_len);
            for (size_t i = 0; i < ctxt_len; i++)
                msg[i] = ctxt[i] ^ z[i];
        } else {
            // message is secret
            integer_to_chars(z, Z);

            // store xor share of z
            gc_z.push_back(nullptr);
            gc_z.back() = new unsigned char[ctxt_len];
            memcpy(gc_z.back(), z, ctxt_len);
            reverse(gc_z.back(), gc_z.back() + ctxt_len);
            z_len.push_back(ctxt_len);

            // commit ALICE's xor share of z using izk.
            switch_to_zk();
            zk_z.push_back(Integer(8 * ctxt_len, gc_z.back(), ALICE));
            sync_zk_gc<IO>();
            switch_to_gc();

            if (party == BOB) {
                // BOB sends xor share z_B to ALICE.
                io->send_data(z, ctxt_len);
            } else {
                // ALICE receives xor share z_B and recover msg.
                io->recv_data(msg, ctxt_len);
                for (size_t i = 0; i < ctxt_len; i++)
                    msg[i] = msg[i] ^ z[i] ^ ctxt[i];
            }
        }
        delete[] z;

        // Now compute the tag.
        size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;
        size_t len = u / 8 + ctxt_len + v / 8 + aad_len + 16;

        unsigned char* x = new unsigned char[len];

        unsigned char ilen[8], mlen[8];
        for (int i = 0; i < 8; i++) {
            /* must be 64 bits */
            ilen[i] = (8 * aad_len) >> (7 - i) * 8;
            mlen[i] = (8 * ctxt_len) >> (7 - i) * 8;
        }

        memcpy(x, aad, aad_len);
        memset(x + aad_len, 0, v / 8);
        memcpy(x + aad_len + v / 8, ctxt, ctxt_len);
        memset(x + aad_len + v / 8 + ctxt_len, 0, u / 8);
        memcpy(x + aad_len + v / 8 + ctxt_len + u / 8, ilen, 8);
        memcpy(x + aad_len + v / 8 + ctxt_len + u / 8 + 8, mlen, 8);

        reverse(x, x + len);
        block* xblk = (block*)x;

        block out = zero_block;
        obv_ghash(out, xblk, (8 * len) / 128, party);

        out ^= z0;

        Commitment c;
        unsigned char* com = new unsigned char[c.output_length];
        unsigned char* rnd = new unsigned char[c.rand_length];

        if (party == ALICE) {
            // ALICE computes commitment of sigma_a, and sends it to BOB
            c.commit(com, rnd, (unsigned char*)&out, sizeof(block));
            io->send_data(com, c.output_length);
            io->flush();

            // ALICE receives commitment of sigma_b, stores it in com
            io_opt->recv_data(com, c.output_length);

            // ALICE sends randomness and sigma_a to ALICE;
            io->send_block(&out, 1);
            io->send_data(rnd, c.rand_length);
            io->flush();
            // ALICE receives randomness and sigma_b
            block outb = zero_block;
            io_opt->recv_block(&outb, 1);
            io_opt->recv_data(rnd, c.rand_length);

            if (c.open(com, rnd, (unsigned char*)&outb, sizeof(block)))
                out = out ^ outb;
            else
                return false;
        } else {
            // BOB computes commitment of sigma_b, and sends it to ALICE
            c.commit(com, rnd, (unsigned char*)&out, sizeof(block));
            io_opt->send_data(com, c.output_length);
            io_opt->flush();

            // BOB receive commitment of sigma_a, stores it in coma;
            unsigned char* coma = new unsigned char[c.output_length];
            io->recv_data(coma, c.output_length);

            // BOB sends randomness and sigma_b to ALICE.
            io_opt->send_block(&out, 1);
            io_opt->send_data(rnd, c.rand_length);
            io_opt->flush();
            // BOB receives randomness and sigma_a
            unsigned char* rnda = new unsigned char[c.rand_length];
            block outa = zero_block;
            io->recv_block(&outa, 1);
            io->recv_data(rnda, c.rand_length);

            memcpy(com, coma, c.output_length);
            memcpy(rnd, rnda, c.rand_length);
            delete[] coma;
            delete[] rnda;

            if (c.open(com, rnd, (unsigned char*)&outa, sizeof(block)))
                out = out ^ outa;
            else
                return false;
        }
        delete[] com;
        delete[] rnd;

        unsigned char* tagc = (unsigned char*)&out;
        reverse(tagc, tagc + 16);

        res = (memcmp(tag, tagc, 16) == 0);

        delete[] x;
        return res;
    }
};

inline void compute_tag(unsigned char* tag,
                        const block h,
                        const block z0,
                        const unsigned char* ctxt,
                        uint64_t ctxt_len,
                        const unsigned char* aad,
                        uint64_t aad_len) {
    size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;
    size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;
    size_t len = u / 8 + ctxt_len + v / 8 + aad_len + 16;

    unsigned char* x = new unsigned char[len];
    unsigned char ilen[8], mlen[8];
    for (int i = 0; i < 8; i++) {
        /* must be 64 bits */
        ilen[i] = (8 * aad_len) >> (7 - i) * 8;
        mlen[i] = (8 * ctxt_len) >> (7 - i) * 8;
    }

    memcpy(x, aad, aad_len);
    memset(x + aad_len, 0, v / 8);
    memcpy(x + aad_len + v / 8, ctxt, ctxt_len);
    memset(x + aad_len + v / 8 + ctxt_len, 0, u / 8);
    memcpy(x + aad_len + v / 8 + ctxt_len + u / 8, ilen, 8);
    memcpy(x + aad_len + v / 8 + ctxt_len + u / 8 + 8, mlen, 8);

    reverse(x, x + len);
    block* xblk = (block*)x;
    reverse(xblk, xblk + (8 * len) / 128);
    block t = ghash(h, xblk, 8 * len / 128);
    t = t ^ z0;

    unsigned char* tagc = (unsigned char*)&t;
    reverse(tagc, tagc + 16);
    memcpy(tag, tagc, 16);
    delete[] x;
}

inline bool compare_tag(const unsigned char* tag,
                        const block h,
                        const block z0,
                        const unsigned char* ctxt,
                        uint64_t ctxt_len,
                        const unsigned char* aad,
                        uint64_t aad_len) {
    unsigned char* ctag = new unsigned char[16];
    compute_tag(ctag, h, z0, ctxt, ctxt_len, aad, aad_len);
    bool res = (memcmp(tag, ctag, 16) == 0);
    delete[] ctag;

    return res;
}

class AEADOffline {
   public:
    Integer expanded_key;
    Integer nonce;
    Integer fixed_iv;

    // `key` and `iv` are client(server) write key and iv respectively derived from master secret.
    // Note the length of `key` is 16-bytes and the length of `iv` is 4-bytes.
    AEADOffline(Integer& key, Integer& iv) {
        expanded_key = computeKS(key);
        Integer H = computeH();
        fixed_iv = iv;
    }
    ~AEADOffline() {}

    inline Integer computeH() {
        Integer in(128, 0, PUBLIC);
        return computeAES_KS(expanded_key, in);
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

    inline void gctr(Integer& res, size_t m) {
        Integer tmp(128, 0, PUBLIC);
        for (size_t i = 0; i < m; i++) {
            Integer content = nonce;
            tmp = computeAES_KS(expanded_key, content);

            concat(res, &tmp, 1);
            nonce = inc(nonce, 32);
        }
    }

    inline void set_nonce() {
        unsigned char riv[8];
        memset(riv, 0x00, 8);
        Integer variable_iv = Integer(64, riv, ALICE);

        Integer ONE = Integer(32, 1, PUBLIC);

        nonce = fixed_iv;
        concat(nonce, &variable_iv, 1);
        concat(nonce, &ONE, 1);
    }

    inline void encrypt(uint64_t msg_len, bool sec_type = false) {
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;
        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        set_nonce();

        Integer Z;
        gctr(Z, 1 + ctr_len);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        if (!sec_type) {
            // message is public
            unsigned char* z = new unsigned char[msg_len];
            memset(z, 0x00, msg_len);
            Z.reveal<unsigned char>((unsigned char*)z, PUBLIC);
            delete[] z;
        }
    }

    inline void decrypt(uint64_t ctxt_len, bool sec_type = false) {
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;
        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;
        set_nonce();

        Integer Z;
        gctr(Z, 1 + ctr_len);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        if (!sec_type) {
            unsigned char* z = new unsigned char[ctxt_len];
            memset(z, 0x00, ctxt_len);
            Z.reveal<unsigned char>((unsigned char*)z, PUBLIC);
            delete[] z;
        }
    }
};
#endif
