/* Parameterized imported NTRU+ KEM glue. */
#include <string.h>
#include <openssl/crypto.h>
#include "internal/constant_time.h"
#include "ntruplus_poly.h"

enum {
    NTRUPLUS_ENCODED_COEFFS_PER_BLOCK = 4,
    NTRUPLUS_ENCODED_BLOCK_BYTES = 6,
    NTRUPLUS_KEM_MSG_BYTES = NTRUPLUS_N / 8 + NTRUPLUS_SYMBYTES,
    NTRUPLUS_KEM_HASH_H_BYTES = NTRUPLUS_SSBYTES + NTRUPLUS_N / 4
};

static inline int ntruplus_kem_gen_f_derand(poly *f, poly *finv,
                                            const uint8_t *coins)
{
    uint8_t buf[NTRUPLUS_N / 4];
    int ret;

    shake256(buf, sizeof(buf), coins, NTRUPLUS_SYMBYTES);
    poly_cbd1(f, buf);
    poly_triple(f, f);
    f->coeffs[0] += 1;
    poly_ntt(f);
    ret = poly_baseinv(finv, f);
    OPENSSL_cleanse(buf, sizeof(buf));
    return ret;
}

static inline int ntruplus_kem_gen_g_derand(poly *g, poly *ginv,
                                            const uint8_t *coins)
{
    uint8_t buf[NTRUPLUS_N / 4];
    int ret;

    shake256(buf, sizeof(buf), coins, NTRUPLUS_SYMBYTES);
    poly_cbd1(g, buf);
    poly_triple(g, g);
    poly_ntt(g);
    ret = poly_baseinv(ginv, g);
    OPENSSL_cleanse(buf, sizeof(buf));
    return ret;
}

static inline void ntruplus_kem_store_keygen_result(uint8_t *pk,
                                                    const poly *f,
                                                    const poly *finv,
                                                    const poly *g,
                                                    const poly *ginv,
                                                    int16_t *h_coeffs,
                                                    int16_t *f_coeffs,
                                                    int16_t *hinv_coeffs,
                                                    uint8_t *pk_hash)
{
    poly h, hinv;
    uint8_t pkbuf[NTRUPLUS_POLYBYTES];
    uint8_t *pkout = pk;

    if (pkout == NULL)
        pkout = pkbuf;
    poly_basemul(&h, g, finv);
    poly_basemul(&hinv, f, ginv);

    poly_tobytes(pkout, &h);

    memcpy(h_coeffs, h.coeffs, NTRUPLUS_POLY_COEFF_BYTES);
    memcpy(f_coeffs, f->coeffs, NTRUPLUS_POLY_COEFF_BYTES);
    memcpy(hinv_coeffs, hinv.coeffs, NTRUPLUS_POLY_COEFF_BYTES);
    hash_f(pk_hash, pkout);
    if (pk == NULL)
        OPENSSL_cleanse(pkbuf, sizeof(pkbuf));
    OPENSSL_cleanse(&h, sizeof(h));
    OPENSSL_cleanse(&hinv, sizeof(hinv));
}

/* Key generation over decoded polynomial storage. */
int ntruplus_kem_keygen(uint8_t *pk, int16_t *h_coeffs, int16_t *f_coeffs,
                        int16_t *hinv_coeffs, uint8_t *pk_hash,
                        int (*random_cb)(uint8_t *out, size_t outlen,
                                         void *arg),
                        void *random_arg)
{
    uint8_t coins[NTRUPLUS_SYMBYTES];
    poly f = { 0 }, finv = { 0 };
    poly g = { 0 }, ginv = { 0 };
    int ret = -1;

    if (h_coeffs == NULL || f_coeffs == NULL || hinv_coeffs == NULL
        || pk_hash == NULL || random_cb == NULL)
        return -1;

    do {
        if (!random_cb(coins, sizeof(coins), random_arg))
            goto end;
    } while (ntruplus_kem_gen_f_derand(&f, &finv, coins));

    do {
        if (!random_cb(coins, sizeof(coins), random_arg))
            goto end;
    } while (ntruplus_kem_gen_g_derand(&g, &ginv, coins));

    ntruplus_kem_store_keygen_result(pk, &f, &finv, &g, &ginv,
                                     h_coeffs, f_coeffs, hinv_coeffs,
                                     pk_hash);
    ret = 0;

end:
    OPENSSL_cleanse(coins, sizeof(coins));
    OPENSSL_cleanse(&f, sizeof(f));
    OPENSSL_cleanse(&finv, sizeof(finv));
    OPENSSL_cleanse(&g, sizeof(g));
    OPENSSL_cleanse(&ginv, sizeof(ginv));
    return ret;
}

/* Encoded polynomial validation and adapters for the key object layer. */
static int ntruplus_kem_encoded_poly_shape_is_valid(size_t len)
{
    return (NTRUPLUS_N % NTRUPLUS_ENCODED_COEFFS_PER_BLOCK) == 0
        && len == NTRUPLUS_POLYBYTES
        && (len % NTRUPLUS_ENCODED_BLOCK_BYTES) == 0
        && (len / NTRUPLUS_ENCODED_BLOCK_BYTES
            == NTRUPLUS_N / NTRUPLUS_ENCODED_COEFFS_PER_BLOCK);
}

static void ntruplus_kem_decode_poly_block(
    uint16_t coeffs[NTRUPLUS_ENCODED_COEFFS_PER_BLOCK],
    const uint8_t in[NTRUPLUS_ENCODED_BLOCK_BYTES])
{
    coeffs[0] = (uint16_t)in[0]
              | ((uint16_t)(in[1] & 0x0f) << 8);
    coeffs[1] = ((uint16_t)in[1] >> 4)
              | ((uint16_t)in[2] << 4);
    coeffs[2] = (uint16_t)in[3]
              | ((uint16_t)(in[4] & 0x0f) << 8);
    coeffs[3] = ((uint16_t)in[4] >> 4)
              | ((uint16_t)in[5] << 4);
}

static uint32_t ntruplus_kem_encoded_poly_block_invalid(
    const uint16_t coeffs[NTRUPLUS_ENCODED_COEFFS_PER_BLOCK])
{
    size_t i;
    uint32_t bad = 0;

    for (i = 0; i < NTRUPLUS_ENCODED_COEFFS_PER_BLOCK; i++)
        bad |= constant_time_ge(coeffs[i], NTRUPLUS_Q);
    return bad;
}

int ntruplus_kem_encoded_poly_is_valid(const uint8_t *in, size_t inlen)
{
    size_t i;
    uint32_t bad = 0;

    if (in == NULL || !ntruplus_kem_encoded_poly_shape_is_valid(inlen))
        return 0;

    for (i = 0; i < inlen; i += NTRUPLUS_ENCODED_BLOCK_BYTES) {
        uint16_t coeffs[NTRUPLUS_ENCODED_COEFFS_PER_BLOCK];

        ntruplus_kem_decode_poly_block(coeffs, in + i);
        bad |= ntruplus_kem_encoded_poly_block_invalid(coeffs);
    }

    return bad == 0;
}

int ntruplus_kem_encode_poly(uint8_t *out, const int16_t *in)
{
    poly p;

    if (out == NULL || in == NULL)
        return 0;
    memcpy(p.coeffs, in, NTRUPLUS_POLY_COEFF_BYTES);
    poly_tobytes(out, &p);
    OPENSSL_cleanse(&p, sizeof(p));
    return 1;
}

int ntruplus_kem_decode_poly(int16_t *out, const uint8_t *in)
{
    poly p;

    if (out == NULL || in == NULL)
        return 0;
    poly_frombytes(&p, in);
    memcpy(out, p.coeffs, NTRUPLUS_POLY_COEFF_BYTES);
    OPENSSL_cleanse(&p, sizeof(p));
    return 1;
}

static void ntruplus_kem_encap_seed_poly(uint8_t *ct, uint8_t *ss,
                                         const poly *h,
                                         const uint8_t *pk_hash,
                                         const uint8_t *coins)
{
    uint8_t msg[NTRUPLUS_KEM_MSG_BYTES];
    uint8_t hash_out[NTRUPLUS_KEM_HASH_H_BYTES];
    uint8_t r_enc[NTRUPLUS_POLYBYTES];
    poly c, r, m;

    memcpy(msg, coins, NTRUPLUS_N / 8);
    memcpy(msg + NTRUPLUS_N / 8, pk_hash, NTRUPLUS_SYMBYTES);
    hash_h(hash_out, msg);

    poly_cbd1(&r, hash_out + NTRUPLUS_SSBYTES);
    poly_ntt(&r);

    poly_tobytes(r_enc, &r);
    hash_g(r_enc, r_enc);
    poly_sotp_encode(&m, msg, r_enc);
    poly_ntt(&m);

    poly_basemul_add(&c, h, &r, &m);
    poly_tobytes(ct, &c);

    memcpy(ss, hash_out, NTRUPLUS_SSBYTES);

    OPENSSL_cleanse(msg, sizeof(msg));
    OPENSSL_cleanse(hash_out, sizeof(hash_out));
    OPENSSL_cleanse(r_enc, sizeof(r_enc));
    OPENSSL_cleanse(&c, sizeof(c));
    OPENSSL_cleanse(&r, sizeof(r));
    OPENSSL_cleanse(&m, sizeof(m));
}

/* Encapsulation. */
int ntruplus_kem_encap_seed(uint8_t *ct, uint8_t *ss,
                            const int16_t *h_coeffs,
                            const uint8_t *pk_hash,
                            const uint8_t *coins)
{
    poly h;

    if (ct == NULL || ss == NULL || h_coeffs == NULL || pk_hash == NULL
        || coins == NULL)
        return 1;

    memcpy(h.coeffs, h_coeffs, NTRUPLUS_POLY_COEFF_BYTES);
    ntruplus_kem_encap_seed_poly(ct, ss, &h, pk_hash, coins);
    OPENSSL_cleanse(&h, sizeof(h));
    return 0;
}

/* Constant-time ciphertext comparison helper. */
static inline int ntruplus_kem_ct_mismatch(const uint8_t *a, const uint8_t *b,
                                           size_t len)
{
    uint8_t acc = 0;
    size_t i;

    for (i = 0; i < len; i++)
        acc |= (uint8_t)(a[i] ^ b[i]);

    return (int)((0U - (uint32_t)acc) >> 31);
}

static int ntruplus_kem_decap_poly(uint8_t *ss, const uint8_t *ct,
                                   const poly *f, const poly *hinv,
                                   const uint8_t *pk_hash)
{
    uint8_t msg[NTRUPLUS_KEM_MSG_BYTES];
    uint8_t r2_enc[NTRUPLUS_POLYBYTES];
    uint8_t r1_enc[NTRUPLUS_POLYBYTES];
    uint8_t hash_out[NTRUPLUS_KEM_HASH_H_BYTES];
    int fail;
    poly c;
    poly r1, r2;
    poly m1, m2;
    size_t i;

    poly_frombytes(&c, ct);

    poly_basemul(&m1, &c, f);
    poly_invntt(&m1);
    poly_crepmod3(&m1, &m1);

    m2 = m1;
    poly_ntt(&m2);
    poly_sub(&c, &c, &m2);
    poly_basemul(&r2, &c, hinv);

    poly_tobytes(r2_enc, &r2);
    hash_g(r1_enc, r2_enc);
    fail = poly_sotp_decode(msg, &m1, r1_enc);

    for (i = 0; i < NTRUPLUS_SYMBYTES; i++)
        msg[i + NTRUPLUS_N / 8] = pk_hash[i];

    hash_h(hash_out, msg);

    poly_cbd1(&r1, hash_out + NTRUPLUS_SSBYTES);
    poly_ntt(&r1);
    poly_tobytes(r1_enc, &r1);

    fail |= ntruplus_kem_ct_mismatch(r2_enc, r1_enc, NTRUPLUS_POLYBYTES);
    fail = (int)((0U - (uint32_t)fail) >> 31);

    for (i = 0; i < NTRUPLUS_SSBYTES; i++)
        ss[i] = hash_out[i] & (uint8_t)(fail - 1);

    OPENSSL_cleanse(msg, sizeof(msg));
    OPENSSL_cleanse(r2_enc, sizeof(r2_enc));
    OPENSSL_cleanse(r1_enc, sizeof(r1_enc));
    OPENSSL_cleanse(hash_out, sizeof(hash_out));
    OPENSSL_cleanse(&c, sizeof(c));
    OPENSSL_cleanse(&r1, sizeof(r1));
    OPENSSL_cleanse(&r2, sizeof(r2));
    OPENSSL_cleanse(&m1, sizeof(m1));
    OPENSSL_cleanse(&m2, sizeof(m2));
    return fail;
}

/* Decapsulation. */
int ntruplus_kem_decap(uint8_t *ss, const uint8_t *ct,
                       const int16_t *f_coeffs,
                       const int16_t *hinv_coeffs,
                       const uint8_t *pk_hash)
{
    poly f, hinv;
    int ret;

    if (ss == NULL || ct == NULL || f_coeffs == NULL || hinv_coeffs == NULL
        || pk_hash == NULL)
        return 1;

    memcpy(f.coeffs, f_coeffs, NTRUPLUS_POLY_COEFF_BYTES);
    memcpy(hinv.coeffs, hinv_coeffs, NTRUPLUS_POLY_COEFF_BYTES);
    ret = ntruplus_kem_decap_poly(ss, ct, &f, &hinv, pk_hash);
    OPENSSL_cleanse(&f, sizeof(f));
    OPENSSL_cleanse(&hinv, sizeof(hinv));
    return ret;
}
