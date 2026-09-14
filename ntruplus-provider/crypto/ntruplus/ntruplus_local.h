#ifndef OSSL_CRYPTO_NTRUPLUS_LOCAL_H
#define OSSL_CRYPTO_NTRUPLUS_LOCAL_H

#include "crypto/ntruplus.h"

#define NTRUPLUS_MAX_N 1152
#define NTRUPLUS_MODULUS 3457

/* Decoded standalone polynomial. */
struct ntruplus_poly_st {
    int16_t coeffs[NTRUPLUS_MAX_N];
};

/*
 * Method table for each parameter-set/code-path object.  The imported KEM
 * entry points use their native convention, 0 on success and nonzero on
 * failure.  The encode/decode adapters use provider-style 1 on success.
 */
struct ntruplus_alg_st {
    int (*keygen)(uint8_t *pk,
                  int16_t *h_coeffs, int16_t *f_coeffs,
                  int16_t *hinv_coeffs, uint8_t *pk_hash,
                  int (*random_cb)(uint8_t *out, size_t outlen,
                                   void *arg),
                  void *random_arg);
    int (*encode_poly)(uint8_t *out, const int16_t *in);
    int (*decode_poly)(int16_t *out, const uint8_t *in);
    int (*encoded_poly_is_valid)(const uint8_t *in, size_t inlen);
    int (*encap_seed)(uint8_t *ct, uint8_t *ss,
                      const int16_t *h_coeffs,
                      const uint8_t *pk_hash,
                      const uint8_t *seed);
    int (*decap)(uint8_t *ss, const uint8_t *ct,
                 const int16_t *f_coeffs, const int16_t *hinv_coeffs,
                 const uint8_t *pk_hash);
};

__owur const NTRUPLUS_ALG *ntruplus_select_alg(const NTRUPLUS_VINFO *vinfo);

static inline int ntruplus_key_is_usable(const NTRUPLUS_KEY *key)
{
    return key != NULL && key->vinfo != NULL;
}

static inline const NTRUPLUS_ALG *ntruplus_key_alg(const NTRUPLUS_KEY *key)
{
    return ntruplus_key_is_usable(key) ? key->alg : NULL;
}

#endif /* OSSL_CRYPTO_NTRUPLUS_LOCAL_H */
