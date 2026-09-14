#ifndef OSSL_CRYPTO_NTRUPLUS_HASH_H
#define OSSL_CRYPTO_NTRUPLUS_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/e_os2.h>
#include <openssl/evp.h>

struct ntruplus_key_st;

typedef struct ntruplus_shake_state_st {
    const struct ntruplus_key_st *key;
    EVP_MD_CTX *shake_ctx;
    int owns_shake_ctx;
    const struct ntruplus_key_st *prev_key;
    EVP_MD_CTX *prev_ctx;
    int prev_failed;
} NTRUPLUS_SHAKE_STATE;

void ntruplus_shake256(uint8_t *out, size_t outlen,
                       const uint8_t *in, size_t inlen);
void ntruplus_shake256_prefix(uint8_t *out, size_t outlen,
                              uint8_t prefix,
                              const uint8_t *in, size_t inlen);
__owur int ntruplus_begin_shake(const struct ntruplus_key_st *key,
                                EVP_MD_CTX *caller_ctx,
                                NTRUPLUS_SHAKE_STATE *state);
__owur int ntruplus_end_shake(NTRUPLUS_SHAKE_STATE *state);

#endif /* OSSL_CRYPTO_NTRUPLUS_HASH_H */
