/* Internal NTRU+ functions for provider submodules, not for application use. */

#ifndef OSSL_CRYPTO_NTRUPLUS_H
#define OSSL_CRYPTO_NTRUPLUS_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/e_os2.h>
#include <openssl/evp.h>

/*
 * Provider-local evp_type values.  They fill the same vinfo role as
 * EVP_PKEY_ML_KEM_* values in OpenSSL's in-tree ML-KEM implementation.
 */
#define EVP_PKEY_NTRUPLUS_768 0
#define EVP_PKEY_NTRUPLUS_864 1
#define EVP_PKEY_NTRUPLUS_1152 2
#define NTRUPLUS_VINFO_COUNT 3

typedef struct ntruplus_vinfo_st {
    const char *algorithm_name;
    size_t prvkey_bytes;
    size_t pubkey_bytes;
    size_t ctext_bytes;
    size_t shsec_bytes;
    size_t encap_seed_bytes;
    int evp_type;
    int n;
    int secbits;
    int security_category;
} NTRUPLUS_VINFO;

#define NTRUPLUS_KEY_HASH_BYTES 32
#define NTRUPLUS_SHARED_SECRET_BYTES 32
#define NTRUPLUS_MAX_ENCAP_SEED_BYTES 144

/* Provider-controlled key import/generation behavior flags. */
#define NTRUPLUS_KEY_RANDOM_PCT (1 << 0)
#define NTRUPLUS_KEY_FIXED_PCT (1 << 1)
/* Mask to check whether PCT on import is enabled */
#define NTRUPLUS_KEY_PCT_TYPE \
    (NTRUPLUS_KEY_RANDOM_PCT | NTRUPLUS_KEY_FIXED_PCT)
/* Default provider flags */
#define NTRUPLUS_KEY_PROV_FLAGS_DEFAULT NTRUPLUS_KEY_RANDOM_PCT

typedef struct ntruplus_poly_st NTRUPLUS_POLY;
typedef struct ntruplus_alg_st NTRUPLUS_ALG;

/*
 * NOTE - any changes to this struct may require
 * ntruplus_ntruplus_key_dup() updates.
 */
typedef struct ntruplus_key_st {
    const NTRUPLUS_VINFO *vinfo;
    OSSL_LIB_CTX *libctx;

    /* Fetched digest, following OpenSSL's ML-KEM key object pattern. */
    EVP_MD *shake256_md;

    /*
     * Decoded key material. Encoded public/private bitstrings are accepted and
     * emitted at provider boundaries, while the key object keeps:
     *   pk = Encodeq(h)
     *   sk = Encodeq(f) || Encodeq(h^-1) || F(pk)
     */
    NTRUPLUS_POLY *h;
    NTRUPLUS_POLY *f;
    NTRUPLUS_POLY *hinv;
    uint8_t pk_hash[NTRUPLUS_KEY_HASH_BYTES];

    /* Selected method table, fixed when the key is created. */
    const NTRUPLUS_ALG *alg;
    int prov_flags; /* PCT flags */
} NTRUPLUS_KEY;

/*
 * Unlike ML-KEM, the NTRU+ private encoding kept here does not carry the
 * public polynomial |h|, so private key material does not imply public key
 * material.
 */
#define ntruplus_ntruplus_key_vinfo(key) ((key)->vinfo)
#define ntruplus_ntruplus_have_pubkey(key) \
    ((key) != NULL && (key)->vinfo != NULL && (key)->h != NULL)
#define ntruplus_ntruplus_have_prvkey(key) \
    ((key) != NULL && (key)->vinfo != NULL \
     && (key)->f != NULL && (key)->hinv != NULL)

/*
 * ----- NTRU+ variant metadata
 */
__owur const NTRUPLUS_VINFO *ntruplus_get_vinfo(int evp_type);

/*
 * ----- NTRU+ key lifecycle
 */
__owur NTRUPLUS_KEY *ntruplus_ntruplus_key_new(OSSL_LIB_CTX *libctx,
                                               const char *properties,
                                               int evp_type);
void ntruplus_ntruplus_key_free(NTRUPLUS_KEY *key);
void ntruplus_ntruplus_key_reset(NTRUPLUS_KEY *key);
__owur NTRUPLUS_KEY *ntruplus_ntruplus_key_dup(const NTRUPLUS_KEY *key,
                                               int selection);

/*
 * ----- Import or generate key material
 */
__owur int ntruplus_ntruplus_public_key_is_valid(const uint8_t *in,
                                                 size_t len,
                                                 const NTRUPLUS_KEY *key);
__owur int ntruplus_ntruplus_private_key_is_valid(const uint8_t *in,
                                                  size_t len,
                                                  const NTRUPLUS_KEY *key);
__owur int ntruplus_ntruplus_parse_public_key(const uint8_t *in,
                                              size_t len, NTRUPLUS_KEY *key);
__owur int ntruplus_ntruplus_parse_public_key_with_hash(const uint8_t *in,
                                                        size_t len,
                                                        NTRUPLUS_KEY *key,
                                                        const uint8_t *pk_hash);
__owur int ntruplus_ntruplus_parse_private_key(const uint8_t *in,
                                               size_t len, NTRUPLUS_KEY *key);
__owur int ntruplus_ntruplus_genkey(uint8_t *pubenc, size_t publen,
                                    NTRUPLUS_KEY *key,
                                    EVP_MD_CTX *shake_ctx);

/*
 * ----- Encode and operate on key material
 */
__owur int ntruplus_ntruplus_encode_public_key(uint8_t *out, size_t len,
                                               const NTRUPLUS_KEY *key);
__owur int ntruplus_ntruplus_encode_private_key(uint8_t *out, size_t len,
                                                const NTRUPLUS_KEY *key);
__owur int ntruplus_ntruplus_hash_public_key(uint8_t *out, size_t outlen,
                                             const uint8_t *pubenc,
                                             size_t publen,
                                             const NTRUPLUS_KEY *key,
                                             EVP_MD_CTX *shake_ctx);
__owur int ntruplus_ntruplus_get_public_hash(uint8_t *out, size_t outlen,
                                             const NTRUPLUS_KEY *key);
__owur int ntruplus_ntruplus_pubkey_cmp(const NTRUPLUS_KEY *key1,
                                        const NTRUPLUS_KEY *key2);
__owur int ntruplus_ntruplus_encap_seed(uint8_t *ct, size_t ctlen,
                                        uint8_t *ss, size_t sslen,
                                        const uint8_t *seed,
                                        size_t seedlen,
                                        const NTRUPLUS_KEY *key,
                                        EVP_MD_CTX *shake_ctx);
__owur int ntruplus_ntruplus_encap_rand(uint8_t *ct, size_t ctlen,
                                        uint8_t *ss, size_t sslen,
                                        const NTRUPLUS_KEY *key,
                                        EVP_MD_CTX *shake_ctx);
__owur int ntruplus_ntruplus_decap(uint8_t *ss, size_t sslen,
                                   const uint8_t *ct, size_t ctlen,
                                   const NTRUPLUS_KEY *key,
                                   EVP_MD_CTX *shake_ctx);

#endif /* OSSL_CRYPTO_NTRUPLUS_H */
