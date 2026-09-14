/* NTRU+ key object support. */
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "ntruplus_hash.h"
#include "ntruplus_local.h"

static size_t ntruplus_poly_coeff_bytes(const NTRUPLUS_VINFO *v)
{
    return (size_t)v->n * sizeof(int16_t);
}

static size_t ntruplus_poly_alloc_bytes(void)
{
    return sizeof(NTRUPLUS_POLY);
}

/* Decoded key-object lifetime. */
static int ntruplus_key_ensure_public(NTRUPLUS_KEY *key)
{
    if (key == NULL)
        return 0;
    if (key->h != NULL)
        return 1;
    if (key->vinfo == NULL)
        return 0;
    key->h = OPENSSL_zalloc(ntruplus_poly_alloc_bytes());
    return key->h != NULL;
}

static void ntruplus_key_clear_public(NTRUPLUS_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_free(key->h);
    key->h = NULL;
}

static int ntruplus_key_ensure_private(NTRUPLUS_KEY *key)
{
    size_t polyalloc;
    uint8_t *priv_mem;

    if (key == NULL)
        return 0;
    if (key->f != NULL && key->hinv != NULL)
        return 1;
    if (key->f != NULL || key->hinv != NULL)
        return 0;
    if (key->vinfo == NULL)
        return 0;

    polyalloc = ntruplus_poly_alloc_bytes();
    priv_mem = OPENSSL_secure_zalloc(2 * polyalloc);
    if (priv_mem == NULL)
        return 0;
    key->f = (NTRUPLUS_POLY *)priv_mem;
    key->hinv = (NTRUPLUS_POLY *)(priv_mem + polyalloc);
    return 1;
}

static void ntruplus_key_clear_private(NTRUPLUS_KEY *key)
{
    if (key == NULL)
        return;
    if (key->f != NULL)
        OPENSSL_secure_clear_free(key->f, 2 * ntruplus_poly_alloc_bytes());
    key->f = NULL;
    key->hinv = NULL;
}

static void ntruplus_poly_copy(NTRUPLUS_POLY *dst, const NTRUPLUS_POLY *src,
                               const NTRUPLUS_VINFO *v)
{
    memcpy(dst->coeffs, src->coeffs, ntruplus_poly_coeff_bytes(v));
}

static void ntruplus_key_copy_public_hash(NTRUPLUS_KEY *dst,
                                          const NTRUPLUS_KEY *src)
{
    memcpy(dst->pk_hash, src->pk_hash, sizeof(dst->pk_hash));
}

static int ntruplus_key_copy_public(NTRUPLUS_KEY *dst,
                                    const NTRUPLUS_KEY *src)
{
    if (!ntruplus_ntruplus_have_pubkey(src) || !ntruplus_key_ensure_public(dst))
        return 0;
    ntruplus_poly_copy(dst->h, src->h, src->vinfo);
    ntruplus_key_copy_public_hash(dst, src);
    return 1;
}

static int ntruplus_key_copy_private(NTRUPLUS_KEY *dst,
                                     const NTRUPLUS_KEY *src)
{
    if (!ntruplus_ntruplus_have_prvkey(src) || !ntruplus_key_ensure_private(dst))
        return 0;
    ntruplus_poly_copy(dst->f, src->f, src->vinfo);
    ntruplus_poly_copy(dst->hinv, src->hinv, src->vinfo);
    ntruplus_key_copy_public_hash(dst, src);
    return 1;
}

static int ntruplus_key_copy_selected(NTRUPLUS_KEY *dst,
                                      const NTRUPLUS_KEY *src,
                                      int key_selection)
{
    switch (key_selection) {
    case 0:
        return 1;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return ntruplus_key_copy_public(dst, src);
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY:
        return ntruplus_key_copy_private(dst, src);
    default:
        return ntruplus_key_copy_public(dst, src)
            && ntruplus_key_copy_private(dst, src);
    }
}

/* Key object lifecycle. */
NTRUPLUS_KEY *ntruplus_ntruplus_key_new(OSSL_LIB_CTX *libctx,
                                        const char *properties,
                                        int evp_type)
{
    const NTRUPLUS_VINFO *vinfo = ntruplus_get_vinfo(evp_type);
    const NTRUPLUS_ALG *alg = NULL;
    NTRUPLUS_KEY *key;

    if (vinfo == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT,
                       "unsupported NTRU+ key type: %d", evp_type);
        return NULL;
    }
    alg = ntruplus_select_alg(vinfo);
    if (alg == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                       "no usable code path for %s",
                       vinfo->algorithm_name);
        return NULL;
    }
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    key->vinfo = vinfo;
    key->libctx = libctx;
    key->alg = alg;
    key->prov_flags = NTRUPLUS_KEY_PROV_FLAGS_DEFAULT;
    key->shake256_md = EVP_MD_fetch(libctx, "SHAKE256", properties);
    if (key->shake256_md == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                       "missing SHAKE256 digest while creating %s key",
                       vinfo->algorithm_name);
        goto err;
    }
    return key;

err:
    ntruplus_ntruplus_key_free(key);
    return NULL;
}

void ntruplus_ntruplus_key_reset(NTRUPLUS_KEY *key)
{
    if (key == NULL)
        return;
    ntruplus_key_clear_public(key);
    ntruplus_key_clear_private(key);
    OPENSSL_cleanse(key->pk_hash, sizeof(key->pk_hash));
}

void ntruplus_ntruplus_key_free(NTRUPLUS_KEY *key)
{
    if (key == NULL)
        return;
    EVP_MD_free(key->shake256_md);
    ntruplus_ntruplus_key_reset(key);
    OPENSSL_free(key);
}

NTRUPLUS_KEY *ntruplus_ntruplus_key_dup(const NTRUPLUS_KEY *key, int selection)
{
    NTRUPLUS_KEY *ret = NULL;
    int key_selection;

    if (key == NULL)
        return NULL;

    key_selection = selection & OSSL_KEYMGMT_SELECT_KEYPAIR;
    if (!ntruplus_ntruplus_have_pubkey(key))
        key_selection &= ~OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    if (!ntruplus_ntruplus_have_prvkey(key))
        key_selection &= ~OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

    ret = OPENSSL_memdup(key, sizeof(*key));
    if (ret == NULL)
        return NULL;
    ret->h = NULL;
    ret->f = NULL;
    ret->hinv = NULL;
    ret->shake256_md = NULL;
    OPENSSL_cleanse(ret->pk_hash, sizeof(ret->pk_hash));

    if (key->shake256_md == NULL || !EVP_MD_up_ref(key->shake256_md)) {
        OPENSSL_free(ret);
        return NULL;
    }
    ret->shake256_md = key->shake256_md;

    if (!ntruplus_key_copy_selected(ret, key, key_selection))
        goto err;
    return ret;

err:
    ntruplus_ntruplus_key_free(ret);
    return NULL;
}

static int ntruplus_key_has_public_hash(const NTRUPLUS_KEY *key)
{
    return ntruplus_ntruplus_have_pubkey(key)
        || ntruplus_ntruplus_have_prvkey(key);
}

static int ntruplus_key_public_hash_matches(const NTRUPLUS_KEY *key,
                                            const uint8_t *pk_hash)
{
    if (!ntruplus_key_has_public_hash(key))
        return 1;
    return pk_hash != NULL
        && CRYPTO_memcmp(key->pk_hash, pk_hash,
                         NTRUPLUS_KEY_HASH_BYTES) == 0;
}

static int ntruplus_key_encoded_poly_is_valid(const NTRUPLUS_KEY *key,
                                              const uint8_t *in, size_t len)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);

    return alg != NULL && alg->encoded_poly_is_valid(in, len);
}

/* Raw public/private key import and export. */
int ntruplus_ntruplus_public_key_is_valid(const uint8_t *in, size_t len,
                                          const NTRUPLUS_KEY *key)
{
    return ntruplus_key_encoded_poly_is_valid(key, in, len);
}

int ntruplus_ntruplus_private_key_is_valid(const uint8_t *in, size_t len,
                                           const NTRUPLUS_KEY *key)
{
    size_t polybytes;

    if (!ntruplus_key_is_usable(key) || in == NULL
        || len != key->vinfo->prvkey_bytes)
        return 0;
    polybytes = key->vinfo->pubkey_bytes;
    return ntruplus_key_encoded_poly_is_valid(key, in, polybytes)
        && ntruplus_key_encoded_poly_is_valid(key, in + polybytes, polybytes);
}

static int ntruplus_parse_public_key_common(const uint8_t *in,
                                            size_t len,
                                            NTRUPLUS_KEY *key,
                                            const uint8_t *pk_hash,
                                            int check_encoding)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);

    if (!ntruplus_key_is_usable(key) || in == NULL
        || len != key->vinfo->pubkey_bytes || key->h != NULL
        || alg == NULL || pk_hash == NULL)
        return 0;
    if (!ntruplus_key_public_hash_matches(key, pk_hash))
        return 0;
    if (check_encoding && !ntruplus_ntruplus_public_key_is_valid(in, len, key))
        return 0;
    if (!ntruplus_key_ensure_public(key))
        return 0;
    if (!alg->decode_poly(key->h->coeffs, in)) {
        ntruplus_key_clear_public(key);
        return 0;
    }
    memcpy(key->pk_hash, pk_hash, sizeof(key->pk_hash));
    return 1;
}

int ntruplus_ntruplus_parse_public_key_with_hash(const uint8_t *in,
                                                 size_t len,
                                                 NTRUPLUS_KEY *key,
                                                 const uint8_t *pk_hash)
{
    return ntruplus_parse_public_key_common(in, len, key, pk_hash, 1);
}

int ntruplus_ntruplus_parse_public_key(const uint8_t *in, size_t len,
                                       NTRUPLUS_KEY *key)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);
    uint8_t pk_hash[NTRUPLUS_KEY_HASH_BYTES] = { 0 };
    int ret = 0;

    if (!ntruplus_key_is_usable(key) || in == NULL
        || len != key->vinfo->pubkey_bytes || key->h != NULL
        || alg == NULL)
        goto end;
    if (!ntruplus_ntruplus_public_key_is_valid(in, len, key))
        goto end;
    if (!ntruplus_ntruplus_hash_public_key(pk_hash, sizeof(pk_hash),
                                           in, len, key, NULL))
        goto end;

    ret = ntruplus_parse_public_key_common(in, len, key, pk_hash, 0);

end:
    OPENSSL_cleanse(pk_hash, sizeof(pk_hash));
    return ret;
}

int ntruplus_ntruplus_parse_private_key(const uint8_t *in, size_t len,
                                        NTRUPLUS_KEY *key)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);
    size_t polybytes;

    if (!ntruplus_key_is_usable(key) || in == NULL
        || len != key->vinfo->prvkey_bytes
        || key->f != NULL || key->hinv != NULL
        || alg == NULL)
        return 0;
    polybytes = key->vinfo->pubkey_bytes;
    if (!ntruplus_ntruplus_private_key_is_valid(in, len, key))
        return 0;
    if (!ntruplus_key_public_hash_matches(key, in + 2 * polybytes))
        return 0;
    if (!ntruplus_key_ensure_private(key))
        return 0;
    if (!alg->decode_poly(key->f->coeffs, in)
        || !alg->decode_poly(key->hinv->coeffs, in + polybytes)) {
        ntruplus_key_clear_private(key);
        return 0;
    }
    memcpy(key->pk_hash, in + 2 * polybytes, sizeof(key->pk_hash));
    return 1;
}

int ntruplus_ntruplus_encode_public_key(uint8_t *out, size_t len,
                                        const NTRUPLUS_KEY *key)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);

    if (!ntruplus_ntruplus_have_pubkey(key) || out == NULL
        || len != key->vinfo->pubkey_bytes || alg == NULL)
        return 0;
    return alg->encode_poly(out, key->h->coeffs);
}

int ntruplus_ntruplus_encode_private_key(uint8_t *out, size_t len,
                                         const NTRUPLUS_KEY *key)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);
    size_t polybytes;

    if (!ntruplus_ntruplus_have_prvkey(key) || out == NULL
        || len != key->vinfo->prvkey_bytes || alg == NULL)
        return 0;
    polybytes = key->vinfo->pubkey_bytes;
    if (!alg->encode_poly(out, key->f->coeffs)
        || !alg->encode_poly(out + polybytes, key->hinv->coeffs))
        return 0;
    memcpy(out + 2 * polybytes, key->pk_hash, sizeof(key->pk_hash));
    return 1;
}

/* Public key hash helpers. */
int ntruplus_ntruplus_hash_public_key(uint8_t *out, size_t outlen,
                                      const uint8_t *pubenc,
                                      size_t publen,
                                      const NTRUPLUS_KEY *key,
                                      EVP_MD_CTX *shake_ctx)
{
    NTRUPLUS_SHAKE_STATE state;

    if (!ntruplus_key_is_usable(key)
        || out == NULL || outlen != NTRUPLUS_KEY_HASH_BYTES
        || pubenc == NULL || publen != key->vinfo->pubkey_bytes)
        return 0;

    if (!ntruplus_begin_shake(key, shake_ctx, &state))
        return 0;
    ntruplus_shake256_prefix(out, outlen, 0x00, pubenc, publen);
    return ntruplus_end_shake(&state);
}

int ntruplus_ntruplus_get_public_hash(uint8_t *out, size_t outlen,
                                      const NTRUPLUS_KEY *key)
{
    if (!ntruplus_key_has_public_hash(key)
        || out == NULL || outlen != NTRUPLUS_KEY_HASH_BYTES)
        return 0;
    memcpy(out, key->pk_hash, NTRUPLUS_KEY_HASH_BYTES);
    return 1;
}

int ntruplus_ntruplus_pubkey_cmp(const NTRUPLUS_KEY *key1,
                                 const NTRUPLUS_KEY *key2)
{
    int have_hash1, have_hash2;

    if (key1 == NULL || key2 == NULL || key1->vinfo != key2->vinfo)
        return 0;

    have_hash1 = ntruplus_key_has_public_hash(key1);
    have_hash2 = ntruplus_key_has_public_hash(key2);
    if (have_hash1 && have_hash2)
        return CRYPTO_memcmp(key1->pk_hash, key2->pk_hash,
                             NTRUPLUS_KEY_HASH_BYTES) == 0;

    return !(have_hash1 ^ have_hash2);
}

struct ntruplus_random_ctx_st {
    OSSL_LIB_CTX *libctx;
    unsigned int strength;
};

static int ntruplus_rand_bytes(uint8_t *out, size_t outlen, void *arg)
{
    struct ntruplus_random_ctx_st *rctx = arg;

    if (rctx == NULL || out == NULL)
        return 0;
    return RAND_priv_bytes_ex(rctx->libctx, out, outlen, rctx->strength) == 1;
}

/* Key generation. */
int ntruplus_ntruplus_genkey(uint8_t *pubenc, size_t publen,
                             NTRUPLUS_KEY *key, EVP_MD_CTX *shake_ctx)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);
    NTRUPLUS_SHAKE_STATE state;
    struct ntruplus_random_ctx_st rctx;
    int ret = 0;

    if (!ntruplus_key_is_usable(key)
        || (pubenc != NULL && publen != key->vinfo->pubkey_bytes)
        || ntruplus_ntruplus_have_pubkey(key)
        || ntruplus_ntruplus_have_prvkey(key)
        || alg == NULL)
        return 0;

    ntruplus_ntruplus_key_reset(key);
    if (!ntruplus_key_ensure_public(key)
        || !ntruplus_key_ensure_private(key)) {
        ntruplus_ntruplus_key_reset(key);
        return 0;
    }
    if (!ntruplus_begin_shake(key, shake_ctx, &state)) {
        ntruplus_ntruplus_key_reset(key);
        return 0;
    }
    rctx.libctx = key->libctx;
    rctx.strength = (unsigned int)key->vinfo->secbits;
    if (alg->keygen(pubenc, key->h->coeffs, key->f->coeffs,
                    key->hinv->coeffs, key->pk_hash,
                    ntruplus_rand_bytes, &rctx) == 0)
        ret = 1;
    ret = ntruplus_end_shake(&state) && ret;

    if (!ret)
        ntruplus_ntruplus_key_reset(key);
    return ret;
}

/* KEM operations over decoded key objects. */
static int ntruplus_key_outputs_are_sized(const NTRUPLUS_KEY *key,
                                          const uint8_t *ct,
                                          size_t ctlen,
                                          const uint8_t *ss,
                                          size_t sslen)
{
    return ntruplus_key_is_usable(key)
        && ct != NULL
        && ctlen == key->vinfo->ctext_bytes
        && ss != NULL
        && sslen == key->vinfo->shsec_bytes;
}

static void ntruplus_key_clear_encap_outputs(const NTRUPLUS_KEY *key,
                                             uint8_t *ct, size_t ctlen,
                                             uint8_t *ss, size_t sslen)
{
    if (ntruplus_key_outputs_are_sized(key, ct, ctlen, ss, sslen)) {
        OPENSSL_cleanse(ct, ctlen);
        OPENSSL_cleanse(ss, sslen);
    }
}

static void ntruplus_key_clear_decap_output(const NTRUPLUS_KEY *key,
                                            uint8_t *ss, size_t sslen)
{
    if (ntruplus_key_is_usable(key)
        && ss != NULL
        && sslen == key->vinfo->shsec_bytes)
        OPENSSL_cleanse(ss, sslen);
}

int ntruplus_ntruplus_encap_seed(uint8_t *ct, size_t ctlen,
                                 uint8_t *ss, size_t sslen,
                                 const uint8_t *seed, size_t seedlen,
                                 const NTRUPLUS_KEY *key,
                                 EVP_MD_CTX *shake_ctx)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);
    NTRUPLUS_SHAKE_STATE state;
    int ret;

    if (!ntruplus_key_outputs_are_sized(key, ct, ctlen, ss, sslen)
        || seed == NULL || seedlen != key->vinfo->encap_seed_bytes
        || alg == NULL
        || !ntruplus_ntruplus_have_pubkey(key)) {
        ntruplus_key_clear_encap_outputs(key, ct, ctlen, ss, sslen);
        return 0;
    }

    if (!ntruplus_begin_shake(key, shake_ctx, &state)) {
        ntruplus_key_clear_encap_outputs(key, ct, ctlen, ss, sslen);
        return 0;
    }
    ret = alg->encap_seed(ct, ss, key->h->coeffs, key->pk_hash,
                          seed) == 0;
    ret = ntruplus_end_shake(&state) && ret;
    if (!ret)
        ntruplus_key_clear_encap_outputs(key, ct, ctlen, ss, sslen);
    return ret;
}

int ntruplus_ntruplus_encap_rand(uint8_t *ct, size_t ctlen,
                                 uint8_t *ss, size_t sslen,
                                 const NTRUPLUS_KEY *key,
                                 EVP_MD_CTX *shake_ctx)
{
    uint8_t seed[NTRUPLUS_MAX_ENCAP_SEED_BYTES];
    int ret;

    if (!ntruplus_key_outputs_are_sized(key, ct, ctlen, ss, sslen))
        return 0;
    if (key->vinfo->encap_seed_bytes > sizeof(seed)) {
        ntruplus_key_clear_encap_outputs(key, ct, ctlen, ss, sslen);
        return 0;
    }

    if (RAND_bytes_ex(key->libctx, seed, key->vinfo->encap_seed_bytes,
                      key->vinfo->secbits) != 1) {
        ntruplus_key_clear_encap_outputs(key, ct, ctlen, ss, sslen);
        OPENSSL_cleanse(seed, sizeof(seed));
        return 0;
    }
    ret = ntruplus_ntruplus_encap_seed(ct, ctlen, ss, sslen, seed,
                                       key->vinfo->encap_seed_bytes, key,
                                       shake_ctx);
    OPENSSL_cleanse(seed, sizeof(seed));
    return ret;
}

int ntruplus_ntruplus_decap(uint8_t *ss, size_t sslen,
                            const uint8_t *ct, size_t ctlen,
                            const NTRUPLUS_KEY *key, EVP_MD_CTX *shake_ctx)
{
    const NTRUPLUS_ALG *alg = ntruplus_key_alg(key);
    NTRUPLUS_SHAKE_STATE state;
    int ret;

    if (!ntruplus_key_outputs_are_sized(key, ct, ctlen, ss, sslen)) {
        ntruplus_key_clear_decap_output(key, ss, sslen);
        return 0;
    }
    if (alg == NULL || !ntruplus_ntruplus_have_prvkey(key)
        || !ntruplus_key_encoded_poly_is_valid(key, ct, ctlen)) {
        ntruplus_key_clear_decap_output(key, ss, sslen);
        return 0;
    }

    if (!ntruplus_begin_shake(key, shake_ctx, &state)) {
        ntruplus_key_clear_decap_output(key, ss, sslen);
        return 0;
    }
    ret = alg->decap(ss, ct, key->f->coeffs,
                     key->hinv->coeffs, key->pk_hash) == 0;
    ret = ntruplus_end_shake(&state) && ret;
    if (!ret)
        ntruplus_key_clear_decap_output(key, ss, sslen);
    return ret;
}
