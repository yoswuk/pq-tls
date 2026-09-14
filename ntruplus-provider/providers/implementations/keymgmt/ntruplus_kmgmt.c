#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/ntruplus.h"
#include "prov/providercommon.h"
#include "providers/implementations/keymgmt/ntruplus_kmgmt.inc"

static OSSL_FUNC_keymgmt_new_fn ntruplus768_new;
static OSSL_FUNC_keymgmt_new_fn ntruplus864_new;
static OSSL_FUNC_keymgmt_new_fn ntruplus1152_new;
static OSSL_FUNC_keymgmt_free_fn ntruplus_free_key;
static OSSL_FUNC_keymgmt_gen_fn ntruplus_gen;
static OSSL_FUNC_keymgmt_gen_init_fn ntruplus768_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn ntruplus864_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn ntruplus1152_gen_init;
static OSSL_FUNC_keymgmt_gen_cleanup_fn ntruplus_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn ntruplus_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn ntruplus_gen_settable_params;
static OSSL_FUNC_keymgmt_load_fn ntruplus_load;
static OSSL_FUNC_keymgmt_get_params_fn ntruplus_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ntruplus_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn ntruplus_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn ntruplus_settable_params;
static OSSL_FUNC_keymgmt_has_fn ntruplus_has;
static OSSL_FUNC_keymgmt_match_fn ntruplus_match;
static OSSL_FUNC_keymgmt_validate_fn ntruplus_validate;
static OSSL_FUNC_keymgmt_import_fn ntruplus_import;
static OSSL_FUNC_keymgmt_export_fn ntruplus_export;
static OSSL_FUNC_keymgmt_import_types_fn ntruplus_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn ntruplus_imexport_types;
static OSSL_FUNC_keymgmt_dup_fn ntruplus_dup;

static const int minimal_selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
    | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

typedef struct ntruplus_gen_ctx_st {
    PROV_CTX *provctx;
    char *propq;
    int selection;
    int evp_type;
    EVP_MD_CTX *shake_ctx;
} PROV_NTRUPLUS_GEN_CTX;

static int ntruplus_pairwise_test(const NTRUPLUS_KEY *key, int key_flags,
                                  EVP_MD_CTX *shake_ctx)
{
    uint8_t entropy[NTRUPLUS_MAX_ENCAP_SEED_BYTES];
    uint8_t secret[NTRUPLUS_SHARED_SECRET_BYTES];
    uint8_t out[NTRUPLUS_SHARED_SECRET_BYTES];
    uint8_t *ctext = NULL;
    const NTRUPLUS_VINFO *v;
    EVP_MD_CTX *ctx = shake_ctx;
    int operation_result = 0;
    int ret = 0;

    /* Unless we have both a public and private key, we can't do the test */
    if (!ntruplus_ntruplus_have_prvkey(key)
        || !ntruplus_ntruplus_have_pubkey(key)
        || (key_flags & NTRUPLUS_KEY_PCT_TYPE) == 0)
        return 1;

    v = ntruplus_ntruplus_key_vinfo(key);
    if (v->encap_seed_bytes > sizeof(entropy)
        || v->shsec_bytes > sizeof(secret)
        || v->shsec_bytes > sizeof(out))
        return 0;

    ctext = OPENSSL_malloc(v->ctext_bytes);
    if (ctx == NULL)
        ctx = EVP_MD_CTX_new();
    if (ctext == NULL || ctx == NULL)
        goto err;

    memset(out, 0, sizeof(out));
    /*
     * The pairwise test is skipped unless either RANDOM or FIXED entropy PCTs
     * are enabled.
     */
    if (key_flags & NTRUPLUS_KEY_RANDOM_PCT) {
        operation_result = ntruplus_ntruplus_encap_rand(ctext, v->ctext_bytes,
            secret, sizeof(secret), key, ctx);
    } else {
        memset(entropy, 0125, v->encap_seed_bytes);
        operation_result = ntruplus_ntruplus_encap_seed(ctext, v->ctext_bytes,
            secret, sizeof(secret),
            entropy, v->encap_seed_bytes,
            key, ctx);
    }
    if (operation_result != 1)
        goto err;

    operation_result = ntruplus_ntruplus_decap(out, sizeof(out), ctext,
        v->ctext_bytes, key, ctx);
    if (operation_result != 1
        || CRYPTO_memcmp(out, secret, sizeof(out)) != 0)
        goto err;

    ret = 1;
err:
    if (ret == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
            "public part of %s private key fails to match private",
            v->algorithm_name);
    }

    if (shake_ctx == NULL)
        EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(entropy, sizeof(entropy));
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(out, sizeof(out));
    OPENSSL_clear_free(ctext, v->ctext_bytes);
    return ret;
}

NTRUPLUS_KEY *ntruplus_prov_ntruplus_new(PROV_CTX *ctx,
                                         const char *propq, int evp_type)
{
    NTRUPLUS_KEY *key;

    if (!ntruplus_prov_is_running())
        return NULL;

    /*
     * When decoding, if the key ends up "loaded" into the same provider, these
     * are the correct config settings, otherwise, new values will be assigned
     * on import into a different provider.  The "load" API does not pass along
     * the provider context.
     */
    if ((key = ntruplus_ntruplus_key_new(PROV_LIBCTX_OF(ctx), propq,
            evp_type)) != NULL) {
        const char *pct_type = ntruplus_prov_ctx_get_param(
            ctx, NTRUPLUS_PKEY_PARAM_IMPORT_PCT_TYPE, "random");

        if (OPENSSL_strcasecmp(pct_type, "random") == 0)
            key->prov_flags |= NTRUPLUS_KEY_RANDOM_PCT;
        else if (OPENSSL_strcasecmp(pct_type, "fixed") == 0)
            key->prov_flags |= NTRUPLUS_KEY_FIXED_PCT;
        else
            key->prov_flags &= ~NTRUPLUS_KEY_PCT_TYPE;
    }
    return key;
}

static int ntruplus_has(const void *vkey, int selection)
{
    const NTRUPLUS_KEY *key = vkey;

    if (!ntruplus_prov_is_running() || key == NULL)
        return 0;

    switch (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
    case 0:
        return 1;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return ntruplus_ntruplus_have_pubkey(key);
    default:
        return ntruplus_ntruplus_have_prvkey(key);
    }
}

static int ntruplus_match(const void *vkey1, const void *vkey2, int selection)
{
    const NTRUPLUS_KEY *key1 = vkey1;
    const NTRUPLUS_KEY *key2 = vkey2;

    if (!ntruplus_prov_is_running())
        return 0;

    /* All we have that can be compared is key material */
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return 1;

    return ntruplus_ntruplus_pubkey_cmp(key1, key2);
}

static int ntruplus_validate(const void *vkey, int selection,
    ntruplus_unused int check_type)
{
    const NTRUPLUS_KEY *key = vkey;

    if (!ntruplus_has(key, selection))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        return ntruplus_ntruplus_have_prvkey(key)
            && ntruplus_ntruplus_have_pubkey(key)
            && ntruplus_pairwise_test(key, NTRUPLUS_KEY_RANDOM_PCT, NULL);
    return 1;
}

static int ntruplus_export(void *vkey, int selection, OSSL_CALLBACK *param_cb,
    void *cbarg)
{
    NTRUPLUS_KEY *key = vkey;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    const NTRUPLUS_VINFO *v;
    uint8_t *pubenc = NULL, *prvenc = NULL;
    size_t prvlen = 0;
    int ret = 0;

    if (!ntruplus_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    v = ntruplus_ntruplus_key_vinfo(key);

    if (!ntruplus_ntruplus_have_pubkey(key)) {
        /* Fail when no key material can be returned */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0
            || !ntruplus_ntruplus_have_prvkey(key)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        pubenc = OPENSSL_malloc(v->pubkey_bytes);
        if (pubenc == NULL
            || !ntruplus_ntruplus_encode_public_key(pubenc, v->pubkey_bytes, key))
            goto err;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && ntruplus_ntruplus_have_prvkey(key)) {
        prvlen = v->prvkey_bytes;
        if ((prvenc = OPENSSL_secure_zalloc(prvlen)) == NULL
            || !ntruplus_ntruplus_encode_private_key(prvenc, prvlen, key))
            goto err;
    }

    if (pubenc == NULL && prvenc == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto err;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        goto err;

    /* The private key, when requested. */
    if (prvenc != NULL
        && !OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PRIV_KEY,
                                             prvenc, prvlen))
        goto err;

    /* The public key, when requested and available. */
    if (pubenc != NULL
        && !OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                             pubenc, v->pubkey_bytes))
        goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_clear_free(params);

err:
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_secure_clear_free(prvenc, prvlen);
    OPENSSL_free(pubenc);
    return ret;
}

static const OSSL_PARAM *ntruplus_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ntruplus_key_type_params_list;
    return NULL;
}

static int ntruplus_ensure_shake_ctx(EVP_MD_CTX **shake_ctx)
{
    if (shake_ctx == NULL)
        return 0;
    if (*shake_ctx == NULL)
        *shake_ctx = EVP_MD_CTX_new();
    return *shake_ctx != NULL;
}

static int ntruplus_public_hash_matches(const NTRUPLUS_KEY *key,
                                        const uint8_t *pubenc,
                                        size_t publen,
                                        const uint8_t *expected,
                                        uint8_t *actual,
                                        EVP_MD_CTX *shake_ctx)
{
    uint8_t local_actual[NTRUPLUS_KEY_HASH_BYTES];
    uint8_t *hash = actual != NULL ? actual : local_actual;
    int ret = 0;

    if (key == NULL || pubenc == NULL || expected == NULL)
        return 0;
    if (!ntruplus_ntruplus_public_key_is_valid(pubenc, publen, key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
            "invalid public part of %s private key",
            ntruplus_ntruplus_key_vinfo(key)->algorithm_name);
        goto end;
    }

    if (!ntruplus_ntruplus_hash_public_key(hash, NTRUPLUS_KEY_HASH_BYTES,
                                           pubenc, publen, key, shake_ctx))
        goto end;
    if (CRYPTO_memcmp(hash, expected, NTRUPLUS_KEY_HASH_BYTES) != 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
            "public part of %s private key hash does not match",
            ntruplus_ntruplus_key_vinfo(key)->algorithm_name);
        goto end;
    }
    ret = 1;

end:
    if (!ret && actual != NULL)
        OPENSSL_cleanse(actual, NTRUPLUS_KEY_HASH_BYTES);
    if (actual == NULL)
        OPENSSL_cleanse(local_actual, sizeof(local_actual));
    return ret;
}

static int ntruplus_public_hash_matches_private(const NTRUPLUS_KEY *key,
                                                const uint8_t *pubenc,
                                                const uint8_t *prvenc,
                                                uint8_t *actual,
                                                EVP_MD_CTX *shake_ctx)
{
    const NTRUPLUS_VINFO *v = key == NULL ? NULL
                                          : ntruplus_ntruplus_key_vinfo(key);
    size_t pubkey_bytes;

    if (v == NULL || pubenc == NULL || prvenc == NULL)
        return 0;
    if (!ntruplus_ntruplus_private_key_is_valid(prvenc, v->prvkey_bytes, key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    pubkey_bytes = v->pubkey_bytes;
    return ntruplus_public_hash_matches(key, pubenc, pubkey_bytes,
                                        prvenc + 2 * pubkey_bytes, actual,
                                        shake_ctx);
}

static int ntruplus_key_fromdata(NTRUPLUS_KEY *key,
    const OSSL_PARAM params[],
    int include_private, EVP_MD_CTX **shake_ctx)
{
    uint8_t pk_hash[NTRUPLUS_KEY_HASH_BYTES] = { 0 };
    const void *pubenc = NULL, *prvenc = NULL;
    size_t publen = 0, prvlen = 0;
    const NTRUPLUS_VINFO *v;
    struct ntruplus_key_type_params_st p;
    int have_public_hash = 0;
    int ret = 0;

    /* Imports create immutable key material. */
    if (key == NULL
        || ntruplus_ntruplus_have_pubkey(key)
        || ntruplus_ntruplus_have_prvkey(key)
        || !ntruplus_key_type_params_decoder(params, &p))
        goto end;
    v = ntruplus_ntruplus_key_vinfo(key);

    if (p.privkey != NULL && include_private) {
        if (OSSL_PARAM_get_octet_string_ptr(p.privkey, &prvenc, &prvlen) != 1)
            goto end;
        if (prvlen != 0 && prvlen != v->prvkey_bytes) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto end;
        }
    }

    if (p.pubkey != NULL) {
        if (OSSL_PARAM_get_octet_string_ptr(p.pubkey, &pubenc, &publen) != 1)
            goto end;
        if (publen != 0 && publen != v->pubkey_bytes) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto end;
        }
    }

    /* The caller MUST specify at least one of private or public keys. */
    if (publen == 0 && prvlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto end;
    }

    /* Check any explicit public key against embedded value in private key */
    if (publen > 0 && prvlen > 0
        && (!ntruplus_ensure_shake_ctx(shake_ctx)
            || !ntruplus_public_hash_matches_private(key, pubenc, prvenc,
                                                     pk_hash, *shake_ctx)))
        goto end;
    have_public_hash = publen > 0 && prvlen > 0;

    if (publen > 0 && !(have_public_hash
        ? ntruplus_ntruplus_parse_public_key_with_hash(pubenc, publen, key,
                                                       pk_hash)
        : ntruplus_ntruplus_parse_public_key(pubenc, publen, key))) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        ntruplus_ntruplus_key_reset(key);
        goto end;
    }
    if (prvlen > 0
        && !ntruplus_ntruplus_parse_private_key(prvenc, prvlen, key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        ntruplus_ntruplus_key_reset(key);
        goto end;
    }
    ret = 1;

end:
    OPENSSL_cleanse(pk_hash, sizeof(pk_hash));
    return ret;
}

static int ntruplus_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    NTRUPLUS_KEY *key = vkey;
    EVP_MD_CTX *shake_ctx = NULL;
    int include_private;
    int res;

    if (!ntruplus_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    res = ntruplus_key_fromdata(key, params, include_private, &shake_ctx);
    if (res > 0 && include_private
        && !ntruplus_pairwise_test(key, key->prov_flags, shake_ctx)) {
        ntruplus_ntruplus_key_reset(key);
        res = 0;
    }
    EVP_MD_CTX_free(shake_ctx);
    return res;
}

static const OSSL_PARAM *ntruplus_gettable_params(ntruplus_unused void *provctx)
{
    return ntruplus_get_params_list;
}

static void *ntruplus_load(const void *reference, size_t reference_sz)
{
    NTRUPLUS_KEY *key = NULL;

    if (ntruplus_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(NTRUPLUS_KEY **)reference;
        /* We grabbed, so we detach it */
        *(NTRUPLUS_KEY **)reference = NULL;
    }
    return key;
}

static int ntruplus_get_key_param(const NTRUPLUS_KEY *key, OSSL_PARAM *p,
    size_t bytes,
    int (*get_f)(uint8_t *out, size_t len,
        const NTRUPLUS_KEY *key))
{
    if (p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;
    p->return_size = bytes;
    if (p->data != NULL)
        if (p->data_size < p->return_size
            || !(*get_f)(p->data, p->return_size, key))
            return 0;
    return 1;
}

/*
 * It is assumed the key is guaranteed non-NULL here, and is from this provider
 */
static int ntruplus_get_params(void *vkey, OSSL_PARAM params[])
{
    NTRUPLUS_KEY *key = vkey;
    const NTRUPLUS_VINFO *v;
    struct ntruplus_get_params_st p;

    if (key == NULL || !ntruplus_get_params_decoder(params, &p))
        return 0;

    v = ntruplus_ntruplus_key_vinfo(key);

    if (p.bits != NULL && !OSSL_PARAM_set_size_t(p.bits, (size_t)v->n))
        return 0;

    if (p.secbits != NULL && !OSSL_PARAM_set_size_t(p.secbits, v->secbits))
        return 0;

    if (p.maxsize != NULL && !OSSL_PARAM_set_size_t(p.maxsize, v->ctext_bytes))
        return 0;

#ifdef OSSL_PKEY_PARAM_SECURITY_CATEGORY
    if (p.seccat != NULL && !OSSL_PARAM_set_int(p.seccat, v->security_category))
        return 0;
#endif

    if (p.pubkey != NULL && ntruplus_ntruplus_have_pubkey(key)) {
        /* Exported to EVP_PKEY_get_raw_public_key() */
        if (!ntruplus_get_key_param(key, p.pubkey, v->pubkey_bytes,
                &ntruplus_ntruplus_encode_public_key))
            return 0;
    }

    if (p.encpubkey != NULL && ntruplus_ntruplus_have_pubkey(key)) {
        /* Needed by EVP_PKEY_get1_encoded_public_key() */
        if (!ntruplus_get_key_param(key, p.encpubkey, v->pubkey_bytes,
                &ntruplus_ntruplus_encode_public_key))
            return 0;
    }

    if (p.privkey != NULL && ntruplus_ntruplus_have_prvkey(key)) {
        /* Exported to EVP_PKEY_get_raw_private_key() */
        if (!ntruplus_get_key_param(key, p.privkey, v->prvkey_bytes,
                &ntruplus_ntruplus_encode_private_key))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *ntruplus_settable_params(ntruplus_unused void *provctx)
{
    return ntruplus_set_params_list;
}

static int ntruplus_set_public_on_private(NTRUPLUS_KEY *key,
                                          const void *pub, size_t publen)
{
    uint8_t expected_hash[NTRUPLUS_KEY_HASH_BYTES] = { 0 };
    uint8_t pk_hash[NTRUPLUS_KEY_HASH_BYTES] = { 0 };
    EVP_MD_CTX *shake_ctx = NULL;
    NTRUPLUS_KEY *tmp = NULL;
    int ret = 0;

    shake_ctx = EVP_MD_CTX_new();
    if (shake_ctx == NULL)
        return 0;

    if (!ntruplus_ntruplus_get_public_hash(expected_hash,
                                           sizeof(expected_hash), key)
        || !ntruplus_public_hash_matches(key, pub, publen, expected_hash,
                                         pk_hash, shake_ctx))
        goto end;

    tmp = ntruplus_ntruplus_key_dup(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
    if (tmp == NULL)
        goto end;

    if (ntruplus_ntruplus_parse_public_key_with_hash(pub, publen, tmp,
                                                     pk_hash)
        && ntruplus_pairwise_test(tmp, tmp->prov_flags, shake_ctx))
        ret = ntruplus_ntruplus_parse_public_key_with_hash(pub, publen, key,
                                                           pk_hash);

end:
    EVP_MD_CTX_free(shake_ctx);
    ntruplus_ntruplus_key_free(tmp);
    OPENSSL_cleanse(expected_hash, sizeof(expected_hash));
    OPENSSL_cleanse(pk_hash, sizeof(pk_hash));
    return ret;
}

static int ntruplus_set_params(void *vkey, const OSSL_PARAM params[])
{
    NTRUPLUS_KEY *key = vkey;
    const NTRUPLUS_VINFO *v;
    const void *pubenc = NULL;
    size_t publen = 0;
    struct ntruplus_set_params_st p;

    if (key == NULL || !ntruplus_set_params_decoder(params, &p))
        return 0;
    v = ntruplus_ntruplus_key_vinfo(key);

    /* Used in TLS via EVP_PKEY_set1_encoded_public_key(). */
    if (p.pub != NULL
        && (OSSL_PARAM_get_octet_string_ptr(p.pub, &pubenc, &publen) != 1
            || publen != v->pubkey_bytes)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    if (publen == 0)
        return 1;

    /* Provider keys are immutable once public key material is present. */
    if (ntruplus_ntruplus_have_pubkey(key)) {
        ERR_raise_data(ERR_LIB_PROV,
            PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            "NTRU+ keys cannot be mutated");
        return 0;
    }

    if (ntruplus_ntruplus_have_prvkey(key))
        return ntruplus_set_public_on_private(key, pubenc, publen);

    return ntruplus_ntruplus_parse_public_key(pubenc, publen, key);
}

static int ntruplus_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    PROV_NTRUPLUS_GEN_CTX *gctx = vgctx;
    struct ntruplus_gen_set_params_st p;

    if (gctx == NULL || !ntruplus_gen_set_params_decoder(params, &p))
        return 0;

    if (p.propq != NULL) {
        if (p.propq->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        if ((gctx->propq = OPENSSL_strdup(p.propq->data)) == NULL)
            return 0;
    }

    return 1;
}

static void *ntruplus_gen_init(void *provctx, int selection,
    const OSSL_PARAM params[], int evp_type)
{
    PROV_NTRUPLUS_GEN_CTX *gctx = NULL;

    /*
     * We can only generate private keys, check that the selection is
     * appropriate.
     */
    if (!ntruplus_prov_is_running()
        || (selection & minimal_selection) == 0
        || (gctx = OPENSSL_zalloc(sizeof(*gctx))) == NULL)
        return NULL;

    gctx->selection = selection;
    gctx->evp_type = evp_type;
    gctx->provctx = provctx;
    if (ntruplus_gen_set_params(gctx, params))
        return gctx;

    ntruplus_gen_cleanup(gctx);
    return NULL;
}

static const OSSL_PARAM *ntruplus_gen_settable_params(
    ntruplus_unused void *vgctx, ntruplus_unused void *provctx)
{
    return ntruplus_gen_set_params_list;
}

static void *ntruplus_gen(void *vgctx, ntruplus_unused OSSL_CALLBACK *osslcb,
    ntruplus_unused void *cbarg)
{
    PROV_NTRUPLUS_GEN_CTX *gctx = vgctx;
    NTRUPLUS_KEY *key;
    int genok = 0;

    if (gctx == NULL
        || (gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
           == OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return NULL;
    key = ntruplus_prov_ntruplus_new(gctx->provctx, gctx->propq,
                                     gctx->evp_type);
    if (key == NULL)
        return NULL;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;
    if (gctx->shake_ctx == NULL) {
        gctx->shake_ctx = EVP_MD_CTX_new();
        if (gctx->shake_ctx == NULL) {
            ntruplus_ntruplus_key_free(key);
            return NULL;
        }
    }
    genok = ntruplus_ntruplus_genkey(NULL, 0, key, gctx->shake_ctx);
    if (genok)
        return key;

    ntruplus_ntruplus_key_free(key);
    return NULL;
}

static void ntruplus_gen_cleanup(void *vgctx)
{
    PROV_NTRUPLUS_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;

    EVP_MD_CTX_free(gctx->shake_ctx);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static void *ntruplus_dup(const void *vkey, int selection)
{
    const NTRUPLUS_KEY *key = vkey;

    if (!ntruplus_prov_is_running())
        return NULL;

    return ntruplus_ntruplus_key_dup(key, selection);
}

static void ntruplus_free_key(void *keydata)
{
    ntruplus_ntruplus_key_free((NTRUPLUS_KEY *)keydata);
}

#define DISPATCH_LOAD_FN \
    { OSSL_FUNC_KEYMGMT_LOAD, (OSSL_FUNC)ntruplus_load },

#define DECLARE_VARIANT(bits)                                                             \
    static OSSL_FUNC_keymgmt_new_fn ntruplus##bits##_new;                                 \
    static OSSL_FUNC_keymgmt_gen_init_fn ntruplus##bits##_gen_init;                       \
    static void *ntruplus##bits##_new(void *provctx)                                      \
    {                                                                                     \
        return ntruplus_prov_ntruplus_new(provctx, NULL, EVP_PKEY_NTRUPLUS_##bits);       \
    }                                                                                     \
    static void *ntruplus##bits##_gen_init(void *provctx, int selection,                  \
        const OSSL_PARAM params[])                                                        \
    {                                                                                     \
        return ntruplus_gen_init(provctx, selection, params,                              \
            EVP_PKEY_NTRUPLUS_##bits);                                                    \
    }                                                                                     \
    const OSSL_DISPATCH ntruplus##bits##_keymgmt_functions[] = {                          \
        { OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)ntruplus##bits##_new },                       \
        { OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)ntruplus_free_key },                         \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC)ntruplus_get_params },                 \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (OSSL_FUNC)ntruplus_gettable_params },       \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (OSSL_FUNC)ntruplus_set_params },                 \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (OSSL_FUNC)ntruplus_settable_params },       \
        { OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)ntruplus_has },                               \
        { OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)ntruplus_match },                           \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (OSSL_FUNC)ntruplus_validate },                     \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (OSSL_FUNC)ntruplus##bits##_gen_init },             \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (OSSL_FUNC)ntruplus_gen_set_params },         \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (OSSL_FUNC)ntruplus_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (OSSL_FUNC)ntruplus_gen },                               \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (OSSL_FUNC)ntruplus_gen_cleanup },               \
        DISPATCH_LOAD_FN { OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)ntruplus_dup },              \
        { OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)ntruplus_import },                         \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)ntruplus_imexport_types },           \
        { OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)ntruplus_export },                         \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)ntruplus_imexport_types },           \
        OSSL_DISPATCH_END                                                                 \
    }

DECLARE_VARIANT(768);
DECLARE_VARIANT(864);
DECLARE_VARIANT(1152);
