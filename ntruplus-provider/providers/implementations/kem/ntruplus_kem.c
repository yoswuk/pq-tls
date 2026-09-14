#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/ntruplus.h"
#include "prov/providercommon.h"
#include "providers/implementations/kem/ntruplus_kem.inc"

static OSSL_FUNC_kem_newctx_fn ntruplus_newctx;
static OSSL_FUNC_kem_freectx_fn ntruplus_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn ntruplus_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn ntruplus_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn ntruplus_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn ntruplus_decapsulate;
static OSSL_FUNC_kem_set_ctx_params_fn ntruplus_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn ntruplus_settable_ctx_params;

typedef struct {
    NTRUPLUS_KEY *key;
    EVP_MD_CTX *shake_ctx;
    uint8_t entropy_buf[NTRUPLUS_MAX_ENCAP_SEED_BYTES];
    uint8_t *entropy;
    int op;
} PROV_NTRUPLUS_CTX;

static int ntruplus_ensure_kem_shake_ctx(PROV_NTRUPLUS_CTX *ctx)
{
    if (ctx->shake_ctx == NULL)
        ctx->shake_ctx = EVP_MD_CTX_new();
    return ctx->shake_ctx != NULL;
}

static void *ntruplus_newctx(ntruplus_unused void *provctx)
{
    PROV_NTRUPLUS_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->key = NULL;
    ctx->shake_ctx = NULL;
    ctx->entropy = NULL;
    ctx->op = 0;
    return ctx;
}

static void ntruplus_freectx(void *vctx)
{
    PROV_NTRUPLUS_CTX *ctx = vctx;

    if (ctx->entropy != NULL)
        OPENSSL_cleanse(ctx->entropy_buf, sizeof(ctx->entropy_buf));
    EVP_MD_CTX_free(ctx->shake_ctx);
    OPENSSL_free(ctx);
}

static int ntruplus_init(void *vctx, int op, void *key,
    const OSSL_PARAM params[])
{
    PROV_NTRUPLUS_CTX *ctx = vctx;

    if (!ntruplus_prov_is_running())
        return 0;
    ctx->key = key;
    ctx->op = op;
    if (ctx->entropy != NULL) {
        OPENSSL_cleanse(ctx->entropy_buf, sizeof(ctx->entropy_buf));
        ctx->entropy = NULL;
    }
    return ntruplus_set_ctx_params(vctx, params);
}

static int ntruplus_encapsulate_init(void *vctx, void *vkey,
    const OSSL_PARAM params[])
{
    NTRUPLUS_KEY *key = vkey;

    if (!ntruplus_ntruplus_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return ntruplus_init(vctx, EVP_PKEY_OP_ENCAPSULATE, key, params);
}

static int ntruplus_decapsulate_init(void *vctx, void *vkey,
    const OSSL_PARAM params[])
{
    NTRUPLUS_KEY *key = vkey;

    if (!ntruplus_ntruplus_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return ntruplus_init(vctx, EVP_PKEY_OP_DECAPSULATE, key, params);
}

static int ntruplus_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_NTRUPLUS_CTX *ctx = vctx;
    struct ntruplus_set_ctx_params_st p;

    if (ctx == NULL || !ntruplus_set_ctx_params_decoder(params, &p))
        return 0;

    /* Encapsulation ephemeral input key material "ikmE" */
    if (ctx->op == EVP_PKEY_OP_ENCAPSULATE && p.ikme != NULL) {
        const NTRUPLUS_VINFO *v;
        size_t len;

        if (!ntruplus_ntruplus_have_pubkey(ctx->key)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }
        v = ntruplus_ntruplus_key_vinfo(ctx->key);
        len = v->encap_seed_bytes;

        ctx->entropy = ctx->entropy_buf;
        if (OSSL_PARAM_get_octet_string(p.ikme, (void **)&ctx->entropy,
                len, &len)
            && len == v->encap_seed_bytes)
            return 1;

        /* Possibly, but much less likely wrong type */
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
        OPENSSL_cleanse(ctx->entropy_buf, sizeof(ctx->entropy_buf));
        ctx->entropy = NULL;
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *ntruplus_settable_ctx_params(
    ntruplus_unused void *vctx, ntruplus_unused void *provctx)
{
    return ntruplus_set_ctx_params_list;
}

static int ntruplus_encapsulate(void *vctx, unsigned char *ctext, size_t *clen,
    unsigned char *shsec, size_t *slen)
{
    PROV_NTRUPLUS_CTX *ctx = vctx;
    NTRUPLUS_KEY *key = ctx->key;
    const NTRUPLUS_VINFO *v;
    size_t encap_clen;
    size_t encap_slen;
    int ret = 0;

    if (!ntruplus_ntruplus_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto end;
    }
    v = ntruplus_ntruplus_key_vinfo(key);
    encap_clen = v->ctext_bytes;
    encap_slen = v->shsec_bytes;

    if (ctext == NULL) {
        if (clen == NULL && slen == NULL)
            return 0;
        if (clen != NULL)
            *clen = encap_clen;
        if (slen != NULL)
            *slen = encap_slen;
        return 1;
    }
    if (shsec == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_OUTPUT_BUFFER,
            "NULL shared-secret buffer");
        goto end;
    }

    if (clen == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER,
            "null ciphertext input/output length pointer");
        goto end;
    } else if (*clen < encap_clen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "ciphertext buffer too small");
        goto end;
    } else {
        *clen = encap_clen;
    }

    if (slen == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER,
            "null shared secret input/output length pointer");
        goto end;
    } else if (*slen < encap_slen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "shared-secret buffer too small");
        goto end;
    } else {
        *slen = encap_slen;
    }

    if (!ntruplus_ensure_kem_shake_ctx(ctx))
        goto end;

    if (ctx->entropy != NULL)
        ret = ntruplus_ntruplus_encap_seed(ctext, encap_clen, shsec,
            encap_slen, ctx->entropy, v->encap_seed_bytes, key,
            ctx->shake_ctx);
    else
        ret = ntruplus_ntruplus_encap_rand(ctext, encap_clen, shsec,
            encap_slen, key, ctx->shake_ctx);

end:
    /*
     * One shot entropy, each encapsulate call must either provide a new
     * "ikmE", or else will use a random value.  If a caller sets an explicit
     * ikmE once for testing, and later performs multiple encapsulations
     * without again calling encapsulate_init(), these should not share the
     * original entropy.
     */
    if (ctx->entropy != NULL) {
        OPENSSL_cleanse(ctx->entropy_buf, sizeof(ctx->entropy_buf));
        ctx->entropy = NULL;
    }
    return ret;
}

static int ntruplus_decapsulate(void *vctx, uint8_t *shsec, size_t *slen,
    const uint8_t *ctext, size_t clen)
{
    PROV_NTRUPLUS_CTX *ctx = vctx;
    NTRUPLUS_KEY *key = ctx->key;
    const NTRUPLUS_VINFO *v;
    size_t decap_slen;

    if (!ntruplus_ntruplus_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    v = ntruplus_ntruplus_key_vinfo(key);
    decap_slen = v->shsec_bytes;

    if (shsec == NULL) {
        if (slen == NULL)
            return 0;
        *slen = decap_slen;
        return 1;
    }

    /* For now tolerate newly-deprecated NULL length pointers. */
    if (slen == NULL) {
        slen = &decap_slen;
    } else if (*slen < decap_slen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "shared-secret buffer too small");
        return 0;
    } else {
        *slen = decap_slen;
    }

    if (!ntruplus_ensure_kem_shake_ctx(ctx)) {
        OPENSSL_cleanse(shsec, decap_slen);
        return 0;
    }

    /* NTRU+ decap handles incorrect ciphertext lengths internally */
    return ntruplus_ntruplus_decap(shsec, decap_slen, ctext, clen, key,
                                   ctx->shake_ctx);
}

const OSSL_DISPATCH ntruplus_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (OSSL_FUNC)ntruplus_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (OSSL_FUNC)ntruplus_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (OSSL_FUNC)ntruplus_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (OSSL_FUNC)ntruplus_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (OSSL_FUNC)ntruplus_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (OSSL_FUNC)ntruplus_freectx },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (OSSL_FUNC)ntruplus_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (OSSL_FUNC)ntruplus_settable_ctx_params },
    OSSL_DISPATCH_END
};
