#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/ntruplus.h"
#include "prov/providercommon.h"

static OSSL_FUNC_kem_newctx_fn ntruplusx_kem_newctx;
static OSSL_FUNC_kem_freectx_fn ntruplusx_kem_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn ntruplusx_kem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn ntruplusx_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn ntruplusx_kem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn ntruplusx_kem_decapsulate;
static OSSL_FUNC_kem_set_ctx_params_fn ntruplusx_kem_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn ntruplusx_kem_settable_ctx_params;

typedef struct {
    OSSL_LIB_CTX *libctx;
    NTRUPLUSX_KEY *key;
    int op;
} PROV_NTRUPLUSX_KEM_CTX;

static void *ntruplusx_kem_newctx(void *provctx)
{
    PROV_NTRUPLUSX_KEM_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->key = NULL;
    ctx->op = 0;
    return ctx;
}

static void ntruplusx_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int ntruplusx_kem_init(void *vctx, int op, void *key,
    ntruplus_unused const OSSL_PARAM params[])
{
    PROV_NTRUPLUSX_KEM_CTX *ctx = vctx;

    if (!ntruplus_prov_is_running())
        return 0;
    ctx->key = key;
    ctx->op = op;
    return 1;
}

static int ntruplusx_kem_encapsulate_init(void *vctx, void *vkey,
    const OSSL_PARAM params[])
{
    NTRUPLUSX_KEY *key = vkey;

    if (!ntruplusx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return ntruplusx_kem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, key, params);
}

static int ntruplusx_kem_decapsulate_init(void *vctx, void *vkey,
    const OSSL_PARAM params[])
{
    NTRUPLUSX_KEY *key = vkey;

    if (!ntruplusx_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return ntruplusx_kem_init(vctx, EVP_PKEY_OP_DECAPSULATE, key, params);
}

static const OSSL_PARAM *ntruplusx_kem_settable_ctx_params(
    ntruplus_unused void *vctx, ntruplus_unused void *provctx)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };

    return params;
}

static int ntruplusx_kem_set_ctx_params(ntruplus_unused void *vctx,
    ntruplus_unused const OSSL_PARAM params[])
{
    return 1;
}

static int ntruplusx_kem_encapsulate(void *vctx, unsigned char *ctext,
    size_t *clen, unsigned char *shsec, size_t *slen)
{
    PROV_NTRUPLUSX_KEM_CTX *pctx = vctx;
    NTRUPLUSX_KEY *key = pctx->key;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *xkey = NULL;
    size_t encap_clen;
    size_t encap_slen;
    uint8_t *cbuf;
    uint8_t *sbuf;
    int ntruplus_slot;
    int ret = 0;

    if (!ntruplusx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto end;
    }
    encap_clen = key->ninfo->ctext_bytes + key->xinfo->pubkey_bytes;
    encap_slen = key->ninfo->shsec_bytes + key->xinfo->shsec_bytes;
    ntruplus_slot = key->xinfo->ntruplus_slot;

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
            "null shared-secret output buffer");
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

    /* NTRU+ encapsulation */
    encap_clen = key->ninfo->ctext_bytes;
    encap_slen = key->ninfo->shsec_bytes;
    cbuf = ctext + ntruplus_slot * key->xinfo->pubkey_bytes;
    sbuf = shsec + ntruplus_slot * key->xinfo->shsec_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->nkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_encapsulate(ctx, cbuf, &encap_clen, sbuf, &encap_slen) <= 0)
        goto end;
    if (encap_clen != key->ninfo->ctext_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s ciphertext output size: %lu",
            key->ninfo->algorithm_name, (unsigned long)encap_clen);
        goto end;
    }
    if (encap_slen != key->ninfo->shsec_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->ninfo->algorithm_name, (unsigned long)encap_slen);
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);

    /*-
     * ECDHE encapsulation
     *
     * Generate own ephemeral private key and add its public key to ctext.
     */
    cbuf = ctext + (1 - ntruplus_slot) * key->ninfo->ctext_bytes;
    encap_clen = key->xinfo->pubkey_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->xkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_keygen(ctx, &xkey) <= 0
        || EVP_PKEY_get_octet_string_param(xkey,
               OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, cbuf, encap_clen,
               &encap_clen) <= 0)
        goto end;
    if (encap_clen != key->xinfo->pubkey_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s public key output size: %lu",
            key->xinfo->algorithm_name, (unsigned long)encap_clen);
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);

    /* Derive the ECDH shared secret */
    encap_slen = key->xinfo->shsec_bytes;
    sbuf = shsec + (1 - ntruplus_slot) * key->ninfo->shsec_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, xkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, key->xkey) <= 0
        || EVP_PKEY_derive(ctx, sbuf, &encap_slen) <= 0)
        goto end;
    if (encap_slen != key->xinfo->shsec_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->xinfo->algorithm_name, (unsigned long)encap_slen);
        goto end;
    }

    ret = 1;
end:
    EVP_PKEY_free(xkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int ntruplusx_kem_decapsulate(void *vctx, uint8_t *shsec, size_t *slen,
    const uint8_t *ctext, size_t clen)
{
    PROV_NTRUPLUSX_KEM_CTX *pctx = vctx;
    NTRUPLUSX_KEY *key = pctx->key;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *xkey = NULL;
    const uint8_t *cbuf;
    uint8_t *sbuf;
    size_t decap_slen;
    size_t decap_clen;
    int ntruplus_slot;
    int ret = 0;

    if (!ntruplusx_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    decap_slen = key->ninfo->shsec_bytes + key->xinfo->shsec_bytes;
    decap_clen = key->ninfo->ctext_bytes + key->xinfo->pubkey_bytes;
    ntruplus_slot = key->xinfo->ntruplus_slot;

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
    if (ctext == NULL || clen != decap_clen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_WRONG_CIPHERTEXT_SIZE,
            "wrong decapsulation input ciphertext size: %lu",
            (unsigned long)clen);
        return 0;
    }

    /* NTRU+ decapsulation */
    decap_clen = key->ninfo->ctext_bytes;
    decap_slen = key->ninfo->shsec_bytes;
    cbuf = ctext + ntruplus_slot * key->xinfo->pubkey_bytes;
    sbuf = shsec + ntruplus_slot * key->xinfo->shsec_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->nkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, sbuf, &decap_slen, cbuf, decap_clen) <= 0)
        goto end;
    if (decap_slen != key->ninfo->shsec_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->ninfo->algorithm_name, (unsigned long)decap_slen);
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);

    /* ECDH decapsulation */
    decap_clen = key->xinfo->pubkey_bytes;
    decap_slen = key->xinfo->shsec_bytes;
    cbuf = ctext + (1 - ntruplus_slot) * key->ninfo->ctext_bytes;
    sbuf = shsec + (1 - ntruplus_slot) * key->ninfo->shsec_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->xkey, key->propq);
    if (ctx == NULL
        || (xkey = EVP_PKEY_new()) == NULL
        || EVP_PKEY_copy_parameters(xkey, key->xkey) <= 0
        || EVP_PKEY_set1_encoded_public_key(xkey, cbuf, decap_clen) <= 0
        || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, xkey) <= 0
        || EVP_PKEY_derive(ctx, sbuf, &decap_slen) <= 0)
        goto end;
    if (decap_slen != key->xinfo->shsec_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->xinfo->algorithm_name, (unsigned long)decap_slen);
        goto end;
    }

    ret = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(xkey);
    return ret;
}

const OSSL_DISPATCH ntruplusx_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (OSSL_FUNC)ntruplusx_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (OSSL_FUNC)ntruplusx_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (OSSL_FUNC)ntruplusx_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (OSSL_FUNC)ntruplusx_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (OSSL_FUNC)ntruplusx_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (OSSL_FUNC)ntruplusx_kem_freectx },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (OSSL_FUNC)ntruplusx_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (OSSL_FUNC)ntruplusx_kem_settable_ctx_params },
    OSSL_DISPATCH_END
};
