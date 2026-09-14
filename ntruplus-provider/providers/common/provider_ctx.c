#include <openssl/params.h>
#include "prov/provider_ctx.h"

PROV_CTX *ntruplus_prov_ctx_new(void)
{
    return OPENSSL_zalloc(sizeof(PROV_CTX));
}

void ntruplus_prov_ctx_free(PROV_CTX *ctx)
{
    OPENSSL_free(ctx);
}

void ntruplus_prov_ctx_set0_libctx(PROV_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    if (ctx != NULL)
        ctx->libctx = libctx;
}

void ntruplus_prov_ctx_set0_handle(PROV_CTX *ctx,
                                   const OSSL_CORE_HANDLE *handle)
{
    if (ctx != NULL)
        ctx->handle = handle;
}

void ntruplus_prov_ctx_set0_core_get_params(PROV_CTX *ctx,
    OSSL_FUNC_core_get_params_fn *c_get_params)
{
    if (ctx != NULL)
        ctx->core_get_params = c_get_params;
}

OSSL_LIB_CTX *ntruplus_prov_ctx_get0_libctx(PROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->libctx;
}

const char *
ntruplus_prov_ctx_get_param(PROV_CTX *ctx, const char *name,
                            const char *defval)
{
    char *val = NULL;
    OSSL_PARAM param[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (ctx == NULL || ctx->handle == NULL || ctx->core_get_params == NULL)
        return defval;

    param[0].key = (char *)name;
    param[0].data_type = OSSL_PARAM_UTF8_PTR;
    param[0].data = (void *)&val;
    param[0].data_size = sizeof(val);
    param[0].return_size = OSSL_PARAM_UNMODIFIED;

    /* Errors are ignored, returning the default value */
    if (ctx->core_get_params(ctx->handle, param)
        && OSSL_PARAM_modified(param)
        && val != NULL)
        return val;
    return defval;
}
