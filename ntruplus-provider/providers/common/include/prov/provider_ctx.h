#ifndef NTRUPLUS_PROV_PROVIDER_CTX_H
# define NTRUPLUS_PROV_PROVIDER_CTX_H

# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/crypto.h>
# include <openssl/types.h>

typedef struct prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx; /* For all provider modules */
    OSSL_FUNC_core_get_params_fn *core_get_params;
} PROV_CTX;

/*
 * To be used anywhere the library context needs to be passed, such as to
 * fetching functions.
 */
# define PROV_LIBCTX_OF(provctx) \
    ntruplus_prov_ctx_get0_libctx((provctx))

PROV_CTX *ntruplus_prov_ctx_new(void);
void ntruplus_prov_ctx_free(PROV_CTX *ctx);
void ntruplus_prov_ctx_set0_libctx(PROV_CTX *ctx, OSSL_LIB_CTX *libctx);
void ntruplus_prov_ctx_set0_handle(PROV_CTX *ctx,
                                   const OSSL_CORE_HANDLE *handle);
void ntruplus_prov_ctx_set0_core_get_params(PROV_CTX *ctx,
    OSSL_FUNC_core_get_params_fn *c_get_params);
OSSL_LIB_CTX *ntruplus_prov_ctx_get0_libctx(PROV_CTX *ctx);
const char *
ntruplus_prov_ctx_get_param(PROV_CTX *ctx, const char *name,
                            const char *defval);

#endif
