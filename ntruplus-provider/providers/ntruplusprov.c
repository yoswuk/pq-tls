#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn ntruplus_gettable_params;
static OSSL_FUNC_provider_get_params_fn ntruplus_get_params;
static OSSL_FUNC_provider_query_operation_fn ntruplus_query;
static OSSL_FUNC_provider_teardown_fn ntruplus_teardown;

#if defined(_WIN32)
# define NTRUPLUS_PROVIDER_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
# define NTRUPLUS_PROVIDER_EXPORT __attribute__((visibility("default")))
#else
# define NTRUPLUS_PROVIDER_EXPORT
#endif

/* Parameters we provide to the core */
static const OSSL_PARAM ntruplus_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ntruplus_gettable_params(ntruplus_unused void *vctx)
{
    return ntruplus_param_types;
}

static int ntruplus_get_params(ntruplus_unused void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int status = ntruplus_prov_is_running();

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, NTRUPLUS_PROVIDER_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, NTRUPLUS_PROVIDER_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, NTRUPLUS_PROVIDER_BUILDINFO))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, status))
        return 0;
    return 1;
}

#define ALG(NAMES, FUNC) { NAMES, "provider=ntruplus", FUNC, NULL }

static const OSSL_ALGORITHM ntruplus_keymgmt[] = {
    ALG(NTRUPLUS_NAMES_768, ntruplus768_keymgmt_functions),
    ALG(NTRUPLUS_NAMES_864, ntruplus864_keymgmt_functions),
    ALG(NTRUPLUS_NAMES_1152, ntruplus1152_keymgmt_functions),
    ALG(NTRUPLUSX_NAMES_X25519_864, ntruplusx_x25519_864_keymgmt_functions),
    ALG(NTRUPLUSX_NAMES_SECP256R1_864,
        ntruplusx_secp256r1_864_keymgmt_functions),
    ALG(NTRUPLUSX_NAMES_SECP384R1_1152,
        ntruplusx_secp384r1_1152_keymgmt_functions),
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ntruplus_asym_kem[] = {
    ALG(NTRUPLUS_NAMES_768, ntruplus_kem_functions),
    ALG(NTRUPLUS_NAMES_864, ntruplus_kem_functions),
    ALG(NTRUPLUS_NAMES_1152, ntruplus_kem_functions),
    ALG(NTRUPLUSX_NAMES_X25519_864, ntruplusx_kem_functions),
    ALG(NTRUPLUSX_NAMES_SECP256R1_864, ntruplusx_kem_functions),
    ALG(NTRUPLUSX_NAMES_SECP384R1_1152, ntruplusx_kem_functions),
    { NULL, NULL, NULL, NULL }
};

#undef ALG

static void ntruplus_teardown(void *vctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(vctx));
    ntruplus_prov_ctx_free(vctx);
}

static const OSSL_ALGORITHM *ntruplus_query(ntruplus_unused void *vctx,
                                            int operation_id, int *no_cache)
{
    *no_cache = 0;

    if (!ntruplus_prov_is_running())
        return NULL;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return ntruplus_keymgmt;
    case OSSL_OP_KEM:
        return ntruplus_asym_kem;
    }
    return NULL;
}

static const OSSL_DISPATCH ntruplus_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ntruplus_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        (void (*)(void))ntruplus_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ntruplus_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ntruplus_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))ntruplus_prov_get_capabilities },
    OSSL_DISPATCH_END
};

NTRUPLUS_PROVIDER_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                                                const OSSL_DISPATCH *in,
                                                const OSSL_DISPATCH **out,
                                                void **provctx)
{
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
    const OSSL_DISPATCH *p;
    OSSL_LIB_CTX *libctx = NULL;

    for (p = in; p->function_id != 0; p++) {
        switch (p->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(p);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if ((*provctx = ntruplus_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new_child(handle, in)) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        ntruplus_teardown(*provctx);
        *provctx = NULL;
        return 0;
    }

    ntruplus_prov_ctx_set0_libctx(*provctx, libctx);
    ntruplus_prov_ctx_set0_handle(*provctx, handle);
    ntruplus_prov_ctx_set0_core_get_params(*provctx, c_get_params);

    *out = ntruplus_dispatch_table;
    return 1;
}

#undef NTRUPLUS_PROVIDER_EXPORT
