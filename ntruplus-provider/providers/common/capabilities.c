#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
/* For TLS1_VERSION etc */
#include <openssl/prov_ssl.h>
#include "prov/names.h"
#include "prov/ntruplus.h"
#include "prov/providercommon.h"

typedef struct ntruplus_tls_group_st {
    int is_hybrid;
    int evp_type;
    unsigned int group_id;
} NTRUPLUS_TLS_GROUP;

static const NTRUPLUS_TLS_GROUP ntruplus_tls_groups[] = {
    { 0, EVP_PKEY_NTRUPLUS_768, 0xFE30 },
    { 0, EVP_PKEY_NTRUPLUS_864, 0xFE31 },
    { 0, EVP_PKEY_NTRUPLUS_1152, 0xFE32 },
    { 1, NTRUPLUSX_VINFO_X25519_864, 0xFE33 },
    { 1, NTRUPLUSX_VINFO_SECP256R1_864, 0xFE34 },
    { 1, NTRUPLUSX_VINFO_SECP384R1_1152, 0xFE35 },
    { 0 },
};

static int ntruplus_tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    const NTRUPLUS_TLS_GROUP *group;
    int is_kem = 1;
    int min_tls = TLS1_3_VERSION;
    int max_tls = 0;
    int min_dtls = -1;
    int max_dtls = -1;

    for (group = ntruplus_tls_groups; group->group_id != 0; ++group) {
        const NTRUPLUSX_VINFO *x = NULL;
        const NTRUPLUS_VINFO *v = NULL;
        const char *algorithm_name;
        unsigned int group_id = group->group_id;
        unsigned int secbits;
        OSSL_PARAM params[11];

        if (group->is_hybrid) {
            x = ntruplusx_get_vinfo((unsigned int)group->evp_type);
            v = x == NULL ? NULL : ntruplus_get_vinfo(x->ntruplus_evp_type);
            algorithm_name = x == NULL ? NULL : x->hybrid_name;
        } else {
            v = ntruplus_get_vinfo(group->evp_type);
            algorithm_name = v == NULL ? NULL : v->algorithm_name;
        }

        if (algorithm_name == NULL || v == NULL)
            return 0;

        secbits = (unsigned int)v->secbits;
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_NAME, (char *)algorithm_name, 0);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, "", 0);
        params[2] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_ALG, (char *)algorithm_name, 0);
        params[3] = OSSL_PARAM_construct_uint(
            OSSL_CAPABILITY_TLS_GROUP_ID, &group_id);
        params[4] = OSSL_PARAM_construct_uint(
            OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, &secbits);
        params[5] = OSSL_PARAM_construct_int(
            OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &min_tls);
        params[6] = OSSL_PARAM_construct_int(
            OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &max_tls);
        params[7] = OSSL_PARAM_construct_int(
            OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &min_dtls);
        params[8] = OSSL_PARAM_construct_int(
            OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &max_dtls);
        params[9] = OSSL_PARAM_construct_int(
            OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &is_kem);
        params[10] = OSSL_PARAM_construct_end();

        if (!cb(params, arg))
            return 0;
    }

    return 1;
}

int ntruplus_prov_get_capabilities(void *provctx, const char *capability,
                                   OSSL_CALLBACK *cb, void *arg)
{
    if (provctx == NULL || !ntruplus_prov_is_running())
        return 0;

    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0)
        return ntruplus_tls_group_capability(cb, arg);

    /* We don't support this capability */
    return 0;
}
