#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/names.h"
#include "prov/ntruplus.h"
#include "prov/providercommon.h"
#include "providers/implementations/keymgmt/ntruplusx_kmgmt.inc"

static OSSL_FUNC_keymgmt_free_fn ntruplusx_key_free;
static OSSL_FUNC_keymgmt_get_params_fn ntruplusx_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ntruplusx_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn ntruplusx_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn ntruplusx_settable_params;
static OSSL_FUNC_keymgmt_has_fn ntruplusx_has;
static OSSL_FUNC_keymgmt_match_fn ntruplusx_match;
static OSSL_FUNC_keymgmt_gen_set_params_fn ntruplusx_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn ntruplusx_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn ntruplusx_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn ntruplusx_gen_cleanup;
static OSSL_FUNC_keymgmt_dup_fn ntruplusx_dup;
static OSSL_FUNC_keymgmt_import_fn ntruplusx_import;
static OSSL_FUNC_keymgmt_import_types_fn ntruplusx_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn ntruplusx_imexport_types;
static OSSL_FUNC_keymgmt_export_fn ntruplusx_export;

static const NTRUPLUSX_VINFO ntruplusx_vinfos[NTRUPLUSX_VINFO_COUNT] = {
    [NTRUPLUSX_VINFO_X25519_864] = {
        NTRUPLUSX_NAMES_X25519_864,
        "X25519",
        NULL,
        32,
        32,
        32,
        0,
        EVP_PKEY_NTRUPLUS_864
    },
    [NTRUPLUSX_VINFO_SECP256R1_864] = {
        NTRUPLUSX_NAMES_SECP256R1_864,
        "EC",
        "P-256",
        65,
        32,
        32,
        1,
        EVP_PKEY_NTRUPLUS_864
    },
    [NTRUPLUSX_VINFO_SECP384R1_1152] = {
        NTRUPLUSX_NAMES_SECP384R1_1152,
        "EC",
        "P-384",
        97,
        48,
        48,
        1,
        EVP_PKEY_NTRUPLUS_1152
    }
};

typedef struct ntruplusx_gen_ctx_st {
    PROV_CTX *provctx;
    char *propq;
    int selection;
    unsigned int evp_type;
} PROV_NTRUPLUSX_GEN_CTX;

typedef struct ntruplusx_export_arg_st {
    const char *algorithm_name;
    uint8_t *pubenc;
    uint8_t *prvenc;
    size_t puboff;
    size_t prvoff;
    size_t publen;
    size_t prvlen;
    int pubcount;
    int prvcount;
} NTRUPLUSX_EXPORT_ARG;

static const int minimal_selection =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

const NTRUPLUSX_VINFO *ntruplusx_get_vinfo(unsigned int evp_type)
{
    const NTRUPLUSX_VINFO *v = NULL;

    if (evp_type < NTRUPLUSX_VINFO_COUNT)
        v = &ntruplusx_vinfos[evp_type];
    return v != NULL && v->hybrid_name != NULL ? v : NULL;
}

/* Takes ownership of propq. */
static NTRUPLUSX_KEY *ntruplusx_key_new(PROV_CTX *provctx,
                                        unsigned int evp_type,
                                        char *propq)
{
    NTRUPLUSX_KEY *key = NULL;
    const NTRUPLUSX_VINFO *xinfo = ntruplusx_get_vinfo(evp_type);
    const NTRUPLUS_VINFO *ninfo;

    if (!ntruplus_prov_is_running() || provctx == NULL || xinfo == NULL)
        goto err;
    ninfo = ntruplus_get_vinfo(xinfo->ntruplus_evp_type);
    if (ninfo == NULL || (key = OPENSSL_malloc(sizeof(*key))) == NULL)
        goto err;

    key->libctx = PROV_LIBCTX_OF(provctx);
    key->propq = propq;
    key->ninfo = ninfo;
    key->xinfo = xinfo;
    key->nkey = NULL;
    key->xkey = NULL;
    key->state = NTRUPLUSX_HAVE_NOKEYS;
    return key;

err:
    OPENSSL_free(propq);
    return NULL;
}

static void ntruplusx_key_free(void *vkey)
{
    NTRUPLUSX_KEY *key = vkey;

    if (key == NULL)
        return;
    OPENSSL_free(key->propq);
    EVP_PKEY_free(key->nkey);
    EVP_PKEY_free(key->xkey);
    OPENSSL_free(key);
}

static int ntruplusx_keypair_selection(int selection)
{
    return selection & OSSL_KEYMGMT_SELECT_KEYPAIR;
}

static int ntruplusx_has(const void *vkey, int selection)
{
    const NTRUPLUSX_KEY *key = vkey;

    if (!ntruplus_prov_is_running() || key == NULL)
        return 0;

    switch (ntruplusx_keypair_selection(selection)) {
    case 0:
        return 1;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return ntruplusx_kem_have_pubkey(key);
    default:
        return ntruplusx_kem_have_prvkey(key);
    }
}

static int ntruplusx_match(const void *vkey1, const void *vkey2, int selection)
{
    const NTRUPLUSX_KEY *key1 = vkey1;
    const NTRUPLUSX_KEY *key2 = vkey2;
    int have_pub1, have_pub2;

    if (!ntruplus_prov_is_running() || key1 == NULL || key2 == NULL)
        return 0;
    if (key1->xinfo != key2->xinfo)
        return 0;
    if (ntruplusx_keypair_selection(selection) == 0)
        return 1;

    have_pub1 = ntruplusx_kem_have_pubkey(key1);
    have_pub2 = ntruplusx_kem_have_pubkey(key2);
    if (!have_pub1 && !have_pub2
        && !ntruplusx_kem_have_prvkey(key1)
        && !ntruplusx_kem_have_prvkey(key2))
        return 1;
    if (key1->nkey == NULL || key1->xkey == NULL
        || key2->nkey == NULL || key2->xkey == NULL)
        return 0;

    return EVP_PKEY_eq(key1->nkey, key2->nkey) == 1
        && EVP_PKEY_eq(key1->xkey, key2->xkey) == 1;
}

static int ntruplusx_export_sub_cb(const OSSL_PARAM *params, void *arg)
{
    NTRUPLUSX_EXPORT_ARG *xarg = arg;
    struct ntruplusx_key_params_st p;
    size_t len = 0;

    if (!ntruplusx_key_params_decoder(params, &p))
        return 0;

    if (xarg->pubenc != NULL && p.pubkey != NULL) {
        void *pub = xarg->pubenc + xarg->puboff;

        if (!OSSL_PARAM_get_octet_string(p.pubkey, &pub, xarg->publen, &len)
            || len != xarg->publen) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                           "unexpected %s public key length",
                           xarg->algorithm_name);
            return 0;
        }
        xarg->pubcount++;
    }

    if (xarg->prvenc != NULL && p.privkey != NULL) {
        void *prv = xarg->prvenc + xarg->prvoff;
        BIGNUM *bn = NULL;
        int bnlen;

        if (p.privkey->data_type == OSSL_PARAM_OCTET_STRING) {
            if (!OSSL_PARAM_get_octet_string(p.privkey, &prv, xarg->prvlen,
                                             &len)
                || len != xarg->prvlen) {
                ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                               "unexpected %s private key length",
                               xarg->algorithm_name);
                return 0;
            }
        } else if (p.privkey->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            if (!OSSL_PARAM_get_BN(p.privkey, &bn)
                || (bnlen = BN_bn2nativepad(bn, prv, xarg->prvlen)) < 0
                || (size_t)bnlen != xarg->prvlen) {
                BN_clear_free(bn);
                ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                               "unexpected %s private key length",
                               xarg->algorithm_name);
                return 0;
            }
            BN_clear_free(bn);
        } else {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                           "unexpected %s private key length",
                           xarg->algorithm_name);
            return 0;
        }
        xarg->prvcount++;
    }

    return 1;
}

static int ntruplusx_export_sub(NTRUPLUSX_EXPORT_ARG *xarg,
                                int selection, NTRUPLUSX_KEY *key)
{
    size_t n_pub = key->ninfo->pubkey_bytes;
    size_t n_prv = key->ninfo->prvkey_bytes;
    size_t x_pub = key->xinfo->pubkey_bytes;
    size_t x_prv = key->xinfo->prvkey_bytes;
    int n_slot = key->xinfo->ntruplus_slot;
    int n_selection = selection;
    int x_selection = selection;

    if (key->xinfo->group_name != NULL) {
        x_selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            x_selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }

    xarg->pubcount = 0;
    xarg->prvcount = 0;

    xarg->algorithm_name = key->ninfo->algorithm_name;
    xarg->puboff = n_slot * x_pub;
    xarg->prvoff = n_slot * x_prv;
    xarg->publen = n_pub;
    xarg->prvlen = n_prv;
    if (!EVP_PKEY_export(key->nkey, n_selection,
                         ntruplusx_export_sub_cb, xarg))
        return 0;

    xarg->algorithm_name = key->xinfo->algorithm_name;
    xarg->puboff = (1 - n_slot) * n_pub;
    xarg->prvoff = (1 - n_slot) * n_prv;
    xarg->publen = x_pub;
    xarg->prvlen = x_prv;
    return EVP_PKEY_export(key->xkey, x_selection,
                           ntruplusx_export_sub_cb, xarg);
}

static int ntruplusx_export(void *vkey, int selection,
                            OSSL_CALLBACK *param_cb, void *cbarg)
{
    NTRUPLUSX_KEY *key = vkey;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    NTRUPLUSX_EXPORT_ARG xarg;
    size_t publen, prvlen;
    int ret = 0;

    if (!ntruplus_prov_is_running() || key == NULL
        || ntruplusx_keypair_selection(selection) == 0)
        return 0;
    if (((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
         && !ntruplusx_kem_have_pubkey(key))
        || ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && !ntruplusx_kem_have_prvkey(key))) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    publen = key->ninfo->pubkey_bytes + key->xinfo->pubkey_bytes;
    prvlen = key->ninfo->prvkey_bytes + key->xinfo->prvkey_bytes;
    memset(&xarg, 0, sizeof(xarg));

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        xarg.pubenc = OPENSSL_malloc(publen);
        if (xarg.pubenc == NULL)
            goto end;
    }
    if (ntruplusx_kem_have_prvkey(key)
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        xarg.prvenc = OPENSSL_secure_zalloc(prvlen);
        if (xarg.prvenc == NULL)
            goto end;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL || !ntruplusx_export_sub(&xarg, selection, key))
        goto end;

    if (xarg.pubenc != NULL && xarg.pubcount == 2
        && !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             xarg.pubenc, publen))
        goto end;
    if (xarg.prvenc != NULL && xarg.prvcount == 2
        && !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             xarg.prvenc, prvlen))
        goto end;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto end;

    ret = param_cb(params, cbarg);

end:
    OSSL_PARAM_clear_free(params);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_free(xarg.pubenc);
    OPENSSL_secure_clear_free(xarg.prvenc, prvlen);
    return ret;
}

static const OSSL_PARAM *ntruplusx_imexport_types(int selection)
{
    if (ntruplusx_keypair_selection(selection) == 0)
        return NULL;
    return ntruplusx_key_params_list;
}

static int ntruplusx_load_component(OSSL_LIB_CTX *libctx, const char *propq,
                                    const char *alg, const char *group,
                                    const char *pname,
                                    int selection, const uint8_t *in,
                                    size_t inlen, EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    size_t n = 0;
    int ret = 0;

    if (group != NULL && strcmp(pname, OSSL_PKEY_PARAM_PRIV_KEY) == 0)
        params[n++] = OSSL_PARAM_construct_BN((char *)pname,
                                              (unsigned char *)in, inlen);
    else
        params[n++] = OSSL_PARAM_construct_octet_string((char *)pname,
                                                        (void *)in, inlen);
    if (group != NULL)
        params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                       (char *)group, 0);
    params[n] = OSSL_PARAM_construct_end();

    if ((ctx = EVP_PKEY_CTX_new_from_name(libctx, alg, propq)) == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, out, selection, params) <= 0)
        goto end;
    ret = 1;

end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int ntruplusx_pairwise_check_component(OSSL_LIB_CTX *libctx,
                                              const char *propq,
                                              EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret;

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)) == NULL)
        return 0;
    ret = EVP_PKEY_pairwise_check(ctx) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int ntruplusx_set_public_component(NTRUPLUSX_KEY *key, EVP_PKEY *pkey,
                                          const uint8_t *pub,
                                          size_t publen)
{
    unsigned char *actual = NULL;
    size_t actuallen;
    int ret;

    actuallen = EVP_PKEY_get1_encoded_public_key(pkey, &actual);
    if (actuallen != 0 && actual != NULL) {
        ret = actuallen == publen && CRYPTO_memcmp(actual, pub, publen) == 0;
        OPENSSL_free(actual);
        return ret;
    }
    ERR_clear_error();

    return EVP_PKEY_set1_encoded_public_key(pkey, pub, publen) > 0
        && ntruplusx_pairwise_check_component(key->libctx, key->propq, pkey);
}

static int ntruplusx_set_public_components(NTRUPLUSX_KEY *key,
                                           const uint8_t *pubenc,
                                           size_t publen)
{
    EVP_PKEY *nkey = NULL;
    EVP_PKEY *xkey = NULL;
    int n_slot = key->xinfo->ntruplus_slot;
    size_t npub = key->ninfo->pubkey_bytes;
    size_t xpub = key->xinfo->pubkey_bytes;
    int ret = 0;

    if (pubenc == NULL || publen != npub + xpub
        || key->nkey == NULL || key->xkey == NULL)
        return 0;

    nkey = EVP_PKEY_dup(key->nkey);
    xkey = EVP_PKEY_dup(key->xkey);
    if (nkey == NULL || xkey == NULL)
        goto end;

    if (!ntruplusx_set_public_component(key, nkey, pubenc + n_slot * xpub,
                                        npub)
        || !ntruplusx_set_public_component(key, xkey,
                                           pubenc + (1 - n_slot) * npub,
                                           xpub))
        goto end;

    EVP_PKEY_free(key->nkey);
    EVP_PKEY_free(key->xkey);
    key->nkey = nkey;
    key->xkey = xkey;
    nkey = xkey = NULL;
    key->state |= NTRUPLUSX_HAVE_PUBKEY;
    ret = 1;

end:
    EVP_PKEY_free(nkey);
    EVP_PKEY_free(xkey);
    return ret;
}

static int ntruplusx_load_keys(NTRUPLUSX_KEY *key,
                               const uint8_t *pubenc, size_t publen,
                               const uint8_t *prvenc, size_t prvlen)
{
    const uint8_t *nin, *xin;
    const char *pname;
    int selection;
    int n_slot = key->xinfo->ntruplus_slot;
    size_t nlen, xlen;
    size_t npub = key->ninfo->pubkey_bytes;
    size_t nprv = key->ninfo->prvkey_bytes;
    size_t xpub = key->xinfo->pubkey_bytes;
    size_t xprv = key->xinfo->prvkey_bytes;

    if (prvlen != 0) {
        nin = prvenc + n_slot * xprv;
        xin = prvenc + (1 - n_slot) * nprv;
        nlen = nprv;
        xlen = xprv;
        pname = OSSL_PKEY_PARAM_PRIV_KEY;
        selection = minimal_selection;
    } else {
        nin = pubenc + n_slot * xpub;
        xin = pubenc + (1 - n_slot) * npub;
        nlen = npub;
        xlen = xpub;
        pname = OSSL_PKEY_PARAM_PUB_KEY;
        selection = key->xinfo->group_name != NULL
            ? minimal_selection
            : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }

    if (!ntruplusx_load_component(key->libctx, key->propq,
                                  key->ninfo->algorithm_name, NULL, pname,
                                  selection, nin, nlen, &key->nkey)
        || !ntruplusx_load_component(key->libctx, key->propq,
                                     key->xinfo->algorithm_name,
                                     key->xinfo->group_name, pname,
                                     selection, xin, xlen, &key->xkey))
        goto err;

    key->state = prvlen != 0 ? NTRUPLUSX_HAVE_PRVKEY
                             : NTRUPLUSX_HAVE_PUBKEY;
    /* NTRU+ private material does not imply public material. */
    if (prvlen != 0 && publen != 0
        && !ntruplusx_set_public_components(key, pubenc, publen))
        goto err;
    return 1;

err:
    EVP_PKEY_free(key->nkey);
    EVP_PKEY_free(key->xkey);
    key->nkey = key->xkey = NULL;
    key->state = NTRUPLUSX_HAVE_NOKEYS;
    return 0;
}

static int ntruplusx_key_fromdata(NTRUPLUSX_KEY *key,
                                  const OSSL_PARAM params[],
                                  int include_private)
{
    struct ntruplusx_key_params_st p;
    const void *pubenc = NULL, *prvenc = NULL;
    size_t publen = 0, prvlen = 0;
    size_t expected_publen, expected_prvlen;

    if (key == NULL
        || ntruplusx_kem_have_pubkey(key)
        || ntruplusx_kem_have_prvkey(key)
        || !ntruplusx_key_params_decoder(params, &p))
        return 0;

    expected_publen = key->ninfo->pubkey_bytes + key->xinfo->pubkey_bytes;
    expected_prvlen = key->ninfo->prvkey_bytes + key->xinfo->prvkey_bytes;

    if (p.pubkey != NULL
        && !OSSL_PARAM_get_octet_string_ptr(p.pubkey, &pubenc, &publen))
        return 0;
    if (include_private && p.privkey != NULL
        && !OSSL_PARAM_get_octet_string_ptr(p.privkey, &prvenc, &prvlen))
        return 0;
    if (publen == 0 && prvlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if ((publen != 0 && publen != expected_publen)
        || (prvlen != 0 && prvlen != expected_prvlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    return ntruplusx_load_keys(key, pubenc, publen, prvenc, prvlen);
}

static int ntruplusx_import(void *vkey, int selection,
                            const OSSL_PARAM params[])
{
    if (!ntruplus_prov_is_running() || vkey == NULL
        || ntruplusx_keypair_selection(selection) == 0)
        return 0;
    return ntruplusx_key_fromdata(vkey, params,
                                  (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
}

static const OSSL_PARAM *ntruplusx_gettable_params(
    ntruplus_unused void *provctx)
{
    return ntruplusx_get_params_list;
}

static int ntruplusx_get_component_params(NTRUPLUSX_EXPORT_ARG *xarg,
                                          int selection, NTRUPLUSX_KEY *key)
{
    if (!ntruplusx_export_sub(xarg, selection, key))
        return 0;
    if (((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
         && xarg->pubcount != 2)
        || ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && xarg->prvcount != 2))
        return 0;
    return 1;
}

static int ntruplusx_get_octet_param(NTRUPLUSX_KEY *key, OSSL_PARAM *p,
                                     int selection, size_t len)
{
    NTRUPLUSX_EXPORT_ARG xarg;

    if (p == NULL)
        return 1;
    if (p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;
    p->return_size = len;
    if (p->data == NULL)
        return 1;
    if (p->data_size < len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    memset(&xarg, 0, sizeof(xarg));
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        xarg.pubenc = p->data;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        xarg.prvenc = p->data;
    return ntruplusx_get_component_params(&xarg, selection, key);
}

static int ntruplusx_get_params(void *vkey, OSSL_PARAM params[])
{
    NTRUPLUSX_KEY *key = vkey;
    struct ntruplusx_get_params_st p;
    size_t publen, prvlen, ctlen;

    if (!ntruplus_prov_is_running() || key == NULL
        || !ntruplusx_get_params_decoder(params, &p))
        return 0;

    publen = key->ninfo->pubkey_bytes + key->xinfo->pubkey_bytes;
    prvlen = key->ninfo->prvkey_bytes + key->xinfo->prvkey_bytes;
    ctlen = key->ninfo->ctext_bytes + key->xinfo->pubkey_bytes;

    if (p.bits != NULL && !OSSL_PARAM_set_int(p.bits, key->ninfo->n))
        return 0;
    if (p.secbits != NULL
        && !OSSL_PARAM_set_int(p.secbits, key->ninfo->secbits))
        return 0;
    if (p.maxsize != NULL && !OSSL_PARAM_set_size_t(p.maxsize, ctlen))
        return 0;
#ifdef OSSL_PKEY_PARAM_SECURITY_CATEGORY
    if (p.seccat != NULL
        && !OSSL_PARAM_set_int(p.seccat, key->ninfo->security_category))
        return 0;
#endif

    if (ntruplusx_kem_have_pubkey(key)
        && !ntruplusx_get_octet_param(key, p.pub,
                                      OSSL_KEYMGMT_SELECT_PUBLIC_KEY, publen))
        return 0;
    if (ntruplusx_kem_have_prvkey(key)
        && !ntruplusx_get_octet_param(key, p.priv,
                                      OSSL_KEYMGMT_SELECT_PRIVATE_KEY, prvlen))
        return 0;
    return 1;
}

static const OSSL_PARAM *ntruplusx_settable_params(
    ntruplus_unused void *provctx)
{
    return ntruplusx_set_params_list;
}

static int ntruplusx_set_params(void *vkey, const OSSL_PARAM params[])
{
    NTRUPLUSX_KEY *key = vkey;
    struct ntruplusx_set_params_st p;
    const void *pubenc = NULL;
    size_t publen = 0;

    if (key == NULL || !ntruplusx_set_params_decoder(params, &p))
        return 0;

    if (p.propq != NULL) {
        OPENSSL_free(key->propq);
        key->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p.propq, &key->propq, 0))
            return 0;
    }

    if (p.pub == NULL)
        return 1;
    if (ntruplusx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return 0;
    }
    if (!OSSL_PARAM_get_octet_string_ptr(p.pub, &pubenc, &publen))
        return 0;
    if (publen != key->ninfo->pubkey_bytes + key->xinfo->pubkey_bytes) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    if (ntruplusx_kem_have_prvkey(key))
        return ntruplusx_set_public_components(key, pubenc, publen);
    return ntruplusx_load_keys(key, pubenc, publen, NULL, 0);
}

static int ntruplusx_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    PROV_NTRUPLUSX_GEN_CTX *gctx = vgctx;
    struct ntruplusx_gen_set_params_st p;

    if (gctx == NULL || !ntruplusx_gen_set_params_decoder(params, &p))
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

static void *ntruplusx_gen_init_common(void *provctx, unsigned int evp_type,
                                       int selection,
                                       const OSSL_PARAM params[])
{
    PROV_NTRUPLUSX_GEN_CTX *gctx = NULL;

    if (!ntruplus_prov_is_running()
        || (selection & minimal_selection) == 0
        || (gctx = OPENSSL_zalloc(sizeof(*gctx))) == NULL)
        return NULL;

    gctx->provctx = provctx;
    gctx->evp_type = evp_type;
    gctx->selection = selection;
    if (ntruplusx_gen_set_params(gctx, params))
        return gctx;

    ntruplusx_gen_cleanup(gctx);
    return NULL;
}

static const OSSL_PARAM *ntruplusx_gen_settable_params(
    ntruplus_unused void *vgctx, ntruplus_unused void *provctx)
{
    return ntruplusx_gen_set_params_list;
}

static void *ntruplusx_gen(void *vgctx, ntruplus_unused OSSL_CALLBACK *osslcb,
                           ntruplus_unused void *cbarg)
{
    PROV_NTRUPLUSX_GEN_CTX *gctx = vgctx;
    NTRUPLUSX_KEY *key;
    char *propq;

    if (gctx == NULL
        || ntruplusx_keypair_selection(gctx->selection)
           == OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return NULL;

    propq = gctx->propq;
    gctx->propq = NULL;
    key = ntruplusx_key_new(gctx->provctx, gctx->evp_type, propq);
    if (key == NULL)
        return NULL;
    if (ntruplusx_keypair_selection(gctx->selection) == 0)
        return key;

    key->nkey = EVP_PKEY_Q_keygen(key->libctx, key->propq,
                                  key->ninfo->algorithm_name);
    key->xkey = EVP_PKEY_Q_keygen(key->libctx, key->propq,
                                  key->xinfo->algorithm_name,
                                  key->xinfo->group_name);
    if (key->nkey != NULL && key->xkey != NULL) {
        key->state = NTRUPLUSX_HAVE_PUBKEY | NTRUPLUSX_HAVE_PRVKEY;
        return key;
    }

    ntruplusx_key_free(key);
    return NULL;
}

static void ntruplusx_gen_cleanup(void *vgctx)
{
    PROV_NTRUPLUSX_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static void *ntruplusx_dup(const void *vkey, int selection)
{
    const NTRUPLUSX_KEY *key = vkey;
    NTRUPLUSX_KEY *ret;

    if (!ntruplus_prov_is_running() || key == NULL)
        return NULL;
    ret = OPENSSL_memdup(key, sizeof(*ret));
    if (ret == NULL)
        return NULL;
    ret->propq = NULL;
    ret->nkey = ret->xkey = NULL;

    if (key->propq != NULL
        && (ret->propq = OPENSSL_strdup(key->propq)) == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    if (key->nkey == NULL) {
        if (key->xkey == NULL)
            return ret;
        OPENSSL_free(ret->propq);
        OPENSSL_free(ret);
        return NULL;
    }

    switch (ntruplusx_keypair_selection(selection)) {
    case 0:
        ret->state = NTRUPLUSX_HAVE_NOKEYS;
        return ret;
    case OSSL_KEYMGMT_SELECT_KEYPAIR:
        ret->nkey = EVP_PKEY_dup(key->nkey);
        ret->xkey = EVP_PKEY_dup(key->xkey);
        if (ret->nkey != NULL && ret->xkey != NULL)
            return ret;
        break;
    default:
        ERR_raise_data(ERR_LIB_PROV, PROV_R_UNSUPPORTED_SELECTION,
            "duplication of partial key material not supported");
        break;
    }

    ntruplusx_key_free(ret);
    return NULL;
}

#define NTRUPLUSX_DISPATCH(suffix, evp_type)                                     \
    static OSSL_FUNC_keymgmt_new_fn ntruplusx_##suffix##_new;                    \
    static void *ntruplusx_##suffix##_new(void *provctx)                         \
    {                                                                            \
        return ntruplusx_key_new(provctx, evp_type, NULL);                       \
    }                                                                            \
    static OSSL_FUNC_keymgmt_gen_init_fn ntruplusx_##suffix##_gen_init;          \
    static void *ntruplusx_##suffix##_gen_init(void *provctx, int selection,     \
                                               const OSSL_PARAM params[])        \
    {                                                                            \
        return ntruplusx_gen_init_common(provctx, evp_type, selection, params);  \
    }                                                                            \
    const OSSL_DISPATCH ntruplusx_##suffix##_keymgmt_functions[] = {             \
        { OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)ntruplusx_##suffix##_new },          \
        { OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)ntruplusx_key_free },               \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC)ntruplusx_get_params },       \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
          (OSSL_FUNC)ntruplusx_gettable_params },                               \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (OSSL_FUNC)ntruplusx_set_params },       \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                    \
          (OSSL_FUNC)ntruplusx_settable_params },                               \
        { OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)ntruplusx_has },                     \
        { OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)ntruplusx_match },                 \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (OSSL_FUNC)ntruplusx_##suffix##_gen_init },\
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (OSSL_FUNC)ntruplusx_gen_set_params },\
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                \
          (OSSL_FUNC)ntruplusx_gen_settable_params },                            \
        { OSSL_FUNC_KEYMGMT_GEN, (OSSL_FUNC)ntruplusx_gen },                     \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (OSSL_FUNC)ntruplusx_gen_cleanup },     \
        { OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)ntruplusx_dup },                     \
        { OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)ntruplusx_import },               \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)ntruplusx_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)ntruplusx_export },               \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)ntruplusx_imexport_types }, \
        OSSL_DISPATCH_END                                                        \
    }

NTRUPLUSX_DISPATCH(x25519_864, NTRUPLUSX_VINFO_X25519_864);
NTRUPLUSX_DISPATCH(secp256r1_864, NTRUPLUSX_VINFO_SECP256R1_864);
NTRUPLUSX_DISPATCH(secp384r1_1152, NTRUPLUSX_VINFO_SECP384R1_1152);

#undef NTRUPLUSX_DISPATCH
