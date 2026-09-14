#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "crypto/ntruplus.h"
#include "prov/names.h"

#define NTRUPLUS_TEST_NELEM(a) (sizeof(a) / sizeof((a)[0]))

typedef struct ntruplus_test_vinfo_st {
    const char *algorithm_name;
    size_t pubkey_bytes;
    size_t ctext_bytes;
    size_t shsec_bytes;
    size_t encap_seed_bytes;
} NTRUPLUS_TEST_VINFO;

static const NTRUPLUS_TEST_VINFO ntruplus_vinfos[] = {
    { "ntruplus768", 1152, 1152, 32, 96 },
    { "ntruplus864", 1296, 1296, 32, 108 },
    { "ntruplus1152", 1728, 1728, 32, 144 },
};

static const NTRUPLUS_TEST_VINFO ntruplus_alias_vinfos[] = {
    { "NTRUPlus768", 1152, 1152, 32, 96 },
    { "NTRUPLUS768", 1152, 1152, 32, 96 },
    { "NTRUPlus864", 1296, 1296, 32, 108 },
    { "NTRUPLUS864", 1296, 1296, 32, 108 },
    { "NTRUPlus1152", 1728, 1728, 32, 144 },
    { "NTRUPLUS1152", 1728, 1728, 32, 144 },
};

static const char *ntruplusx_algs[] = {
    NTRUPLUSX_NAMES_X25519_864,
    NTRUPLUSX_NAMES_SECP256R1_864,
    NTRUPLUSX_NAMES_SECP384R1_1152,
};

static int test_full = 0;

static int fail(const char *alg, const char *msg)
{
    fprintf(stderr, "%s: %s\n", alg, msg);
    return 0;
}

static int full_test_enabled(void)
{
    const char *full = getenv("NTRUPLUS_FULL_TEST");

    return test_full
        || (full != NULL && full[0] != '\0' && strcmp(full, "0") != 0);
}

static int keygen_with_name(const char *name, EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    int ret = 0;

    *out = NULL;
    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, name,
                                          "provider=ntruplus")) == NULL
        || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_keygen(ctx, &key) <= 0)
        goto end;

    *out = key;
    key = NULL;
    ret = 1;

end:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int public_key_from_encoded(EVP_PKEY *src, const unsigned char *pub,
                                   size_t publen, EVP_PKEY **out)
{
    EVP_PKEY *key = NULL;
    int ret = 0;

    *out = NULL;
    if ((key = EVP_PKEY_new()) == NULL)
        goto end;
    if (EVP_PKEY_copy_parameters(key, src) <= 0)
        goto end;
    if (EVP_PKEY_eq(src, key) == 1)
        goto end;
    if (EVP_PKEY_set1_encoded_public_key(key, pub, publen) <= 0)
        goto end;
    if (EVP_PKEY_eq(src, key) != 1 || EVP_PKEY_eq(key, src) != 1)
        goto end;

    *out = key;
    key = NULL;
    ret = 1;

end:
    EVP_PKEY_free(key);
    return ret;
}

static int public_key_from_data(const char *name, EVP_PKEY *src,
                                EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    *out = NULL;
    if (EVP_PKEY_todata(src, EVP_PKEY_PUBLIC_KEY, &params) <= 0)
        goto end;
    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, name,
                                          "provider=ntruplus")) == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        goto end;
    if (EVP_PKEY_eq(src, key) != 1 || EVP_PKEY_eq(key, src) != 1)
        goto end;

    *out = key;
    key = NULL;
    ret = 1;

end:
    OSSL_PARAM_free(params);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int private_key_from_data(const char *name, EVP_PKEY *src,
                                 EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    *out = NULL;
    if (EVP_PKEY_todata(src, EVP_PKEY_PRIVATE_KEY, &params) <= 0)
        goto end;
    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, name,
                                          "provider=ntruplus")) == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PRIVATE_KEY, params) <= 0)
        goto end;
    if (EVP_PKEY_eq(src, key) != 1 || EVP_PKEY_eq(key, src) != 1)
        goto end;

    *out = key;
    key = NULL;
    ret = 1;

end:
    OSSL_PARAM_free(params);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int encapsulate(EVP_PKEY *key, const unsigned char *ikme,
                       size_t ikmelen, unsigned char **ct, size_t *ctlen,
                       unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2], *p = NULL;
    unsigned char *lct = NULL;
    unsigned char *lss = NULL;
    size_t lctlen = 0, lsslen = 0;
    int ret = 0;

    *ct = NULL;
    *ss = NULL;

    if (ikme != NULL) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
                                                       (void *)ikme, ikmelen);
        params[1] = OSSL_PARAM_construct_end();
        p = params;
    }

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) == NULL
        || EVP_PKEY_encapsulate_init(ctx, p) <= 0
        || EVP_PKEY_encapsulate(ctx, NULL, &lctlen, NULL, &lsslen) <= 0)
        goto end;

    if ((lct = OPENSSL_zalloc(lctlen)) == NULL
        || (lss = OPENSSL_zalloc(lsslen)) == NULL)
        goto end;

    if (EVP_PKEY_encapsulate(ctx, lct, &lctlen, lss, &lsslen) <= 0)
        goto end;

    *ct = lct;
    *ctlen = lctlen;
    *ss = lss;
    *sslen = lsslen;
    lct = NULL;
    lss = NULL;
    ret = 1;

end:
    OPENSSL_free(lct);
    OPENSSL_clear_free(lss, lsslen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int decapsulate(EVP_PKEY *key, const unsigned char *ct, size_t ctlen,
                       unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *lss = NULL;
    size_t lsslen = 0;
    int ret = 0;

    *ss = NULL;
    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) == NULL
        || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, NULL, &lsslen, ct, ctlen) <= 0)
        goto end;

    if ((lss = OPENSSL_zalloc(lsslen)) == NULL)
        goto end;
    if (EVP_PKEY_decapsulate(ctx, lss, &lsslen, ct, ctlen) <= 0)
        goto end;

    *ss = lss;
    *sslen = lsslen;
    lss = NULL;
    ret = 1;

end:
    OPENSSL_clear_free(lss, lsslen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int shared_secret_is_nonzero(const unsigned char *ss, size_t sslen)
{
    unsigned char acc = 0;
    size_t i;

    for (i = 0; i < sslen; i++)
        acc |= ss[i];
    return acc != 0;
}

static int bad_ciphertext_length_rejected(EVP_PKEY *key,
                                          const unsigned char *ct,
                                          size_t ctlen, size_t sslen)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ss = NULL;
    int ret = 0;

    if (ctlen == 0)
        return 0;
    if ((ss = OPENSSL_zalloc(sslen)) == NULL)
        goto end;
    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) == NULL
        || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
        goto end;

    ret = EVP_PKEY_decapsulate(ctx, ss, &sslen, ct, ctlen - 1) <= 0;
    ERR_clear_error();

end:
    OPENSSL_clear_free(ss, sslen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static void fill_ikme(unsigned char *ikme, size_t ikmelen)
{
    size_t i;

    for (i = 0; i < ikmelen; i++)
        ikme[i] = (unsigned char)(ikmelen + i);
}

static int test_ntruplus_roundtrip(const NTRUPLUS_TEST_VINFO *v)
{
    EVP_PKEY *akey = NULL;
    EVP_PKEY *bkey = NULL;
    EVP_PKEY *dkey = NULL;
    unsigned char *rawpub = NULL;
    unsigned char *ct = NULL;
    unsigned char *ass = NULL;
    unsigned char *dss = NULL;
    unsigned char *bss = NULL;
    size_t rawpublen, ctlen = 0;
    size_t asslen = 0, dsslen = 0, bsslen = 0;
    int ret = 0;

    if (!keygen_with_name(v->algorithm_name, &akey)) {
        fail(v->algorithm_name, "keygen failed");
        goto end;
    }

    rawpublen = EVP_PKEY_get1_encoded_public_key(akey, &rawpub);
    if (rawpublen != v->pubkey_bytes || rawpub == NULL) {
        fail(v->algorithm_name, "encoded public key export failed");
        goto end;
    }

    if (!public_key_from_encoded(akey, rawpub, rawpublen, &bkey)) {
        fail(v->algorithm_name, "encoded public key import failed");
        goto end;
    }

    if (!private_key_from_data(v->algorithm_name, akey, &dkey)) {
        fail(v->algorithm_name, "private key import failed");
        goto end;
    }

    if (!encapsulate(bkey, NULL, 0, &ct, &ctlen, &bss, &bsslen)
        || ctlen != v->ctext_bytes || bsslen != v->shsec_bytes) {
        fail(v->algorithm_name, "encapsulate failed");
        goto end;
    }

    if (!decapsulate(akey, ct, ctlen, &ass, &asslen)
        || asslen != bsslen || memcmp(ass, bss, asslen) != 0) {
        fail(v->algorithm_name, "decapsulate failed");
        goto end;
    }

    if (!decapsulate(dkey, ct, ctlen, &dss, &dsslen)
        || dsslen != bsslen || memcmp(dss, bss, dsslen) != 0) {
        fail(v->algorithm_name, "private-only decapsulate failed");
        goto end;
    }

    if (!shared_secret_is_nonzero(ass, asslen)) {
        fail(v->algorithm_name, "shared secret is zero");
        goto end;
    }

    ret = 1;

end:
    OPENSSL_free(rawpub);
    OPENSSL_free(ct);
    OPENSSL_clear_free(ass, asslen);
    OPENSSL_clear_free(dss, dsslen);
    OPENSSL_clear_free(bss, bsslen);
    EVP_PKEY_free(dkey);
    EVP_PKEY_free(bkey);
    EVP_PKEY_free(akey);
    return ret;
}

static int test_ntruplus(void)
{
    int full = full_test_enabled();
    size_t i = full ? 0 : 1;
    size_t end = full ? NTRUPLUS_TEST_NELEM(ntruplus_vinfos) : i + 1;

    for (; i < end; i++)
        if (!test_ntruplus_roundtrip(&ntruplus_vinfos[i]))
            return 0;

    return 1;
}

static int test_ntruplus_aliases(void)
{
    EVP_PKEY *key = NULL;
    unsigned char *rawpub = NULL;
    size_t rawpublen;
    size_t i;
    int ret = 1;

    for (i = 0; i < NTRUPLUS_TEST_NELEM(ntruplus_alias_vinfos); i++) {
        const NTRUPLUS_TEST_VINFO *v = &ntruplus_alias_vinfos[i];

        if (!keygen_with_name(v->algorithm_name, &key)) {
            fail(v->algorithm_name, "alias keygen failed");
            ret = 0;
            goto loop_end;
        }

        rawpublen = EVP_PKEY_get1_encoded_public_key(key, &rawpub);
        if (rawpublen != v->pubkey_bytes || rawpub == NULL) {
            fail(v->algorithm_name, "alias public key export failed");
            ret = 0;
            goto loop_end;
        }

loop_end:
        OPENSSL_free(rawpub);
        EVP_PKEY_free(key);
        rawpub = NULL;
        key = NULL;
        if (!ret)
            break;
    }

    return ret;
}

static int test_seeded_ntruplus(void)
{
    unsigned char ikme[NTRUPLUS_MAX_ENCAP_SEED_BYTES];
    size_t i;
    int ret = 1;

    for (i = 0; i < NTRUPLUS_TEST_NELEM(ntruplus_vinfos); i++) {
        const NTRUPLUS_TEST_VINFO *v = &ntruplus_vinfos[i];
        EVP_PKEY *akey = NULL;
        EVP_PKEY *bkey = NULL;
        unsigned char *rawpub = NULL;
        unsigned char *ct1 = NULL, *ct2 = NULL;
        unsigned char *ss1 = NULL, *ss2 = NULL, *dss = NULL;
        size_t rawpublen;
        size_t ctlen1 = 0, ctlen2 = 0;
        size_t sslen1 = 0, sslen2 = 0, dsslen = 0;

        fill_ikme(ikme, v->encap_seed_bytes);

        if (!keygen_with_name(v->algorithm_name, &akey)) {
            fail(v->algorithm_name, "keygen failed");
            ret = 0;
            goto loop_end;
        }

        rawpublen = EVP_PKEY_get1_encoded_public_key(akey, &rawpub);
        if (rawpublen != v->pubkey_bytes || rawpub == NULL
            || !public_key_from_encoded(akey, rawpub, rawpublen, &bkey)) {
            fail(v->algorithm_name, "encoded public key setup failed");
            ret = 0;
            goto loop_end;
        }

        if (!encapsulate(bkey, ikme, v->encap_seed_bytes,
                         &ct1, &ctlen1, &ss1, &sslen1)
            || !encapsulate(bkey, ikme, v->encap_seed_bytes,
                            &ct2, &ctlen2, &ss2, &sslen2)
            || ctlen1 != v->ctext_bytes || ctlen2 != v->ctext_bytes
            || sslen1 != v->shsec_bytes || sslen2 != v->shsec_bytes
            || memcmp(ct1, ct2, ctlen1) != 0
            || memcmp(ss1, ss2, sslen1) != 0) {
            fail(v->algorithm_name, "seeded encapsulate failed");
            ret = 0;
            goto loop_end;
        }

        if (!decapsulate(akey, ct1, ctlen1, &dss, &dsslen)
            || dsslen != sslen1 || memcmp(dss, ss1, dsslen) != 0) {
            fail(v->algorithm_name, "seeded decapsulate failed");
            ret = 0;
            goto loop_end;
        }

        if (!bad_ciphertext_length_rejected(akey, ct1, ctlen1, sslen1)) {
            fail(v->algorithm_name, "bad ciphertext length accepted");
            ret = 0;
            goto loop_end;
        }

loop_end:
        OPENSSL_free(rawpub);
        OPENSSL_free(ct1);
        OPENSSL_free(ct2);
        OPENSSL_clear_free(ss1, sslen1);
        OPENSSL_clear_free(ss2, sslen2);
        OPENSSL_clear_free(dss, dsslen);
        EVP_PKEY_free(bkey);
        EVP_PKEY_free(akey);
        if (!ret)
            break;
    }

    return ret;
}

static int test_ntruplusx_roundtrip(void)
{
    EVP_PKEY *akey = NULL;
    EVP_PKEY *bkey = NULL;
    EVP_PKEY *dkey = NULL;
    unsigned char *ct = NULL;
    unsigned char *ass = NULL;
    unsigned char *bss = NULL;
    unsigned char *dss = NULL;
    size_t ctlen = 0, asslen = 0, bsslen = 0, dsslen = 0;
    size_t i;
    int ret = 1;

    for (i = 0; i < NTRUPLUS_TEST_NELEM(ntruplusx_algs); i++) {
        if (!keygen_with_name(ntruplusx_algs[i], &akey)) {
            fail(ntruplusx_algs[i], "hybrid keygen failed");
            ret = 0;
            goto loop_end;
        }

        if (!public_key_from_data(ntruplusx_algs[i], akey, &bkey)) {
            fail(ntruplusx_algs[i], "hybrid public key import failed");
            ret = 0;
            goto loop_end;
        }

        if (!private_key_from_data(ntruplusx_algs[i], akey, &dkey)) {
            fail(ntruplusx_algs[i], "hybrid private key import failed");
            ret = 0;
            goto loop_end;
        }

        if (!encapsulate(bkey, NULL, 0, &ct, &ctlen, &bss, &bsslen)) {
            fail(ntruplusx_algs[i], "hybrid encapsulate failed");
            ret = 0;
            goto loop_end;
        }

        if (!decapsulate(akey, ct, ctlen, &ass, &asslen)
            || asslen != bsslen || memcmp(ass, bss, asslen) != 0) {
            fail(ntruplusx_algs[i], "hybrid decapsulate failed");
            ret = 0;
            goto loop_end;
        }

        if (!decapsulate(dkey, ct, ctlen, &dss, &dsslen)
            || dsslen != bsslen || memcmp(dss, bss, dsslen) != 0) {
            fail(ntruplusx_algs[i], "hybrid private-only decapsulate failed");
            ret = 0;
            goto loop_end;
        }

        if (!shared_secret_is_nonzero(ass, asslen)) {
            fail(ntruplusx_algs[i], "hybrid shared secret is zero");
            ret = 0;
            goto loop_end;
        }

        if (!bad_ciphertext_length_rejected(akey, ct, ctlen, asslen)) {
            fail(ntruplusx_algs[i], "hybrid bad ciphertext length accepted");
            ret = 0;
            goto loop_end;
        }

loop_end:
        OPENSSL_free(ct);
        OPENSSL_clear_free(ass, asslen);
        OPENSSL_clear_free(bss, bsslen);
        OPENSSL_clear_free(dss, dsslen);
        EVP_PKEY_free(dkey);
        EVP_PKEY_free(bkey);
        EVP_PKEY_free(akey);
        ct = NULL;
        ass = NULL;
        bss = NULL;
        dss = NULL;
        dkey = NULL;
        bkey = NULL;
        akey = NULL;
        ctlen = 0;
        asslen = 0;
        bsslen = 0;
        dsslen = 0;
        if (!ret)
            break;
    }

    return ret;
}

static int test_ntruplusx_dup_partial_selection(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *dest = NULL;
    size_t ctlen = 0, sslen = 0;
    size_t i;
    int copy_result;
    int ret = 1;

    for (i = 0; i < NTRUPLUS_TEST_NELEM(ntruplusx_algs); i++) {
        if (!keygen_with_name(ntruplusx_algs[i], &key)
            || (dest = EVP_PKEY_new()) == NULL) {
            fail(ntruplusx_algs[i], "hybrid keygen failed");
            ret = 0;
            goto loop_end;
        }

        /*
         * EVP_PKEY_copy_parameters() exercises a partial-duplication path.
         * It may fail because NTRU+ hybrid KEM keys do not expose separate
         * domain parameters, but it must not corrupt the source key.
         */
        copy_result = EVP_PKEY_copy_parameters(dest, key);
        if (copy_result > 0 && EVP_PKEY_eq(dest, key) == 1) {
            fail(ntruplusx_algs[i], "hybrid partial copy produced full key");
            ret = 0;
            goto loop_end;
        }
        ERR_clear_error();
        ctlen = 0;
        sslen = 0;

        if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) == NULL
            || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
            || EVP_PKEY_encapsulate(ctx, NULL, &ctlen, NULL, &sslen) <= 0
            || ctlen == 0 || sslen == 0) {
            fail(ntruplusx_algs[i], "hybrid partial copy corrupted key");
            ret = 0;
            goto loop_end;
        }

loop_end:
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dest);
        EVP_PKEY_free(key);
        ctx = NULL;
        dest = NULL;
        key = NULL;
        if (!ret)
            break;
    }

    return ret;
}

static const char *test_module_dir = NULL;
static OSSL_PROVIDER *defprov = NULL;
static OSSL_PROVIDER *ntruplusprov = NULL;

int ntruplus_test_set_full(int full)
{
    test_full = full;
    return 1;
}

int ntruplus_test_set_module_dir(const char *module_dir)
{
    test_module_dir = module_dir;
    return test_module_dir != NULL;
}

static int load_providers(void)
{
    if (test_module_dir == NULL)
        return 0;

    if (!OSSL_PROVIDER_set_default_search_path(NULL, test_module_dir))
        return 0;
    if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL)
        return 0;
    if ((ntruplusprov = OSSL_PROVIDER_load(NULL, "ntruplus")) == NULL)
        return 0;
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(ntruplusprov);
    OSSL_PROVIDER_unload(defprov);
}

int setup_tests(void)
{
    if (!load_providers())
        return 0;

    return test_ntruplus()
        && test_ntruplus_aliases()
        && test_seeded_ntruplus()
        && test_ntruplusx_roundtrip()
        && test_ntruplusx_dup_partial_selection();
}
