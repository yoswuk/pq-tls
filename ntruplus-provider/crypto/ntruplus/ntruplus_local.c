/* Runtime dispatch for parameterized NTRU+ code paths. */
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "ntruplus_local.h"

#ifdef NTRUPLUS_ENABLE_AVX2
# define NTRUPLUS_AVX2_QINV 12929
# define NTRUPLUS_AVX2_LOW ((1U << 12) - 1)
# define NTRUPLUS_AVX2_V ((1U << 26) / NTRUPLUS_MODULUS)
# define NTRUPLUS_AVX2_V2 10923
# define NTRUPLUS_AVX2_WQINV 13706
# define NTRUPLUS_AVX2_W -886
# define NTRUPLUS_AVX2_QM1DIV2 1728
# define NTRUPLUS_AVX2_QP1DIV2 1729
# define NTRUPLUS_AVX2_R2 867
# define NTRUPLUS_AVX2_R2QINV 2787
# define NTRUPLUS_AVX2_RINV -682
# define NTRUPLUS_AVX2_RINVQINV 29782
# define NTRUPLUS_AVX2_MASK_5555 0x5555
# define NTRUPLUS_AVX2_MASK_0303 0x0303
# define NTRUPLUS_AVX2_MASK_0101 0x0101
# define NTRUPLUS_AVX2_FILL_16(x) \
    { x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x }
# if defined(__GNUC__) || defined(__clang__)
#  define NTRUPLUS_AVX2_CONST_ATTR \
    __attribute__((aligned(32), visibility("hidden")))
# else
#  define NTRUPLUS_AVX2_CONST_ATTR
# endif

const int16_t ntruplus_avx2_low_mask[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_LOW);
const int16_t ntruplus_avx2_16xv[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_V);
const int16_t ntruplus_avx2_16xv2[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_V2);
const int16_t ntruplus_avx2_16x1[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(1);
const int16_t ntruplus_avx2_16x3[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(3);
const int16_t ntruplus_avx2_16xq[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_MODULUS);
const int16_t ntruplus_avx2_16xqp1div2[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_QP1DIV2);
const int16_t ntruplus_avx2_16xqm1div2[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_QM1DIV2);
const int16_t ntruplus_avx2_16xqinv[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_QINV);
const int16_t ntruplus_avx2_16xw[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_W);
const int16_t ntruplus_avx2_16xwqinv[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_WQINV);
const int16_t ntruplus_avx2_16xR2[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_R2);
const int16_t ntruplus_avx2_16xR2qinv[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_R2QINV);
const int16_t ntruplus_avx2_16xRinv[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_RINV);
const int16_t ntruplus_avx2_16xRinvqinv[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_RINVQINV);
const int16_t ntruplus_avx2_16x5555[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_MASK_5555);
const int16_t ntruplus_avx2_16x0303[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_MASK_0303);
const int16_t ntruplus_avx2_16x0101[16] NTRUPLUS_AVX2_CONST_ATTR =
    NTRUPLUS_AVX2_FILL_16(NTRUPLUS_AVX2_MASK_0101);

# undef NTRUPLUS_AVX2_QINV
# undef NTRUPLUS_AVX2_LOW
# undef NTRUPLUS_AVX2_V
# undef NTRUPLUS_AVX2_V2
# undef NTRUPLUS_AVX2_WQINV
# undef NTRUPLUS_AVX2_W
# undef NTRUPLUS_AVX2_QM1DIV2
# undef NTRUPLUS_AVX2_QP1DIV2
# undef NTRUPLUS_AVX2_R2
# undef NTRUPLUS_AVX2_R2QINV
# undef NTRUPLUS_AVX2_RINV
# undef NTRUPLUS_AVX2_RINVQINV
# undef NTRUPLUS_AVX2_MASK_5555
# undef NTRUPLUS_AVX2_MASK_0303
# undef NTRUPLUS_AVX2_MASK_0101
# undef NTRUPLUS_AVX2_FILL_16
# undef NTRUPLUS_AVX2_CONST_ATTR
#endif /* NTRUPLUS_ENABLE_AVX2 */

#define NTRUPLUS_DECLARE_ALG(n, suffix)                                     \
    int ntruplus##n##_##suffix##_keygen(                                    \
        uint8_t *pk, int16_t *h_coeffs, int16_t *f_coeffs,                  \
        int16_t *hinv_coeffs, uint8_t *pk_hash,                             \
        int (*random_cb)(uint8_t *out, size_t outlen, void *arg),           \
        void *random_arg);                                                  \
    int ntruplus##n##_##suffix##_encode_poly(uint8_t *out,                  \
                                             const int16_t *in);            \
    int ntruplus##n##_##suffix##_decode_poly(int16_t *out,                  \
                                             const uint8_t *in);            \
    int ntruplus##n##_##suffix##_encoded_poly_is_valid(                     \
        const uint8_t *in, size_t inlen);                                   \
    int ntruplus##n##_##suffix##_encap_seed(                                \
        uint8_t *ct, uint8_t *ss,                                           \
        const int16_t *h_coeffs, const uint8_t *pk_hash,                    \
        const uint8_t *seed);                                               \
    int ntruplus##n##_##suffix##_decap(uint8_t *ss,                         \
                                       const uint8_t *ct,                   \
                                       const int16_t *f_coeffs,             \
                                       const int16_t *hinv_coeffs,          \
                                       const uint8_t *pk_hash)

NTRUPLUS_DECLARE_ALG(768, c);
NTRUPLUS_DECLARE_ALG(864, c);
NTRUPLUS_DECLARE_ALG(1152, c);

#ifdef NTRUPLUS_ENABLE_AVX2
NTRUPLUS_DECLARE_ALG(768, avx2);
NTRUPLUS_DECLARE_ALG(864, avx2);
NTRUPLUS_DECLARE_ALG(1152, avx2);
#endif

#undef NTRUPLUS_DECLARE_ALG

typedef enum ntruplus_code_path_e {
    NTRUPLUS_CODE_AUTO,
    NTRUPLUS_CODE_C,
    NTRUPLUS_CODE_AVX2
} NTRUPLUS_CODE_PATH;

typedef struct ntruplus_alg_entry_st {
    const NTRUPLUS_ALG *c_alg;
    const NTRUPLUS_ALG *avx2_alg;
} NTRUPLUS_ALG_ENTRY;

#define NTRUPLUS_DEFINE_ALG(n, suffix)                           \
    static const NTRUPLUS_ALG ntruplus##n##_##suffix##_alg = {    \
        ntruplus##n##_##suffix##_keygen,                         \
        ntruplus##n##_##suffix##_encode_poly,                    \
        ntruplus##n##_##suffix##_decode_poly,                    \
        ntruplus##n##_##suffix##_encoded_poly_is_valid,           \
        ntruplus##n##_##suffix##_encap_seed,                     \
        ntruplus##n##_##suffix##_decap,                          \
    }

NTRUPLUS_DEFINE_ALG(768, c);
NTRUPLUS_DEFINE_ALG(864, c);
NTRUPLUS_DEFINE_ALG(1152, c);

#ifdef NTRUPLUS_ENABLE_AVX2
NTRUPLUS_DEFINE_ALG(768, avx2);
NTRUPLUS_DEFINE_ALG(864, avx2);
NTRUPLUS_DEFINE_ALG(1152, avx2);

static int ntruplus_have_avx2(void)
{
# if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
# else
    return 0;
# endif
}
#endif

#undef NTRUPLUS_DEFINE_ALG

#ifdef NTRUPLUS_ENABLE_AVX2
# define NTRUPLUS_AVX2_ALG(n) &ntruplus##n##_avx2_alg
#else
# define NTRUPLUS_AVX2_ALG(n) NULL
#endif

#define NTRUPLUS_ALG_ENTRY(n) \
    { &ntruplus##n##_c_alg, NTRUPLUS_AVX2_ALG(n) }

static const NTRUPLUS_ALG_ENTRY ntruplus_alg_entries[NTRUPLUS_VINFO_COUNT] = {
    [EVP_PKEY_NTRUPLUS_768] = NTRUPLUS_ALG_ENTRY(768),
    [EVP_PKEY_NTRUPLUS_864] = NTRUPLUS_ALG_ENTRY(864),
    [EVP_PKEY_NTRUPLUS_1152] = NTRUPLUS_ALG_ENTRY(1152),
};

#undef NTRUPLUS_ALG_ENTRY
#undef NTRUPLUS_AVX2_ALG

static NTRUPLUS_CODE_PATH ntruplus_code_path(void)
{
    const char *path = ossl_safe_getenv("NTRUPLUS_CODE_PATH");

    if (path == NULL || path[0] == '\0'
        || OPENSSL_strcasecmp(path, "auto") == 0)
        return NTRUPLUS_CODE_AUTO;
    if (OPENSSL_strcasecmp(path, "c") == 0)
        return NTRUPLUS_CODE_C;
    if (OPENSSL_strcasecmp(path, "avx2") == 0)
        return NTRUPLUS_CODE_AVX2;
    return NTRUPLUS_CODE_AUTO;
}

static const NTRUPLUS_ALG_ENTRY *ntruplus_alg_entry_by_vinfo(
    const NTRUPLUS_VINFO *vinfo)
{
    if (vinfo == NULL || vinfo->evp_type < 0
        || vinfo->evp_type >= NTRUPLUS_VINFO_COUNT)
        return NULL;
    return &ntruplus_alg_entries[vinfo->evp_type];
}

static const NTRUPLUS_ALG *ntruplus_select_alg_from_entry(
    const NTRUPLUS_ALG_ENTRY *entry, NTRUPLUS_CODE_PATH code_path)
{
    if (entry == NULL)
        return NULL;

#ifdef NTRUPLUS_ENABLE_AVX2
    if (code_path != NTRUPLUS_CODE_C
        && entry->avx2_alg != NULL
        && ntruplus_have_avx2())
        return entry->avx2_alg;
#endif

    if (code_path == NTRUPLUS_CODE_AVX2)
        return NULL;
    return entry->c_alg;
}

const NTRUPLUS_ALG *ntruplus_select_alg(const NTRUPLUS_VINFO *vinfo)
{
    const NTRUPLUS_ALG_ENTRY *entry;

    entry = ntruplus_alg_entry_by_vinfo(vinfo);
    return ntruplus_select_alg_from_entry(entry, ntruplus_code_path());
}
