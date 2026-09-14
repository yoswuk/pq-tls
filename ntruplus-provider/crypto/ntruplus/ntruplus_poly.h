/* Internal parameterized NTRU+ code-path interface. */
#ifndef OSSL_CRYPTO_NTRUPLUS_POLY_H
# define OSSL_CRYPTO_NTRUPLUS_POLY_H

# include <stddef.h>
# include <stdint.h>
# include "ntruplus_symmetric.h"

# ifndef NTRUPLUS_PREFIX
#  error "NTRUPLUS_PREFIX must be defined before compiling this file"
# endif
# ifndef NTRUPLUS_N
#  error "NTRUPLUS_N must be defined before compiling this file"
# endif

# ifndef NTRUPLUS_JOIN
#  define NTRUPLUS_JOIN2(a, b) a ## _ ## b
#  define NTRUPLUS_JOIN(a, b) NTRUPLUS_JOIN2(a, b)
#  define NTRUPLUS_JOIN_DEFINED
# endif

/* Method-table entry points. */
# define ntruplus_kem_keygen NTRUPLUS_JOIN(NTRUPLUS_PREFIX, keygen)
# define ntruplus_kem_encode_poly NTRUPLUS_JOIN(NTRUPLUS_PREFIX, encode_poly)
# define ntruplus_kem_decode_poly NTRUPLUS_JOIN(NTRUPLUS_PREFIX, decode_poly)
# define ntruplus_kem_encoded_poly_is_valid \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, encoded_poly_is_valid)
# define ntruplus_kem_encap_seed NTRUPLUS_JOIN(NTRUPLUS_PREFIX, encap_seed)
# define ntruplus_kem_decap NTRUPLUS_JOIN(NTRUPLUS_PREFIX, decap)

/* Imported symmetric and polynomial helper names. */
# define poly NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly)
# define hash_f NTRUPLUS_JOIN(NTRUPLUS_PREFIX, hash_f)
# define hash_g NTRUPLUS_JOIN(NTRUPLUS_PREFIX, hash_g)
# define hash_h NTRUPLUS_JOIN(NTRUPLUS_PREFIX, hash_h)
# define shake256 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, shake256)
# define zetas NTRUPLUS_JOIN(NTRUPLUS_PREFIX, zetas)
# define zetas_mont NTRUPLUS_JOIN(NTRUPLUS_PREFIX, zetas_mont)
# define poly_tobytes NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_tobytes)
# define poly_frombytes NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_frombytes)
# define poly_cbd1 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_cbd1)
# define poly_sotp_encode NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_sotp_encode)
# define poly_sotp_decode NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_sotp_decode)
# define poly_ntt NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_ntt)
# define poly_invntt NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_invntt)
# define poly_baseinv NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_baseinv)
# define poly_basemul NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_basemul)
# define poly_basemul_add NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_basemul_add)
# define poly_sub NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_sub)
# define poly_triple NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_triple)
# define poly_crepmod3 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_crepmod3)
# define plantard_reduce NTRUPLUS_JOIN(NTRUPLUS_PREFIX, plantard_reduce)
# define plantard_reduce_acc NTRUPLUS_JOIN(NTRUPLUS_PREFIX, plantard_reduce_acc)
# define plantard_mul NTRUPLUS_JOIN(NTRUPLUS_PREFIX, plantard_mul)
# define montgomery_reduce NTRUPLUS_JOIN(NTRUPLUS_PREFIX, montgomery_reduce)
# define fqmul NTRUPLUS_JOIN(NTRUPLUS_PREFIX, fqmul)
# define fqmul_neg NTRUPLUS_JOIN(NTRUPLUS_PREFIX, fqmul_neg)
# define fqsqr NTRUPLUS_JOIN(NTRUPLUS_PREFIX, fqsqr)
# define fqinv NTRUPLUS_JOIN(NTRUPLUS_PREFIX, fqinv)
# define fqinv_batch NTRUPLUS_JOIN(NTRUPLUS_PREFIX, fqinv_batch)
# define ntt NTRUPLUS_JOIN(NTRUPLUS_PREFIX, ntt)
# define invntt NTRUPLUS_JOIN(NTRUPLUS_PREFIX, invntt)
# define baseinv NTRUPLUS_JOIN(NTRUPLUS_PREFIX, baseinv)
# define baseinv_1 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, baseinv_1)
# define baseinv_2 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, baseinv_2)
# define basemul NTRUPLUS_JOIN(NTRUPLUS_PREFIX, basemul)
# define crepmod3 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, crepmod3)

# ifdef NTRUPLUS_SOURCE_AVX2
/* Imported AVX2 helper names and shared AVX2 constants. */
# define poly_freeze_avx2 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_freeze_avx2)
# define poly_cbd1_block NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_cbd1_block)
# define poly_sotp_decode_block \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_sotp_decode_block)
# define poly_baseinv_1 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_baseinv_1)
# define poly_baseinv_2 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_baseinv_2)
# define poly_add NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_add)
# define zetas_inv NTRUPLUS_JOIN(NTRUPLUS_PREFIX, zetas_inv)
# define poly_fqmul_avx2 NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_fqmul_avx2)
# define poly_fqmul_precomp_avx2 \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_fqmul_precomp_avx2)
# define poly_fqmul_precomp_neg_avx2 \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_fqmul_precomp_neg_avx2)
# define poly_barrett_reduce_avx2 \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_barrett_reduce_avx2)
# define poly_baseinv4_block_avx2 \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_baseinv4_block_avx2)
# define poly_baseinv3_block_avx2 \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_baseinv3_block_avx2)
# define poly_basemul4_block_avx2 \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_basemul4_block_avx2)
# define poly_basemul3_block_avx2 \
    NTRUPLUS_JOIN(NTRUPLUS_PREFIX, poly_basemul3_block_avx2)
# define _low_mask ntruplus_avx2_low_mask
# define _16xv ntruplus_avx2_16xv
# define _16xv2 ntruplus_avx2_16xv2
# define _16x1 ntruplus_avx2_16x1
# define _16x3 ntruplus_avx2_16x3
# define _16xq ntruplus_avx2_16xq
# define _16xqp1div2 ntruplus_avx2_16xqp1div2
# define _16xqm1div2 ntruplus_avx2_16xqm1div2
# define _16xqinv ntruplus_avx2_16xqinv
# define _16xw ntruplus_avx2_16xw
# define _16xwqinv ntruplus_avx2_16xwqinv
# define _16xR2 ntruplus_avx2_16xR2
# define _16xR2qinv ntruplus_avx2_16xR2qinv
# define _16xRinv ntruplus_avx2_16xRinv
# define _16xRinvqinv ntruplus_avx2_16xRinvqinv
# define _16x5555 ntruplus_avx2_16x5555
# define _16x0303 ntruplus_avx2_16x0303
# define _16x0101 ntruplus_avx2_16x0101
# endif

/* Parameter-set specialization used by the imported code. */
# if NTRUPLUS_N == 768
#  define NTRUPLUS_D 4
#  define NTRUPLUS_POLYBYTES 1152
# elif NTRUPLUS_N == 864
#  define NTRUPLUS_D 3
#  define NTRUPLUS_POLYBYTES 1296
# elif NTRUPLUS_N == 1152
#  define NTRUPLUS_D 4
#  define NTRUPLUS_POLYBYTES 1728
# else
#  error "unsupported NTRU+ parameter set"
# endif

# define NTRUPLUS_Q 3457
# define NTRUPLUS_SYMBYTES 32
# define NTRUPLUS_SSBYTES 32

# define NTRUPLUS_POLY_COEFF_BYTES (NTRUPLUS_N * sizeof(int16_t))

# ifdef NTRUPLUS_SOURCE_AVX2
#  include <immintrin.h>
#  define NTRUPLUS_POLY_ATTR __attribute__((aligned(32)))
# else
#  define NTRUPLUS_POLY_ATTR
# endif

typedef struct NTRUPLUS_POLY_ATTR {
    int16_t coeffs[NTRUPLUS_N];
} poly;

/* Encodeq/Decodeq serialization for one parameterized polynomial. */
void poly_tobytes(uint8_t r[NTRUPLUS_POLYBYTES], const poly *a);
void poly_frombytes(poly *r, const uint8_t a[NTRUPLUS_POLYBYTES]);

/* Sampling and one-time-pad message encoding helpers. */
void poly_cbd1(poly *r, const uint8_t buf[NTRUPLUS_N / 4]);
void poly_sotp_encode(poly *r, const uint8_t msg[NTRUPLUS_N / 8],
                      const uint8_t buf[NTRUPLUS_N / 4]);
int poly_sotp_decode(uint8_t msg[NTRUPLUS_N / 8], const poly *a,
                     const uint8_t buf[NTRUPLUS_N / 4]);

/* NTT-domain arithmetic used by KEM operations. */
void poly_ntt(poly *r);
void poly_invntt(poly *r);
int poly_baseinv(poly *r, const poly *a);
void poly_basemul(poly *r, const poly *a, const poly *b);
void poly_basemul_add(poly *r, const poly *a, const poly *b, const poly *c);
void poly_sub(poly *r, const poly *a, const poly *b);
void poly_triple(poly *r, const poly *a);
void poly_crepmod3(poly *r, const poly *a);

# ifdef NTRUPLUS_SOURCE_AVX2
/* AVX2-only helpers and constants used by the imported code. */
void poly_baseinv_1(poly *r, __m256i *den, const poly *a);
void poly_add(poly *r, const poly *a, const poly *b);

extern const int16_t ntruplus_avx2_low_mask[16];
extern const int16_t ntruplus_avx2_16xv[16];
extern const int16_t ntruplus_avx2_16xv2[16];
extern const int16_t ntruplus_avx2_16x1[16];
extern const int16_t ntruplus_avx2_16x3[16];
extern const int16_t ntruplus_avx2_16xq[16];
extern const int16_t ntruplus_avx2_16xqp1div2[16];
extern const int16_t ntruplus_avx2_16xqm1div2[16];
extern const int16_t ntruplus_avx2_16xqinv[16];
extern const int16_t ntruplus_avx2_16xw[16];
extern const int16_t ntruplus_avx2_16xwqinv[16];
extern const int16_t ntruplus_avx2_16xR2[16];
extern const int16_t ntruplus_avx2_16xR2qinv[16];
extern const int16_t ntruplus_avx2_16xRinv[16];
extern const int16_t ntruplus_avx2_16xRinvqinv[16];
extern const int16_t ntruplus_avx2_16x5555[16];
extern const int16_t ntruplus_avx2_16x0303[16];
extern const int16_t ntruplus_avx2_16x0101[16];
# endif

# if defined(NTRUPLUS_SOURCE_AVX2) && (defined(__GNUC__) || defined(__clang__))
#  define NTRUPLUS_VISIBILITY_PUSHED
#  pragma GCC visibility push(hidden)
# endif

#endif /* OSSL_CRYPTO_NTRUPLUS_POLY_H */
