/* Internal symmetric/hash helper declarations for parameterized NTRU+ code paths. */
#ifndef OSSL_CRYPTO_NTRUPLUS_SYMMETRIC_H
# define OSSL_CRYPTO_NTRUPLUS_SYMMETRIC_H

# include <stddef.h>
# include <stdint.h>

# ifndef NTRUPLUS_JOIN
#  define NTRUPLUS_JOIN2(a, b) a ## _ ## b
#  define NTRUPLUS_JOIN(a, b) NTRUPLUS_JOIN2(a, b)
# endif

# ifndef NTRUPLUS_PREFIX
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void hash_f(uint8_t *out, const uint8_t *in);
void hash_g(uint8_t *out, const uint8_t *in);
void hash_h(uint8_t *out, const uint8_t *in);
# else
void NTRUPLUS_JOIN(NTRUPLUS_PREFIX, shake256)(uint8_t *output, size_t outlen,
                                             const uint8_t *input, size_t inlen);
void NTRUPLUS_JOIN(NTRUPLUS_PREFIX, hash_f)(uint8_t *out, const uint8_t *in);
void NTRUPLUS_JOIN(NTRUPLUS_PREFIX, hash_g)(uint8_t *out, const uint8_t *in);
void NTRUPLUS_JOIN(NTRUPLUS_PREFIX, hash_h)(uint8_t *out, const uint8_t *in);
# endif

#endif
