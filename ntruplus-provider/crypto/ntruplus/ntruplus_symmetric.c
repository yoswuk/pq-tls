#include "ntruplus_hash.h"
#include "ntruplus_poly.h"
#include "ntruplus_symmetric.h"

void shake256(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen)
{
    ntruplus_shake256(output, outlen, input, inlen);
}

enum {
    NTRUPLUS_HASH_F_IN_BYTES = NTRUPLUS_POLYBYTES,
    NTRUPLUS_HASH_F_OUT_BYTES = NTRUPLUS_SYMBYTES,
    NTRUPLUS_HASH_G_IN_BYTES = NTRUPLUS_POLYBYTES,
    NTRUPLUS_HASH_G_OUT_BYTES = NTRUPLUS_N / 4,
    NTRUPLUS_HASH_H_IN_BYTES = NTRUPLUS_N / 8 + NTRUPLUS_SYMBYTES,
    NTRUPLUS_HASH_H_OUT_BYTES = NTRUPLUS_SSBYTES + NTRUPLUS_N / 4
};

void hash_f(uint8_t *out, const uint8_t *in)
{
    ntruplus_shake256_prefix(out, NTRUPLUS_HASH_F_OUT_BYTES, 0x00,
                             in, NTRUPLUS_HASH_F_IN_BYTES);
}

void hash_g(uint8_t *out, const uint8_t *in)
{
    ntruplus_shake256_prefix(out, NTRUPLUS_HASH_G_OUT_BYTES, 0x01,
                             in, NTRUPLUS_HASH_G_IN_BYTES);
}

void hash_h(uint8_t *out, const uint8_t *in)
{
    ntruplus_shake256_prefix(out, NTRUPLUS_HASH_H_OUT_BYTES, 0x02,
                             in, NTRUPLUS_HASH_H_IN_BYTES);
}
