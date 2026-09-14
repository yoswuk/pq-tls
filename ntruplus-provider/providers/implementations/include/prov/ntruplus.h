#ifndef NTRUPLUS_PROV_NTRUPLUS_H
# define NTRUPLUS_PROV_NTRUPLUS_H

# include "crypto/ntruplus.h"
# include "prov/provider_ctx.h"

# define NTRUPLUS_PKEY_PARAM_IMPORT_PCT_TYPE "ntruplus.import_pct_type"

enum {
    NTRUPLUSX_VINFO_X25519_864 = 0,
    NTRUPLUSX_VINFO_SECP256R1_864,
    NTRUPLUSX_VINFO_SECP384R1_1152,
    NTRUPLUSX_VINFO_COUNT
};

typedef struct ntruplusx_vinfo_st {
    const char *hybrid_name;
    const char *algorithm_name;
    const char *group_name;
    size_t pubkey_bytes;
    size_t prvkey_bytes;
    size_t shsec_bytes;
    int ntruplus_slot;
    int ntruplus_evp_type;
} NTRUPLUSX_VINFO;

typedef struct ntruplusx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const NTRUPLUS_VINFO *ninfo;
    const NTRUPLUSX_VINFO *xinfo;
    EVP_PKEY *nkey;
    EVP_PKEY *xkey;
    unsigned int state;
} NTRUPLUSX_KEY;

# define NTRUPLUSX_HAVE_NOKEYS 0
# define NTRUPLUSX_HAVE_PUBKEY 1U
# define NTRUPLUSX_HAVE_PRVKEY 2U
/*
 * MLX can treat private key material as implying public key material because
 * ML-KEM private keys carry enough public state.  NTRU+ private encodings only
 * carry f, h^-1 and F(pk), so hybrid keys keep public and private availability
 * as separate flags.
 */
# define ntruplusx_kem_have_pubkey(key) \
    ((key) != NULL && (((key)->state & NTRUPLUSX_HAVE_PUBKEY) != 0))
# define ntruplusx_kem_have_prvkey(key) \
    ((key) != NULL && (((key)->state & NTRUPLUSX_HAVE_PRVKEY) != 0))

__owur NTRUPLUS_KEY *ntruplus_prov_ntruplus_new(PROV_CTX *ctx,
                                                const char *propq,
                                                int evp_type);
__owur const NTRUPLUSX_VINFO *ntruplusx_get_vinfo(unsigned int evp_type);

#endif
