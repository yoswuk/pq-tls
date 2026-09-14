#ifndef NTRUPLUS_PROV_IMPLEMENTATIONS_H
# define NTRUPLUS_PROV_IMPLEMENTATIONS_H

# include <openssl/core.h>
# include <openssl/types.h>

extern const OSSL_DISPATCH ntruplus768_keymgmt_functions[];
extern const OSSL_DISPATCH ntruplus864_keymgmt_functions[];
extern const OSSL_DISPATCH ntruplus1152_keymgmt_functions[];
extern const OSSL_DISPATCH ntruplus_kem_functions[];
extern const OSSL_DISPATCH ntruplusx_x25519_864_keymgmt_functions[];
extern const OSSL_DISPATCH ntruplusx_secp256r1_864_keymgmt_functions[];
extern const OSSL_DISPATCH ntruplusx_secp384r1_1152_keymgmt_functions[];
extern const OSSL_DISPATCH ntruplusx_kem_functions[];

#endif
