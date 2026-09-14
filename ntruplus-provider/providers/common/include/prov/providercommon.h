#ifndef NTRUPLUS_PROVIDERCOMMON_H
# define NTRUPLUS_PROVIDERCOMMON_H

# include <openssl/core_dispatch.h>

# ifndef ntruplus_unused
#  if defined(__GNUC__) || defined(__clang__)
#   define ntruplus_unused __attribute__((unused))
#  else
#   define ntruplus_unused
#  endif
# endif

# ifndef ossl_likely
#  if defined(__GNUC__) || defined(__clang__)
#   define ossl_likely(x) __builtin_expect(!!(x), 1)
#  else
#   define ossl_likely(x) (x)
#  endif
# endif

# ifndef ossl_unlikely
#  if defined(__GNUC__) || defined(__clang__)
#   define ossl_unlikely(x) __builtin_expect(!!(x), 0)
#  else
#   define ossl_unlikely(x) (x)
#  endif
# endif

OSSL_FUNC_provider_get_capabilities_fn ntruplus_prov_get_capabilities;

int ntruplus_prov_is_running(void);

#endif
