# NTRU+ Provider Configuration Patch

`ntruplus-provider-config.patch` updates OpenSSL's existing
`apps/openssl.cnf` instead of replacing it with a minimal configuration.

The patch:

- adds `ntruplus = ntruplus_sect` to `[provider_sect]`;
- explicitly activates the default provider, because activating another
  provider disables its implicit activation; and
- adds `[ntruplus_sect]`, which loads
  `${ENV::NTRUPLUS_PROVIDER_PATH}/ntruplus.so` and activates it.

Set and export `NTRUPLUS_PROVIDER_PATH` before starting an OpenSSL process that
uses the patched configuration.
