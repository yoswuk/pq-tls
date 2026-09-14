# NTRU+ OpenSSL Provider

This directory contains an external OpenSSL 4 provider for NTRU+ standalone and
hybrid KEM algorithms.

This README covers provider-local details: registered provider algorithms,
source layout, implementation notes, provider build commands, EVP tests, and
direct provider speed tests. The repository root README covers OpenSSL patch
application, certificate fixtures, and TLS handshake benchmarking.

## Provider Algorithms

Provider KEM algorithm names:

```text
ntruplus768
ntruplus864
ntruplus1152
X25519NTRUPLUS864
SecP256r1NTRUPLUS864
SecP384r1NTRUPLUS1152
```

The size pairings follow OpenSSL's ML-KEM and MLX hybrid structure:

```text
ntruplus768             ML-KEM-512 level
ntruplus864             ML-KEM-768 level
ntruplus1152            ML-KEM-1024 level
X25519NTRUPLUS864       X25519MLKEM768 shape
SecP256r1NTRUPLUS864    SecP256r1MLKEM768 shape
SecP384r1NTRUPLUS1152   SecP384r1MLKEM1024 shape
```

`X25519NTRUPLUS768` and `X25519NTRUPLUS1152` are intentionally not part of the
provider algorithm set.

## Source Layout

| File | Role |
| --- | --- |
| `include/crypto/ntruplus.h` | Internal standalone NTRU+ key/core API used by provider adapters, matching OpenSSL's `include/crypto/ml_kem.h` layout |
| `crypto/ntruplus/build.info` | No-op OpenSSL crypto layout marker; CMake remains authoritative for this provider |
| `crypto/ntruplus/ntruplus_params.c` | NTRU+ parameter metadata table and variant lookup, matching OpenSSL's `ml_dsa_params.c` style |
| `crypto/ntruplus/ntruplus_local.h` | Crypto-private NTRU+ method table and helper declarations, matching OpenSSL's local header pattern |
| `crypto/ntruplus/ntruplus_local.c` | Generated code-path declarations, shared AVX2 constants, and runtime code-path dispatch |
| `crypto/ntruplus/ntruplus_hash.c` | Provider SHAKE bridge used by parameterized NTRU+ code |
| `crypto/ntruplus/ntruplus_hash.h` | Provider SHAKE bridge declarations |
| `crypto/ntruplus/ntruplus_symmetric.h` | Internal parameterized SHAKE/hash helper declarations |
| `crypto/ntruplus/ntruplus_key.c` | NTRU+ key object lifecycle, encoded key handling, key generation, public-key hashing, KEM operations, and comparison |
| `crypto/ntruplus/ntruplus_kem.c` | Imported parameterized NTRU+ KEM glue, encoded polynomial validation, and encode/decode adapters compiled once per parameter set and code path |
| `crypto/ntruplus/ntruplus_poly.c` | Imported parameterized polynomial arithmetic, NTT, base inversion, and base multiplication |
| `crypto/ntruplus/ntruplus_poly.h` | Internal parameterized polynomial interface and per-parameter symbol aliases |
| `crypto/ntruplus/ntruplus_symmetric.c` | Imported parameterized SHAKE/hash helpers |
| `providers/common/capabilities.c` | Provider capability registration, following OpenSSL's `providers/common/capabilities.c` split |
| `providers/common/include/prov/provider_ctx.h` | Provider context declaration, following OpenSSL's `prov/provider_ctx.h` split |
| `providers/common/provider_ctx.c` | Provider context helper implementation, following OpenSSL's `providers/common/provider_ctx.c` split |
| `providers/common/include/prov/providercommon.h` | Provider common running-state declaration, following OpenSSL's `prov/providercommon.h` split |
| `providers/implementations/include/prov/implementations.h` | Provider implementation dispatch declarations, following OpenSSL's `prov/implementations.h` split |
| `providers/implementations/include/prov/names.h` | Provider algorithm name macros, following OpenSSL's `prov/names.h` split |
| `providers/implementations/include/prov/ntruplus.h` | Provider-local NTRU+ key helper and hybrid key declarations, following OpenSSL's `prov/ml_kem.h` split |
| `providers/prov_running.c` | Provider running-state helper, following OpenSSL's `providers/prov_running.c` split |
| `providers/implementations/build.info` | No-op OpenSSL layout marker; CMake remains authoritative for this provider |
| `providers/implementations/keymgmt/build.info` | No-op OpenSSL keymgmt layout marker |
| `providers/implementations/keymgmt/ntruplus_kmgmt.c` | Standalone provider key management |
| `providers/implementations/keymgmt/ntruplus_kmgmt.inc.in` | Standalone keymgmt parameter metadata decoder template, matching OpenSSL generated `.inc.in` layout |
| `providers/implementations/keymgmt/ntruplus_kmgmt.inc` | Checked-in generated standalone keymgmt decoder fallback for standalone builds |
| `providers/implementations/keymgmt/ntruplusx_kmgmt.c` | Hybrid provider key management, following OpenSSL's `mlx_kmgmt.c` split |
| `providers/implementations/keymgmt/ntruplusx_kmgmt.inc.in` | Hybrid keymgmt parameter metadata decoder template, matching OpenSSL generated `.inc.in` layout |
| `providers/implementations/keymgmt/ntruplusx_kmgmt.inc` | Checked-in generated hybrid keymgmt decoder fallback for standalone builds |
| `providers/implementations/kem/build.info` | No-op OpenSSL KEM layout marker |
| `providers/implementations/kem/ntruplus_kem.c` | Standalone encapsulate/decapsulate operation |
| `providers/implementations/kem/ntruplus_kem.inc.in` | Standalone KEM settable parameter metadata decoder template, matching OpenSSL generated `.inc.in` layout |
| `providers/implementations/kem/ntruplus_kem.inc` | Checked-in generated standalone KEM decoder fallback for standalone builds |
| `providers/implementations/kem/ntruplusx_kem.c` | Hybrid encapsulate/decapsulate operation, following OpenSSL's `mlx_kem.c` split |
| `providers/ntruplusprov.c` | Provider entry point and dispatch tables, following OpenSSL's `legacyprov.c`/`defltprov.c` naming |
| `test/ntruplus_evp_extra_test.c` | Provider-level EVP KEM test, following OpenSSL's `ml_kem_evp_extra_test` naming |
| `test/ntruplustest.c` | Minimal standalone test main used by the CMake test executable |

`crypto/ntruplus/ntruplus_kem.c`, `crypto/ntruplus/ntruplus_poly.c`, and
`crypto/ntruplus/ntruplus_symmetric.c` are compiled multiple times by CMake
with `NTRUPLUS_N`, `NTRUPLUS_PREFIX`, and `NTRUPLUS_SOURCE_AVX2` set for each
parameter set and code path.

## Implementation Notes

The internal core API exposes ML-KEM-like key lifecycle boundaries:
`ntruplus_ntruplus_parse_public_key()`,
`ntruplus_ntruplus_parse_private_key()`,
`ntruplus_ntruplus_encode_public_key()`,
`ntruplus_ntruplus_encode_private_key()`, `ntruplus_ntruplus_genkey()`,
`ntruplus_ntruplus_encap_seed()`, `ntruplus_ntruplus_encap_rand()`, and
`ntruplus_ntruplus_decap()`.

The provider stores decoded key structures internally. The public key is the
polynomial `h`; the private key is `(f, h^-1, F(pk))`. Encoded public and
private bitstrings are accepted and emitted at provider boundaries. The decode
path rejects coefficients outside `[0, q - 1]`, and decapsulation checks the
ciphertext encoding before calling the selected code path.

The KEM operation supports the OpenSSL KEM context parameter `ikme`
(`OSSL_KEM_PARAM_IKME`) for deterministic encapsulation. The value is one-shot
and is cleansed after an encapsulation attempt.

```text
ntruplus768     96 bytes
ntruplus864    108 bytes
ntruplus1152   144 bytes
```

SHAKE is routed through OpenSSL's digest framework. `NTRUPLUS_KEY` owns a
fetched `EVP_MD *` for `SHAKE256`, and the imported one-shot `shake256()` calls
are redirected to that fetched digest instead of compiling the original
`fips202.c` into the provider. `randombytes.c` is not compiled. Provider key
generation uses `RAND_priv_bytes_ex()`, and random encapsulation uses
`RAND_bytes_ex()`.

The provider creates a child `OSSL_LIB_CTX` and fetches `SHAKE256` from there.
Applications must load a provider that supplies SHAKE, normally `default` or
`fips`, alongside `ntruplus`.

The default x86_64 build includes both portable C and intrinsic AVX2 code paths
for all parameter sets. No external assembly objects are linked. Runtime
dispatch selects AVX2 when the module contains AVX2 code and the CPU supports
it; otherwise it uses the portable C path.

For debugging or benchmarking, set `NTRUPLUS_CODE_PATH`:

```bash
NTRUPLUS_CODE_PATH=auto  # default
NTRUPLUS_CODE_PATH=c     # force portable C
NTRUPLUS_CODE_PATH=avx2  # require AVX2
```

`NTRUPLUS_CODE_PATH=avx2` fails intentionally if AVX2 code is not built or the
CPU does not support AVX2.

## Build

OpenSSL 4 is required. Point CMake at an OpenSSL build or install tree that
provides `OpenSSLConfig.cmake`; otherwise CMake may find system OpenSSL 3.x,
which is too old for the provider KEM APIs used here.

From this provider directory:

```bash
export BUILD_DIR=build
cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DOpenSSL_DIR=/path/to/directory/containing/OpenSSLConfig.cmake
cmake --build "$BUILD_DIR" -j"$(nproc)"
```

From the repository root:

```bash
cmake -S ntruplus-provider -B .build/ntruplus-provider \
  -DCMAKE_BUILD_TYPE=Release \
  -DOpenSSL_DIR="$PWD/.build/openssl"
cmake --build .build/ntruplus-provider -j"$(nproc)"
```

Do not use the OpenSSL build directory itself as the provider build directory.

## EVP Extra Test

Set `OPENSSL_BIN` to an OpenSSL executable that is ABI-compatible with the
headers and libraries used by CMake. `BUILD_DIR` must point at the CMake build
directory containing `ntruplus.so`.

```bash
export OPENSSL_BIN=/path/to/openssl-4/bin/openssl
export BUILD_DIR="${BUILD_DIR:-build}"
export PROVIDER_PATH="$(cd "$BUILD_DIR" && pwd)"

test -f "$PROVIDER_PATH/ntruplus.so"
```

List the registered provider KEM algorithms:

```bash
"$OPENSSL_BIN" list -kem-algorithms \
  -provider-path "$PROVIDER_PATH" \
  -provider default \
  -provider ntruplus
```

Run the default EVP extra test:

```bash
ctest --test-dir "$PROVIDER_PATH" --output-on-failure
NTRUPLUS_CODE_PATH=auto "$PROVIDER_PATH/ntruplus_evp_extra_test" "$PROVIDER_PATH"
NTRUPLUS_CODE_PATH=c    "$PROVIDER_PATH/ntruplus_evp_extra_test" "$PROVIDER_PATH"
```

If the module was built with AVX2 support and the CPU supports AVX2:

```bash
NTRUPLUS_CODE_PATH=avx2 "$PROVIDER_PATH/ntruplus_evp_extra_test" "$PROVIDER_PATH"
```

The default test is intentionally close to OpenSSL's ML-KEM EVP extra test
level: key generation, encoded public-key export/import, KEM operation,
deterministic `ikme` encapsulation replay, split public/private use, provider
algorithm aliases, hybrid public/private import paths, and the same hybrid
partial-duplication regression shape covered by OpenSSL's ML-KEM extra test.
The deeper provider boundary regression suite is available explicitly:

```bash
NTRUPLUS_FULL_TEST=1 "$PROVIDER_PATH/ntruplus_evp_extra_test" "$PROVIDER_PATH"
"$PROVIDER_PATH/ntruplus_evp_extra_test" --full "$PROVIDER_PATH"
```

OpenSSL's in-tree `ml_kem_evp_extra_test` also has a `-test-rand` mode. This
external provider does not mirror that mode directly because NTRU+ random draws
run inside the provider child `OSSL_LIB_CTX`; setting `TEST-RAND` on the test
process default library context does not control that child context. The EVP
extra test instead verifies deterministic encapsulation through the OpenSSL KEM
`ikme` parameter and replays the same vector through keypair, public-only, and
private-only imports.

## Provider Speed Test

These commands run OpenSSL's provider-level KEM benchmark directly. They do not
measure the TLS handshake path.

```bash
export OPENSSL_BIN=/path/to/openssl-4/bin/openssl
export BUILD_DIR="${BUILD_DIR:-build}"
export PROVIDER_PATH="$(cd "$BUILD_DIR" && pwd)"

test -f "$PROVIDER_PATH/ntruplus.so"
```

Measure the runtime-selected code path:

```bash
NTRUPLUS_CODE_PATH=auto "$OPENSSL_BIN" speed -seconds 3 -kem-algorithms \
  -provider-path "$PROVIDER_PATH" \
  -provider default \
  -provider ntruplus \
  ntruplus768 ntruplus864 ntruplus1152 \
  X25519NTRUPLUS864 SecP256r1NTRUPLUS864 SecP384r1NTRUPLUS1152
```

Compare code paths:

```bash
NTRUPLUS_CODE_PATH=c "$OPENSSL_BIN" speed -seconds 3 -kem-algorithms \
  -provider-path "$PROVIDER_PATH" \
  -provider default \
  -provider ntruplus \
  ntruplus768 ntruplus864 ntruplus1152 \
  X25519NTRUPLUS864 SecP256r1NTRUPLUS864 SecP384r1NTRUPLUS1152

NTRUPLUS_CODE_PATH=avx2 "$OPENSSL_BIN" speed -seconds 3 -kem-algorithms \
  -provider-path "$PROVIDER_PATH" \
  -provider default \
  -provider ntruplus \
  ntruplus768 ntruplus864 ntruplus1152 \
  X25519NTRUPLUS864 SecP256r1NTRUPLUS864 SecP384r1NTRUPLUS1152
```

`NTRUPLUS_CODE_PATH=avx2` fails intentionally if the module was built without
AVX2 support or is run on a CPU without AVX2.
