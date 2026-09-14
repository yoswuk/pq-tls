# SLH-DSA TLS SignatureScheme Patch

`slh-dsa-tls-signature-schemes.patch` exposes the SLH-DSA provider
implementation already present in OpenSSL 4.0 as TLS 1.3 signature schemes.

This patch does not implement SLH-DSA cryptography, ASN.1 OIDs, key
management, or the signature provider itself. It assumes those pieces already
exist in upstream OpenSSL 4.0. The patch scope is limited to making TLS
recognize the `slhdsa_*` SignatureScheme code points and advertise them in the
default `signature_algorithms` extension.

## Signature Schemes

| IANA name | Code point | OpenSSL algorithm |
| --- | --- | --- |
| `slhdsa_sha2_128s` | `0x0911` | `SLH-DSA-SHA2-128s` |
| `slhdsa_sha2_128f` | `0x0912` | `SLH-DSA-SHA2-128f` |
| `slhdsa_sha2_192s` | `0x0913` | `SLH-DSA-SHA2-192s` |
| `slhdsa_sha2_192f` | `0x0914` | `SLH-DSA-SHA2-192f` |
| `slhdsa_sha2_256s` | `0x0915` | `SLH-DSA-SHA2-256s` |
| `slhdsa_sha2_256f` | `0x0916` | `SLH-DSA-SHA2-256f` |
| `slhdsa_shake_128s` | `0x0917` | `SLH-DSA-SHAKE-128s` |
| `slhdsa_shake_128f` | `0x0918` | `SLH-DSA-SHAKE-128f` |
| `slhdsa_shake_192s` | `0x0919` | `SLH-DSA-SHAKE-192s` |
| `slhdsa_shake_192f` | `0x091a` | `SLH-DSA-SHAKE-192f` |
| `slhdsa_shake_256s` | `0x091b` | `SLH-DSA-SHAKE-256s` |
| `slhdsa_shake_256f` | `0x091c` | `SLH-DSA-SHAKE-256f` |

The code points follow the IANA TLS SignatureScheme registry entries for
`draft-reddy-tls-slhdsa`.

## Runtime Changes

### `include/internal/tlssigalgs.h`

Adds internal TLS signature scheme constants:

- `TLSEXT_SIGALG_slhdsa_sha2_128s` through
  `TLSEXT_SIGALG_slhdsa_shake_256f`
- matching `TLSEXT_SIGALG_*_name` strings

The code point constants are needed by the provider capability table and the
default signature scheme list. The name macros are convenience definitions; the
patch currently uses literal strings in trace output, so these name macros are
not strictly required for runtime behavior.

### `providers/common/capabilities.c`

Adds `TLS-SIGALG` provider capability entries for the 12 SLH-DSA variants.
This is the core change that makes TLS load SLH-DSA as provider-backed
signature schemes.

For each SLH-DSA scheme, the capability entry supplies:

- TLS IANA name, for example `slhdsa_sha2_128s`
- OpenSSL algorithm name, for example `SLH-DSA-SHA2-128s`
- ASN.1 object identifier, for example `2.16.840.1.101.3.4.3.20`
- TLS SignatureScheme code point
- security bits: 128, 192, or 256
- protocol bounds: TLS 1.3 in the current OpenSSL provider-backed sigalg path
- DTLS disabled with `-1, -1`

The top-level preprocessor guard is extended from ML-DSA/SM2 only to include
`!defined(OPENSSL_NO_SLH_DSA)`.

The existing SM2 entry index is moved from `3` to `15` because the SLH-DSA
entries are inserted after the three ML-DSA entries in the shared constants
array. That index adjustment is required if SLH-DSA and SM2 are both enabled.

### `ssl/t1_lib.c`

Adds all 12 SLH-DSA code points to the default TLS signature algorithm
preference list.

This makes the schemes appear in the default `signature_algorithms` extension
when the corresponding provider algorithms are available. In OpenSSL 4.0,
provider-backed signature schemes can also be appended later by
`ssl_setup_sigalgs()`, so this block is mostly about default advertisement
order and deterministic trace output rather than the provider capability itself.

The current patch places SLH-DSA after RSA PKCS#1 SHA-2 schemes and before
legacy SHA-1/SHA-224 entries. If the experiment should prefer PQ signatures
earlier, these entries can be moved near the existing ML-DSA entries.

## Trace And Test Changes

### `ssl/t1_trce.c`

Adds text names for the SLH-DSA code points to TLS trace output.

This does not affect handshake behavior. Without this change, trace output can
still show the numeric code points, but the names may appear as unknown.

### `test/recipes/75-test_quicapi_data/ssltraceref*.txt`

Updates QUIC API trace reference files so OpenSSL's trace tests expect the new
SLH-DSA schemes in `signature_algorithms`.

These files are test fixtures only.

### `test/recipes/90-test_sslapi_data/ssltraceref*.txt`

Updates SSL API trace reference files for the same reason as the QUIC trace
references.

These files are test fixtures only.

## Minimal Functional Surface

For just enabling SLH-DSA in TLS, the essential parts are:

1. SignatureScheme code point constants in `include/internal/tlssigalgs.h`
2. Provider `TLS-SIGALG` capabilities in `providers/common/capabilities.c`

The following parts are useful but not essential to the runtime enablement:

- default preference-list insertion in `ssl/t1_lib.c`
- human-readable trace names in `ssl/t1_trce.c`
- trace reference fixture updates under `test/recipes/*_data/`

Keeping those optional parts is still reasonable for this repository because
the test harness inspects TLS behavior and trace output while comparing
ML-DSA and SLH-DSA certificate chains.

## Out Of Scope

This patch does not:

- implement SLH-DSA cryptography
- add or regenerate OpenSSL object database entries
- enable SLH-DSA for DTLS
- change certificate generation logic
- change `s_client` or `s_server` command-line parsing
- make the IANA `slhdsa_*` entries recommended; they are currently draft-based
  registry entries
