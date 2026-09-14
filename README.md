# OpenSSL SLH-DSA and NTRU+ TLS Support

This repository provides an OpenSSL 4.0.1 setup for TLS 1.3 experiments with
SLH-DSA certificates and standalone and hybrid NTRU+ groups.

The NTRU+ provider source is included directly under `ntruplus-provider/`.
Its six experimental TLS groups use private-use IDs `0xFE30`–`0xFE35`.

## Layout

- `openssl/`: pinned OpenSSL source submodule.
- `ntruplus-provider/`: included provider source, built from this checkout.
- `patches/openssl/`: OpenSSL patches and notes.
- `scripts/enable-openssl-*.sh`: idempotent patch helpers.
- `scripts/bench-*.sh`: TLS, KEM, and signature benchmark helpers.
- `fixtures/pki/`: test-only root CA fixtures. Do not trust them in production.
- `results/seoul-sao-paulo/`: the paper's 5,400 measurements and summary tables.

## Supported Algorithms

### Certificate Chains And Signatures

Non-PQC baselines:

```text
ed25519                 ed448
ecdsa_p256              ecdsa_p384              ecdsa_p521
```

Standalone PQC algorithms:

```text
mldsa44                 mldsa65                 mldsa87
slhdsa_sha2_128s        slhdsa_sha2_128f
slhdsa_sha2_192s        slhdsa_sha2_192f
slhdsa_sha2_256s        slhdsa_sha2_256f
slhdsa_shake_128s       slhdsa_shake_128f
slhdsa_shake_192s       slhdsa_shake_192f
slhdsa_shake_256s       slhdsa_shake_256f
```

### TLS Key Exchange Groups

Non-PQC baselines:

```text
x25519                  x448
secp256r1               secp384r1               secp521r1
```

Standalone PQC groups:

```text
mlkem512                mlkem768                mlkem1024
ntruplus768             ntruplus864             ntruplus1152
```

Hybrid groups (non-PQC + PQC):

```text
x25519_mlkem768         secp256r1_mlkem768      secp384r1_mlkem1024
x25519_ntruplus864      secp256r1_ntruplus864   secp384r1_ntruplus1152
```

By default, the KEM component benchmark runs every listed TLS group except the
standalone `secp256r1`, `secp384r1`, and `secp521r1` baselines.

## Requirements

- Bash and a Linux/GNU userland with `nproc`, `timeout`, `date`, `awk`, `sed`,
  `sort`, and `ss` (iproute2).
- Git with submodule support.
- `patch` for applying the OpenSSL source and provider-configuration changes.
- Perl, `make`, and a GNU or Clang C compiler for building OpenSSL from source.
- CMake 3.18 or newer for `ntruplus-provider`.

## Build And Verify

### Initialize

On both hosts, clone this repository and fetch the pinned OpenSSL source:

```bash
git clone https://github.com/yoswuk/pq-tls.git
cd pq-tls
git submodule update --init --depth=1 -- openssl
```

For an existing checkout, run the `git submodule` command from the repository
root.
The experiment uses OpenSSL **4.0.1** at
`1e963a8680ec78ad2072792c7a1a71f3c530bd2e`. Keep this OpenSSL pin when
reproducing the experiment; `git submodule update --remote` would select
different code.

Set the shared paths used by the remaining commands in each host's shell.
Set them again when opening a new shell:

```bash
export OPENSSL_SOURCE_DIR="$PWD/openssl"
export OPENSSL_BUILD_DIR="$PWD/.build/openssl"
export OPENSSL_BIN="$OPENSSL_BUILD_DIR/apps/openssl"
export OPENSSL_CONF="$OPENSSL_SOURCE_DIR/apps/openssl.cnf"
```

### Enable And Verify SLH-DSA TLS

Apply the SLH-DSA TLS SignatureScheme patch to the OpenSSL source tree:

```bash
./scripts/enable-openssl-slh-dsa-tls.sh
```

Build OpenSSL:

```bash
mkdir -p "$OPENSSL_BUILD_DIR"
(
  cd "$OPENSSL_BUILD_DIR"
  perl "$OPENSSL_SOURCE_DIR/Configure" \
    no-shared \
    --openssldir="$OPENSSL_SOURCE_DIR/apps"
  make -j"$(nproc)"
)
```

`--openssldir` makes `openssl/apps/openssl.cnf` this build's default
configuration.

Verify that the resulting OpenSSL exposes the SLH-DSA TLS signature schemes:

```bash
"$OPENSSL_BIN" list -tls-signature-algorithms
```

### Build, Enable, And Verify the NTRU+ Provider

Set the provider build directory:

```bash
export NTRUPLUS_PROVIDER_PATH="$PWD/.build/ntruplus-provider"
```

Build the included provider source in a separate build directory:

```bash
cmake -S "$PWD/ntruplus-provider" \
  -B "$NTRUPLUS_PROVIDER_PATH" \
  -DCMAKE_BUILD_TYPE=Release \
  -DOpenSSL_DIR="$OPENSSL_BUILD_DIR"
cmake --build "$NTRUPLUS_PROVIDER_PATH" \
  --target ntruplus_provider \
  -j"$(nproc)"
```

Patch OpenSSL's existing configuration file to activate both the default and
NTRU+ providers. The helper is idempotent:

```bash
./scripts/enable-openssl-ntruplus-provider.sh
```

The patch preserves the rest of `openssl/apps/openssl.cnf` and adds these
provider entries:

```ini
[provider_sect]
default = default_sect
ntruplus = ntruplus_sect

[default_sect]
activate = 1

[ntruplus_sect]
module = ${ENV::NTRUPLUS_PROVIDER_PATH}/ntruplus.so
activate = 1
```

`NTRUPLUS_PROVIDER_PATH` must remain exported because
`${ENV::NTRUPLUS_PROVIDER_PATH}` is expanded when each OpenSSL process loads the
configuration. Verify that OpenSSL automatically loads both providers from the
patched default configuration:

```bash
"$OPENSSL_BIN" list -providers
```

Then verify that the loaded provider exposes the NTRU+ TLS groups:

```bash
"$OPENSSL_BIN" list -tls-groups -tls1_3
```

Confirm `"$OPENSSL_BIN" version` reports 4.0.1 on both hosts.

## TLS Benchmark

### Certificate Fixtures (Optional)

Pre-generated test root CA fixtures are stored under `fixtures/pki/`. They
cover the baseline and PQ certificate algorithms used by the benchmark. Only
regenerate them when the fixture set intentionally changes:

```bash
./scripts/generate-pqc-root-ca-fixtures.sh
```

After regeneration, copy the same `fixtures/pki/pqc-test-root-*` files to both
the server and client hosts.

### Run The Benchmark

Run commands from the repository root. The examples use `mldsa44` and the
default port 4443.

Start the server with all supported groups:

```bash
HOST=0.0.0.0 ./scripts/bench-tls.sh --role server --code-path c \
  --group all --chain mldsa44
```

Wait for the server's `ACCEPT` message, then measure the paper's six KEM groups
for the example `mldsa44` chain. Replace `192.0.2.10` with the server address:

```bash
HOST=192.0.2.10 ./scripts/bench-tls.sh --role client --code-path c \
  --group pqc --repeat 100 --chain mldsa44
```

Output and measurement:

The client writes raw measurements to
`.work/bench-tls/result_mldsa44_c.tsv`, group summaries to
`.work/bench-tls/summary_mldsa44_c.tsv`, and individual run logs under
`.work/bench-tls/runs/`. A client run with the same chain and code path replaces
the TSV files, so set a different `WORK_DIR` to preserve each experiment.

The `handshake_ms` column reports the end-to-end elapsed time for each client
run, including process startup, TCP connection setup, TLS negotiation, and the
HTTP exchange. Certificates are generated before measurement. Absolute times
may vary with hardware and network conditions.

Use the following options to run additional benchmark configurations:

#### `--role`

| Value | Description |
| --- | --- |
| `server` | Runs the TLS server |
| `client` | Runs the TLS client and records measurements |

This option is required.

#### `--chain`

| Value | Description |
| --- | --- |
| `CHAIN` | Selects a chain listed under [Certificate Chains And Signatures](#certificate-chains-and-signatures); required on both server and client with the same value |

#### `--group`

| Value | Description |
| --- | --- |
| `all` | Enables or measures all 17 classical, standalone PQC, and hybrid groups |
| `pqc` | Enables or measures the paper's six standalone ML-KEM and NTRU+ groups |
| `GROUP` | Enables or measures one group listed under [TLS Key Exchange Groups](#tls-key-exchange-groups) |

The server uses `all` by default. The client must specify a value.

#### `--code-path`

| Value | Description |
| --- | --- |
| `auto` | Component benchmark default; uses normal CPU dispatch |
| `c` | TLS default; disables OpenSSL x86 acceleration and uses the portable NTRU+ C path |
| `avx2` | Requires the NTRU+ AVX2 implementation; supported by the TLS and KEM benchmarks |

#### `--repeat`

| Value | Description |
| --- | --- |
| `N` | Client connections per selected group; default: 5 |

Use `-h` or `--help` to list supported groups, signature chains, and options.

## Component Benchmarks

Examples:

```bash
./scripts/bench-kem.sh --seconds 3 --code-path c
./scripts/bench-signature.sh --seconds 3 --code-path c
```

### Options

#### `--seconds`

Use this option to change the measurement duration:

| Value | Description |
| --- | --- |
| `N` | Measurement time per algorithm; default: 3 seconds |

Use `--help` to list supported algorithms and path options.
