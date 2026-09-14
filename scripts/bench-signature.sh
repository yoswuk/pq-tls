#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OPENSSL_BUILD_DIR=${OPENSSL_BUILD_DIR:-"$ROOT_DIR/.build/openssl"}
OPENSSL_BIN=${OPENSSL_BIN:-"$OPENSSL_BUILD_DIR/apps/openssl"}
NTRUPLUS_PROVIDER_PATH=${NTRUPLUS_PROVIDER_PATH:-"$ROOT_DIR/.build/ntruplus-provider"}
export NTRUPLUS_PROVIDER_PATH
SECONDS_PER_ALG=3
CODE_PATH=${SIGNATURE_CODE_PATH:-auto}
OPENSSL_IA32CAP_PORTABLE=${OPENSSL_IA32CAP_PORTABLE:-0:0:0:0:0}
DEFAULT_ALGORITHMS=(
    ed25519
    ed448
    ecdsa_p256
    ecdsa_p384
    ecdsa_p521
    mldsa44
    mldsa65
    mldsa87
    slhdsa_sha2_128s
    slhdsa_sha2_128f
    slhdsa_sha2_192s
    slhdsa_sha2_192f
    slhdsa_sha2_256s
    slhdsa_sha2_256f
    slhdsa_shake_128s
    slhdsa_shake_128f
    slhdsa_shake_192s
    slhdsa_shake_192f
    slhdsa_shake_256s
    slhdsa_shake_256f
)

usage() {
    cat <<EOF
Usage: $0 [--seconds N] [--openssl PATH] [--code-path PATH] [ALG...]

Defaults:
  seconds:    $SECONDS_PER_ALG
  openssl:    $OPENSSL_BIN
  code-path:  $CODE_PATH
  algorithms: ${DEFAULT_ALGORITHMS[*]}

Environment:
  OPENSSL_BUILD_DIR
  OPENSSL_BIN
  NTRUPLUS_PROVIDER_PATH
  SIGNATURE_CODE_PATH
  OPENSSL_IA32CAP_PORTABLE
EOF
}

normalize_code_path() {
    case "$1" in
        auto|AUTO|native)
            printf '%s\n' auto
            ;;
        c|C|portable)
            printf '%s\n' c
            ;;
        *)
            echo "Unknown signature code path: $1" >&2
            echo "Expected one of: c, auto" >&2
            exit 2
            ;;
    esac
}

normalize_algorithm() {
    case "$1" in
        ed25519|ED25519)
            printf '%s %s\n' positional ed25519
            ;;
        ed448|ED448)
            printf '%s %s\n' positional ed448
            ;;
        ecdsap256|ecdsa_p256|ECDSA-P256)
            printf '%s %s\n' positional ecdsap256
            ;;
        ecdsap384|ecdsa_p384|ECDSA-P384)
            printf '%s %s\n' positional ecdsap384
            ;;
        ecdsap521|ecdsa_p521|ECDSA-P521)
            printf '%s %s\n' positional ecdsap521
            ;;
        mldsa44|MLDSA44|ML-DSA-44)
            printf '%s %s\n' signature ML-DSA-44
            ;;
        mldsa65|MLDSA65|ML-DSA-65)
            printf '%s %s\n' signature ML-DSA-65
            ;;
        mldsa87|MLDSA87|ML-DSA-87)
            printf '%s %s\n' signature ML-DSA-87
            ;;
        slhdsa_sha2_128s|SLH-DSA-SHA2-128s)
            printf '%s %s\n' signature SLH-DSA-SHA2-128s
            ;;
        slhdsa_sha2_128f|SLH-DSA-SHA2-128f)
            printf '%s %s\n' signature SLH-DSA-SHA2-128f
            ;;
        slhdsa_sha2_192s|SLH-DSA-SHA2-192s)
            printf '%s %s\n' signature SLH-DSA-SHA2-192s
            ;;
        slhdsa_sha2_192f|SLH-DSA-SHA2-192f)
            printf '%s %s\n' signature SLH-DSA-SHA2-192f
            ;;
        slhdsa_sha2_256s|SLH-DSA-SHA2-256s)
            printf '%s %s\n' signature SLH-DSA-SHA2-256s
            ;;
        slhdsa_sha2_256f|SLH-DSA-SHA2-256f)
            printf '%s %s\n' signature SLH-DSA-SHA2-256f
            ;;
        slhdsa_shake_128s|SLH-DSA-SHAKE-128s)
            printf '%s %s\n' signature SLH-DSA-SHAKE-128s
            ;;
        slhdsa_shake_128f|SLH-DSA-SHAKE-128f)
            printf '%s %s\n' signature SLH-DSA-SHAKE-128f
            ;;
        slhdsa_shake_192s|SLH-DSA-SHAKE-192s)
            printf '%s %s\n' signature SLH-DSA-SHAKE-192s
            ;;
        slhdsa_shake_192f|SLH-DSA-SHAKE-192f)
            printf '%s %s\n' signature SLH-DSA-SHAKE-192f
            ;;
        slhdsa_shake_256s|SLH-DSA-SHAKE-256s)
            printf '%s %s\n' signature SLH-DSA-SHAKE-256s
            ;;
        slhdsa_shake_256f|SLH-DSA-SHAKE-256f)
            printf '%s %s\n' signature SLH-DSA-SHAKE-256f
            ;;
        ECDSA|ecdsa)
            echo "ECDSA is ambiguous; use ecdsa_p256, ecdsa_p384, or ecdsa_p521" >&2
            exit 2
            ;;
        *)
            echo "Unknown signature benchmark algorithm: $1" >&2
            exit 2
            ;;
    esac
}

REQUESTED=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --seconds)
            SECONDS_PER_ALG=$2
            shift
            ;;
        --openssl)
            OPENSSL_BIN=$2
            shift
            ;;
        --code-path)
            CODE_PATH=$2
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            REQUESTED=("$@")
            break
            ;;
        -*)
            usage >&2
            exit 2
            ;;
        *)
            REQUESTED=("$@")
            break
            ;;
    esac
    shift
done

case "$SECONDS_PER_ALG" in
    ''|*[!0-9]*)
        echo "--seconds must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "$SECONDS_PER_ALG" -lt 1 ]; then
    echo "--seconds must be positive" >&2
    exit 2
fi
if [ ! -x "$OPENSSL_BIN" ]; then
    echo "OpenSSL binary not found: $OPENSSL_BIN" >&2
    exit 1
fi

CODE_PATH=$(normalize_code_path "$CODE_PATH")
if [ "$CODE_PATH" = c ]; then
    OPENSSL_ia32cap=$OPENSSL_IA32CAP_PORTABLE
    export OPENSSL_ia32cap
fi

if [ "${#REQUESTED[@]}" -eq 0 ]; then
    REQUESTED=("${DEFAULT_ALGORITHMS[@]}")
fi

positional=()
signature=()
for alg in "${REQUESTED[@]}"; do
    normalized_line=$(normalize_algorithm "$alg")
    read -r kind normalized <<< "$normalized_line"
    case "$kind" in
        positional)
            positional+=("$normalized")
            ;;
        signature)
            signature+=("$normalized")
            ;;
    esac
done

printf '\n== signature code path: %s ==\n' "$CODE_PATH"
printf 'OPENSSL_ia32cap=%s\n' "${OPENSSL_ia32cap-<unset: native detection>}"

if [ "${#positional[@]}" -gt 0 ]; then
    "$OPENSSL_BIN" speed -seconds "$SECONDS_PER_ALG" "${positional[@]}"
fi

if [ "${#signature[@]}" -gt 0 ]; then
    "$OPENSSL_BIN" speed \
        -seconds "$SECONDS_PER_ALG" \
        -signature-algorithms \
        "${signature[@]}"
fi
