#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OPENSSL_BUILD_DIR=${OPENSSL_BUILD_DIR:-"$ROOT_DIR/.build/openssl"}
OPENSSL_BIN=${OPENSSL_BIN:-"$OPENSSL_BUILD_DIR/apps/openssl"}
NTRUPLUS_PROVIDER_PATH=${NTRUPLUS_PROVIDER_PATH:-"$ROOT_DIR/.build/ntruplus-provider"}
SECONDS_PER_ALG=3
CODE_PATH=${NTRUPLUS_CODE_PATH:-auto}
OPENSSL_IA32CAP_PORTABLE=${OPENSSL_IA32CAP_PORTABLE:-0:0:0:0:0}
DEFAULT_ALGORITHMS=(
    x25519
    x448
    mlkem512
    mlkem768
    mlkem1024
    x25519_mlkem768
    secp256r1_mlkem768
    secp384r1_mlkem1024
    ntruplus768
    ntruplus864
    ntruplus1152
    x25519_ntruplus864
    secp256r1_ntruplus864
    secp384r1_ntruplus1152
)
ALGORITHMS=("${DEFAULT_ALGORITHMS[@]}")

usage() {
    cat <<EOF
Usage: $0 [--seconds N] [--openssl PATH] [--ntruplus-provider-path DIR] [--code-path PATH] [ALG...]

Defaults:
  seconds:       $SECONDS_PER_ALG
  openssl:       $OPENSSL_BIN
  ntruplus-provider-path: $NTRUPLUS_PROVIDER_PATH
  code-path:     $CODE_PATH
  algorithms:    ${DEFAULT_ALGORITHMS[*]}

Environment:
  OPENSSL_BUILD_DIR
  OPENSSL_BIN
  NTRUPLUS_PROVIDER_PATH
  NTRUPLUS_CODE_PATH
  OPENSSL_IA32CAP_PORTABLE
EOF
}

normalize_code_path() {
    case "$1" in
        auto|AUTO)
            printf '%s\n' auto
            ;;
        c|C)
            printf '%s\n' c
            ;;
        avx2|AVX2)
            printf '%s\n' avx2
            ;;
        *)
            echo "Unknown NTRU+ code path: $1" >&2
            exit 2
            ;;
    esac
}

normalize_algorithm() {
    case "$1" in
        x25519|X25519)
            printf '%s\n' X25519
            ;;
        x448|X448)
            printf '%s\n' X448
            ;;
        mlkem512|MLKEM512|ML-KEM-512)
            printf '%s\n' ML-KEM-512
            ;;
        mlkem768|MLKEM768|ML-KEM-768)
            printf '%s\n' ML-KEM-768
            ;;
        mlkem1024|MLKEM1024|ML-KEM-1024)
            printf '%s\n' ML-KEM-1024
            ;;
        x25519_mlkem768|x25519mlkem768|X25519MLKEM768)
            printf '%s\n' X25519MLKEM768
            ;;
        secp256r1_mlkem768|secp256r1mlkem768|SecP256r1MLKEM768)
            printf '%s\n' SecP256r1MLKEM768
            ;;
        secp384r1_mlkem1024|secp384r1mlkem1024|SecP384r1MLKEM1024)
            printf '%s\n' SecP384r1MLKEM1024
            ;;
        ntruplus768|NTRUPlus768|NTRUPLUS768)
            printf '%s\n' ntruplus768
            ;;
        ntruplus864|NTRUPlus864|NTRUPLUS864)
            printf '%s\n' ntruplus864
            ;;
        ntruplus1152|NTRUPlus1152|NTRUPLUS1152)
            printf '%s\n' ntruplus1152
            ;;
        x25519_ntruplus864|x25519ntruplus864|X25519NTRUPLUS864)
            printf '%s\n' X25519NTRUPLUS864
            ;;
        secp256r1_ntruplus864|secp256r1ntruplus864|SecP256r1NTRUPLUS864)
            printf '%s\n' SecP256r1NTRUPLUS864
            ;;
        secp384r1_ntruplus1152|secp384r1ntruplus1152|SecP384r1NTRUPLUS1152)
            printf '%s\n' SecP384r1NTRUPLUS1152
            ;;
        *)
            echo "Unknown KEM benchmark algorithm: $1" >&2
            exit 2
            ;;
    esac
}

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
        --ntruplus-provider-path)
            NTRUPLUS_PROVIDER_PATH=$2
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
            ALGORITHMS=("$@")
            break
            ;;
        -*)
            usage >&2
            exit 2
            ;;
        *)
            ALGORITHMS=("$@")
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
if [ "${#ALGORITHMS[@]}" -eq 0 ]; then
    echo "at least one algorithm is required" >&2
    exit 2
fi
if [ ! -x "$OPENSSL_BIN" ]; then
    echo "OpenSSL binary not found: $OPENSSL_BIN" >&2
    exit 1
fi
export NTRUPLUS_PROVIDER_PATH
if [ ! -f "$NTRUPLUS_PROVIDER_PATH/ntruplus.so" ]; then
    echo "ntruplus provider not found: $NTRUPLUS_PROVIDER_PATH/ntruplus.so" >&2
    echo "Build it with:" >&2
    echo "  cmake --build \"$NTRUPLUS_PROVIDER_PATH\" --target ntruplus_provider" >&2
    echo "or set NTRUPLUS_PROVIDER_PATH to the directory containing ntruplus.so." >&2
    exit 1
fi

CODE_PATH=$(normalize_code_path "$CODE_PATH")
NTRUPLUS_CODE_PATH=$CODE_PATH
export NTRUPLUS_CODE_PATH
if [ "$CODE_PATH" = c ]; then
    OPENSSL_ia32cap=$OPENSSL_IA32CAP_PORTABLE
    export OPENSSL_ia32cap
fi

if ! PROVIDER_LIST=$("$OPENSSL_BIN" list -providers 2>&1); then
    printf '%s\n' "$PROVIDER_LIST" >&2
    echo "OpenSSL could not load its configured providers." >&2
    exit 1
fi
if ! awk '$1 == "ntruplus" { found = 1 } END { exit !found }' \
    <<< "$PROVIDER_LIST"; then
    printf '%s\n' "$PROVIDER_LIST" >&2
    echo "ntruplus provider is not active through the OpenSSL configuration." >&2
    echo "Check the README Build And Verify steps and the binary's OPENSSLDIR." >&2
    exit 1
fi

OPENSSL_ALGORITHMS=()
for alg in "${ALGORITHMS[@]}"; do
    OPENSSL_ALGORITHMS+=("$(normalize_algorithm "$alg")")
done

printf '\n== NTRUPLUS_CODE_PATH=%s ==\n' "$CODE_PATH"
printf 'OPENSSL_ia32cap=%s\n' "${OPENSSL_ia32cap-<unset: native detection>}"
"$OPENSSL_BIN" speed \
    -seconds "$SECONDS_PER_ALG" \
    -kem-algorithms \
    "${OPENSSL_ALGORITHMS[@]}"
