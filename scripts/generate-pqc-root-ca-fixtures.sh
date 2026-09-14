#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OPENSSL_BUILD_DIR=${OPENSSL_BUILD_DIR:-"$ROOT_DIR/.build/openssl"}
FIXTURE_DIR=${FIXTURE_DIR:-"$ROOT_DIR/fixtures/pki"}
NTRUPLUS_PROVIDER_PATH=${NTRUPLUS_PROVIDER_PATH:-"$ROOT_DIR/.build/ntruplus-provider"}

OPENSSL_BIN=${OPENSSL_BIN:-"$OPENSSL_BUILD_DIR/apps/openssl"}
export NTRUPLUS_PROVIDER_PATH

usage() {
    cat <<EOF
Usage: $0

Generate PQC test-suite root CA fixtures under:
  $FIXTURE_DIR

Options:
  -h, --help       Show this help.

Environment:
  OPENSSL_BUILD_DIR="$OPENSSL_BUILD_DIR"
  OPENSSL_BIN="$OPENSSL_BIN"
  FIXTURE_DIR="$FIXTURE_DIR"
  NTRUPLUS_PROVIDER_PATH="$NTRUPLUS_PROVIDER_PATH"
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ ! -x "$OPENSSL_BIN" ]; then
    echo "OpenSSL binary not found: $OPENSSL_BIN" >&2
    exit 1
fi

root_fixture_stem() {
    printf '%s\n' "$1" \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//'
}

gen_key() {
    local alg=$1 out=$2

    case "$alg" in
        ECDSA-P256)
            "$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt group:prime256v1 -out "$out" >/dev/null
            ;;
        ECDSA-P384)
            "$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt group:secp384r1 -out "$out" >/dev/null
            ;;
        ECDSA-P521)
            "$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt group:secp521r1 -out "$out" >/dev/null
            ;;
        *)
            "$OPENSSL_BIN" genpkey -algorithm "$alg" -out "$out" >/dev/null
            ;;
    esac
}

generate_root() {
    local alg=$1 stem key csr crt tmp_dir

    stem=$(root_fixture_stem "$alg")
    key="$FIXTURE_DIR/pqc-test-root-$stem.key"
    csr="$FIXTURE_DIR/pqc-test-root-$stem.csr"
    crt="$FIXTURE_DIR/pqc-test-root-$stem.crt"

    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pqc-root-ca.XXXXXX")

    gen_key "$alg" "$tmp_dir/root.key"
    "$OPENSSL_BIN" req -new -key "$tmp_dir/root.key" -out "$tmp_dir/root.csr" \
        -subj "/CN=PQC Test Root $alg" >/dev/null
    "$OPENSSL_BIN" x509 -req -in "$tmp_dir/root.csr" \
        -signkey "$tmp_dir/root.key" \
        -out "$tmp_dir/root.crt" -days 3650 \
        -extfile <(printf '%s\n' '[v3_ca]' \
            'basicConstraints=critical,CA:true,pathlen:1' \
            'keyUsage=critical,keyCertSign,cRLSign' \
            'subjectKeyIdentifier=hash' \
            'authorityKeyIdentifier=keyid,issuer') \
        -extensions v3_ca >/dev/null

    mkdir -p "$FIXTURE_DIR"
    mv "$tmp_dir/root.key" "$key"
    mv "$tmp_dir/root.crt" "$crt"
    rm -f "$csr"
    rm -rf "$tmp_dir"
    echo "WRITE $stem"
}

for alg in \
    ED25519 \
    ED448 \
    ECDSA-P256 \
    ECDSA-P384 \
    ECDSA-P521 \
    ML-DSA-44 \
    ML-DSA-65 \
    ML-DSA-87 \
    SLH-DSA-SHA2-128s \
    SLH-DSA-SHA2-128f \
    SLH-DSA-SHA2-192s \
    SLH-DSA-SHA2-192f \
    SLH-DSA-SHA2-256s \
    SLH-DSA-SHA2-256f \
    SLH-DSA-SHAKE-128s \
    SLH-DSA-SHAKE-128f \
    SLH-DSA-SHAKE-192s \
    SLH-DSA-SHAKE-192f \
    SLH-DSA-SHAKE-256s \
    SLH-DSA-SHAKE-256f
do
    generate_root "$alg"
done
