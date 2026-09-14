#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OPENSSL_SOURCE_DIR=${OPENSSL_SOURCE_DIR:-"$ROOT_DIR/openssl"}
PATCH_FILE="$ROOT_DIR/patches/openssl/ntruplus-provider-config.patch"

usage() {
    echo "Usage: $0"
}

if [ "$#" -eq 1 ]; then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
    esac
fi
if [ "$#" -ne 0 ]; then
    usage >&2
    exit 2
fi

if [ ! -f "$PATCH_FILE" ]; then
    echo "Patch file not found: $PATCH_FILE" >&2
    exit 1
fi

if [ ! -f "$OPENSSL_SOURCE_DIR/apps/openssl.cnf" ]; then
    echo "OpenSSL configuration not found at $OPENSSL_SOURCE_DIR/apps/openssl.cnf" >&2
    echo "Run: git submodule update --init --depth=1" >&2
    exit 1
fi

if patch --force --silent --dry-run --reverse -d "$OPENSSL_SOURCE_DIR" -p1 \
    < "$PATCH_FILE" >/dev/null 2>&1; then
    echo "NTRU+ provider is already enabled in $OPENSSL_SOURCE_DIR/apps/openssl.cnf"
    exit 0
fi

patch --force --silent --dry-run --forward -d "$OPENSSL_SOURCE_DIR" -p1 \
    < "$PATCH_FILE"
patch --force --forward -d "$OPENSSL_SOURCE_DIR" -p1 < "$PATCH_FILE"
echo "Enabled NTRU+ provider in $OPENSSL_SOURCE_DIR/apps/openssl.cnf"
