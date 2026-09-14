#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURE_DIR=${FIXTURE_DIR:-"$ROOT_DIR/fixtures/pki"}
OPENSSL_BUILD_DIR=${OPENSSL_BUILD_DIR:-"$ROOT_DIR/.build/openssl"}
WORK_DIR=${WORK_DIR:-"$ROOT_DIR/.work/bench-tls"}
CODE_PATH=${TLS_CODE_PATH:-c}
REPEAT=${TLS_REPEAT:-5}
OPENSSL_IA32CAP_PORTABLE=${OPENSSL_IA32CAP_PORTABLE:-0:0:0:0:0}
TIMEOUT_SECS=180
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-4443}
ROLE=""
CHAIN_SPEC=""
TLS_GROUP=""
GROUP_NAME=""
ALL_CHAIN_NAMES="ed25519 ed448 ecdsa_p256 ecdsa_p384 ecdsa_p521 mldsa44 mldsa65 mldsa87 slhdsa_sha2_128s slhdsa_sha2_128f slhdsa_sha2_192s slhdsa_sha2_192f slhdsa_sha2_256s slhdsa_sha2_256f slhdsa_shake_128s slhdsa_shake_128f slhdsa_shake_192s slhdsa_shake_192f slhdsa_shake_256s slhdsa_shake_256f"
ALL_GROUP_NAMES="x25519 x448 secp256r1 secp384r1 secp521r1 mlkem512 mlkem768 mlkem1024 x25519_mlkem768 secp256r1_mlkem768 secp384r1_mlkem1024 ntruplus768 ntruplus864 ntruplus1152 x25519_ntruplus864 secp256r1_ntruplus864 secp384r1_ntruplus1152"
PQC_GROUP_NAMES="mlkem512 mlkem768 mlkem1024 ntruplus768 ntruplus864 ntruplus1152"

OPENSSL_BIN=${OPENSSL_BIN:-"$OPENSSL_BUILD_DIR/apps/openssl"}
NTRUPLUS_PROVIDER_PATH=${NTRUPLUS_PROVIDER_PATH:-"$ROOT_DIR/.build/ntruplus-provider"}
export NTRUPLUS_PROVIDER_PATH

usage() {
    cat <<EOF
Usage: $0 --role server|client [--code-path PATH] [--repeat N] [--group GROUP] --chain CHAIN

Options:
  --role ROLE       Run as server or client.
  --chain CHAIN     Certificate chain algorithm.
  --group GROUP     TLS group, pqc, or all. Required for the client.
  --code-path PATH  Use c, auto, or avx2. Default: $CODE_PATH
  --repeat N        Client handshakes per group. Default: $REPEAT
  -h, --help        Show this help.

Chains:
  $ALL_CHAIN_NAMES

Groups:
  all pqc $ALL_GROUP_NAMES
  pqc selects the paper's six standalone KEM groups:
    $PQC_GROUP_NAMES
  Select the signature algorithm separately with --chain.

Environment:
  OPENSSL_BUILD_DIR="$OPENSSL_BUILD_DIR"
  OPENSSL_BIN="$OPENSSL_BIN"
  FIXTURE_DIR="$FIXTURE_DIR"
  WORK_DIR="$WORK_DIR"
  NTRUPLUS_PROVIDER_PATH="$NTRUPLUS_PROVIDER_PATH"
  TLS_CODE_PATH=$CODE_PATH
  TLS_REPEAT=$REPEAT
  OPENSSL_IA32CAP_PORTABLE=$OPENSSL_IA32CAP_PORTABLE
  HOST=$HOST
  PORT=$PORT

Server example:
  HOST=0.0.0.0 $0 --role server \\
    --code-path c \\
    --group pqc \\
    --chain slhdsa_shake_256s

Client example:
  HOST=<server-ip> $0 --role client \\
    --code-path c \\
    --repeat 100 \\
    --group pqc \\
    --chain slhdsa_shake_256s
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --role)
            ROLE=$2
            shift
            ;;
        --chain)
            CHAIN_SPEC=$2
            shift
            ;;
        --group)
            TLS_GROUP=$2
            shift
            ;;
        --code-path)
            CODE_PATH=$2
            shift
            ;;
        --repeat)
            REPEAT=$2
            shift
            ;;
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

if [ "$ROLE" != "server" ] && [ "$ROLE" != "client" ]; then
    echo "--role must be server or client" >&2
    exit 2
fi
if [ -z "$CHAIN_SPEC" ]; then
    echo "--chain is required" >&2
    exit 2
fi
if [ -z "$TLS_GROUP" ]; then
    if [ "$ROLE" = "server" ]; then
        TLS_GROUP=all
    else
        echo "--group is required with --role client" >&2
        exit 2
    fi
fi
case "$REPEAT" in
    ''|*[!0-9]*)
        echo "--repeat must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "$REPEAT" -lt 1 ]; then
    echo "--repeat must be a positive integer" >&2
    exit 2
fi
if [ ! -x "$OPENSSL_BIN" ]; then
    echo "OpenSSL binary not found: $OPENSSL_BIN" >&2
    exit 1
fi
apply_code_path() {
    case "$CODE_PATH" in
        c|portable)
            CODE_PATH=c
            NTRUPLUS_CODE_PATH=c
            OPENSSL_ia32cap=$OPENSSL_IA32CAP_PORTABLE
            export NTRUPLUS_CODE_PATH OPENSSL_ia32cap
            ;;
        auto|native)
            CODE_PATH=auto
            NTRUPLUS_CODE_PATH=auto
            export NTRUPLUS_CODE_PATH
            ;;
        avx2)
            CODE_PATH=avx2
            NTRUPLUS_CODE_PATH=avx2
            export NTRUPLUS_CODE_PATH
            ;;
        *)
            echo "Unknown --code-path: $CODE_PATH" >&2
            echo "Expected one of: c, auto, avx2" >&2
            exit 2
            ;;
    esac
}

apply_code_path

if [ ! -f "$NTRUPLUS_PROVIDER_PATH/ntruplus.so" ]; then
    echo "ntruplus provider not found: $NTRUPLUS_PROVIDER_PATH/ntruplus.so" >&2
    echo "Build it with:" >&2
    echo "  cmake --build \"$NTRUPLUS_PROVIDER_PATH\" --target ntruplus_provider" >&2
    echo "or set NTRUPLUS_PROVIDER_PATH to the directory containing ntruplus.so." >&2
    exit 1
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

normalize_tls_group() {
    case "$1" in
        x25519|X25519)
            printf '%s\n' X25519
            ;;
        x448|X448)
            printf '%s\n' X448
            ;;
        secp256r1|SecP256r1)
            printf '%s\n' SecP256r1
            ;;
        secp384r1|SecP384r1)
            printf '%s\n' SecP384r1
            ;;
        secp521r1|SecP521r1)
            printf '%s\n' SecP521r1
            ;;
        mlkem512|MLKEM512)
            printf '%s\n' MLKEM512
            ;;
        mlkem768|MLKEM768)
            printf '%s\n' MLKEM768
            ;;
        mlkem1024|MLKEM1024)
            printf '%s\n' MLKEM1024
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
            echo "Unknown TLS group: $1" >&2
            exit 2
            ;;
    esac
}

normalize_group_name() {
    printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]'
}

selected_group_names() {
    case "$1" in
        all) printf '%s\n' "$ALL_GROUP_NAMES" ;;
        pqc) printf '%s\n' "$PQC_GROUP_NAMES" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

tls_group_list() {
    local group=$1 result="" item tls_group

    for item in $(selected_group_names "$group"); do
        tls_group=$(normalize_tls_group "$item") || return $?
        if [ -z "$result" ]; then
            result=$tls_group
        else
            result="$result:$tls_group"
        fi
    done
    printf '%s\n' "$result"
}

set_chain_from_alias() {
    chain_name=$1
    root_tls=$1

    case "$chain_name" in
        ed25519)
            root_alg=ED25519
            ;;
        ed448)
            root_alg=ED448
            ;;
        ecdsa_p256)
            root_alg=ECDSA-P256
            root_tls=ecdsa_secp256r1_sha256
            ;;
        ecdsa_p384)
            root_alg=ECDSA-P384
            root_tls=ecdsa_secp384r1_sha384
            ;;
        ecdsa_p521)
            root_alg=ECDSA-P521
            root_tls=ecdsa_secp521r1_sha512
            ;;
        mldsa44|mldsa65|mldsa87)
            root_alg=ML-DSA-${chain_name#mldsa}
            ;;
        slhdsa_sha2_*|slhdsa_shake_*)
            root_alg=$(printf '%s\n' "$chain_name" \
                | sed -E 's/^slhdsa_/SLH-DSA-/; s/_/-/g; s/sha2/SHA2/; s/shake/SHAKE/')
            ;;
        *)
            echo "Unknown chain alias: $chain_name" >&2
            exit 2
            ;;
    esac

    int_alg=$root_alg
    int_tls=$root_tls
    server_alg=$root_alg
    server_tls=$root_tls
}

root_fixture_stem() {
    printf '%s\n' "$1" \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//'
}

root_fixture_path() {
    local alg=$1 ext=$2 stem
    stem=$(root_fixture_stem "$alg")
    printf '%s/pqc-test-root-%s.%s\n' "$FIXTURE_DIR" "$stem" "$ext"
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

chain_metadata() {
    printf 'name=%s\n' "$1"
    printf 'root_alg=%s\n' "$2"
    printf 'int_alg=%s\n' "$3"
    printf 'server_alg=%s\n' "$4"
}

chain_is_reusable() {
    local name=$1 root_alg=$2 int_alg=$3 server_alg=$4 out_dir=$5
    local expected actual file fixture_root_cert

    for file in .chain-meta root.crt root.key intermediate.crt intermediate.key server.crt server.key chain.crt; do
        [ -f "$out_dir/$file" ] || return 1
    done

    expected=$(chain_metadata "$name" "$root_alg" "$int_alg" "$server_alg")
    actual=$(cat "$out_dir/.chain-meta")
    [ "$actual" = "$expected" ] || return 1

    fixture_root_cert=$(root_fixture_path "$root_alg" crt)
    [ -f "$fixture_root_cert" ] || return 1
    cmp -s "$fixture_root_cert" "$out_dir/root.crt" || return 1

    "$OPENSSL_BIN" verify -CAfile "$out_dir/root.crt" \
        -untrusted "$out_dir/intermediate.crt" \
        "$out_dir/server.crt" >/dev/null 2>&1
}

make_chain() {
    local name=$1 root_alg=$2 int_alg=$3 server_alg=$4 out_dir=$5
    local root_cert root_key

    if chain_is_reusable "$name" "$root_alg" "$int_alg" "$server_alg" "$out_dir"; then
        echo "Reusing 3-level chain: $name"
        return
    fi

    echo "Generating 3-level chain: $name"
    rm -rf "$out_dir"
    mkdir -p "$out_dir"

    root_cert=$(root_fixture_path "$root_alg" crt)
    root_key=$(root_fixture_path "$root_alg" key)
    if [ ! -f "$root_cert" ] || [ ! -f "$root_key" ]; then
        echo "Fixture root files not found for $root_alg: $root_cert / $root_key" >&2
        exit 1
    fi
    cp "$root_cert" "$out_dir/root.crt"
    cp "$root_key" "$out_dir/root.key"

    gen_key "$int_alg" "$out_dir/intermediate.key"
    "$OPENSSL_BIN" req -new -key "$out_dir/intermediate.key" -out "$out_dir/intermediate.csr" \
        -subj "/CN=$name Intermediate CA" >/dev/null
    "$OPENSSL_BIN" x509 -req -in "$out_dir/intermediate.csr" \
        -CA "$out_dir/root.crt" -CAkey "$out_dir/root.key" -CAcreateserial \
        -out "$out_dir/intermediate.crt" -days 2 \
        -extfile <(printf '%s\n' '[v3_ca]' \
            'basicConstraints=critical,CA:true,pathlen:0' \
            'keyUsage=critical,keyCertSign,cRLSign' \
            'subjectKeyIdentifier=hash' \
            'authorityKeyIdentifier=keyid,issuer') \
        -extensions v3_ca >/dev/null

    gen_key "$server_alg" "$out_dir/server.key"
    "$OPENSSL_BIN" req -new -key "$out_dir/server.key" -out "$out_dir/server.csr" \
        -subj "/CN=localhost" >/dev/null
    "$OPENSSL_BIN" x509 -req -in "$out_dir/server.csr" \
        -CA "$out_dir/intermediate.crt" -CAkey "$out_dir/intermediate.key" -CAcreateserial \
        -out "$out_dir/server.crt" -days 2 \
        -extfile <(printf '%s\n' '[server_cert]' \
            'basicConstraints=critical,CA:false' \
            'keyUsage=critical,digitalSignature' \
            'extendedKeyUsage=serverAuth' \
            'subjectAltName=DNS:localhost,IP:127.0.0.1' \
            'subjectKeyIdentifier=hash' \
            'authorityKeyIdentifier=keyid,issuer') \
        -extensions server_cert >/dev/null

    cp "$out_dir/intermediate.crt" "$out_dir/chain.crt"
    "$OPENSSL_BIN" verify -CAfile "$out_dir/root.crt" \
        -untrusted "$out_dir/intermediate.crt" "$out_dir/server.crt" >/dev/null
    chain_metadata "$name" "$root_alg" "$int_alg" "$server_alg" > "$out_dir/.chain-meta"
}

ensure_client_root() {
    local chain_dir=$1 root_alg=$2
    local root_cert

    root_cert=$(root_fixture_path "$root_alg" crt)
    if [ ! -f "$root_cert" ]; then
        echo "Root certificate not found: $root_cert" >&2
        exit 1
    fi
    if [ -f "$chain_dir/root.crt" ] \
        && cmp -s "$root_cert" "$chain_dir/root.crt"; then
        return
    fi
    mkdir -p "$chain_dir"
    cp "$root_cert" "$chain_dir/root.crt"
}

port_listener_lines() {
    local port=$1
    command -v ss >/dev/null 2>&1 || return 1
    ss -ltnp 2>/dev/null \
        | awk -v port="$port" '$1 == "LISTEN" {
              n = split($4, addr, ":")
              if (addr[n] == port) print
          }'
}

port_is_listening() {
    [ -n "$(port_listener_lines "$1")" ]
}

now_ns() {
    date +%s%N
}

elapsed_ms() {
    printf '%s\n' "$((($2 - $1) / 1000000))"
}

stop_benchmark() {
    echo "Interrupted; stopping benchmark." >&2
    exit 130
}

is_interrupt_status() {
    case "$1" in
        130|143)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

trap stop_benchmark INT TERM

negotiated_group_ok() {
    local log_file=$1 group=$2

    if grep -q "Negotiated TLS1.3 group: $group" "$log_file"; then
        return 0
    fi

    case "$group" in
        X25519) grep -q 'Peer Temp Key: X25519' "$log_file" ;;
        X448) grep -q 'Peer Temp Key: X448' "$log_file" ;;
        SecP256r1) grep -q 'Peer Temp Key: ECDH, prime256v1' "$log_file" ;;
        SecP384r1) grep -q 'Peer Temp Key: ECDH, secp384r1' "$log_file" ;;
        SecP521r1) grep -q 'Peer Temp Key: ECDH, secp521r1' "$log_file" ;;
        *) return 0 ;;
    esac
}

summarize_times() {
    local times_file=$1 pass_count=$2
    local avg_ms min_ms max_ms median_ms

    if [ "$pass_count" -eq 0 ]; then
        printf 'NA\tNA\tNA\tNA\n'
        return
    fi

    read -r avg_ms min_ms max_ms < <(
        awk '
            NR == 1 { min = max = $1 }
            {
                sum += $1
                if ($1 < min) min = $1
                if ($1 > max) max = $1
            }
            END { printf "%.1f %s %s\n", sum / NR, min, max }
        ' "$times_file"
    )
    median_ms=$(
        sort -n "$times_file" \
            | awk -v n="$pass_count" '
                NR == int((n + 1) / 2) { a = $1 }
                NR == int((n + 2) / 2) { b = $1 }
                END {
                    if (n % 2) {
                        printf "%s", a
                    } else {
                        printf "%.1f", (a + b) / 2
                    }
                }
            '
    )

    printf '%s\t%s\t%s\t%s\n' "$avg_ms" "$median_ms" "$min_ms" "$max_ms"
}

run_server() {
    local group=$1 sigalgs=$2 chain_dir=$3 log_file=$4

    if port_is_listening "$PORT"; then
        echo "Port already in use: $PORT" >&2
        port_listener_lines "$PORT" >&2
        exit 1
    fi

    echo "Serving $chain_name $GROUP_NAME"
    echo "Code path: $CODE_PATH"
    echo "TLS key log: $KEYLOG_FILE"
    echo "Stop with Ctrl+C when client benchmarking is done."
    exec "$OPENSSL_BIN" s_server \
        -accept "$HOST:$PORT" \
        -cert "$chain_dir/server.crt" \
        -key "$chain_dir/server.key" \
        -cert_chain "$chain_dir/chain.crt" \
        -tls1_3 \
        -groups "$group" \
        -sigalgs "$sigalgs" \
        -keylogfile "$KEYLOG_FILE" \
        -www 2>&1 | tee "$log_file"
}

run_client_group() {
    local group_name=$1 sigalgs=$2 chain_dir=$3 results=$4 summary=$5
    local tls_group run_dir client_log times_file status start_ns end_ns
    local handshake_ms run failed=0 passed=0 avg_ms median_ms min_ms max_ms

    tls_group=$(normalize_tls_group "$group_name")
    run_dir="$WORK_DIR/runs/${chain_name}_${CODE_PATH}_${group_name}"
    mkdir -p "$run_dir"
    times_file="$run_dir/times.ms"
    : > "$times_file"

    for ((run = 1; run <= REPEAT; run++)); do
        client_log=$(printf '%s/client_%03d.log' "$run_dir" "$run")
        status=1
        handshake_ms=0

        printf '%-8s %-24s %-24s %4d/%-4d\n' \
            "CONNECT" "$chain_name" "$group_name" "$run" "$REPEAT"
        start_ns=$(now_ns)
        set +e
        printf 'GET / HTTP/1.0\r\n\r\n' | timeout "$TIMEOUT_SECS"s "$OPENSSL_BIN" s_client \
            -connect "$HOST:$PORT" \
            -servername localhost \
            -verify_hostname localhost \
            -verify_depth 3 \
            -verify_return_error \
            -tls1_3 \
            -groups "$tls_group" \
            -sigalgs "$sigalgs" \
            -CAfile "$chain_dir/root.crt" \
            -keylogfile "$KEYLOG_FILE" \
            -brief >"$client_log" 2>&1
        status=$?
        set -e
        end_ns=$(now_ns)
        handshake_ms=$(elapsed_ms "$start_ns" "$end_ns")

        if is_interrupt_status "$status"; then
            echo "Interrupted during $group_name run $run/$REPEAT." >&2
            exit "$status"
        fi

        if [ "$status" -eq 0 ] \
            && grep -q 'Verification: OK' "$client_log" \
            && grep -q "Signature type: $server_tls" "$client_log" \
            && negotiated_group_ok "$client_log" "$tls_group"; then
            printf 'PASS\t%s\t%s\t%s\t%d\t%s\n' \
                "$chain_name" "$group_name" "$CODE_PATH" "$run" "$handshake_ms" >> "$results"
            printf '%-8s %-24s %-24s %4d/%-4d %8s ms\n' \
                "PASS" "$chain_name" "$group_name" "$run" "$REPEAT" "$handshake_ms"
            printf '%s\n' "$handshake_ms" >> "$times_file"
            passed=$((passed + 1))
            continue
        fi

        printf 'FAIL\t%s\t%s\t%s\t%d\t%s\n' \
            "$chain_name" "$group_name" "$CODE_PATH" "$run" "$handshake_ms" >> "$results"
        printf '%-8s %-24s %-24s %4d/%-4d %8s ms\n' \
            "FAIL" "$chain_name" "$group_name" "$run" "$REPEAT" "$handshake_ms"
        sed -n '1,120p' "$client_log" >&2
        failed=$((failed + 1))
    done

    read -r avg_ms median_ms min_ms max_ms < <(summarize_times "$times_file" "$passed")
    printf '%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n' \
        "$chain_name" "$group_name" "$CODE_PATH" "$REPEAT" "$passed" "$failed" \
        "$avg_ms" "$median_ms" "$min_ms" "$max_ms" >> "$summary"
    printf '%-8s %-24s %-24s pass=%d/%d avg=%s ms median=%s ms\n' \
        "SUMMARY" "$chain_name" "$group_name" "$passed" "$REPEAT" "$avg_ms" "$median_ms"

    [ "$failed" -eq 0 ]
}

run_client() {
    local sigalgs=$1 chain_dir=$2 results=$3 summary=$4
    local group_name failed=0 total=0

    printf 'result\tchain\tgroup\tcode_path\trun\thandshake_ms\n' > "$results"
    printf 'chain\tgroup\tcode_path\trepeat\tpasses\tfails\tavg_ms\tmedian_ms\tmin_ms\tmax_ms\n' > "$summary"
    printf '%-8s %-24s %-24s %9s %11s\n' "STATUS" "CHAIN" "GROUP" "RUN" "TIME"
    echo "Code path: $CODE_PATH"
    echo "Repeat: $REPEAT"

    for group_name in $(selected_group_names "$GROUP_NAME"); do
        total=$((total + 1))
        if ! run_client_group "$group_name" "$sigalgs" "$chain_dir" "$results" "$summary"; then
            failed=$((failed + 1))
        fi
    done

    echo "Results: $results"
    echo "Summary: $summary"
    echo "TLS key log: $KEYLOG_FILE"
    if [ "$failed" -ne 0 ]; then
        echo "Passed: $((total - failed))/$total" >&2
        exit 1
    fi
}

GROUP_NAME=$(normalize_group_name "$TLS_GROUP")
TLS_GROUP=$(tls_group_list "$TLS_GROUP")
set_chain_from_alias "$CHAIN_SPEC"
CHAIN_DIR="$WORK_DIR/chains/$chain_name"
RUN_DIR="$WORK_DIR/runs/${chain_name}_${CODE_PATH}"
KEYLOG_FILE="$WORK_DIR/tls_${chain_name}_${CODE_PATH}.keys"
mkdir -p "$RUN_DIR" "$(dirname "$KEYLOG_FILE")"
SIGALGS="$server_tls:$int_tls:$root_tls"

case "$ROLE" in
    server)
        make_chain "$chain_name" "$root_alg" "$int_alg" "$server_alg" "$CHAIN_DIR"
        run_server "$TLS_GROUP" "$SIGALGS" "$CHAIN_DIR" "$RUN_DIR/server.log"
        ;;
    client)
        ensure_client_root "$CHAIN_DIR" "$root_alg"
        run_client "$SIGALGS" "$CHAIN_DIR" \
            "$WORK_DIR/result_${chain_name}_${CODE_PATH}.tsv" \
            "$WORK_DIR/summary_${chain_name}_${CODE_PATH}.tsv"
        ;;
esac
