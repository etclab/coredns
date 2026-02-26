#!/bin/bash
# Config 4: CODoH full defense stack WITHOUT SGX enclave
# Architecture: 3-process IPC (cache process + proxy + target) — same as Config 5
# Defenses: ORAM cache + cover responses + batched insertions + bucketed padding
#
# Purpose: Isolate SGX overhead. Compare Config 4 (no SGX) vs Config 5 (SGX) to
# measure the performance cost of running the cache inside an SGX enclave.
#
# Differences from Config 5:
#   - Always uses enclave-sim (plain process), never ego run
#   - No attestation server, no provisioning flow
#   - Ed25519 signature verification disabled in enclave-sim (negligible: <1μs/insert)
#   - Target uses Corefile.target-nosgx (no enclave_url directive)

CONFIG_NAME="codoh-nosgx"
CONFIG_NUM=4
CONFIG_PROTOCOL="codoh"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    # Start cache process (plain binary, no SGX — same defenses as Config 5)
    echo "Starting cache process (ORAM N=${CODOH_CACHE_SIZE:-1024}, padding, batching — no SGX)..."
    CODOH_USE_ORAM=true \
    CODOH_CACHE_SIZE="${CODOH_CACHE_SIZE:-1024}" \
    CODOH_PAD_BUCKETS=16384 \
    CODOH_BATCH_SIZE="${CODOH_BATCH_SIZE:-10}" \
    CODOH_BATCH_COMMIT_PROB="${CODOH_BATCH_COMMIT_PROB:-0.1}" \
        "$root_dir/enclave-sim" \
        > "$output_dir/enclave.log" 2>&1 &

    # No wait_for_enclave_attest — sim mode has no attestation server.
    # enclave-sim self-provisions immediately and creates the IPC socket.
    wait_for_enclave_socket

    echo "Starting CODoH target on port 8443 (covers k=${CODOH_COVER_COUNT:-3})..."
    CODOH_COVER_COUNT="${CODOH_COVER_COUNT:-3}" \
    CODOH_COVER_DOMAIN_FILE="$root_dir/benchmark/top-1k-resolvable.csv" \
    CODOH_PROXY_CALLBACK_URL="https://${PROXY_IP:-127.0.0.1}:8080" \
    CODOH_COVER_RESOLVER="$UPSTREAM_RESOLVER" \
    CODOH_COVER_TIMEOUT_MS=2000 \
        "$root_dir/coredns-test" -conf "$COREFILE_DIR/Corefile.target-nosgx" \
        > "$output_dir/codoh-target.log" 2>&1 &
    sleep 2

    echo "Starting CODoH proxy on port 8080..."
    "$root_dir/coredns-test" -conf "$COREFILE_DIR/Corefile.proxy" \
        > "$output_dir/codoh-proxy.log" 2>&1 &
    sleep 2

    HEALTH_URLS="https://${PROXY_IP:-127.0.0.1}:8080/health https://${TARGET_IP:-127.0.0.1}:8443/health"
}

client_args() {
    local cert_path=$1 domains_path=$2 iterations=$3 distribution=$4 output_prefix=$5

    echo "--protocol codoh \
        --target ${TARGET_IP:-127.0.0.1}:8443 \
        --proxy ${PROXY_IP:-127.0.0.1}:8080 \
        --distribution $distribution \
        --iterations $iterations \
        --customcert $cert_path \
        --domains $domains_path \
        --output ${output_prefix}.csv \
        --summary ${output_prefix}.json"
}
