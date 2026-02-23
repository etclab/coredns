#!/bin/bash
# Config 7: CODoH full defense stack
# Architecture: Same as Config 4 (3-process IPC)
# Adds: ORAM cache + cover responses + batched insertions + bucketed padding
# This is the production configuration matching the paper's complete design.

CONFIG_NAME="codoh-full"
CONFIG_NUM=7
CONFIG_PROTOCOL="codoh"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    # Start enclave (ORAM cache, full defenses)
    echo "Starting enclave (ORAM N=${CODOH_CACHE_SIZE:-1024}, padding, batching)..."
    if [[ "${SGX_MODE:-false}" == "true" ]]; then
        CODOH_USE_ORAM=true \
        CODOH_CACHE_SIZE="${CODOH_CACHE_SIZE:-1024}" \
        CODOH_PAD_BUCKETS=16384 \
        CODOH_BATCH_SIZE="${CODOH_BATCH_SIZE:-10}" \
        CODOH_BATCH_COMMIT_PROB="${CODOH_BATCH_COMMIT_PROB:-0.1}" \
            ego run "$root_dir/enclave/enclave" \
            > "$output_dir/enclave.log" 2>&1 &
    else
        CODOH_USE_ORAM=true \
        CODOH_CACHE_SIZE="${CODOH_CACHE_SIZE:-1024}" \
        CODOH_PAD_BUCKETS=16384 \
        CODOH_BATCH_SIZE="${CODOH_BATCH_SIZE:-10}" \
        CODOH_BATCH_COMMIT_PROB="${CODOH_BATCH_COMMIT_PROB:-0.1}" \
            "$root_dir/enclave-sim" \
            > "$output_dir/enclave.log" 2>&1 &
    fi
    sleep 2

    echo "Starting CODoH target on port 8443 (covers k=${CODOH_COVER_COUNT:-3})..."
    CODOH_COVER_COUNT="${CODOH_COVER_COUNT:-3}" \
    CODOH_COVER_DOMAIN_FILE="$root_dir/benchmark/top-1k-resolvable.csv" \
    CODOH_PROXY_CALLBACK_URL="https://127.0.0.1:8080" \
    CODOH_COVER_RESOLVER="127.0.0.1:5353" \
    CODOH_COVER_TIMEOUT_MS=2000 \
        "$root_dir/coredns-test" -conf "$root_dir/Corefile.target" \
        > "$output_dir/codoh-target.log" 2>&1 &
    sleep 2

    echo "Starting CODoH proxy on port 8080..."
    "$root_dir/coredns-test" -conf "$root_dir/Corefile.proxy" \
        > "$output_dir/codoh-proxy.log" 2>&1 &
    sleep 2

    HEALTH_URLS="https://127.0.0.1:8080/health https://127.0.0.1:8443/health"
}

client_args() {
    local cert_path=$1 domains_path=$2 iterations=$3 distribution=$4 output_prefix=$5

    echo "--protocol codoh \
        --target 127.0.0.1:8443 \
        --proxy 127.0.0.1:8080 \
        --distribution $distribution \
        --iterations $iterations \
        --customcert $cert_path \
        --domains $domains_path \
        --output ${output_prefix}.csv \
        --summary ${output_prefix}.json"
}
