#!/bin/bash
# Config 6: CODoH IPC with LRU cache + cover responses
# Architecture: Same as Config 4 (3-process IPC)
# Adds: Cover responses (k=3) for cache-insert indistinguishability

CONFIG_NAME="codoh-cover"
CONFIG_NUM=6
CONFIG_PROTOCOL="codoh"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    # Start enclave (simulation mode, LRU cache)
    echo "Starting enclave (simulation, LRU cache)..."
    "$root_dir/enclave-sim" \
        > "$output_dir/enclave.log" 2>&1 &
    sleep 2

    echo "Starting CODoH target on port 8443 (covers enabled)..."
    CODOH_COVER_COUNT=3 \
    CODOH_COVER_DOMAIN_FILE="$root_dir/benchmark/top-1m.csv" \
    CODOH_PROXY_CALLBACK_URL="https://127.0.0.1:8080" \
    CODOH_COVER_RESOLVER="8.8.8.8:53" \
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
