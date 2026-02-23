#!/bin/bash
# Config 4p: CODoH IPC + bucketed padding (ablation)
# Architecture: Same as Config 4 (3-process IPC, LRU cache)
# Adds: Bucketed wire-layer padding only (no ORAM, no covers, no batching)
# Purpose: Isolate marginal cost of padding mechanism

CONFIG_NAME="codoh-pad"
CONFIG_NUM="4p"
CONFIG_PROTOCOL="codoh"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    # Start enclave (LRU cache + padding)
    echo "Starting enclave (LRU cache, padding bucket=16384)..."
    if [[ "${SGX_MODE:-false}" == "true" ]]; then
        CODOH_PAD_BUCKETS=16384 \
            ego run "$root_dir/enclave/enclave" \
            > "$output_dir/enclave.log" 2>&1 &
    else
        CODOH_PAD_BUCKETS=16384 \
            "$root_dir/enclave-sim" \
            > "$output_dir/enclave.log" 2>&1 &
    fi
    wait_for_enclave_attest

    echo "Starting CODoH target on port 8443..."
    "$root_dir/coredns-test" -conf "$root_dir/Corefile.target" \
        > "$output_dir/codoh-target.log" 2>&1 &
    wait_for_enclave_socket

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
