#!/bin/bash
# Config 4: CODoH with VOPRF tokens (3-process IPC architecture)
# Architecture: Client → CODoH Proxy (port 8080) ↔ Enclave (IPC) → CODoH Target (port 8443)
# Adds: VOPRF tokens, epoch verification, spent set, IPC
# Uses LRU cache (default)

CONFIG_NAME="codoh-token"
CONFIG_NUM=4
CONFIG_PROTOCOL="codoh"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    # Start enclave (simulation mode, LRU cache)
    echo "Starting enclave (simulation, LRU cache)..."
    local secret_hex
    secret_hex=$(cat "$root_dir/dev-master-secret.txt")
    CODOH_MASTER_SECRET=$secret_hex \
        "$root_dir/enclave-sim" \
        > "$output_dir/enclave.log" 2>&1 &
    sleep 2

    echo "Starting CODoH target on port 8443..."
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
