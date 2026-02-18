#!/bin/bash
# Config 1: DoH (plain DNS-over-HTTPS baseline)
# Architecture: Client → DoH Server (HTTPS)
# No encryption layer, no proxy — RFC 8484 baseline

CONFIG_NAME="doh"
CONFIG_NUM=1
CONFIG_PROTOCOL="doh"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    echo "Starting DoH server on port 7443..."
    "$root_dir/coredns-test" -conf "$root_dir/benchmark/Corefile.doh" \
        > "$output_dir/doh-server.log" 2>&1 &
    sleep 2

    HEALTH_URLS="https://127.0.0.1:7443/health"
}

client_args() {
    local cert_path=$1 domains_path=$2 iterations=$3 distribution=$4 output_prefix=$5

    echo "--protocol doh \
        --target 127.0.0.1:7443 \
        --distribution $distribution \
        --iterations $iterations \
        --customcert $cert_path \
        --domains $domains_path \
        --output ${output_prefix}.csv \
        --summary ${output_prefix}.json"
}
