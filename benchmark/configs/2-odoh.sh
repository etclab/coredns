#!/bin/bash
# Config 2: ODoH (Oblivious DNS-over-HTTPS baseline)
# Architecture: Client → ODoH Proxy → ODoH Target
# Standard ODoH — no caching, no enclave

CONFIG_NAME="odoh"
CONFIG_NUM=2
CONFIG_PROTOCOL="odoh"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    echo "Starting ODoH target on port 9443..."
    "$root_dir/coredns-test" -conf "$COREFILE_DIR/Corefile.odoh-target" \
        > "$output_dir/odoh-target.log" 2>&1 &
    sleep 2

    echo "Starting ODoH proxy on port 9080..."
    "$root_dir/coredns-test" -conf "$COREFILE_DIR/Corefile.odoh-proxy" \
        > "$output_dir/odoh-proxy.log" 2>&1 &
    sleep 2

    HEALTH_URLS="https://${PROXY_IP:-127.0.0.1}:9080/health https://${TARGET_IP:-127.0.0.1}:9443/health"
}

client_args() {
    local cert_path=$1 domains_path=$2 iterations=$3 distribution=$4 output_prefix=$5

    echo "--protocol odoh \
        --target ${TARGET_IP:-127.0.0.1}:9443 \
        --proxy ${PROXY_IP:-127.0.0.1}:9080 \
        --distribution $distribution \
        --iterations $iterations \
        --customcert $cert_path \
        --domains $domains_path \
        --output ${output_prefix}.csv \
        --summary ${output_prefix}.json"
}
