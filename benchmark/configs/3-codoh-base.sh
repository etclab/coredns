#!/bin/bash
# Config 3: CODoH-base (minimal upgrade from ODoH)
# Architecture: Client → Enclave-Proxy (HTTPS, port 10443) → CODoH Target (port 10444)
# Adds: enclave-based LRU cache, simplified blob (kc + query)
# No tokens, no signatures, no IPC — 2-process architecture
#
# IMPORTANT: This config runs from a pinned git worktree (commit e81a315)
# because proxy mode is not compatible with the current IPC-based codebase.
# The worktree is created by setup.sh at benchmark/worktrees/config3-proxy/
#
# Supports SGX_MODE=true (set by run-all.sh --sgx)

CONFIG_NAME="codoh-base"
CONFIG_NUM=3
CONFIG_PROTOCOL="codoh-base"

# Worktree path for Config 3 binaries
WORKTREE_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/worktrees/config3-proxy"

start_config() {
    local root_dir=$1 cert_path=$2 output_dir=$3

    # Verify worktree exists
    if [[ ! -d "$WORKTREE_DIR" ]]; then
        echo "ERROR: Config 3 worktree not found at $WORKTREE_DIR"
        echo "Run setup.sh to create it (pinned to commit e81a315)"
        return 1
    fi

    # Use worktree binaries
    local wt="$WORKTREE_DIR"

    echo "Starting CODoH-base target on port 10444..."
    "$wt/coredns-test" -conf "$root_dir/benchmark/Corefile.codoh-base-target" \
        > "$output_dir/codoh-base-target.log" 2>&1 &
    sleep 2

    # For SGX: certs must be under /tmp (mounted in enclave.json)
    local enclave_cert="$cert_path"
    local enclave_key="${cert_path%.pem}-key.pem"
    if [[ "${SGX_MODE:-false}" == "true" ]]; then
        cp "$cert_path" /tmp/codoh-bench-cert.pem
        cp "${cert_path%.pem}-key.pem" /tmp/codoh-bench-key.pem
        enclave_cert="/tmp/codoh-bench-cert.pem"
        enclave_key="/tmp/codoh-bench-key.pem"
    fi

    echo "Starting enclave-proxy on port 10443..."
    if [[ "${SGX_MODE:-false}" == "true" ]]; then
        ego run "$wt/enclave/enclave" \
            -mode proxy \
            -https-port 10443 \
            -tls-cert "$enclave_cert" \
            -tls-key "$enclave_key" \
            -target "https://127.0.0.1:10444" \
            > "$output_dir/enclave-proxy.log" 2>&1 &
    else
        "$wt/enclave-sim" \
            -mode proxy \
            -https-port 10443 \
            -tls-cert "$enclave_cert" \
            -tls-key "$enclave_key" \
            -target "https://127.0.0.1:10444" \
            > "$output_dir/enclave-proxy.log" 2>&1 &
    fi

    HEALTH_URLS="https://127.0.0.1:10443/health https://127.0.0.1:10444/health"
}

client_args() {
    local cert_path=$1 domains_path=$2 iterations=$3 distribution=$4 output_prefix=$5

    echo "--protocol codoh-base \
        --target 127.0.0.1:10444 \
        --proxy 127.0.0.1:10443 \
        --distribution $distribution \
        --iterations $iterations \
        --customcert $cert_path \
        --domains $domains_path \
        --output ${output_prefix}.csv \
        --summary ${output_prefix}.json"
}
