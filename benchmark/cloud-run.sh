#!/bin/bash
# CODoH Cloud Benchmark — Cross-VM Orchestrator
#
# Runs from the CLIENT VM. SSH into proxy/target to start processes,
# run benchmarks locally, collect results.
#
# Usage: ./benchmark/cloud-run.sh [--configs 2,3,4] [--resolver cloudflare] [--no-sgx] [--quick|--standard|--full] [--sweep-oram] [--sweep-cover]
#
# Prerequisites:
#   1. Fill in benchmark/cloud-env.local.sh with PROXY_IP, TARGET_IP
#   2. Run cloud-setup.sh on each VM (proxy, target, client)
#   3. Ensure SSH key auth works: ssh $SSH_USER@$PROXY_IP "echo ok"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Load cloud env
if [[ -f "$SCRIPT_DIR/cloud-env.local.sh" ]]; then
    source "$SCRIPT_DIR/cloud-env.local.sh"
else
    echo "ERROR: benchmark/cloud-env.local.sh not found."
    echo "  cp benchmark/cloud-env.sh benchmark/cloud-env.local.sh"
    echo "  # Fill in PROXY_IP and TARGET_IP"
    exit 1
fi

# Validate required vars
if [[ -z "${PROXY_IP:-}" || -z "${TARGET_IP:-}" ]]; then
    echo "ERROR: PROXY_IP and TARGET_IP must be set in cloud-env.local.sh"
    exit 1
fi

# Export for config scripts
export PROXY_IP TARGET_IP

# Defaults
RUN_MODE="standard"
RUN_ID=""
SELECTED_CONFIGS=""
ITERATIONS=10000
WARMUP_QUERIES=0
SELECTED_WORKLOADS="cold,zipf,warm"
ZIPF_S=1.0
SWEEP_ORAM=false
SWEEP_COVER=false
CLEANUP_ONLY=false
: "${SGX_MODE:=true}"
: "${UPSTREAM_RESOLVER:=1.1.1.1:53}"
: "${SSH_USER:=azureuser}"
: "${SSH_KEY:=$HOME/.ssh/id_rsa}"
: "${REMOTE_ROOT:=/home/$SSH_USER/Projects/codoh/coredns}"
RESOLVER="unbound"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --run-id)       RUN_ID="$2"; shift 2 ;;
        --configs)      SELECTED_CONFIGS="$2"; shift 2 ;;
        --workloads)    SELECTED_WORKLOADS="$2"; shift 2 ;;
        --iterations)   ITERATIONS="$2"; shift 2 ;;
        --warmup)       WARMUP_QUERIES="$2"; shift 2 ;;
        --quick)        RUN_MODE="quick"; shift ;;
        --standard)     RUN_MODE="standard"; shift ;;
        --full)         RUN_MODE="full"; shift ;;
        --no-sgx)       SGX_MODE=false; shift ;;
        --sweep-oram)   SWEEP_ORAM=true; shift ;;
        --sweep-cover)  SWEEP_COVER=true; shift ;;
        --zipf-s)       ZIPF_S="$2"; shift 2 ;;
        --resolver)     RESOLVER="$2"; shift 2 ;;
        --cleanup)      CLEANUP_ONLY=true; shift ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--configs 2,3,4] [--quick|--standard|--full] [--no-sgx] [--sweep-oram] [--sweep-cover] [--cleanup] [--resolver cloudflare|google|HOST:PORT]"
            exit 1
            ;;
    esac
done

# Map resolver
case $RESOLVER in
    unbound)    UPSTREAM_RESOLVER="127.0.0.1:5353" ;;
    cloudflare) UPSTREAM_RESOLVER="1.1.1.1:53" ;;
    google)     UPSTREAM_RESOLVER="8.8.8.8:53" ;;
    *)
        if [[ "$RESOLVER" == *:* ]]; then
            UPSTREAM_RESOLVER="$RESOLVER"
        else
            echo "ERROR: Invalid resolver '$RESOLVER'"
            exit 1
        fi
        ;;
esac
export SGX_MODE UPSTREAM_RESOLVER

# Apply mode defaults
case $RUN_MODE in
    quick)
        [[ -z "$SELECTED_CONFIGS" ]] && SELECTED_CONFIGS="2,3,4,5"
        ITERATIONS=50
        WARMUP_QUERIES=10
        SELECTED_WORKLOADS="warm"
        ;;
    standard)
        [[ -z "$SELECTED_CONFIGS" ]] && SELECTED_CONFIGS="1,2,3,4,5"
        ;;
    full)
        [[ -z "$SELECTED_CONFIGS" ]] && SELECTED_CONFIGS="1,2,3,4,5"
        SWEEP_ORAM=true
        SWEEP_COVER=true
        ;;
esac

# Results directory
[[ -z "$RUN_ID" ]] && RUN_ID="cloud_${RUN_MODE}_$(date +%Y%m%d_%H%M%S)"
OUTPUT_BASE="$SCRIPT_DIR/results/$RUN_ID"
OUTPUT_RAW="$OUTPUT_BASE/raw"
COREFILE_DIR="$OUTPUT_BASE/corefiles"
export COREFILE_DIR
mkdir -p "$OUTPUT_RAW" "$COREFILE_DIR" "$OUTPUT_BASE/logs"

# SSH helpers
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"
ssh_proxy()  { ssh $SSH_OPTS "$SSH_USER@$PROXY_IP" "$@"; }
ssh_target() { ssh $SSH_OPTS "$SSH_USER@$TARGET_IP" "$@"; }
scp_to_proxy()  { scp $SSH_OPTS "$1" "$SSH_USER@$PROXY_IP:$2"; }
scp_to_target() { scp $SSH_OPTS "$1" "$SSH_USER@$TARGET_IP:$2"; }
scp_from_proxy()  { scp $SSH_OPTS "$SSH_USER@$PROXY_IP:$1" "$2"; }
scp_from_target() { scp $SSH_OPTS "$SSH_USER@$TARGET_IP:$1" "$2"; }

CLIENT_PATH="$(dirname "$ROOT_DIR")/codoh-client/odoh-client"
CLIENT_PATH_CONFIG3="$(dirname "$ROOT_DIR")/codoh-client/worktrees/config3/odoh-client"
CERT_PATH="$ROOT_DIR/localhost.pem"
DOMAINS_1M="$SCRIPT_DIR/top-10k-resolvable.csv"
DOMAINS_1K="$SCRIPT_DIR/top-1k-resolvable.csv"

IFS=',' read -ra CONFIGS <<< "$SELECTED_CONFIGS"
IFS=',' read -ra WORKLOADS <<< "$SELECTED_WORKLOADS"

# Save metadata
cat > "$OUTPUT_BASE/metadata.json" << METAEOF
{
    "run_id": "$RUN_ID",
    "mode": "cloud_${RUN_MODE}",
    "proxy_ip": "$PROXY_IP",
    "target_ip": "$TARGET_IP",
    "iterations": $ITERATIONS,
    "warmup": $WARMUP_QUERIES,
    "sgx_mode": $SGX_MODE,
    "resolver": "$RESOLVER",
    "upstream_resolver": "$UPSTREAM_RESOLVER",
    "zipf_s": $ZIPF_S,
    "configs": "$SELECTED_CONFIGS",
    "workloads": "$SELECTED_WORKLOADS",
    "sweep_oram": $SWEEP_ORAM,
    "sweep_cover": $SWEEP_COVER,
    "timestamp": "$(date -Iseconds)",
    "client_hostname": "$(hostname)"
}
METAEOF

echo "=== CODoH Cloud Benchmark ($RUN_MODE mode) ==="
echo "Proxy:      $PROXY_IP"
echo "Target:     $TARGET_IP"
echo "Configs:    $SELECTED_CONFIGS"
echo "Workloads:  $SELECTED_WORKLOADS"
echo "Iterations: $ITERATIONS (+ $WARMUP_QUERIES warmup)"
echo "Resolver:   $RESOLVER ($UPSTREAM_RESOLVER)"
echo "SGX mode:   $SGX_MODE"
$SWEEP_ORAM && echo "Sweep ORAM: N=256,512,2048"
$SWEEP_COVER && echo "Sweep Cover: k=1,5"
echo "Output:     $OUTPUT_BASE/"
echo ""

#######################################
# Verify SSH connectivity
#######################################
echo "=== Verifying SSH connectivity ==="
if ! ssh_proxy "echo ok" > /dev/null 2>&1; then
    echo "ERROR: Cannot SSH to proxy ($PROXY_IP)"
    exit 1
fi
echo "  Proxy SSH: OK"

if ! ssh_target "echo ok" > /dev/null 2>&1; then
    echo "ERROR: Cannot SSH to target ($TARGET_IP)"
    exit 1
fi
echo "  Target SSH: OK"
echo ""

#######################################
# Generate Corefiles with IP substitutions
#######################################
generate_corefiles() {
    echo "=== Generating Corefiles ==="

    # Copy templates and substitute IPs
    for cf in "$SCRIPT_DIR/Corefile.doh" "$SCRIPT_DIR/Corefile.odoh-target" \
              "$SCRIPT_DIR/Corefile.odoh-proxy" "$SCRIPT_DIR/Corefile.codoh-base-target" \
              "$SCRIPT_DIR/Corefile.target-nosgx" \
              "$ROOT_DIR/Corefile.target" "$ROOT_DIR/Corefile.proxy"; do
        [[ -f "$cf" ]] || continue
        local basename
        basename=$(basename "$cf")

        # Start with upstream resolver substitution
        sed "s|127\.0\.0\.1:5353|$UPSTREAM_RESOLVER|g" "$cf" > "$COREFILE_DIR/$basename"

        # Corefile-specific IP substitutions for cross-VM
        case "$basename" in
            Corefile.target)
                # enclave_url points to proxy VM (enclave attestation)
                sed -i "s|https://127\.0\.0\.1:8444|https://$PROXY_IP:8444|g" "$COREFILE_DIR/$basename"
                ;;
            Corefile.proxy)
                # target points to target VM
                sed -i "s|https://127\.0\.0\.1:8443|https://$TARGET_IP:8443|g" "$COREFILE_DIR/$basename"
                ;;
            Corefile.odoh-proxy)
                # target points to target VM
                sed -i "s|https://127\.0\.0\.1:9443|https://$TARGET_IP:9443|g" "$COREFILE_DIR/$basename"
                ;;
        esac
    done

    echo "  Generated $(ls "$COREFILE_DIR" | wc -l) Corefiles in $COREFILE_DIR/"
}

#######################################
# Distribute files to VMs
#######################################
distribute_files() {
    echo "=== Distributing files to VMs ==="

    # Certs: copy proxy's cert to target and client (for TLS verification)
    echo "  Fetching proxy cert..."
    scp_from_proxy "$REMOTE_ROOT/localhost.pem" "$ROOT_DIR/localhost.pem"
    scp_from_proxy "$REMOTE_ROOT/localhost-key.pem" "$ROOT_DIR/localhost-key.pem"

    # Send proxy cert to target too (target needs it to verify proxy connections)
    echo "  Sending proxy cert to target..."
    scp_to_target "$ROOT_DIR/localhost.pem" "$REMOTE_ROOT/localhost.pem"
    scp_to_target "$ROOT_DIR/localhost-key.pem" "$REMOTE_ROOT/localhost-key.pem"

    # Send Corefiles to proxy VM
    echo "  Sending Corefiles to proxy..."
    ssh_proxy "mkdir -p $REMOTE_ROOT/benchmark/cloud-corefiles"
    for cf in "$COREFILE_DIR"/Corefile.*; do
        [[ -f "$cf" ]] || continue
        scp_to_proxy "$cf" "$REMOTE_ROOT/benchmark/cloud-corefiles/$(basename "$cf")"
    done

    # Send Corefiles to target VM
    echo "  Sending Corefiles to target..."
    ssh_target "mkdir -p $REMOTE_ROOT/benchmark/cloud-corefiles"
    for cf in "$COREFILE_DIR"/Corefile.*; do
        [[ -f "$cf" ]] || continue
        scp_to_target "$cf" "$REMOTE_ROOT/benchmark/cloud-corefiles/$(basename "$cf")"
    done

    echo "  Distribution complete."
}

#######################################
# Remote process management
#######################################
remote_cleanup() {
    echo "Cleaning up remote processes..."
    # Kill by port first (most reliable), then by name.
    # IMPORTANT: avoid pkill -f with patterns that appear in this command string,
    # otherwise pkill kills the bash shell running this cleanup (self-kill).
    ssh_proxy 'for port in 8080 8443 8444 10443; do \
                   lsof -ti :$port 2>/dev/null | xargs -r kill -9 2>/dev/null; \
               done; \
               pkill -9 coredns-test 2>/dev/null; \
               pkill -9 enclave-sim 2>/dev/null; \
               killall -9 ego-host 2>/dev/null; \
               rm -f /tmp/codoh-enclave.sock; \
               sleep 3; \
               for port in 8444 8080 8443; do \
                   lsof -ti :$port 2>/dev/null | xargs -r kill -9 2>/dev/null; \
               done; \
               true' 2>/dev/null || true
    ssh_target 'pkill -9 coredns-test 2>/dev/null; true' 2>/dev/null || true
    sleep 2
}

trap remote_cleanup EXIT

# --cleanup: just clean up and exit
if $CLEANUP_ONLY; then
    remote_cleanup
    echo "Done."
    trap - EXIT
    exit 0
fi

# Flush Unbound cache on target VM (between workloads for clean measurements)
flush_unbound_cache() {
    if [[ "$RESOLVER" == "unbound" ]]; then
        echo "  Flushing Unbound cache on target..."
        if ! ssh_target "sudo unbound-control flush_zone . 2>/dev/null"; then
            echo "  WARNING: Failed to flush Unbound cache (unbound-control not available?)"
        fi
    fi
}

# Wait for a remote port to be reachable from this client
wait_for_remote() {
    local host=$1 port=$2 max_wait=${3:-60}
    echo "  Waiting for $host:$port (up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if curl -sk "https://$host:$port/health" > /dev/null 2>&1; then
            echo "  $host:$port ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: $host:$port not ready after ${max_wait}s"
    return 1
}

# Wait for enclave attestation on proxy VM
wait_for_remote_attest() {
    local max_wait=${1:-60}
    echo "  Waiting for enclave attestation ($PROXY_IP:8444, up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if curl -sk "https://$PROXY_IP:8444/attest" > /dev/null 2>&1; then
            echo "  Enclave attestation ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: Enclave attestation not ready after ${max_wait}s"
    return 1
}

# Wait for IPC socket on proxy VM (via SSH check)
wait_for_remote_socket() {
    local max_wait=${1:-30}
    echo "  Waiting for enclave IPC socket on proxy (up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if ssh_proxy "test -S /tmp/codoh-enclave.sock" 2>/dev/null; then
            echo "  IPC socket ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: IPC socket not found after ${max_wait}s"
    return 1
}

#######################################
# Config-specific startup
#######################################
CLOUD_CF="$REMOTE_ROOT/benchmark/cloud-corefiles"

start_config_1() {
    echo "--- Starting Config 1: DoH ---"

    # Target VM: DoH server (single process, no proxy)
    echo "  Starting DoH server on $TARGET_IP:7443..."
    ssh_target "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.doh \
        > /tmp/bench-doh-server.log 2>&1 </dev/null &)"

    wait_for_remote "$TARGET_IP" 7443
}

start_config_2() {
    echo "--- Starting Config 2: ODoH ---"

    # Target VM: ODoH target
    echo "  Starting ODoH target on $TARGET_IP:9443..."
    ssh_target "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.odoh-target \
        > /tmp/bench-odoh-target.log 2>&1 </dev/null &)"

    # Proxy VM: ODoH proxy
    echo "  Starting ODoH proxy on $PROXY_IP:9080..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.odoh-proxy \
        > /tmp/bench-odoh-proxy.log 2>&1 </dev/null &)"

    wait_for_remote "$PROXY_IP" 9080
    wait_for_remote "$TARGET_IP" 9443
}

start_config_3() {
    echo "--- Starting Config 3: CODoH-base ---"
    local wt="$REMOTE_ROOT/benchmark/worktrees/config3-proxy"

    # Target VM: CODoH-base target (worktree binary)
    echo "  Starting CODoH-base target on $TARGET_IP:10444..."
    ssh_target "cd $wt && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.codoh-base-target \
        > /tmp/bench-codoh-base-target.log 2>&1 </dev/null &)"

    # Proxy VM: enclave-proxy
    local enclave_bin="$wt/enclave-sim"
    if [[ "$SGX_MODE" == "true" ]]; then
        enclave_bin="ego run $wt/enclave/enclave"
        # Copy certs to /tmp for SGX
        ssh_proxy "cp $REMOTE_ROOT/localhost.pem /tmp/codoh-bench-cert.pem; \
                   cp $REMOTE_ROOT/localhost-key.pem /tmp/codoh-bench-key.pem"
    fi
    local cert_flag key_flag
    if [[ "$SGX_MODE" == "true" ]]; then
        cert_flag="/tmp/codoh-bench-cert.pem"
        key_flag="/tmp/codoh-bench-key.pem"
    else
        cert_flag="$REMOTE_ROOT/localhost.pem"
        key_flag="$REMOTE_ROOT/localhost-key.pem"
    fi

    echo "  Starting enclave-proxy on $PROXY_IP:10443..."
    ssh_proxy "cd $wt && (nohup $enclave_bin \
        -mode proxy \
        -https-port 10443 \
        -tls-cert $cert_flag \
        -tls-key $key_flag \
        -target https://$TARGET_IP:10444 \
        > /tmp/bench-enclave-proxy.log 2>&1 </dev/null &)"

    wait_for_remote "$PROXY_IP" 10443
    wait_for_remote "$TARGET_IP" 10444
}

start_config_4() {
    local enclave_env="$1"
    local target_env="$2"
    echo "--- Starting Config 4: CODoH no-SGX ---"

    # Proxy VM: enclave-sim (always plain binary, no SGX)
    local enclave_cmd="$enclave_env $REMOTE_ROOT/enclave-sim"

    echo "  Starting enclave-sim on proxy VM..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup bash -c '$enclave_cmd' > /tmp/bench-enclave.log 2>&1 </dev/null &)"
    wait_for_remote_socket 30

    # Target VM: codohtarget (no-SGX variant — no attestation)
    echo "  Starting CODoH target on $TARGET_IP:8443..."
    ssh_target "cd $REMOTE_ROOT && (nohup bash -c '$target_env ./coredns-test -conf $CLOUD_CF/Corefile.target-nosgx' > /tmp/bench-codoh-target.log 2>&1 </dev/null &)"
    wait_for_remote "$TARGET_IP" 8443

    # Proxy VM: codohproxy
    echo "  Starting CODoH proxy on $PROXY_IP:8080..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.proxy \
        > /tmp/bench-codoh-proxy.log 2>&1 </dev/null &)"
    wait_for_remote "$PROXY_IP" 8080
}

start_config_5() {
    local enclave_env="$1"
    local target_env="$2"
    echo "--- Starting Config 5: CODoH full (SGX) ---"

    # Proxy VM: SGX enclave
    local enclave_cmd="$enclave_env ego run $REMOTE_ROOT/enclave/enclave"

    echo "  Starting SGX enclave on proxy VM..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup bash -c '$enclave_cmd' > /tmp/bench-enclave.log 2>&1 </dev/null &)"
    wait_for_remote_attest 60

    # Target VM: codohtarget (SGX variant — provisions via attestation)
    echo "  Starting CODoH target on $TARGET_IP:8443..."
    ssh_target "cd $REMOTE_ROOT && (nohup bash -c '$target_env ./coredns-test -conf $CLOUD_CF/Corefile.target' > /tmp/bench-codoh-target.log 2>&1 </dev/null &)"
    wait_for_remote_socket 30
    wait_for_remote "$TARGET_IP" 8443

    # Proxy VM: codohproxy
    echo "  Starting CODoH proxy on $PROXY_IP:8080..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.proxy \
        > /tmp/bench-codoh-proxy.log 2>&1 </dev/null &)"
    wait_for_remote "$PROXY_IP" 8080
}

#######################################
# Validate workload result — catch broken caches early
#######################################
validate_workload_result() {
    local config_name=$1 workload=$2 json_file=$3

    [[ -f "$json_file" ]] || return 0

    # Only validate cache-capable configs on warm/zipf workloads
    case "$config_name" in
        codoh-base|codoh-nosgx|codoh-full|codoh) ;;
        *) return 0 ;;
    esac
    [[ "$workload" == "cold" ]] && return 0

    local cache_misses cache_hits iterations
    cache_misses=$(python3 -c "import json; d=json.load(open('$json_file')); print(d.get('cache_misses', -1))" 2>/dev/null)
    cache_hits=$(python3 -c "import json; d=json.load(open('$json_file')); print(d.get('cache_hits', -1))" 2>/dev/null)
    iterations=$(python3 -c "import json; d=json.load(open('$json_file')); print(d.get('iterations', 0))" 2>/dev/null)

    # Flag zero cache hits on warm workload — cache is broken
    if [[ "$workload" == "warm" && "$cache_hits" =~ ^[0-9]+$ && "$cache_hits" -eq 0 && "$iterations" -gt 0 ]]; then
        echo "  ERROR: $config_name/$workload has 0 cache hits out of $iterations queries!"
        echo "         Cache is not working — check HPKE info string, enclave logs for decrypt errors."
        return 1
    fi

    # Flag 100% misses on zipf (very unlikely with 1k domain list)
    if [[ "$workload" == "zipf" && "$cache_misses" =~ ^[0-9]+$ && "$cache_misses" -eq "$iterations" && "$iterations" -gt 10 ]]; then
        echo "  WARNING: $config_name/$workload has 100% cache misses — cache may be broken."
        return 1
    fi

    return 0
}

#######################################
# Run workload (local client → remote proxy/target)
#######################################
run_cloud_workload() {
    local config_name=$1 workload=$2 protocol=$3 proxy_arg=$4 target_arg=$5
    local iterations=$6 warmup=$7 output_dir=$8 client_bin=${9:-$CLIENT_PATH}

    local distribution domains_path zipf_args=""
    case $workload in
        cold)
            distribution="sequential"
            domains_path="$DOMAINS_1M"
            ;;
        zipf)
            distribution="zipf"
            domains_path="$DOMAINS_1K"
            zipf_args="--zipf-s $ZIPF_S"
            ;;
        warm)
            distribution="sequential"
            echo "1,google.com" > /tmp/warm-domain.csv
            domains_path="/tmp/warm-domain.csv"
            ;;
    esac

    # Cold workload: skip warmup pass — it would prime Unbound with the first
    # $warmup domains, then the measured run hits those same domains warm.
    [[ "$workload" == "cold" ]] && warmup=0

    local output_prefix="$output_dir/${config_name}_${workload}"

    # Warm-up pass
    if [[ $warmup -gt 0 ]]; then
        echo "  Warm-up: $warmup queries..."
        $client_bin latency \
            --protocol "$protocol" \
            $proxy_arg $target_arg \
            --distribution "$distribution" \
            --iterations "$warmup" \
            --customcert "$CERT_PATH" \
            --domains "$domains_path" \
            --output /tmp/warmup.csv \
            --summary /tmp/warmup.json \
            $zipf_args > /dev/null 2>&1 || true
        rm -f /tmp/warmup.csv /tmp/warmup.json 2>/dev/null
    fi

    # Measured run
    echo "  Running $workload ($distribution, $iterations queries)..."
    if ! $client_bin latency \
        --protocol "$protocol" \
        $proxy_arg $target_arg \
        --distribution "$distribution" \
        --iterations "$iterations" \
        --customcert "$CERT_PATH" \
        --domains "$domains_path" \
        --output "${output_prefix}.csv" \
        --summary "${output_prefix}.json" \
        $zipf_args 2>&1 | tail -5; then
        echo "  WARNING: $config_name/$workload had issues"
        return 1
    fi

    # Validate cache behavior
    validate_workload_result "$config_name" "$workload" "${output_prefix}.json" || return 1
}

#######################################
# Run a config across workloads
#######################################
run_cloud_config() {
    local config_num=$1

    echo ""
    echo "========================================"
    echo "Config $config_num"
    echo "========================================"

    # Cleanup previous
    remote_cleanup

    # Start config-specific processes
    local config_name protocol proxy_arg target_arg client_bin="$CLIENT_PATH"
    local enclave_env="CODOH_USE_ORAM=true CODOH_CACHE_SIZE=${CODOH_CACHE_SIZE:-1024} CODOH_BATCH_SIZE=${CODOH_BATCH_SIZE:-10} CODOH_BATCH_COMMIT_PROB=${CODOH_BATCH_COMMIT_PROB:-0.1}"
    local target_env="CODOH_COVER_COUNT=${CODOH_COVER_COUNT:-3} CODOH_COVER_DOMAIN_FILE=$REMOTE_ROOT/benchmark/top-10k-resolvable.csv CODOH_COVER_POPULAR_CUTOFF=1000 CODOH_PROXY_CALLBACK_URL=https://$PROXY_IP:8080 CODOH_COVER_RESOLVER=$UPSTREAM_RESOLVER CODOH_COVER_TIMEOUT_MS=2000"

    case $config_num in
        1)
            start_config_1
            config_name="doh"
            protocol="doh"
            proxy_arg=""
            target_arg="--target $TARGET_IP:7443"
            ;;
        2)
            start_config_2
            config_name="odoh"
            protocol="odoh"
            proxy_arg="--proxy $PROXY_IP:9080"
            target_arg="--target $TARGET_IP:9443"
            ;;
        3)
            start_config_3
            config_name="codoh-base"
            protocol="codoh-base"
            proxy_arg="--proxy $PROXY_IP:10443"
            target_arg="--target $TARGET_IP:10444"
            client_bin="$CLIENT_PATH_CONFIG3"
            ;;
        4)
            start_config_4 "$enclave_env" "$target_env"
            config_name="codoh-nosgx"
            protocol="codoh"
            proxy_arg="--proxy $PROXY_IP:8080"
            target_arg="--target $TARGET_IP:8443"
            ;;
        5)
            start_config_5 "$enclave_env" "$target_env"
            config_name="codoh-full"
            protocol="codoh"
            proxy_arg="--proxy $PROXY_IP:8080"
            target_arg="--target $TARGET_IP:8443"
            ;;
        *)
            echo "WARNING: Config $config_num not supported in cloud mode, skipping"
            return 1
            ;;
    esac

    # Run workloads
    local success=0 fail=0
    for workload in "${WORKLOADS[@]}"; do
        flush_unbound_cache
        if run_cloud_workload "$config_name" "$workload" "$protocol" \
            "$proxy_arg" "$target_arg" "$ITERATIONS" "$WARMUP_QUERIES" "$OUTPUT_RAW" "$client_bin"; then
            ((success++)) || true
        else
            ((fail++)) || true
        fi
    done

    echo "  Config $config_num: $success passed, $fail failed"
}

#######################################
# Summary table
#######################################
print_summary() {
    echo ""
    echo "=== Results Summary ==="
    echo ""
    printf "%-20s %-8s %10s %10s %10s %10s\n" "Config" "Workload" "Median" "P95" "P99" "QPS"
    printf "%-20s %-8s %10s %10s %10s %10s\n" "------" "--------" "------" "------" "------" "------"

    for json_file in "$OUTPUT_RAW"/*.json "$OUTPUT_RAW"/sweep_*/*.json; do
        [[ -f "$json_file" ]] || continue
        python3 -c "
import json, os
d = json.load(open('$json_file'))
l = d.get('latency_ms', {})
name = os.path.basename('$json_file').replace('.json','')
parts = name.rsplit('_', 1)
cfg, wl = parts[0], parts[1] if len(parts) == 2 else '?'
print(f'{cfg:<20} {wl:<8} {l.get(\"p50\",0):>10.2f} {l.get(\"p95\",0):>10.2f} {l.get(\"p99\",0):>10.2f} {d.get(\"throughput_qps\",0):>10.1f}')
" 2>/dev/null
    done
}

#######################################
# Main
#######################################
generate_corefiles
distribute_files

echo ""
for config_num in "${CONFIGS[@]}"; do
    run_cloud_config "$config_num"
done

# ORAM capacity sweep (re-runs config 5 with different cache sizes)
if $SWEEP_ORAM; then
    echo ""
    echo "=== ORAM Capacity Sweep ==="
    SAVED_OUTPUT_RAW="$OUTPUT_RAW"
    for oram_n in 256 512 2048; do  # 1024 already covered in main
        echo ""
        echo "--- ORAM N=$oram_n ---"
        export CODOH_CACHE_SIZE=$oram_n
        OUTPUT_RAW="$SAVED_OUTPUT_RAW/sweep_oram_${oram_n}"
        mkdir -p "$OUTPUT_RAW"
        run_cloud_config 5
    done
    unset CODOH_CACHE_SIZE
    OUTPUT_RAW="$SAVED_OUTPUT_RAW"
fi

# Cover count sweep (re-runs config 5 with different cover counts)
if $SWEEP_COVER; then
    echo ""
    echo "=== Cover Count Sweep ==="
    SAVED_OUTPUT_RAW="$OUTPUT_RAW"
    for cover_k in 1 5; do  # k=3 already covered in main
        echo ""
        echo "--- Cover k=$cover_k ---"
        export CODOH_COVER_COUNT=$cover_k
        OUTPUT_RAW="$SAVED_OUTPUT_RAW/sweep_cover_${cover_k}"
        mkdir -p "$OUTPUT_RAW"
        run_cloud_config 5
    done
    unset CODOH_COVER_COUNT
    OUTPUT_RAW="$SAVED_OUTPUT_RAW"
fi

# Collect logs
echo ""
echo "=== Collecting remote logs ==="
scp_from_proxy "/tmp/bench-*.log" "$OUTPUT_BASE/logs/" 2>/dev/null || echo "  No logs on proxy"
scp_from_target "/tmp/bench-*.log" "$OUTPUT_BASE/logs/" 2>/dev/null || echo "  No logs on target"
echo "  Logs: $OUTPUT_BASE/logs/"

print_summary

echo ""
echo "=== Cloud Benchmark Complete ==="
echo "Results: $OUTPUT_BASE/"
echo "Raw:     $OUTPUT_RAW/"
echo "Logs:    $OUTPUT_BASE/logs/"
