#!/bin/bash
# CODoH Multi-Configuration Benchmark Orchestrator
#
# Run modes:
#   --quick       Smoke test (10q all configs) + spot check (500q on configs 4,7)  ~5-8 min
#   --standard    Core comparison (10Kq on configs 2,3,7)                          ~45-90 min
#   (default)     Full benchmark (10Kq all configs + ablation + sweeps)            ~4-7 hrs
#
# Usage:
#   ./benchmark/run-all.sh [options]
#
# Options:
#   --run-id NAME        Name for results directory (default: timestamp)
#   --configs 1,3,5,7    Run only specified configs (default: mode-dependent)
#   --workloads cold,zipf,warm  Run only specified workloads (default: all)
#   --iterations N       Queries per workload (default: 10000)
#   --warmup N           Warm-up queries to discard (default: 100)
#   --quick              Quick validation mode
#   --standard           Standard comparison mode
#   --no-sgx             Use simulation mode (default: SGX)
#   --sweep-oram         Run ORAM capacity sweep (N=256,1024,2048 on configs 5,7)
#   --sweep-cover        Run cover count sweep (k=1,3,5 on configs 6,7)
#   --resolver NAME      Upstream resolver: unbound (default), cloudflare, google, or HOST:PORT
#   --zipf-s S           Zipf skew parameter (default: 1.0)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$SCRIPT_DIR/configs"

# Defaults (full mode)
RUN_MODE="full"
RUN_ID=""
SELECTED_CONFIGS=""
SELECTED_WORKLOADS="cold,zipf,warm"
ITERATIONS=10000
WARMUP_QUERIES=100
ZIPF_S=1.0
SGX_MODE=true
SWEEP_ORAM=false
SWEEP_COVER=false
RESOLVER="unbound"

CLIENT_PATH="$(dirname "$ROOT_DIR")/codoh-client/odoh-client"
CERT_PATH="$ROOT_DIR/localhost.pem"
DOMAINS_1M="$SCRIPT_DIR/top-1m-10k-resolvable.csv"
DOMAINS_1K="$SCRIPT_DIR/top-1k-resolvable.csv"

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
        --no-sgx)       SGX_MODE=false; shift ;;
        --sweep-oram)   SWEEP_ORAM=true; shift ;;
        --sweep-cover)  SWEEP_COVER=true; shift ;;
        --zipf-s)       ZIPF_S="$2"; shift 2 ;;
        --resolver)     RESOLVER="$2"; shift 2 ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--run-id NAME] [--configs 1,3,5] [--quick|--standard] [--no-sgx] [--resolver unbound|cloudflare|google|HOST:PORT] [--sweep-oram] [--sweep-cover]"
            exit 1
            ;;
    esac
done

# Apply mode defaults
case $RUN_MODE in
    quick)
        [[ -z "$SELECTED_CONFIGS" ]] && SELECTED_CONFIGS="1,2,3,4,5,6,7"
        ITERATIONS=10         # Phase 1: smoke
        WARMUP_QUERIES=0
        SELECTED_WORKLOADS="warm"
        ;;
    standard)
        [[ -z "$SELECTED_CONFIGS" ]] && SELECTED_CONFIGS="2,3,7"
        ;;
    full)
        [[ -z "$SELECTED_CONFIGS" ]] && SELECTED_CONFIGS="1,2,3,4,4b,4p,5,6,7"
        ;;
esac

# Export SGX_MODE so config scripts can use it
export SGX_MODE

# Map resolver name to address
case $RESOLVER in
    unbound)    UPSTREAM_RESOLVER="127.0.0.1:5353" ;;
    cloudflare) UPSTREAM_RESOLVER="1.1.1.1:53" ;;
    google)     UPSTREAM_RESOLVER="8.8.8.8:53" ;;
    *)
        # Treat as raw host:port
        if [[ "$RESOLVER" == *:* ]]; then
            UPSTREAM_RESOLVER="$RESOLVER"
        else
            echo "ERROR: Invalid resolver '$RESOLVER'. Use: unbound, cloudflare, google, or HOST:PORT"
            exit 1
        fi
        ;;
esac
export UPSTREAM_RESOLVER

# Results directory
if [[ -z "$RUN_ID" ]]; then
    RUN_ID="${RUN_MODE}_$(date +%Y%m%d_%H%M%S)"
fi
OUTPUT_BASE="$SCRIPT_DIR/results/$RUN_ID"
OUTPUT_RAW="$OUTPUT_BASE/raw"
OUTPUT_PROCESSED="$OUTPUT_BASE/processed"
mkdir -p "$OUTPUT_RAW" "$OUTPUT_PROCESSED"

# Generate Corefiles with selected resolver
COREFILE_DIR="$OUTPUT_BASE/corefiles"
export COREFILE_DIR
mkdir -p "$COREFILE_DIR"

for cf in "$SCRIPT_DIR/Corefile.doh" "$SCRIPT_DIR/Corefile.odoh-target" "$SCRIPT_DIR/Corefile.odoh-proxy" \
          "$SCRIPT_DIR/Corefile.codoh-base-target" "$ROOT_DIR/Corefile.target" "$ROOT_DIR/Corefile.proxy"; do
    if [[ -f "$cf" ]]; then
        sed "s|127\.0\.0\.1:5353|$UPSTREAM_RESOLVER|g" "$cf" > "$COREFILE_DIR/$(basename "$cf")"
    fi
done

# Save run metadata
cat > "$OUTPUT_BASE/metadata.json" << METAEOF
{
    "run_id": "$RUN_ID",
    "mode": "$RUN_MODE",
    "iterations": $ITERATIONS,
    "warmup": $WARMUP_QUERIES,
    "sgx_mode": $SGX_MODE,
    "resolver": "$RESOLVER",
    "upstream_resolver": "$UPSTREAM_RESOLVER",
    "zipf_s": $ZIPF_S,
    "configs": "$SELECTED_CONFIGS",
    "workloads": "$SELECTED_WORKLOADS",
    "timestamp": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "kernel": "$(uname -r)",
    "config3_commit": "e81a315ec3a91dee1bad2cc2bbf139ebee145ab8"
}
METAEOF

echo "=== CODoH Benchmark ($RUN_MODE mode) ==="
echo "Run ID:     $RUN_ID"
echo "Configs:    $SELECTED_CONFIGS"
echo "Workloads:  $SELECTED_WORKLOADS"
echo "Iterations: $ITERATIONS (+ $WARMUP_QUERIES warmup)"
echo "Resolver:   $RESOLVER ($UPSTREAM_RESOLVER)"
echo "SGX mode:   $SGX_MODE"
echo "Output:     $OUTPUT_BASE/"
echo ""

# Convert comma-separated lists to arrays
IFS=',' read -ra CONFIGS <<< "$SELECTED_CONFIGS"
IFS=',' read -ra WORKLOADS <<< "$SELECTED_WORKLOADS"

#######################################
# Cleanup function
#######################################
cleanup_all() {
    echo "Cleaning up all processes..."
    pkill -9 -f coredns-test 2>/dev/null || true
    pkill -9 -f enclave-sim 2>/dev/null || true
    pkill -9 -f 'ego-host.*enclave' 2>/dev/null || true
    pkill -9 -f erthost 2>/dev/null || true
    for port in 7443 8080 8443 9080 9443 10443 10444; do
        lsof -ti :$port 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    rm -f /tmp/codoh-enclave.sock 2>/dev/null || true
    sleep 2
}
trap cleanup_all EXIT

#######################################
# Build binaries (skip in quick mode if already built)
#######################################
build_binaries() {
    echo "=== Building Binaries ==="
    cd "$ROOT_DIR"

    if [[ ! -f "$ROOT_DIR/coredns-test" ]] || [[ "$RUN_MODE" != "quick" ]]; then
        echo "Building coredns-test..."
        go build -o coredns-test . 2>/dev/null
    fi

    if $SGX_MODE; then
        if [[ ! -f "$ROOT_DIR/enclave/enclave" ]] || [[ "$RUN_MODE" != "quick" ]]; then
            echo "Building SGX enclave..."
            (cd enclave && ego-go build -tags ego -o enclave ./cmd && ego sign enclave.json) 2>/dev/null
        fi
    else
        if [[ ! -f "$ROOT_DIR/enclave-sim" ]] || [[ "$RUN_MODE" != "quick" ]]; then
            echo "Building enclave-sim..."
            go build -o enclave-sim ./enclave/cmd 2>/dev/null
        fi
    fi

    if [[ ! -f "$CLIENT_PATH" ]] || [[ "$RUN_MODE" != "quick" ]]; then
        echo "Building odoh-client..."
        (cd "$(dirname "$ROOT_DIR")/codoh-client" && go build -o odoh-client ./cmd 2>/dev/null)
    fi

    echo "Build complete."
    echo ""
}

#######################################
# Wait for enclave (IPC configs)
#######################################
# Phase 1: Wait for attestation server (port 8444) — call after starting enclave
wait_for_enclave_attest() {
    local port="${1:-8444}"
    local max_wait="${2:-30}"

    echo "Waiting for enclave attestation (port $port, up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if curl -sk "https://127.0.0.1:$port/attest" > /dev/null 2>&1; then
            echo "  Enclave attestation ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "WARNING: Enclave attestation not ready after ${max_wait}s!"
    return 1
}

# Phase 2: Wait for IPC socket — call after starting target (which provisions the enclave)
wait_for_enclave_socket() {
    local socket="${1:-/tmp/codoh-enclave.sock}"
    local max_wait="${2:-30}"

    echo "Waiting for enclave socket (up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if [[ -S "$socket" ]]; then
            echo "  Enclave socket ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "WARNING: Enclave socket not found after ${max_wait}s!"
    return 1
}

#######################################
# Health check with polling
#######################################
wait_for_health() {
    local urls="$1"
    local max_wait="${2:-30}"
    local all_ok=false

    echo "Waiting for services (up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        all_ok=true
        for url in $urls; do
            if ! curl -sk "$url" > /dev/null 2>&1; then
                all_ok=false
                break
            fi
        done
        if $all_ok; then
            echo "  All services ready after ${i}s"
            return 0
        fi
        sleep 1
    done

    # Final status report
    for url in $urls; do
        if curl -sk "$url" > /dev/null 2>&1; then
            echo "  $(echo "$url" | sed 's|https://||'): OK"
        else
            echo "  $(echo "$url" | sed 's|https://||'): FAILED"
        fi
    done

    echo "WARNING: Some health checks failed after ${max_wait}s!"
    return 1
}

#######################################
# Run a single workload
#######################################
run_workload() {
    local config_name=$1 workload=$2 client_args_fn=$3 iterations=$4 warmup=$5 output_dir=$6

    # Allow per-config client override (e.g., Config 3 worktree client)
    local client_bin="${CONFIG_CLIENT_PATH:-$CLIENT_PATH}"

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
        *)
            echo "Unknown workload: $workload"
            return 1
            ;;
    esac

    local output_prefix="$output_dir/${config_name}_${workload}"

    # Warm-up pass (discarded)
    if [[ $warmup -gt 0 ]]; then
        echo "  Warm-up: $warmup queries..."
        local warmup_args
        warmup_args=$(eval "$client_args_fn" "'$CERT_PATH'" "'$domains_path'" "'$warmup'" "'$distribution'" "'/tmp/warmup'")
        eval "$client_bin" latency $warmup_args $zipf_args > /dev/null 2>&1 || true
        rm -f /tmp/warmup.csv /tmp/warmup.json 2>/dev/null
    fi

    # Measured run
    echo "  Running $workload ($distribution, $iterations queries)..."
    local args
    args=$(eval "$client_args_fn" "'$CERT_PATH'" "'$domains_path'" "'$iterations'" "'$distribution'" "'$output_prefix'")

    if ! eval "$client_bin" latency $args $zipf_args 2>&1 | tail -5; then
        echo "  WARNING: $config_name/$workload had issues"
        return 1
    fi
    echo ""
}

#######################################
# Run a config across workloads
#######################################
run_config() {
    local config_num=$1 iterations=$2 warmup=$3 output_dir=$4
    shift 4
    local workloads=("$@")

    # Find config file (supports numeric and alphanumeric like 4b, 4p)
    local config_file
    config_file=$(ls "$CONFIG_DIR/${config_num}-"*.sh 2>/dev/null | head -1)

    if [[ -z "$config_file" || ! -f "$config_file" ]]; then
        echo "WARNING: Config $config_num not found, skipping"
        return 1
    fi

    # Reset per-config overrides
    CONFIG_CLIENT_PATH=""

    # Source the config profile
    source "$config_file"

    echo ""
    echo "========================================"
    echo "Config $CONFIG_NUM: $CONFIG_NAME"
    echo "========================================"

    # Cleanup previous config's processes
    cleanup_all

    # Start this config's processes
    if ! start_config "$ROOT_DIR" "$CERT_PATH" "$output_dir"; then
        echo "ERROR: Config $CONFIG_NUM failed to start"
        return 1
    fi

    # Wait for health
    local timeout=15
    if $SGX_MODE; then timeout=45; fi
    if ! wait_for_health "$HEALTH_URLS" "$timeout"; then
        echo "Skipping config $CONFIG_NUM due to health check failure"
        return 1
    fi

    # Run workloads
    local success=0 fail=0
    for workload in "${workloads[@]}"; do
        if run_workload "$CONFIG_NAME" "$workload" "client_args" "$iterations" "$warmup" "$output_dir"; then
            ((success++)) || true
        else
            ((fail++)) || true
        fi
    done

    echo "  Config $CONFIG_NUM: $success passed, $fail failed"
    return 0
}

#######################################
# Quick mode
#######################################
run_quick() {
    # Phase 1: Smoke — 50 queries, warm workload, all configs
    echo "=== Phase 1: Smoke Test (50 queries, warm, all configs) ==="
    local smoke_pass=0 smoke_fail=0
    local smoke_file="$OUTPUT_RAW/smoke.txt"
    : > "$smoke_file"

    for config_num in "${CONFIGS[@]}"; do
        if run_config "$config_num" 50 10 "$OUTPUT_RAW" "warm"; then
            echo "PASS  Config $config_num" >> "$smoke_file"
            ((smoke_pass++)) || true
        else
            echo "FAIL  Config $config_num" >> "$smoke_file"
            ((smoke_fail++)) || true
        fi
    done

    echo ""
    echo "Smoke results: $smoke_pass passed, $smoke_fail failed"
    cat "$smoke_file"

    if [[ $smoke_fail -gt 0 ]]; then
        echo "WARNING: Some configs failed smoke test!"
    fi

    # Phase 2: Spot check — 1000 queries, all 3 workloads, configs 2, 4, 7
    echo ""
    echo "=== Phase 2: Spot Check (1000 queries, all workloads, configs 2+4+7) ==="
    for config_num in 2 4 7; do
        run_config "$config_num" 1000 50 "$OUTPUT_RAW" "cold" "zipf" "warm"
    done
}

#######################################
# Standard mode
#######################################
run_standard() {
    echo "=== Standard Comparison (configs 2,3,7) ==="
    for config_num in "${CONFIGS[@]}"; do
        run_config "$config_num" "$ITERATIONS" "$WARMUP_QUERIES" "$OUTPUT_RAW" "${WORKLOADS[@]}"
    done
}

#######################################
# Full mode
#######################################
run_full() {
    echo "=== Full Benchmark ==="

    # Main comparison
    echo ""
    echo "--- Main Comparison ---"
    for config_num in "${CONFIGS[@]}"; do
        run_config "$config_num" "$ITERATIONS" "$WARMUP_QUERIES" "$OUTPUT_RAW" "${WORKLOADS[@]}"
    done

    # ORAM capacity sweep
    if $SWEEP_ORAM; then
        echo ""
        echo "--- ORAM Capacity Sweep ---"
        for oram_n in 256 2048; do  # 1024 already covered in main
            for config_num in 5 7; do
                export CODOH_CACHE_SIZE=$oram_n
                local sweep_dir="$OUTPUT_RAW/sweep_oram_${oram_n}"
                mkdir -p "$sweep_dir"
                run_config "$config_num" "$ITERATIONS" "$WARMUP_QUERIES" "$sweep_dir" "${WORKLOADS[@]}"
                unset CODOH_CACHE_SIZE
            done
        done
    fi

    # Cover count sweep
    if $SWEEP_COVER; then
        echo ""
        echo "--- Cover Count Sweep ---"
        for cover_k in 1 5; do  # k=3 already covered in main
            for config_num in 6 7; do
                export CODOH_COVER_COUNT=$cover_k
                local sweep_dir="$OUTPUT_RAW/sweep_cover_${cover_k}"
                mkdir -p "$sweep_dir"
                run_config "$config_num" "$ITERATIONS" "$WARMUP_QUERIES" "$sweep_dir" "${WORKLOADS[@]}"
                unset CODOH_COVER_COUNT
            done
        done
    fi
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
        [[ "$(basename "$json_file")" == "metadata.json" ]] && continue
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
build_binaries

case $RUN_MODE in
    quick)    run_quick ;;
    standard) run_standard ;;
    full)     run_full ;;
esac

print_summary

echo ""
echo "=== Benchmark Complete ==="
echo "Results: $OUTPUT_BASE/"
echo "Raw:     $OUTPUT_RAW/"

# Exit non-zero if quick mode had smoke failures
if [[ "$RUN_MODE" == "quick" && -f "$OUTPUT_RAW/smoke.txt" ]]; then
    if grep -q "FAIL" "$OUTPUT_RAW/smoke.txt"; then
        exit 1
    fi
fi
