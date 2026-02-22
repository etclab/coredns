#!/bin/bash
# CODoH Multi-Configuration Benchmark Orchestrator
# Runs benchmarks across all 7 configurations from the comparison matrix.
#
# Usage:
#   ./benchmark/run-all.sh [options]
#
# Options:
#   --configs 1,3,5,7    Run only specified configs (default: all)
#   --workloads cold,zipf,warm  Run only specified workloads (default: all)
#   --iterations N       Queries per workload (default: 1000)
#   --quick              Quick mode: 100 iterations, cold workload only
#   --sgx                Use SGX enclave (default: simulation)
#   --zipf-s S           Zipf skew parameter (default: 1.0)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$SCRIPT_DIR/configs"

# Defaults
SELECTED_CONFIGS="1,2,3,4,5,6,7"
SELECTED_WORKLOADS="cold,zipf,warm"
ITERATIONS=1000
ZIPF_S=1.0
SGX_MODE=false

CLIENT_PATH="$(dirname "$ROOT_DIR")/codoh-client/odoh-client"
CERT_PATH="$ROOT_DIR/localhost.pem"
DOMAINS_1M="$SCRIPT_DIR/top-1m.csv"
DOMAINS_1K="$SCRIPT_DIR/top-1k.csv"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --configs)
            SELECTED_CONFIGS="$2"
            shift 2
            ;;
        --workloads)
            SELECTED_WORKLOADS="$2"
            shift 2
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --quick)
            ITERATIONS=100
            SELECTED_WORKLOADS="cold"
            shift
            ;;
        --sgx)
            SGX_MODE=true
            shift
            ;;
        --zipf-s)
            ZIPF_S="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--configs 1,3,5] [--workloads cold,zipf,warm] [--iterations N] [--quick] [--sgx] [--zipf-s S]"
            exit 1
            ;;
    esac
done

# Export SGX_MODE so config scripts can use it
export SGX_MODE

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$SCRIPT_DIR/results/comparison_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

echo "=== CODoH Multi-Configuration Benchmark ==="
echo "Configs:    $SELECTED_CONFIGS"
echo "Workloads:  $SELECTED_WORKLOADS"
echo "Iterations: $ITERATIONS"
echo "SGX mode:   $SGX_MODE"
echo "Zipf s:     $ZIPF_S"
echo "Output:     $OUTPUT_DIR"
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
    pkill -9 -f enclave-sgx 2>/dev/null || true
    pkill -9 -f erthost 2>/dev/null || true
    for port in 7443 8080 8443 9080 9443 10443 10444; do
        lsof -ti :$port 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    rm -f /tmp/codoh-enclave.sock 2>/dev/null || true
    sleep 2
}
trap cleanup_all EXIT

#######################################
# Build all binaries
#######################################
echo "=== Building Binaries ==="
cd "$ROOT_DIR"

echo "Building coredns-test..."
go build -o coredns-test . 2>/dev/null

if $SGX_MODE; then
    echo "Building SGX enclave..."
    (cd enclave && ego-go build -o enclave ./cmd && ego sign enclave) 2>/dev/null
else
    echo "Building enclave-sim..."
    go build -o enclave-sim ./enclave/cmd 2>/dev/null
fi

echo "Building odoh-client..."
(cd "$(dirname "$ROOT_DIR")/codoh-client" && go build -o odoh-client ./cmd 2>/dev/null)

echo "Build complete."
echo ""

#######################################
# Health check with polling
#######################################
wait_for_health() {
    local urls="$1"
    local max_wait="${2:-30}"  # default 30s timeout
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
            echo "All services ready after ${i}s"
            break
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

    if ! $all_ok; then
        echo "WARNING: Some health checks failed after ${max_wait}s!"
        return 1
    fi
}

#######################################
# Run a single workload
#######################################
run_workload() {
    local config_name=$1 workload=$2 client_args_fn=$3

    local distribution domains_path zipf_args=""
    case $workload in
        cold)
            distribution="sequential"
            domains_path="$DOMAINS_1M"
            ;;
        zipf)
            distribution="zipf"
            domains_path="${DOMAINS_1K:-$DOMAINS_1M}"
            zipf_args="--zipf-s $ZIPF_S"
            ;;
        warm)
            distribution="sequential"
            # Create single-domain file for warm test (all cache hits)
            echo "1,google.com" > /tmp/warm-domain.csv
            domains_path="/tmp/warm-domain.csv"
            ;;
        *)
            echo "Unknown workload: $workload"
            return 1
            ;;
    esac

    # Use top-1k for zipf if available, fall back to top-1m
    if [[ "$workload" == "zipf" && -f "$DOMAINS_1K" ]]; then
        domains_path="$DOMAINS_1K"
    fi

    local output_prefix="$OUTPUT_DIR/${config_name}_${workload}"
    echo "  Running $workload workload ($distribution, $ITERATIONS iterations)..."

    local args
    args=$(eval "$client_args_fn" "'$CERT_PATH'" "'$domains_path'" "'$ITERATIONS'" "'$distribution'" "'$output_prefix'")

    # Run the benchmark
    if ! eval "$CLIENT_PATH" latency $args $zipf_args 2>&1 | tail -20; then
        echo "  WARNING: $config_name/$workload benchmark had issues"
    fi
    echo ""
}

#######################################
# Main benchmark loop
#######################################
SUMMARY_DATA=()

for config_num in "${CONFIGS[@]}"; do
    config_file="$CONFIG_DIR/${config_num}-*.sh"
    config_file=$(ls $config_file 2>/dev/null | head -1)

    if [[ -z "$config_file" || ! -f "$config_file" ]]; then
        echo "WARNING: Config $config_num not found, skipping"
        continue
    fi

    # Source the config profile
    source "$config_file"

    echo ""
    echo "========================================"
    echo "Config $CONFIG_NUM: $CONFIG_NAME ($CONFIG_PROTOCOL)"
    echo "========================================"

    # Cleanup previous config's processes
    cleanup_all

    # Start this config's processes
    start_config "$ROOT_DIR" "$CERT_PATH" "$OUTPUT_DIR"

    # Wait for health with polling (longer timeout for SGX)
    local_timeout=15
    if $SGX_MODE; then
        local_timeout=30
    fi
    echo "Health check:"
    if ! wait_for_health "$HEALTH_URLS" "$local_timeout"; then
        echo "Skipping config $CONFIG_NUM due to health check failure"
        continue
    fi
    echo ""

    # Run selected workloads
    for workload in "${WORKLOADS[@]}"; do
        run_workload "$CONFIG_NAME" "$workload" "client_args"
    done

    # Collect summary for report
    for workload in "${WORKLOADS[@]}"; do
        local_summary="$OUTPUT_DIR/${CONFIG_NAME}_${workload}.json"
        if [[ -f "$local_summary" ]]; then
            SUMMARY_DATA+=("$CONFIG_NUM|$CONFIG_NAME|$workload|$local_summary")
        fi
    done
done

#######################################
# Generate comparison plot (gnuplot)
#######################################
echo ""
echo "=== Generating Plot ==="

# Write per-workload data files (one row per config)
for workload in "${WORKLOADS[@]}"; do
    dat="$OUTPUT_DIR/${workload}.dat"
    : > "$dat"
    for entry in "${SUMMARY_DATA[@]}"; do
        IFS='|' read -r cfg_num cfg_name wkload json_file <<< "$entry"
        [[ "$wkload" != "$workload" || ! -f "$json_file" ]] && continue
        python3 -c "
import json
d = json.load(open('$json_file'))
l = d['latency_ms']
print('\"$cfg_name\"', f\"{l['mean']:.2f}\", f\"{l['p50']:.2f}\", f\"{l['p95']:.2f}\", f\"{l['p99']:.2f}\", f\"{d['throughput_qps']:.1f}\")
" >> "$dat" 2>/dev/null
    done

    # Transpose for plotting: rows=metrics, columns=configs
    python3 -c "
import sys
rows = [line.split() for line in open('$dat') if line.strip()]
if not rows: sys.exit()
names = [r[0] for r in rows]
metrics = ['\"Mean\"','\"P50\"','\"P95\"','\"P99\"']
print('\"Metric\"', ' '.join(names))
for i, m in enumerate(metrics):
    print(m, ' '.join(r[i+1] for r in rows))
" > "$OUTPUT_DIR/${workload}_plot.dat" 2>/dev/null
done

# Build gnuplot script
NUM_WL=${#WORKLOADS[@]}
PLOT_PNG="$OUTPUT_DIR/comparison.png"
GP_SCRIPT="$OUTPUT_DIR/plot.gp"

{
    echo "set terminal pngcairo size 1200,$((400 * NUM_WL)) enhanced font 'Arial,12'"
    echo "set output '$PLOT_PNG'"
    echo "set style data histogram"
    echo "set style histogram clustered gap 1"
    echo "set style fill solid 0.8 border -1"
    echo "set key outside top right"
    echo "set grid ytics"
    if [[ $NUM_WL -gt 1 ]]; then
        echo "set multiplot layout $NUM_WL,1"
    fi

    for workload in "${WORKLOADS[@]}"; do
        # Count config columns from the transposed file
        ncols=$(head -1 "$OUTPUT_DIR/${workload}_plot.dat" | wc -w)
        echo "set title '${workload} workload — Latency (ms)'"
        echo "set ylabel 'Latency (ms)'"
        plot_cmd="plot '$OUTPUT_DIR/${workload}_plot.dat' using 2:xtic(1) title columnheader(2)"
        for (( c=3; c<=ncols; c++ )); do
            plot_cmd="$plot_cmd, '' using $c title columnheader($c)"
        done
        echo "$plot_cmd"
        echo ""
    done

    if [[ $NUM_WL -gt 1 ]]; then
        echo "unset multiplot"
    fi
} > "$GP_SCRIPT"

gnuplot "$GP_SCRIPT"

# Print summary table to console
echo ""
printf "%-20s %-8s %8s %8s %8s %8s %8s\n" "Config" "Workload" "Mean" "P50" "P95" "P99" "QPS"
printf "%-20s %-8s %8s %8s %8s %8s %8s\n" "------" "--------" "------" "------" "------" "------" "------"
for entry in "${SUMMARY_DATA[@]}"; do
    IFS='|' read -r cfg_num cfg_name wkload json_file <<< "$entry"
    [[ ! -f "$json_file" ]] && continue
    python3 -c "
import json
d = json.load(open('$json_file'))
l = d['latency_ms']
print(f\"{'$cfg_name':<20} {'$wkload':<8} {l['mean']:>8.2f} {l['p50']:>8.2f} {l['p95']:>8.2f} {l['p99']:>8.2f} {d['throughput_qps']:>8.1f}\")
" 2>/dev/null
done

echo ""
echo "=== Benchmark Complete ==="
echo "Results: $OUTPUT_DIR/"
echo "Plot:    $PLOT_PNG"
