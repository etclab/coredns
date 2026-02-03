#!/bin/bash
# CODoH Stochastic Defense Benchmark
# Measures latency impact of Phase 3 stochastic defenses
#
# Usage: ./benchmark/run-stochastic-benchmark.sh [options]
#   --oram         Use ORAM cache (default: LRU)
#   --iterations N Number of queries per test (default: 500)
#   --quick        Quick mode: fewer iterations (100)
#   --domains FILE Path to domains file (default: top-1k.csv)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse arguments
ORAM_MODE=false
ITERATIONS=500
DOMAINS_FILE="$SCRIPT_DIR/top-1k.csv"

for arg in "$@"; do
    case "$arg" in
        --oram)
            ORAM_MODE=true
            ;;
        --quick)
            ITERATIONS=100
            ;;
        --iterations=*)
            ITERATIONS="${arg#*=}"
            ;;
        --domains=*)
            DOMAINS_FILE="${arg#*=}"
            ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$SCRIPT_DIR/results/stochastic_$TIMESTAMP"
CLIENT_PATH="$(dirname "$ROOT_DIR")/codoh-client/odoh-client"
CERT_PATH="$ROOT_DIR/localhost.pem"
SECRET_HEX=$(cat "$ROOT_DIR/dev-master-secret.txt")

mkdir -p "$OUTPUT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}=== CODoH Stochastic Defense Benchmark ===${NC}"
echo ""
echo "Configuration:"
echo "  Iterations:  $ITERATIONS"
echo "  Cache type:  $(if $ORAM_MODE; then echo 'ORAM'; else echo 'LRU'; fi)"
echo "  Domains:     $DOMAINS_FILE"
echo "  Output:      $OUTPUT_DIR"
echo ""

# Verify client exists
if [ ! -f "$CLIENT_PATH" ]; then
    echo -e "${YELLOW}Warning: codoh-client not found at $CLIENT_PATH${NC}"
    echo "Building may fail. Ensure client is available."
fi

cd "$ROOT_DIR"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    pkill -9 -f coredns-test 2>/dev/null || true
    pkill -9 -f enclave-sim 2>/dev/null || true
    for port in 8080 8443; do
        lsof -ti :$port 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    rm -f /tmp/codoh-enclave.sock 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# Build
echo -e "${YELLOW}Building binaries...${NC}"
go build -o coredns-test . 2>&1 | tail -5 || true
go build -o enclave-sim ./enclave/cmd 2>&1 | tail -5 || true
echo "Build complete."
echo ""

# Function to start services with given stochastic config
start_services() {
    local p_fn=$1
    local p_ins=$2
    local churn_enabled=$3
    local churn_interval=$4
    local test_name=$5

    cleanup

    echo -e "${BLUE}Starting services: $test_name${NC}"
    echo "  p_fn=$p_fn, p_ins=$p_ins, churn=$churn_enabled"

    # Build env vars
    local ENV_VARS="CODOH_MASTER_SECRET=$SECRET_HEX"
    ENV_VARS="$ENV_VARS CODOH_HIT_SUPPRESSION_PROB=$p_fn"
    ENV_VARS="$ENV_VARS CODOH_INSERT_PROB=$p_ins"

    if $ORAM_MODE; then
        ENV_VARS="$ENV_VARS CODOH_USE_ORAM=true"
        ENV_VARS="$ENV_VARS CODOH_ORAM_BLOCK_SIZE=4096"
    fi

    if [ "$churn_enabled" = "true" ]; then
        ENV_VARS="$ENV_VARS CODOH_CHURN_ENABLED=true"
        ENV_VARS="$ENV_VARS CODOH_CHURN_INTERVAL_SECS=$churn_interval"
    fi

    # Start enclave
    eval "$ENV_VARS ./enclave-sim" > "$OUTPUT_DIR/${test_name}_enclave.log" 2>&1 &
    sleep 2

    # Start target
    ./coredns-test -conf Corefile.target > "$OUTPUT_DIR/${test_name}_target.log" 2>&1 &
    sleep 2

    # Start proxy
    ./coredns-test -conf Corefile.proxy > "$OUTPUT_DIR/${test_name}_proxy.log" 2>&1 &
    sleep 2

    # Health check
    if ! curl -sk https://127.0.0.1:8080/health > /dev/null 2>&1; then
        echo "  ERROR: Proxy failed to start"
        return 1
    fi
    if ! curl -sk https://127.0.0.1:8443/health > /dev/null 2>&1; then
        echo "  ERROR: Target failed to start"
        return 1
    fi

    # Show enclave config from log
    grep -E "(LRU|ORAM) cache:" "$OUTPUT_DIR/${test_name}_enclave.log" | head -1

    return 0
}

# Function to run benchmark
run_benchmark() {
    local test_name=$1
    local distribution=$2

    echo "  Running $distribution benchmark..."

    if [ ! -f "$CLIENT_PATH" ]; then
        echo "  SKIPPED: Client not available"
        return 1
    fi

    $CLIENT_PATH latency \
        --protocol codoh \
        --distribution "$distribution" \
        --iterations "$ITERATIONS" \
        --target 127.0.0.1:8443 \
        --proxy 127.0.0.1:8080 \
        --customcert "$CERT_PATH" \
        --domains "$DOMAINS_FILE" \
        --output "$OUTPUT_DIR/${test_name}_${distribution}.csv" \
        --summary "$OUTPUT_DIR/${test_name}_${distribution}.json" 2>&1 | grep -E "(mean|p50|p95|completed)" || true

    return 0
}

# Function to count cache events from enclave log
analyze_cache_behavior() {
    local test_name=$1
    local log_file="$OUTPUT_DIR/${test_name}_enclave.log"

    echo "  Cache behavior:"

    # Count patterns - use grep -c with || true to avoid exit on no match
    local hits=$(grep -c "Cache hit for" "$log_file" 2>/dev/null) || hits=0
    local misses=$(grep -c "Cache miss for" "$log_file" 2>/dev/null) || misses=0
    local suppressed=$(grep -c "suppressing hit" "$log_file" 2>/dev/null) || suppressed=0
    local skipped=$(grep -c "skipping insert" "$log_file" 2>/dev/null) || skipped=0
    local churned=$(grep -c "churned block" "$log_file" 2>/dev/null) || churned=0

    echo "    Hits: $hits, Misses: $misses"
    echo "    Suppressed: $suppressed, Skipped inserts: $skipped, Churned: $churned"

    # Save to summary
    cat >> "$OUTPUT_DIR/${test_name}_cache_stats.txt" << EOF
Cache Statistics for $test_name
================================
Hits:            $hits
Misses:          $misses
Suppressed hits: $suppressed
Skipped inserts: $skipped
Churned blocks:  $churned
EOF
}

#######################################
# Test Configurations
#######################################

echo -e "${GREEN}=== Test 1: Baseline (No Defenses) ===${NC}"
if start_services 0.0 1.0 false 0 "baseline"; then
    run_benchmark "baseline" "zipf"
    analyze_cache_behavior "baseline"
fi
echo ""

echo -e "${GREEN}=== Test 2: Light Defenses (p_fn=0.1, p_ins=0.9) ===${NC}"
if start_services 0.1 0.9 false 0 "light"; then
    run_benchmark "light" "zipf"
    analyze_cache_behavior "light"
fi
echo ""

echo -e "${GREEN}=== Test 3: Moderate Defenses (p_fn=0.2, p_ins=0.8) ===${NC}"
if start_services 0.2 0.8 false 0 "moderate"; then
    run_benchmark "moderate" "zipf"
    analyze_cache_behavior "moderate"
fi
echo ""

echo -e "${GREEN}=== Test 4: Heavy Defenses (p_fn=0.3, p_ins=0.7) ===${NC}"
if start_services 0.3 0.7 false 0 "heavy"; then
    run_benchmark "heavy" "zipf"
    analyze_cache_behavior "heavy"
fi
echo ""

# ORAM-specific tests with churn
if $ORAM_MODE; then
    echo -e "${GREEN}=== Test 5: ORAM + Churn (p_fn=0.1, p_ins=0.9, churn=30s) ===${NC}"
    if start_services 0.1 0.9 true 30 "oram_churn"; then
        run_benchmark "oram_churn" "zipf"
        analyze_cache_behavior "oram_churn"
    fi
    echo ""
fi

echo -e "${GREEN}=== Test 6: Maximum Security (p_fn=0.5, p_ins=0.5) ===${NC}"
if start_services 0.5 0.5 false 0 "max_security"; then
    run_benchmark "max_security" "zipf"
    analyze_cache_behavior "max_security"
fi
echo ""

#######################################
# Summary Report
#######################################
cleanup

echo -e "${GREEN}=== Benchmark Complete ===${NC}"
echo ""
echo "Results saved to: $OUTPUT_DIR/"
echo ""

# Generate comparison report
REPORT_FILE="$OUTPUT_DIR/comparison_report.txt"
cat > "$REPORT_FILE" << EOF
CODoH Stochastic Defense Benchmark Report
==========================================
Date: $(date)
Cache: $(if $ORAM_MODE; then echo 'ORAM'; else echo 'LRU'; fi)
Iterations: $ITERATIONS
Domains: $DOMAINS_FILE

Configuration Comparison
------------------------
EOF

echo -e "${BLUE}=== Latency Comparison (Zipf distribution) ===${NC}"
echo ""
printf "%-15s %10s %10s %10s %10s %10s\n" "Config" "Mean(ms)" "P50(ms)" "P95(ms)" "P99(ms)" "HitRate"
printf "%-15s %10s %10s %10s %10s %10s\n" "-------" "--------" "-------" "-------" "-------" "-------"

for config in baseline light moderate heavy max_security oram_churn; do
    json_file="$OUTPUT_DIR/${config}_zipf.json"
    if [ -f "$json_file" ]; then
        # Parse JSON values - handle nested latency_ms object
        mean=$(python3 -c "import json; d=json.load(open('$json_file')); print(f\"{d['latency_ms']['mean']:.2f}\")" 2>/dev/null || echo "N/A")
        p50=$(python3 -c "import json; d=json.load(open('$json_file')); print(f\"{d['latency_ms']['p50']:.2f}\")" 2>/dev/null || echo "N/A")
        p95=$(python3 -c "import json; d=json.load(open('$json_file')); print(f\"{d['latency_ms']['p95']:.2f}\")" 2>/dev/null || echo "N/A")
        p99=$(python3 -c "import json; d=json.load(open('$json_file')); print(f\"{d['latency_ms']['p99']:.2f}\")" 2>/dev/null || echo "N/A")
        hitrate=$(python3 -c "import json; d=json.load(open('$json_file')); print(f\"{d['cache_hit_rate']*100:.1f}%\")" 2>/dev/null || echo "N/A")
        printf "%-15s %10s %10s %10s %10s %10s\n" "$config" "$mean" "$p50" "$p95" "$p99" "$hitrate"
        echo "$config: mean=$mean, p50=$p50, p95=$p95, p99=$p99, hit_rate=$hitrate" >> "$REPORT_FILE"
    fi
done

echo ""
echo -e "${BLUE}=== Cache Behavior Summary ===${NC}"
echo ""
printf "%-15s %8s %8s %10s %10s %8s\n" "Config" "Hits" "Misses" "Suppressed" "Skipped" "Churned"
printf "%-15s %8s %8s %10s %10s %8s\n" "-------" "----" "------" "----------" "-------" "-------"

for config in baseline light moderate heavy max_security oram_churn; do
    log_file="$OUTPUT_DIR/${config}_enclave.log"
    if [ -f "$log_file" ]; then
        hits=$(grep -c "Cache hit for" "$log_file" 2>/dev/null) || hits=0
        misses=$(grep -c "Cache miss for" "$log_file" 2>/dev/null) || misses=0
        suppressed=$(grep -c "suppressing hit" "$log_file" 2>/dev/null) || suppressed=0
        skipped=$(grep -c "skipping insert" "$log_file" 2>/dev/null) || skipped=0
        churned=$(grep -c "churned block" "$log_file" 2>/dev/null) || churned=0
        printf "%-15s %8s %8s %10s %10s %8s\n" "$config" "$hits" "$misses" "$suppressed" "$skipped" "$churned"
    fi
done

echo ""
echo "Full report: $REPORT_FILE"
echo "Log files: $OUTPUT_DIR/*_enclave.log"
echo ""

# Show defense recommendations
cat << 'EOF'

=== Defense Level Recommendations ===

Production (balanced security/performance):
  CODOH_HIT_SUPPRESSION_PROB=0.1
  CODOH_INSERT_PROB=0.9
  Expected: ~10% latency increase, strong snapshot resistance

High Security (privacy-focused):
  CODOH_HIT_SUPPRESSION_PROB=0.2
  CODOH_INSERT_PROB=0.8
  CODOH_USE_ORAM=true
  CODOH_CHURN_ENABLED=true
  CODOH_CHURN_INTERVAL_SECS=60
  Expected: ~25% latency increase, very strong snapshot resistance

Maximum Security (paranoid mode):
  CODOH_HIT_SUPPRESSION_PROB=0.3
  CODOH_INSERT_PROB=0.7
  CODOH_USE_ORAM=true
  CODOH_CHURN_ENABLED=true
  CODOH_CHURN_INTERVAL_SECS=30
  Expected: ~50% latency increase, maximum snapshot resistance

EOF