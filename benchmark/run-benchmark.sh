#!/bin/bash
# CODoH Benchmark Script
# Compares ODoH (baseline) vs CODoH latency with real domain dataset
# Run from coredns root: ./benchmark/run-benchmark.sh [iterations]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

ITERATIONS=${1:-1000}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$SCRIPT_DIR/results/$TIMESTAMP"
CLIENT_PATH="/Users/pniroula/Projects/codoh/odoh-client-go/odoh-client"
CERT_PATH="$ROOT_DIR/localhost.pem"
DOMAINS_PATH="$SCRIPT_DIR/top-1m.csv"

mkdir -p "$OUTPUT_DIR"

echo "=== CODoH Benchmark Suite ==="
echo "Iterations: $ITERATIONS"
echo "Output dir: $OUTPUT_DIR"
echo "Domains:    $DOMAINS_PATH"
echo ""

cd "$ROOT_DIR"

cleanup() {
    echo "Cleaning up..."
    pkill -9 coredns 2>/dev/null || true
    pkill -9 enclave 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# Build if needed
echo "Building binaries..."
go build -o coredns-test . 2>/dev/null
go build -o enclave-test ./enclave/cmd 2>/dev/null
echo "Build complete."
echo ""

#######################################
# ODoH Baseline Benchmark
#######################################
echo "=== Starting ODoH Baseline Benchmark ==="

cleanup

# Start ODoH target (port 9443)
echo "Starting ODoH target..."
./coredns-test -conf "$SCRIPT_DIR/Corefile.odoh-target" > /tmp/odoh-target.log 2>&1 &
sleep 2

# Start ODoH proxy (port 9080)
echo "Starting ODoH proxy..."
./coredns-test -conf "$SCRIPT_DIR/Corefile.odoh-proxy" > /tmp/odoh-proxy.log 2>&1 &
sleep 2

# Health check
curl -sk https://127.0.0.1:9080/health > /dev/null && echo "ODoH proxy: OK" || echo "ODoH proxy: FAILED"
curl -sk https://127.0.0.1:9443/health > /dev/null && echo "ODoH target: OK" || echo "ODoH target: FAILED"

echo "Running ODoH benchmark (sequential)..."
$CLIENT_PATH latency \
    --protocol odoh \
    --distribution sequential \
    --iterations $ITERATIONS \
    --target 127.0.0.1:9443 \
    --proxy 127.0.0.1:9080 \
    --customcert $CERT_PATH \
    --domains $DOMAINS_PATH \
    --output "$OUTPUT_DIR/odoh.csv" \
    --summary "$OUTPUT_DIR/odoh.json"

#######################################
# CODoH Benchmark
#######################################
echo ""
echo "=== Starting CODoH Benchmark ==="

cleanup

# Start enclave
echo "Starting enclave..."
SECRET_HEX=$(cat "$ROOT_DIR/dev-master-secret.txt")
CODOH_MASTER_SECRET=$SECRET_HEX ./enclave-test > /tmp/enclave.log 2>&1 &
sleep 2

# Start CODoH target (port 8443)
echo "Starting CODoH target..."
./coredns-test -conf "$ROOT_DIR/Corefile.target" > /tmp/codoh-target.log 2>&1 &
sleep 2

# Start CODoH proxy (port 8080)
echo "Starting CODoH proxy..."
./coredns-test -conf "$ROOT_DIR/Corefile.proxy" > /tmp/codoh-proxy.log 2>&1 &
sleep 2

# Health check
curl -sk https://127.0.0.1:8080/health > /dev/null && echo "CODoH proxy: OK" || echo "CODoH proxy: FAILED"
curl -sk https://127.0.0.1:8443/health > /dev/null && echo "CODoH target: OK" || echo "CODoH target: FAILED"

echo "Running CODoH benchmark (sequential - cold cache)..."
$CLIENT_PATH latency \
    --protocol codoh \
    --distribution sequential \
    --iterations $ITERATIONS \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert $CERT_PATH \
    --domains $DOMAINS_PATH \
    --output "$OUTPUT_DIR/codoh_cold.csv" \
    --summary "$OUTPUT_DIR/codoh_cold.json"

echo ""
echo "Running CODoH benchmark (zipf - realistic cache)..."
$CLIENT_PATH latency \
    --protocol codoh \
    --distribution zipf \
    --zipf-s 1.0 \
    --iterations $ITERATIONS \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert $CERT_PATH \
    --domains $DOMAINS_PATH \
    --output "$OUTPUT_DIR/codoh_zipf.csv" \
    --summary "$OUTPUT_DIR/codoh_zipf.json"

echo ""
echo "Running CODoH benchmark (warm - best case cache)..."
# Create single-domain file for warm test
echo "1,google.com" > /tmp/warm-domain.csv
$CLIENT_PATH latency \
    --protocol codoh \
    --distribution sequential \
    --iterations $ITERATIONS \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert $CERT_PATH \
    --domains /tmp/warm-domain.csv \
    --output "$OUTPUT_DIR/codoh_warm.csv" \
    --summary "$OUTPUT_DIR/codoh_warm.json"

#######################################
# Summary
#######################################
echo ""
echo "=== Benchmark Complete ==="
echo "Results saved to $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/

echo ""
echo "=== Quick Comparison ==="
echo "ODoH (baseline):"
cat "$OUTPUT_DIR/odoh.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
echo ""
echo "CODoH (cold - sequential):"
cat "$OUTPUT_DIR/codoh_cold.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
echo ""
echo "CODoH (zipf - realistic):"
cat "$OUTPUT_DIR/codoh_zipf.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
echo ""
echo "CODoH (warm - best case):"
cat "$OUTPUT_DIR/codoh_warm.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
