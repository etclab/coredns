#!/bin/bash
# CODoH Benchmark Script
# Compares ODoH (baseline) vs CODoH latency

set -e

ITERATIONS=${1:-1000}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="benchmark-results/$TIMESTAMP"
CLIENT_PATH="/Users/pniroula/Projects/codoh/odoh-client-go/odoh-client"
CERT_PATH="/Users/pniroula/Projects/codoh/coredns/localhost.pem"

mkdir -p "$OUTPUT_DIR"

echo "=== CODoH Benchmark Suite ==="
echo "Iterations: $ITERATIONS"
echo "Output dir: $OUTPUT_DIR"
echo ""

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
./coredns-test -conf Corefile.odoh-target > /tmp/odoh-target.log 2>&1 &
sleep 2

# Start ODoH proxy (port 9080)
echo "Starting ODoH proxy..."
./coredns-test -conf Corefile.odoh-proxy > /tmp/odoh-proxy.log 2>&1 &
sleep 2

# Health check
curl -sk https://127.0.0.1:9080/health > /dev/null && echo "ODoH proxy: OK" || echo "ODoH proxy: FAILED"
curl -sk https://127.0.0.1:9443/health > /dev/null && echo "ODoH target: OK" || echo "ODoH target: FAILED"

echo "Running ODoH benchmark..."
$CLIENT_PATH latency \
    --protocol odoh \
    --scenario cold \
    --iterations $ITERATIONS \
    --target 127.0.0.1:9443 \
    --proxy 127.0.0.1:9080 \
    --customcert $CERT_PATH \
    --output "$OUTPUT_DIR/odoh_cold.csv" \
    --summary "$OUTPUT_DIR/odoh_cold.json" \
    --domain-prefix "odoh"

#######################################
# CODoH Benchmark
#######################################
echo ""
echo "=== Starting CODoH Benchmark ==="

cleanup

# Start enclave
echo "Starting enclave..."
SECRET_HEX=$(cat dev-master-secret.txt)
CODOH_MASTER_SECRET=$SECRET_HEX ./enclave-test > /tmp/enclave.log 2>&1 &
sleep 2

# Start CODoH target (port 8443)
echo "Starting CODoH target..."
./coredns-test -conf Corefile.target > /tmp/codoh-target.log 2>&1 &
sleep 2

# Start CODoH proxy (port 8080)
echo "Starting CODoH proxy..."
./coredns-test -conf Corefile.proxy > /tmp/codoh-proxy.log 2>&1 &
sleep 2

# Health check
curl -sk https://127.0.0.1:8080/health > /dev/null && echo "CODoH proxy: OK" || echo "CODoH proxy: FAILED"
curl -sk https://127.0.0.1:8443/health > /dev/null && echo "CODoH target: OK" || echo "CODoH target: FAILED"

echo "Running CODoH benchmark (cold cache)..."
$CLIENT_PATH latency \
    --protocol codoh \
    --scenario cold \
    --iterations $ITERATIONS \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert $CERT_PATH \
    --output "$OUTPUT_DIR/codoh_cold.csv" \
    --summary "$OUTPUT_DIR/codoh_cold.json" \
    --domain-prefix "codoh-cold"

echo ""
echo "Running CODoH benchmark (warm cache)..."
$CLIENT_PATH latency \
    --protocol codoh \
    --scenario warm \
    --iterations $ITERATIONS \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert $CERT_PATH \
    --output "$OUTPUT_DIR/codoh_warm.csv" \
    --summary "$OUTPUT_DIR/codoh_warm.json" \
    --domain-prefix "codoh-warm"

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
cat "$OUTPUT_DIR/odoh_cold.json" | grep -E '"(mean|p50|p95|p99)"' | head -4
echo ""
echo "CODoH (cold cache):"
cat "$OUTPUT_DIR/codoh_cold.json" | grep -E '"(mean|p50|p95|p99)"' | head -4
echo ""
echo "CODoH (warm cache):"
cat "$OUTPUT_DIR/codoh_warm.json" | grep -E '"(mean|p50|p95|p99)"' | head -4
