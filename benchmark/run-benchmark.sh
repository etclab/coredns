#!/bin/bash
# CODoH Benchmark Script
# Compares ODoH (baseline) vs CODoH latency with real domain dataset
# Usage: ./benchmark/run-benchmark.sh [--sgx] [--oram] [iterations]
#   --sgx       Include SGX hardware enclave benchmark (requires SGX device access)
#   --oram      Use ORAM cache instead of LRU cache (for access pattern hiding)
#   iterations  Number of queries per benchmark (default: 1000)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse arguments
SGX_MODE=false
ORAM_MODE=false
ITERATIONS=1000
for arg in "$@"; do
    if [[ "$arg" == "--sgx" ]]; then
        SGX_MODE=true
    elif [[ "$arg" == "--oram" ]]; then
        ORAM_MODE=true
    elif [[ "$arg" =~ ^[0-9]+$ ]]; then
        ITERATIONS=$arg
    fi
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$SCRIPT_DIR/results/$TIMESTAMP"
CLIENT_PATH="$(dirname "$ROOT_DIR")/codoh-client/odoh-client"
CERT_PATH="$ROOT_DIR/localhost.pem"
DOMAINS_PATH="$SCRIPT_DIR/top-1m.csv"

mkdir -p "$OUTPUT_DIR"

echo "=== CODoH Benchmark Suite ==="
echo "Iterations: $ITERATIONS"
echo "SGX mode:   $SGX_MODE"
echo "ORAM cache: $ORAM_MODE"
echo "Output dir: $OUTPUT_DIR"
echo "Domains:    $DOMAINS_PATH"
echo ""

cd "$ROOT_DIR"

cleanup() {
    echo "Cleaning up..."
    pkill -9 -f coredns-test 2>/dev/null || true
    pkill -9 -f enclave-sim 2>/dev/null || true
    pkill -9 -f enclave-sgx 2>/dev/null || true
    pkill -9 -f erthost 2>/dev/null || true  # EGo runtime host
    # Kill any processes on our test ports
    # fuser -k 8080/tcp 8443/tcp 9080/tcp 9443/tcp 18080/tcp 18443/tcp 18444/tcp 2>/dev/null || true
    # With (cross-platform):
    for port in 8080 8443 9080 9443 18080 18443 18444; do
        lsof -ti :$port | xargs kill -9 2>/dev/null || true
    done
    rm -f /tmp/codoh-enclave.sock /tmp/codoh-sgx-enclave.sock 2>/dev/null || true
    sleep 2
}
trap cleanup EXIT

# Build if needed
echo "Building binaries..."
go build -o coredns-test . 2>/dev/null
go build -o enclave-sim ./enclave/cmd 2>/dev/null
if $SGX_MODE; then
    echo "Building SGX enclave..."
    (cd enclave && ego-go build -tags ego -o enclave ./cmd) 2>/dev/null
    (cd enclave && ego sign enclave) 2>/dev/null
    mv enclave/enclave "$ROOT_DIR/enclave-sgx"
fi
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
# CODoH Benchmark (Simulation Mode)
#######################################
if ! $SGX_MODE; then
    echo ""
    echo "=== Starting CODoH Benchmark (Simulation) ==="

    cleanup

    # Start enclave (simulation mode)
    echo "Starting enclave (simulation)..."
    SECRET_HEX=$(cat "$ROOT_DIR/dev-master-secret.txt")
    if $ORAM_MODE; then
        echo "Using ORAM cache"
        CODOH_USE_ORAM=true CODOH_MASTER_SECRET=$SECRET_HEX ./enclave-sim > /tmp/enclave.log 2>&1 &
    else
        echo "Using LRU cache"
        CODOH_MASTER_SECRET=$SECRET_HEX ./enclave-sim > /tmp/enclave.log 2>&1 &
    fi
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

    echo "Running CODoH simulation benchmark (cold)..."
    $CLIENT_PATH latency \
        --protocol codoh \
        --distribution sequential \
        --iterations $ITERATIONS \
        --target 127.0.0.1:8443 \
        --proxy 127.0.0.1:8080 \
        --customcert $CERT_PATH \
        --domains $DOMAINS_PATH \
        --output "$OUTPUT_DIR/codoh_sim_cold.csv" \
        --summary "$OUTPUT_DIR/codoh_sim_cold.json"

    echo ""
    echo "Running CODoH simulation benchmark (zipf)..."
    $CLIENT_PATH latency \
        --protocol codoh \
        --distribution zipf \
        --zipf-s 1.0 \
        --iterations $ITERATIONS \
        --target 127.0.0.1:8443 \
        --proxy 127.0.0.1:8080 \
        --customcert $CERT_PATH \
        --domains $DOMAINS_PATH \
        --output "$OUTPUT_DIR/codoh_sim_zipf.csv" \
        --summary "$OUTPUT_DIR/codoh_sim_zipf.json"

    echo ""
    echo "Running CODoH simulation benchmark (warm)..."
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
        --output "$OUTPUT_DIR/codoh_sim_warm.csv" \
        --summary "$OUTPUT_DIR/codoh_sim_warm.json"
fi

#######################################
# CODoH Benchmark (SGX Hardware Mode)
#######################################
if $SGX_MODE; then
    echo ""
    echo "=== Starting CODoH Benchmark (SGX Hardware) ==="

    cleanup

    # Create SGX-specific Corefiles
    cat > /tmp/codoh-sgx-target.conf << EOF
.:5353 {
    codohtarget {
        port 18443
        tls_cert $CERT_PATH
        tls_key ${CERT_PATH%.pem}-key.pem
        upstream 8.8.8.8:53
        token_enabled
        epoch_duration 1h
        rate_limit 10000
        master_secret $ROOT_DIR/dev-master-secret.txt
        enclave_url https://localhost:18444
    }
}
EOF

    cat > /tmp/codoh-sgx-proxy.conf << EOF
.:5353 {
    codohproxy {
        port 18080
        target https://localhost:18443/dns-query
        tls_cert $CERT_PATH
        tls_key ${CERT_PATH%.pem}-key.pem
        insecure_skip_verify true
        enclave_enabled
        enclave_socket /tmp/codoh-sgx-enclave.sock
        enclave_bypass_on_failure
    }
}
EOF

    # Start SGX enclave
    echo "Starting SGX enclave..."
    if $ORAM_MODE; then
        echo "Using ORAM cache (SGX)"
        CODOH_USE_ORAM=true ego run ./enclave-sgx --socket /tmp/codoh-sgx-enclave.sock --https-port 18444 > /tmp/enclave-sgx.log 2>&1 &
    else
        echo "Using LRU cache (SGX)"
        ego run ./enclave-sgx --socket /tmp/codoh-sgx-enclave.sock --https-port 18444 > /tmp/enclave-sgx.log 2>&1 &
    fi
    ENCLAVE_SGX_PID=$!
    sleep 3

    # Verify SGX enclave started
    if ! kill -0 $ENCLAVE_SGX_PID 2>/dev/null; then
        echo "ERROR: SGX enclave failed to start. Check /tmp/enclave-sgx.log"
        cat /tmp/enclave-sgx.log | tail -10
        exit 1
    fi

    # Wait for attestation server
    echo "Waiting for SGX attestation server..."
    for i in {1..10}; do
        if curl -sk https://localhost:18444/health > /dev/null 2>&1; then
            echo "SGX attestation server ready"
            break
        fi
        sleep 1
    done

    # Start CODoH target (provisions to SGX enclave)
    echo "Starting CODoH target (will provision to SGX enclave)..."
    ./coredns-test -conf /tmp/codoh-sgx-target.conf > /tmp/codoh-sgx-target.log 2>&1 &
    sleep 3

    # Wait for enclave socket (target must provision first)
    echo "Waiting for SGX enclave provisioning..."
    for i in {1..30}; do
        if [ -S /tmp/codoh-sgx-enclave.sock ]; then
            echo "SGX enclave socket ready"
            break
        fi
        sleep 1
    done

    # Start CODoH proxy
    echo "Starting CODoH proxy..."
    ./coredns-test -conf /tmp/codoh-sgx-proxy.conf > /tmp/codoh-sgx-proxy.log 2>&1 &
    sleep 2

    # Health check
    curl -sk https://127.0.0.1:18080/health > /dev/null && echo "CODoH SGX proxy: OK" || echo "CODoH SGX proxy: FAILED"
    curl -sk https://127.0.0.1:18443/health > /dev/null && echo "CODoH SGX target: OK" || echo "CODoH SGX target: FAILED"

    echo "Running CODoH SGX benchmark (cold)..."
    $CLIENT_PATH latency \
        --protocol codoh \
        --distribution sequential \
        --iterations $ITERATIONS \
        --target 127.0.0.1:18443 \
        --proxy 127.0.0.1:18080 \
        --customcert $CERT_PATH \
        --domains $DOMAINS_PATH \
        --output "$OUTPUT_DIR/codoh_sgx_cold.csv" \
        --summary "$OUTPUT_DIR/codoh_sgx_cold.json"

    echo ""
    echo "Running CODoH SGX benchmark (zipf)..."
    $CLIENT_PATH latency \
        --protocol codoh \
        --distribution zipf \
        --zipf-s 1.0 \
        --iterations $ITERATIONS \
        --target 127.0.0.1:18443 \
        --proxy 127.0.0.1:18080 \
        --customcert $CERT_PATH \
        --domains $DOMAINS_PATH \
        --output "$OUTPUT_DIR/codoh_sgx_zipf.csv" \
        --summary "$OUTPUT_DIR/codoh_sgx_zipf.json"

    echo ""
    echo "Running CODoH SGX benchmark (warm)..."
    $CLIENT_PATH latency \
        --protocol codoh \
        --distribution sequential \
        --iterations $ITERATIONS \
        --target 127.0.0.1:18443 \
        --proxy 127.0.0.1:18080 \
        --customcert $CERT_PATH \
        --domains /tmp/warm-domain.csv \
        --output "$OUTPUT_DIR/codoh_sgx_warm.csv" \
        --summary "$OUTPUT_DIR/codoh_sgx_warm.json"
fi

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

if ! $SGX_MODE; then
    echo ""
    echo "CODoH Simulation (cold):"
    cat "$OUTPUT_DIR/codoh_sim_cold.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
    echo ""
    echo "CODoH Simulation (zipf):"
    cat "$OUTPUT_DIR/codoh_sim_zipf.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
    echo ""
    echo "CODoH Simulation (warm):"
    cat "$OUTPUT_DIR/codoh_sim_warm.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
fi

if $SGX_MODE; then
    echo ""
    echo "CODoH SGX (cold):"
    cat "$OUTPUT_DIR/codoh_sgx_cold.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
    echo ""
    echo "CODoH SGX (zipf):"
    cat "$OUTPUT_DIR/codoh_sgx_zipf.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
    echo ""
    echo "CODoH SGX (warm):"
    cat "$OUTPUT_DIR/codoh_sgx_warm.json" | grep -E '"(mean|p50|p95|p99|cache_hit_rate)"' | head -5
fi
