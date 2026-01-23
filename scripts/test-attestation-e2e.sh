#!/bin/bash
# End-to-end test for CODoH attestation flow
# Usage: ./scripts/test-attestation-e2e.sh [--sgx]
#   --sgx    Run with real SGX hardware (requires ego, SGX device access)
#   (default) Run in simulation mode

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR="/tmp/codoh-test-$$"

# Parse arguments
SGX_MODE=false
if [[ "$1" == "--sgx" ]]; then
    SGX_MODE=true
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

cleanup() {
    log "Cleaning up..."
    [ -n "$ENCLAVE_PID" ] && kill $ENCLAVE_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill $TARGET_PID 2>/dev/null || true
    [ -n "$PROXY_PID" ] && kill $PROXY_PID 2>/dev/null || true
    rm -rf "$TEST_DIR"
    log "Cleanup complete"
}
trap cleanup EXIT

# Create test directory
mkdir -p "$TEST_DIR"
cd "$PROJECT_ROOT"

if $SGX_MODE; then
    log "Running in SGX mode"
else
    log "Running in simulation mode (use --sgx for hardware SGX)"
fi
log "Test directory: $TEST_DIR"

# Step 1: Generate master secret
log "Generating master secret..."
openssl rand -hex 32 > "$TEST_DIR/master-secret.txt"

# Step 2: Generate TLS certificates (with SANs for modern TLS verification)
log "Generating TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# Step 3: Build components
log "Building enclave..."
if $SGX_MODE; then
    (cd enclave && ego-go build -tags ego -o "$TEST_DIR/enclave" ./cmd)
    cp enclave/enclave.json enclave/private.pem "$TEST_DIR/"
    (cd "$TEST_DIR" && ego sign enclave)
else
    (cd enclave && go build -o "$TEST_DIR/enclave" ./cmd)
fi

log "Building coredns..."
go build -o "$TEST_DIR/coredns" .

# Step 4: Create Corefiles
log "Creating configuration files..."

if $SGX_MODE; then
    # SGX mode: target provisions secret to enclave via HTTPS
    cat > "$TEST_DIR/target-corefile" << EOF
.:15354 {
    codohtarget {
        port 18443
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        upstream 8.8.8.8:53
        token_enabled
        epoch_duration 1h
        rate_limit 100
        master_secret $TEST_DIR/master-secret.txt
        enclave_url https://localhost:18444
    }
}
EOF
else
    # Simulation mode: both use shared secret file
    cat > "$TEST_DIR/target-corefile" << EOF
.:15354 {
    codohtarget {
        port 18443
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        upstream 8.8.8.8:53
        token_enabled
        epoch_duration 1h
        rate_limit 100
        master_secret $TEST_DIR/master-secret.txt
    }
}
EOF
fi

cat > "$TEST_DIR/proxy-corefile" << EOF
.:15353 {
    codohproxy {
        port 18080
        target https://localhost:18443/dns-query
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        insecure_skip_verify true
        enclave_enabled
        enclave_socket $TEST_DIR/enclave.sock
        enclave_bypass_on_failure
    }
}
EOF

# Step 5: Start enclave
if $SGX_MODE; then
    log "Starting enclave (SGX mode)..."
    ego run "$TEST_DIR/enclave" \
        --socket "$TEST_DIR/enclave.sock" \
        --https-port 18444 \
        > "$TEST_DIR/enclave.log" 2>&1 &
else
    log "Starting enclave (simulation mode)..."
    "$TEST_DIR/enclave" \
        --socket "$TEST_DIR/enclave.sock" \
        --https-port 18444 \
        --secret "$TEST_DIR/master-secret.txt" \
        > "$TEST_DIR/enclave.log" 2>&1 &
fi
ENCLAVE_PID=$!

# Wait for enclave to start
sleep 2
if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
    error "Enclave failed to start. Check $TEST_DIR/enclave.log"
fi
log "Enclave started (PID: $ENCLAVE_PID)"

# Step 6: Start target
log "Starting target..."
"$TEST_DIR/coredns" -conf "$TEST_DIR/target-corefile" \
    > "$TEST_DIR/target.log" 2>&1 &
TARGET_PID=$!

sleep 2
if ! kill -0 $TARGET_PID 2>/dev/null; then
    error "Target failed to start. Check $TEST_DIR/target.log"
fi
log "Target started (PID: $TARGET_PID)"

# Wait for enclave socket (in SGX mode, target must provision first)
log "Waiting for enclave IPC socket..."
for i in {1..30}; do
    if [ -S "$TEST_DIR/enclave.sock" ]; then
        log "Enclave socket ready"
        break
    fi
    sleep 1
done
if [ ! -S "$TEST_DIR/enclave.sock" ]; then
    warn "Enclave socket not found after 30s, continuing anyway"
fi

# Step 7: Start proxy
log "Starting proxy..."
"$TEST_DIR/coredns" -conf "$TEST_DIR/proxy-corefile" \
    > "$TEST_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

sleep 3
if ! kill -0 $PROXY_PID 2>/dev/null; then
    error "Proxy failed to start. Check $TEST_DIR/proxy.log"
fi
log "Proxy started (PID: $PROXY_PID)"

# Step 8: Verify services
log "Verifying services..."

# Check enclave IPC socket
if [ -S "$TEST_DIR/enclave.sock" ]; then
    log "Enclave IPC socket: OK"
else
    warn "Enclave IPC socket not found"
fi

# Check enclave HTTPS (only available in SGX mode)
ENCLAVE_HEALTH=$(curl -sk https://localhost:18444/health 2>/dev/null || echo "")
if [[ "$ENCLAVE_HEALTH" == *"ready"* ]]; then
    log "Enclave HTTPS health: ready (SGX mode)"
elif [[ -n "$ENCLAVE_HEALTH" ]]; then
    warn "Enclave HTTPS health: $ENCLAVE_HEALTH"
else
    log "Enclave HTTPS: not running (simulation mode)"
fi

# Check enclave attestation endpoint (SGX mode only)
ATTEST=$(curl -sk https://localhost:18444/attest 2>/dev/null || echo "")
if [[ "$ATTEST" == *"pubkey"* ]]; then
    log "Enclave attestation endpoint: OK"
fi

# Check target health
TARGET_HEALTH=$(curl -sk https://localhost:18443/health 2>/dev/null || echo "failed")
if [[ "$TARGET_HEALTH" == "OK" ]]; then
    log "Target health: OK"
else
    warn "Target health: $TARGET_HEALTH"
fi

# Check proxy health
PROXY_HEALTH=$(curl -sk https://localhost:18080/health 2>/dev/null || echo "failed")
if [[ "$PROXY_HEALTH" == "OK" ]]; then
    log "Proxy health: OK"
else
    warn "Proxy health: $PROXY_HEALTH"
fi

# Step 9: Show logs
echo ""
log "=== Enclave Log (last 10 lines) ==="
tail -10 "$TEST_DIR/enclave.log"

echo ""
log "=== Target Log (last 10 lines) ==="
tail -10 "$TEST_DIR/target.log"

echo ""
log "=== Proxy Log (last 10 lines) ==="
tail -10 "$TEST_DIR/proxy.log"

# Step 10: Test with odoh-client
echo ""
ODOH_CLIENT="$PROJECT_ROOT/../codoh-client/odoh-client"
if [ -x "$ODOH_CLIENT" ]; then
    log "Testing with odoh-client..."
    "$ODOH_CLIENT" odoh --domain example.com. --dnstype A \
        --proxy localhost:18080 \
        --target localhost:18443 \
        --enclave \
        --customcert "$TEST_DIR/cert.pem" 2>&1 || warn "odoh-client test failed"
else
    warn "odoh-client not found at $ODOH_CLIENT"
    log "Build it with: cd ../codoh-client && go build -o odoh-client ./cmd/..."
fi

echo ""
log "=== Test Summary ==="
if $SGX_MODE; then
    log "Mode:     SGX hardware"
    log "Enclave:  IPC at $TEST_DIR/enclave.sock, HTTPS at https://localhost:18444 (PID: $ENCLAVE_PID)"
else
    log "Mode:     Simulation"
    log "Enclave:  IPC at $TEST_DIR/enclave.sock (PID: $ENCLAVE_PID)"
fi
log "Target:   https://localhost:18443 (PID: $TARGET_PID)"
log "Proxy:    https://localhost:18080 (PID: $PROXY_PID)"
log "Logs:     $TEST_DIR/*.log"
echo ""
log "Press Ctrl+C to stop all services and cleanup"

# Keep running until interrupted
wait
