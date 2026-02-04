#!/bin/bash
# End-to-end test for MLE (Message-Locked Encryption) mode
# Tests the ciphertext-only cache functionality
#
# Usage: ./scripts/test-mle-e2e.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLIENT_ROOT="$PROJECT_ROOT/../codoh-client"
TEST_DIR="/tmp/codoh-mle-test-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

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

log "=== MLE End-to-End Test ==="
log "Test directory: $TEST_DIR"
echo ""

# Step 1: Generate master secret and signing key
log "Generating secrets..."
openssl rand -hex 32 > "$TEST_DIR/master-secret.txt"

# Step 2: Generate TLS certificates
log "Generating TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# Step 3: Build components
log "Building enclave..."
go build -o "$TEST_DIR/enclave" ./enclave/cmd

log "Building coredns..."
go build -o "$TEST_DIR/coredns" .

log "Building odoh-client..."
(cd "$CLIENT_ROOT" && go build -o "$TEST_DIR/odoh-client" ./cmd/...)

# Step 4: Create Corefiles with signing key for MLE
log "Creating configuration files..."

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
        signing_key $TEST_DIR/signing-key.pem
    }
}
EOF

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
log "Starting enclave..."
"$TEST_DIR/enclave" \
    --socket "$TEST_DIR/enclave.sock" \
    --https-port 18444 \
    --secret "$TEST_DIR/master-secret.txt" \
    > "$TEST_DIR/enclave.log" 2>&1 &
ENCLAVE_PID=$!

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

# Wait for signing key to be generated
sleep 1

# Wait for enclave socket
log "Waiting for enclave IPC socket..."
for i in {1..10}; do
    if [ -S "$TEST_DIR/enclave.sock" ]; then
        log "Enclave socket ready"
        break
    fi
    sleep 1
done
if [ ! -S "$TEST_DIR/enclave.sock" ]; then
    error "Enclave socket not found"
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

echo ""
log "=== Testing MLE Functionality ==="
echo ""

# Test 1: Salt endpoint
info "Test 1: Salt endpoint"
SALT_RESPONSE=$(curl -sk https://localhost:18443/.well-known/codoh-salt 2>/dev/null)
if echo "$SALT_RESPONSE" | grep -q '"epoch"'; then
    echo -e "${GREEN}✓${NC} Salt endpoint returns valid JSON"
    echo "  Response: $SALT_RESPONSE"
else
    echo -e "${RED}✗${NC} Salt endpoint failed"
    echo "  Response: $SALT_RESPONSE"
fi
echo ""

# Test 2: Health checks
info "Test 2: Health checks"
TARGET_HEALTH=$(curl -sk https://localhost:18443/health 2>/dev/null || echo "failed")
PROXY_HEALTH=$(curl -sk https://localhost:18080/health 2>/dev/null || echo "failed")

if [[ "$TARGET_HEALTH" == "OK" ]]; then
    echo -e "${GREEN}✓${NC} Target health: OK"
else
    echo -e "${RED}✗${NC} Target health: $TARGET_HEALTH"
fi

if [[ "$PROXY_HEALTH" == "OK" ]]; then
    echo -e "${GREEN}✓${NC} Proxy health: OK"
else
    echo -e "${RED}✗${NC} Proxy health: $PROXY_HEALTH"
fi
echo ""

# Test 3: Legacy enclave mode (for comparison)
info "Test 3: Legacy enclave mode query"
ENCLAVE_RESULT=$("$TEST_DIR/odoh-client" odoh \
    --domain example.com. --dnstype A \
    --proxy localhost:18080 \
    --target localhost:18443 \
    --enclave \
    --customcert "$TEST_DIR/cert.pem" 2>&1) || true

if echo "$ENCLAVE_RESULT" | grep -q "CACHE"; then
    echo -e "${GREEN}✓${NC} Legacy enclave mode works"
    echo "$ENCLAVE_RESULT" | grep -E "(CACHE|example\.com)" | head -3
else
    echo -e "${YELLOW}!${NC} Legacy enclave mode result:"
    echo "$ENCLAVE_RESULT" | head -5
fi
echo ""

# Test 4: MLE mode - first query (cache miss expected)
info "Test 4: MLE mode - first query (expect cache miss)"
TEST_DOMAIN="mle-test-$(date +%s).example.com."
MLE_RESULT1=$("$TEST_DIR/odoh-client" odoh \
    --domain "$TEST_DOMAIN" --dnstype A \
    --proxy localhost:18080 \
    --target localhost:18443 \
    --mle \
    --customcert "$TEST_DIR/cert.pem" 2>&1) || true

if echo "$MLE_RESULT1" | grep -q "MLE CACHE MISS"; then
    echo -e "${GREEN}✓${NC} MLE cache miss (expected for first query)"
elif echo "$MLE_RESULT1" | grep -q "MLE"; then
    echo -e "${YELLOW}!${NC} MLE result (unexpected):"
    echo "$MLE_RESULT1" | head -5
else
    echo -e "${RED}✗${NC} MLE mode failed:"
    echo "$MLE_RESULT1" | head -10
fi
echo ""

# Test 5: MLE mode - second query (cache hit expected)
info "Test 5: MLE mode - second query (expect cache hit)"
sleep 1
MLE_RESULT2=$("$TEST_DIR/odoh-client" odoh \
    --domain "$TEST_DOMAIN" --dnstype A \
    --proxy localhost:18080 \
    --target localhost:18443 \
    --mle \
    --customcert "$TEST_DIR/cert.pem" 2>&1) || true

if echo "$MLE_RESULT2" | grep -q "MLE CACHE HIT"; then
    echo -e "${GREEN}✓${NC} MLE cache hit (expected for second query)"
    echo "$MLE_RESULT2" | grep "MLE CACHE HIT"
elif echo "$MLE_RESULT2" | grep -q "MLE CACHE MISS"; then
    echo -e "${YELLOW}!${NC} MLE cache miss (unexpected - cache may not be working)"
else
    echo -e "${RED}✗${NC} MLE mode failed:"
    echo "$MLE_RESULT2" | head -10
fi
echo ""

# Test 6: Different domain should miss
info "Test 6: Different domain (expect cache miss)"
DIFF_DOMAIN="different-$(date +%s).example.com."
MLE_RESULT3=$("$TEST_DIR/odoh-client" odoh \
    --domain "$DIFF_DOMAIN" --dnstype A \
    --proxy localhost:18080 \
    --target localhost:18443 \
    --mle \
    --customcert "$TEST_DIR/cert.pem" 2>&1) || true

if echo "$MLE_RESULT3" | grep -q "MLE CACHE MISS"; then
    echo -e "${GREEN}✓${NC} Different domain misses cache (correct)"
else
    echo -e "${YELLOW}!${NC} Unexpected result:"
    echo "$MLE_RESULT3" | head -5
fi
echo ""

# Show relevant logs
log "=== Enclave Log (MLE-related) ==="
grep -i "mle\|tag\|lookup\|store" "$TEST_DIR/enclave.log" 2>/dev/null | tail -20 || echo "  No MLE logs found"

echo ""
log "=== Target Log (MLE-related) ==="
grep -i "mle\|salt\|argon" "$TEST_DIR/target.log" 2>/dev/null | tail -10 || echo "  No MLE logs found"

echo ""
log "=== Test Summary ==="
log "Test directory: $TEST_DIR"
log "Enclave PID: $ENCLAVE_PID"
log "Target PID: $TARGET_PID"
log "Proxy PID: $PROXY_PID"
echo ""
log "Full logs available at:"
log "  $TEST_DIR/enclave.log"
log "  $TEST_DIR/target.log"
log "  $TEST_DIR/proxy.log"
echo ""

# Summary
echo -e "${BLUE}=== MLE Test Results ===${NC}"
if echo "$MLE_RESULT1" | grep -q "MLE"; then
    echo -e "${GREEN}✓${NC} MLE mode is functional"
else
    echo -e "${RED}✗${NC} MLE mode may have issues"
fi

echo ""
log "Press Ctrl+C to stop all services and cleanup"
wait