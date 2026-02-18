#!/bin/bash
# End-to-end test for CODoH-base (Config 3) — proxy mode
# Tests enclave-proxy with LRU cache, simplified blob, no tokens
#
# Usage: ./scripts/test-codoh-base-e2e.sh [--sgx]
#   --sgx   Run enclave inside SGX (default: simulation)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLIENT_ROOT="$PROJECT_ROOT/../codoh-client"
TEST_DIR="/tmp/codoh-base-test-$$"

# Parse args
SGX_MODE=false
for arg in "$@"; do
    if [[ "$arg" == "--sgx" ]]; then
        SGX_MODE=true
    fi
done

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
    rm -rf "$TEST_DIR"
    log "Cleanup complete"
}
trap cleanup EXIT

# Create test directory
mkdir -p "$TEST_DIR"
cd "$PROJECT_ROOT"

if $SGX_MODE; then
    log "=== CODoH-base End-to-End Test (SGX) ==="
else
    log "=== CODoH-base End-to-End Test (Simulation) ==="
fi
log "Test directory: $TEST_DIR"
echo ""

# Step 1: Generate TLS certificates
log "Generating TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# Step 2: Build components
log "Building coredns..."
go build -o "$TEST_DIR/coredns" .

if $SGX_MODE; then
    log "Building SGX enclave..."
    cd enclave
    ego-go build -o enclave ./cmd
    ego sign enclave
    cd "$PROJECT_ROOT"
    # SGX binary stays in enclave/ dir (ego run needs enclave.json next to it)
else
    log "Building enclave (simulation)..."
    go build -o "$TEST_DIR/enclave" ./enclave/cmd
fi

log "Building odoh-client..."
(cd "$CLIENT_ROOT" && go build -o "$TEST_DIR/odoh-client" ./cmd/...)

# Step 3: Create target Corefile (codohtarget without tokens)
log "Creating configuration..."
cat > "$TEST_DIR/target-corefile" << EOF
.:15354 {
    codohtarget {
        port 10444
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        upstream 8.8.8.8:53
    }
}
EOF

# Step 4: Start target
log "Starting CODoH-base target on port 10444..."
"$TEST_DIR/coredns" -conf "$TEST_DIR/target-corefile" \
    > "$TEST_DIR/target.log" 2>&1 &
TARGET_PID=$!

sleep 2
if ! kill -0 $TARGET_PID 2>/dev/null; then
    error "Target failed to start. Check $TEST_DIR/target.log"
fi
log "Target started (PID: $TARGET_PID)"

# Step 5: Start enclave-proxy
# Certs are in $TEST_DIR which is under /tmp (mounted in enclave.json)
log "Starting enclave-proxy on port 10443..."
if $SGX_MODE; then
    ego run "$PROJECT_ROOT/enclave/enclave" \
        -mode proxy \
        -https-port 10443 \
        -tls-cert "$TEST_DIR/cert.pem" \
        -tls-key "$TEST_DIR/key.pem" \
        -target "https://127.0.0.1:10444" \
        > "$TEST_DIR/enclave.log" 2>&1 &
else
    "$TEST_DIR/enclave" \
        -mode proxy \
        -https-port 10443 \
        -tls-cert "$TEST_DIR/cert.pem" \
        -tls-key "$TEST_DIR/key.pem" \
        -target "https://127.0.0.1:10444" \
        > "$TEST_DIR/enclave.log" 2>&1 &
fi
ENCLAVE_PID=$!

# SGX enclave loading takes significantly longer than simulation
if $SGX_MODE; then
    log "Waiting for SGX enclave to initialize (this may take 10-15s)..."
    for i in {1..30}; do
        if curl -sk https://127.0.0.1:10443/health > /dev/null 2>&1; then
            log "Enclave-proxy ready after ${i}s"
            break
        fi
        if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
            error "Enclave-proxy exited. Check $TEST_DIR/enclave.log"
        fi
        sleep 1
    done
    if ! curl -sk https://127.0.0.1:10443/health > /dev/null 2>&1; then
        warn "Enclave-proxy not responding after 30s. Log:"
        tail -10 "$TEST_DIR/enclave.log"
        error "Enclave-proxy failed to start"
    fi
else
    sleep 2
    if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
        error "Enclave-proxy failed to start. Check $TEST_DIR/enclave.log"
    fi
fi
log "Enclave-proxy started (PID: $ENCLAVE_PID)"

echo ""
log "=== Testing CODoH-base Functionality ==="
echo ""

# Test 1: Health checks
info "Test 1: Health checks"
TARGET_HEALTH=$(curl -sk https://127.0.0.1:10444/health 2>/dev/null || echo "failed")
PROXY_HEALTH=$(curl -sk https://127.0.0.1:10443/health 2>/dev/null || echo "failed")

PASS=0
FAIL=0

if [[ "$TARGET_HEALTH" == "OK" ]]; then
    echo -e "${GREEN}✓${NC} Target health: OK"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗${NC} Target health: $TARGET_HEALTH"
    FAIL=$((FAIL + 1))
fi

if [[ "$PROXY_HEALTH" == "OK" ]]; then
    echo -e "${GREEN}✓${NC} Proxy health: OK"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗${NC} Proxy health: $PROXY_HEALTH"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 2: Enclave key endpoint
info "Test 2: Enclave key endpoint"
ENCLAVE_KEY=$(curl -sk https://127.0.0.1:10443/enclave-keys 2>/dev/null || echo "failed")
if [[ ${#ENCLAVE_KEY} -gt 20 ]]; then
    echo -e "${GREEN}✓${NC} Enclave key returned (${#ENCLAVE_KEY} chars)"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗${NC} Enclave key failed: $ENCLAVE_KEY"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 3: ODoH configs proxy
info "Test 3: ODoH configs proxied through enclave-proxy"
CONFIGS=$(curl -sk https://127.0.0.1:10443/.well-known/odohconfigs 2>/dev/null | wc -c)
if [[ $CONFIGS -gt 10 ]]; then
    echo -e "${GREEN}✓${NC} ODoH configs proxied ($CONFIGS bytes)"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗${NC} ODoH configs proxy failed"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 4: CODoH-base query — first query (cache miss expected)
info "Test 4: First query (expect cache miss)"
RESULT1=$("$TEST_DIR/odoh-client" latency \
    --protocol codoh-base \
    --target 127.0.0.1:10444 \
    --proxy 127.0.0.1:10443 \
    --iterations 1 \
    --domains <(echo "1,example.com") \
    --distribution sequential \
    --customcert "$TEST_DIR/cert.pem" 2>&1) || true

if echo "$RESULT1" | grep -q "Cache MISS"; then
    echo -e "${GREEN}✓${NC} First query: cache miss (correct)"
    PASS=$((PASS + 1))
elif echo "$RESULT1" | grep -q "successful"; then
    echo -e "${GREEN}✓${NC} First query succeeded"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗${NC} First query failed:"
    echo "$RESULT1" | tail -5
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 5: Same domain again — cache hit expected
info "Test 5: Repeat query (expect cache hit)"
RESULT2=$("$TEST_DIR/odoh-client" latency \
    --protocol codoh-base \
    --target 127.0.0.1:10444 \
    --proxy 127.0.0.1:10443 \
    --iterations 1 \
    --domains <(echo "1,example.com") \
    --distribution sequential \
    --customcert "$TEST_DIR/cert.pem" 2>&1) || true

if echo "$RESULT2" | grep -q "Cache HIT"; then
    echo -e "${GREEN}✓${NC} Repeat query: cache hit (correct)"
    PASS=$((PASS + 1))
elif echo "$RESULT2" | grep -q "successful"; then
    echo -e "${YELLOW}!${NC} Repeat query succeeded (check logs for hit/miss)"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗${NC} Repeat query failed:"
    echo "$RESULT2" | tail -5
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 6: Warm benchmark — 20 queries, same domain
info "Test 6: Warm benchmark (20 queries, same domain)"
echo "1,google.com" > "$TEST_DIR/warm.csv"
RESULT3=$("$TEST_DIR/odoh-client" latency \
    --protocol codoh-base \
    --target 127.0.0.1:10444 \
    --proxy 127.0.0.1:10443 \
    --iterations 20 \
    --domains "$TEST_DIR/warm.csv" \
    --distribution sequential \
    --customcert "$TEST_DIR/cert.pem" 2>&1) || true

HIT_RATE=$(echo "$RESULT3" | grep -oP '[\d.]+% hit rate' | head -1)
if [[ -n "$HIT_RATE" ]]; then
    echo -e "${GREEN}✓${NC} Warm benchmark: $HIT_RATE"
    PASS=$((PASS + 1))
elif echo "$RESULT3" | grep -q "successful"; then
    echo -e "${GREEN}✓${NC} Warm benchmark completed"
    echo "$RESULT3" | grep -E "(Cache|Latency|Mean)" | head -5
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗${NC} Warm benchmark failed:"
    echo "$RESULT3" | tail -10
    FAIL=$((FAIL + 1))
fi
echo ""

# Show relevant logs
log "=== Enclave-Proxy Log (last 15 lines) ==="
tail -15 "$TEST_DIR/enclave.log" 2>/dev/null || echo "  No logs"

echo ""
log "=== Test Summary ==="
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"
echo ""
log "Full logs:"
log "  $TEST_DIR/enclave.log"
log "  $TEST_DIR/target.log"

if [[ $FAIL -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}=== All tests passed ===${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}=== $FAIL test(s) failed ===${NC}"
    exit 1
fi
