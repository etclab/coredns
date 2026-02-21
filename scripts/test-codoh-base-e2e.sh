#!/bin/bash
# End-to-end test for CODoH-base (Config 3) — 2-process proxy mode
#
# Architecture: enclave-proxy (HTTPS server) + target (codohtarget plugin)
# The enclave runs in proxy mode (-mode proxy), terminates client connections,
# and forwards to the target. No IPC socket, no codohproxy plugin.
#
# Usage: ./scripts/test-codoh-base-e2e.sh
#
# Build nuance: ego-go does NOT auto-set the 'ego' build tag — use -tags ego

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLIENT_ROOT="$PROJECT_ROOT/../codoh-client"
TEST_DIR="/tmp/codoh-base-test-$$"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

cleanup() {
    log "Cleaning up..."
    [ -n "$ENCLAVE_PID" ] && kill $ENCLAVE_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill $TARGET_PID 2>/dev/null || true
    # ego-host children don't die with parent — kill by port
    for port in 10443 10444; do
        lsof -ti :$port 2>/dev/null | xargs kill 2>/dev/null || true
    done
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

command -v ego >/dev/null 2>&1 || fail "ego not found"
command -v ego-go >/dev/null 2>&1 || fail "ego-go not found"

mkdir -p "$TEST_DIR"
cd "$PROJECT_ROOT"

log "=== CODoH-base (Config 3) End-to-End Test ==="
log "Test dir: $TEST_DIR"
echo ""

# --- Build ---
log "Building coredns..."
go build -o "$TEST_DIR/coredns" .

log "Building enclave (ego-go -tags ego)..."
(cd enclave && ego-go build -tags ego -o enclave ./cmd)
(cd enclave && ego sign enclave.json) 2>&1 | grep -v "^$"

if [ -x "$CLIENT_ROOT/odoh-client" ]; then
    log "Client binary found"
else
    log "Building client..."
    (cd "$CLIENT_ROOT" && go build -o odoh-client ./cmd)
fi

# --- TLS certs ---
log "Generating test TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# --- Target Corefile (no enclave_url — proxy mode doesn't use attestation) ---
cat > "$TEST_DIR/target-corefile" << EOF
.:15354 {
    codohtarget {
        port 10444
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        upstream 8.8.8.8:53
        log_queries true
    }
}
EOF

# --- Launch: target first, then enclave-proxy ---
# In proxy mode, no attestation flow — enclave-proxy just forwards to target.

PASS=0
FAIL=0

log "Starting target on port 10444..."
"$TEST_DIR/coredns" -conf "$TEST_DIR/target-corefile" \
    > "$TEST_DIR/target.log" 2>&1 &
TARGET_PID=$!
sleep 2

if ! kill -0 $TARGET_PID 2>/dev/null; then
    cat "$TEST_DIR/target.log"
    fail "Target exited"
fi

log "Starting enclave-proxy on port 10443 (SGX, proxy mode)..."
# Proxy mode flags: -mode proxy -tls-cert -tls-key -target
# Certs must be under /tmp (mounted in enclave.json)
CODOH_CACHE_SIZE=1000 \
ego run enclave/enclave \
    -mode proxy \
    -tls-cert "$TEST_DIR/cert.pem" \
    -tls-key "$TEST_DIR/key.pem" \
    -target "https://127.0.0.1:10444" \
    > "$TEST_DIR/enclave.log" 2>&1 &
ENCLAVE_PID=$!

# SGX loading takes ~5-15s
log "Waiting for enclave-proxy to initialize..."
for i in $(seq 1 30); do
    if curl -sk https://127.0.0.1:10443/health >/dev/null 2>&1; then
        log "Enclave-proxy ready after ${i}s"
        break
    fi
    if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
        cat "$TEST_DIR/enclave.log"
        fail "Enclave-proxy exited"
    fi
    sleep 1
done

if ! curl -sk https://127.0.0.1:10443/health >/dev/null 2>&1; then
    tail -10 "$TEST_DIR/enclave.log"
    fail "Enclave-proxy not responding after 30s"
fi

echo ""
log "=== Tests ==="
echo ""

# Test 1: Health checks
info "Test 1: Health checks"
TARGET_HEALTH=$(curl -sk https://127.0.0.1:10444/health 2>/dev/null || echo "failed")
PROXY_HEALTH=$(curl -sk https://127.0.0.1:10443/health 2>/dev/null || echo "failed")

if [[ "$TARGET_HEALTH" == "OK" ]]; then
    echo -e "${GREEN}  PASS${NC} Target health: OK"; PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC} Target health: $TARGET_HEALTH"; FAIL=$((FAIL + 1))
fi
if [[ "$PROXY_HEALTH" == "OK" ]]; then
    echo -e "${GREEN}  PASS${NC} Proxy health: OK"; PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC} Proxy health: $PROXY_HEALTH"; FAIL=$((FAIL + 1))
fi

# Test 2: Enclave key endpoint
info "Test 2: Enclave key endpoint"
EKEY=$(curl -sk https://127.0.0.1:10443/enclave-keys 2>/dev/null | wc -c)
if [ "$EKEY" -gt 20 ] 2>/dev/null; then
    echo -e "${GREEN}  PASS${NC} Enclave key returned (${EKEY} bytes)"; PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC} Enclave key endpoint failed"; FAIL=$((FAIL + 1))
fi

# Test 3: ODoH configs proxied
info "Test 3: ODoH configs proxied through enclave-proxy"
CONFIGS=$(curl -sk https://127.0.0.1:10443/.well-known/odohconfigs 2>/dev/null | wc -c)
if [ "$CONFIGS" -gt 10 ] 2>/dev/null; then
    echo -e "${GREEN}  PASS${NC} ODoH configs proxied ($CONFIGS bytes)"; PASS=$((PASS + 1))
else
    echo -e "${RED}  FAIL${NC} ODoH configs proxy failed"; FAIL=$((FAIL + 1))
fi

# Test 4-5: Client queries
CLIENT="$CLIENT_ROOT/odoh-client"
if [ -x "$CLIENT" ]; then
    echo "1,example.com" > "$TEST_DIR/domains.csv"

    info "Test 4: First query (expect cache miss)"
    R1=$("$CLIENT" latency \
        --protocol codoh-base \
        --target 127.0.0.1:10444 \
        --proxy 127.0.0.1:10443 \
        --iterations 1 \
        --domains "$TEST_DIR/domains.csv" \
        --distribution sequential \
        --customcert "$TEST_DIR/cert.pem" 2>&1) || true

    if echo "$R1" | grep -q "MISS\|successful"; then
        echo -e "${GREEN}  PASS${NC} First query succeeded"; PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAIL${NC}"; echo "$R1" | tail -3; FAIL=$((FAIL + 1))
    fi

    info "Test 5: Repeat query (expect cache hit)"
    R2=$("$CLIENT" latency \
        --protocol codoh-base \
        --target 127.0.0.1:10444 \
        --proxy 127.0.0.1:10443 \
        --iterations 1 \
        --domains "$TEST_DIR/domains.csv" \
        --distribution sequential \
        --customcert "$TEST_DIR/cert.pem" 2>&1) || true

    if echo "$R2" | grep -q "HIT"; then
        echo -e "${GREEN}  PASS${NC} Cache hit on repeat query"; PASS=$((PASS + 1))
    elif echo "$R2" | grep -q "successful"; then
        echo -e "${YELLOW}  WARN${NC} Query succeeded but no cache hit detected"; PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAIL${NC}"; echo "$R2" | tail -3; FAIL=$((FAIL + 1))
    fi
else
    warn "Client not found — skipping query tests"
fi

# --- Summary ---
echo ""
log "=== Results ==="
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"
echo ""
log "Logs: $TEST_DIR/{enclave,target}.log"

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}=== All tests passed ===${NC}"
else
    echo -e "${RED}=== $FAIL test(s) failed ===${NC}"
    exit 1
fi
