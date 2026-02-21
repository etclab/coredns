#!/bin/bash
# End-to-end test for SGX attestation and signing key provisioning
#
# Tests the full attestation flow:
#   1. Enclave generates HPKE keypair + SGX quote
#   2. Enclave starts attestation server on HTTPS port
#   3. Target fetches quote, verifies (if sgxverify tag), provisions signing pubkey
#   4. Enclave receives signing key, exits defensive mode, starts IPC listener
#   5. Proxy connects to enclave socket
#   6. Client queries succeed end-to-end
#
# Usage: ./scripts/test-attestation-e2e.sh
#
# Build nuances:
#   - ego-go does NOT auto-set the 'ego' build tag — always pass -tags ego
#   - go.mod must be at go 1.25.1 for ego-go compatibility
#   - For quote verification on the target side, build with: go build -tags sgxverify
#     (requires Open Enclave SDK headers; omit for dev — skips verification)
#   - enclave/enclave.json must list all CODOH_* env vars with "fromHost": true

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR="/tmp/codoh-attest-test-$$"

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
    [ -n "$PROXY_PID" ] && kill $PROXY_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill $TARGET_PID 2>/dev/null || true
    [ -n "$ENCLAVE_PID" ] && kill $ENCLAVE_PID 2>/dev/null || true
    # ego-host children don't die with parent — kill by port
    for port in 18080 18443 18444; do
        lsof -ti :$port 2>/dev/null | xargs kill 2>/dev/null || true
    done
    rm -f "$TEST_DIR/enclave.sock"
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

command -v ego >/dev/null 2>&1 || fail "ego not found"
command -v ego-go >/dev/null 2>&1 || fail "ego-go not found"
[ -c /dev/sgx_enclave ] || warn "/dev/sgx_enclave not found — SGX may not work"

mkdir -p "$TEST_DIR"
cd "$PROJECT_ROOT"

log "=== SGX Attestation End-to-End Test ==="
log "Test dir: $TEST_DIR"
echo ""

# --- Build ---
log "Building enclave (ego-go -tags ego)..."
(cd enclave && ego-go build -tags ego -o enclave ./cmd)

log "Signing enclave..."
(cd enclave && ego sign enclave.json) 2>&1 | grep -v "^$"

# Extract MRSIGNER for verification
MRSIGNER=$(cd enclave && ego signerid enclave 2>/dev/null | tail -1)
log "MRSIGNER: $MRSIGNER"

log "Building coredns..."
go build -o "$TEST_DIR/coredns" .

# --- TLS certs ---
log "Generating test TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# --- Corefiles ---
# Target Corefile with enclave_url triggers attestation-based provisioning.
# Without enclave_url, target won't provision the signing key.
cat > "$TEST_DIR/target-corefile" << EOF
.:15354 {
    codohtarget {
        port 18443
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        upstream 8.8.8.8:53
        signing_key $TEST_DIR/signing-key.pem
        enclave_url https://127.0.0.1:18444
        log_queries true
    }
}
EOF

cat > "$TEST_DIR/proxy-corefile" << EOF
.:15353 {
    codohproxy {
        port 18080
        target https://127.0.0.1:18443/dns-query
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        insecure_skip_verify true
        enclave_enabled
        enclave_socket $TEST_DIR/enclave.sock
        enclave_bypass_on_failure true
    }
}
EOF

# --- Launch: enclave -> target -> proxy ---
# Order matters: enclave must serve /attest before target calls it.

log "Starting enclave (SGX)..."
CODOH_CACHE_SIZE=1000 \
CODOH_BATCH_SIZE=5 \
CODOH_BATCH_COMMIT_PROB=1.0 \
CODOH_WARMUP_THRESHOLD=3 \
CODOH_REPLAY_DELTA_SECS=30 \
ego run enclave/enclave \
    --socket "$TEST_DIR/enclave.sock" \
    --https-port 18444 \
    > "$TEST_DIR/enclave.log" 2>&1 &
ENCLAVE_PID=$!

# Wait for attestation server
for i in $(seq 1 20); do
    if curl -sk https://127.0.0.1:18444/health >/dev/null 2>&1; then
        log "Attestation server ready after ${i}s"
        break
    fi
    if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
        cat "$TEST_DIR/enclave.log"
        fail "Enclave exited"
    fi
    sleep 1
done

# --- Test 1: Attestation endpoint ---
info "Test 1: Attestation endpoint"
ATTEST=$(curl -sk https://127.0.0.1:18444/attest 2>/dev/null)
PUBKEY=$(echo "$ATTEST" | python3 -c "import sys,json; print(json.load(sys.stdin).get('pubkey',''))" 2>/dev/null || echo "")
QUOTE=$(echo "$ATTEST" | python3 -c "import sys,json; q=json.load(sys.stdin).get('quote',''); print(len(q))" 2>/dev/null || echo "0")

if [ -n "$PUBKEY" ] && [ "$QUOTE" -gt 100 ] 2>/dev/null; then
    echo -e "${GREEN}  PASS${NC} Quote present (${QUOTE} chars b64), pubkey returned"
else
    echo -e "${RED}  FAIL${NC} Attestation response incomplete"
    echo "  Response: $ATTEST"
fi

# --- Test 2: Target provisions signing key ---
info "Test 2: Signing key provisioning"
log "Starting target (will call /attest + /provision on enclave)..."
"$TEST_DIR/coredns" -conf "$TEST_DIR/target-corefile" \
    > "$TEST_DIR/target.log" 2>&1 &
TARGET_PID=$!
sleep 5

if grep -q "provisioned to enclave successfully" "$TEST_DIR/target.log"; then
    echo -e "${GREEN}  PASS${NC} Signing key provisioned via attestation"
else
    echo -e "${RED}  FAIL${NC} Provisioning failed"
    tail -10 "$TEST_DIR/target.log"
fi

# --- Test 3: Enclave IPC socket ---
info "Test 3: Enclave IPC socket"
# After provisioning, enclave initializes cache and starts IPC listener
for i in $(seq 1 10); do
    if [ -S "$TEST_DIR/enclave.sock" ]; then
        echo -e "${GREEN}  PASS${NC} IPC socket created"
        break
    fi
    sleep 1
done
[ -S "$TEST_DIR/enclave.sock" ] || echo -e "${RED}  FAIL${NC} IPC socket not found"

# --- Test 4: Proxy connects ---
info "Test 4: Proxy startup"
"$TEST_DIR/coredns" -conf "$TEST_DIR/proxy-corefile" \
    > "$TEST_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 3

if grep -q "Registered /enclave-keys" "$TEST_DIR/proxy.log"; then
    echo -e "${GREEN}  PASS${NC} Proxy registered enclave endpoints"
else
    echo -e "${RED}  FAIL${NC} Proxy startup issue"
    tail -5 "$TEST_DIR/proxy.log"
fi

# --- Test 5: Enclave key endpoint ---
info "Test 5: Enclave key endpoint via proxy"
EKEY=$(curl -sk https://127.0.0.1:18080/enclave-keys 2>/dev/null | wc -c)
if [ "$EKEY" -gt 20 ] 2>/dev/null; then
    echo -e "${GREEN}  PASS${NC} Enclave key returned (${EKEY} bytes)"
else
    echo -e "${RED}  FAIL${NC} Enclave key endpoint failed"
fi

# --- Test 6: Client query ---
CLIENT="$PROJECT_ROOT/../codoh-client/odoh-client"
if [ -x "$CLIENT" ]; then
    info "Test 6: Client query (cold + warm)"
    echo "1,example.com" > "$TEST_DIR/domains.csv"

    R1=$("$CLIENT" latency \
        --protocol codoh \
        --target 127.0.0.1:18443 \
        --proxy 127.0.0.1:18080 \
        --customcert "$TEST_DIR/cert.pem" \
        --domains "$TEST_DIR/domains.csv" \
        --iterations 3 \
        --distribution sequential 2>&1) || true

    R2=$("$CLIENT" latency \
        --protocol codoh \
        --target 127.0.0.1:18443 \
        --proxy 127.0.0.1:18080 \
        --customcert "$TEST_DIR/cert.pem" \
        --domains "$TEST_DIR/domains.csv" \
        --iterations 3 \
        --distribution sequential 2>&1) || true

    if echo "$R1" | grep -q "successful"; then
        echo -e "${GREEN}  PASS${NC} Cold cache queries succeeded"
    else
        echo -e "${RED}  FAIL${NC} Cold cache:"
        echo "$R1" | tail -5
    fi

    if echo "$R2" | grep -q "hit"; then
        HIT=$(echo "$R2" | grep -oP '[\d.]+ hits' || echo "?")
        echo -e "${GREEN}  PASS${NC} Warm cache: $HIT"
    else
        echo -e "${YELLOW}  WARN${NC} No cache hits on second run"
    fi
else
    warn "Client not found at $CLIENT — skipping query tests"
fi

# --- Summary ---
echo ""
log "=== Logs ==="
log "  $TEST_DIR/enclave.log"
log "  $TEST_DIR/target.log"
log "  $TEST_DIR/proxy.log"

echo ""
log "=== Enclave Log (SGX-related) ==="
grep -E "(SGX|quote|provision|ready|Enclave)" "$TEST_DIR/enclave.log" | head -10

echo ""
log "=== Target Log (attestation) ==="
grep -E "(Provision|attestation|signing)" "$TEST_DIR/target.log" | head -10
