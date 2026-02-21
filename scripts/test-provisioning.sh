#!/bin/bash
# Quick test for the SGX attestation + signing key provisioning flow
#
# Tests only the enclave <-> target handshake:
#   1. Enclave starts in SGX, generates quote, serves /attest
#   2. Target fetches quote, provisions signing pubkey via /provision
#   3. Enclave receives key and becomes ready
#
# Usage: ./scripts/test-provisioning.sh
#
# This is a focused test — no proxy, no client queries.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR="/tmp/codoh-provision-test-$$"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; exit 1; }

cleanup() {
    [ -n "$ENCLAVE_PID" ] && kill $ENCLAVE_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill $TARGET_PID 2>/dev/null || true
    # ego-host children don't die with parent — kill by port
    for port in 18443 18444; do
        lsof -ti :$port 2>/dev/null | xargs kill 2>/dev/null || true
    done
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

command -v ego >/dev/null 2>&1 || fail "ego not found"
command -v ego-go >/dev/null 2>&1 || fail "ego-go not found"

mkdir -p "$TEST_DIR"
cd "$PROJECT_ROOT"

log "=== Provisioning Flow Test ==="
echo ""

# --- Build ---
log "Building enclave (ego-go -tags ego)..."
(cd enclave && ego-go build -tags ego -o enclave ./cmd)
(cd enclave && ego sign enclave.json) 2>&1 | grep -v "^$"

MRSIGNER=$(cd enclave && ego signerid enclave 2>/dev/null | tail -1)
log "MRSIGNER: $MRSIGNER"

log "Building coredns..."
go build -o "$TEST_DIR/coredns" .

# --- TLS certs ---
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# --- Target Corefile ---
cat > "$TEST_DIR/target-corefile" << EOF
.:15354 {
    codohtarget {
        port 18443
        tls_cert $TEST_DIR/cert.pem
        tls_key $TEST_DIR/key.pem
        upstream 8.8.8.8:53
        signing_key $TEST_DIR/signing-key.pem
        enclave_url https://127.0.0.1:18444
    }
}
EOF

# --- Start enclave ---
log "Starting enclave (SGX)..."
ego run enclave/enclave \
    --socket "$TEST_DIR/enclave.sock" \
    --https-port 18444 \
    > "$TEST_DIR/enclave.log" 2>&1 &
ENCLAVE_PID=$!

for i in $(seq 1 20); do
    if curl -sk https://127.0.0.1:18444/health >/dev/null 2>&1; then
        log "Attestation server ready after ${i}s"
        break
    fi
    if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
        cat "$TEST_DIR/enclave.log"; fail "Enclave exited"
    fi
    sleep 1
done

# --- Verify attestation endpoint ---
log "Fetching attestation info..."
ATTEST=$(curl -sk https://127.0.0.1:18444/attest 2>/dev/null)
echo "$ATTEST" | python3 -m json.tool 2>/dev/null | head -10 || echo "$ATTEST"

HEALTH_BEFORE=$(curl -sk https://127.0.0.1:18444/health 2>/dev/null)
log "Health before provisioning: $HEALTH_BEFORE"

# --- Start target (triggers provisioning) ---
log "Starting target (will provision signing key)..."
"$TEST_DIR/coredns" -conf "$TEST_DIR/target-corefile" \
    > "$TEST_DIR/target.log" 2>&1 &
TARGET_PID=$!
sleep 5

# --- Verify provisioning ---
if grep -q "provisioned to enclave successfully" "$TEST_DIR/target.log"; then
    echo -e "${GREEN}PASS${NC} Signing key provisioned"
else
    echo -e "${RED}FAIL${NC} Provisioning failed"
    echo "Target log:"
    cat "$TEST_DIR/target.log"
fi

HEALTH_AFTER=$(curl -sk https://127.0.0.1:18444/health 2>/dev/null)
log "Health after provisioning: $HEALTH_AFTER"

# Check IPC socket
if [ -S "$TEST_DIR/enclave.sock" ]; then
    echo -e "${GREEN}PASS${NC} IPC socket created after provisioning"
else
    echo -e "${RED}FAIL${NC} IPC socket not found"
fi

# --- Logs ---
echo ""
log "=== Enclave Log ==="
cat "$TEST_DIR/enclave.log"

echo ""
log "=== Target Log ==="
grep -E "(Provision|attestation|signing|enclave)" "$TEST_DIR/target.log" || cat "$TEST_DIR/target.log"
