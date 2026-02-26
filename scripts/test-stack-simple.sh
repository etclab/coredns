#!/bin/bash
# Quick Config 5 (IPC mode) smoke test — SGX enclave + target + proxy
#
# Verifies: enclave starts in SGX, attestation provisions signing key,
# proxy connects to enclave socket, client queries succeed (miss + hit).
#
# Usage: ./scripts/test-stack-simple.sh
#
# Prerequisites:
#   - EGo SDK installed (ego, ego-go)
#   - SGX device nodes (/dev/sgx_enclave, /dev/sgx_provision)
#   - go.mod at go 1.25.1 (ego-go ships 1.25.1)
#   - enclave/enclave.json lists all CODOH_* env vars with fromHost:true
#   - Dev certs: localhost.pem + localhost-key.pem in project root

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLIENT_ROOT="$PROJECT_ROOT/../codoh-client"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; exit 1; }

cleanup() {
    log "Cleaning up..."
    [ -n "$PROXY_PID" ] && kill $PROXY_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill $TARGET_PID 2>/dev/null || true
    [ -n "$ENCLAVE_PID" ] && kill $ENCLAVE_PID 2>/dev/null || true
    # ego-host children don't die with parent — kill by port
    for port in 8080 8443 8444; do
        lsof -ti :$port 2>/dev/null | xargs kill 2>/dev/null || true
    done
    pkill -f 'ego-host.*enclave --socket /tmp/codoh-enclave' 2>/dev/null || true
    rm -f /tmp/codoh-enclave.sock
    sleep 1
}
trap cleanup EXIT

cd "$PROJECT_ROOT"
cleanup 2>/dev/null || true

# --- Preflight checks ---
command -v ego >/dev/null 2>&1 || fail "ego not found"
command -v ego-go >/dev/null 2>&1 || fail "ego-go not found"
[ -f localhost.pem ] || fail "localhost.pem not found in project root"
[ -f localhost-key.pem ] || fail "localhost-key.pem not found in project root"
[ -f benchmark/top-1m.csv ] || fail "benchmark/top-1m.csv not found"

# --- Build ---
log "Building coredns-test..."
go build -o coredns-test .

log "Building enclave (ego-go -tags ego)..."
# NOTE: ego-go does NOT auto-set the 'ego' build tag — must pass -tags ego
(cd enclave && ego-go build -tags ego -o enclave ./cmd)

log "Signing enclave..."
(cd enclave && ego sign enclave.json) 2>&1 | grep -v "^$"

log "Building client..."
(cd "$CLIENT_ROOT" && go build -o odoh-client ./cmd)

# --- Launch order: enclave -> target -> proxy ---
# Enclave must be running before target starts (attestation provisioning).

log "Starting enclave (SGX)..."
CODOH_CACHE_SIZE=10000 \
CODOH_BATCH_SIZE=10 \
CODOH_BATCH_COMMIT_PROB=1.0 \
CODOH_WARMUP_THRESHOLD=5 \
CODOH_REPLAY_DELTA_SECS=30 \
ego run enclave/enclave --socket /tmp/codoh-enclave.sock \
    > /tmp/enclave.log 2>&1 &
ENCLAVE_PID=$!

# In SGX mode the enclave blocks until provisioned:
#   1. Loads into SGX (~4s)
#   2. Starts attestation server on :8444
#   3. Blocks on provisionCh waiting for target to POST /provision
#   4. Only THEN creates the IPC socket
# So we wait for the attestation server, start the target, then wait for the socket.

for i in $(seq 1 20); do
    if curl -sk https://127.0.0.1:8444/health >/dev/null 2>&1; then
        log "Attestation server ready after ${i}s"
        break
    fi
    if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
        echo ""; cat /tmp/enclave.log
        fail "Enclave exited unexpectedly"
    fi
    sleep 1
done
curl -sk https://127.0.0.1:8444/health >/dev/null 2>&1 || fail "Attestation server not ready after 20s"

# Verify SGX mode (not simulation)
if grep -q "SGX mode enabled" /tmp/enclave.log; then
    log "Enclave running in SGX mode"
elif grep -q "simulation mode" /tmp/enclave.log; then
    warn "Enclave fell back to SIMULATION mode — check ego build tags"
    warn "Ensure: ego-go build -tags ego ./cmd"
fi

log "Starting target..."
# Target provisions signing key to enclave via attestation on startup
CODOH_COVER_COUNT=3 \
CODOH_COVER_DOMAIN_FILE=benchmark/top-1m.csv \
CODOH_PROXY_CALLBACK_URL=https://127.0.0.1:8080 \
CODOH_COVER_RESOLVER=8.8.8.8:53 \
CODOH_COVER_TIMEOUT_MS=2000 \
./coredns-test -conf Corefile.target > /tmp/target.log 2>&1 &
TARGET_PID=$!
sleep 4

if ! kill -0 $TARGET_PID 2>/dev/null; then
    echo ""; cat /tmp/target.log
    fail "Target exited unexpectedly"
fi

if grep -q "provisioned to enclave successfully" /tmp/target.log; then
    log "Signing key provisioned via attestation"
else
    warn "Provisioning status unclear — check /tmp/target.log"
fi

if grep -q "Cover sampler loaded" /tmp/target.log; then
    log "Cover sampler active"
fi

# After target provisions the signing key, enclave unblocks and creates the IPC socket
for i in $(seq 1 15); do
    if [ -S /tmp/codoh-enclave.sock ]; then
        log "Enclave IPC socket ready"
        break
    fi
    sleep 1
done
[ -S /tmp/codoh-enclave.sock ] || fail "Enclave socket not found after provisioning"

log "Starting proxy..."
./coredns-test -conf Corefile.proxy > /tmp/proxy.log 2>&1 &
PROXY_PID=$!
sleep 2

if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo ""; cat /tmp/proxy.log
    fail "Proxy exited unexpectedly"
fi

if grep -q "Registered /enclave-keys and /cache-insert" /tmp/proxy.log; then
    log "Proxy registered enclave endpoints"
fi

# --- Client queries ---
echo ""
log "=== Query Test: Cold Cache ==="
RESULT1=$("$CLIENT_ROOT/odoh-client" latency \
    --protocol codoh \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert localhost.pem \
    --domains benchmark/top-1m.csv \
    --iterations 5 \
    --distribution sequential 2>&1) || true
echo "$RESULT1" | grep -E "(Cache|Iterations|Latency|Mean|hit rate)" || echo "$RESULT1" | tail -5

echo ""
log "=== Query Test: Warm Cache ==="
RESULT2=$("$CLIENT_ROOT/odoh-client" latency \
    --protocol codoh \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert localhost.pem \
    --domains benchmark/top-1m.csv \
    --iterations 5 \
    --distribution sequential 2>&1) || true
echo "$RESULT2" | grep -E "(Cache|Iterations|Latency|Mean|hit rate)" || echo "$RESULT2" | tail -5

# --- Verdict ---
echo ""
PASS=true
if echo "$RESULT1" | grep -q "successful"; then
    echo -e "${GREEN}PASS${NC} Cold cache queries succeeded"
else
    echo -e "${RED}FAIL${NC} Cold cache queries failed"
    PASS=false
fi

if echo "$RESULT2" | grep -q "hit rate"; then
    HIT_RATE=$(echo "$RESULT2" | grep -oP '[\d.]+% hit rate')
    echo -e "${GREEN}PASS${NC} Warm cache: $HIT_RATE"
else
    echo -e "${RED}FAIL${NC} Warm cache queries failed"
    PASS=false
fi

echo ""
log "Logs: /tmp/{enclave,target,proxy}.log"

if $PASS; then
    echo -e "${GREEN}=== All checks passed ===${NC}"
else
    echo -e "${RED}=== Some checks failed ===${NC}"
    exit 1
fi
