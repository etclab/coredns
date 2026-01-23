#!/bin/bash
# Quick test for enclave provisioning flow
# In simulation mode: tests file-based secret loading
# In SGX mode: tests HTTPS provisioning (requires SGX hardware)
#
# Usage: ./scripts/test-provisioning.sh

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
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

cleanup() {
    [ -n "$ENCLAVE_PID" ] && kill $ENCLAVE_PID 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"
cd "$PROJECT_ROOT"

# Build enclave
log "Building enclave..."
(cd enclave && go build -o "$TEST_DIR/enclave-dev" ./cmd)

# Generate secret
log "Generating master secret..."
openssl rand -hex 32 > "$TEST_DIR/master-secret.txt"
SECRET=$(cat "$TEST_DIR/master-secret.txt")
log "Secret: $SECRET"

# Start enclave with secret file (simulation mode)
log "Starting enclave with --secret flag..."
"$TEST_DIR/enclave-dev" \
    --socket "$TEST_DIR/enclave.sock" \
    --https-port 18444 \
    --secret "$TEST_DIR/master-secret.txt" \
    > "$TEST_DIR/enclave.log" 2>&1 &
ENCLAVE_PID=$!

sleep 2

if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
    error "Enclave failed to start. Log:"
    cat "$TEST_DIR/enclave.log"
    exit 1
fi

# Check health
log "Checking enclave health..."
HEALTH=$(curl -sk https://localhost:18444/health 2>/dev/null || echo "connection failed")
echo "  Response: $HEALTH"

# Get attestation info
log "Fetching attestation info..."
ATTEST=$(curl -sk https://localhost:18444/attest 2>/dev/null || echo "{}")
PUBKEY=$(echo "$ATTEST" | jq -r '.pubkey // "none"')
QUOTE=$(echo "$ATTEST" | jq -r '.quote // "none"')
log "Public key: ${PUBKEY:0:30}..."
if [ "$QUOTE" = "" ] || [ "$QUOTE" = "none" ]; then
    log "Quote: (empty - simulation mode, no SGX)"
else
    log "Quote: ${QUOTE:0:30}... (SGX mode)"
fi

# Test IPC ready check
log "Testing IPC ready check..."
# Create a simple client to test the ready message
cat > "$TEST_DIR/check_ready.go" << 'GOEOF'
package main

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "net"
    "os"
)

type Request struct {
    Type string `json:"type"`
}

type Response struct {
    Status string `json:"status"`
    Ready  bool   `json:"ready"`
}

func main() {
    conn, err := net.Dial("unix", os.Args[1])
    if err != nil {
        fmt.Println("Connect error:", err)
        os.Exit(1)
    }
    defer conn.Close()

    req := Request{Type: "ready"}
    payload, _ := json.Marshal(req)
    binary.Write(conn, binary.BigEndian, uint32(len(payload)))
    conn.Write(payload)

    var length uint32
    binary.Read(conn, binary.BigEndian, &length)
    respPayload := make([]byte, length)
    conn.Read(respPayload)

    var resp Response
    json.Unmarshal(respPayload, &resp)
    fmt.Printf("Status: %s, Ready: %v\n", resp.Status, resp.Ready)

    if resp.Ready {
        os.Exit(0)
    }
    os.Exit(1)
}
GOEOF

(cd "$TEST_DIR" && go build -o check_ready check_ready.go)
READY_RESULT=$("$TEST_DIR/check_ready" "$TEST_DIR/enclave.sock" 2>&1)
log "IPC Ready check: $READY_RESULT"

# Show results
echo ""
if [[ "$HEALTH" == *"ready"* ]] || [[ "$READY_RESULT" == *"Ready: true"* ]]; then
    log "=========================================="
    log "SUCCESS: Enclave is running and ready!"
    log "=========================================="
    log ""
    log "Endpoints:"
    log "  HTTPS: https://localhost:18444"
    log "  IPC:   $TEST_DIR/enclave.sock"
    log ""
    log "In simulation mode:"
    log "  - Secret loaded from file (--secret flag)"
    log "  - Quote is empty (no SGX hardware)"
    log "  - Attestation endpoints work but verification skipped"
    log ""
    log "In SGX mode (with ego run):"
    log "  - Enclave waits for provisioning via /provision"
    log "  - Target fetches quote, verifies, and provisions secret"
else
    error "FAILED: Enclave not ready"
fi

# Show enclave logs
echo ""
log "=== Enclave Log ==="
cat "$TEST_DIR/enclave.log"
