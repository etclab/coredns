#!/bin/bash
# End-to-end test for SGX attestation flow (REAL SGX MODE)
# Requires: SGX hardware, EGo SDK installed
#
# Usage: ./scripts/test-attestation-sgx.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR="/tmp/codoh-sgx-test-$$"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

cleanup() {
    log "Cleaning up..."
    [ -n "$ENCLAVE_PID" ] && kill $ENCLAVE_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill $TARGET_PID 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Check for EGo
if ! command -v ego &> /dev/null; then
    error "EGo not found. Install from: https://docs.edgeless.systems/ego"
fi

if ! command -v ego-go &> /dev/null; then
    error "ego-go not found. Install EGo SDK."
fi

mkdir -p "$TEST_DIR"
cd "$PROJECT_ROOT"

log "Test directory: $TEST_DIR"

# Step 1: Generate master secret
log "Generating master secret..."
openssl rand -hex 32 > "$TEST_DIR/master-secret.txt"
SECRET=$(cat "$TEST_DIR/master-secret.txt")
log "Secret: $SECRET"

# Step 2: Generate TLS certificates for target (with SANs)
log "Generating TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# Step 3: Build enclave with EGo
log "Building enclave with ego-go..."
cd enclave
ego-go build -tags ego -o "$TEST_DIR/enclave" ./cmd

log "Signing enclave..."
cp enclave.json "$TEST_DIR/"
cp private.pem "$TEST_DIR/" 2>/dev/null || {
    log "Generating new signing key..."
    openssl genrsa -out "$TEST_DIR/private.pem" -3 3072
}

# Update enclave.json paths
cat > "$TEST_DIR/enclave.json" << EOF
{
    "exe": "enclave",
    "key": "private.pem",
    "debug": true,
    "heapSize": 512,
    "productID": 1,
    "securityVersion": 1,
    "mounts": [
        {"source": "/tmp", "target": "/tmp", "type": "hostfs", "readOnly": false}
    ],
    "env": [
        {"name": "HOME", "fromHost": true}
    ]
}
EOF

cd "$TEST_DIR"
ego sign enclave

# Get MRSIGNER
MRSIGNER=$(ego signerid private.pem)
log "MRSIGNER: $MRSIGNER"

cd "$PROJECT_ROOT"

# Step 4: Build coredns (regular go, not ego)
log "Building coredns..."
go build -o "$TEST_DIR/coredns" .

# Step 5: Create target Corefile with attestation
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
        enclave_mrsigner $MRSIGNER
    }
}
EOF

# Step 6: Start enclave (will wait for provisioning)
log "Starting enclave with ego run..."
log "Enclave will wait for provisioning from target..."
cd "$TEST_DIR"
ego run enclave --socket "$TEST_DIR/enclave.sock" --https-port 18444 \
    > "$TEST_DIR/enclave.log" 2>&1 &
ENCLAVE_PID=$!
cd "$PROJECT_ROOT"

# Wait for enclave to start HTTPS server
sleep 3

if ! kill -0 $ENCLAVE_PID 2>/dev/null; then
    error "Enclave failed to start. Log:"
    cat "$TEST_DIR/enclave.log"
fi

# Check attestation endpoint is up
log "Checking enclave attestation endpoint..."
ATTEST=$(curl -sk https://localhost:18444/attest 2>/dev/null || echo "failed")
if [[ "$ATTEST" == "failed" ]]; then
    warn "Attestation endpoint not ready yet, waiting..."
    sleep 2
    ATTEST=$(curl -sk https://localhost:18444/attest 2>/dev/null || echo "failed")
fi

QUOTE=$(echo "$ATTEST" | jq -r '.quote // "none"' 2>/dev/null || echo "none")
if [ "$QUOTE" != "none" ] && [ "$QUOTE" != "" ]; then
    log "SGX quote generated (${#QUOTE} chars base64)"
else
    warn "No SGX quote in response - check enclave logs"
fi

# Check health (should be waiting for provision)
HEALTH=$(curl -sk https://localhost:18444/health 2>/dev/null)
log "Enclave health: $HEALTH"

# Step 7: Start target (this will provision the enclave!)
log "Starting target (will provision enclave)..."
"$TEST_DIR/coredns" -conf "$TEST_DIR/target-corefile" \
    > "$TEST_DIR/target.log" 2>&1 &
TARGET_PID=$!

sleep 5

if ! kill -0 $TARGET_PID 2>/dev/null; then
    warn "Target may have failed. Checking logs..."
    cat "$TEST_DIR/target.log"
fi

# Step 8: Check if provisioning succeeded
log "Checking enclave health after provisioning..."
HEALTH=$(curl -sk https://localhost:18444/health 2>/dev/null)
log "Enclave health: $HEALTH"

# Check IPC ready
cat > "$TEST_DIR/check_ready.go" << 'GOEOF'
package main

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "net"
    "os"
)

func main() {
    conn, err := net.Dial("unix", os.Args[1])
    if err != nil {
        fmt.Println("Connect error:", err)
        os.Exit(1)
    }
    defer conn.Close()

    req := map[string]string{"type": "ready"}
    payload, _ := json.Marshal(req)
    binary.Write(conn, binary.BigEndian, uint32(len(payload)))
    conn.Write(payload)

    var length uint32
    binary.Read(conn, binary.BigEndian, &length)
    respPayload := make([]byte, length)
    conn.Read(respPayload)

    var resp map[string]interface{}
    json.Unmarshal(respPayload, &resp)
    fmt.Printf("IPC Ready: %v\n", resp["ready"])
}
GOEOF
go build -o "$TEST_DIR/check_ready" "$TEST_DIR/check_ready.go"
"$TEST_DIR/check_ready" "$TEST_DIR/enclave.sock" || true

# Show logs
echo ""
log "=== Enclave Log ==="
cat "$TEST_DIR/enclave.log"

echo ""
log "=== Target Log (last 20 lines) ==="
tail -20 "$TEST_DIR/target.log"

echo ""
if [[ "$HEALTH" == *"ready"* ]]; then
    log "=========================================="
    log "SUCCESS: SGX Attestation & Provisioning!"
    log "=========================================="
    log ""
    log "The target:"
    log "  1. Fetched SGX quote from enclave"
    log "  2. Verified quote and MRSIGNER"
    log "  3. Encrypted master secret with enclave's public key"
    log "  4. Provisioned secret to enclave"
    log ""
    log "Enclave is now ready to process requests!"
else
    warn "Provisioning may have failed - check logs above"
fi

log ""
log "Press Ctrl+C to stop"
wait
