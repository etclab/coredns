#!/bin/bash
# Simple test to verify CODoH stack starts correctly

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

MASTER_SECRET=$(openssl rand -hex 32)

echo "=== Simple CODoH Stack Test ==="
echo ""

cleanup() {
    echo "Cleaning up..."
    pkill -f coredns-test 2>/dev/null || true
    pkill -f enclave-sim 2>/dev/null || true
    for port in 8080 8443; do
        lsof -ti :$port 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    rm -f /tmp/codoh-enclave.sock
    sleep 1
}
trap cleanup EXIT

cleanup

echo "Building..."
go build -o coredns-test . || exit 1
go build -o enclave-sim ./enclave/cmd || exit 1
echo ""

echo "Starting enclave..."
CODOH_MASTER_SECRET=$MASTER_SECRET \
./enclave-sim -socket /tmp/codoh-enclave.sock > /tmp/enclave.log 2>&1 &
ENCLAVE_PID=$!
sleep 2

if ! ps -p $ENCLAVE_PID > /dev/null; then
    echo -e "${RED}✗ Enclave failed to start${NC}"
    cat /tmp/enclave.log
    exit 1
fi
echo -e "${GREEN}✓ Enclave started (PID: $ENCLAVE_PID)${NC}"
grep "Enclave ready" /tmp/enclave.log || grep "cache" /tmp/enclave.log

echo ""
echo "Starting proxy..."
./coredns-test -conf Corefile.proxy > /tmp/proxy.log 2>&1 &
PROXY_PID=$!
sleep 3

if ! ps -p $PROXY_PID > /dev/null; then
    echo -e "${RED}✗ Proxy failed to start${NC}"
    cat /tmp/proxy.log
    exit 1
fi
echo -e "${GREEN}✓ Proxy started (PID: $PROXY_PID)${NC}"

echo ""
echo "Starting target..."
./coredns-test -conf Corefile.target > /tmp/target.log 2>&1 &
TARGET_PID=$!
sleep 3

if ! ps -p $TARGET_PID > /dev/null; then
    echo -e "${RED}✗ Target failed to start${NC}"
    cat /tmp/target.log
    exit 1
fi
echo -e "${GREEN}✓ Target started (PID: $TARGET_PID)${NC}"

echo ""
echo "Testing endpoints..."
if curl -sk https://127.0.0.1:8080/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Proxy health check OK${NC}"
else
    echo -e "${RED}✗ Proxy health check failed${NC}"
fi

if curl -sk https://127.0.0.1:8443/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Target health check OK${NC}"
else
    echo -e "${RED}✗ Target health check failed${NC}"
fi

echo ""
echo -e "${GREEN}=== Stack is running ===${NC}"
echo ""
echo "Proxy:  https://127.0.0.1:8080"
echo "Target: https://127.0.0.1:8443"
echo ""
echo "Logs:"
echo "  /tmp/enclave.log"
echo "  /tmp/proxy.log"
echo "  /tmp/target.log"
echo ""
echo "Press Ctrl+C to stop"
wait
