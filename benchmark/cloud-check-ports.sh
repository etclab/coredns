#!/bin/bash
# CODoH Cloud Benchmark — Port Reachability Check
#
# Verifies that benchmark ports are open between client, proxy, and target VMs.
# Starts temporary listeners on remote VMs, probes from client.
#
# Usage: ./benchmark/cloud-check-ports.sh
#
# Requires: benchmark/cloud-env.local.sh with PROXY_IP, TARGET_IP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load cloud env
if [[ -f "$SCRIPT_DIR/cloud-env.local.sh" ]]; then
    source "$SCRIPT_DIR/cloud-env.local.sh"
else
    echo "ERROR: benchmark/cloud-env.local.sh not found."
    echo "  cp benchmark/cloud-env.sh benchmark/cloud-env.local.sh"
    exit 1
fi

if [[ -z "${PROXY_IP:-}" || -z "${TARGET_IP:-}" ]]; then
    echo "ERROR: PROXY_IP and TARGET_IP must be set in cloud-env.local.sh"
    exit 1
fi

: "${SSH_USER:=azureuser}"
: "${SSH_KEY:=$HOME/.ssh/id_ed25519}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"

# Proxy inbound: 8080 (codohproxy), 8444 (enclave attest), 9080 (odohproxy), 10443 (config3 proxy)
# Target inbound: 8443 (codohtarget), 9443 (odohtarget), 10444 (config3 target)

PROXY_PORTS=(8080 8444 9080 10443)
TARGET_PORTS=(7443 8443 9443 10444)

PROXY_LABELS=("codohproxy" "enclave-attest" "odohproxy" "config3-proxy")
TARGET_LABELS=("doh" "codohtarget" "odohtarget" "config3-target")

echo "=== CODoH Port Reachability Check ==="
echo "Proxy:  $PROXY_IP (ports: ${PROXY_PORTS[*]})"
echo "Target: $TARGET_IP (ports: ${TARGET_PORTS[*]})"
echo ""

# Helper: start temporary python listeners on a remote VM
start_listeners() {
    local host=$1; shift
    local ports=("$@")
    ssh $SSH_OPTS "$SSH_USER@$host" "
        for p in ${ports[*]}; do
            python3 -c \"
import socket, sys, os
import time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('0.0.0.0', int(sys.argv[1])))
    s.listen(5)
    s.settimeout(1)
    end = time.time() + 15
    while time.time() < end:
        try:
            c, _ = s.accept()
            c.close()
        except:
            pass
except:
    pass
finally:
    s.close()
\" \$p &>/dev/null &
        done
        sleep 0.5
    " &
}

# Helper: probe a port from client
check_port() {
    local label=$1 host=$2 port=$3
    if nc -zw2 "$host" "$port" 2>/dev/null; then
        echo "  OK      $label ($host:$port)"
        return 0
    elif timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        echo "  OK      $label ($host:$port)"
        return 0
    else
        echo "  BLOCKED $label ($host:$port)"
        return 1
    fi
}

# Cleanup on exit
cleanup_listeners() {
    ssh $SSH_OPTS "$SSH_USER@$PROXY_IP" "pkill -f 'python3 -c.*socket.*bind' 2>/dev/null; true" 2>/dev/null || true
    ssh $SSH_OPTS "$SSH_USER@$TARGET_IP" "pkill -f 'python3 -c.*socket.*bind' 2>/dev/null; true" 2>/dev/null || true
}
trap cleanup_listeners EXIT

# Start listeners
start_listeners "$PROXY_IP" "${PROXY_PORTS[@]}"
PROXY_PID=$!
start_listeners "$TARGET_IP" "${TARGET_PORTS[@]}"
TARGET_PID=$!

sleep 2
wait $PROXY_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

# Probe
port_fail=0

echo "--- Client → Proxy ---"
for i in "${!PROXY_PORTS[@]}"; do
    check_port "${PROXY_LABELS[$i]}" "$PROXY_IP" "${PROXY_PORTS[$i]}" || ((port_fail++))
done

echo "--- Client → Target ---"
for i in "${!TARGET_PORTS[@]}"; do
    check_port "${TARGET_LABELS[$i]}" "$TARGET_IP" "${TARGET_PORTS[$i]}" || ((port_fail++))
done

# Cross-VM: proxy → target (query forwarding)
echo "--- Proxy → Target ---"
for i in "${!TARGET_PORTS[@]}"; do
    if ssh $SSH_OPTS "$SSH_USER@$PROXY_IP" "nc -zw2 $TARGET_IP ${TARGET_PORTS[$i]}" 2>/dev/null; then
        echo "  OK      ${TARGET_LABELS[$i]} ($TARGET_IP:${TARGET_PORTS[$i]})"
    else
        echo "  BLOCKED ${TARGET_LABELS[$i]} ($TARGET_IP:${TARGET_PORTS[$i]})"
        ((port_fail++))
    fi
done

# Cross-VM: target → proxy (attestation + cover callbacks)
echo "--- Target → Proxy ---"
for i in "${!PROXY_PORTS[@]}"; do
    if ssh $SSH_OPTS "$SSH_USER@$TARGET_IP" "nc -zw2 $PROXY_IP ${PROXY_PORTS[$i]}" 2>/dev/null; then
        echo "  OK      ${PROXY_LABELS[$i]} ($PROXY_IP:${PROXY_PORTS[$i]})"
    else
        echo "  BLOCKED ${PROXY_LABELS[$i]} ($PROXY_IP:${PROXY_PORTS[$i]})"
        ((port_fail++))
    fi
done

echo ""
if [[ $port_fail -gt 0 ]]; then
    echo "RESULT: $port_fail port(s) blocked."
    echo ""
    echo "Open them in Azure NSG:"
    echo "  # Proxy NSG:"
    echo "  az network nsg rule create --resource-group <RG> --nsg-name <PROXY_NSG> \\"
    echo "    --name AllowBenchPorts --priority 1010 --direction Inbound \\"
    echo "    --access Allow --protocol Tcp --destination-port-ranges ${PROXY_PORTS[*]}"
    echo ""
    echo "  # Target NSG:"
    echo "  az network nsg rule create --resource-group <RG> --nsg-name <TARGET_NSG> \\"
    echo "    --name AllowBenchPorts --priority 1010 --direction Inbound \\"
    echo "    --access Allow --protocol Tcp --destination-port-ranges ${TARGET_PORTS[*]}"
    exit 1
else
    echo "RESULT: All ports reachable."
fi
