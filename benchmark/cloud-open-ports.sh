#!/bin/bash
# CODoH Cloud Benchmark — Open Benchmark Ports in Azure NSGs
#
# Usage: ./benchmark/cloud-open-ports.sh
#
# Requires: benchmark/cloud-env.local.sh with RESOURCE_GROUP, PROXY_NSG, TARGET_NSG
# Requires: az login

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/cloud-env.local.sh" ]]; then
    source "$SCRIPT_DIR/cloud-env.local.sh"
else
    echo "ERROR: benchmark/cloud-env.local.sh not found."
    exit 1
fi

if [[ -z "${RESOURCE_GROUP:-}" || -z "${PROXY_NSG:-}" || -z "${TARGET_NSG:-}" ]]; then
    echo "ERROR: RESOURCE_GROUP, PROXY_NSG, and TARGET_NSG must be set in cloud-env.local.sh"
    exit 1
fi

if ! command -v az &>/dev/null; then
    echo "ERROR: Azure CLI (az) not found. Install: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

PROXY_PORTS="8080 8444 9080 10443"
TARGET_PORTS="7443 8443 9443 10444"

echo "=== Opening Benchmark Ports ==="
echo "Resource group: $RESOURCE_GROUP"
echo ""

echo "Proxy NSG ($PROXY_NSG): ports $PROXY_PORTS"
az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$PROXY_NSG" \
    --name AllowCODoHBench \
    --priority 1010 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-ranges $PROXY_PORTS \
    --output table

echo ""
echo "Target NSG ($TARGET_NSG): ports $TARGET_PORTS"
az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$TARGET_NSG" \
    --name AllowCODoHBench \
    --priority 1010 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-ranges $TARGET_PORTS \
    --output table

echo ""
echo "Done. Verify with: ./benchmark/cloud-check-ports.sh"
