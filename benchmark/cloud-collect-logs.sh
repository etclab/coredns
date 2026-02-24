#!/bin/bash
# CODoH Cloud Benchmark — Post-run Log Fetcher
#
# Collects /tmp/bench-*.log from proxy and target VMs into results/<run-id>/logs/
#
# Usage: ./benchmark/cloud-collect-logs.sh <run-id>
#
# If no run-id given, collects into a timestamped directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load cloud env
if [[ -f "$SCRIPT_DIR/cloud-env.local.sh" ]]; then
    source "$SCRIPT_DIR/cloud-env.local.sh"
else
    echo "ERROR: benchmark/cloud-env.local.sh not found."
    exit 1
fi

if [[ -z "${PROXY_IP:-}" || -z "${TARGET_IP:-}" ]]; then
    echo "ERROR: PROXY_IP and TARGET_IP must be set in cloud-env.local.sh"
    exit 1
fi

: "${SSH_USER:=azureuser}"
: "${SSH_KEY:=$HOME/.ssh/id_rsa}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"

RUN_ID="${1:-logs_$(date +%Y%m%d_%H%M%S)}"
LOG_DIR="$SCRIPT_DIR/results/$RUN_ID/logs"
mkdir -p "$LOG_DIR"

echo "=== Collecting logs ==="
echo "  Run ID: $RUN_ID"
echo "  Output: $LOG_DIR/"
echo ""

# Proxy logs
echo "  Proxy ($PROXY_IP)..."
scp $SSH_OPTS "$SSH_USER@$PROXY_IP:/tmp/bench-*.log" "$LOG_DIR/" 2>/dev/null && \
    echo "    $(ls "$LOG_DIR"/bench-*proxy* "$LOG_DIR"/bench-*enclave* 2>/dev/null | wc -l) files" || \
    echo "    No logs found"

# Target logs
echo "  Target ($TARGET_IP)..."
scp $SSH_OPTS "$SSH_USER@$TARGET_IP:/tmp/bench-*.log" "$LOG_DIR/" 2>/dev/null && \
    echo "    $(ls "$LOG_DIR"/bench-*target* 2>/dev/null | wc -l) files" || \
    echo "    No logs found"

echo ""
echo "=== Logs collected ==="
echo "  $LOG_DIR/"
ls -la "$LOG_DIR/" 2>/dev/null
