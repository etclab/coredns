#!/bin/bash
# Prewarm Unbound's cache with all domains used in benchmarks.
# Run once per session before starting benchmark runs.
# Unbound must be running on 127.0.0.1:5353 with cache-min-ttl: 86400.
#
# Usage: ./benchmark/prewarm-unbound.sh [--parallel N]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOLVER="127.0.0.1"
PORT=5353
PARALLEL=50

while [[ $# -gt 0 ]]; do
    case $1 in
        --parallel) PARALLEL="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check Unbound is running
if ! dig +short @${RESOLVER} -p ${PORT} google.com > /dev/null 2>&1; then
    echo "ERROR: Unbound not responding on ${RESOLVER}:${PORT}"
    echo "Install and start: sudo apt install unbound && sudo cp benchmark/unbound.conf /etc/unbound/unbound.conf.d/benchmark.conf && sudo systemctl restart unbound"
    exit 1
fi

echo "=== Prewarming Unbound cache ==="
echo "Resolver: ${RESOLVER}:${PORT}"
echo "Parallelism: ${PARALLEL}"

# Collect all unique domains from benchmark workload files
DOMAINS_FILE=$(mktemp)
trap "rm -f $DOMAINS_FILE" EXIT

# top-1k resolvable (zipf workload)
if [[ -f "$SCRIPT_DIR/top-1k-resolvable.csv" ]]; then
    cut -d',' -f2 "$SCRIPT_DIR/top-1k-resolvable.csv" >> "$DOMAINS_FILE"
fi

# top-10K resolvable (cold workload)
if [[ -f "$SCRIPT_DIR/top-10k-resolvable.csv" ]]; then
    cut -d',' -f2 "$SCRIPT_DIR/top-10k-resolvable.csv" >> "$DOMAINS_FILE"
fi

# warm workload domain
echo "google.com" >> "$DOMAINS_FILE"

# Deduplicate
sort -u "$DOMAINS_FILE" -o "$DOMAINS_FILE"
TOTAL=$(wc -l < "$DOMAINS_FILE")
echo "Domains to prewarm: ${TOTAL}"

# Prewarm using parallel dig queries
STARTED=$(date +%s)
xargs -P "$PARALLEL" -I {} dig +short @${RESOLVER} -p ${PORT} {} A < "$DOMAINS_FILE" > /dev/null 2>&1
ELAPSED=$(($(date +%s) - STARTED))

echo "Prewarm complete: ${TOTAL} domains in ${ELAPSED}s"

# Verify a sample
SAMPLE=$(head -1 "$SCRIPT_DIR/top-1k-resolvable.csv" | cut -d',' -f2)
if dig +short @${RESOLVER} -p ${PORT} "$SAMPLE" A > /dev/null 2>&1; then
    echo "Verification: ${SAMPLE} cached OK"
else
    echo "WARNING: Verification failed for ${SAMPLE}"
fi
