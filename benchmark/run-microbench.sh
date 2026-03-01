#!/usr/bin/env bash
# run-microbench.sh — Run all microbenchmarks and save results.
#
# Usage:
#   ./benchmark/run-microbench.sh [--iterations N] [--run-id NAME] [--padding-domains FILE]
#
# Runs from repository root. Results saved to benchmark/results/<run-id>/microbench/.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Defaults
ITERATIONS=10000
RUN_ID="micro_$(date +%Y%m%d_%H%M%S)"
PADDING_DOMAINS="benchmark/top-10k-resolvable.csv"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --run-id)     RUN_ID="$2"; shift 2 ;;
        --padding-domains) PADDING_DOMAINS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--iterations N] [--run-id NAME] [--padding-domains FILE]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

OUTDIR="benchmark/results/${RUN_ID}/microbench"
mkdir -p "$OUTDIR"

echo "=== CODoH Microbenchmarks ==="
echo "Iterations: ${ITERATIONS}x"
echo "Output:     ${OUTDIR}/"
echo ""

# --- 1. Crypto operations ---
echo "--- Crypto operations ---"
go test -bench='^Benchmark(HPKE|AESGCM|Ed25519)' \
    -benchtime="${ITERATIONS}x" -count=3 \
    ./enclave/ 2>/dev/null | tee "${OUTDIR}/crypto.txt"
echo ""

# --- 2. Cache access latency ---
echo "--- Cache access latency (LRU + ORAM, N=256..2048) ---"
go test -bench='^Benchmark(LRU|ORAM)Cache' \
    -benchtime="${ITERATIONS}x" -count=3 \
    ./enclave/ 2>/dev/null | tee "${OUTDIR}/cache.txt"
echo ""

# --- 3. IPC round-trip ---
echo "--- IPC round-trip ---"
go test -bench='^BenchmarkIPC' \
    -benchtime="${ITERATIONS}x" -count=3 \
    ./enclave/cmd/ 2>/dev/null | tee "${OUTDIR}/ipc.txt"
echo ""

# --- 4. Padding overhead ---
echo "--- Padding overhead ---"
if [[ -f "$PADDING_DOMAINS" ]]; then
    go run benchmark/analyze-padding.go \
        -domains "$PADDING_DOMAINS" -workers 100 -timeout 5 \
        2>/dev/null | tee "${OUTDIR}/padding.txt"
else
    echo "SKIP: ${PADDING_DOMAINS} not found (run benchmark/setup.sh first)"
fi
echo ""

echo "=== Done ==="
echo "Results in: ${OUTDIR}/"
echo ""
echo "Files:"
ls -1 "${OUTDIR}/"