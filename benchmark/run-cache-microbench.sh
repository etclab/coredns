#!/usr/bin/env bash
# run-cache-microbench.sh — Cache primitive microbenchmarks for Table 4.
#
# Runs LRU + ORAMCache (coredns) and LinearScan + PathORAM (pathoram-go)
# at a shared capacity sweep, both Plain and SGX (via ego).
#
# Output:
#   benchmark/results/<run-id>/
#     raw/{coredns,pathoram}_{plain,sgx}.txt   raw `go test -bench` output
#     system-info.txt                           CPU / EPC / ego version
#     medians.json                              parsed medians (ns/op)
#     table.txt                                 plaintext aligned table
#     summary.md                                human-readable summary
#
# Assumes pathoram-go is cloned as a sibling to this repo (override with
# PATHORAM_DIR=...). Restores test sources on exit (success or failure).

set -euo pipefail

CODOH_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATHORAM_DIR="${PATHORAM_DIR:-${CODOH_ROOT}/../pathoram-go}"

# Defaults
N_VALUES="256,512,1024,2048,4096,16384"
BLOCK_SIZE=4096
ITERS=10000
COUNT=3
SKIP_SGX=0
SKIP_PLAIN=0
RUN_ID="cache-micro-$(date +%Y%m%d_%H%M%S)"
GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
EGO_BIN="${EGO_BIN:-/usr/local/bin/ego}"
EGO_GO_BIN="${EGO_GO_BIN:-/usr/local/bin/ego-go}"

usage() {
    cat <<EOF
Usage: $0 [options]
  --n-values   <csv>   capacity sweep (default: ${N_VALUES})
  --block-size <int>   ORAM block size in bytes (default: ${BLOCK_SIZE})
  --iters      <int>   benchtime iterations (default: ${ITERS})
  --count      <int>   trials per subtest (default: ${COUNT})
  --skip-sgx           skip ego-run portion (plain only)
  --skip-plain         skip plain portion (sgx only)
  --run-id     <str>   output dir name (default: ${RUN_ID})
  --pathoram-dir <dir> override pathoram-go location

Env: GO_BIN, EGO_BIN, EGO_GO_BIN, PATHORAM_DIR
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --n-values)      N_VALUES="$2"; shift 2 ;;
        --block-size)    BLOCK_SIZE="$2"; shift 2 ;;
        --iters)         ITERS="$2"; shift 2 ;;
        --count)         COUNT="$2"; shift 2 ;;
        --skip-sgx)      SKIP_SGX=1; shift ;;
        --skip-plain)    SKIP_PLAIN=1; shift ;;
        --run-id)        RUN_ID="$2"; shift 2 ;;
        --pathoram-dir)  PATHORAM_DIR="$2"; shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

# --- Validate pathoram-go (must be a sibling clone) -------------------------
if [[ ! -d "$PATHORAM_DIR" ]]; then
    echo "FATAL: pathoram-go not found at '${PATHORAM_DIR}'." >&2
    echo "       Clone it as a sibling of this repo, or pass --pathoram-dir / set PATHORAM_DIR." >&2
    exit 4
fi
PATHORAM_DIR="$(cd "$PATHORAM_DIR" && pwd)"
if [[ ! -f "${PATHORAM_DIR}/oram_test.go" ]]; then
    echo "FATAL: '${PATHORAM_DIR}' is not a pathoram-go checkout (missing oram_test.go)." >&2
    exit 4
fi

OUT="${CODOH_ROOT}/benchmark/results/${RUN_ID}"
RAW="${OUT}/raw"
mkdir -p "$RAW"

echo "=== Cache microbenchmark ==="
echo "  N values:    ${N_VALUES}"
echo "  Block size:  ${BLOCK_SIZE}"
echo "  Iterations:  ${ITERS}x  (count=${COUNT})"
echo "  Out:         ${OUT}"
echo "  pathoram-go: ${PATHORAM_DIR}"
echo

# --- 1. System info ---------------------------------------------------------
{
    echo "host=$(hostname)"
    echo "kernel=$(uname -r)"
    echo "cpu=$(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2);print $2;exit}')"
    echo "vcpus=$(nproc)"
    echo "go=$($GO_BIN version 2>&1)"
    echo "ego-go=$($EGO_GO_BIN version 2>&1)"
    echo "ego=$($EGO_BIN env 2>&1 | head -1 || true)"
    echo "sgx-devices=$(ls /dev/sgx* 2>/dev/null | tr '\n' ' ')"
    echo "n-values=${N_VALUES}"
    echo "block-size=${BLOCK_SIZE}"
    echo "iters=${ITERS}"
    echo "count=${COUNT}"
    echo "coredns-commit=$(cd "$CODOH_ROOT" && git rev-parse HEAD)"
    echo "pathoram-commit=$(cd "$PATHORAM_DIR" && git rev-parse HEAD)"
} > "${OUT}/system-info.txt"

# --- 2. Patch test sources --------------------------------------------------
PORAM_TEST="${PATHORAM_DIR}/oram_test.go"
CORE_TEST="${CODOH_ROOT}/enclave/cache_benchmark_test.go"

cp "$PORAM_TEST" "${PORAM_TEST}.bak"
cp "$CORE_TEST" "${CORE_TEST}.bak"

restore() {
    [[ -f "${PORAM_TEST}.bak" ]] && mv "${PORAM_TEST}.bak" "$PORAM_TEST"
    [[ -f "${CORE_TEST}.bak" ]] && mv "${CORE_TEST}.bak" "$CORE_TEST"
}
trap restore EXIT

N_GO="${N_VALUES//,/, }"

# pathoram-go: 4 occurrences each of numBlocksValues / blockSizes
sed -i -E "s/numBlocksValues := \[\]int\{[^}]*\}/numBlocksValues := []int{${N_GO}}/g" "$PORAM_TEST"
sed -i -E "s/blockSizes := \[\]int\{[^}]*\}/blockSizes := []int{${BLOCK_SIZE}}/g" "$PORAM_TEST"

# coredns: single cacheSizes
sed -i -E "s/var cacheSizes = \[\]int\{[^}]*\}/var cacheSizes = []int{${N_GO}}/" "$CORE_TEST"

echo "Patched cacheSizes / numBlocksValues to {${N_VALUES}}"
echo

# --- 3. Plain runs ----------------------------------------------------------
if [[ $SKIP_PLAIN -eq 0 ]]; then
    echo "--- coredns: LRU + ORAMCache (plain) ---"
    (cd "$CODOH_ROOT" && \
        $GO_BIN test -bench='^Benchmark(LRU|ORAM)Cache_(Get|Put)$' \
            -benchtime="${ITERS}x" -count="${COUNT}" -run=^$ \
            ./enclave/) > "${RAW}/coredns_plain.txt" 2>&1
    echo "  -> ${RAW}/coredns_plain.txt"

    echo "--- pathoram-go: LinearScan + PathORAM (plain) ---"
    (cd "$PATHORAM_DIR" && \
        $GO_BIN test -bench='^Benchmark(LinearScan|Access|BaselineMap|BaselineArray)$' \
            -benchtime="${ITERS}x" -count="${COUNT}" -run=^$ \
            .) > "${RAW}/pathoram_plain.txt" 2>&1
    echo "  -> ${RAW}/pathoram_plain.txt"
fi

# --- 4. SGX runs ------------------------------------------------------------
if [[ $SKIP_SGX -eq 0 ]]; then
    if [[ ! -e /dev/sgx_enclave ]]; then
        echo "WARN: /dev/sgx_enclave not present; skipping SGX runs" >&2
    else
        SIGNING_KEY="${CODOH_ROOT}/enclave/private.pem"
        [[ -f "$SIGNING_KEY" ]] || { echo "FATAL: missing $SIGNING_KEY" >&2; exit 3; }

        write_manifest() {
            local exe="$1"
            cat <<EOF
{
    "exe": "${exe}",
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
        }

        # coredns SGX
        echo "--- coredns: LRU + ORAMCache (SGX, ego run) ---"
        (
            cd "${CODOH_ROOT}/enclave"
            $EGO_GO_BIN test -c -o cache_bench.test .
            write_manifest cache_bench.test > cache_bench_enclave.json
            $EGO_BIN sign cache_bench_enclave.json
            $EGO_BIN run cache_bench.test \
                -test.bench='^Benchmark(LRU|ORAM)Cache_(Get|Put)$' \
                -test.benchtime="${ITERS}x" -test.count="${COUNT}" -test.run=^$
        ) > "${RAW}/coredns_sgx.txt" 2>&1
        echo "  -> ${RAW}/coredns_sgx.txt"

        # pathoram-go SGX
        echo "--- pathoram-go: LinearScan + PathORAM (SGX, ego run) ---"
        (
            cd "$PATHORAM_DIR"
            cp -f "$SIGNING_KEY" private.pem
            $EGO_GO_BIN test -c -o pathoram_bench.test .
            write_manifest pathoram_bench.test > pathoram_bench_enclave.json
            $EGO_BIN sign pathoram_bench_enclave.json
            $EGO_BIN run pathoram_bench.test \
                -test.bench='^Benchmark(LinearScan|Access|BaselineMap|BaselineArray)$' \
                -test.benchtime="${ITERS}x" -test.count="${COUNT}" -test.run=^$
        ) > "${RAW}/pathoram_sgx.txt" 2>&1
        echo "  -> ${RAW}/pathoram_sgx.txt"
    fi
fi

# --- 5. Parse + emit --------------------------------------------------------
echo
echo "--- Parsing & emitting tables ---"
python3 "${CODOH_ROOT}/benchmark/parse-cache-microbench.py" \
    --raw-dir "$RAW" \
    --out-dir "$OUT" \
    --block-size "$BLOCK_SIZE" \
    --n-values "$N_VALUES"

echo
echo "=== Done ==="
echo "Output: ${OUT}/"
ls -1 "$OUT"
