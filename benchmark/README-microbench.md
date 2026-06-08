# Cache-primitive microbenchmark (paper Table 4)

Measures **per-operation cache latency vs. capacity `N`**, comparing the four
cache backends used in the paper — LRU, linear scan, our ORAM cache, and
PathORAM — each **Plain** (native) and **SGX** (under `ego run`). This is the
heavier, cross-repo microbenchmark behind **Table 4**; for the lightweight
single-binary crypto/IPC/padding microbenchmarks see the
[`## Microbenchmarks`](README.md#microbenchmarks) section of `README.md`.

Two scripts:

| Script | Role |
|--------|------|
| `run-cache-microbench.sh`   | Orchestrator: patches the capacity sweep, runs all benches Plain + SGX, calls the parser. |
| `parse-cache-microbench.py` | Parses raw `go test -bench` output → `medians.json`, `table.txt`, `summary.md`. |

## What gets measured

| Backend | Benchmark(s) | Source |
|---------|--------------|--------|
| **LRU**       | `BenchmarkLRUCache_{Get,Put}`   | `enclave/cache_benchmark_test.go` (this repo) |
| **ORAM**      | `BenchmarkORAMCache_{Get,Put}`  | `enclave/cache_benchmark_test.go` (this repo) |
| **LinearScan**| `BenchmarkLinearScan`           | `pathoram-go/oram_test.go` (sibling repo) |
| **PathORAM**  | `BenchmarkAccess` (+ `BenchmarkBaselineMap/Array`) | `pathoram-go/oram_test.go` (sibling repo) |

The reported value is the **median ns/op** across trials, emitted in
microseconds. `table.txt` is the read-latency (`Get`) sweep that becomes Table 4.

## Prerequisites

1. **Go** — default `/usr/local/go/bin/go` (override with `GO_BIN`).
2. **python3** — for the parser.
3. **`pathoram-go` sibling repo** — cloned next to this repo as `../pathoram-go`
   (module `github.com/etclab/pathoram-go`). Override with `--pathoram-dir` /
   `PATHORAM_DIR`. Provides the LinearScan and PathORAM columns; without it those
   columns are empty.
4. **For the SGX half only:**
   - [EGo](https://github.com/edgelesssys/ego) installed (`ego`, `ego-go`;
     defaults `/usr/local/bin/...`, override `EGO_BIN` / `EGO_GO_BIN`).
   - An SGX machine exposing `/dev/sgx_enclave` (absent → SGX runs auto-skip with a warning).
   - An enclave **signing key at `enclave/private.pem`**. This is *not* shipped
     (gitignored). Generate one once:
     ```bash
     openssl genrsa -out enclave/private.pem -3 3072   # EGo key format: RSA-3072, exponent 3
     ```

## Quick start

```bash
# Plain only — no SGX hardware needed (LRU/ORAM/LinearScan/PathORAM, native)
./benchmark/run-cache-microbench.sh --skip-sgx

# Full Table 4 — Plain + SGX (run on the SGX VM, signing key in place)
./benchmark/run-cache-microbench.sh
```

The script **temporarily patches** the capacity sweep in both test files
(`var cacheSizes` here; `numBlocksValues`/`blockSizes` in `pathoram-go`) via
`sed`, and **restores them on exit** (success or failure, via a `trap`). It does
not leave the trees dirty.

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--n-values <csv>`   | `256,512,1024,2048,4096,16384` | capacity sweep |
| `--block-size <int>` | `4096` | ORAM block size (bytes) |
| `--iters <int>`      | `10000` | `go test -benchtime=<N>x` |
| `--count <int>`      | `3` | trials per subtest (median taken) |
| `--skip-sgx`         | off | Plain only |
| `--skip-plain`       | off | SGX only |
| `--run-id <str>`     | `cache-micro-<timestamp>` | output dir name |
| `--pathoram-dir <d>` | `../pathoram-go` | sibling repo location |

Env overrides: `GO_BIN`, `EGO_BIN`, `EGO_GO_BIN`, `PATHORAM_DIR`.

## Output

Everything lands in `benchmark/results/<run-id>/`:

```
raw/coredns_plain.txt    raw/coredns_sgx.txt      # LRU + ORAM
raw/pathoram_plain.txt   raw/pathoram_sgx.txt     # LinearScan + PathORAM
system-info.txt          # CPU / vCPUs / Go / ego / SGX devices / both repo commits
medians.json             # full per-(backend, N, op) medians, ns/op
table.txt                # Get-latency sweep in µs  ->  paper Table 4
summary.md               # human-readable table + SGX/Plain overhead ratios
```

`system-info.txt` records the `coredns` and `pathoram-go` commit hashes, so a run
is fully self-describing. Paper numbers were collected on the same Azure VMs as
the macrobenchmarks, median of 10 000 iterations.

## Re-parsing without re-running

```bash
python3 benchmark/parse-cache-microbench.py \
  --raw-dir benchmark/results/<run-id>/raw \
  --out-dir benchmark/results/<run-id> \
  --block-size 4096 --n-values 256,512,1024,2048,4096,16384
```

## Troubleshooting

- **`/dev/sgx_enclave not present`** → SGX runs are skipped (warning only); Plain results still produced.
- **`FATAL: missing .../enclave/private.pem`** → generate the signing key (see prereqs).
- **Empty LinearScan/PathORAM columns** → `pathoram-go` not found; pass `--pathoram-dir`.
- **Want a faster smoke test** → `--n-values 256,1024 --iters 1000 --count 1 --skip-sgx`.
