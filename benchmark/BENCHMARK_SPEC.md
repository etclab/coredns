# CODoH Benchmark Specification

## 1. Evaluation Approach

**Hybrid**: main comparison table across all configs (summary), plus targeted ablation table isolating individual defense overhead. CDF plots for distribution deep-dive.

---

## 2. Configuration Matrix

### 2.1 Main Configs

| # | Name | Architecture | Cache | Defenses | Purpose |
|---|------|-------------|-------|----------|---------|
| 1 | DoH | 1-proc | — | None | Pure baseline (RFC 8484) |
| 2 | ODoH | 2-proc | — | HPKE | Encryption overhead baseline |
| 3 | CODoH-base | 2-proc (proxy mode) | LRU | Dual HPKE | Enclave + caching overhead |
| 4 | CODoH-nosgx | 3-proc (IPC) | ORAM | ORAM + covers + batching + padding | Full defenses, no SGX (isolates SGX overhead) |
| 5 | CODoH-full | 3-proc (IPC, SGX) | ORAM | ORAM + covers + batching + padding | Full defense stack |

### 2.2 Parameter Sweeps

Sweeps run on relevant configs only (not the full matrix):

**ORAM capacity sweep** (Config 5):
- N = 256, 1024, 2048
- Sized to fit within SGX EPC (~115MB usable; BIOS-configurable on Xeon Scalable)
- Block size: 4096B, Z=5 → tree sizes: ~5MB, ~40MB, ~80MB

**Cover count sweep** (Config 5):
- k = 1, 3, 5

---

## 3. Workloads

| Workload | Distribution | Domain source | Queries | Purpose |
|----------|-------------|--------------|---------|---------|
| cold | sequential | top-1m.csv (first 10K) | 10,000 | All cache misses |
| zipf | Zipf s=1.0 | top-1k.csv | 10,000 | Mixed hits/misses (realistic skew) |
| warm | sequential | single domain (google.com) | 10,000 | All cache hits (after first) |

### 3.1 Warm-up Protocol

Before each measured workload:
1. Send **100 warm-up queries** (same workload distribution)
2. Discard warm-up latencies
3. Begin 10K measured queries

Warm-up self-validates system readiness — if warm-up queries fail, the config isn't ready.

---

## 4. Metrics

### 4.1 Per-Run Metrics

| Metric | Detail |
|--------|--------|
| Latency | Median, P95, P99 (per query round-trip) |
| Throughput | Queries per second (aggregate) |
| Cache hit rate | hits / total (from enclave health endpoint) |

### 4.2 Ablation Table Format

Each row shows:
- **Absolute**: Median / P95 / P99 in milliseconds
- **Delta**: Δ vs Config 5 in ms and % (e.g., "+12ms / +24%")

### 4.3 Visualization

- **Main comparison**: Summary table (all configs, Median/P95/P99 per workload)
- **Ablation deep-dive**: CDF plots per workload, configs overlaid
- **Sweep results**: Line plots (ORAM capacity or k on x-axis, latency on y-axis)
- **Tooling**: gnuplot

---

## 5. Execution Environment

### 5.1 SGX Requirement

All benchmark numbers are **SGX-only**. No simulation results in the paper.

`setup.sh` fails hard if `/dev/sgx_enclave` is not present:
```
SGX hardware required for artifact evaluation. Aborting.
```

### 5.2 Upstream Resolver

**Local Unbound** (recursive resolver on localhost):
- Port: 5353 (avoids systemd-resolved conflict)
- `cache-min-ttl: 86400` (24h TTL override)
- `prefetch: no` (clean measurement)
- Prewarm script (`benchmark/prewarm-unbound.sh`) sends parallel queries for all domains in workload files before benchmark begins
- Prewarm once per session (~2 min with parallelism)
- **Rationale**: Isolates CODoH system overhead from upstream RTT variance. Cover overhead reflects crypto/IPC cost, not resolver latency.

### 5.3 Concurrency

Sequential queries only (single client). Measures per-query overhead cleanly.

---

## 6. Infrastructure

### 6.1 Directory Layout

```
benchmark/
├── configs/
│   ├── 1-doh.sh
│   ├── 2-odoh.sh
│   ├── 3-codoh-base.sh
│   ├── 4-codoh-nosgx.sh
│   └── 5-codoh-full.sh
├── results/
│   └── <run-id>/               # e.g., "final-sgx-2026-02-24"
│       ├── raw/                 # JSON output per config per workload
│       └── processed/           # CSVs, CDF data, gnuplot scripts
├── run-all.sh                   # orchestrator
├── setup.sh                     # one-command: build, certs, domain lists
├── prewarm-unbound.sh           # prewarm Unbound cache
├── unbound.conf                 # benchmark Unbound config
└── plot/
    ├── comparison-table.gp      # summary table gnuplot script
    ├── cdf.gp                   # CDF overlay plot
    └── sweep.gp                 # parameter sweep line plots
```

### 6.2 Config 3 Worktree

Config 3 (CODoH-base, proxy mode) requires an older codebase where the 2-process proxy architecture was functional. It runs from a pinned git worktree on the same branch (`codoh-design-v2`).

- **Worktree path**: `benchmark/worktrees/config3-proxy/`
- **Pinned commit**: `e81a315ec3a91dee1bad2cc2bbf139ebee145ab8`
- `setup.sh` creates the worktree: `git worktree add benchmark/worktrees/config3-proxy e81a315`
- Config 3's `start_config()` builds and runs binaries from the worktree path
- The crypto primitives (HPKE suite, key derivation) are the same across both versions — only the architecture differs
- Document the pinned commit hash in results metadata
- Worktree is read-only during benchmarks (no modifications)

### 6.3 setup.sh Responsibilities

1. Check SGX availability (`/dev/sgx_enclave`) — fail hard if absent
2. Check/install ego SDK
3. Build enclave binary: `cd enclave && ego-go build -tags ego -o enclave ./cmd && ego sign enclave.json`
4. Build server binary: `go build -o coredns-test .` (from project root)
5. Build client binary: `cd ../codoh-client && go build -o odoh-client ./cmd`
6. Generate dev TLS certs (localhost.pem, localhost-key.pem) via mkcert or openssl
7. Download Cisco top-1M domain list if not present
8. Install + configure Unbound (port 5353, benchmark config)
9. Print summary of built artifacts and readiness

### 6.3 run-all.sh Fixes Required

- [ ] Fix SGX paths for Config 5 (currently hardcode `enclave-sim`, need `ego run`)
- [ ] Replace 2s sleep with 100-query warm-up protocol
- [ ] Add `--run-id` flag for results directory naming
- [ ] Support `--configs` flag to run subset (e.g., `--configs 1,2,3,4`)
- [ ] Support sweep mode for ORAM/cover parameter variation
- [ ] Increase query count to 10K (from current ~1K)
- [ ] Add enclave health check (poll IPC socket or /health on enclave attestation port)

---

## 7. Benchmark Run Matrix

### 7.1 Main Comparison (all configs, default params)

| Config | cold | zipf | warm |
|--------|------|------|------|
| 1 (DoH) | x | x | x |
| 2 (ODoH) | x | x | x |
| 3 (CODoH-base) | x | x | x |
| 4 (CODoH-nosgx, N=1024, k=3) | x | x | x |
| 5 (CODoH-full, N=1024, k=3) | x | x | x |

**Runs: 5 configs * 3 workloads = 15 runs**

### 7.2 ORAM Capacity Sweep

| N | Config 5 |
|---|----------|
| 256 | cold, zipf, warm |
| 1024 | (from §7.1) |
| 2048 | cold, zipf, warm |

**New runs: 2 sizes * 1 config * 3 workloads = 6 runs** (1024 reused from §7.1)

### 7.3 Cover Count Sweep

| k | Config 5 |
|---|----------|
| 1 | cold, zipf, warm |
| 3 | (from §7.1) |
| 5 | cold, zipf, warm |

**New runs: 2 values * 1 config * 3 workloads = 6 runs** (k=3 reused from §7.1)

### 7.4 Total

- Main: 15
- ORAM sweep: 6
- Cover sweep: 6
- **Total: 27 runs**

At ~10K queries per run, estimated ~3-8 min/run (varies by config), total runtime: **~2-4 hours**.

---

## 8. Quick Validation Mode

A fast smoke-test + spot-check mode for verifying system correctness before committing to a full run.

**Invocation**: `./run-all.sh --quick [--run-id <name>]`

### 8.1 Phase 1: Smoke Test (all configs)

- **50 queries** per config, `warm` workload only, 10-query warm-up
- **Pass/fail** per config
- Runs all 5 main configs sequentially
- **Purpose**: Catch startup failures, broken IPC, cert issues, port conflicts
- **Estimated time**: ~3-5 minutes total

### 8.2 Phase 2: Spot Check (Configs 2, 3, 4, 5)

- **1000 queries** per workload (cold, zipf, warm) on Configs 2 (ODoH), 3 (CODoH-base), 4 (CODoH-nosgx), and 5 (CODoH-full)
- 50-query warm-up (discarded)
- Reports rough Median/P95 — sufficient to detect regressions and compare across workloads
- **Purpose**: Sanity-check baselines and extremes across all traffic patterns
- **Estimated time**: ~5-10 minutes total

### 8.3 Output

- Smoke results: `results/<run-id>/quick/smoke.txt` (PASS/FAIL per config)
- Spot-check results: `results/<run-id>/quick/spot-{config}-{workload}.json`
- Script exits non-zero if any smoke config FAILs

**Total quick validation time: ~8-15 minutes.**

---

## 8b. Standard Mode (~1 hour)

An intermediate run comparing the three key system tiers with full 10K query counts. Gives publication-usable numbers for the core comparison without the ablation/sweep overhead.

**Invocation**: `./run-all.sh --standard [--run-id <name>]`

### Configs

| # | Name | Role in comparison |
|---|------|--------------------|
| 2 | ODoH | Baseline — encrypted DNS, no caching, no enclave |
| 3 | CODoH-base | Proxy mode — enclave + LRU cache, minimal defenses |
| 4 | CODoH-nosgx | Full defenses, no SGX — isolates SGX overhead |
| 5 | CODoH-full | Full defense stack — ORAM + covers + batching + padding (SGX) |

### Runs

| Config | cold (10K) | zipf (10K) | warm (10K) |
|--------|-----------|-----------|-----------|
| 2 (ODoH) | x | x | x |
| 3 (CODoH-base) | x | x | x |
| 4 (CODoH-nosgx) | x | x | x |
| 5 (CODoH-full) | x | x | x |

- 100-query warm-up per run (discarded)
- **12 runs total**
- Estimated ~5-10 min/run → **~60-120 minutes**

### What it shows

- **ODoH → CODoH-base**: cost of adding an enclave cache (encryption + caching overhead)
- **CODoH-base → CODoH-nosgx**: cost of full privacy defenses (ORAM, covers, batching, padding, IPC architecture)
- **CODoH-nosgx → CODoH-full**: cost of SGX enclave isolation
- Enough to answer: "how much does full privacy cost over baseline encrypted DNS?"

### Output

- `results/<run-id>/standard/{config}_{workload}.json`
- Summary table printed to stdout on completion

---

## 9. Cleanup Plan

### 9.1 Delete

| File | Reason |
|------|--------|
| `run-benchmark.sh` | Pre-v2: stochastic defenses, `token_enabled`, inline Corefiles with removed directives, wrong ports (18080/18443). Fully superseded by `run-all.sh` + config scripts. |
| `run-mle-stochastic-benchmark.sh` | MLE + stochastic design removed in v2. All env vars (`CODOH_HIT_SUPPRESSION_PROB`, `CODOH_INSERT_PROB`, `CODOH_CHURN_*`), log patterns, and `dev-master-secret.txt` dependency are gone. |

### 9.2 Update

| File | Changes |
|------|---------|
| `run-all.sh` | Default iterations 1K→10K; add `--run-id`, `--quick`, `--standard` modes; fix SGX build path (`ego-go build -tags ego`, `ego sign enclave.json` from `enclave/` dir); add warm-up protocol (100 queries discarded); fix cleanup to kill `ego-host` children (`pkill -f 'ego-host.*enclave'`); add `--configs` flag for subset runs; add sweep mode for ORAM/cover params; all upstream resolvers → `127.0.0.1:5353` |
| `configs/3-codoh-base.sh` | Build/run from worktree at `benchmark/worktrees/config3-proxy/` (pinned `e81a315`), not current HEAD |
| `configs/4-codoh-nosgx.sh` | Full defense stack without SGX; all CODOH_* env vars |
| `configs/5-codoh-full.sh` | Full defense stack (SGX); SGX branching; all CODOH_* env vars |
| `README.md` | Rewrite to document 4-config matrix, three run modes, setup instructions, results layout |
| `Corefile.codoh-base-target` | Upstream → `127.0.0.1:5353` |

### 9.3 Keep As-Is

`configs/1-doh.sh`, `configs/2-odoh.sh`, `Corefile.doh`, `Corefile.odoh-proxy`, `Corefile.odoh-target`, `top-1m.csv`, `top-1k.csv`, `top-10.csv`

### 9.4 Create

| File | Purpose |
|------|---------|
| `setup.sh` | One-command build + environment setup (§6.3) |
| `prewarm-unbound.sh` | Parallel DNS prewarm for Unbound cache |
| `unbound.conf` | Benchmark-tuned Unbound configuration |
| `plot/comparison-table.gp` | Summary table gnuplot script |
| `plot/cdf.gp` | CDF overlay plot |
| `plot/sweep.gp` | Parameter sweep line plots |

### 9.5 Upstream Resolver Consistency

All configs that resolve upstream DNS must point to local Unbound (`127.0.0.1:5353`). This includes:
- Corefiles for Configs 1-5 (the `forward` directive)
- `CODOH_COVER_RESOLVER` env var in Configs 4 and 5
- Target Corefiles (`Corefile.target`, `Corefile.codoh-base-target`, etc.)

Exception: DoH (Config 1) and ODoH (Config 2) baselines may optionally keep `8.8.8.8` if the goal is to show real-world DoH/ODoH latency. Decision: **use Unbound for all** — consistency matters more than realism for baselines.

---

## 10. Reproducibility Notes

- All numbers are SGX-only (`ego run`)
- Unbound with `cache-min-ttl: 86400` — prewarm once per session via `prewarm-unbound.sh`
- ORAM sizes chosen to fit within SGX EPC (~115MB usable; BIOS-configurable on Xeon Scalable): N ∈ {256, 1024, 2048}
- Report system specs: CPU model, EPC size, RAM, kernel version, ego version
- Artifact reviewer runs: `./setup.sh && ./prewarm-unbound.sh && ./run-all.sh --run-id artifact-eval`
