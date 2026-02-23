# CODoH Benchmark

Reproduce the performance evaluation from the CODoH paper. Compares plain DoH, ODoH, and CODoH with incremental privacy defenses across three DNS workloads.

## Prerequisites

- **Hardware**: Intel CPU with SGX support (`/dev/sgx_enclave` must exist)
- **OS**: Ubuntu 22.04+ (tested on 6.8.0-1010-intel kernel)
- **Software**: Go 1.25+, [EGo SDK](https://docs.edgeless.systems/ego), `dig`, `curl`, `python3`, `gnuplot`
- **Repos**: This repo (`coredns/`) and `codoh-client/` must be siblings in the same parent directory

```
codoh/
├── coredns/         # this repo
└── codoh-client/    # client binary
```

## Step-by-Step

All commands run from the **repository root** (`coredns/`).

### 1. Build everything

```bash
./benchmark/setup.sh
```

This will:
- Verify SGX hardware (fails if absent)
- Build the SGX enclave, server (`coredns-test`), and client (`odoh-client`)
- Generate TLS certificates
- Download the Cisco Umbrella top-1M domain list
- Create a git worktree for Config 3 (pinned to commit `e81a315`)

Expected output ends with a "Setup Complete" summary listing all binary paths.

### 2. Set up the local DNS resolver

We use a local [Unbound](https://nlnetlabs.nl/projects/unbound/about/) resolver to eliminate upstream DNS latency variance from measurements.

```bash
sudo apt install unbound -y
sudo cp benchmark/unbound.conf /etc/unbound/unbound.conf.d/benchmark.conf
sudo systemctl restart unbound
```

Verify it's working:

```bash
dig @127.0.0.1 -p 5353 google.com +short
```

You should see an IP address. If not, check `sudo systemctl status unbound`.

### 3. Prewarm the resolver cache

Prewarms Unbound with all domains used in the workloads. Takes ~2 minutes. Only needs to run once per session (cache persists for 24 hours).

```bash
./benchmark/prewarm-unbound.sh
```

### 4. Validate the setup

Run a quick smoke test to verify all configurations start and respond correctly:

```bash
./benchmark/run-all.sh --quick
```

This sends 10 queries to each config (smoke test) then 500 queries to Configs 4 and 7 (spot check). Takes ~5-8 minutes. Check the output for any `FAIL` lines.

### 5. Run the benchmark

Choose a run mode:

```bash
# Standard comparison (~1 hour)
# Compares ODoH vs CODoH-base vs CODoH-full — the paper's core result
./benchmark/run-all.sh --standard --sgx --run-id std-01

# Full evaluation (~4-7 hours)
# All 9 configs + ablation + parameter sweeps
./benchmark/run-all.sh --sgx --run-id full-01 --sweep-oram --sweep-cover
```

### 6. Find the results

Results are in `benchmark/results/<run-id>/`:

```
benchmark/results/std-01/
├── metadata.json              # Run parameters, system info, timestamps
├── raw/
│   ├── odoh_cold.json         # Per-config per-workload results
│   ├── odoh_cold.csv          # Per-query latency trace
│   ├── codoh-base_cold.json
│   ├── codoh-full_zipf.json
│   └── ...
└── processed/                 # (populated by plotting scripts)
```

Each `.json` file contains:

```json
{
  "latency_ms": { "min": 0.5, "mean": 7.1, "p50": 0.9, "p95": 29.6, "p99": 40.6 },
  "throughput_qps": 140.8,
  "cache_hit_rate": 0.776,
  "iterations": 10000,
  "successful": 10000
}
```

A summary table is printed to stdout when the run completes.

---

## What's Being Measured

### Configurations

The benchmark incrementally adds privacy defenses to measure their individual overhead:

| # | Config | What it adds over previous |
|---|--------|---------------------------|
| 1 | **DoH** | Baseline — plain DNS-over-HTTPS |
| 2 | **ODoH** | + Oblivious proxy (HPKE encryption) |
| 3 | **CODoH-base** | + Enclave with LRU cache (2-proc proxy mode) |
| 4 | **CODoH-IPC** | + 3-proc IPC architecture, dummy responses, replay protection |
| 5 | **CODoH-ORAM** | + ORAM cache (hides access patterns) |
| 6 | **CODoH-cover** | + Cover responses (hides cache set membership) |
| 7 | **CODoH-full** | + All defenses: ORAM + covers + batching + padding |

Ablation configs **4b** (batching only) and **4p** (padding only) isolate cheap defenses.

### Workloads

| Name | Pattern | Purpose |
|------|---------|---------|
| **cold** | 10K unique domains (sequential) | Worst case: all cache misses |
| **zipf** | 10K queries, Zipf s=1.0 over 1K domains | Realistic: skewed popularity with natural hits |
| **warm** | 10K queries to `google.com` | Best case: all cache hits after first |

### Parameter Sweeps

| Sweep | Values | Configs | Purpose |
|-------|--------|---------|---------|
| ORAM capacity (N) | 256, 1024, 2048 | 5, 7 | ORAM scaling within SGX EPC |
| Cover count (k) | 1, 3, 5 | 6, 7 | Privacy vs. performance tradeoff |

---

## Options Reference

```
./benchmark/run-all.sh [OPTIONS]

Modes (mutually exclusive):
  --quick              Smoke test + spot check                    (~5-8 min)
  --standard           Core 3-config comparison                   (~1 hour)
  (default)            Full 9-config evaluation                   (~4-7 hrs)

Options:
  --run-id NAME        Name for results directory (default: auto-generated)
  --sgx                Run enclaves with SGX (ego run). Required for paper results.
  --configs 1,4,7      Run only specified configs
  --workloads cold,warm Run only specified workloads
  --iterations N       Queries per workload (default: 10000)
  --warmup N           Warm-up queries to discard (default: 100)
  --sweep-oram         ORAM capacity sweep (N=256,1024,2048)
  --sweep-cover        Cover count sweep (k=1,3,5)
  --zipf-s S           Zipf skew parameter (default: 1.0)
```

---

## Troubleshooting

**`setup.sh` fails with "SGX hardware required"**
Your machine needs Intel SGX. Check `ls /dev/sgx*`. Without SGX, remove `--sgx` from run commands to use simulation mode (results won't match the paper).

**Unbound not responding on port 5353**
Check for systemd-resolved conflict: `sudo systemctl stop systemd-resolved`. Verify config: `sudo unbound-checkconf`.

**Config 3 fails with "worktree not found"**
Run `./benchmark/setup.sh` first. It creates the git worktree at `benchmark/worktrees/config3-proxy/`.

**Health check timeout on SGX configs**
SGX enclave initialization is slow (10-30s). The orchestrator waits up to 45s in SGX mode. If still failing, check enclave logs in `results/<run-id>/raw/enclave.log`.

**Port conflicts**
Kill leftover processes: `lsof -ti :8080 :8443 :7443 :9080 :9443 :10443 :10444 | xargs kill -9`
Also: `pkill -f 'ego-host.*enclave'` and `rm -f /tmp/codoh-enclave.sock`

**Prewarm takes too long**
Increase parallelism: `./benchmark/prewarm-unbound.sh --parallel 100`

---

## Ports Used

| Port | Service |
|------|---------|
| 5353 | Unbound (local resolver) |
| 7443 | DoH server (Config 1) |
| 8080 | CODoH proxy (Configs 4-7) |
| 8443 | CODoH target (Configs 4-7) |
| 8444 | Enclave attestation |
| 9080 | ODoH proxy (Config 2) |
| 9443 | ODoH target (Config 2) |
| 10443 | CODoH-base enclave-proxy (Config 3) |
| 10444 | CODoH-base target (Config 3) |

## Notes for Artifact Reviewers

- All paper numbers use `--sgx`. Simulation mode (`enclave-sim`) is for development only.
- Config 3 runs from a pinned git worktree (`e81a315`) because the proxy-mode architecture diverged from the current IPC-based codebase. The crypto primitives are identical.
- ORAM sweep sizes (256/1024/2048) are chosen to fit within the SGX EPC (~93MB). Larger ORAM trees cause EPC paging and unrepresentative results.
- Unbound's `cache-min-ttl: 86400` ensures cached entries survive the entire benchmark session. Prewarm once before running.
- `metadata.json` in each results directory records all run parameters for reproducibility.
