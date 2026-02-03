# CODoH Benchmark

Latency comparison between ODoH (baseline) and CODoH (with enclave).

## Quick Start

```bash
# From coredns root directory
./benchmark/run-benchmark.sh        # Full benchmark (1000 iterations)
./benchmark/run-benchmark.sh 100    # Quick test (100 iterations)
```

Results saved to `benchmark/results/<timestamp>/`.

## Test Scenarios

| Test | Distribution | Description |
|------|--------------|-------------|
| `odoh` | sequential | ODoH baseline, unique queries from Top 1M |
| `codoh_cold` | sequential | CODoH cache miss path (all unique domains) |
| `codoh_zipf` | Zipf (s=1.0) | CODoH realistic traffic (natural cache hits) |
| `codoh_warm` | single domain | CODoH best-case (all cache hits after first) |

## Architecture

```
ODoH Baseline (ports 9080/9443):
  Client → odohproxy → odohtarget → upstream DNS

CODoH (ports 8080/8443):
  Client → codohproxy → enclave → codohtarget → upstream DNS
```

## Files

```
benchmark/
├── run-benchmark.sh              # Main benchmark (ODoH vs CODoH)
├── run-stochastic-benchmark.sh   # Stochastic defense benchmark
├── SPEC.md                       # Full specification
├── README.md                     # This file
├── top-1m.csv                    # Cisco Umbrella Top 1M domains
├── top-1k.csv                    # Top 1K domains (for quick tests)
├── Corefile.odoh-proxy           # ODoH baseline proxy config
├── Corefile.odoh-target          # ODoH baseline target config
└── results/                      # Benchmark output
    ├── <timestamp>/              # Main benchmark results
    │   ├── odoh.{csv,json}
    │   ├── codoh_cold.{csv,json}
    │   ├── codoh_zipf.{csv,json}
    │   └── codoh_warm.{csv,json}
    └── stochastic_<timestamp>/   # Stochastic benchmark results
        ├── baseline_zipf.{csv,json}
        ├── light_zipf.{csv,json}
        ├── moderate_zipf.{csv,json}
        ├── heavy_zipf.{csv,json}
        ├── max_security_zipf.{csv,json}
        ├── *_enclave.log
        └── comparison_report.txt
```

## Manual Usage

```bash
# Build (from coredns root)
go build -o coredns-test .
go build -o enclave-test ./enclave/cmd
cd ../odoh-client-go && go build -o odoh-client ./cmd/odoh-client.go

# Run individual benchmark
./odoh-client latency \
  --protocol codoh \
  --distribution zipf \
  --iterations 1000 \
  --target 127.0.0.1:8443 \
  --proxy 127.0.0.1:8080 \
  --domains benchmark/top-1m.csv \
  --zipf-s 1.0 \
  --customcert localhost.pem \
  --output results.csv \
  --summary results.json
```

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--protocol` | odoh | `odoh` or `codoh` |
| `--distribution` | sequential | `sequential` or `zipf` |
| `--iterations` | 1000 | Number of queries |
| `--domains` | - | Path to domains CSV (rank,domain format) |
| `--zipf-s` | 1.0 | Zipf skew parameter (higher = more skewed) |
| `--target` | 127.0.0.1:8443 | Target address |
| `--proxy` | - | Proxy address (required for codoh) |
| `--customcert` | - | Path to CA cert for self-signed TLS |
| `--output` | - | CSV output path |
| `--summary` | - | JSON summary path |

## Output Format

### JSON Summary

```json
{
  "protocol": "codoh",
  "distribution": "zipf",
  "iterations": 1000,
  "successful": 1000,
  "failed": 0,
  "cache_hits": 776,
  "cache_misses": 224,
  "cache_hit_rate": 0.776,
  "latency_ms": {
    "min": 0.5,
    "max": 89.3,
    "mean": 7.1,
    "p50": 0.9,
    "p95": 29.6,
    "p99": 40.6
  },
  "throughput_qps": 140.8,
  "token_fetch_ms": 4.2,
  "total_duration_s": 7.1
}
```

### CSV

```csv
timestamp,protocol,distribution,query_num,domain,latency_ms,cache_status,success,error
1768846058834,codoh,zipf,1,google.com.,0.871,hit,true,
1768846058835,codoh,zipf,2,facebook.com.,29.243,miss,true,
```

## Ports

| Service | ODoH Baseline | CODoH |
|---------|---------------|-------|
| Proxy | 9080 | 8080 |
| Target | 9443 | 8443 |
| Enclave | - | Unix socket |

---

## Stochastic Defense Benchmark

Measures the latency impact of Phase 3 stochastic defenses (hit suppression, non-insertion, churn).

### Quick Start

```bash
# Quick test (100 iterations, ~2-3 minutes)
./benchmark/run-stochastic-benchmark.sh --quick

# Standard test (500 iterations)
./benchmark/run-stochastic-benchmark.sh

# With ORAM cache + churn test
./benchmark/run-stochastic-benchmark.sh --oram

# Custom iterations
./benchmark/run-stochastic-benchmark.sh --iterations=200
```

### Test Configurations

| Config | p_fn | p_ins | Churn | Description |
|--------|------|-------|-------|-------------|
| baseline | 0.0 | 1.0 | No | No defenses (reference) |
| light | 0.1 | 0.9 | No | Production recommended |
| moderate | 0.2 | 0.8 | No | Balanced security |
| heavy | 0.3 | 0.7 | No | Higher security |
| max_security | 0.5 | 0.5 | No | Maximum snapshot resistance |
| oram_churn | 0.1 | 0.9 | 30s | ORAM only, with background eviction |

### Stochastic Parameters

| Parameter | Env Variable | Description |
|-----------|--------------|-------------|
| Hit Suppression (p_fn) | `CODOH_HIT_SUPPRESSION_PROB` | Probability of returning miss even when cached [0.0-1.0] |
| Insert Probability (p_ins) | `CODOH_INSERT_PROB` | Probability of caching a response [0.0-1.0] |
| Churn Enabled | `CODOH_CHURN_ENABLED` | Enable background random eviction (ORAM only) |
| Churn Interval | `CODOH_CHURN_INTERVAL_SECS` | Seconds between churn events |

### Output

Results saved to `benchmark/results/stochastic_<timestamp>/`:

| File | Description |
|------|-------------|
| `*_zipf.csv/json` | Latency measurements |
| `*_enclave.log` | Cache hit/miss/suppression logs |
| `*_cache_stats.txt` | Cache behavior summary |
| `comparison_report.txt` | Side-by-side comparison |

### Example Results

```
Config            Mean(ms)    P50(ms)    P95(ms)    P99(ms)    HitRate
-------           --------    -------    -------    -------    -------
baseline             12.36      13.84      24.67      27.24      36.0%
light                12.69      13.75      25.23      28.71      30.0%
moderate             15.24      13.91      27.11      83.16      21.0%
heavy                14.11      14.01      25.68      29.52      25.0%
max_security         15.37      14.17      26.76      28.98      13.0%

Config              Hits   Misses Suppressed    Skipped  Churned
-------             ----   ------ ----------    -------  -------
baseline              36       64          0          0        0
light                 30       70          4          6        0
moderate              21       79         10         16        0
heavy                 25       75         10         20        0
max_security          13       87         17         46        0
```

### Recommended Production Settings

```bash
# Balanced security/performance (~3% latency overhead)
CODOH_HIT_SUPPRESSION_PROB=0.1
CODOH_INSERT_PROB=0.9

# High security with ORAM (~25% latency overhead)
CODOH_USE_ORAM=true
CODOH_HIT_SUPPRESSION_PROB=0.2
CODOH_INSERT_PROB=0.8
CODOH_CHURN_ENABLED=true
CODOH_CHURN_INTERVAL_SECS=60
```
