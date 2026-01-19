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
├── run-benchmark.sh      # Automated benchmark script
├── SPEC.md               # Full specification
├── README.md             # This file
├── top-1m.csv            # Cisco Umbrella Top 1M domains
├── Corefile.odoh-proxy   # ODoH baseline proxy config
├── Corefile.odoh-target  # ODoH baseline target config
└── results/              # Benchmark output
    └── <timestamp>/
        ├── odoh.{csv,json}
        ├── codoh_cold.{csv,json}
        ├── codoh_zipf.{csv,json}
        └── codoh_warm.{csv,json}
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
