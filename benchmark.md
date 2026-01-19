# CODoH Benchmark

Latency comparison between ODoH (baseline) and CODoH (with enclave).

## Quick Start

```bash
# Full benchmark (1000 iterations)
./run-benchmark.sh

# Quick test (100 iterations)
./run-benchmark.sh 100
```

Results saved to `benchmark-results/`.

## Default Tests

| Test | Protocol | Scenario | Description |
|------|----------|----------|-------------|
| `odoh_cold` | ODoH | cold | Baseline, unique queries |
| `codoh_cold` | CODoH | cold | Cache miss path (token → target → store) |
| `codoh_warm` | CODoH | warm | Cache hit path (token → cache → encrypt) |

## Architecture

```
ODoH Baseline (ports 9080/9443):
  Client → odohproxy → odohtarget → upstream DNS

CODoH (ports 8080/8443):
  Client → codohproxy → enclave → codohtarget → upstream DNS
```

## Manual Usage

```bash
# Build
go build -o coredns-test .
go build -o enclave-test ./enclave/cmd
cd /path/to/odoh-client-go && go build -o odoh-client ./cmd/odoh-client.go

# Start services (ODoH baseline)
./coredns-test -conf Corefile.odoh-target &
./coredns-test -conf Corefile.odoh-proxy &

# Start services (CODoH)
CODOH_MASTER_SECRET=$(cat dev-master-secret.txt) ./enclave-test &
./coredns-test -conf Corefile.target &
./coredns-test -conf Corefile.proxy &

# Run benchmark
./odoh-client latency \
  --protocol odoh|codoh \
  --scenario cold|warm \
  --iterations 1000 \
  --target 127.0.0.1:8443 \
  --proxy 127.0.0.1:8080 \
  --customcert localhost.pem \
  --output results.csv \
  --summary results.json
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--protocol` | odoh | `odoh` or `codoh` |
| `--scenario` | cold | `cold` (unique queries) or `warm` (repeated) |
| `--iterations` | 1000 | Number of queries |
| `--target` | 127.0.0.1:8443 | Target address |
| `--proxy` | - | Proxy address (required for codoh) |
| `--customcert` | - | Path to CA cert for self-signed TLS |
| `--output` | - | CSV output path |
| `--summary` | - | JSON summary path |
| `--domain-prefix` | bench | Prefix for generated domains |

## Output Format

### JSON Summary

```json
{
  "protocol": "codoh",
  "scenario": "cold",
  "iterations": 1000,
  "successful": 998,
  "failed": 2,
  "latency_ms": {
    "min": 22.5,
    "max": 89.3,
    "mean": 35.2,
    "p50": 33.1,
    "p95": 52.4,
    "p99": 71.2
  },
  "throughput_qps": 28.4,
  "token_fetch_ms": 4.2,
  "total_duration_s": 35.2
}
```

### CSV

```csv
timestamp,protocol,scenario,query_num,latency_ms,cache_status,success,error
1768846058834,codoh,cold,1,29.243,miss,true,
1768846058863,codoh,cold,2,22.780,miss,true,
```

## Ports

| Service | ODoH Baseline | CODoH |
|---------|---------------|-------|
| Proxy | 9080 | 8080 |
| Target | 9443 | 8443 |
| Enclave | - | Unix socket |

## Config Files

| File | Description |
|------|-------------|
| `Corefile.odoh-proxy` | ODoH baseline proxy |
| `Corefile.odoh-target` | ODoH baseline target |
| `Corefile.proxy` | CODoH proxy |
| `Corefile.target` | CODoH target |
