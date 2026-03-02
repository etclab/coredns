# CODoH Cloud Benchmark — ELI5 Guide

> **Audience**: Someone who needs to run the page-load benchmark across 3 Azure VMs (client, proxy, target) and wants to understand every script, the execution order, and what's missing.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [Script-by-Script Summary](#2-script-by-script-summary)
3. [Execution Order & Dependencies](#3-execution-order--dependencies)
4. [How IPs, Certs, and Code Cloning Are Handled](#4-how-ips-certs-and-code-cloning-are-handled)
5. [What's Missing / Manual Steps](#5-whats-missing--manual-steps)
6. [Quick Reference Cheatsheet](#6-quick-reference-cheatsheet)

---

## 1. The Big Picture

You have **3 VMs** in Azure:

| VM | Role | What runs on it | Azure VM type |
|----|------|-----------------|---------------|
| **Client** | Sends DNS queries, measures latency | `odoh-client` benchmark tool (or Playwright + dnscrypt-proxy for page-load) | Any VM |
| **Proxy** | Oblivious relay + SGX enclave | `coredns-test` (codohproxy plugin) + enclave binary | **DCsv3** (SGX required) |
| **Target** | Resolves DNS queries | `coredns-test` (codohtarget plugin) + upstream resolver | Any VM |

**Data flow**: `Client → Proxy (encrypts via enclave) → Target (resolves DNS) → Proxy → Client`

The benchmark scripts automate: provisioning these VMs with code & dependencies, starting the right processes on each, running the benchmark from the client, and collecting results.

---

## 2. Script-by-Script Summary

### Configuration & Environment

| Script | What it does | Run where? |
|--------|-------------|------------|
| **`cloud-env.sh`** | **Template** for environment variables (VM IPs, SSH keys, Azure NSG names, git branch). You copy this to `cloud-env.local.sh` and fill in your values. Never edited directly. | N/A (template) |
| **`cloud-env.local.sh`** | Your **local copy** with actual IPs and settings. Gitignored. Every other `cloud-*` script sources this file. | Created on Client VM |

### VM Provisioning & Setup

| Script | What it does | Run where? |
|--------|-------------|------------|
| **`cloud-provision.sh`** | **One-shot bootstrapper.** SSHs into proxy and target VMs, installs Go, clones the repo via `gh`, checks out the right branch, and runs `cloud-setup.sh` on each. Also sets up the client locally and checks port reachability. This is the "do everything" script. | **Client VM** |
| **`cloud-setup.sh`** | **Per-VM role provisioner.** Takes a role argument (`proxy`, `target`, or `client`) and installs role-specific dependencies. For proxy: installs EGo SDK, builds SGX enclave, builds `coredns-test`, generates TLS certs. For target: builds `coredns-test`, downloads domain lists, filters resolvable domains, generates TLS certs. For client: builds `odoh-client`, downloads domain lists. | **On each VM** (called by `cloud-provision.sh` via SSH, or manually) |

### Port Management

| Script | What it does | Run where? |
|--------|-------------|------------|
| **`cloud-check-ports.sh`** | Checks if benchmark ports are open between all VMs (client→proxy, client→target, proxy→target, target→proxy). Starts temporary Python listeners on remote VMs, probes with `nc`. Tells you which ports are blocked. | **Client VM** |
| **`cloud-open-ports.sh`** | Opens benchmark ports in Azure NSGs using `az` CLI. Requires `RESOURCE_GROUP`, `PROXY_NSG`, `TARGET_NSG` in `cloud-env.local.sh`. Proxy ports: 8080, 8444, 9080, 10443. Target ports: 7443, 8443, 9443, 10444. | **Client VM** |

### Running Benchmarks

| Script | What it does | Run where? |
|--------|-------------|------------|
| **`cloud-run.sh`** | **Cross-VM benchmark orchestrator.** Runs from the client. SSHs into proxy/target to start the right processes (enclave, coredns instances), generates Corefiles with correct IPs, distributes certs and configs to VMs, runs the `odoh-client` benchmark tool locally, collects results. Supports 5 configurations, 3 workloads, ORAM/cover sweeps. | **Client VM** |
| **`run-all.sh`** | **Single-machine orchestrator.** Same as `cloud-run.sh` but assumes everything runs on one machine (localhost). Used for local development/testing, not for distributed cloud benchmarks. | **Single machine** |
| **`setup.sh`** | **Single-machine setup.** Builds all binaries, generates certs, downloads domain lists, sets up Unbound. Designed for running everything on one SGX machine. `cloud-setup.sh` is the cloud equivalent split by role. | **Single machine** |

### Data & Utilities

| Script | What it does | Run where? |
|--------|-------------|------------|
| **`filter-resolvable.sh`** | Filters `top-1m.csv` to produce exactly N domains that actually resolve (no NXDOMAIN/SERVFAIL). Uses parallel `dig` queries. Produces `top-1k-resolvable.csv` and `top-10k-resolvable.csv`. | **Target VM** (called by `cloud-setup.sh target`) |
| **`prewarm-unbound.sh`** | Preloads Unbound's cache with all benchmark domains so upstream DNS latency doesn't affect measurements. Only relevant when using local Unbound (not for cloud mode with `cloudflare` resolver). | **Target VM** (if using Unbound) |
| **`cloud-collect-logs.sh`** | Post-run log fetcher. SCPs `/tmp/bench-*.log` from proxy and target VMs into `results/<run-id>/logs/`. Useful for debugging failed runs. | **Client VM** |
| **`patch-config3-client.sh`** | Patches the Config 3 client worktree for compatibility with the Config 3 server worktree (different content-type and decryption logic). Called automatically by `cloud-setup.sh client`. | **Client VM** |

### Plotting & Analysis

| Script | What it does | Run where? |
|--------|-------------|------------|
| **`plot.sh`** | Generates CDF plots (EPS+PDF) and LaTeX tables from benchmark results. Calls `plot_preprocess.py` then `gnuplot`. | **Client VM** (post-run) |
| **`plot_preprocess.py`** | Python script that reads raw JSON/CSV results, computes CDFs, generates gnuplot scripts and LaTeX table fragments. | **Client VM** (called by `plot.sh`) |

### Corefile Templates

| File | Config | Ports |
|------|--------|-------|
| `Corefile.doh` | Config 1: Plain DoH server | 7443 |
| `Corefile.odoh-target` | Config 2: ODoH target | 9443 |
| `Corefile.odoh-proxy` | Config 2: ODoH proxy | 9080 |
| `Corefile.codoh-base-target` | Config 3: CODoH-base target | 10444 |
| `Corefile.target-nosgx` | Config 4: CODoH target (no SGX) | 8443 |
| `Corefile.target` (repo root) | Config 5: CODoH target (full SGX) | 8443 |
| `Corefile.proxy` (repo root) | Config 4 & 5: CODoH proxy | 8080 |

---

## 3. Execution Order & Dependencies

### Step 0: Create Azure VMs (MANUAL)

> **There is NO script to create VMs.** You must create them manually in Azure.

You need:
- **Proxy VM**: Azure **DCsv3** series (SGX-capable). Ubuntu 22.04.
- **Target VM**: Any Azure VM. Ubuntu 22.04.
- **Client VM**: Any Azure VM (or your local machine). Ubuntu 22.04.

After creating VMs:
1. Note down their public IPs
2. Set up SSH key auth (`ssh-copy-id` or Azure SSH key injection)
3. Install `gh` CLI on all VMs and run `gh auth login` (repos are private)

### Step 1: Configure Environment (Client VM)

```bash
cd coredns/benchmark
cp cloud-env.sh cloud-env.local.sh
# Edit cloud-env.local.sh — fill in:
#   PROXY_IP=<proxy VM public IP>
#   TARGET_IP=<target VM public IP>
#   RESOURCE_GROUP=<your Azure resource group>
#   PROXY_NSG=<NSG name on proxy VM>
#   TARGET_NSG=<NSG name on target VM>
#   SSH_KEY=<path to your SSH private key>
```

### Step 2: Run cloud-provision.sh (Client VM)

```bash
./benchmark/cloud-provision.sh
```

This single command does **everything** in order:
1. Verifies SSH connectivity to proxy and target
2. **Proxy VM** (via SSH): Installs Go → clones repo → checks out branch → runs `cloud-setup.sh proxy` (installs EGo, builds enclave + coredns-test, generates TLS certs with SANs for both VMs)
3. **Target VM** (via SSH): Installs Go → clones repo → checks out branch → runs `cloud-setup.sh target` (builds coredns-test, downloads domain lists, filters resolvable domains, generates TLS certs)
4. **Client (local)**: Clones `codoh-client` repo → runs `cloud-setup.sh client` (builds odoh-client, downloads domain lists, sets up Config 3 client worktree)
5. Checks port reachability (`cloud-check-ports.sh`). If ports are blocked AND NSG vars are set, auto-runs `cloud-open-ports.sh`

### Step 3: Run Benchmarks (Client VM)

```bash
# Quick smoke test (~5-8 min)
./benchmark/cloud-run.sh --quick

# Standard comparison (~1 hour)
./benchmark/cloud-run.sh --standard --run-id my-run

# Full suite with sweeps (~2-4 hours)
./benchmark/cloud-run.sh --configs 2,3,4,5 --sweep-oram --sweep-cover --run-id full-01
```

What `cloud-run.sh` does internally:
1. Verifies SSH connectivity
2. Generates Corefiles with IP substitutions (`127.0.0.1` → actual VM IPs)
3. Fetches TLS certs from proxy VM → distributes to target and client
4. For each config: SSHs into VMs to start processes → waits for health checks → runs `odoh-client latency` locally → collects results
5. Between configs: kills all remote processes, cleans up
6. At the end: SCPs logs from both VMs, prints summary table

### Step 4: Collect Results & Plot (Client VM)

```bash
# Results are automatically saved to benchmark/results/<run-id>/
# Optionally fetch extra logs:
./benchmark/cloud-collect-logs.sh <run-id>

# Generate plots (requires gnuplot, python3):
./benchmark/plot.sh benchmark/results/<run-id>
```

### Dependency Graph (Visual)

```
Manual: Create 3 Azure VMs + SSH keys + gh auth login
  │
  ▼
cloud-env.sh ──copy──▶ cloud-env.local.sh (fill in IPs)
  │
  ▼
cloud-provision.sh (run on Client VM)
  ├── SSH to Proxy ──▶ cloud-setup.sh proxy
  │     ├── Install Go
  │     ├── Clone repo (gh)
  │     ├── Install EGo SDK + Azure DCAP
  │     ├── Build: enclave (SGX) + enclave-sim + coredns-test
  │     ├── Build: Config 3 worktree binaries
  │     └── Generate TLS certs (with SANs for both VMs)
  │
  ├── SSH to Target ──▶ cloud-setup.sh target
  │     ├── Install Go
  │     ├── Clone repo (gh)
  │     ├── Build: coredns-test
  │     ├── Download & filter domain lists
  │     ├── Build: Config 3 worktree binary
  │     └── Generate TLS certs
  │
  ├── Local (Client) ──▶ cloud-setup.sh client
  │     ├── Clone codoh-client repo
  │     ├── Build: odoh-client
  │     ├── Download domain lists
  │     └── Setup Config 3 client worktree + patches
  │
  └── cloud-check-ports.sh
        └── (if blocked) ──▶ cloud-open-ports.sh (az CLI)
  │
  ▼
cloud-run.sh (run on Client VM)
  ├── generate Corefiles (IP substitution)
  ├── distribute certs & Corefiles to VMs
  ├── for each config: start processes on VMs → benchmark → cleanup
  └── collect logs + print summary
  │
  ▼
plot.sh (optional, post-run)
```

---

## 4. How IPs, Certs, and Code Cloning Are Handled

### IP Configuration

- IPs are set **once** in `cloud-env.local.sh` (`PROXY_IP`, `TARGET_IP`)
- Every script sources `cloud-env.local.sh` to get these IPs
- `cloud-run.sh` substitutes `127.0.0.1` in Corefile templates with actual VM IPs:
  - `Corefile.target`: `enclave_url` → points to `PROXY_IP:8444` (attestation)
  - `Corefile.proxy`: `target` → points to `TARGET_IP:8443` (DNS resolution)
  - `Corefile.odoh-proxy`: `target` → points to `TARGET_IP:9443`
  - Upstream resolver: `127.0.0.1:5353` → `UPSTREAM_RESOLVER` (default: `1.1.1.1:53`)
- The client tool gets IPs via `--proxy` and `--target` CLI flags in `cloud-run.sh`

### TLS Certificates

- **Generated on each VM** during `cloud-setup.sh` using `openssl` (self-signed, ECDSA P-256)
- SANs include: `localhost`, `127.0.0.1`, the VM's own IP, and the other VM's IP
- **Proxy's cert is the authoritative one**: `cloud-run.sh` SCPs `localhost.pem` + `localhost-key.pem` from the proxy to both the target and client VMs
- The client uses `--customcert` flag to trust the self-signed cert
- Both target and proxy share the **same cert** (proxy's), which has SANs covering all IPs
- Cert files live at `$REMOTE_ROOT/localhost.pem` and `$REMOTE_ROOT/localhost-key.pem`
- For SGX (Config 5): certs are copied to `/tmp/codoh-bench-cert.pem` because the enclave's filesystem is sealed

### Code Cloning

- **Handled automatically** by `cloud-provision.sh`
- Uses GitHub CLI (`gh repo clone etclab/coredns`) — requires `gh auth login` on each VM beforehand
- Clones to `$REMOTE_ROOT` (default: `/home/azureuser/Projects/codoh/coredns`)
- Checks out `$GIT_BRANCH` (default: `codoh-design-v2`)
- If a partial clone exists, it's removed and re-cloned
- The `codoh-client` repo is cloned locally on the client VM (sibling directory)
- Each VM only gets the code it needs — proxy and target get `coredns`, client gets both `coredns` and `codoh-client`

---

## 5. What's Missing / Manual Steps

### Must Do Manually

| What | Why it's manual | How to do it |
|------|----------------|--------------|
| **Create Azure VMs** | No provisioning script (no Terraform/Bicep/ARM template) | Azure Portal or `az vm create`. Proxy must be DCsv3 (SGX). |
| **SSH key setup** | Scripts assume key auth already works | `ssh-copy-id azureuser@<IP>` or use Azure's SSH key provisioning |
| **`gh auth login`** on all 3 VMs | Repos are private; `gh` needs auth token | SSH into each VM, run `gh auth login` |
| **Install Azure CLI** on client VM | `cloud-open-ports.sh` needs `az` | `curl -sL https://aka.ms/InstallAzureCLI \| sudo bash` |
| **Install `nc` (netcat)** | `cloud-check-ports.sh` uses it | Usually pre-installed; if not: `sudo apt install netcat-openbsd` |

### Page-Load Benchmark Specifics (Your Use Case)

The existing scripts are designed for the **`odoh-client latency`** benchmark (raw DNS query latency). For your **page-load benchmark** with Playwright + dnscrypt-proxy, the following gaps exist:

| Gap | Details |
|-----|---------|
| **dnscrypt-proxy setup** | Not handled by any script. You need to install and configure dnscrypt-proxy on the client VM to forward DNS queries to the CODoH proxy. |
| **Playwright setup** | Not handled. The page-load benchmark client lives in a separate repo. |
| **Client VM benchmark script** | `cloud-run.sh` runs `odoh-client latency`, not a page-load test. You'll need to either modify `cloud-run.sh` or write a separate orchestrator for page-load. |
| **dnscrypt-proxy → CODoH proxy config** | dnscrypt-proxy needs to be configured to use `PROXY_IP:8080` as its upstream DoH/ODoH server. The exact config depends on how CODoH is exposed (DoH endpoint format). |

### What Proxy and Target Setup Looks Like (for your page-load benchmark)

The proxy and target setup is **already handled** by the existing scripts. You only need:

1. Run `cloud-provision.sh` from the client — it sets up proxy and target fully.
2. For running the actual benchmark, instead of `cloud-run.sh`, you'd:
   - SSH into target: start `coredns-test` with the appropriate Corefile
   - SSH into proxy: start the enclave + `coredns-test` with proxy Corefile  
   - On client: start `dnscrypt-proxy` → run your Playwright page-load script

The start-up commands for each config are defined in `cloud-run.sh` functions: `start_config_1()` through `start_config_5()`. You can extract the relevant SSH commands from there.

### Potential Issues

| Issue | Details |
|-------|---------|
| **TLS cert SANs** | If your client uses a hostname (not IP), the self-signed certs only cover IPs and `localhost`. You may need to regenerate certs with additional SANs. |
| **Upstream resolver** | Cloud mode defaults to `1.1.1.1:53` (Cloudflare). For page-load benchmarks you probably want this (realistic). For micro-benchmarks, local Unbound is better (isolates DNS variance). |
| **Config 3 worktree** | An older codepath pinned to commit `e81a315`. Has compatibility patches applied automatically. If you only care about the current CODoH design (Configs 4/5), you can skip Config 3. |
| **Port conflicts** | If any port (8080, 8443, 8444, etc.) is in use on a VM, processes will fail silently. `cloud-run.sh` kills existing processes before each config. |
| **SGX group membership** | After `cloud-setup.sh proxy` adds the user to `sgx_prv`, you need to logout/login or `newgrp sgx_prv` for it to take effect. |

---

## 6. Quick Reference Cheatsheet

### First-Time Setup (do once)

```bash
# 1. Create VMs in Azure (manual — Portal or az cli)
#    Proxy: Standard_DC4s_v3 (SGX), Ubuntu 22.04
#    Target: Standard_D4s_v5, Ubuntu 22.04
#    Client: Standard_D4s_v5, Ubuntu 22.04

# 2. SSH into each VM and install gh + authenticate
ssh azureuser@<PROXY_IP>
  sudo apt install gh -y && gh auth login
ssh azureuser@<TARGET_IP>
  sudo apt install gh -y && gh auth login

# 3. On client VM: configure environment
cd coredns/benchmark
cp cloud-env.sh cloud-env.local.sh
vim cloud-env.local.sh   # fill in PROXY_IP, TARGET_IP, SSH_KEY, NSG vars

# 4. Provision everything (from client VM)
./benchmark/cloud-provision.sh
```

### Running Benchmarks

```bash
# Quick validation
./benchmark/cloud-run.sh --quick

# Standard run (Configs 2-5, 10K queries each)  
./benchmark/cloud-run.sh --standard --run-id std-01

# Full with sweeps
./benchmark/cloud-run.sh --run-id full-01 --sweep-oram --sweep-cover

# Just cleanup remote processes
./benchmark/cloud-run.sh --cleanup
```

### Troubleshooting

```bash
# Check port reachability
./benchmark/cloud-check-ports.sh

# Open blocked ports
./benchmark/cloud-open-ports.sh

# Collect remote logs after a failed run
./benchmark/cloud-collect-logs.sh <run-id>

# SSH into proxy/target to check process status
ssh -i $SSH_KEY azureuser@$PROXY_IP "ps aux | grep -E 'coredns|enclave'"
ssh -i $SSH_KEY azureuser@$TARGET_IP "ps aux | grep coredns"

# Check if enclave IPC socket exists on proxy
ssh -i $SSH_KEY azureuser@$PROXY_IP "ls -la /tmp/codoh-enclave.sock"
```

### Files That Matter

```
benchmark/
├── cloud-env.local.sh          ← YOUR config (IPs, SSH keys, NSG names)
├── cloud-provision.sh          ← Step 2: one-shot setup for all VMs
├── cloud-setup.sh              ← Per-VM setup (called by provision)
├── cloud-run.sh                ← Step 3: run benchmarks from client
├── cloud-check-ports.sh        ← Debug: check port connectivity
├── cloud-open-ports.sh         ← Fix: open ports in Azure NSGs
├── cloud-collect-logs.sh       ← Debug: fetch logs from VMs
├── filter-resolvable.sh        ← Data: filter domains that resolve
├── prewarm-unbound.sh          ← Perf: warm resolver cache (local only)
├── plot.sh + plot_preprocess.py ← Post-run: generate plots
├── patch-config3-client.sh     ← Compat: patch older client code
├── setup.sh + run-all.sh       ← Single-machine equivalents (not for cloud)
├── configs/                    ← Per-config startup scripts (used by run-all.sh)
├── Corefile.*                  ← CoreDNS config templates  
├── unbound.conf                ← Unbound config (local resolver)
├── top-1m.csv / top-1k.csv    ← Domain lists (downloaded during setup)
└── results/                    ← Benchmark output (created at runtime)
```

---

## 7. Page-Load Benchmark VMs

The following VMs have been provisioned for the page-load benchmark:

| VM Name | Role | SKU | vCPUs | RAM | OS | Region |
|---------|------|-----|-------|-----|----|--------|
| **pl-client** | Client (Playwright + dnscrypt-proxy) | Standard D2alds v6 | 2 | 4 GiB | Ubuntu 24.04 | North Central US |
| **pl-target** | Target (coredns + codohtarget) | Standard D2s v3 | 2 | 8 GiB | Ubuntu 24.04 | Central US |
| **pl-proxy** | Proxy (enclave + codohproxy) | Standard DC4s v2 | 4 | 16 GiB | Ubuntu 24.04 | East US |

> **Note**: `pl-proxy` uses the **DC4s v2** series which supports SGX (required for the enclave). The client and target VMs don't need SGX.
