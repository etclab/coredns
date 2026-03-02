#!/bin/bash
# CODoH Cloud Page-Load Benchmark — Setup & Runner
#
# Manages the page-load benchmark client setup and orchestrates remote
# proxy/target VMs. This script handles:
#   1. Clone codoh-evals (Playwright page-load harness)
#   2. Clone dnscrypt-proxy (forwards system DNS → CODoH proxy)
#   3. Build dnscrypt-proxy + install Playwright
#   4. Start remote CoDOH processes (enclave, target, proxy) via SSH
#   5. Configure dnscrypt-proxy to point at PROXY_IP:8080
#   6. Set system DNS → dnscrypt-proxy
#   7. Run Playwright page-load benchmark
#   8. Clean up everything on exit
#
# Usage:
#   ./benchmark/cloud-page-load-bench.sh setup                    # install everything (run once)
#   ./benchmark/cloud-page-load-bench.sh run [--config 2|4|5] ...   # run page-load benchmark
#   ./benchmark/cloud-page-load-bench.sh cleanup                  # kill all processes, revert DNS
#
# Prerequisites:
#   1. Fill in benchmark/cloud-env.local.sh with PROXY_IP, TARGET_IP, SSH_KEY
#   2. Proxy + target VMs already provisioned via cloud-provision.sh
#   3. gh auth login done on this machine (repos are private)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PARENT_DIR="$(dirname "$ROOT_DIR")"

# Load cloud env
if [[ -f "$SCRIPT_DIR/cloud-env.local.sh" ]]; then
    source "$SCRIPT_DIR/cloud-env.local.sh"
else
    echo "ERROR: benchmark/cloud-env.local.sh not found."
    echo "  cp benchmark/cloud-env.sh benchmark/cloud-env.local.sh"
    echo "  # Fill in PROXY_IP and TARGET_IP"
    exit 1
fi

# Validate required vars
if [[ -z "${PROXY_IP:-}" || -z "${TARGET_IP:-}" ]]; then
    echo "ERROR: PROXY_IP and TARGET_IP must be set in cloud-env.local.sh"
    exit 1
fi

: "${SSH_USER:=azureuser}"
: "${SSH_KEY:=$HOME/.ssh/id_rsa}"
: "${REMOTE_ROOT:=/home/$SSH_USER/Projects/codoh/coredns}"
: "${GIT_BRANCH:=codoh-design-v2}"
: "${UPSTREAM_RESOLVER:=1.1.1.1:53}"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"
GO="/usr/local/go/bin/go"

# Repo locations on the client machine
EVALS_DIR="$PARENT_DIR/codoh-evals"
DNSCRYPT_DIR="$PARENT_DIR/dnscrypt-proxy"

# Port on the proxy VM that CODoH proxy listens on (DoH/ODoH endpoint)
PROXY_CODOH_PORT="${PROXY_CODOH_PORT:-8080}"

# Tool paths (venv-based, no activate/deactivate needed)
PYTHON="$EVALS_DIR/venv/bin/python"
PLAYWRIGHT="$EVALS_DIR/venv/bin/playwright"
DNSCRYPT_BIN="$DNSCRYPT_DIR/dnscrypt-proxy/dnscrypt-proxy"
CERT_PATH="$ROOT_DIR/localhost.pem"
CLOUD_CF="$REMOTE_ROOT/benchmark/cloud-corefiles"

#######################################
# Helpers
#######################################

die() { echo "ERROR: $*" >&2; exit 1; }

require_gh() {
    if ! command -v gh &>/dev/null; then
        die "GitHub CLI (gh) is required but not installed. Install it: sudo apt install gh"
    fi
    if ! gh auth status &>/dev/null 2>&1; then
        die "GitHub CLI is not authenticated. Run: gh auth login"
    fi
}

clone_or_update() {
    local gh_repo=$1 target_dir=$2 label=$3 branch=${4:-}
    if [[ -d "$target_dir/.git" ]]; then
        echo "  $label: exists — pulling latest..."
        if [[ -n "$branch" ]]; then
            git -C "$target_dir" checkout "$branch" 2>/dev/null || true
        fi
        git -C "$target_dir" pull --ff-only 2>/dev/null || true
    else
        if [[ -d "$target_dir" ]]; then
            echo "  Removing partial clone at $target_dir..."
            rm -rf "$target_dir"
        fi
        echo "  Cloning $label (gh repo clone $gh_repo)..."
        mkdir -p "$(dirname "$target_dir")"
        if [[ -n "$branch" ]]; then
            (cd "$(dirname "$target_dir")" && gh repo clone "$gh_repo" "$(basename "$target_dir")" -- --branch "$branch")
        else
            (cd "$(dirname "$target_dir")" && gh repo clone "$gh_repo" "$(basename "$target_dir")")
        fi
    fi
    echo "  $label: $target_dir (branch: ${branch:-default})"
}

# Shared functions (SSH helpers, remote process management, corefiles, configs)
source "$SCRIPT_DIR/cloud-common.sh"

#######################################
# Cert fetch
#######################################

fetch_proxy_cert() {
    local cert_dest="$ROOT_DIR/localhost.pem"
    local key_dest="$ROOT_DIR/localhost-key.pem"

    if [[ -f "$cert_dest" ]]; then
        echo "  Cert: $cert_dest (already exists — skipping)"
        return
    fi

    echo "  Fetching cert from $SSH_USER@$PROXY_IP:$REMOTE_ROOT/localhost.pem..."
    if scp $SSH_OPTS \
        "$SSH_USER@$PROXY_IP:$REMOTE_ROOT/localhost.pem" "$cert_dest" && \
       scp $SSH_OPTS \
        "$SSH_USER@$PROXY_IP:$REMOTE_ROOT/localhost-key.pem" "$key_dest"; then
        echo "  Cert: $cert_dest"
    else
        echo "  WARNING: Could not fetch cert from proxy VM."
        echo "  Copy manually: scp $SSH_USER@$PROXY_IP:$REMOTE_ROOT/localhost.pem $cert_dest"
    fi
}

#######################################
# SETUP
#######################################

cmd_setup() {
    echo "=== CODoH Page-Load Benchmark: Setup ==="
    echo "Proxy:    $PROXY_IP:$PROXY_CODOH_PORT"
    echo "Target:   $TARGET_IP"
    echo "coredns:  $ROOT_DIR"
    echo "evals:    $EVALS_DIR"
    echo "dnscrypt: $DNSCRYPT_DIR"
    echo ""

    #--- Step 1: require gh ---------------------------------------------------
    echo "[1/7] Checking GitHub CLI..."
    require_gh
    echo "  gh: OK"
    echo ""

    #--- Step 2: check coredns repo -------------------------------------------
    echo "[2/7] Checking coredns repo..."
    if [[ -f "$ROOT_DIR/go.mod" ]]; then
        echo "  coredns: $ROOT_DIR (already cloned)"
        local current_branch
        current_branch=$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)
        echo "  branch: $current_branch"
    else
        echo "  coredns not found at $ROOT_DIR — cloning..."
        mkdir -p "$PARENT_DIR"
        (cd "$PARENT_DIR" && gh repo clone etclab/coredns)
        git -C "$ROOT_DIR" checkout "$GIT_BRANCH"
    fi
    echo ""

    #--- Step 3: clone codoh-evals -------------------------------------------
    echo "[3/7] Cloning codoh-evals..."
    clone_or_update "etclab/codoh-evals" "$EVALS_DIR" "codoh-evals" "main"
    echo ""

    #--- Step 4: clone dnscrypt-proxy -----------------------------------------
    echo "[4/7] Cloning dnscrypt-proxy..."
    clone_or_update "etclab/dnscrypt-proxy" "$DNSCRYPT_DIR" "dnscrypt-proxy" "$GIT_BRANCH"
    echo ""

    #--- Step 5: build dnscrypt-proxy -----------------------------------------
    echo "[5/7] Building dnscrypt-proxy..."
    if [[ ! -x "$GO" ]]; then
        die "Go not found at $GO. Install it first."
    fi
    (cd "$DNSCRYPT_DIR/dnscrypt-proxy" && $GO build -mod vendor)
    echo "  dnscrypt-proxy build complete: $DNSCRYPT_BIN"
    echo ""

    #--- Step 6: install Playwright in venv -----------------------------------
    echo "[6/7] Installing Playwright in venv..."
    sudo apt-get install -y python3-venv
    python3 -m venv "$EVALS_DIR/venv"
    "$PYTHON" -m pip install playwright
    "$PLAYWRIGHT" install
    "$PLAYWRIGHT" install-deps
    echo "  Playwright venv ready: $EVALS_DIR/venv/"
    echo ""

    #--- Step 7: copy TLS cert from proxy VM ----------------------------------
    echo "[7/7] Fetching TLS certificate from proxy VM..."
    fetch_proxy_cert
    echo ""

    echo "=== Setup complete ==="
    echo ""
    echo "Next steps:"
    echo "  Run the benchmark:  $0 run [--config 4|5] [--sites FILE] [--runs N]"
}

#######################################
# RUN — full benchmark orchestration
#######################################

cmd_run() {
    # Parse run arguments
    local CONFIG=4
    # local SITES="$EVALS_DIR/sampled-100-of-2000-resolvable.csv"
    local SITES="$EVALS_DIR/sampled-500-of-2000-resolvable.csv"
    local RUNS=1
    local RUN_ID="pageload-$(date +%Y%m%d-%H%M%S)"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)  CONFIG="$2"; shift 2 ;;
            --sites)   SITES="$2"; shift 2 ;;
            --runs)    RUNS="$2"; shift 2 ;;
            --run-id)  RUN_ID="$2"; shift 2 ;;
            *)
                echo "Unknown run option: $1"
                echo "Usage: $0 run [--config 2|4|5] [--sites FILE] [--runs N] [--run-id ID]"
                exit 1
                ;;
        esac
    done

    # Validate config
    if [[ "$CONFIG" != "2" && "$CONFIG" != "4" && "$CONFIG" != "5" ]]; then
        die "Invalid --config value: $CONFIG (must be 2, 4, or 5)"
    fi

    # --- Step 1: Create run directory ---
    local RUN_DIR="$SCRIPT_DIR/results/$RUN_ID"
    mkdir -p "$RUN_DIR"

    # Determine strategy name for output files and benchmark-har.py
    local STRATEGY
    case "$CONFIG" in
        2) STRATEGY="odoh" ;;
        *) STRATEGY="codoh" ;;
    esac

    local RESULTS_CSV="$RUN_DIR/results_har_${STRATEGY}.csv"
    local BENCH_LOG="$RUN_DIR/benchmark-har-${STRATEGY}.log"

    # Tee all output to run log
    exec > >(tee -a "$RUN_DIR/run.log") 2>&1

    echo "=== CODoH Page-Load Benchmark: Run ==="
    local config_desc
    case "$CONFIG" in
        2) config_desc="ODoH" ;;
        4) config_desc="CODoH no-SGX" ;;
        5) config_desc="CODoH full SGX" ;;
    esac
    echo "Config:   $CONFIG ($config_desc)"
    echo "Sites:    $SITES"
    echo "Runs:     $RUNS"
    echo "Run ID:   $RUN_ID"
    echo "Results:  $RUN_DIR/"
    echo ""

    # --- Step 2: Save metadata ---
    cat > "$RUN_DIR/metadata.json" << METAEOF
{
    "run_id": "$RUN_ID",
    "config": $CONFIG,
    "proxy_ip": "$PROXY_IP",
    "target_ip": "$TARGET_IP",
    "sites": "$SITES",
    "runs": $RUNS,
    "upstream_resolver": "$UPSTREAM_RESOLVER",
    "timestamp": "$(date -Iseconds)",
    "client_hostname": "$(hostname)"
}
METAEOF

    # --- Step 3: Prompt for sudo ---
    echo "This script needs sudo to bind DNS to port 53 and set system DNS."
    # sudo -v

    # --- Step 4: Verify SSH ---
    echo ""
    echo "=== Verifying SSH connectivity ==="
    if ! ssh_proxy "echo ok" > /dev/null 2>&1; then
        die "Cannot SSH to proxy ($PROXY_IP)"
    fi
    echo "  Proxy SSH: OK"

    if ! ssh_target "echo ok" > /dev/null 2>&1; then
        die "Cannot SSH to target ($TARGET_IP)"
    fi
    echo "  Target SSH: OK"
    echo ""

    # --- EXIT trap ---
    cleanup_on_exit() {
        echo ""
        echo "=== Cleaning up ==="
        # Stop local dnscrypt-proxy
        sudo pkill -x dnscrypt-proxy 2>/dev/null || true
        sleep 1
        sudo pkill -9 -x dnscrypt-proxy 2>/dev/null || true
        # Revert DNS
        local iface
        iface=$(ip -o route show default | awk '{print $5; exit}')
        [[ -n "$iface" ]] && "$EVALS_DIR/unset-dns.sh" "$iface" 2>/dev/null || true
        # Stop remote processes
        remote_cleanup 2>/dev/null || true
        echo "=== Done ==="
    }
    trap cleanup_on_exit EXIT

    # --- Step 5: Start remote processes ---
    echo "=== Starting remote processes ==="
    local enclave_env="CODOH_USE_ORAM=true CODOH_CACHE_SIZE=${CODOH_CACHE_SIZE:-1024} CODOH_BATCH_SIZE=${CODOH_BATCH_SIZE:-10} CODOH_BATCH_COMMIT_PROB=${CODOH_BATCH_COMMIT_PROB:-0.1}"
    local target_env="CODOH_COVER_COUNT=${CODOH_COVER_COUNT:-3} CODOH_COVER_DOMAIN_FILE=$REMOTE_ROOT/benchmark/top-10k-resolvable.csv CODOH_COVER_POPULAR_CUTOFF=1000 CODOH_PROXY_CALLBACK_URL=https://$PROXY_IP:8080 CODOH_COVER_RESOLVER=$UPSTREAM_RESOLVER CODOH_COVER_TIMEOUT_MS=2000"

    COREFILE_DIR="$RUN_DIR/corefiles"
    mkdir -p "$COREFILE_DIR"

    remote_cleanup
    generate_corefiles
    distribute_files

    case "$CONFIG" in
        2) start_config_2 ;;
        4) start_config_4 "$enclave_env" "$target_env" ;;
        5) start_config_5 "$enclave_env" "$target_env" ;;
    esac
    echo ""

    # --- Step 6: Generate dnscrypt-proxy config ---
    echo "=== Generating dnscrypt-proxy config ==="

    # Config 2 (ODoH) uses a different template, ports, and stamp section names
    local DNSCRYPT_CONF DNSCRYPT_TEMPLATE
    local TARGET_PORT RELAY_PORT STAMP_TARGET_NAME STAMP_RELAY_NAME

    if [[ "$CONFIG" == "2" ]]; then
        # ODoH: template from master branch, ODoH ports
        DNSCRYPT_CONF="$RUN_DIR/dnscrypt-proxy-odoh.toml"
        TARGET_PORT=9443
        RELAY_PORT=9080
        STAMP_TARGET_NAME="local-odoh"
        STAMP_RELAY_NAME="local-odoh-relay"

        # The ODoH template lives on the master branch while setup clones
        # codoh-design-v2. Extract it via git-show so we don't need to switch branches.
        local ODOH_TEMPLATE_GIT="dnscrypt-proxy/dnscrypt-proxy-local-odoh.toml"
        if ! git -C "$DNSCRYPT_DIR" show "origin/master:$ODOH_TEMPLATE_GIT" > "$DNSCRYPT_CONF" 2>/dev/null; then
            die "Could not extract ODoH template from origin/master in $DNSCRYPT_DIR.
  Run: git -C $DNSCRYPT_DIR fetch origin master"
        fi
    else
        # CODoH: template from codoh-design-v2 branch, CODoH ports
        DNSCRYPT_CONF="$RUN_DIR/dnscrypt-proxy-codoh.toml"
        local DNSCRYPT_TEMPLATE="$DNSCRYPT_DIR/dnscrypt-proxy/dnscrypt-proxy-codoh.toml"
        TARGET_PORT=8443
        RELAY_PORT=8080
        STAMP_TARGET_NAME="codoh-target"
        STAMP_RELAY_NAME="codoh-relay"

        if [[ ! -f "$DNSCRYPT_TEMPLATE" ]]; then
            die "dnscrypt-proxy config template not found: $DNSCRYPT_TEMPLATE"
        fi
        cp "$DNSCRYPT_TEMPLATE" "$DNSCRYPT_CONF"
    fi

    # 6a. CODoH-specific: replace proxy_host with cloud IP
    if [[ "$CONFIG" != "2" ]]; then
        sed -i "s|proxy_host = '127\.0\.0\.1:8080'|proxy_host = '${PROXY_IP}:${RELAY_PORT}'|g" "$DNSCRYPT_CONF"
    fi

    # 6b. Generate DNS stamps encoding cloud IPs
    local TARGET_STAMP
    TARGET_STAMP=$("$PYTHON" -c "
import base64
def lp(s):
    b = s.encode()
    return bytes([len(b)]) + b
buf = bytes([0x05]) + b'\x00' * 8 + lp('${TARGET_IP}:${TARGET_PORT}') + lp('/dns-query')
print('sdns://' + base64.urlsafe_b64encode(buf).rstrip(b'=').decode())
")

    local RELAY_STAMP
    RELAY_STAMP=$("$PYTHON" -c "
import base64
def lp(s):
    b = s.encode()
    return bytes([len(b)]) + b
buf = bytes([0x85]) + b'\x00' * 8 + lp('${PROXY_IP}:${RELAY_PORT}') + b'\x00' + lp('${PROXY_IP}:${RELAY_PORT}') + lp('/proxy')
print('sdns://' + base64.urlsafe_b64encode(buf).rstrip(b'=').decode())
")

    echo "  Target stamp: $TARGET_STAMP"
    echo "  Relay stamp:  $RELAY_STAMP"

    # Replace static stamps in config (section names differ per config)
    # Allow optional leading whitespace — ODoH template indents sections under [static]
    sed -i "/^[[:space:]]*\[static\.${STAMP_TARGET_NAME}\]/,/^$/{ s|^\([[:space:]]*\)stamp = '.*'|\1stamp = '${TARGET_STAMP}'| }" "$DNSCRYPT_CONF"
    sed -i "/^[[:space:]]*\[static\.${STAMP_RELAY_NAME}\]/,/^$/{ s|^\([[:space:]]*\)stamp = '.*'|\1stamp = '${RELAY_STAMP}'| }" "$DNSCRYPT_CONF"

    # 6c. Configure TLS cert trust: set root_ca for self-signed proxy cert
    if grep -q '^\[doh_client_x509_auth\]' "$DNSCRYPT_CONF"; then
        # CODoH template: append after existing section header
        sed -i "/^\[doh_client_x509_auth\]/a creds = [{ server_name = '*', root_ca = '${CERT_PATH}' }]" "$DNSCRYPT_CONF"
    else
        # ODoH template: add the section at the end
        printf '\n[doh_client_x509_auth]\ncreds = [{ server_name = '"'"'*'"'"', root_ca = '"'"'%s'"'"' }]\n' "$CERT_PATH" >> "$DNSCRYPT_CONF"
    fi

    echo "  Config: $DNSCRYPT_CONF"
    echo ""

    # --- Step 7: Kill existing local dnscrypt-proxy ---
    echo "=== Stopping existing dnscrypt-proxy ==="
    if pgrep -x dnscrypt-proxy >/dev/null 2>&1; then
        echo "  Stopping existing dnscrypt-proxy..."
        sudo pkill -x dnscrypt-proxy || true
        sleep 2
        if pgrep -x dnscrypt-proxy >/dev/null 2>&1; then
            sudo pkill -9 -x dnscrypt-proxy || true
        fi
    else
        echo "  No existing dnscrypt-proxy found."
    fi
    echo ""

    # --- Step 8: Start dnscrypt-proxy ---
    echo "=== Starting dnscrypt-proxy ==="
    sudo "$DNSCRYPT_BIN" -config "$DNSCRYPT_CONF" &
    echo "  dnscrypt-proxy started (PID $!)"
    echo ""

    # --- Step 9: Wait for readiness ---
    echo "=== Waiting for dnscrypt-proxy readiness ==="
    for i in $(seq 1 30); do
        if dig google.com +short +timeout=2 >/dev/null 2>&1; then
            echo "  dnscrypt-proxy is ready (after ${i}s)."
            break
        fi
        if [[ $i -eq 30 ]]; then
            echo "  WARNING: dnscrypt-proxy not responding after 30s, proceeding anyway..."
        fi
        sleep 1
    done
    echo ""

    # --- Step 10: Detect network interface + set DNS ---
    echo "=== Setting system DNS ==="
    local INTERFACE
    INTERFACE=$(ip -o route show default | awk '{print $5; exit}')
    echo "  Network interface: $INTERFACE"
    "$EVALS_DIR/set-dns.sh" "$INTERFACE"
    echo ""

    # --- Step 11: Run benchmark ---
    echo "=== Running page-load benchmark ==="
    echo "  Sites: $SITES"
    echo "  Runs:  $RUNS"
    echo ""

    "$PYTHON" "$EVALS_DIR/benchmark-har.py" "$STRATEGY" \
        --randomize --runs="$RUNS" \
        --sites="$SITES" \
        --output="$RESULTS_CSV" \
        --log="$BENCH_LOG"

    echo ""

    # --- Step 12: Print results ---
    echo "=== Benchmark Complete ==="
    echo "Results directory: $RUN_DIR/"
    echo "  CSV:      $RESULTS_CSV"
    echo "  Log:      $BENCH_LOG"
    echo "  Run log:  $RUN_DIR/run.log"
    echo "  Metadata: $RUN_DIR/metadata.json"
    echo "  Config:   $DNSCRYPT_CONF"
}

#######################################
# CLEANUP
#######################################

cmd_cleanup() {
    echo "=== Cleanup: stopping all page-load benchmark processes ==="

    # 1. Kill local dnscrypt-proxy
    echo "  Stopping local dnscrypt-proxy..."
    sudo pkill -x dnscrypt-proxy 2>/dev/null || true
    sleep 1
    sudo pkill -9 -x dnscrypt-proxy 2>/dev/null || true

    # 2. Detect interface
    local INTERFACE
    INTERFACE=$(ip -o route show default | awk '{print $5; exit}')

    # 3. Revert DNS
    if [[ -n "$INTERFACE" ]]; then
        echo "  Reverting DNS on interface $INTERFACE..."
        "$EVALS_DIR/unset-dns.sh" "$INTERFACE" 2>/dev/null || true
    fi

    # 4. Kill remote processes
    echo "  Stopping remote processes..."
    remote_cleanup 2>/dev/null || true

    echo "  Done."
}

#######################################
# Dispatch
#######################################

CMD="${1:-}"
shift || true

case "$CMD" in
    setup)   cmd_setup ;;
    run)     cmd_run "$@" ;;
    cleanup) cmd_cleanup ;;
    *)
        echo "Usage: $0 <setup|run|cleanup> [options]"
        echo ""
        echo "Commands:"
        echo "  setup    Clone repos, build dnscrypt-proxy, install Playwright (run once)"
        echo "  run      Run the page-load benchmark"
        echo "  cleanup  Kill all processes, revert DNS"
        echo ""
        echo "Run options:"
        echo "  --config <2|4|5>  Config 2=ODoH, 4=CODoH no-SGX (default), 5=CODoH full SGX"
        echo "  --sites <file>    CSV file of sites to benchmark"
        echo "  --runs <N>        Number of benchmark runs (default: 1)"
        echo "  --run-id <id>     Custom run identifier"
        exit 1
        ;;
esac
