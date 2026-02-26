#!/bin/bash
# CODoH Cloud Benchmark — Per-VM Role Provisioner
#
# Usage: ./benchmark/cloud-setup.sh <proxy|target|client> [--resolver cloudflare]
#
# Run this ON the VM you're provisioning. It installs dependencies and builds
# the correct binaries for that VM's role.
#
# Roles:
#   proxy  — SGX enclave + codohproxy (Azure DCsv3)
#   target — codohtarget + upstream resolver
#   client — odoh-client benchmark tool

set -e

ROLE="${1:-}"
if [[ -z "$ROLE" || ! "$ROLE" =~ ^(proxy|target|client)$ ]]; then
    echo "Usage: $0 <proxy|target|client> [--resolver cloudflare]"
    echo ""
    echo "Roles:"
    echo "  proxy   Build SGX enclave + proxy binaries (run on DCsv3 VM)"
    echo "  target  Build target binary + download domain lists"
    echo "  client  Build odoh-client benchmark tool"
    exit 1
fi
shift

# Parse extra flags
RESOLVER_MODE="cloudflare"
while [[ $# -gt 0 ]]; do
    case $1 in
        --resolver) RESOLVER_MODE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CLIENT_DIR="$(dirname "$ROOT_DIR")/codoh-client"

# Source cloud env if present
if [[ -f "$SCRIPT_DIR/cloud-env.local.sh" ]]; then
    source "$SCRIPT_DIR/cloud-env.local.sh"
fi

echo "=== CODoH Cloud Setup: $ROLE ==="
echo ""

#######################################
# Common: Check/Install Go
#######################################
install_go() {
    local required="1.25.1"
    if command -v go &>/dev/null; then
        local current
        current=$(go version | grep -oP 'go(\d+\.\d+(\.\d+)?)' | sed 's/go//')
        echo "  Go: $current (installed)"
        return 0
    fi

    echo "  Installing Go $required..."
    local archive="go${required}.linux-amd64.tar.gz"
    curl -sLO "https://go.dev/dl/$archive"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$archive"
    rm -f "$archive"

    # Add to PATH if not already there
    if ! grep -q '/usr/local/go/bin' ~/.profile 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.profile
    fi
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo "  Go: $(go version)"
}

#######################################
# Common: Ensure repo is checked out
#######################################
check_repo() {
    if [[ ! -f "$ROOT_DIR/go.mod" ]]; then
        echo "ERROR: Repository not found at $ROOT_DIR"
        echo "Clone the repo first:"
        echo "  mkdir -p $(dirname "$ROOT_DIR") && cd $(dirname "$ROOT_DIR")"
        echo "  git clone <repo-url> coredns"
        exit 1
    fi

    local branch="${GIT_BRANCH:-codoh-design-v2}"
    local current_branch
    current_branch=$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)
    if [[ "$current_branch" != "$branch" ]]; then
        echo "  Switching to branch $branch..."
        git -C "$ROOT_DIR" checkout "$branch"
        git -C "$ROOT_DIR" pull --ff-only 2>/dev/null || true
    fi
    echo "  Repo: $ROOT_DIR (branch: $branch)"
}

echo "[1/N] Checking Go installation..."
install_go

echo "[2/N] Checking repository..."
check_repo

#######################################
# PROXY role
#######################################
setup_proxy() {
    local step=3

    # Check SGX
    echo "[$step/N] Checking SGX hardware..."
    if [[ -e /dev/sgx_enclave ]]; then
        echo "  SGX: available"
        SGX_AVAILABLE=true
    else
        echo "  WARNING: /dev/sgx_enclave not found — will build simulation mode only"
        SGX_AVAILABLE=false
    fi
    ((step++))

    # Install EGo if SGX available and ego missing or broken (snap version lacks OE SDK)
    if $SGX_AVAILABLE && { ! command -v ego &>/dev/null || [[ "$(which ego 2>/dev/null)" == /snap/* ]]; }; then
        echo "[$step/N] Installing EGo SDK..."

        # Remove snap ego if present (lacks OE SDK, CGo symbols won't link)
        if [[ "$(which ego 2>/dev/null)" == /snap/* ]]; then
            echo "  Removing broken snap ego-dev..."
            sudo snap remove ego-dev 2>/dev/null || true
        fi

        # Add Intel SGX repo (EGo .deb depends on SGX runtime packages)
        sudo mkdir -p /etc/apt/keyrings
        wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
            | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc >/dev/null
        echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" \
            | sudo tee /etc/apt/sources.list.d/intel-sgx.list >/dev/null
        sudo apt-get update -qq

        # Install EGo .deb + build deps (per official README)
        local ego_version="1.8.1"
        local ego_deb="ego_${ego_version}_amd64_ubuntu-$(lsb_release -rs).deb"
        wget -q "https://github.com/edgelesssys/ego/releases/download/v${ego_version}/${ego_deb}" -O /tmp/ego.deb
        sudo apt-get install -y /tmp/ego.deb build-essential libssl-dev
        rm -f /tmp/ego.deb

        echo "  EGo: $(ego version 2>/dev/null || echo 'installed')"
    elif $SGX_AVAILABLE; then
        echo "[$step/N] EGo SDK: already installed"
    fi
    ((step++))

    # Install Azure DCAP client (SGX quote provider) + add user to sgx_prv group
    if $SGX_AVAILABLE; then
        if ! dpkg -s az-dcap-client &>/dev/null; then
            echo "[$step/N] Installing Azure DCAP client..."
            # Add Microsoft repo key if not present
            if [[ ! -f /usr/share/keyrings/msft.gpg ]]; then
                wget -qO- https://packages.microsoft.com/keys/microsoft.asc \
                    | sudo gpg --dearmor -o /usr/share/keyrings/msft.gpg
            fi
            echo "deb [signed-by=/usr/share/keyrings/msft.gpg arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" \
                | sudo tee /etc/apt/sources.list.d/msprod.list >/dev/null
            sudo apt-get update -qq
            sudo apt-get install -y az-dcap-client
        else
            echo "[$step/N] Azure DCAP client: already installed"
        fi

        # Ensure user is in sgx_prv group (needed for quote generation)
        if ! id -nG | grep -qw sgx_prv; then
            echo "  Adding $USER to sgx_prv group..."
            sudo usermod -aG sgx_prv "$USER"
            echo "  NOTE: Group change requires logout/login or 'newgrp sgx_prv' to take effect"
        fi
    fi
    ((step++))

    # Build SGX enclave
    if $SGX_AVAILABLE && command -v ego-go &>/dev/null; then
        echo "[$step/N] Building SGX enclave..."
        if ! (cd "$ROOT_DIR/enclave" && ego-go build -tags ego -o enclave ./cmd); then
            echo "FATAL: SGX enclave build failed"
            exit 1
        fi
        if ! (cd "$ROOT_DIR/enclave" && ego sign enclave.json); then
            echo "FATAL: ego sign failed"
            exit 1
        fi
        echo "  Enclave SGX: $ROOT_DIR/enclave/enclave"
    fi
    ((step++))

    # Build enclave-sim (always, as fallback)
    echo "[$step/N] Building enclave-sim..."
    (cd "$ROOT_DIR" && go build -o enclave-sim ./enclave/cmd)
    echo "  Enclave sim: $ROOT_DIR/enclave-sim"
    ((step++))

    # Build coredns-test (server binary for proxy role)
    echo "[$step/N] Building coredns-test..."
    (cd "$ROOT_DIR" && go build -o coredns-test .)
    echo "  Server: $ROOT_DIR/coredns-test"
    ((step++))

    # Config 3 worktree
    echo "[$step/N] Setting up Config 3 worktree..."
    local worktree_dir="$SCRIPT_DIR/worktrees/config3-proxy"
    if [[ ! -d "$worktree_dir" ]]; then
        mkdir -p "$SCRIPT_DIR/worktrees"
        git -C "$ROOT_DIR" worktree add "$worktree_dir" e81a315ec3a91dee1bad2cc2bbf139ebee145ab8 2>&1 | tail -3

        # Apply compatibility patches (same as setup.sh)
        if grep -q 'go 1.25.5' "$worktree_dir/go.mod"; then
            sed -i 's/^go 1.25.5/go 1.25.1/' "$worktree_dir/go.mod"
            sed -i 's|pathoram-go v0.1.[01]|pathoram-go v0.1.2|' "$worktree_dir/go.mod"
            (cd "$worktree_dir" && GOFLAGS=-mod=mod go mod tidy 2>&1 | tail -3)
        fi
        if grep -q 'codoh-enclave-v1' "$worktree_dir/enclave/crypto.go"; then
            sed -i 's/codoh-enclave-v1/codoh transport key/' "$worktree_dir/enclave/crypto.go"
            sed -i 's/X-ODoH-Blob/X-CoDOH-Query/g' "$worktree_dir/enclave/cmd/proxy_mode.go"
        fi
        if grep -q 'codoh-enclave-v1' "$worktree_dir/plugin/codohtarget/enclave_encrypt.go" 2>/dev/null; then
            sed -i 's/codoh-enclave-v1/codoh transport key/' "$worktree_dir/plugin/codohtarget/enclave_encrypt.go"
        fi
    fi

    # Build Config 3 binaries
    (cd "$worktree_dir" && go build -o coredns-test .)
    (cd "$worktree_dir" && go build -o enclave-sim ./enclave/cmd)
    if $SGX_AVAILABLE && command -v ego-go &>/dev/null; then
        if ! (cd "$worktree_dir/enclave" && ego-go build -tags ego -o enclave ./cmd && ego sign enclave.json); then
            echo "FATAL: Config 3 SGX enclave build failed"
            exit 1
        fi
    fi
    echo "  Config 3 worktree: $worktree_dir"
    ((step++))

    # Generate TLS certs with remote SANs
    echo "[$step/N] Generating TLS certificates..."
    local own_ip
    own_ip=$(hostname -I | awk '{print $1}')
    local san="DNS:localhost,IP:127.0.0.1,IP:${own_ip}"
    [[ -n "${TARGET_IP:-}" ]] && san="${san},IP:${TARGET_IP}"

    # Always regenerate in cloud mode (SANs may differ from previous run)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$ROOT_DIR/localhost-key.pem" -out "$ROOT_DIR/localhost.pem" \
        -days 365 -nodes -subj "/CN=localhost" \
        -addext "subjectAltName=${san}" 2>/dev/null
    echo "  Cert SANs: $san"
    echo "  Cert: $ROOT_DIR/localhost.pem"
}

#######################################
# TARGET role
#######################################
setup_target() {
    local step=3

    # Build coredns-test
    echo "[$step/N] Building coredns-test..."
    (cd "$ROOT_DIR" && go build -o coredns-test .)
    echo "  Server: $ROOT_DIR/coredns-test"
    ((step++))

    # Download domain lists
    echo "[$step/N] Downloading domain lists..."
    if [[ ! -f "$SCRIPT_DIR/top-1m.csv" ]]; then
        curl -sL "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" \
            -o /tmp/top-1m.csv.zip
        unzip -o /tmp/top-1m.csv.zip -d "$SCRIPT_DIR" > /dev/null
        rm -f /tmp/top-1m.csv.zip
        echo "  Downloaded: top-1m.csv"
    else
        echo "  top-1m.csv: exists"
    fi

    if [[ ! -f "$SCRIPT_DIR/top-1k.csv" ]]; then
        head -1000 "$SCRIPT_DIR/top-1m.csv" > "$SCRIPT_DIR/top-1k.csv"
    fi
    ((step++))

    # Filter resolvable domains
    echo "[$step/N] Filtering resolvable domains..."
    local resolver_addr
    case "$RESOLVER_MODE" in
        cloudflare) resolver_addr="1.1.1.1" ; resolver_port="53" ;;
        google)     resolver_addr="8.8.8.8" ; resolver_port="53" ;;
        unbound)    resolver_addr="127.0.0.1" ; resolver_port="5353" ;;
        *)          resolver_addr="${RESOLVER_MODE%%:*}" ; resolver_port="${RESOLVER_MODE##*:}" ;;
    esac

    if [[ ! -f "$SCRIPT_DIR/top-1k-resolvable.csv" ]]; then
        "$SCRIPT_DIR/filter-resolvable.sh" --count 1000 --resolver "$resolver_addr:$resolver_port"
    else
        echo "  top-1k-resolvable.csv: exists ($(wc -l < "$SCRIPT_DIR/top-1k-resolvable.csv") domains)"
    fi

    if [[ ! -f "$SCRIPT_DIR/top-10k-resolvable.csv" ]]; then
        "$SCRIPT_DIR/filter-resolvable.sh" --count 10000 --resolver "$resolver_addr:$resolver_port"
    else
        echo "  top-10k-resolvable.csv: exists ($(wc -l < "$SCRIPT_DIR/top-10k-resolvable.csv") domains)"
    fi
    ((step++))

    # Config 3 worktree (cloud-run.sh uses $wt/coredns-test on target VM)
    echo "[$step/N] Setting up Config 3 worktree..."
    local worktree_dir="$SCRIPT_DIR/worktrees/config3-proxy"
    if [[ ! -d "$worktree_dir" ]]; then
        mkdir -p "$SCRIPT_DIR/worktrees"
        git -C "$ROOT_DIR" worktree add "$worktree_dir" e81a315ec3a91dee1bad2cc2bbf139ebee145ab8 2>&1 | tail -3

        # Apply compatibility patches (same as proxy role)
        if grep -q 'go 1.25.5' "$worktree_dir/go.mod"; then
            sed -i 's/^go 1.25.5/go 1.25.1/' "$worktree_dir/go.mod"
            sed -i 's|pathoram-go v0.1.[01]|pathoram-go v0.1.2|' "$worktree_dir/go.mod"
            (cd "$worktree_dir" && GOFLAGS=-mod=mod go mod tidy 2>&1 | tail -3)
        fi
        if grep -q 'codoh-enclave-v1' "$worktree_dir/enclave/crypto.go"; then
            sed -i 's/codoh-enclave-v1/codoh transport key/' "$worktree_dir/enclave/crypto.go"
            sed -i 's/X-ODoH-Blob/X-CoDOH-Query/g' "$worktree_dir/enclave/cmd/proxy_mode.go"
        fi
        if grep -q 'codoh-enclave-v1' "$worktree_dir/plugin/codohtarget/enclave_encrypt.go" 2>/dev/null; then
            sed -i 's/codoh-enclave-v1/codoh transport key/' "$worktree_dir/plugin/codohtarget/enclave_encrypt.go"
        fi
    fi

    # Build only coredns-test (target doesn't need enclave binaries)
    (cd "$worktree_dir" && go build -o coredns-test .)
    echo "  Config 3 worktree: $worktree_dir"
    ((step++))

    # Generate TLS certs
    echo "[$step/N] Generating TLS certificates..."
    local own_ip
    own_ip=$(hostname -I | awk '{print $1}')
    local san="DNS:localhost,IP:127.0.0.1,IP:${own_ip}"
    [[ -n "${PROXY_IP:-}" ]] && san="${san},IP:${PROXY_IP}"

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$ROOT_DIR/localhost-key.pem" -out "$ROOT_DIR/localhost.pem" \
        -days 365 -nodes -subj "/CN=localhost" \
        -addext "subjectAltName=${san}" 2>/dev/null
    echo "  Cert SANs: $san"
    ((step++))

    # Optionally install Unbound
    if [[ "$RESOLVER_MODE" == "unbound" ]]; then
        echo "[$step/N] Checking Unbound..."
        if ! dig +short @127.0.0.1 -p 5353 google.com > /dev/null 2>&1; then
            echo "  Unbound not running. Install with:"
            echo "    sudo apt install -y unbound"
            echo "    sudo cp $SCRIPT_DIR/unbound.conf /etc/unbound/unbound.conf.d/benchmark.conf"
            echo "    sudo systemctl restart unbound"
        else
            echo "  Unbound: running on 127.0.0.1:5353"
        fi
    else
        echo "[$step/N] Using upstream resolver: $RESOLVER_MODE (skipping Unbound)"
    fi
}

#######################################
# CLIENT role
#######################################
setup_client() {
    local step=3

    # Build odoh-client
    echo "[$step/N] Building odoh-client..."
    if [[ ! -d "$CLIENT_DIR" ]]; then
        echo "ERROR: Client repo not found at $CLIENT_DIR"
        echo "Clone it: cd $(dirname "$ROOT_DIR") && git clone <repo-url> codoh-client"
        exit 1
    fi
    (cd "$CLIENT_DIR" && go build -o odoh-client ./cmd)
    echo "  Client: $CLIENT_DIR/odoh-client"
    ((step++))

    # Download domain lists (client needs them for workload generation)
    echo "[$step/N] Downloading domain lists..."
    if [[ ! -f "$SCRIPT_DIR/top-1m.csv" ]]; then
        curl -sL "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" \
            -o /tmp/top-1m.csv.zip
        unzip -o /tmp/top-1m.csv.zip -d "$SCRIPT_DIR" > /dev/null
        rm -f /tmp/top-1m.csv.zip
    fi
    [[ ! -f "$SCRIPT_DIR/top-1k.csv" ]] && head -1000 "$SCRIPT_DIR/top-1m.csv" > "$SCRIPT_DIR/top-1k.csv"
    echo "  Domain lists: ready"
    ((step++))

    # Config 3 client worktree (matching pre-padding codoh-client)
    echo "[$step/N] Setting up Config 3 client worktree..."
    local client_wt="$CLIENT_DIR/worktrees/config3"
    if [[ ! -d "$client_wt" ]]; then
        mkdir -p "$CLIENT_DIR/worktrees"
        git -C "$CLIENT_DIR" worktree add "$client_wt" 010e7fe9bae41ec2b0405d3fd78d109afd9f18e6 2>&1 | tail -3

        # Patch HPKE info string to match server worktree
        if grep -q 'codoh-enclave-v2' "$client_wt/commands/blob.go"; then
            sed -i 's/codoh-enclave-v2/codoh transport key/' "$client_wt/commands/blob.go"
        fi
        # Patch response content-type (server returns codoh-cached, not codoh-response)
        if grep -q 'codoh-response' "$client_wt/commands/request.go"; then
            "$SCRIPT_DIR/patch-config3-client.sh" "$client_wt/commands/request.go"
        fi
    fi
    (cd "$client_wt" && go build -o odoh-client ./cmd)
    echo "  Config 3 client worktree: $client_wt"
    ((step++))

    # Copy certs from proxy VM (user must do this manually or via cloud-run.sh)
    echo "[$step/N] TLS certificates..."
    if [[ -f "$ROOT_DIR/localhost.pem" ]]; then
        echo "  Cert: $ROOT_DIR/localhost.pem (exists)"
    else
        echo "  NOTE: Copy localhost.pem from the proxy VM:"
        echo "    scp ${SSH_USER:-azureuser}@\$PROXY_IP:${REMOTE_ROOT:-$ROOT_DIR}/localhost.pem $ROOT_DIR/"
    fi
}

#######################################
# Dispatch
#######################################
case "$ROLE" in
    proxy)  setup_proxy ;;
    target) setup_target ;;
    client) setup_client ;;
esac

echo ""
echo "=== $ROLE setup complete ==="
