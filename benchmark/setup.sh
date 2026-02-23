#!/bin/bash
# CODoH Benchmark Setup Script
# One-command environment preparation for artifact evaluation.
# Builds all binaries, generates certs, downloads data, configures Unbound.
#
# Usage: ./benchmark/setup.sh [--clean]
#
# Options:
#   --clean    Remove all build artifacts and worktrees before rebuilding
#
# Requirements: SGX hardware (/dev/sgx_enclave), ego SDK, Go 1.25+, mkcert or openssl

set -e

# Handle --clean
if [[ "${1:-}" == "--clean" ]]; then
    echo "=== Cleaning build artifacts ==="
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    ROOT_DIR="$(dirname "$SCRIPT_DIR")"
    CLIENT_DIR="$(dirname "$ROOT_DIR")/codoh-client"

    # Kill running processes
    pkill -9 -f coredns-test 2>/dev/null || true
    pkill -9 -f enclave-sim 2>/dev/null || true
    pkill -9 -f 'ego-host.*enclave' 2>/dev/null || true
    rm -f /tmp/codoh-enclave.sock 2>/dev/null || true

    # Remove binaries
    rm -f "$ROOT_DIR/coredns-test" "$ROOT_DIR/enclave-sim"
    rm -f "$ROOT_DIR/enclave/enclave"
    rm -f "$CLIENT_DIR/odoh-client" 2>/dev/null

    # Remove Config 3 worktree
    if [[ -d "$SCRIPT_DIR/worktrees/config3-proxy" ]]; then
        git -C "$ROOT_DIR" worktree remove "$SCRIPT_DIR/worktrees/config3-proxy" --force 2>/dev/null || true
        rm -rf "$SCRIPT_DIR/worktrees"
    fi

    echo "  Removed: coredns-test, enclave-sim, enclave/enclave, odoh-client"
    echo "  Removed: Config 3 worktree"
    echo "  Clean complete. Run ./benchmark/setup.sh to rebuild."
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CLIENT_DIR="$(dirname "$ROOT_DIR")/codoh-client"

echo "=== CODoH Benchmark Setup ==="
echo ""

#######################################
# 1. Check SGX
#######################################
echo "[1/8] Checking SGX hardware..."
if [[ ! -e /dev/sgx_enclave ]]; then
    echo "FATAL: SGX hardware required for artifact evaluation."
    echo "/dev/sgx_enclave not found. This machine does not have SGX support."
    exit 1
fi
if [[ ! -e /dev/sgx_provision ]]; then
    echo "WARNING: /dev/sgx_provision not found. Attestation may fail."
fi
echo "  SGX: OK"

#######################################
# 2. Check ego SDK
#######################################
echo "[2/8] Checking ego SDK..."
if ! command -v ego &> /dev/null; then
    echo "FATAL: ego SDK not found. Install from https://docs.edgeless.systems/ego"
    exit 1
fi
if ! command -v ego-go &> /dev/null; then
    echo "FATAL: ego-go not found. Install ego SDK."
    exit 1
fi
echo "  ego: $(ego version 2>/dev/null || echo 'installed')"

#######################################
# 3. Build enclave binary (SGX)
#######################################
echo "[3/8] Building SGX enclave..."
cd "$ROOT_DIR/enclave"
ego-go build -tags ego -o enclave ./cmd 2>&1 | tail -5
ego sign enclave.json 2>&1 | tail -5
cd "$ROOT_DIR"
echo "  Enclave: $ROOT_DIR/enclave/enclave (SGX-signed)"

#######################################
# 4. Build enclave-sim (for quick validation)
#######################################
echo "[4/8] Building enclave-sim..."
go build -o enclave-sim ./enclave/cmd 2>&1 | tail -5
echo "  Enclave-sim: $ROOT_DIR/enclave-sim"

#######################################
# 5. Build server binary
#######################################
echo "[5/8] Building coredns-test..."
go build -o coredns-test . 2>&1 | tail -5
echo "  Server: $ROOT_DIR/coredns-test"

#######################################
# 6. Build client binary
#######################################
echo "[6/8] Building odoh-client..."
if [[ ! -d "$CLIENT_DIR" ]]; then
    echo "FATAL: Client repo not found at $CLIENT_DIR"
    exit 1
fi
(cd "$CLIENT_DIR" && go build -o odoh-client ./cmd 2>&1 | tail -5)
echo "  Client: $CLIENT_DIR/odoh-client"

#######################################
# 7. Generate TLS certs
#######################################
echo "[7/8] Checking TLS certificates..."
if [[ -f "$ROOT_DIR/localhost.pem" && -f "$ROOT_DIR/localhost-key.pem" ]]; then
    echo "  Certs: already exist"
else
    if command -v mkcert &> /dev/null; then
        (cd "$ROOT_DIR" && mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1)
    else
        echo "  Generating self-signed cert with openssl..."
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$ROOT_DIR/localhost-key.pem" -out "$ROOT_DIR/localhost.pem" \
            -days 365 -nodes -subj "/CN=localhost" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    fi
    echo "  Certs: generated"
fi

#######################################
# 8. Download domain lists
#######################################
echo "[8/8] Checking domain lists..."
if [[ ! -f "$SCRIPT_DIR/top-1m.csv" ]]; then
    echo "  Downloading Cisco Umbrella top-1M..."
    curl -sL "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" \
        -o /tmp/top-1m.csv.zip
    unzip -o /tmp/top-1m.csv.zip -d "$SCRIPT_DIR" > /dev/null
    rm -f /tmp/top-1m.csv.zip
    echo "  Downloaded: $SCRIPT_DIR/top-1m.csv"
else
    echo "  top-1m.csv: exists ($(wc -l < "$SCRIPT_DIR/top-1m.csv") domains)"
fi

if [[ ! -f "$SCRIPT_DIR/top-1k.csv" ]]; then
    echo "  Generating top-1k.csv from top-1m.csv..."
    head -1000 "$SCRIPT_DIR/top-1m.csv" > "$SCRIPT_DIR/top-1k.csv"
fi

# Generate resolvable domain subsets (filters out NXDOMAIN/SERVFAIL/timeout).
# This isolates CODoH overhead from upstream DNS failure variance.
# Requires Unbound running on 127.0.0.1:5353.
if [[ ! -f "$SCRIPT_DIR/top-1k-resolvable.csv" ]] || [[ ! -f "$SCRIPT_DIR/top-1m-10k-resolvable.csv" ]]; then
    if dig +short @127.0.0.1 -p 5353 google.com > /dev/null 2>&1; then
        echo "  Filtering resolvable domains (this takes a few minutes)..."

        # top-1k resolvable
        if [[ ! -f "$SCRIPT_DIR/top-1k-resolvable.csv" ]]; then
            echo "    Filtering top-1k..."
            while IFS= read -r line; do
                domain=$(echo "$line" | cut -d',' -f2)
                if dig +short +time=2 +tries=1 @127.0.0.1 -p 5353 "$domain" A 2>/dev/null | grep -q '^[0-9]'; then
                    echo "$line"
                fi
            done < "$SCRIPT_DIR/top-1k.csv" > "$SCRIPT_DIR/top-1k-resolvable.csv"
            echo "    top-1k-resolvable.csv: $(wc -l < "$SCRIPT_DIR/top-1k-resolvable.csv") of 1000"
        fi

        # top-1m first 10K resolvable
        if [[ ! -f "$SCRIPT_DIR/top-1m-10k-resolvable.csv" ]]; then
            echo "    Filtering top-10k..."
            head -10000 "$SCRIPT_DIR/top-1m.csv" | while IFS= read -r line; do
                domain=$(echo "$line" | cut -d',' -f2)
                if dig +short +time=2 +tries=1 @127.0.0.1 -p 5353 "$domain" A 2>/dev/null | grep -q '^[0-9]'; then
                    echo "$line"
                fi
            done > "$SCRIPT_DIR/top-1m-10k-resolvable.csv"
            echo "    top-1m-10k-resolvable.csv: $(wc -l < "$SCRIPT_DIR/top-1m-10k-resolvable.csv") of 10000"
        fi
    else
        echo "  WARNING: Unbound not running — skipping resolvable domain filtering."
        echo "  Set up Unbound first, then re-run setup.sh to generate filtered lists."
    fi
fi

#######################################
# Config 3 worktree
#######################################
echo ""
echo "=== Config 3 Worktree ==="
WORKTREE_DIR="$SCRIPT_DIR/worktrees/config3-proxy"
if [[ -d "$WORKTREE_DIR" ]]; then
    echo "  Worktree: already exists at $WORKTREE_DIR"
else
    echo "  Creating worktree for Config 3 (pinned to e81a315)..."
    mkdir -p "$SCRIPT_DIR/worktrees"
    git -C "$ROOT_DIR" worktree add "$WORKTREE_DIR" e81a315ec3a91dee1bad2cc2bbf139ebee145ab8 2>&1 | tail -3
    echo "  Worktree: $WORKTREE_DIR"
fi

# Patch go.mod version to match ego-go (1.25.1) — the pinned commit
# uses 1.25.5 which is newer than the ego SDK ships.
# Patch go.mod: downgrade go version to match ego-go (1.25.1) and bump
# pathoram-go from v0.1.0 (requires go 1.25.5) to v0.1.1 (supports 1.25.1).
if grep -q 'pathoram-go v0.1.0' "$WORKTREE_DIR/go.mod" || grep -q 'go 1.25.5' "$WORKTREE_DIR/go.mod"; then
    echo "  Patching go.mod for ego-go compatibility..."
    sed -i 's/^go 1.25.5/go 1.25.1/' "$WORKTREE_DIR/go.mod"
    sed -i 's|pathoram-go v0.1.0|pathoram-go v0.1.1|' "$WORKTREE_DIR/go.mod"
    (cd "$WORKTREE_DIR" && GOFLAGS=-mod=mod go mod tidy 2>&1 | tail -3)
fi

# Build Config 3 binaries from worktree
echo "  Building Config 3 binaries from worktree..."
(cd "$WORKTREE_DIR" && go build -o coredns-test . 2>&1 | tail -5)
(cd "$WORKTREE_DIR" && go build -o enclave-sim ./enclave/cmd 2>&1 | tail -5)
if [[ "${SGX_MODE:-true}" == "true" ]]; then
    (cd "$WORKTREE_DIR/enclave" && ego-go build -tags ego -o enclave ./cmd 2>&1 | tail -5 && ego sign enclave.json 2>&1 | tail -5) || echo "  WARNING: Config 3 SGX build failed (may need manual fix)"
fi

#######################################
# Unbound check
#######################################
echo ""
echo "=== Unbound Resolver ==="
if dig +short @127.0.0.1 -p 5353 google.com > /dev/null 2>&1; then
    echo "  Unbound: running on 127.0.0.1:5353"
else
    echo "  Unbound: NOT running on port 5353"
    echo "  To set up:"
    echo "    sudo apt install unbound"
    echo "    sudo cp $SCRIPT_DIR/unbound.conf /etc/unbound/unbound.conf.d/benchmark.conf"
    echo "    sudo systemctl restart unbound"
    echo ""
    echo "  Then run: ./benchmark/prewarm-unbound.sh"
fi

#######################################
# Summary
#######################################
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Binaries:"
echo "  Server:      $ROOT_DIR/coredns-test"
echo "  Enclave SGX: $ROOT_DIR/enclave/enclave"
echo "  Enclave Sim: $ROOT_DIR/enclave-sim"
echo "  Client:      $CLIENT_DIR/odoh-client"
echo "  Config 3 WT: $WORKTREE_DIR/"
echo ""
echo "Next steps:"
echo "  1. Ensure Unbound is running: dig @127.0.0.1 -p 5353 google.com"
echo "  2. Prewarm Unbound cache:     ./benchmark/prewarm-unbound.sh"
echo "  3. Run quick validation:       ./benchmark/run-all.sh --quick"
echo "  4. Run standard benchmark:     ./benchmark/run-all.sh --standard --run-id my-run"
echo "  5. Run full benchmark:         ./benchmark/run-all.sh --run-id my-run"
