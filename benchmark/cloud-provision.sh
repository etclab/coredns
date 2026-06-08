#!/bin/bash
# CODoH Cloud Benchmark — One-shot VM Bootstrapper
#
# Run from the CLIENT VM only. Provisions proxy + target via SSH,
# then sets up the client locally.
#
# Prerequisites:
#   1. Fill in benchmark/cloud-env.local.sh with PROXY_IP, TARGET_IP
#   2. Ensure SSH key auth works: ssh $SSH_USER@$PROXY_IP "echo ok"
#   3. gh auth login on all three VMs (repos are private)
#
# Usage: ./benchmark/cloud-provision.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

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
: "${GIT_BRANCH:=codoh-main}"
: "${RESOLVER:=unbound}"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"
REMOTE_PARENT="$(dirname "$REMOTE_ROOT")"
REMOTE_CLIENT="$REMOTE_PARENT/codoh-client"
LOCAL_CLIENT="$(dirname "$ROOT_DIR")/codoh-client"
GO_VERSION="1.25.1"

echo "=== CODoH Cloud Provision ==="
echo "Proxy:   $PROXY_IP"
echo "Target:  $TARGET_IP"
echo "Branch:  $GIT_BRANCH"
echo "Remote:  $REMOTE_ROOT"
echo ""

#######################################
# Verify SSH connectivity
#######################################
echo "[1/5] Verifying SSH connectivity..."
if ! ssh $SSH_OPTS "$SSH_USER@$PROXY_IP" "echo ok" > /dev/null 2>&1; then
    echo "ERROR: Cannot SSH to proxy ($PROXY_IP)"
    exit 1
fi
echo "  Proxy SSH: OK"

if ! ssh $SSH_OPTS "$SSH_USER@$TARGET_IP" "echo ok" > /dev/null 2>&1; then
    echo "ERROR: Cannot SSH to target ($TARGET_IP)"
    exit 1
fi
echo "  Target SSH: OK"
echo ""

#######################################
# Remote provisioner (proxy + target)
#######################################
provision_remote() {
    local role=$1 host=$2
    echo "[${role}] Provisioning $host..."

    # Non-login SSH shells don't source ~/.profile, so export PATH explicitly
    local path_prefix="export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin;"

    # Install Go if missing
    echo "  [$role] Checking Go..."
    ssh $SSH_OPTS "$SSH_USER@$host" "${path_prefix} command -v go" > /dev/null 2>&1 || {
        echo "  [$role] Installing Go $GO_VERSION..."
        ssh $SSH_OPTS "$SSH_USER@$host" "
            curl -sLO https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
            sudo rm -rf /usr/local/go && \
            sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
            rm -f go${GO_VERSION}.linux-amd64.tar.gz && \
            grep -q '/usr/local/go/bin' ~/.profile 2>/dev/null || \
                echo 'export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin' >> ~/.profile
        "
    }
    ssh $SSH_OPTS "$SSH_USER@$host" "${path_prefix} go version"

    # Clone repo if absent (remove partial clones first)
    echo "  [$role] Checking repo..."
    ssh $SSH_OPTS "$SSH_USER@$host" "test -f $REMOTE_ROOT/go.mod" 2>/dev/null || {
        ssh $SSH_OPTS "$SSH_USER@$host" "
            if [[ -d $REMOTE_ROOT ]]; then
                echo '  Removing partial clone at $REMOTE_ROOT...'
                rm -rf $REMOTE_ROOT
            fi
        "
        echo "  [$role] Cloning coredns repo..."
        ssh $SSH_OPTS "$SSH_USER@$host" "
            sed -i 's/git_protocol: ssh/git_protocol: https/' ~/.config/gh/hosts.yml 2>/dev/null; \
            mkdir -p $REMOTE_PARENT && \
            cd $REMOTE_PARENT && \
            ${path_prefix} gh repo clone etclab/coredns -- --branch $GIT_BRANCH
        "
    }

    # Checkout correct branch
    echo "  [$role] Checking out $GIT_BRANCH..."
    ssh $SSH_OPTS "$SSH_USER@$host" "
        cd $REMOTE_ROOT && \
        git fetch origin && \
        git checkout $GIT_BRANCH && \
        git pull --ff-only 2>/dev/null || true
    "

    # Run cloud-setup.sh for the role
    local setup_args="$role"
    [[ "$role" == "target" ]] && setup_args="target --resolver $RESOLVER"

    echo "  [$role] Running cloud-setup.sh $setup_args..."
    ssh $SSH_OPTS "$SSH_USER@$host" "
        ${path_prefix} cd $REMOTE_ROOT && ./benchmark/cloud-setup.sh $setup_args
    "

    echo "  [$role] Done."
    echo ""
}

#######################################
# Provision remote VMs
#######################################
echo "[2/5] Provisioning proxy VM..."
provision_remote proxy "$PROXY_IP"

echo "[3/5] Provisioning target VM..."
provision_remote target "$TARGET_IP"

#######################################
# Provision client (local)
#######################################
echo "[4/5] Provisioning client (local)..."

# Clone codoh-client if absent (remove partial clones first)
if [[ ! -f "$LOCAL_CLIENT/go.mod" ]]; then
    if [[ -d "$LOCAL_CLIENT" ]]; then
        echo "  Removing partial clone at $LOCAL_CLIENT..."
        rm -rf "$LOCAL_CLIENT"
    fi
    echo "  Cloning codoh-client..."
    mkdir -p "$(dirname "$LOCAL_CLIENT")"
    (cd "$(dirname "$LOCAL_CLIENT")" && gh repo clone etclab/codoh-client -- --branch "$GIT_BRANCH")
fi

# Run cloud-setup.sh client
echo "  Running cloud-setup.sh client..."
(cd "$ROOT_DIR" && ./benchmark/cloud-setup.sh client)

#######################################
# Verify cross-VM port reachability
#######################################
echo "[5/5] Checking cross-VM port reachability..."
if ! "$SCRIPT_DIR/cloud-check-ports.sh"; then
    echo ""
    if [[ -n "${RESOURCE_GROUP:-}" && -n "${PROXY_NSG:-}" && -n "${TARGET_NSG:-}" ]]; then
        echo "Ports blocked — opening via Azure NSG..."
        "$SCRIPT_DIR/cloud-open-ports.sh"
        echo ""
        echo "Re-checking ports..."
        "$SCRIPT_DIR/cloud-check-ports.sh" || echo "WARNING: Some ports still blocked after NSG update (may take a few seconds to propagate)"
    else
        echo "Ports blocked. To auto-fix, set RESOURCE_GROUP, PROXY_NSG, TARGET_NSG in cloud-env.local.sh"
        echo "Or run manually: ./benchmark/cloud-open-ports.sh"
    fi
fi
echo ""

echo "=== Provision Complete ==="
echo ""
echo "All three VMs are ready. Next steps:"
echo "  1. Run benchmarks:  ./benchmark/cloud-run.sh --quick"
echo "  2. Full suite:      ./benchmark/cloud-run.sh --configs 2,3,4"
echo ""
echo "If you changed cloud-env.local.sh IPs, re-run this script."
