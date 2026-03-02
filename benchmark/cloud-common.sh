# cloud-common.sh — Shared functions for CODoH cloud benchmarks
#
# Sourced by cloud-run.sh and cloud-page-load-bench.sh.
# Not executable on its own — no shebang, no arg parsing, no traps.
#
# Callers must set before sourcing:
#   SSH_OPTS, SSH_USER, PROXY_IP, TARGET_IP
#   SCRIPT_DIR, ROOT_DIR, REMOTE_ROOT, UPSTREAM_RESOLVER

#######################################
# SSH helpers
#######################################

ssh_proxy()  { ssh $SSH_OPTS "$SSH_USER@$PROXY_IP" "$@"; }
ssh_target() { ssh $SSH_OPTS "$SSH_USER@$TARGET_IP" "$@"; }
scp_to_proxy()  { scp $SSH_OPTS "$1" "$SSH_USER@$PROXY_IP:$2"; }
scp_to_target() { scp $SSH_OPTS "$1" "$SSH_USER@$TARGET_IP:$2"; }
scp_from_proxy()  { scp $SSH_OPTS "$SSH_USER@$PROXY_IP:$1" "$2"; }
scp_from_target() { scp $SSH_OPTS "$SSH_USER@$TARGET_IP:$1" "$2"; }

#######################################
# Remote process management
#######################################

remote_cleanup() {
    echo "Cleaning up remote processes..."
    # Kill by port first (most reliable), then by name.
    # IMPORTANT: avoid pkill -f with patterns that appear in this command string,
    # otherwise pkill kills the bash shell running this cleanup (self-kill).
    ssh_proxy 'for port in 8080 8443 8444 9080 9443 10443; do \
                   lsof -ti :$port 2>/dev/null | xargs -r kill -9 2>/dev/null; \
               done; \
               pkill -9 coredns-test 2>/dev/null; \
               pkill -9 enclave-sim 2>/dev/null; \
               killall -9 ego-host 2>/dev/null; \
               rm -f /tmp/codoh-enclave.sock; \
               sleep 3; \
               for port in 8444 8080 8443; do \
                   lsof -ti :$port 2>/dev/null | xargs -r kill -9 2>/dev/null; \
               done; \
               true' 2>/dev/null || true
    ssh_target 'pkill -9 coredns-test 2>/dev/null; true' 2>/dev/null || true
    sleep 2
}

wait_for_remote() {
    local host=$1 port=$2 max_wait=${3:-60}
    echo "  Waiting for $host:$port (up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if curl -sk "https://$host:$port/health" > /dev/null 2>&1; then
            echo "  $host:$port ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: $host:$port not ready after ${max_wait}s"
    return 1
}

wait_for_remote_attest() {
    local max_wait=${1:-60}
    echo "  Waiting for enclave attestation ($PROXY_IP:8444, up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if curl -sk "https://$PROXY_IP:8444/attest" > /dev/null 2>&1; then
            echo "  Enclave attestation ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: Enclave attestation not ready after ${max_wait}s"
    return 1
}

wait_for_remote_socket() {
    local max_wait=${1:-30}
    echo "  Waiting for enclave IPC socket on proxy (up to ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        if ssh_proxy "test -S /tmp/codoh-enclave.sock" 2>/dev/null; then
            echo "  IPC socket ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: IPC socket not found after ${max_wait}s"
    return 1
}

#######################################
# Corefile generation & distribution
#######################################

# Uses globals: $SCRIPT_DIR, $ROOT_DIR, $UPSTREAM_RESOLVER, $COREFILE_DIR
generate_corefiles() {
    echo "=== Generating Corefiles ==="

    # Copy templates and substitute IPs
    for cf in "$SCRIPT_DIR/Corefile.doh" "$SCRIPT_DIR/Corefile.odoh-target" \
              "$SCRIPT_DIR/Corefile.odoh-proxy" "$SCRIPT_DIR/Corefile.codoh-base-target" \
              "$SCRIPT_DIR/Corefile.target-nosgx" \
              "$ROOT_DIR/Corefile.target" "$ROOT_DIR/Corefile.proxy"; do
        [[ -f "$cf" ]] || continue
        local basename
        basename=$(basename "$cf")

        # Start with upstream resolver substitution
        sed "s|127\.0\.0\.1:5353|$UPSTREAM_RESOLVER|g" "$cf" > "$COREFILE_DIR/$basename"

        # Corefile-specific IP substitutions for cross-VM
        case "$basename" in
            Corefile.target)
                # enclave_url points to proxy VM (enclave attestation)
                sed -i "s|https://127\.0\.0\.1:8444|https://$PROXY_IP:8444|g" "$COREFILE_DIR/$basename"
                ;;
            Corefile.proxy)
                # target points to target VM
                sed -i "s|https://127\.0\.0\.1:8443|https://$TARGET_IP:8443|g" "$COREFILE_DIR/$basename"
                ;;
            Corefile.odoh-proxy)
                # target points to target VM
                sed -i "s|https://127\.0\.0\.1:9443|https://$TARGET_IP:9443|g" "$COREFILE_DIR/$basename"
                ;;
        esac
    done

    echo "  Generated $(ls "$COREFILE_DIR" | wc -l) Corefiles in $COREFILE_DIR/"
}

# Uses globals: $ROOT_DIR, $REMOTE_ROOT, $COREFILE_DIR, $CLOUD_CF
distribute_files() {
    echo "=== Distributing files to VMs ==="

    # Regenerate cert on proxy with all known public IPs in SANs.
    # This is necessary because cloud-setup.sh runs before the peer IP is known,
    # so the cert may only have the private IP.  Regenerating here ensures both
    # PROXY_IP and TARGET_IP are covered, which is required for TLS verification
    # when dnscrypt-proxy fetches /.well-known/odohconfigs from TARGET_IP:8443.
    echo "  Regenerating TLS cert on proxy with SANs for both public IPs..."
    local proxy_private_ip
    proxy_private_ip=$(ssh_proxy "hostname -I | awk '{print \$1}'")
    local san="DNS:localhost,IP:127.0.0.1,IP:${proxy_private_ip},IP:${PROXY_IP},IP:${TARGET_IP}"
    ssh_proxy "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout $REMOTE_ROOT/localhost-key.pem -out $REMOTE_ROOT/localhost.pem \
        -days 365 -nodes -subj '/CN=localhost' \
        -addext 'subjectAltName=${san}' 2>/dev/null"
    echo "  Cert SANs: $san"

    # Certs: copy proxy's cert to target and client (for TLS verification)
    echo "  Fetching proxy cert..."
    scp_from_proxy "$REMOTE_ROOT/localhost.pem" "$ROOT_DIR/localhost.pem"
    scp_from_proxy "$REMOTE_ROOT/localhost-key.pem" "$ROOT_DIR/localhost-key.pem"

    # Send proxy cert to target too (target needs it to verify proxy connections)
    echo "  Sending proxy cert to target..."
    scp_to_target "$ROOT_DIR/localhost.pem" "$REMOTE_ROOT/localhost.pem"
    scp_to_target "$ROOT_DIR/localhost-key.pem" "$REMOTE_ROOT/localhost-key.pem"

    # Send Corefiles to proxy VM
    echo "  Sending Corefiles to proxy..."
    ssh_proxy "mkdir -p $CLOUD_CF"
    for cf in "$COREFILE_DIR"/Corefile.*; do
        [[ -f "$cf" ]] || continue
        scp_to_proxy "$cf" "$CLOUD_CF/$(basename "$cf")"
    done

    # Send Corefiles to target VM
    echo "  Sending Corefiles to target..."
    ssh_target "mkdir -p $CLOUD_CF"
    for cf in "$COREFILE_DIR"/Corefile.*; do
        [[ -f "$cf" ]] || continue
        scp_to_target "$cf" "$CLOUD_CF/$(basename "$cf")"
    done

    echo "  Distribution complete."
}

#######################################
# Config-specific startup
#######################################

: "${CLOUD_CF:=$REMOTE_ROOT/benchmark/cloud-corefiles}"

start_config_1() {
    echo "--- Starting Config 1: DoH ---"

    # Target VM: DoH server (single process, no proxy)
    echo "  Starting DoH server on $TARGET_IP:7443..."
    ssh_target "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.doh \
        > /tmp/bench-doh-server.log 2>&1 </dev/null &)"

    wait_for_remote "$TARGET_IP" 7443
}

start_config_2() {
    echo "--- Starting Config 2: ODoH ---"

    # Target VM: ODoH target
    echo "  Starting ODoH target on $TARGET_IP:9443..."
    ssh_target "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.odoh-target \
        > /tmp/bench-odoh-target.log 2>&1 </dev/null &)"

    # Proxy VM: ODoH proxy
    echo "  Starting ODoH proxy on $PROXY_IP:9080..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.odoh-proxy \
        > /tmp/bench-odoh-proxy.log 2>&1 </dev/null &)"

    wait_for_remote "$PROXY_IP" 9080
    wait_for_remote "$TARGET_IP" 9443
}

start_config_3() {
    echo "--- Starting Config 3: CODoH-base ---"
    local wt="$REMOTE_ROOT/benchmark/worktrees/config3-proxy"

    # Target VM: CODoH-base target (worktree binary)
    echo "  Starting CODoH-base target on $TARGET_IP:10444..."
    ssh_target "cd $wt && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.codoh-base-target \
        > /tmp/bench-codoh-base-target.log 2>&1 </dev/null &)"

    # Proxy VM: enclave-proxy
    local enclave_bin="$wt/enclave-sim"
    if [[ "$SGX_MODE" == "true" ]]; then
        enclave_bin="ego run $wt/enclave/enclave"
        # Copy certs to /tmp for SGX
        ssh_proxy "cp $REMOTE_ROOT/localhost.pem /tmp/codoh-bench-cert.pem; \
                   cp $REMOTE_ROOT/localhost-key.pem /tmp/codoh-bench-key.pem"
    fi
    local cert_flag key_flag
    if [[ "$SGX_MODE" == "true" ]]; then
        cert_flag="/tmp/codoh-bench-cert.pem"
        key_flag="/tmp/codoh-bench-key.pem"
    else
        cert_flag="$REMOTE_ROOT/localhost.pem"
        key_flag="$REMOTE_ROOT/localhost-key.pem"
    fi

    echo "  Starting enclave-proxy on $PROXY_IP:10443..."
    ssh_proxy "cd $wt && (nohup $enclave_bin \
        -mode proxy \
        -https-port 10443 \
        -tls-cert $cert_flag \
        -tls-key $key_flag \
        -target https://$TARGET_IP:10444 \
        > /tmp/bench-enclave-proxy.log 2>&1 </dev/null &)"

    wait_for_remote "$PROXY_IP" 10443
    wait_for_remote "$TARGET_IP" 10444
}

start_config_4() {
    local enclave_env="$1"
    local target_env="$2"
    echo "--- Starting Config 4: CODoH no-SGX ---"

    # Proxy VM: enclave-sim (always plain binary, no SGX)
    local enclave_cmd="$enclave_env $REMOTE_ROOT/enclave-sim"

    echo "  Starting enclave-sim on proxy VM..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup bash -c '$enclave_cmd' > /tmp/bench-enclave.log 2>&1 </dev/null &)"
    wait_for_remote_socket 30

    # Target VM: codohtarget (no-SGX variant — no attestation)
    echo "  Starting CODoH target on $TARGET_IP:8443..."
    ssh_target "cd $REMOTE_ROOT && (nohup bash -c '$target_env ./coredns-test -conf $CLOUD_CF/Corefile.target-nosgx' > /tmp/bench-codoh-target.log 2>&1 </dev/null &)"
    wait_for_remote "$TARGET_IP" 8443

    # Proxy VM: codohproxy
    echo "  Starting CODoH proxy on $PROXY_IP:8080..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.proxy \
        > /tmp/bench-codoh-proxy.log 2>&1 </dev/null &)"
    wait_for_remote "$PROXY_IP" 8080
}

start_config_5() {
    local enclave_env="$1"
    local target_env="$2"
    echo "--- Starting Config 5: CODoH full (SGX) ---"

    # Proxy VM: SGX enclave
    local enclave_cmd="$enclave_env ego run $REMOTE_ROOT/enclave/enclave"

    echo "  Starting SGX enclave on proxy VM..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup bash -c '$enclave_cmd' > /tmp/bench-enclave.log 2>&1 </dev/null &)"
    wait_for_remote_attest 60

    # Target VM: codohtarget (SGX variant — provisions via attestation)
    echo "  Starting CODoH target on $TARGET_IP:8443..."
    ssh_target "cd $REMOTE_ROOT && (nohup bash -c '$target_env ./coredns-test -conf $CLOUD_CF/Corefile.target' > /tmp/bench-codoh-target.log 2>&1 </dev/null &)"
    wait_for_remote_socket 30
    wait_for_remote "$TARGET_IP" 8443

    # Proxy VM: codohproxy
    echo "  Starting CODoH proxy on $PROXY_IP:8080..."
    ssh_proxy "cd $REMOTE_ROOT && (nohup ./coredns-test -conf $CLOUD_CF/Corefile.proxy \
        > /tmp/bench-codoh-proxy.log 2>&1 </dev/null &)"
    wait_for_remote "$PROXY_IP" 8080
}
