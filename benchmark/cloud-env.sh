#!/bin/bash
# CODoH Cloud Benchmark — Environment Template
#
# Copy this file to cloud-env.local.sh and fill in your values:
#   cp benchmark/cloud-env.sh benchmark/cloud-env.local.sh
#
# cloud-env.local.sh is gitignored.

# Required: VM IP addresses
PROXY_IP=          # Azure DCsv3 (SGX) — runs enclave + proxy
TARGET_IP=         # Any Azure VM — runs codohtarget + resolver

# SSH settings
SSH_USER="${SSH_USER:-azureuser}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"

# Remote project root (where repo is cloned on VMs)
REMOTE_ROOT="/home/${SSH_USER}/Projects/codoh/coredns"

# Upstream DNS resolver for target VM
UPSTREAM_RESOLVER="${UPSTREAM_RESOLVER:-1.1.1.1:53}"

# SGX mode (set false if proxy VM lacks SGX for testing)
SGX_MODE="${SGX_MODE:-true}"

# Git branch to checkout on remote VMs
GIT_BRANCH="${GIT_BRANCH:-codoh-design-v2}"
