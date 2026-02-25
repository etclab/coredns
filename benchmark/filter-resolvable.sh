#!/bin/bash
# Filter top-1m.csv to produce exactly N resolvable domains.
#
# Usage: ./benchmark/filter-resolvable.sh [--count N] [--resolver HOST:PORT] [--parallel P]
# Output: benchmark/top-Nk-resolvable.csv

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT="$SCRIPT_DIR/top-1m.csv"
TARGET_COUNT=10000
RESOLVER="8.8.8.8:53"
PARALLEL=50

while [[ $# -gt 0 ]]; do
    case $1 in
        --count)    TARGET_COUNT="$2"; shift 2 ;;
        --resolver) RESOLVER="$2"; shift 2 ;;
        --parallel) PARALLEL="$2"; shift 2 ;;
        *) echo "Usage: $0 [--count N] [--resolver HOST:PORT] [--parallel P]"; exit 1 ;;
    esac
done

HOST="${RESOLVER%%:*}"
PORT="${RESOLVER##*:}"
LABEL="$((TARGET_COUNT / 1000))k"
OUTPUT="$SCRIPT_DIR/top-${LABEL}-resolvable.csv"

if [[ ! -f "$INPUT" ]]; then
    echo "ERROR: $INPUT not found. Run setup.sh first."
    exit 1
fi

if ! dig +short +time=1 +tries=1 "@$HOST" -p "$PORT" google.com A > /dev/null 2>&1; then
    echo "ERROR: Resolver $RESOLVER not responding."
    exit 1
fi

echo "Filtering resolvable domains from top-1m.csv"
echo "  Target: $TARGET_COUNT domains"
echo "  Resolver: $RESOLVER  Parallel: $PARALLEL"

TMPOUT=$(mktemp)
LOCKFILE=$(mktemp)
trap "rm -f $TMPOUT $LOCKFILE" EXIT

check_and_append() {
    local line="$1" host="$2" port="$3" outfile="$4" lock="$5"
    local domain
    domain=$(echo "$line" | cut -d',' -f2)
    if dig +short +time=2 +tries=1 "@$host" -p "$port" "$domain" A 2>/dev/null | grep -q '^[0-9]'; then
        flock "$lock" bash -c "echo '$line' >> '$outfile'"
    fi
}
export -f check_and_append

# Feed lines to xargs, which runs PARALLEL workers
# Stop reading input once we have enough results
(
    checked=0
    while IFS= read -r line; do
        echo "$line"
        checked=$((checked + 1))
        # Periodically check if we have enough
        if (( checked % 200 == 0 )); then
            got=$(wc -l < "$TMPOUT" 2>/dev/null || echo 0)
            # Request ~20% extra to account for in-flight jobs
            if [[ $got -ge $TARGET_COUNT ]]; then
                break
            fi
        fi
    done < "$INPUT"
) | xargs -P "$PARALLEL" -I '{}' bash -c 'check_and_append "{}" "$0" "$1" "$2" "$3"' "$HOST" "$PORT" "$TMPOUT" "$LOCKFILE" &

XARGS_PID=$!

# Progress monitor
while kill -0 "$XARGS_PID" 2>/dev/null; do
    sleep 3
    got=$(wc -l < "$TMPOUT" 2>/dev/null || echo 0)
    echo "  Progress: $got / $TARGET_COUNT"
    if [[ $got -ge $TARGET_COUNT ]]; then
        kill "$XARGS_PID" 2>/dev/null || true
        wait "$XARGS_PID" 2>/dev/null || true
        break
    fi
done
wait 2>/dev/null || true

sort -t',' -k1 -n "$TMPOUT" | head -n "$TARGET_COUNT" > "$OUTPUT"
ACTUAL=$(wc -l < "$OUTPUT")
echo "Done: $OUTPUT ($ACTUAL domains)"
