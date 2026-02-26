#!/bin/bash
# Patch Config 3 client worktree (010e7fe) for server worktree (e81a315) compatibility.
#
# The server returns "application/codoh-cached" with raw kc-encrypted bytes,
# but the client expects "application/codoh-response" with a two-chunk format.
# This script replaces the two-chunk handler with direct codoh-cached decryption.
#
# Usage: ./patch-config3-client.sh <path-to-request.go>

set -e

REQUEST_GO="$1"
if [[ -z "$REQUEST_GO" || ! -f "$REQUEST_GO" ]]; then
    echo "Usage: $0 <path-to-commands/request.go>"
    exit 1
fi

# 1. Change content-type constant
sed -i 's|"application/codoh-response"|"application/codoh-cached"|' "$REQUEST_GO"

# 2. Replace the two-chunk handler with direct decryption
export PATCH_TARGET="$REQUEST_GO"
python3 -c '
import os, sys

path = os.environ["PATCH_TARGET"]
with open(path, "r") as f:
    content = f.read()

# Remove encoding/binary import (no longer needed after removing two-chunk parsing)
content = content.replace("\t\"encoding/binary\"\n", "")

# The two-chunk handler block to replace (find by unique anchor)
anchor = "case codohResponseContentType:"
idx = content.find(anchor)
if idx < 0:
    print("WARNING: Could not find codohResponseContentType case", file=sys.stderr)
    sys.exit(1)

# Find the end of this case block (next case statement)
next_case = content.find("\n\tcase ", idx + len(anchor))
if next_case < 0:
    print("WARNING: Could not find next case after codohResponseContentType", file=sys.stderr)
    sys.exit(1)

# Build replacement
new_block = """\tcase codohResponseContentType:
\t\t// Cache hit \u2014 raw kc-encrypted response from server
\t\tresult.CacheHit = true
\t\tdecrypted, err := DecryptCachedResponse(kr, bodyBytes)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("decrypt cached response: %w", err)
\t\t}
\t\tresult.RawResponse = decrypted
\t\tlog.Println("Cache HIT - response decrypted with kc")

"""

content = content[:idx] + new_block + content[next_case+1:]

with open(path, "w") as f:
    f.write(content)

print("  Patched response handler successfully")
'
