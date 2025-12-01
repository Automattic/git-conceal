#!/bin/bash

set -euo pipefail

echo "~~~ Download binary"
platform_triple="$1"
buildkite-agent artifact download "git-conceal-${platform_triple}-*" .
binary=$(find . -name "git-conceal-${platform_triple}-*" -type f -print -quit)
chmod +x "$binary"
echo "Binary: $binary"

echo "~~~ Status before decrypt"
"$binary" status

echo "~~~ Content before decrypt"
function dump_bin_file() { command -v hexdump >/dev/null 2>&1 && hexdump -C "$1" || od -A x -t x1z "$1"; }
echo "=== some-secrets.txt ==="
dump_bin_file "some-secrets.txt"
echo "=== more-secrets.txt ==="
dump_bin_file "more-secrets.txt"

echo "~~~ Decrypt repo"
# This would be a leak in a real repo, but this key is temporary for testing purposes
# and we're only encrypting dummy files here, so it's okay.
export A8C_GIT_SECRETS_KEY="1YaHw1Cx6qWAgh6113al4h8pmxqlFEz1n3knFLyhOVY="
"$binary" unlock env:A8C_GIT_SECRETS_KEY

echo "~~~ Status after decrypt"
"$binary" status

echo "~~~ Content after decrypt"
echo "=== some-secrets.txt ==="
cat some-secrets.txt
echo "=== more-secrets.txt ==="
cat more-secrets.txt
