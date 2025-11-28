#!/bin/bash

set -euo pipefail

echo "~~~ Download binary"
system=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
buildkite-agent artifact download "a8c-git-secrets-${system}-${arch}-*" .
binary=$(find . -name "a8c-git-secrets-*" -type f -print -quit)
chmod +x "$binary"
echo "Binary: $binary"

echo "~~~ Content before decrypt"
echo "=== some-secrets.txt ==="
cat some-secrets.txt | xxd
echo "=== more-secrets.txt ==="
cat more-secrets.txt | xxd

echo "~~~ Status before decrypt"
"$binary" status

echo "~~~ Decrypt repo"
# This would be a leak in a real repo, but this key is temporary for testing purposes
# and we're only encrypting dummy files here, so it's okay.
export A8C_GIT_SECRETS_KEY="1YaHw1Cx6qWAgh6113al4h8pmxqlFEz1n3knFLyhOVY="
"$binary" unlock env:A8C_GIT_SECRETS_KEY

echo "~~~ Status after decrypt"
"$binary" status

echo "~~~ Content after decrypt"
echo "=== some-secrets.txt ==="
cat some-secrets.txt | xxd
echo "=== more-secrets.txt ==="
cat more-secrets.txt | xxd
