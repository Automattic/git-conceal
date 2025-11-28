#!/bin/bash

set -euo pipefail

echo "~~~ Building..."
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"
cargo build --release

echo "~~~ Uploading artifact..."
system=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
version=$(git rev-parse --short HEAD)
extension="${1:-}"
target_name="a8c-git-secrets-${system}-${arch}-${version}${extension}"
cp "target/release/a8c-git-secrets" "$target_name"
buildkite-agent artifact upload "$target_name"
