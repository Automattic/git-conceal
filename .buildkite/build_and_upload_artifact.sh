#!/bin/bash

set -euo pipefail

echo "~~~ Building..."
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"
cargo build --release

echo "~~~ Uploading artifact..."
target_triple=$(rustc -vV | grep "^host" | awk '{print $2}')
version=$(git rev-parse --short HEAD)
extension="${1:-}"
dest_filename="a8c-git-secrets-${target_triple}-${version}${extension}"
cp "target/release/a8c-git-secrets" "$dest_filename"
buildkite-agent artifact upload "$dest_filename"
