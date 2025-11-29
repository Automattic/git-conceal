#!/bin/bash

set -euo pipefail

echo "~~~ Building..."
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"
cargo build --release

echo "~~~ Testing..."
cargo test

echo "~~~ Uploading artifact..."
platform_triple=$(rustc -vV | grep "^host" | awk '{print $2}')
version=$(git rev-parse --short HEAD)
extension="${1:-}"
dest_filename="a8c-git-secrets-${platform_triple}-${version}${extension}"
cp "target/release/a8c-git-secrets" "$dest_filename"
buildkite-agent artifact upload "$dest_filename"
