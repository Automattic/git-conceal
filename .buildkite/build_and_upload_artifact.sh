#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Building Release..."
make build-release

echo "~~~ Uploading artifact..."
platform_triple=$(rustc -vV | grep "^host" | awk '{print $2}')
version="${BUILDKITE_TAG:-${BUILDKITE_COMMIT:0:7}}"
extension="${1:-}"
dest_filename="git-conceal-${platform_triple}-${version}${extension}"
cp "target/release/git-conceal" "$dest_filename"
buildkite-agent artifact upload "$dest_filename"
