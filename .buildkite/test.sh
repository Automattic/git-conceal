#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Checking Release..."
cargo check --release

echo "~~~ Running Tests..."
cargo test
