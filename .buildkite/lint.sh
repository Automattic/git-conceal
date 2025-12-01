#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Linting..."
cargo clippy -- --deny warnings --allow clippy::pedantic --warn missing_docs
