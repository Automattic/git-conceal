#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Linting..."
make lint-pedantic
