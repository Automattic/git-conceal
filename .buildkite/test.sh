#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Checking Release..."
make check-release

echo "~~~ Running Tests..."
make test

echo "~~~ Testing \`install.sh\` script..."
printf "git-conceal command: %s\n" "$(command -v git-conceal || echo "not found")"
./install.sh --prefix ./bin
export PATH=$PATH:./bin
git-conceal --version || echo "git-conceal not found"
