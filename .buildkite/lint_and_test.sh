#!/bin/bash

set -euo pipefail

echo "~~~ Linting..."
make lint-pedantic

echo "~~~ Checking Release..."
make check-release

echo "~~~ Running Tests..."
make test
