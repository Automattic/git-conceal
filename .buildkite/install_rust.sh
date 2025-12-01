#!/bin/bash

set -euo pipefail

echo "~~~ Installing Rust"
if command -v rustc &> /dev/null; then
  echo "Rust is already installed"
  exit 0
elif command -v brew &> /dev/null; then
  echo "Installing Rust via Homebrew..."
  brew install rust
else
  echo "Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
