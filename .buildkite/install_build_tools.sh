#!/bin/bash

set -euo pipefail

echo "~~~ Installing Rust"
if command -v rustc &> /dev/null; then
  echo "Rust is already installed"
elif command -v brew &> /dev/null; then
  echo "Installing Rust via Homebrew..."
  brew install rust
else
  echo "Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

echo "~~~ Installing Make"
if command -v make &> /dev/null; then
  echo "Make is already installed"
elif binpath="$(command -v mingw32-make 2> /dev/null)"; then
  echo "Aliasing make to mingw32-make..."
  binname="$(basename "$binpath")"
  ln -sf "$binpath" "$(dirname "$binpath")/${binname/mingw32-make/make}"
else
  echo "Expected make to be installed, but it is not"
  exit 1
fi
