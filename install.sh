#!/bin/bash

# Description:
#   Installation script for `git-conceal` (https://github.com/Automattic/git-conceal)
#
#   The script downloads the `git-conceal` binary from GitHub releases for the current platform and architecture
#   and installs it on the system.
#
# The script supports macOS (Intel and ARM), Linux (x86_64), and Windows (x86_64).
#
# Usage:
#   To install git-conceal, run:
#     curl -fsSL https://raw.githubusercontent.com/Automattic/git-conceal/trunk/install.sh | bash
#
#   To install to a custom directory:
#     curl -fsSL https://raw.githubusercontent.com/Automattic/git-conceal/trunk/install.sh | bash -s -- --prefix /custom/path
#
#   Or download and run manually:
#     curl -fsSL https://raw.githubusercontent.com/Automattic/git-conceal/trunk/install.sh -o install.sh
#     bash install.sh [--prefix /custom/path]
#

set -euo pipefail

# Parse command line arguments
CUSTOM_PREFIX=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --prefix)
            CUSTOM_PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            CUSTOM_PREFIX="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--prefix /custom/path]"
            exit 1
            ;;
    esac
done

# Determine platform-specific variables
OS=$(uname -s)
ARCH=$(uname -m)

if [[ "$OS" == "MINGW"* ]] || [[ "$OS" == "MSYS"* ]] || [[ "$OS" == "CYGWIN"* ]]; then
    EXECUTABLE_NAME="git-conceal.exe"
    INSTALL_CMD="/usr/bin/install"
    IS_WINDOWS=true
else
    EXECUTABLE_NAME="git-conceal"
    INSTALL_CMD="install"
    IS_WINDOWS=false
fi

# Map platform and architecture to Rust target triple format
case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64)
                TARGET_TRIPLE="aarch64-apple-darwin"
                ;;
            x86_64)
                TARGET_TRIPLE="x86_64-apple-darwin"
                ;;
            *)
                echo "Unsupported architecture on macOS: $ARCH"
                exit 2
                ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            x86_64)
                TARGET_TRIPLE="x86_64-unknown-linux-gnu"
                ;;
            aarch64|arm64)
                TARGET_TRIPLE="aarch64-unknown-linux-gnu"
                ;;
            *)
                echo "Unsupported architecture on Linux: $ARCH"
                exit 2
                ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*)
        case "$ARCH" in
            x86_64)
                TARGET_TRIPLE="x86_64-pc-windows-gnu"
                ;;
            *)
                echo "Unsupported architecture on Windows: $ARCH"
                exit 2
                ;;
        esac
        ;;
    *)
        echo "Unsupported operating system: $OS"
        exit 2
        ;;
esac

# Get the latest release tag from GitHub API
LATEST_RELEASE_URL="https://api.github.com/repos/Automattic/git-conceal/releases/latest"
RELEASE_INFO=$(curl --location --silent "$LATEST_RELEASE_URL")
if [[ -z "$RELEASE_INFO" ]]; then
    echo "Failed to fetch release information from GitHub"
    exit 1
fi

# Extract the version (tag_name) from the release info
VERSION=$(echo "$RELEASE_INFO" | jq -r '.tag_name // empty')
if [[ -z "$VERSION" ]] || [[ "$VERSION" == "null" ]]; then
    echo "Failed to extract version from release information"
    exit 1
fi

# Construct the asset name
if [[ "$IS_WINDOWS" == "true" ]]; then
    ASSET_NAME="git-conceal-${TARGET_TRIPLE}-${VERSION}.exe"
else
    ASSET_NAME="git-conceal-${TARGET_TRIPLE}-${VERSION}"
fi

# Determine the install directory based on platform
if [[ -n "$CUSTOM_PREFIX" ]]; then
    # Use custom prefix if provided
    INSTALL_DIR="$CUSTOM_PREFIX"
else
    if [[ "$IS_WINDOWS" == "true" ]]; then
        # For Windows, try to use a directory in PATH or user's local bin
        if [[ -n "${LOCALAPPDATA:-}" ]]; then
            INSTALL_DIR="$LOCALAPPDATA/Programs/git-conceal"
        else
            INSTALL_DIR="$HOME/.local/bin"
        fi
    else
        # For Unix-like systems, try /usr/local/bin first, fallback to ~/.local/bin
        if [[ -w "/usr/local/bin" ]]; then
            INSTALL_DIR="/usr/local/bin"
        else
            INSTALL_DIR="$HOME/.local/bin"
        fi
    fi
fi

# Create temp directory for download
TEMP_DIR=$(mktemp -d)
trap "rm -rf '$TEMP_DIR'" EXIT

# Download the binary to temp directory
DOWNLOAD_URL="https://github.com/Automattic/git-conceal/releases/download/${VERSION}/${ASSET_NAME}"
TEMP_BINARY="$TEMP_DIR/$EXECUTABLE_NAME"
echo "Downloading $ASSET_NAME from GitHub releases..."
if ! curl --location --silent --fail --output "$TEMP_BINARY" "$DOWNLOAD_URL"; then
    echo "Failed to download $ASSET_NAME from $DOWNLOAD_URL"
    exit 1
fi


# Install the binary in INSTALL_DIR
INSTALL_PATH="$INSTALL_DIR/$EXECUTABLE_NAME"
echo "Installing $EXECUTABLE_NAME to $INSTALL_PATH..."
"$INSTALL_CMD" -d "$INSTALL_DIR"
"$INSTALL_CMD" -m 755 "$TEMP_BINARY" "$INSTALL_PATH"

# Remove quarantine attribute on macOS
if [[ "$OS" == "Darwin" ]]; then
    if xattr -d com.apple.quarantine "$INSTALL_PATH" 2>/dev/null || true; then
        echo "Removed quarantine attribute from $INSTALL_PATH"
    fi
fi

# Verify installation
if [[ -f "$INSTALL_PATH" ]] && [[ -x "$INSTALL_PATH" ]]; then
    echo "Successfully installed git-conceal to $INSTALL_PATH"
    if [[ "$INSTALL_DIR" == "$HOME/.local/bin" ]] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo ""
        echo "Note: $INSTALL_DIR is not in your PATH."
        echo "Add the following to your shell configuration file (~/.bashrc, ~/.zshrc, etc.):"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
else
    echo "Installation failed: $INSTALL_PATH is not executable"
    exit 1
fi
