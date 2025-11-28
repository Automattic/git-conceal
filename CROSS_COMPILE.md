# Building for Windows

## Option 1: Native Windows Build (Recommended)

Since you have Windows agents in Buildkite with Windows SDK and Rust installed, the easiest approach is to build natively on Windows.

### On Windows (Buildkite agent or local Windows machine)

```powershell
# Build release binary
cargo build --release
```

The binary will be at: `target\release\a8c-git-secrets.exe`

### Buildkite Pipeline Example

Add a Windows build step to your Buildkite pipeline:

```yaml
steps:
  - label: "Build Windows"
    agents:
      queue: windows  # or whatever your Windows agent queue is named
    commands:
      - cargo build --release
      - buildkite-agent artifact upload "target/release/a8c-git-secrets.exe"
```

## Option 2: Cross-Compilation from macOS/Linux

If you need to build from macOS or Linux, you can use cross-compilation, though it's more complex due to the `git2` dependency.

### Using `cross` tool

```bash
# Install cross
cargo install cross --git https://github.com/cross-rs/cross

# Build for Windows
cross build --target x86_64-pc-windows-gnu --release
```

The binary will be at: `target/x86_64-pc-windows-gnu/release/a8c-git-secrets.exe`

### Manual cross-compilation

1. Install the Windows target:
   ```bash
   rustup target add x86_64-pc-windows-gnu
   ```

2. Install MinGW-w64 (on macOS):
   ```bash
   brew install mingw-w64
   ```

3. Build:
   ```bash
   cargo build --release --target x86_64-pc-windows-gnu
   ```

**Note**: Cross-compilation with `git2` (which depends on libgit2) can be tricky and may require additional setup for linking native libraries.

## Recommendation

For your setup with Buildkite Windows agents, **Option 1 (native Windows build)** is the most reliable and straightforward approach.
