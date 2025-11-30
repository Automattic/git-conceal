# a8c-git-secrets

A Rust implementation of transparent file encryption in git repositories, similar to [git-crypt](https://github.com/AGWA/git-crypt), but using only symmetric keys (no GPG support).

## Features

- **Transparent encryption/decryption**: Files are automatically encrypted on commit and decrypted on checkout
- **Symmetric key encryption**: Uses AES-256-CTR with deterministic IVs (compatible with git's change detection)
- **Cross-platform**: Works on macOS, Linux, and Windows
- **Git filter integration**: Seamlessly integrates with git's clean/smudge filters

## Installation

### From Source

```bash
git clone <repository-url>
cd a8c-git-secrets
cargo build --release
```

The binary will be at `target/release/a8c-git-secrets` (or `target/release/a8c-git-secrets.exe` on Windows).

### Add to PATH

Make sure the binary is in your PATH, or use the full path when configuring git filters.

## Usage

### Initialize a Repository

To set up encryption for a git repository:

```bash
cd /path/to/your/repo
a8c-git-secrets init
```

This will:
- Generate a new 256-bit encryption key
- Store the key in `.git/a8c-git-secrets.key` with secure file permissions (read/write for owner only)
- Configure git filters for encryption/decryption
- Display the key (save it securely!)

**Important**: Save the displayed key securely! You'll need it to unlock the repository on other machines or share it with collaborators.

### Configure Files to Encrypt

Create or edit `.gitattributes` in your repository root to specify which files should be encrypted:

```
# Encrypt a specific file
secretfile filter=a8c-git-secrets diff=a8c-git-secrets

# Encrypt all files with a specific extension
*.key filter=a8c-git-secrets diff=a8c-git-secrets

# Encrypt all files in a directory
secretdir/** filter=a8c-git-secrets diff=a8c-git-secrets
```

**Important**: Make sure `.gitattributes` itself is NOT encrypted! You can explicitly exclude it:

```
.gitattributes !filter !diff
```

### Unlock a Repository

When you clone a repository with encrypted files, or if the repository is locked, you need to unlock it:

```bash
# From environment variable (base64 encoded)
export GIT_SECRETS_KEY="YOUR_BASE64_KEY"
a8c-git-secrets unlock env:GIT_SECRETS_KEY

# From file (raw binary, 32 bytes)
a8c-git-secrets unlock /path/to/key.bin

# From stdin (raw binary, 32 bytes)
cat /path/to/key.bin | a8c-git-secrets unlock -
# Or convert from base64:
echo "YOUR_BASE64_KEY" | base64 -d | a8c-git-secrets unlock -
```

This will:
- Store the key in `.git/a8c-git-secrets.key` with secure file permissions
- Set up git filters if not already configured
- Decrypt all encrypted files in the working directory

### Lock a Repository

To remove the encryption key file from the repository (files will remain encrypted):

```bash
a8c-git-secrets lock
```

### Check Status

To see the current encryption status:

```bash
a8c-git-secrets status
```

This shows:
- Whether the repository is locked or unlocked
- Whether filters are configured
- Which file patterns are encrypted (from `.gitattributes`)

## How It Works

1. **Encryption**: When you commit a file marked for encryption, git's "clean" filter encrypts it using AES-256-CTR before storing it in the repository.

2. **Decryption**: When you checkout a file, git's "smudge" filter decrypts it automatically.

3. **Deterministic Encryption**: The same plaintext always encrypts to the same ciphertext (using a deterministic IV derived from the file content). This allows git to detect when files haven't changed.

4. **Key Storage**: The encryption key is stored in `.git/a8c-git-secrets.key` (local to your repository clone). The file is created with secure permissions (read/write for owner only on Unix systems). It's never committed to the repository.

## Security Considerations

- **Key Management**: The encryption key is stored in plaintext in `.git/a8c-git-secrets.key`. The file is automatically created with secure permissions (mode 0600 on Unix systems - read/write for owner only). On Unix systems, you can verify permissions with:
  ```bash
  ls -l .git/a8c-git-secrets.key
  ```
  If permissions are incorrect, fix them with:
  ```bash
  chmod 600 .git/a8c-git-secrets.key
  ```
  Protect your `.git` directory appropriately - it should not be accessible to other users on the system.

- **Key Sharing**: Share keys securely with collaborators (e.g., via encrypted channels, password managers, etc.)

- **File Patterns**: Make sure your `.gitattributes` patterns are correct before adding sensitive files, or they won't be encrypted!

- **Backup Keys**: Always backup your encryption keys. If you lose the key, encrypted files cannot be recovered.

## Limitations

- **No Key Rotation**: Unlike git-crypt, this tool doesn't support key rotation or revoking access (by design, for simplicity).
- **No GPG Support**: Only symmetric keys are supported (no GPG key management).
- **File Metadata**: File names, commit messages, and other metadata are not encrypted.
- **File Size**: Encrypted files are not compressible by git.

## Comparison with git-crypt

This tool is inspired by git-crypt but differs in:
- **Language**: Written in Rust instead of C++
- **Key Management**: Only supports symmetric keys (no GPG)
- **Simplicity**: Focused on the core use case of symmetric key encryption

## License

MIT OR Apache-2.0

