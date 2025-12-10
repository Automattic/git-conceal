# git-conceal

<table><tr height="40px">
<td width="150px"><img alt="icon" src="Icon.png" width="128px" height="128px" /></td>
<td>This tool provides transparent encryption of files in Git repositories using a symmetric key.<br />
Its goal is to allow you to store some secret files as encrypted in an otherwise public repo.</td>
</tr></table>

Inspired by [git-crypt](https://github.com/AGWA/git-crypt). Written in Rust for its first-class **cross-platform support**.

## Features

 - **Transparent encryption/decryption**: Files are automatically encrypted on commit and decrypted on checkout, thanks to [git filters built-in feature](https://git-scm.com/docs/gitattributes#_filter)
 - **Symmetric key encryption**: Uses AES-256-CTR ([Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with 256-bit keys in [Counter Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))) with deterministic IVs ([Initialization Vectors](https://en.wikipedia.org/wiki/Initialization_vector))
 - **Supports key rotation**: If your key gets leaked or a coworker leaves your team, you can rotate your secrets and encryption key easily
 - **Cross-platform**: Works on macOS, Linux, and Windows

## Overview

 - After you run `git-conceal init` to generate a cryptographic key and configure your working copy, just list the files you want to encrypt on commit in your `.gitattributes` file.
 - At that point, files will be in clear text in your working copy (since you have the key locally)—so e.g. your compiler will be able use them just like any other file—but it will be encrypted on the fly by `git` on `commit`—so that only the encrypted content is stored in the repository (object database and remote repos)
 - On subsequent `git checkout`, only if the user doing the `checkout` has the filters and key configured on their machine will the content be decrypted in their local working copy.

You can learn more about technical details of how Git filter works in [this article](https://mobile.blog/2025/11/13/git-filters-diff-drivers-a-technical-overview/).

## Installation

### Install script (Recommended)

The easiest way to install `git-conceal` is using the install script:

```bash
curl -fsSL https://raw.githubusercontent.com/Automattic/git-conceal/trunk/install.sh | bash
```

This will automatically:
- Detect your platform and architecture
- Download the appropriate binary from the latest GitHub release
- Install it to the appropriate location (`/usr/local/bin` on Unix systems if writable, otherwise `~/.local/bin`)

To install to a custom directory:

```bash
curl -fsSL https://raw.githubusercontent.com/Automattic/git-conceal/trunk/install.sh | bash -s -- --prefix /custom/path
```

Or download and run the script manually:

```bash
curl -fsSL https://raw.githubusercontent.com/Automattic/git-conceal/trunk/install.sh -o install.sh
bash install.sh [--prefix /custom/path]
```

### Manual download from GitHub Releases

Alternatively, you can manually download the pre-built binary suitable for your platform (Linux, macOS, Windows) from [the latest GitHub release](https://github.com/Automattic/git-conceal/releases/latest):

1. Download the binary for your platform
2. Rename it `git-conceal` (or `git-conceal.exe` on Windows) and save it in a directory in your `$PATH` (e.g. `/usr/local/bin`)
3. On macOS/Linux, ensure to make it executable (`chmod +x git-conceal`)
4. On macOS, you might need to remove the quarantine attribute too before you can run it: `xattr -d com.apple.quarantine git-conceal`

### Build from source

```bash
git clone https://github.com/Automattic/git-conceal
cd git-conceal
cargo build --release
```

The binary will be at `target/release/git-conceal` (or `target/release/git-conceal.exe` on Windows).

## Usage

### Initialize a repository

To set up encryption for a Git repository that doesn't use this tool yet:

```bash
cd /path/to/your/repo
git-conceal init
```

This will:
- Generate a new 256-bit encryption key
- Store the key in `.git/git-conceal.key` with secure file permissions.
- Configure Git filters for encryption/decryption
- Display the key so you can share it with your coworkers.

You will only have to do this once.

> [!IMPORTANT]
> Save the displayed key securely! You'll need it to unlock the repository on other machines or share it with collaborators.

### Configure files to encrypt

Create or edit `.gitattributes` in your repository root to specify which files should be encrypted by adding the `filter=git-conceal` attribute to them, for example:

```
# Encrypt specific files
secretfile filter=git-conceal diff=git-conceal
config/secrets.yml filter=git-conceal diff=git-conceal

# Encrypt all files with specific extensions
*.key filter=git-conceal diff=git-conceal
*.pem filter=git-conceal diff=git-conceal
*.p12 filter=git-conceal diff=git-conceal

# Encrypt all files in a directory (use ** to match recursively)
secrets/** filter=git-conceal diff=git-conceal
private/** filter=git-conceal diff=git-conceal
```

> [!IMPORTANT]
> Make sure `.gitattributes` itself is NOT encrypted! If needed, you can explicitly exclude it adding this line to it:

```
# Exclude .gitattributes itself from encryption
.gitattributes !filter !diff
```

### Add new encrypted files

At that point, when you will `git add` a file to that repo that matches one of the `filter=git-conceal` pattern, that file's blob/content will be encrypted on the fly by Git.

> [!IMPORTANT]
> Make sure the file pattern is listed in `.gitattributes` _before_ you `git add` the file containing secrets, as the Git filters are applied at the time you `git add`.

> [!TIP]
> If you forgot to add a file pattern in `.gitattributes` before  `git add`-ing a file, you can either remove the file from the staging area and re-add it again, or use `git add --renormalize <file>`

### Verify if files are encrypted

To give you peace of mind and validate that files you added to your repo are processed by the Git filter, you can use `git-conceal status` (to list all the files that will go through the encryption filter) or `git-conceal status <file>` to check a specific file. This command will validate that the file would match a pattern of your `.gitattributes` that has the `filter=git-conceal` attribute set.

You can also check what the blob content of the corresponding object looks like in the repository database by using `git show :<file>` (or `git show HEAD:<file>` if it's commited into `HEAD` already).
This will show the raw content as stored in the repository. So even if `cat my-secret-file.txt` will show you the clear text locally (assuming you have unlocked your working copy with the right key), `git show :my-secret-file.txt` will show you the raw, encrypted binary data stored in the repository (assuming that file matches a `.gitattributes` pattern with `filter=git-conceal` set)

### Unlock a repository

After you freshly clone a repository which contains files which have been encrypted by `git-conceal`, you need to provide the symmetric key that your coworkers would have shared with you to decrypt it:

```bash
# Option 1: Provide the key via an environment variable (base64 encoded). Recommended on CI.
export GIT_SECRETS_KEY="YOUR_BASE64_KEY"
git-conceal unlock env:GIT_SECRETS_KEY

# Option 2: Provide the Base64-encoded key as command line argument. (Only use locally, as on CI this could leak the key in logs).
git-conceal unlock "base64:c3VwcG9zZWRseS15b3VyLWJpbmFyeS1zZWNyZXRrZXk="

# Option 3: Provide a path to a from file containing the raw binary, 32 bytes key.
git-conceal unlock /path/to/key.bin

# Option 4: Provide it via stdin (expects raw binary, 32 bytes as input)
cat /path/to/key.bin | git-conceal unlock -
# Or convert from base64. (Only use locally, as on CI this could leak the key in logs).
echo "c3VwcG9zZWRseS15b3VyLWJpbmFyeS1zZWNyZXRrZXk=" | base64 -d | git-conceal unlock -
```

This will:
- Store the key in `.git/git-conceal.key` with secure file permissions
- Set up Git filters in the Git config of this working copy (if not already configured)
- Decrypt all encrypted files in the working directory

### Lock a repository

To remove the encryption key file from the local working copy and restore the content of the local files to their encrypted content, you can "lock" your working copy:

```bash
git-conceal lock
git-conceal lock --force # to ignore local changes if any
```

> [!TIP]
> This can be useful in the rare case where you need to switch between branches that contain secret files that were encrypted with different keys (see "Rotate the encryption key" below), to avoid errors during the Git operations while Git processes files from branch A that were encrypted with keyA and tries to decrypt them with the keyB that was used back in branch B.
> It should be pretty rare to rotate keys though, so it should be very uncommon to have to lock a repository in your everyday workflow.

### Check files status

To see the current encryption status:

```bash
git-conceal status
```

This shows:
- Whether the repository is locked or unlocked
- Whether filters are configured
- Which file patterns are encrypted (from `.gitattributes`)

```bash
git-conceal status <FILES>
```

This shows the status of each file (i.e. if it will be processed by the files according to the `.gitattributes` or not)

### Show the encryption key

If you need to show the local symmetric encryption key you are using in your local working copy, typically so you can share it with your coworkers so that they can decrypt their working copy too:

```bash
git-conceal key show
```

### Rotate the encryption key

There are times when you might need to rotate the encryption key used in an encrypted repository.
For example, in the unfortunate even of the key leaking or when a coworker leaves your team/company and you want to ensure they can't access new secrets.

You can rotate the encryption key with:

```bash
git-conceal key rotate
```

Your working copy has to be unlocked with the current key before you can call this command.

This command will explain the impacts of rotating the key and ask for confirmation, then generate a new key, re-encrypt the encrypted files with the new key, and mark them as changed in the Git index, ready for you to commit them, providing you follow-up instructions at the end (share the new key, etc)

> [!IMPORTANT]
> 1. While users with the old key won't be able to decrypt secrets files commited to the repo after that point (unless you share the new key with them, obviously), they will still be able to decrypt the content of files from older commits in the Git history that were encrypted with the old key.
> 2. For this reason, when you rotate your encryption key with the `key rotate` command, you will likely want to _also_ rotate the secrets these secret files contain.

---

## How it works

1. **Encryption**: When you commit a file marked for encryption, Git's "clean" filter encrypts it using AES-256-CTR before storing it in the repository.

2. **Decryption**: When you checkout a file, Git's "smudge" filter decrypts it automatically.

3. **Deterministic Encryption**: The same plaintext always encrypts to the same ciphertext (using a deterministic IV derived from the file content). This allows Git to detect when files haven't changed. (See [SECURITY.md](./SECURITY.md) for more details on the security implications of deterministic encryption.)

4. **Key Storage**: The encryption key is stored in `.git/git-conceal.key` (local to your repository clone). The file is created with secure permissions (read/write for owner only on Unix systems). It is never committed to the repository.

## Security considerations

For detailed security information, including key management, deterministic encryption implications, and security best practices, see [SECURITY.md](./SECURITY.md).

## Limitations

- **No GPG Support**: Unlike `git-crypt`, only symmetric keys are supported (no GPG key management).
- **File Metadata**: File names, commit messages, and other metadata are not encrypted.
- **File Size**: Encrypted files are not compressible by Git.

## New releases

Releases are automated by our CI every time we make a `git tag` on the repo. Be sure to update the version in the `Cargo.toml` first though.

 - Create a `release/x.y.z` branch
 - Edit `Cargo.toml` to update the `version = "x.y.z"` field
 - Run `cargo check` to update the `Cargo.lock` and validate the code still compiles
 - `git add Cargo.toml Cargo.lock` then `git commit -m "Bump version to x.y.z"`
 - Create a PR and get it merged
 - Once it has landed in `trunk`, push a new tag (`git tag "x.y.z"` then `git push origin "x.y.z"`)
 - Then let the CI build the release binaries for all platforms, create the GitHub Release, and attach the compiled binaries as assets.

## License

[MPL-2.0](./LICENSE)
