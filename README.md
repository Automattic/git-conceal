# a8c-git-secrets

This tool provides transparent encryption of files in git repositories using a symmetric key.
Its goal is to allow you to store some secret files as encrypted in an otherwise public repo.

It has been inspired by [git-crypt](https://github.com/AGWA/git-crypt), but written in Rust to have first-class cross-platform support.

## Features

 - **Transparent encryption/decryption**: Files are automatically encrypted on commit and decrypted on checkout, thanks to [git filters built-in feature](https://git-scm.com/docs/gitattributes#_filter)
 - **Symmetric key encryption**: Uses AES-256-CTR with deterministic IVs (compatible with git's change detection)
 - **Supports key rotation**: If your key gets leaked or a coworker leaves your team, you can rotate your secrets and encryption key easily
 - **Cross-platform**: Works on macOS, Linux, and Windows

## Overview

 - After you run `a8c-git-secrets init` to generate a cryptographic key and configure your working copy, just list the files you want to encrypt on commit in your `.gitattributes` file.
 - At that point, files will be in clear text in your working copy (since you have the key locally)—so e.g. your compiler will be able use them just like any other file—but it will be encrypted on the fly by `git` on `commit`—so that only the encrypted content is stored in the repository (object database and remote repos)
 - On subsequent `git checkout`, only if the user doing the `checkout` has the filters and key configured on their machine will the content be decrypted in their local working copy.

You can learn more about technical details of how git filter works in [this article](https://mobile.blog/2025/11/13/git-filters-diff-drivers-a-technical-overview/).

## Installation

### Build from Source

```bash
git clone <repository-url>
cd a8c-git-secrets
cargo build --release
```

The binary will be at `target/release/a8c-git-secrets` (or `target/release/a8c-git-secrets.exe` on Windows).

### Download from GitHub Release

Download the pre-build binary suitable for your platform (Linux, macOS, Windows) from the latest GitHub release.
Then rename it `a8c-git-secrets` and save it ideally in a directory in your `$PATH` (e.g. `/usr/local/bin`). That's it!

## Usage

### Initialize a Repository

To set up encryption for a git repository that doesn't use this tool yet:

```bash
cd /path/to/your/repo
a8c-git-secrets init
```

This will:
- Generate a new 256-bit encryption key
- Store the key in `.git/a8c-git-secrets.key` with secure file permissions.
- Configure git filters for encryption/decryption
- Display the key so you can share it with your coworkers.

You will only have to do this once.

> [!IMPORTANT]
> Save the displayed key securely! You'll need it to unlock the repository on other machines or share it with collaborators.

### Configure Files to Encrypt

Create or edit `.gitattributes` in your repository root to specify which files should be encrypted by adding the `filter=a8c-git-secrets` attribute to them, for example:

```
# Encrypt specific files
secretfile filter=a8c-git-secrets diff=a8c-git-secrets
config/secrets.yml filter=a8c-git-secrets diff=a8c-git-secrets

# Encrypt all files with specific extensions
*.key filter=a8c-git-secrets diff=a8c-git-secrets
*.pem filter=a8c-git-secrets diff=a8c-git-secrets
*.p12 filter=a8c-git-secrets diff=a8c-git-secrets

# Encrypt all files in a directory (use ** to match recursively)
secrets/** filter=a8c-git-secrets diff=a8c-git-secrets
private/** filter=a8c-git-secrets diff=a8c-git-secrets
```

> [!IMPORTANT]
> Make sure `.gitattributes` itself is NOT encrypted! If needed, you can explicitly exclude it:

```
.gitattributes !filter !diff
```

### Add new files

At that point, when you will `git add` a file to that repo that matches one of the `filter=a8c-git-secrets` pattern, that file's blob/content will be encrypted on the fly by git.

> [!IMPORTANT]
> Make sure the file pattern is listed in `.gitattributes` _before_ you `git add` the file containing secrets, as the git filters are applied at the time you `git add`.

> [!TIP]
> If you forgot to add a file pattern in `.gitattributes` before  `git add`-ing a file, you can either remove the file from the staging area and re-add it again, or use `git add --renormalize <file>`

### Verify if files are encrypted

To give you peace of mind and validate that files you added to your repo are processed by the git filter, you can use `a8c-git-secrets status` (to list all the files that will go through the encryption filter) or `a8c-git-secrets status <file>` to check a specific file. This command will validate that the file would match a pattern of your `.gitattributes` that has the `filter=a8c-git-secrets` attribute set.

You can also check what the blob content of the corresponding object looks like in the repository database by using `git show :<file>` (or `git show HEAD:<file>` if it's commited into `HEAD` already).
This will show the raw content as stored in the repository. So even if `cat my-secret-file.txt` will show you the clear text locally (assuming you have unlocked your working copy with the right key), `git show :my-secret-file.txt` will show you the raw, encrypted binary data stored in the repository (assuming that file matches a `.gitattributes` pattern with `filter=a8c-git-secrets` set)

### Unlock a Repository

After you freshly clone a repository which contains files which has been encrypted by `a8c-git-secrets`, you need to provide the symmetric key that your coworkers would have shared with you to decrypt it:

```bash
# Option 1: Provide the key via an environment variable (base64 encoded)
export GIT_SECRETS_KEY="YOUR_BASE64_KEY"
a8c-git-secrets unlock env:GIT_SECRETS_KEY

# Option 2: Provide a path to a from file containing the raw binary, 32 bytes key
a8c-git-secrets unlock /path/to/key.bin

# Option 3: Provide it via stdin (expects raw binary, 32 bytes as input)
cat /path/to/key.bin | a8c-git-secrets unlock -
# Or convert from base64:
echo "YOUR_BASE64_KEY" | base64 -d | a8c-git-secrets unlock -
```

This will:
- Store the key in `.git/a8c-git-secrets.key` with secure file permissions
- Set up git filters in the git config of this working copy (if not already configured)
- Decrypt all encrypted files in the working directory

> [!NOTE]
> Unlocking a repository can take a while if the repository has a lot of files, because `a8c-git-secrets` needs to check every file in the repository (`git ls-files`) and for each check if it has the `filter` attribute or not, to know which files to decrypt. Once you've run the `unlock` command, you won't need to run it again (unless you run `lock` at some point), and checkouts won't be affected by the delay because git will 

### Lock a Repository

To remove the encryption key file from the local working copy and restore the content of the local files to their encrypted content, you can "lock" your working copy:

```bash
a8c-git-secrets lock
a8c-git-secrets lock --force # to ignore local changes if any
```

> [!TIP]
> This can be useful in the rare case where you need to switch between branches that contain secret files that were encrypted with different keys (see "key rotation" below), to avoid errors during the git operations while git processes files from branch A that were encrypted with keyA and tries to decrypt them with the keyB that was used back in branch B.
> This is pretty rare to rotate keys though, so should be very uncommon to have to lock a repository in your everyday workflow.

### Check Files Status

To see the current encryption status:

```bash
a8c-git-secrets status
```

This shows:
- Whether the repository is locked or unlocked
- Whether filters are configured
- Which file patterns are encrypted (from `.gitattributes`)

```bash
a8c-git-secrets status <FILES>
```

This shows the status of each file (i.e. if it will be processed by the files according to the `.gitattributes` or not)

### Show the encryption key

If you need to show the local symmetric encryption key you are using in your local working copy, typically so you can share it with your coworkers so that they can decrypt their working copy too:

```bash
a8c-git-secrets key show
```

### Rotate the encryption key

If your symmetric encryption key has leaked somehow, or if one of your coworkers leaves your team/company and you want to rotate your secrets to ensure they can't access your new secrets anymore even if they had the key at some point, there's an easy way to rotate the encryption key used by an encrypted repo:

```bash
a8c-git-secrets key rotate
```

Your working copy has to be unlocked with the current key before you can call this command.

This command will explain the impacts of rotating the key and ask for confirmation, then generate a new key, re-encrypt the encrypted files with the new key, and mark them as changed in the git index, ready for you to commit them, providing you follow-up instructions at the end (share the new key, etc)

> [!IMPORTANT]
> 1. While users with the old key won't be able to decrypt secrets files commited to the repo after that point (unless you share the new key with them, obviously), they will still be able to decrypt the content of files from older commits in the git history that were encrypted with the old key.
> 2. For this reason, when you rotate your encryption key with the `key rotate` command, you will likely want to _also_ rotate the secrets these secret files contain.

---

## How It Works

1. **Encryption**: When you commit a file marked for encryption, git's "clean" filter encrypts it using AES-256-CTR before storing it in the repository.

2. **Decryption**: When you checkout a file, git's "smudge" filter decrypts it automatically.

3. **Deterministic Encryption**: The same plaintext always encrypts to the same ciphertext (using a deterministic IV derived from the file content). This allows git to detect when files haven't changed.

4. **Key Storage**: The encryption key is stored in `.git/a8c-git-secrets.key` (local to your repository clone). The file is created with secure permissions (read/write for owner only on Unix systems). It is never committed to the repository.

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

- **No GPG Support**: Unlike `git-crypt`, only symmetric keys are supported (no GPG key management).
- **File Metadata**: File names, commit messages, and other metadata are not encrypted.
- **File Size**: Encrypted files are not compressible by git.


## License

MIT
