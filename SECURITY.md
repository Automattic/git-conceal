# Security documentation

This document provides detailed information about the security model, considerations, and implications of using `git-conceal`.

## Security considerations

### How keys are stored

The encryption key is stored in plaintext in `.git/git-conceal.key`.
Like other files in `.git/` subfolders, this file is not part of your working copy files so not at risk of being pushed to the remote repository.

The file is automatically created with secure permissions to prevent other users on your computer from accessing it:

- **Unix systems**: Mode 0600 (read/write for owner only)
- **Windows**: ACL restricted to the current user only

On Unix systems, you can verify permissions with:
```bash
ls -l .git/git-conceal.key
```

If permissions are incorrect, fix them with:
```bash
chmod 600 .git/git-conceal.key
```

### Sharing your keys

Share keys securely with collaborators (e.g., via encrypted channels, password managers, etc.).
Never commit the key file to the repository.

### Backup your keys

Always backup your encryption keys. If you lose the key, encrypted files cannot be recovered.

### File patterns

Make sure your `.gitattributes` patterns are correct before adding sensitive files, and that you didn't make any typo in the name of your `filter=git-conceal` attribute, or those files won't be encrypted!

The filters are applied at `git add` time, so files must be listed in `.gitattributes` before being staged.

You can check if a file that you added via `git add` will be encrypted once pushed to the remote by using:
```bash
git-conceal status <filename>
```

If you accidentally `git add`-ed a secret file before having the right filter for it in `.gitattributes`, you can `git restore --staged <file>` and `git add <file>` it again afterwards, or use `git add --renormalize <file>`.

## Deterministic encryption: security implications

`git-conceal` uses **deterministic encryption** (same plaintext → same ciphertext) which is necessary for git's content-addressable storage to work efficiently.

This design choice has some small security implications that is worth being aware of, even though that shouldn't cause any concerns in the context in which `git-conceal` is used in practice.

### What attackers can learn

1. **Content equality detection**: An attacker who can observe the encrypted files in the repository can determine if two files have identical content, or if a file's content hasn't changed between commits, even without the encryption key.

2. **Pattern analysis**: An attacker can identify files that are frequently updated vs. files that remain static, which may leak information about which secrets are actively used.

3. **File relationships**: By comparing encrypted file contents across commits, an attacker can detect when files are copied, moved, or when their content is synchronized.

### What remains protected

- **Actual file contents**: The actual file contents remain protected as long as the encryption key is kept secret. Without the key, attackers cannot decrypt the files.

- **Integrity**: The HMAC ensures integrity and verifies that the correct key is used for decryption. Any tampering with encrypted files will be detected.

- **Key verification**: The HMAC also serves as a key verification mechanism - if you use the wrong key, decryption will fail with an authentication error rather than producing garbage output.

### When this design is acceptable

For secrets stored in git repositories, the primary threat is typically:

- Unauthorized access to the repository (e.g., compromised git hosting service)
- Leaked repository backups
- Accidental public repository exposure

In these scenarios, deterministic encryption still protects the actual secret values. The ability to detect unchanged files is essential for git's efficiency and is a necessary trade-off for transparent encryption in version control systems.

### When this may not be sufficient

Consider alternative approaches if you need:

- **Hide file equality**: If you need to hide the fact that two files contain the same secret, consider using different keys or additional obfuscation techniques.

- **Hide update patterns**: If you need to hide update patterns (e.g., to prevent attackers from knowing which secrets are actively maintained), consider using a different encryption scheme. Note that this would break git's content deduplication and significantly impact repository size.

- **Protection against active attackers**: If you're protecting against attackers who can observe your repository in real-time and correlate changes with external events, deterministic encryption may leak timing information.

### Technical details

The encryption uses:
- **Algorithm**: AES-256-CTR (Counter Mode) is used for the encryption of the data.
- **IV derivation**: SHA-256 hash of the plaintext. The first 16 bytes are used as the Input Vector.
- **Authentication**: HMAC-SHA256 over the entire ciphertext (magic header + version + IV + encrypted data) is used as a signature to validate the data hasn't been tampered with.
- **Key derivation**: HMAC key is derived from the encryption key using HKDF-SHA256, for proper key separation.

This ensures that:
- The same plaintext always produces the same ciphertext (required for git)
- The encryption key and HMAC key are cryptographically separated
- Any modification to the encrypted data is detected
- Using the wrong key results in authentication failure, not garbage output

