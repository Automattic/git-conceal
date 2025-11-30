use crate::crypto;
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use git2::Repository;
use std::fs;
use std::path::{Path, PathBuf};

/// Filename for the encryption key file stored in .git directory
const KEY_FILE_NAME: &str = "a8c-git-secrets.key";

/// Generate a new encryption key
pub fn generate_key() -> [u8; crypto::KEY_SIZE] {
    crypto::generate_key()
}

/// Export key as base64 string
pub fn key_to_base64(key: &[u8; crypto::KEY_SIZE]) -> String {
    general_purpose::STANDARD.encode(key)
}

/// Import key from base64 string
pub fn key_from_base64(key_b64: &str) -> Result<[u8; crypto::KEY_SIZE]> {
    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .context("Failed to decode base64 key")?;

    if key_bytes.len() != crypto::KEY_SIZE {
        anyhow::bail!(
            "Invalid key size: expected {} bytes, got {}",
            crypto::KEY_SIZE,
            key_bytes.len()
        );
    }

    let mut key = [0u8; crypto::KEY_SIZE];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Get the path to the key file in the .git directory
fn get_key_file_path(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;
    let git_dir = repo.path();
    Ok(git_dir.join(KEY_FILE_NAME))
}

/// Load the encryption key from the key file in .git directory
pub fn load_key(repo_path: &Path) -> Result<[u8; crypto::KEY_SIZE]> {
    let key_file = get_key_file_path(repo_path)?;

    let key_bytes = fs::read(&key_file).with_context(|| {
        format!(
            "Encryption key not found at {}. Run 'a8c-git-secrets unlock' first.",
            key_file.display()
        )
    })?;

    if key_bytes.len() != crypto::KEY_SIZE {
        anyhow::bail!(
            "Invalid key file size: expected {} bytes, got {}",
            crypto::KEY_SIZE,
            key_bytes.len()
        );
    }

    let mut key = [0u8; crypto::KEY_SIZE];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Store the encryption key in a file in the .git directory with secure permissions
pub fn store_key(repo_path: &Path, key: &[u8; crypto::KEY_SIZE]) -> Result<()> {
    let key_file = get_key_file_path(repo_path)?;

    // Write the key as raw bytes to the file
    fs::write(&key_file, key)
        .with_context(|| format!("Failed to write key file: {}", key_file.display()))?;

    // Set secure file permissions (read/write for owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_file)
            .with_context(|| {
                format!(
                    "Failed to get metadata for key file: {}",
                    key_file.display()
                )
            })?
            .permissions();
        perms.set_mode(0o600); // rw------- (owner read/write only)
        fs::set_permissions(&key_file, perms).with_context(|| {
            format!(
                "Failed to set permissions on key file: {}",
                key_file.display()
            )
        })?;
    }

    #[cfg(windows)]
    {
        // On Windows, file permissions work differently through ACLs
        // The file will have default permissions which are typically secure
        // in a .git directory that's already protected
        // Note: More sophisticated Windows ACL manipulation would require winapi crate
    }

    Ok(())
}

/// Remove the encryption key file from the .git directory
pub fn remove_key(repo_path: &Path) -> Result<()> {
    let key_file = get_key_file_path(repo_path)?;

    // Remove the key file, but it's okay if it doesn't exist
    if key_file.exists() {
        fs::remove_file(&key_file)
            .with_context(|| format!("Failed to remove key file: {}", key_file.display()))?;
    }

    Ok(())
}
