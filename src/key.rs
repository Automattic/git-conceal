use crate::crypto;
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::path::Path;

const KEY_SIZE: usize = 32;

/// Load the encryption key from git config
pub fn load_key_from_config(repo_path: &Path) -> Result<[u8; KEY_SIZE]> {
    use git2::Repository;

    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let config = repo.config().context("Failed to get git config")?;

    let key_b64 = config
        .get_string("a8c-git-secrets.key")
        .context("Encryption key not found in git config. Run 'a8c-git-secrets unlock' first.")?;

    let key_bytes = general_purpose::STANDARD
        .decode(&key_b64)
        .context("Failed to decode base64 key from git config")?;

    if key_bytes.len() != KEY_SIZE {
        anyhow::bail!(
            "Invalid key size: expected {} bytes, got {}",
            KEY_SIZE,
            key_bytes.len()
        );
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Store the encryption key in git config
pub fn store_key_in_config(repo_path: &Path, key: &[u8; KEY_SIZE]) -> Result<()> {
    use git2::Repository;

    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let mut config = repo.config().context("Failed to get git config")?;

    let key_b64 = general_purpose::STANDARD.encode(key);
    config
        .set_str("a8c-git-secrets.key", &key_b64)
        .context("Failed to store key in git config")?;

    Ok(())
}

/// Generate a new encryption key
pub fn generate_key() -> [u8; KEY_SIZE] {
    crypto::generate_key()
}

/// Export key as base64 string
pub fn key_to_base64(key: &[u8; KEY_SIZE]) -> String {
    general_purpose::STANDARD.encode(key)
}

/// Import key from base64 string
pub fn key_from_base64(key_b64: &str) -> Result<[u8; KEY_SIZE]> {
    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .context("Failed to decode base64 key")?;

    if key_bytes.len() != KEY_SIZE {
        anyhow::bail!(
            "Invalid key size: expected {} bytes, got {}",
            KEY_SIZE,
            key_bytes.len()
        );
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Read key from stdin or environment variable
pub fn read_key_from_input(env_var: Option<&str>) -> Result<[u8; KEY_SIZE]> {
    // First try environment variable if provided
    if let Some(var) = env_var {
        if let Ok(key_str) = std::env::var(var) {
            return key_from_base64(key_str.trim());
        }
    }

    // Otherwise read from stdin
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("Failed to read key from stdin")?;

    key_from_base64(input.trim())
}

use std::io::Read;

/// Remove the encryption key from git config
pub fn remove_key_from_config(repo_path: &Path) -> Result<()> {
    use git2::Repository;

    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let mut config = repo.config().context("Failed to get git config")?;

    // Remove the key (ignore error if it doesn't exist)
    let _ = config.remove("a8c-git-secrets.key");

    Ok(())
}
