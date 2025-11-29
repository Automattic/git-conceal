use crate::crypto;
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use git2::Repository;
use std::path::Path;

const KEY_SIZE: usize = 32;
pub const CONFIG_KEY_NAME: &str = "a8c-git-secrets.key";

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

/// Load the encryption key from git config
pub fn load_key_from_config(repo_path: &Path) -> Result<[u8; KEY_SIZE]> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let config = repo.config().context("Failed to get git config")?;

    let key_b64 = config
        .get_string(CONFIG_KEY_NAME)
        .context("Encryption key not found in git config. Run 'a8c-git-secrets unlock' first.")?;

    key_from_base64(&key_b64).context("Failed to decode base64 key from git config")
}

/// Store the encryption key in git config
pub fn store_key_in_config(repo_path: &Path, key: &[u8; KEY_SIZE]) -> Result<()> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let mut config = repo.config().context("Failed to get git config")?;

    let key_b64 = key_to_base64(key);
    config
        .set_str(CONFIG_KEY_NAME, &key_b64)
        .context("Failed to store key in git config")?;

    Ok(())
}

/// Remove the encryption key from git config
pub fn remove_key_from_config(repo_path: &Path) -> Result<()> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let mut config = repo.config().context("Failed to get git config")?;

    // Remove the key (ignore error if it doesn't exist)
    let _ = config.remove(CONFIG_KEY_NAME);

    Ok(())
}
