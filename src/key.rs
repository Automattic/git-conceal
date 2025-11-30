use crate::crypto;
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use git2::Repository;
use std::fs;
use std::io::Read;
use std::ops::Deref;
use std::path::{Path, PathBuf};

/// Filename for the encryption key file stored in .git directory
const KEY_FILE_NAME: &str = "a8c-git-secrets.key";

/// Encryption key for a8c-git-secrets
///
/// This type wraps the raw key bytes and provides a safe API for key operations.
/// The underlying representation is only exposed when needed for cryptographic operations.
#[derive(Clone)]
pub struct Key {
    bytes: [u8; crypto::KEY_SIZE],
}

impl Key {
    /// Generate a new random encryption key
    pub fn generate() -> Self {
        Self {
            bytes: crypto::generate_key(),
        }
    }

    /// Load the encryption key from the key file in .git directory
    pub fn load(repo_path: &Path) -> Result<Self> {
        let key_file = get_key_file_path(repo_path)?;

        read_key_from_file(&key_file).with_context(|| {
            format!(
                "Encryption key not found at {}. Run 'a8c-git-secrets unlock' first.",
                key_file.display()
            )
        })
    }

    /// Store the encryption key in a file in the .git directory with secure permissions
    pub fn store(&self, repo_path: &Path) -> Result<()> {
        let key_file = get_key_file_path(repo_path)?;

        // Write the key as raw bytes to the file
        fs::write(&key_file, self.bytes)
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
    pub fn remove(repo_path: &Path) -> Result<()> {
        let key_file = get_key_file_path(repo_path)?;

        // Remove the key file, but it's okay if it doesn't exist
        if key_file.exists() {
            fs::remove_file(&key_file)
                .with_context(|| format!("Failed to remove key file: {}", key_file.display()))?;
        }

        Ok(())
    }

    /// Export key as base64 string
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.bytes)
    }

    /// Import key from base64 string
    pub fn from_base64(key_b64: &str) -> Result<Self> {
        let key_bytes = general_purpose::STANDARD
            .decode(key_b64)
            .context("Failed to decode base64 key")?;
        bytes_to_key(key_bytes).context("Invalid key size from base64")
    }

    /// Read encryption key from various sources
    ///
    /// Supports:
    /// - `"-"` for reading from stdin (raw binary format, 32 bytes)
    /// - `"env:VARNAME"` for reading from environment variable (base64 encoded)
    /// - File path for reading from a file (raw binary format, 32 bytes)
    ///
    /// Returns the encryption key.
    pub fn read_from_source(key_source: &str) -> Result<Self> {
        if key_source == "-" {
            // Read from stdin (raw binary format)
            let mut key_bytes = Vec::new();
            std::io::stdin()
                .read_to_end(&mut key_bytes)
                .context("Failed to read key from stdin")?;
            bytes_to_key(key_bytes).context("Invalid key size from stdin")
        } else if let Some(env_var) = key_source.strip_prefix("env:") {
            // Read from environment variable (base64 encoded, format: env:VARNAME)
            if env_var.is_empty() {
                anyhow::bail!("Environment variable name cannot be empty after 'env:'");
            }
            let key_b64 = std::env::var(env_var).with_context(|| {
                format!("Failed to read key from environment variable {}", env_var)
            })?;
            Self::from_base64(key_b64.trim())
        } else {
            // Read from file (raw binary format)
            read_key_from_file(Path::new(key_source))
                .with_context(|| format!("Failed to read key from file: {}", key_source))
        }
    }

    /// Get a reference to the underlying key bytes
    ///
    /// This is primarily used for cryptographic operations that need direct access
    /// to the raw key material.
    pub fn as_bytes(&self) -> &[u8; crypto::KEY_SIZE] {
        &self.bytes
    }
}

impl Deref for Key {
    type Target = [u8; crypto::KEY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Get the path to the key file in the .git directory
fn get_key_file_path(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;
    let git_dir = repo.path();
    Ok(git_dir.join(KEY_FILE_NAME))
}

/// Convert a byte vector to a key array, validating the length
fn bytes_to_key(key_bytes: Vec<u8>) -> Result<Key> {
    if key_bytes.len() != crypto::KEY_SIZE {
        anyhow::bail!(
            "Invalid key size: expected {} bytes, got {}",
            crypto::KEY_SIZE,
            key_bytes.len()
        );
    }

    let mut bytes = [0u8; crypto::KEY_SIZE];
    bytes.copy_from_slice(&key_bytes);
    Ok(Key { bytes })
}

/// Read encryption key from a file (raw binary format)
fn read_key_from_file(file_path: &Path) -> Result<Key> {
    let key_bytes = fs::read(file_path)
        .with_context(|| format!("Failed to read key from file: {}", file_path.display()))?;
    bytes_to_key(key_bytes)
}
