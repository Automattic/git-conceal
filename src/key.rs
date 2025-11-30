use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;

/// Encryption key for a8c-git-secrets
///
/// This type wraps the raw key bytes and provides a safe API for key operations.
/// The underlying representation is only exposed when needed for cryptographic operations.
#[derive(Clone)]
pub struct Key {
    bytes: [u8; Self::KEY_SIZE],
}

impl Key {
    /// Size of the encryption key in bytes (256 bits for AES-256)
    pub const KEY_SIZE: usize = 32;

    /// Create a new Key from raw bytes
    ///
    /// This is primarily used internally when constructing keys from various sources.
    pub(crate) fn from_bytes(bytes: [u8; Self::KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Generate a new random encryption key
    pub fn generate() -> Self {
        let bytes_vec = crate::crypto::generate_key_bytes(Self::KEY_SIZE);
        let mut bytes = [0u8; Self::KEY_SIZE];
        bytes.copy_from_slice(&bytes_vec);
        Self::from_bytes(bytes)
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

    /// Read encryption key from a file (raw binary format, 32 bytes)
    pub fn from_file(file_path: &Path) -> Result<Self> {
        let key_bytes = fs::read(file_path)
            .with_context(|| format!("Failed to read key from file: {}", file_path.display()))?;
        bytes_to_key(key_bytes)
            .with_context(|| format!("Invalid key size in file: {}", file_path.display()))
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
            Self::from_file(Path::new(key_source))
        }
    }

    /// Get a reference to the underlying key bytes
    ///
    /// This is primarily used for cryptographic operations that need direct access
    /// to the raw key material.
    pub fn as_bytes(&self) -> &[u8; Self::KEY_SIZE] {
        &self.bytes
    }
}

impl Deref for Key {
    type Target = [u8; Self::KEY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Convert a byte vector to a key array, validating the length
fn bytes_to_key(key_bytes: Vec<u8>) -> Result<Key> {
    if key_bytes.len() != Key::KEY_SIZE {
        anyhow::bail!(
            "Invalid key size: expected {} bytes, got {}",
            Key::KEY_SIZE,
            key_bytes.len()
        );
    }

    let mut bytes = [0u8; Key::KEY_SIZE];
    bytes.copy_from_slice(&key_bytes);
    Ok(Key::from_bytes(bytes))
}
