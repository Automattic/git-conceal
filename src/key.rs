use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;

/// Symmetric key for encryption/decryption
///
/// This type wraps the raw key bytes and provides a safe API for key operations.
/// The underlying representation is only exposed when needed for cryptographic operations.
#[derive(Clone, Debug)]
pub struct Key {
    bytes: [u8; Self::KEY_SIZE],
}

impl Key {
    /// Size of the encryption key in bytes (256 bits for AES-256)
    pub const KEY_SIZE: usize = 32;

    /// Create a new Key from raw bytes
    ///
    /// This is primarily used internally when constructing keys from various sources.
    pub fn from_bytes(bytes: [u8; Self::KEY_SIZE]) -> Self {
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

// === Private Helper functions === //

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

// === Tests === //

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Constant test key bytes for deterministic testing
    const TEST_KEY_BYTES: [u8; Key::KEY_SIZE] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    /// Get a constant test key
    fn test_key() -> Key {
        Key::from_bytes(TEST_KEY_BYTES)
    }

    #[test]
    fn test_key_size() {
        assert_eq!(Key::KEY_SIZE, 32);
    }

    #[test]
    fn test_from_bytes() {
        let key = Key::from_bytes(TEST_KEY_BYTES);
        assert_eq!(key.as_bytes(), &TEST_KEY_BYTES);
    }

    #[test]
    fn test_generate() {
        let key1 = Key::generate();
        let key2 = Key::generate();

        // Keys should be the correct size
        assert_eq!(key1.as_bytes().len(), Key::KEY_SIZE);
        assert_eq!(key2.as_bytes().len(), Key::KEY_SIZE);

        // Keys should be different (very unlikely to be the same)
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_to_base64() {
        let key = test_key();
        let b64 = key.to_base64();

        assert!(!b64.is_empty());
        assert!(b64
            .chars()
            .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn test_from_base64() {
        let key = test_key();
        let b64 = key.to_base64();

        let decoded_key = Key::from_base64(&b64).unwrap();
        assert_eq!(decoded_key.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_base64_roundtrip() {
        let original_key = test_key();
        let b64 = original_key.to_base64();
        let decoded_key = Key::from_base64(&b64).unwrap();

        assert_eq!(original_key.as_bytes(), decoded_key.as_bytes());
    }

    #[test]
    fn test_from_base64_invalid_base64() {
        let result = Key::from_base64("not valid base64!!!");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode base64 key"));
    }

    #[test]
    fn test_from_base64_wrong_size() {
        // Base64 of 16 bytes (too short)
        let short_b64 = "dGVzdC1rZXktMTYtYnl0ZXM="; // "test-key-16-bytes"
        let result = Key::from_base64(short_b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key size"));
    }

    #[test]
    fn test_from_base64_empty_string() {
        let result = Key::from_base64("");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_base64_with_whitespace() {
        let key = test_key();
        let b64 = key.to_base64();

        // Test with leading/trailing whitespace (should be trimmed in read_from_source)
        let decoded_key = Key::from_base64(&format!("  {}  ", b64));
        // Note: from_base64 doesn't trim, but read_from_source does
        // So this should fail, but read_from_source with env: should work
        assert!(decoded_key.is_err());
    }

    #[test]
    fn test_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        let key = test_key();
        fs::write(&key_file, key.as_bytes()).unwrap();

        let loaded_key = Key::from_file(&key_file).unwrap();
        assert_eq!(loaded_key.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_from_file_nonexistent() {
        let result = Key::from_file(Path::new("/nonexistent/path/key.bin"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read key from file"));
    }

    #[test]
    fn test_from_file_wrong_size() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        // Write a file with wrong size
        fs::write(&key_file, vec![0u8; 16]).unwrap();

        let result = Key::from_file(&key_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key size"));
    }

    #[test]
    fn test_from_file_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        fs::write(&key_file, vec![]).unwrap();

        let result = Key::from_file(&key_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key size"));
    }

    #[test]
    fn test_from_file_too_large() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        // Write a file with too many bytes
        fs::write(&key_file, vec![0u8; 64]).unwrap();

        let result = Key::from_file(&key_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key size"));
    }

    #[test]
    fn test_read_from_source_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        let key = test_key();
        fs::write(&key_file, key.as_bytes()).unwrap();

        let loaded_key = Key::read_from_source(key_file.to_str().unwrap()).unwrap();
        assert_eq!(loaded_key.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_read_from_source_env() {
        let key = test_key();
        let b64 = key.to_base64();

        // Set environment variable
        std::env::set_var("TEST_KEY_VAR", &b64);

        let loaded_key = Key::read_from_source("env:TEST_KEY_VAR").unwrap();
        assert_eq!(loaded_key.as_bytes(), key.as_bytes());

        // Clean up
        std::env::remove_var("TEST_KEY_VAR");
    }

    #[test]
    fn test_read_from_source_env_with_whitespace() {
        let key = test_key();
        let b64 = key.to_base64();

        // Set environment variable with whitespace
        std::env::set_var("TEST_KEY_VAR", &format!("  {}  ", b64));

        let loaded_key = Key::read_from_source("env:TEST_KEY_VAR").unwrap();
        assert_eq!(loaded_key.as_bytes(), key.as_bytes());

        // Clean up
        std::env::remove_var("TEST_KEY_VAR");
    }

    #[test]
    fn test_read_from_source_env_nonexistent() {
        // Make sure the variable doesn't exist
        std::env::remove_var("NONEXISTENT_VAR");

        let result = Key::read_from_source("env:NONEXISTENT_VAR");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read key from environment variable"));
    }

    #[test]
    fn test_read_from_source_env_empty_name() {
        let result = Key::read_from_source("env:");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Environment variable name cannot be empty"));
    }

    // Note: Testing stdin reading is complex in unit tests as it requires
    // mocking stdin or using a separate process. This would be better suited
    // for integration tests. The file and env var cases are tested above.

    #[test]
    fn test_read_from_source_invalid_source() {
        let result = Key::read_from_source("/nonexistent/path/key.bin");
        assert!(result.is_err());
    }

    #[test]
    fn test_as_bytes() {
        let key = test_key();
        let bytes = key.as_bytes();

        assert_eq!(bytes.len(), Key::KEY_SIZE);
        assert_eq!(bytes, &TEST_KEY_BYTES);
    }

    #[test]
    fn test_deref() {
        let key = test_key();
        let bytes: &[u8; Key::KEY_SIZE] = &*key;

        assert_eq!(bytes, &TEST_KEY_BYTES);
    }

    #[test]
    fn test_clone() {
        let key1 = test_key();
        let key2 = key1.clone();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
        // Verify they are independent (modify one, other unchanged)
        // Since Key doesn't have interior mutability, we can't easily test this,
        // but clone should work correctly
    }

    #[test]
    fn test_multiple_generate_keys_unique() {
        let mut keys = Vec::new();
        for _ in 0..10 {
            keys.push(Key::generate());
        }

        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].as_bytes(), keys[j].as_bytes());
            }
        }
    }

    #[test]
    fn test_base64_encoding_consistency() {
        let key = test_key();
        let b64_1 = key.to_base64();
        let b64_2 = key.to_base64();

        // Same key should produce same base64 encoding
        assert_eq!(b64_1, b64_2);
    }

    #[test]
    fn test_key_equality_via_bytes() {
        let key1 = Key::from_bytes(TEST_KEY_BYTES);
        let key2 = Key::from_bytes(TEST_KEY_BYTES);

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_inequality() {
        let key1 = test_key();
        let mut different_bytes = TEST_KEY_BYTES;
        different_bytes[0] ^= 0xFF; // Flip first byte
        let key2 = Key::from_bytes(different_bytes);

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_multiple_base64_decodings() {
        let key = test_key();
        let b64 = key.to_base64();

        // Decode multiple times, should get same result
        let decoded1 = Key::from_base64(&b64).unwrap();
        let decoded2 = Key::from_base64(&b64).unwrap();
        let decoded3 = Key::from_base64(&b64).unwrap();

        assert_eq!(decoded1.as_bytes(), key.as_bytes());
        assert_eq!(decoded2.as_bytes(), key.as_bytes());
        assert_eq!(decoded3.as_bytes(), key.as_bytes());
    }
}
