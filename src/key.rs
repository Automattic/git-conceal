use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::fmt::Display;
use std::fs;
use std::path::Path;

/// Symmetric key for encryption/decryption
///
/// This type wraps the raw key bytes and provides a safe API for key operations.
/// (The underlying raw bytes should only be needed when calling low-level cryptographic operations.)
#[must_use]
#[derive(Clone, Debug)]
pub struct Key {
    bytes: [u8; Self::KEY_SIZE],
}

impl Key {
    /// Size of the encryption key in bytes (256 bits for AES-256)
    pub const KEY_SIZE: usize = 32;

    /// Generate a new random encryption key
    ///
    /// # Errors
    /// Returns an error if the OS random number generator fails to generate the key bytes.
    pub fn generate() -> Result<Self> {
        let bytes_vec = crate::crypto::generate_key_bytes(Self::KEY_SIZE)?;
        let mut bytes = [0u8; Self::KEY_SIZE];
        bytes.copy_from_slice(&bytes_vec);
        Ok(Self::from(bytes))
    }
}

// === Conversion Traits === //

/// Get a reference to the underlying key bytes
///
/// This is primarily used for cryptographic operations that need direct access
/// to the raw key material.
impl AsRef<[u8; Self::KEY_SIZE]> for Key {
    fn as_ref(&self) -> &[u8; Self::KEY_SIZE] {
        &self.bytes
    }
}

/// Create a new Key from raw bytes
///
/// This is primarily used internally when constructing keys from various sources.
impl From<[u8; Self::KEY_SIZE]> for Key {
    fn from(bytes: [u8; Self::KEY_SIZE]) -> Self {
        Self { bytes }
    }
}

/// Try to convert a byte slice of arbitrary length to a Key, validating the length is correct
impl TryFrom<&[u8]> for Key {
    type Error = anyhow::Error;
    fn try_from(slice: &[u8]) -> Result<Key> {
        let key_bytes: [u8; Key::KEY_SIZE] = slice.try_into().with_context(|| {
            format!(
                "Invalid key size: expected {} bytes, got {}",
                Key::KEY_SIZE,
                slice.len()
            )
        })?;
        Ok(Key::from(key_bytes))
    }
}

/// Read encryption key from a file (raw binary format, 32 bytes)
impl TryFrom<&Path> for Key {
    type Error = anyhow::Error;
    fn try_from(path: &Path) -> Result<Self> {
        let key_bytes = fs::read(path)
            .with_context(|| format!("Failed to read key from file: {}", path.display()))?;
        Key::try_from(key_bytes.as_slice())
            .with_context(|| format!("Invalid key size in file: {}", path.display()))
    }
}

/// Create a key from a base64-encoded string
///
/// The input string is automatically trimmed of leading and trailing whitespace
/// to handle cases where base64 strings are copied with extra whitespace.
impl TryFrom<&str> for Key {
    type Error = anyhow::Error;
    fn try_from(key_b64: &str) -> Result<Self> {
        let key_bytes = general_purpose::STANDARD
            .decode(key_b64.trim())
            .context("Failed to decode base64 key")?;
        Key::try_from(key_bytes.as_slice()).context("Invalid size for key decoded from base64")
    }
}

/// Export key as base64 string
impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", general_purpose::STANDARD.encode(self.bytes))
    }
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
        Key::from(TEST_KEY_BYTES)
    }

    #[test]
    fn test_key_size() {
        assert_eq!(Key::KEY_SIZE, 32);
    }

    #[test]
    fn test_generate() {
        let key1 = Key::generate().unwrap();
        let key2 = Key::generate().unwrap();

        // Keys should be the correct size
        assert_eq!(key1.as_ref().len(), Key::KEY_SIZE);
        assert_eq!(key2.as_ref().len(), Key::KEY_SIZE);

        // Keys should be different (very unlikely to be the same)
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_multiple_generate_keys_unique() {
        let mut keys = Vec::new();
        for _ in 0..10 {
            keys.push(Key::generate().unwrap());
        }

        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].as_ref(), keys[j].as_ref());
            }
        }
    }

    #[test]
    fn test_as_ref() {
        let key = test_key();
        let bytes = key.as_ref();

        assert_eq!(bytes.len(), Key::KEY_SIZE);
        assert_eq!(bytes, &TEST_KEY_BYTES);
    }

    #[test]
    fn test_from_bytes() {
        let key = Key::from(TEST_KEY_BYTES);
        assert_eq!(key.as_ref(), &TEST_KEY_BYTES);
    }

    #[test]
    fn test_try_from_unsized_bytes() {
        let unsized_bytes: &[u8] = &TEST_KEY_BYTES;
        let key = Key::try_from(unsized_bytes).unwrap();
        assert_eq!(key.as_ref(), &TEST_KEY_BYTES);
    }

    #[test]
    fn test_try_from_path() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        let key = test_key();
        fs::write(&key_file, key.as_ref()).unwrap();

        let loaded_key = Key::try_from(key_file.as_path()).unwrap();
        assert_eq!(loaded_key.as_ref(), key.as_ref());
    }

    #[test]
    fn test_try_from_path_nonexistent() {
        let result = Key::try_from(Path::new("/nonexistent/path/key.bin"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read key from file"));
    }

    #[test]
    fn test_try_from_path_wrong_size() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        // Write a file with wrong size
        fs::write(&key_file, vec![0u8; 16]).unwrap();

        let result = Key::try_from(key_file.as_path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key size"));
    }

    #[test]
    fn test_try_from_path_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        fs::write(&key_file, vec![]).unwrap();

        let result = Key::try_from(key_file.as_path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key size"));
    }

    #[test]
    fn test_try_from_path_too_large() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        // Write a file with too many bytes
        fs::write(&key_file, vec![0u8; 64]).unwrap();

        let result = Key::try_from(key_file.as_path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key size"));
    }

    #[test]
    fn test_try_from_string_base64() {
        let key = test_key();
        let b64 = key.to_string();

        let decoded_key = Key::try_from(b64.as_str()).unwrap();
        assert_eq!(decoded_key.as_ref(), key.as_ref());
    }

    #[test]
    fn test_try_from_string_base64_invalid_base64() {
        let result = Key::try_from("not valid base64!!!");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode base64 key"));
    }

    #[test]
    fn test_try_from_string_base64_wrong_size() {
        // Base64 of 16 bytes (too short)
        let short_b64 = "dGVzdC1rZXktMTYtYnl0ZXM="; // "test-key-16-bytes"
        let result = Key::try_from(short_b64);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid size for key decoded from base64"
        );
    }

    #[test]
    fn test_try_from_string_base64_empty_string() {
        let result = Key::try_from("");
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_string_base64_with_whitespace() {
        let key = test_key();
        let b64 = key.to_string();

        // Test with leading/trailing whitespace (should be automatically trimmed)
        let decoded_key = Key::try_from(format!("  {}  ", b64).as_str()).unwrap();
        assert_eq!(decoded_key.as_ref(), key.as_ref());

        // Test with newlines and tabs
        let decoded_key2 = Key::try_from(format!("\n\t{}\n\t", b64).as_str()).unwrap();
        assert_eq!(decoded_key2.as_ref(), key.as_ref());
    }

    #[test]
    fn test_to_string_base64() {
        let key = test_key();
        let b64 = key.to_string();

        assert!(!b64.is_empty());
        assert!(b64
            .chars()
            .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn test_to_string_base64_encoding_consistency() {
        let key = test_key();
        let b64_1 = key.to_string();
        let b64_2 = key.to_string();

        // Same key should produce same base64 encoding
        assert_eq!(b64_1, b64_2);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original_key = test_key();
        let b64 = original_key.to_string();
        let decoded_key = Key::try_from(b64.as_str()).unwrap();

        assert_eq!(original_key.as_ref(), decoded_key.as_ref());
    }

    #[test]
    fn test_multiple_base64_decodings() {
        let key = test_key();
        let b64 = key.to_string();

        // Decode multiple times, should get same result
        let decoded1 = Key::try_from(b64.as_str()).unwrap();
        let decoded2 = Key::try_from(b64.as_str()).unwrap();
        let decoded3 = Key::try_from(b64.as_str()).unwrap();

        assert_eq!(decoded1.as_ref(), key.as_ref());
        assert_eq!(decoded2.as_ref(), key.as_ref());
        assert_eq!(decoded3.as_ref(), key.as_ref());
    }

    #[test]
    fn test_key_equality_via_bytes() {
        let key1 = Key::from(TEST_KEY_BYTES);
        let key2 = Key::from(TEST_KEY_BYTES);

        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_key_inequality() {
        let key1 = test_key();
        let mut different_bytes = TEST_KEY_BYTES;
        different_bytes[0] ^= 0xFF; // Flip first byte
        let key2 = Key::from(different_bytes);

        assert_ne!(key1.as_ref(), key2.as_ref());
    }
}
