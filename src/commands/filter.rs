use crate::crypto;
use crate::key::Key;
use crate::repo::Repo;
use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Read, Write};

/// Git clean filter: encrypt data from stdin and write to stdout
/// This filter is idempotent: clean(clean(data)) == clean(data)
/// If the input is already encrypted (has magic header), it passes through unchanged.
pub fn clean_filter(repo: &Repo) -> Result<()> {
    let key = repo.load_key().context("Failed to load encryption key")?;
    let input = read_stdin()?;
    let output = apply_clean_filter(&key, &input)?;
    io::stdout()
        .write_all(&output)
        .context("Failed to write to stdout")?;
    Ok(())
}

/// Git smudge filter: decrypt data from stdin and write to stdout
/// This filter is idempotent: smudge(smudge(data)) == smudge(data)
/// If the input is already plaintext (no magic header), it passes through unchanged.
pub fn smudge_filter(repo: &Repo) -> Result<()> {
    let key = repo.load_key().context("Failed to load encryption key")?;
    let input = read_stdin()?;
    let output = apply_smudge_filter(&key, &input)?;
    io::stdout()
        .write_all(&output)
        .context("Failed to write plaintext to stdout")?;
    Ok(())
}

/// Git diff textconv: decrypt file and write to stdout
/// Used by git diff to show decrypted content of encrypted files.
/// Takes a filename as argument (provided by git when using textconv).
pub fn diff_textconv(repo: &Repo, filename: &str) -> Result<()> {
    let key = repo.load_key().context("Failed to load encryption key")?;

    // Read file
    let input = fs::read(filename).with_context(|| format!("Failed to read file: {}", filename))?;

    // Decrypt if encrypted, otherwise output as-is
    let plaintext = if crypto::is_encrypted(&input) {
        crypto::decrypt(&key, &input).context("Failed to decrypt data")?
    } else {
        input
    };

    // Output plaintext content
    io::stdout()
        .write_all(&plaintext)
        .context("Failed to write content to stdout")?;

    Ok(())
}

// === Private Helper functions === //

/// Read all data from stdin
fn read_stdin() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .context("Failed to read input from stdin")?;
    Ok(input)
}

/// Apply clean filter logic: encrypt plaintext, pass through encrypted data unchanged
/// This is idempotent: clean(clean(data)) == clean(data)
fn apply_clean_filter(key: &Key, input: &[u8]) -> Result<Vec<u8>> {
    // Check if input is already encrypted using magic header
    if crypto::is_encrypted(input) {
        // Input is already encrypted, pass through unchanged
        // This ensures idempotency: clean(clean(data)) == clean(data)
        Ok(input.to_vec())
    } else {
        // Input is plaintext, encrypt it
        crypto::encrypt(key, input).context("Failed to encrypt data")
    }
}

/// Apply smudge filter logic: decrypt encrypted data, pass through plaintext unchanged
/// This is idempotent: smudge(smudge(data)) == smudge(data)
fn apply_smudge_filter(key: &Key, input: &[u8]) -> Result<Vec<u8>> {
    // Check if input is encrypted using magic header
    if !crypto::is_encrypted(input) {
        // Input is already plaintext, pass through unchanged
        // This ensures idempotency: smudge(smudge(data)) == smudge(data)
        Ok(input.to_vec())
    } else {
        // Input is encrypted, decrypt it
        crypto::decrypt(key, input).context("Failed to decrypt data")
    }
}

// === Tests === //

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant test key for deterministic testing
    fn test_key() -> Key {
        const TEST_KEY_BYTES: [u8; Key::KEY_SIZE] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        Key::from(TEST_KEY_BYTES)
    }

    #[test]
    fn test_apply_clean_filter_encrypts_plaintext() {
        let key = test_key();
        let plaintext = b"Hello, world!";

        let result = apply_clean_filter(&key, plaintext).unwrap();
        assert!(crypto::is_encrypted(&result));
        assert_ne!(result, plaintext);

        // Verify we can decrypt it
        let decrypted = crypto::decrypt(&key, &result).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_apply_clean_filter_idempotent() {
        let key = test_key();
        let plaintext = b"Test data";

        // First encryption
        let encrypted1 = apply_clean_filter(&key, plaintext).unwrap();
        assert!(crypto::is_encrypted(&encrypted1));

        // Second "encryption" (should pass through unchanged)
        let encrypted2 = apply_clean_filter(&key, &encrypted1).unwrap();
        assert_eq!(encrypted1, encrypted2);
    }

    #[test]
    fn test_apply_smudge_filter_decrypts_encrypted() {
        let key = test_key();
        let plaintext = b"Secret message";

        let encrypted = crypto::encrypt(&key, plaintext).unwrap();
        let result = apply_smudge_filter(&key, &encrypted).unwrap();

        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_apply_smudge_filter_idempotent() {
        let key = test_key();
        let plaintext = b"Plain text data";

        // First "decryption" (already plaintext, should pass through)
        let result1 = apply_smudge_filter(&key, plaintext).unwrap();
        assert_eq!(result1, plaintext);

        // Second "decryption" (should still pass through)
        let result2 = apply_smudge_filter(&key, &result1).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_apply_smudge_filter_passes_through_plaintext() {
        let key = test_key();
        let plaintext = b"This is not encrypted";

        let result = apply_smudge_filter(&key, plaintext).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_apply_clean_smudge_roundtrip() {
        let key = test_key();
        let original = b"Roundtrip test data";

        // Clean (encrypt)
        let encrypted = apply_clean_filter(&key, original).unwrap();
        assert!(crypto::is_encrypted(&encrypted));

        // Smudge (decrypt)
        let decrypted = apply_smudge_filter(&key, &encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_apply_clean_smudge_multiple_roundtrips() {
        let key = test_key();
        let original = b"Multiple roundtrips";

        let mut data = original.to_vec();

        // Multiple clean/smudge cycles
        for _ in 0..3 {
            data = apply_clean_filter(&key, &data).unwrap();
            assert!(crypto::is_encrypted(&data));
            data = apply_smudge_filter(&key, &data).unwrap();
            assert_eq!(data, original);
        }
    }

    #[test]
    fn test_apply_clean_filter_empty_input() {
        let key = test_key();
        let empty = b"";

        let result = apply_clean_filter(&key, empty).unwrap();
        assert!(crypto::is_encrypted(&result));

        let decrypted = apply_smudge_filter(&key, &result).unwrap();
        assert_eq!(decrypted, empty);
    }

    #[test]
    fn test_apply_smudge_filter_empty_encrypted() {
        let key = test_key();
        let empty = b"";

        let encrypted = crypto::encrypt(&key, empty).unwrap();
        let result = apply_smudge_filter(&key, &encrypted).unwrap();

        assert_eq!(result, empty);
    }

    #[test]
    fn test_apply_clean_filter_large_input() {
        let key = test_key();
        let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let encrypted = apply_clean_filter(&key, &large_data).unwrap();
        assert!(crypto::is_encrypted(&encrypted));

        let decrypted = apply_smudge_filter(&key, &encrypted).unwrap();
        assert_eq!(decrypted, large_data);
    }

    #[test]
    fn test_apply_clean_filter_binary_data() {
        let key = test_key();
        let binary_data = vec![0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE];

        let encrypted = apply_clean_filter(&key, &binary_data).unwrap();
        let decrypted = apply_smudge_filter(&key, &encrypted).unwrap();

        assert_eq!(decrypted, binary_data);
    }

    #[test]
    fn test_apply_clean_filter_utf8_data() {
        let key = test_key();
        let utf8_data = "Hello, 世界! 🌍".as_bytes();

        let encrypted = apply_clean_filter(&key, utf8_data).unwrap();
        let decrypted = apply_smudge_filter(&key, &encrypted).unwrap();

        assert_eq!(decrypted, utf8_data);
    }

    #[test]
    fn test_apply_smudge_filter_wrong_key_fails() {
        let key1 = test_key();
        let key2 = Key::generate().unwrap();
        let plaintext = b"Secret data";

        let encrypted = crypto::encrypt(&key1, plaintext).unwrap();

        // Decrypting with wrong key should fail
        let result = apply_smudge_filter(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_clean_filter_deterministic() {
        let key = test_key();
        let plaintext = b"Deterministic test";

        // Encrypt same plaintext twice
        let encrypted1 = apply_clean_filter(&key, plaintext).unwrap();
        let encrypted2 = apply_clean_filter(&key, plaintext).unwrap();

        // Should produce same ciphertext (deterministic encryption)
        assert_eq!(encrypted1, encrypted2);
    }
}
