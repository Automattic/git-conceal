use crate::key;
use aes::Aes256;
use anyhow::{Context, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::TryRngCore;
use sha2::{Digest, Sha256};

/// Encrypted format:
/// [MAGIC_HEADER][VERSION][IV][encrypted data][HMAC]
///  - MAGIC_HEADER is used to identify the file as encrypted
///  - VERSION is the format version
///  - IV is the initialization vector for the AES-256-CTR cipher
///  - encrypted data is the AES-256-CTR encrypted data of the file's original content
///  - HMAC is used to validate integrity of the decryption key and the encrypted data
const MAGIC_HEADER: &[u8] = b"\0a8ccrypt";
const MAGIC_HEADER_SIZE: usize = MAGIC_HEADER.len();
const VERSION: u8 = 1; // Format version (includes HMAC for key verification)
const IV_SIZE: usize = 16;
const HMAC_SIZE: usize = 32; // SHA-256 HMAC output size
const ENCRYPTED_HEADER_SIZE: usize = MAGIC_HEADER_SIZE + 1 + IV_SIZE; // magic + version + IV
const MIN_ENCRYPTED_SIZE: usize = ENCRYPTED_HEADER_SIZE + HMAC_SIZE; // minimum size with HMAC

/// Generate random key bytes of the specified size
pub fn generate_key_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("Failed to generate random key bytes from OS RNG");
    bytes
}

/// Check if data appears to be encrypted (has the magic header)
pub fn is_encrypted(data: &[u8]) -> bool {
    if data.len() < MIN_ENCRYPTED_SIZE {
        return false;
    }

    // Check for magic header: \0 followed by "a8ccrypt"
    data.starts_with(MAGIC_HEADER)
}

/// Encrypt data using AES-256-CTR with a deterministic IV
/// The IV is derived from the SHA-256 hash of the plaintext, ensuring
/// that the same plaintext always encrypts to the same ciphertext.
/// This is required for git to detect when files haven't changed.
///
/// Encrypted format:
/// [1 byte: \0][8 bytes: "a8ccrypt"][1 byte: version][16 bytes: IV][encrypted data][32 bytes: HMAC]
///
/// The HMAC is computed over: magic + version + IV + encrypted data
/// and is used to verify the decryption key is correct.
pub fn encrypt(key: &key::Key, plaintext: &[u8]) -> Result<Vec<u8>> {
    // Derive IV from SHA-256 hash of plaintext (like git-crypt uses HMAC-SHA1)
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    let hash = hasher.finalize();

    // Use first 16 bytes as IV for CTR mode
    let mut iv = [0u8; IV_SIZE];
    iv.copy_from_slice(&hash[..IV_SIZE]);

    let mut cipher = Ctr128BE::<Aes256>::new(key.as_bytes().into(), &iv.into());
    let mut buffer = plaintext.to_vec();
    cipher.apply_keystream(&mut buffer);

    // Build result with magic header: \0 + "a8ccrypt" + version + IV + encrypted data
    let mut result = Vec::with_capacity(ENCRYPTED_HEADER_SIZE + buffer.len() + HMAC_SIZE);
    result.extend_from_slice(MAGIC_HEADER);
    result.push(VERSION);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buffer);

    // Compute HMAC (authenticates the entire ciphertext including header)
    let hmac_key = derive_hmac_key(key);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&hmac_key).context("Failed to create HMAC instance")?;
    mac.update(&result); // HMAC covers: magic + version + IV + encrypted data
    let hmac_tag = mac.finalize().into_bytes();
    result.extend_from_slice(&hmac_tag);

    Ok(result)
}

/// Decrypt data using AES-256-CTR
/// Verifies HMAC before decrypting to ensure the correct key is used.
pub fn decrypt(key: &key::Key, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < MIN_ENCRYPTED_SIZE {
        anyhow::bail!("Ciphertext too short to contain header, IV, and HMAC");
    }

    // Verify magic header
    if !ciphertext.starts_with(MAGIC_HEADER) {
        anyhow::bail!("Invalid magic header - data does not appear to be encrypted");
    }

    // Extract and verify version byte
    let version = ciphertext[MAGIC_HEADER_SIZE];
    if version != VERSION {
        anyhow::bail!(
            "Unsupported encryption format version: {} (expected {})",
            version,
            VERSION
        );
    }

    // Extract IV (after magic header + version byte)
    let iv_start = MAGIC_HEADER_SIZE + 1;
    let iv_end = iv_start + IV_SIZE;
    let iv = &ciphertext[iv_start..iv_end];

    // Extract encrypted data and HMAC
    let data_end = ciphertext.len() - HMAC_SIZE;
    let encrypted_data = &ciphertext[iv_end..data_end];
    let expected_hmac = &ciphertext[data_end..];

    // Verify HMAC before attempting decryption
    let hmac_key = derive_hmac_key(key);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&hmac_key).context("Failed to create HMAC instance")?;
    // HMAC covers: magic + version + IV + encrypted data (everything except the HMAC itself)
    mac.update(&ciphertext[..ciphertext.len() - HMAC_SIZE]);
    mac.verify_slice(expected_hmac).map_err(|_| {
        anyhow::anyhow!(
            "HMAC verification failed - the decryption key may be incorrect, \
                 or the file may have been tampered with. Please verify you're using \
                 the correct key for this repository."
        )
    })?;

    // Decrypt the data
    let mut cipher = Ctr128BE::<Aes256>::new(key.as_bytes().into(), iv.into());
    let mut buffer = encrypted_data.to_vec();
    cipher.apply_keystream(&mut buffer);

    Ok(buffer)
}

// === Private Helper functions === //

/// Derive HMAC key from encryption key using a KDF (Key Derivation Function)
/// This provides proper key separation and follows cryptographic best practices.
fn derive_hmac_key(encryption_key: &key::Key) -> [u8; key::Key::KEY_SIZE] {
    let kdf = Hkdf::<Sha256>::new(None, encryption_key.as_bytes());
    let mut hmac_key = [0u8; key::Key::KEY_SIZE];
    kdf.expand(b"a8c-git-secrets-hmac", &mut hmac_key)
        .expect("HKDF expansion failed (output length mismatch)");
    hmac_key
}

// === Tests === //

#[cfg(test)]
mod tests {
    use super::*;

    /// Test key for deterministic testing
    fn test_key1() -> key::Key {
        const TEST_KEY1_BYTES: [u8; key::Key::KEY_SIZE] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        key::Key::from_bytes(TEST_KEY1_BYTES)
    }

    /// Second test key for tests requiring different keys
    fn test_key2() -> key::Key {
        const TEST_KEY2_BYTES: [u8; key::Key::KEY_SIZE] = [
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];
        key::Key::from_bytes(TEST_KEY2_BYTES)
    }

    #[test]
    fn test_generate_key_bytes() {
        let key1_bytes = generate_key_bytes(key::Key::KEY_SIZE);
        let key2_bytes = generate_key_bytes(key::Key::KEY_SIZE);

        // Keys should be the correct size
        assert_eq!(key1_bytes.len(), key::Key::KEY_SIZE);
        assert_eq!(key2_bytes.len(), key::Key::KEY_SIZE);

        // Keys should be different (very unlikely to be the same)
        assert_ne!(key1_bytes, key2_bytes);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key1();
        let plaintext = b"Hello, world! This is a test message.";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let key = test_key1();
        let plaintext = b"";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        assert!(ciphertext.len() >= MIN_ENCRYPTED_SIZE);

        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_single_byte() {
        let key = test_key1();
        let plaintext = b"a";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_very_small_file() {
        let key = test_key1();
        let plaintext = b"hi";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        let key = test_key1();
        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let ciphertext = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_binary_data() {
        let key = test_key1();
        let plaintext: Vec<u8> = vec![0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE];

        let ciphertext = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = test_key1();
        let plaintext = b"This should encrypt to the same ciphertext";

        let ciphertext1 = encrypt(&key, plaintext).unwrap();
        let ciphertext2 = encrypt(&key, plaintext).unwrap();

        // Same plaintext with same key should produce same ciphertext
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = test_key1();
        let key2 = test_key2();
        let plaintext = b"Same plaintext, different keys";

        let ciphertext1 = encrypt(&key1, plaintext).unwrap();
        let ciphertext2 = encrypt(&key2, plaintext).unwrap();

        // Different keys should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = test_key1();
        let key2 = test_key2();
        let plaintext = b"Secret message";

        let ciphertext = encrypt(&key1, plaintext).unwrap();

        // Decrypting with wrong key should fail
        let result = decrypt(&key2, &ciphertext);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("HMAC verification failed"));
    }

    #[test]
    fn test_is_encrypted_with_encrypted_data() {
        let key = test_key1();
        let plaintext = b"Test data";
        let ciphertext = encrypt(&key, plaintext).unwrap();

        assert!(is_encrypted(&ciphertext));
    }

    #[test]
    fn test_is_encrypted_with_plaintext() {
        let plaintext = b"This is not encrypted";
        assert!(!is_encrypted(plaintext));
    }

    #[test]
    fn test_is_encrypted_with_empty_data() {
        assert!(!is_encrypted(b""));
    }

    #[test]
    fn test_is_encrypted_with_too_short_data() {
        // Data shorter than MIN_ENCRYPTED_SIZE should not be considered encrypted
        let short_data = vec![0u8; MIN_ENCRYPTED_SIZE - 1];
        assert!(!is_encrypted(&short_data));
    }

    #[test]
    fn test_is_encrypted_with_wrong_magic_header() {
        // Data of correct size but wrong magic header
        let mut fake_encrypted = vec![0u8; MIN_ENCRYPTED_SIZE];
        fake_encrypted[0] = 0xFF; // Wrong first byte
        assert!(!is_encrypted(&fake_encrypted));
    }

    #[test]
    fn test_decrypt_too_short_ciphertext() {
        let key = test_key1();
        let short_data = vec![0u8; MIN_ENCRYPTED_SIZE - 1];

        let result = decrypt(&key, &short_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_decrypt_invalid_magic_header() {
        let key = test_key1();
        let mut fake_ciphertext = vec![0u8; MIN_ENCRYPTED_SIZE];
        fake_ciphertext[0] = 0xFF; // Wrong magic header

        let result = decrypt(&key, &fake_ciphertext);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid magic header"));
    }

    #[test]
    fn test_decrypt_wrong_version() {
        let key = test_key1();
        let plaintext = b"Test";
        let mut ciphertext = encrypt(&key, plaintext).unwrap();

        // Change version byte to wrong value
        ciphertext[MAGIC_HEADER_SIZE] = 0xFF;

        let result = decrypt(&key, &ciphertext);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported encryption format version"));
    }

    #[test]
    fn test_decrypt_corrupted_hmac() {
        let key = test_key1();
        let plaintext = b"Test data";
        let mut ciphertext = encrypt(&key, plaintext).unwrap();

        // Corrupt the HMAC (last 32 bytes)
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 0xFF; // Flip bits

        let result = decrypt(&key, &ciphertext);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("HMAC verification failed"));
    }

    #[test]
    fn test_decrypt_corrupted_encrypted_data() {
        let key = test_key1();
        let plaintext = b"Test data";
        let mut ciphertext = encrypt(&key, plaintext).unwrap();

        // Corrupt the encrypted data (but not the HMAC)
        let data_start = ENCRYPTED_HEADER_SIZE;
        ciphertext[data_start] ^= 0xFF; // Flip bits in encrypted data

        // This should fail HMAC verification
        let result = decrypt(&key, &ciphertext);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("HMAC verification failed"));
    }

    #[test]
    fn test_decrypt_corrupted_iv() {
        let key = test_key1();
        let plaintext = b"Test data";
        let mut ciphertext = encrypt(&key, plaintext).unwrap();

        // Corrupt the IV
        let iv_start = MAGIC_HEADER_SIZE + 1;
        ciphertext[iv_start] ^= 0xFF;

        // This should fail HMAC verification
        let result = decrypt(&key, &ciphertext);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("HMAC verification failed"));
    }

    #[test]
    fn test_encrypt_decrypt_multibyte_utf8() {
        let key = test_key1();
        let plaintext = "Hello, 世界! 🌍".as_bytes();

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_newlines() {
        let key = test_key1();
        let plaintext = b"Line 1\nLine 2\nLine 3\n";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_null_bytes() {
        let key = test_key1();
        let plaintext = b"Before\0After\0\0End";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypted_output_structure() {
        let key = test_key1();
        let plaintext = b"Test";
        let ciphertext = encrypt(&key, plaintext).unwrap();

        // Check structure: magic header + version + IV + encrypted data + HMAC
        assert!(ciphertext.len() >= MIN_ENCRYPTED_SIZE);
        assert_eq!(&ciphertext[0..MAGIC_HEADER_SIZE], MAGIC_HEADER);
        assert_eq!(ciphertext[MAGIC_HEADER_SIZE], VERSION);

        // Check that HMAC is at the end
        let expected_hmac_start = ciphertext.len() - HMAC_SIZE;
        assert!(expected_hmac_start > ENCRYPTED_HEADER_SIZE);
    }

    #[test]
    fn test_encrypt_decrypt_exact_min_size_plaintext() {
        // Test with plaintext that results in exactly MIN_ENCRYPTED_SIZE when encrypted
        let key = test_key1();
        // This is tricky - we need plaintext that when encrypted gives us exactly the minimum
        // But since encryption adds header, any plaintext will be larger than MIN_ENCRYPTED_SIZE
        // So let's just test with a very small plaintext
        let plaintext = b"x";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        assert!(ciphertext.len() >= MIN_ENCRYPTED_SIZE);

        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_multiple_encrypt_decrypt_operations() {
        let key = test_key1();
        let plaintexts = vec![
            b"First message".as_slice(),
            b"Second message".as_slice(),
            b"Third message".as_slice(),
        ];

        for plaintext in plaintexts {
            let ciphertext = encrypt(&key, plaintext).unwrap();
            let decrypted = decrypt(&key, &ciphertext).unwrap();
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }

    #[test]
    fn test_encrypt_decrypt_all_zeros() {
        let key = test_key1();
        let plaintext = vec![0u8; 100];

        let ciphertext = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_all_ones() {
        let key = test_key1();
        let plaintext = vec![0xFFu8; 100];

        let ciphertext = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
