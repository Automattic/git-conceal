use aes::Aes256;
use anyhow::{Context, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use rand::RngCore;
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
const KEY_SIZE: usize = 32;
const HMAC_SIZE: usize = 32; // SHA-256 HMAC output size
const ENCRYPTED_HEADER_SIZE: usize = MAGIC_HEADER_SIZE + 1 + IV_SIZE; // magic + version + IV
const MIN_ENCRYPTED_SIZE: usize = ENCRYPTED_HEADER_SIZE + HMAC_SIZE; // minimum size with HMAC

type HmacSha256 = Hmac<Sha256>;

/// Generate a random 256-bit key for AES-256-CTR
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Derive HMAC key from encryption key
/// Uses a simple key derivation: HMAC key = SHA-256(encryption_key || "a8c-git-secrets-hmac")
fn derive_hmac_key(encryption_key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(encryption_key);
    hasher.update(b"a8c-git-secrets-hmac");
    let hash = hasher.finalize();
    let mut hmac_key = [0u8; KEY_SIZE];
    hmac_key.copy_from_slice(&hash);
    hmac_key
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
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    // Derive IV from SHA-256 hash of plaintext (like git-crypt uses HMAC-SHA1)
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    let hash = hasher.finalize();

    // Use first 16 bytes as IV for CTR mode
    let mut iv = [0u8; IV_SIZE];
    iv.copy_from_slice(&hash[..IV_SIZE]);

    let mut cipher = Ctr128BE::<Aes256>::new(key.into(), &iv.into());
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
        HmacSha256::new_from_slice(&hmac_key).context("Failed to create HMAC instance")?;
    mac.update(&result); // HMAC covers: magic + version + IV + encrypted data
    let hmac_tag = mac.finalize().into_bytes();
    result.extend_from_slice(&hmac_tag);

    Ok(result)
}

/// Decrypt data using AES-256-CTR
/// Verifies HMAC before decrypting to ensure the correct key is used.
pub fn decrypt(key: &[u8; KEY_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
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
        HmacSha256::new_from_slice(&hmac_key).context("Failed to create HMAC instance")?;
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
    let mut cipher = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut buffer = encrypted_data.to_vec();
    cipher.apply_keystream(&mut buffer);

    Ok(buffer)
}
