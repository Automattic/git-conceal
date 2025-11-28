use aes::Aes256;
use anyhow::Result;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::RngCore;
use sha2::{Digest, Sha256};

const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;
const MAGIC_HEADER: &[u8] = b"\0a8ccrypt";
const MAGIC_HEADER_SIZE: usize = 9; // 1 byte null + 8 bytes "a8ccrypt"
const VERSION_BYTE: u8 = 1;
const ENCRYPTED_HEADER_SIZE: usize = MAGIC_HEADER_SIZE + 1 + IV_SIZE; // magic + version + IV

/// Generate a random 256-bit key for AES-256-CTR
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Check if data appears to be encrypted (has the magic header)
pub fn is_encrypted(data: &[u8]) -> bool {
    if data.len() < ENCRYPTED_HEADER_SIZE {
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
/// The encrypted output format is:
/// [1 byte: \0][8 bytes: "a8ccrypt"][1 byte: version][16 bytes: IV][encrypted data]
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
    let mut result = Vec::with_capacity(ENCRYPTED_HEADER_SIZE + buffer.len());
    result.extend_from_slice(MAGIC_HEADER);
    result.push(VERSION_BYTE);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buffer);

    Ok(result)
}

/// Decrypt data using AES-256-CTR
/// The input format is:
/// [1 byte: \0][8 bytes: "a8ccrypt"][1 byte: version][16 bytes: IV][encrypted data]
pub fn decrypt(key: &[u8; KEY_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < ENCRYPTED_HEADER_SIZE {
        anyhow::bail!("Ciphertext too short to contain header and IV");
    }

    // Verify magic header
    if !ciphertext.starts_with(MAGIC_HEADER) {
        anyhow::bail!("Invalid magic header - data does not appear to be encrypted");
    }

    // Extract version byte
    let version = ciphertext[MAGIC_HEADER_SIZE];
    if version != VERSION_BYTE {
        anyhow::bail!("Unsupported encryption format version: {}", version);
    }

    // Extract IV (after magic header + version byte)
    let iv_start = MAGIC_HEADER_SIZE + 1;
    let iv_end = iv_start + IV_SIZE;
    let iv = &ciphertext[iv_start..iv_end];

    // Extract encrypted data (after header + IV)
    let encrypted_data = &ciphertext[iv_end..];

    let mut cipher = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut buffer = encrypted_data.to_vec();
    cipher.apply_keystream(&mut buffer);

    Ok(buffer)
}
