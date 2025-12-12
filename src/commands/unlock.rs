use crate::key::Key;
use crate::repo;
use anyhow::{Context, Result};
use std::io::Read;

pub fn cmd_unlock(key_source: String) -> Result<()> {
    let repo = repo::Repo::discover()?;

    // Check if any filtered files have local modifications
    let dirty_filtered = repo.dirty_filtered_files()?;
    if !dirty_filtered.is_empty() {
        eprintln!("Error: Cannot unlock repository while there are local modifications in some encrypted files:");
        for file in &dirty_filtered {
            eprintln!("  {}", file.display());
        }
        eprintln!("\nPlease commit, stash or undo your changes before unlocking.");
        anyhow::bail!("Repository has dirty encrypted files");
    }

    let key = read_from_source(&key_source)?;

    // Store key in key file
    repo.store_key(&key).context("Failed to store key file")?;

    // Set up Git filters
    repo.setup_filters()
        .context("Failed to set up Git filters")?;

    // Force re-checkout of filtered files to trigger smudge filter (decrypt them)
    repo.force_recheckout(repo.find_filtered_files()?)
        .context("Failed to re-checkout encrypted files")?;

    println!("Repository unlocked successfully");
    Ok(())
}

/// Read encryption key from various sources
///
/// Supports:
/// - Base64-encoded key string (passed directly as argument)
/// - `"env:VARNAME"` for reading from environment variable (base64 encoded)
/// - `"-"` for reading from stdin (raw binary format, 32 bytes)
///
/// Returns the encryption key.
fn read_from_source(key_source: &str) -> Result<Key> {
    if key_source == "-" {
        // Read from stdin (raw binary format)
        let mut key_bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut key_bytes)
            .context("Failed to read key from stdin")?;
        Key::try_from(key_bytes.as_slice())
    } else if let Some(env_var) = key_source.strip_prefix("env:") {
        // Read from environment variable (base64 encoded, format: env:VARNAME)
        if env_var.is_empty() {
            anyhow::bail!("Environment variable name cannot be empty after 'env:'");
        }
        let key_b64 = std::env::var(env_var)
            .with_context(|| format!("Failed to read key from environment variable {}", env_var))?;
        Key::try_from(key_b64.as_str())
    } else {
        // Treat as base64-encoded key (unprefixed)
        Key::try_from(key_source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// This test must run serially (not in parallel with other tests) because it modifies
    /// environment variables. Environment variable modification is not thread-safe and can
    /// cause race conditions when tests run in parallel.
    #[serial_test::serial]
    #[test]
    #[allow(unsafe_code)] // Required for std::env::set_var/remove_var in Rust 2024 Edition
    fn test_read_from_source_env() {
        let key = test_key();
        let b64 = key.to_string();

        // Set environment variable
        // SAFETY: This test runs serially, so no race conditions with other tests
        unsafe {
            std::env::set_var("TEST_KEY_VAR", &b64);
        }

        let loaded_key = read_from_source("env:TEST_KEY_VAR").unwrap();
        assert_eq!(loaded_key.as_ref(), key.as_ref());

        // Clean up
        unsafe {
            std::env::remove_var("TEST_KEY_VAR");
        }
    }

    /// This test must run serially (not in parallel with other tests) because it modifies
    /// environment variables. Environment variable modification is not thread-safe and can
    /// cause race conditions when tests run in parallel.
    #[serial_test::serial]
    #[test]
    #[allow(unsafe_code)] // Required for std::env::set_var/remove_var in Rust 2024 Edition
    fn test_read_from_source_env_with_whitespace() {
        let key = test_key();
        let b64 = key.to_string();

        // Set environment variable with whitespace
        // SAFETY: This test runs serially, so no race conditions with other tests
        unsafe {
            std::env::set_var("TEST_KEY_VAR", &format!("  {}  ", b64));
        }

        let loaded_key = read_from_source("env:TEST_KEY_VAR").unwrap();
        assert_eq!(loaded_key.as_ref(), key.as_ref());

        // Clean up
        unsafe {
            std::env::remove_var("TEST_KEY_VAR");
        }
    }

    /// This test must run serially (not in parallel with other tests) because it modifies
    /// environment variables. Environment variable modification is not thread-safe and can
    /// cause race conditions when tests run in parallel.
    #[serial_test::serial]
    #[test]
    #[allow(unsafe_code)] // Required for std::env::set_var/remove_var in Rust 2024 Edition
    fn test_read_from_source_env_nonexistent() {
        // Make sure the variable doesn't exist
        // SAFETY: This test runs serially, so no race conditions with other tests
        unsafe {
            std::env::remove_var("NONEXISTENT_VAR");
        }

        let result = read_from_source("env:NONEXISTENT_VAR");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read key from environment variable"));
    }

    #[test]
    fn test_read_from_source_env_empty_name() {
        let result = read_from_source("env:");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Environment variable name cannot be empty"));
    }

    #[test]
    fn test_read_from_source_base64() {
        let key = test_key();
        let b64 = key.to_string();
        let loaded_key = read_from_source(&b64).unwrap();
        assert_eq!(loaded_key.as_ref(), key.as_ref());
    }

    // Note: Testing stdin reading is complex in unit tests as it requires
    // mocking stdin or using a separate process. This would be better suited
    // for integration tests. The env var and base64 cases are tested above.

    #[test]
    fn test_read_from_source_invalid_base64() {
        // A user accidentally passing a file path should be treated as base64 key and fail to decode
        let result = read_from_source("path/to/secret-symmetric-key.bin");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode base64 key"));
    }
}
