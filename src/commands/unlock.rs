use crate::key::Key;
use crate::repo;
use anyhow::{Context, Result};
use std::io::Read;

pub fn cmd_unlock(key_source: KeySource) -> Result<()> {
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

    let key = Key::try_from(key_source)?;

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

/// Possible sources to read the encryption key from
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Base64-encoded key string passed directly as argument
    ArgumentValue(String),
    /// Environment variable containing the base64-encoded key
    EnvVar(String),
    /// Raw binary key read from stdin
    Stdin,
}

/// Convert the argument passed to the `unlock` command into a `KeySource`:
impl std::str::FromStr for KeySource {
    type Err = anyhow::Error;
    fn from_str(arg_value: &str) -> Result<Self> {
        if arg_value == "-" {
            Ok(Self::Stdin)
        } else if let Some(env_var) = arg_value.strip_prefix("env:") {
            if env_var.is_empty() {
                anyhow::bail!("Environment variable name cannot be empty after 'env:'");
            }
            Ok(Self::EnvVar(env_var.to_string()))
        } else {
            Ok(Self::ArgumentValue(arg_value.to_string()))
        }
    }
}

/// Read encryption key from various possible sources
impl TryFrom<KeySource> for Key {
    type Error = anyhow::Error;
    fn try_from(key_source: KeySource) -> Result<Key> {
        match key_source {
            KeySource::ArgumentValue(arg_value) => Key::try_from(arg_value.as_str()),
            KeySource::EnvVar(env_var) => {
                let key_b64 = std::env::var(env_var.as_str()).with_context(|| {
                    format!(
                        "Failed to read key from environment variable {}",
                        env_var.as_str()
                    )
                })?;
                Key::try_from(key_b64.as_str())
            }
            KeySource::Stdin => {
                let mut key_bytes = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut key_bytes)
                    .context("Failed to read key from stdin")?;
                Key::try_from(key_bytes.as_slice())
            }
        }
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
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)] // Required for std::env::set_var/remove_var in Rust 2024 Edition
    fn test_key_source_from_env() {
        let key = test_key();
        let b64 = key.to_string();

        // Set environment variable
        // SAFETY: This test runs serially, so no race conditions with other tests
        unsafe {
            std::env::set_var("TEST_KEY_VAR", &b64);
        }

        let key_source: KeySource = "env:TEST_KEY_VAR".parse().unwrap();
        assert_eq!(key_source, KeySource::EnvVar("TEST_KEY_VAR".to_string()));

        let loaded_key = Key::try_from(key_source).unwrap();
        assert_eq!(loaded_key.as_ref(), key.as_ref());

        // Clean up
        unsafe {
            std::env::remove_var("TEST_KEY_VAR");
        }
    }

    /// This test must run serially (not in parallel with other tests) because it modifies
    /// environment variables. Environment variable modification is not thread-safe and can
    /// cause race conditions when tests run in parallel.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)] // Required for std::env::set_var/remove_var in Rust 2024 Edition
    fn test_key_source_from_env_with_whitespace() {
        let key = test_key();
        let b64 = key.to_string();

        // Set environment variable with whitespace
        // SAFETY: This test runs serially, so no race conditions with other tests
        unsafe {
            std::env::set_var("TEST_KEY_VAR", &format!("  {}  ", b64));
        }

        let key_source: KeySource = "env:TEST_KEY_VAR".parse().unwrap();
        assert_eq!(key_source, KeySource::EnvVar("TEST_KEY_VAR".to_string()));

        let loaded_key = Key::try_from(key_source).unwrap();
        assert_eq!(loaded_key.as_ref(), key.as_ref());

        // Clean up
        unsafe {
            std::env::remove_var("TEST_KEY_VAR");
        }
    }

    /// This test must run serially (not in parallel with other tests) because it modifies
    /// environment variables. Environment variable modification is not thread-safe and can
    /// cause race conditions when tests run in parallel.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)] // Required for std::env::set_var/remove_var in Rust 2024 Edition
    fn test_key_source_from_env_nonexistent() {
        // Make sure the variable doesn't exist
        // SAFETY: This test runs serially, so no race conditions with other tests
        unsafe {
            std::env::remove_var("NONEXISTENT_VAR");
        }

        let key_source: KeySource = "env:NONEXISTENT_VAR".parse().unwrap();
        assert_eq!(key_source, KeySource::EnvVar("NONEXISTENT_VAR".to_string()));

        let result = Key::try_from(key_source);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read key from environment variable"));
    }

    #[test]
    fn test_key_source_from_env_empty_name() {
        let result: Result<KeySource> = "env:".parse();

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Environment variable name cannot be empty"));
    }

    #[test]
    fn test_key_source_from_base64_argument() {
        let key = test_key();
        let b64 = key.to_string();
        let key_source: KeySource = b64.parse().unwrap();
        assert_eq!(key_source, KeySource::ArgumentValue(b64));

        let loaded_key = Key::try_from(key_source).unwrap();
        assert_eq!(loaded_key.as_ref(), key.as_ref());
    }

    #[test]
    fn test_key_source_from_invalid_base64_argument() {
        // A user accidentally passing a file path as a base64 key
        // This path happens to not be valid base64 (due to the `.` and `-` characters in it)
        let path_looking_string = "path/to/secret-symmetric-key.bin";
        let key_source: KeySource = path_looking_string.parse().unwrap();
        assert_eq!(
            key_source,
            KeySource::ArgumentValue(path_looking_string.to_string())
        );

        let result = Key::try_from(key_source);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode base64 key"));
    }

    #[test]
    fn test_key_source_from_base64_argument_invalid_key_length() {
        // A user accidentally passing a file path as a base64 key
        // This path happens to be valid base64, but the wrong length
        let path_looking_string = "path/to/the/secret/symmetric/key";
        let key_source: KeySource = path_looking_string.parse().unwrap();
        assert_eq!(
            key_source,
            KeySource::ArgumentValue(path_looking_string.to_string())
        );

        let result = Key::try_from(key_source);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid size for key decoded from base64"));
    }

    #[test]
    fn test_key_source_from_stdin_argument() {
        let key_source: KeySource = "-".parse().unwrap();
        assert_eq!(key_source, KeySource::Stdin);

        // Note: Testing stdin reading is complex in unit tests as it requires mocking stdin or using a separate process.
        // Hence why we're only testing the parsing of "-" as KeySource::Stdin but not the Key::try_from(KeySource::Stdin) itself.
        // (If we really wanted to test this case of reading from stdin itself, an integration test would be better suited.)
    }
}
