use crate::crypto;
use crate::key;
use anyhow::{Context, Result};
use std::io::{self, Read, Write};
use std::path::Path;

/// Git clean filter: encrypt data from stdin and write to stdout
/// This filter is idempotent: clean(clean(data)) == clean(data)
/// If the input is already encrypted (has magic header), it passes through unchanged.
pub fn clean_filter(repo_path: &Path) -> Result<()> {
    let key = key::load_key_from_config(repo_path).context("Failed to load encryption key")?;

    // Read input from stdin
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .context("Failed to read input from stdin")?;

    // Check if input is already encrypted using magic header
    if crypto::is_encrypted(&input) {
        // Input is already encrypted, pass through unchanged
        // This ensures idempotency: clean(clean(data)) == clean(data)
        io::stdout()
            .write_all(&input)
            .context("Failed to write to stdout")?;
        return Ok(());
    }

    // Input is plaintext, encrypt it
    let ciphertext = crypto::encrypt(&key, &input).context("Failed to encrypt data")?;
    io::stdout()
        .write_all(&ciphertext)
        .context("Failed to write ciphertext to stdout")?;

    Ok(())
}

/// Git smudge filter: decrypt data from stdin and write to stdout
/// This filter is idempotent: smudge(smudge(data)) == smudge(data)
/// If the input is already plaintext (no magic header), it passes through unchanged.
pub fn smudge_filter(repo_path: &Path) -> Result<()> {
    let key = key::load_key_from_config(repo_path).context("Failed to load encryption key")?;

    // Read input from stdin
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .context("Failed to read input from stdin")?;

    // Check if input is encrypted using magic header
    if !crypto::is_encrypted(&input) {
        // Input is already plaintext, pass through unchanged
        // This ensures idempotency: smudge(smudge(data)) == smudge(data)
        io::stdout()
            .write_all(&input)
            .context("Failed to write to stdout")?;
        return Ok(());
    }

    // Input is encrypted, decrypt it
    let plaintext = crypto::decrypt(&key, &input).context("Failed to decrypt data")?;
    io::stdout()
        .write_all(&plaintext)
        .context("Failed to write plaintext to stdout")?;

    Ok(())
}
