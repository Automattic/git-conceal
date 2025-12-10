use crate::key;
use crate::repo;
use crate::BINARY_NAME;
use anyhow::{Context, Result};
use indoc::indoc;

pub fn cmd_init() -> Result<()> {
    let repo = repo::Repo::discover()?;

    // Check if already initialized
    if repo.filters_configured()? {
        anyhow::bail!(
            "Repository is already initialized for {} (filters already configured)",
            BINARY_NAME
        )
    }
    if repo.is_unlocked()? {
        anyhow::bail!("Repository is already configured and unlocked (key file exists)")
    }

    // Generate a new key
    let key = key::Key::generate().context("Failed to generate encryption key")?;
    repo.store_key(&key).context("Failed to store key file")?;

    // Set up Git filters
    repo.setup_filters()
        .context("Failed to set up Git filters")?;

    let key_b64 = key.to_base64();
    let instructions = init_instructions(&key_b64);
    println!("{}", instructions);

    Ok(())
}

/// Format initialization instructions for display to the user
fn init_instructions(key_b64: &str) -> String {
    format!(
        indoc! {r#"
            Repository initialized for {bin_name}

            Your encryption key (base64, save this securely!):
            {key_b64}

            Once you share this key with users you trust, they can unlock their working copy using one of these methods:
              - From environment variable (base64):
                export GIT_SECRETS_KEY='{key_b64}'
                {bin_name} unlock env:GIT_SECRETS_KEY
              - From base64-encoded key in the command line:
                {bin_name} unlock "base64:{key_b64}"
              - From file (raw binary, 32 bytes):
                {bin_name} unlock /path/to/key.bin
              - From stdin (raw binary, 32 bytes):
                echo '{key_b64}' | base64 -d | {bin_name} unlock -

            To start adding files to be encrypted in this repository:
              - List files (or file patterns) you want to encrypt in your `.gitattributes` file, like this:
                ```
                secrets-file.json  filter={filter} diff={diff}
                secrets/*  filter={filter} diff={diff}
                ```
              - `git add` and `git commit` those files, alongside the `.gitattributes` file.
                The files having the `filter` attribute set will be encrypted on commit and decrypted on checkout automatically.
              - Run '{bin_name} status' to validate the list of files that are encrypted.
        "#},
        bin_name = BINARY_NAME,
        key_b64 = key_b64,
        filter = repo::FILTER_NAME,
        diff = repo::DIFF_NAME,
    )
}
