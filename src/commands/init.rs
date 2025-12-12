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

    let instructions = init_instructions(key);
    println!("{}", instructions);

    Ok(())
}

/// Format initialization instructions for display to the user
fn init_instructions(key: key::Key) -> String {
    format!(
        indoc! {r#"
            Repository initialized for {bin_name}

            Your encryption key (base64, save this securely!):
            {key}

            Once you share this key with users you trust, they can unlock their working copy using one of these methods:
              - From base64-encoded key passed directly as argument:
                {bin_name} unlock "{key}"
              - From environment variable (base64):
                export GIT_CONCEAL_SECRET_KEY='{key}'
                {bin_name} unlock env:GIT_CONCEAL_SECRET_KEY
              - From stdin (raw binary, 32 bytes):
                echo '{key}' | base64 -d | {bin_name} unlock -
                {bin_name} unlock - < /path/to/raw-binary-key.bin

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
        key = key,
        filter = repo::FILTER_NAME,
        diff = repo::DIFF_NAME,
    )
}
