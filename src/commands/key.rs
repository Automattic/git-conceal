use crate::key::Key;
use crate::repo;
use crate::BINARY_NAME;
use anyhow::{Context, Result};
use indoc::indoc;
use std::io::Write;

pub fn cmd_key_show(raw: bool) -> Result<()> {
    let repo = repo::Repo::discover()?;
    if !repo.is_unlocked()? {
        anyhow::bail!(
            "Repository is locked (no key file found). Run '{} unlock' first.",
            BINARY_NAME
        );
    }

    let key = repo.load_key().context("Failed to load encryption key")?;
    if raw {
        std::io::stdout()
            .write_all(key.as_ref())
            .context("Failed to write key to stdout")?;
    } else {
        println!("{}", key);
    }

    Ok(())
}

pub fn cmd_key_rotate(skip_confirmation: bool) -> Result<()> {
    let repo = repo::Repo::discover()?;
    if !repo.is_unlocked()? {
        anyhow::bail!(
            "Repository is locked. Please run '{} unlock' first before rotating the key.",
            BINARY_NAME
        );
    }

    if !skip_confirmation && !confirm(&rotate_confirmation_prompt())? {
        anyhow::bail!("Key rotation cancelled.");
    }

    let new_key = Key::generate().context("Failed to generate new encryption key")?;
    repo.store_key(&new_key)
        .context("Failed to store new key")?;

    // Re-normalize filtered files to re-encrypt them with the new key
    println!("Re-encrypting secret files with the new key...");
    repo.renormalize_files(repo.find_filtered_files()?)
        .context("Failed to re-normalize encrypted files")?;

    // Print follow-up instructions for the user
    let instructions = rotate_instructions(&new_key);
    println!("{}", instructions);

    Ok(())
}

/// Prompt the user for confirmation (yes/no)
///
/// Displays the prompt message and waits for user input. Returns `true` if the user
/// confirms with "yes" or "y" (case-insensitive), `false` otherwise.
///
/// # Errors
/// Returns an error if reading from stdin or writing to stdout fails.
fn confirm(prompt: &str) -> Result<bool> {
    print!("{}", prompt);
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read user input")?;

    let input = input.trim().to_lowercase();
    Ok(input == "yes" || input == "y")
}

fn rotate_confirmation_prompt() -> String {
    indoc! {r#"
        WARNING

        This will re-encrypt all secret files in this repository with a new key.

        This means that other users of this repository that had the old key will no
        longer be able to access the content of the secret files commited after that
        change, unless you share the new key with them.

        Note that anyone who has the old key will still be able to decrypt the old
        content of the secret files committed before this rotation in the Git history.
        For this reason, especially if you are rotating the encryption key because
        of a leak or of someone leaving the team, it is recommended to _also_ rotate
        the actual secrets contained in those files.

        Are you sure you want to continue and rotate the encryption key? (yes/no):
    "#}
    .to_string()
}

/// Format key rotation instructions for display to the user
fn rotate_instructions(key: &Key) -> String {
    format!(
        indoc! {r#"
            Key rotation completed successfully
            Encrypted file(s) have been re-keyed and staged for commit.

            New encryption key (base64, save this securely and share with your team!):
            {key}

            Next steps:
              1. Consider also rotating the actual secrets contained in the secret files
                 (as the old key can still decrypt the old content from Git history),
                 and update the content of those files with the new secrets.

              2. Commit the re-keyed secret files:
                 git commit -m "Rotate encryption key and re-encrypt secret files"

              3. Share the new key with your coworkers securely. They will need to:
                 a. Run '{bin_name} lock' to lock their repository
                 b. Run 'git pull' to get the re-keyed secrets
                 c. Run '{bin_name} unlock' with the new key to unlock with the new key

            Once all team members have updated to the new key, the old key can be discarded.
        "#},
        bin_name = BINARY_NAME,
        key = key,
    )
}
