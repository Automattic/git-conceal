use crate::repo;
use anyhow::{Context, Result};

pub fn cmd_lock(force: bool) -> Result<()> {
    let repo = repo::Repo::discover()?;

    // Check if any filtered files have local modifications
    if !force {
        let dirty_filtered = repo.dirty_filtered_files()?;
        if !dirty_filtered.is_empty() {
            eprintln!("Error: Cannot lock repository while there are local modifications in some encrypted files:");
            for file in &dirty_filtered {
                eprintln!("  {}", file.display());
            }
            eprintln!("\nPlease commit, stash or undo your changes before locking, or use --force to force lock.");
            anyhow::bail!("Repository has dirty encrypted files");
        }
    }

    // Remove Git filter configuration first (so Git won't try to decrypt on checkout)
    repo.remove_filters()
        .context("Failed to remove Git filters")?;

    // Remove the encryption key file
    repo.remove_key().context("Failed to remove key file")?;

    // Re-checkout filtered files to get raw encrypted data from repository
    repo.force_recheckout(repo.find_filtered_files()?)
        .context("Failed to re-checkout encrypted files")?;

    println!("Repository locked (key and filters removed, files re-checked in encrypted state)");
    Ok(())
}
