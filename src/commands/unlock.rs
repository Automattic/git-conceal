use crate::key;
use crate::repo;
use anyhow::{Context, Result};

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

    let key = key::Key::read_from_source(&key_source)?;

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
