#![deny(unsafe_code)]
#![warn(missing_docs)]

//! a8c-git-secrets - Transparent file encryption in git using symmetric keys
//!
//! This tool provides transparent encryption and decryption of files in git repositories,
//! similar to git-crypt but using only symmetric keys (no GPG support).
//!
//! Files are automatically encrypted on commit and decrypted on checkout using git's
//! clean/smudge filter mechanism.

mod crypto;
mod filter;
mod key;
mod repo;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indoc::indoc;
use std::io::Write;

#[derive(Parser)]
#[command(name = "a8c-git-secrets")]
#[command(about = "Transparent file encryption in git using symmetric keys")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Init
    #[command(
        about = "Initialize a repository for encryption",
        long_about = "Use this command to set up a repository to start using a8c-git-secrets. \n\
                      It generates an encryption key, sets up git filters locally for the repository, \
                      and provides instructions to save the key and how to start adding files to be encrypted."
    )]
    Init,
    // Unlock
    #[command(
        about = "Unlock an encrypted repository and decrypt existing files",
        long_about = "Use this command to unlock a repository that already contains encrypted files. \n\
                      It sets up git filters, saves the key you provide in a key file, \
                      and decrypts any encrypted files in the working directory."
    )]
    Unlock {
        /// Key source: '-' for stdin, 'env:VARNAME' for environment variable, or file path
        key_source: String,
    },
    // Lock
    #[command(
        about = "Lock a decrypted repository and restore files to their encrypted state",
        long_about = "Use this command to remove the encryption key file and git filters from the local repository \
                      of an unlocked repository, and to restore files to their encrypted state."
    )]
    Lock {
        /// Force lock even if there are local modifications in some encrypted files
        #[arg(short, long)]
        force: bool,
    },
    // Status
    #[command(
        about = "Show encryption status of the repository and encrypted files",
        long_about = "Use this command to show the encryption status of the repository and encrypted files.\n\
                      If file paths are provided, it shows the encryption status of the specific files only."
    )]
    Status {
        /// Files to check (if empty, shows repository status)
        #[arg(value_name = "FILE")]
        files: Vec<String>,
    },
    /// Key management commands
    #[command(about = "Manage encryption key")]
    Key {
        #[command(subcommand)]
        key_cmd: KeyCommands,
    },
    /// Git filter commands (internal use)
    #[command(hide = true)]
    Filter {
        #[command(subcommand)]
        filter_cmd: FilterCommands,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Show the current encryption key
    #[command(
        about = "Show the current encryption key",
        long_about = "Print the current encryption key, so you can share it with trusted coworkers."
    )]
    Show {
        /// Print the key as raw bytes instead of base64
        #[arg(short, long)]
        raw: bool,
    },
    /// Rotate the encryption key
    #[command(
        about = "Rotate the encryption key",
        long_about = "Generate a new encryption key to replace the existing one. \
                      The repository must be unlocked. After the key rotation, \
                      all secret files will be re-encrypted with the new key and staged for commit."
    )]
    Rotate {
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        skip_confirmation: bool,
    },
}

#[derive(Subcommand)]
enum FilterCommands {
    /// Clean filter: encrypt data (used by git on commit)
    Clean,
    /// Smudge filter: decrypt data (used by git on checkout)
    Smudge,
    /// Textconv: decrypt file for git diff (takes filename as argument)
    Textconv {
        /// Filename to decrypt and show in diff
        #[arg(value_name = "FILE")]
        filename: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Unlock { key_source } => cmd_unlock(key_source),
        Commands::Lock { force } => cmd_lock(force),
        Commands::Status { files } => cmd_status(files),
        Commands::Key { key_cmd } => cmd_key(key_cmd),
        Commands::Filter { filter_cmd } => cmd_filter(filter_cmd),
    }
}

fn cmd_init() -> Result<()> {
    let repo = repo::Repo::discover()?;

    // Check if already initialized
    if repo.filters_configured()? {
        eprintln!(
            "Repository is already initialized for a8c-git-secrets (filters already configured)"
        );
        return Ok(());
    }
    if repo.is_unlocked()? {
        anyhow::bail!("Repository is already configured and unlocked (key file exists)");
    }

    // Generate a new key
    let key = key::Key::generate();
    repo.store_key(&key).context("Failed to store key file")?;

    // Set up git filters
    repo.setup_filters()
        .context("Failed to set up git filters")?;

    let key_b64 = key.to_base64();
    let instructions = init_instructions(&key_b64);
    println!("{}", instructions);

    Ok(())
}

fn cmd_unlock(key_source: String) -> Result<()> {
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

    // Set up git filters
    repo.setup_filters()
        .context("Failed to set up git filters")?;

    // Force re-checkout of filtered files to trigger smudge filter (decrypt them)
    repo.force_recheckout(repo.find_filtered_files()?)
        .context("Failed to re-checkout encrypted files")?;

    println!("Repository unlocked successfully");
    Ok(())
}

fn cmd_lock(force: bool) -> Result<()> {
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

    // Remove git filter configuration first (so git won't try to decrypt on checkout)
    repo.remove_filters()
        .context("Failed to remove git filters")?;

    // Remove the encryption key file
    repo.remove_key().context("Failed to remove key file")?;

    // Re-checkout filtered files to get raw encrypted data from repository
    repo.force_recheckout(repo.find_filtered_files()?)
        .context("Failed to re-checkout encrypted files")?;

    println!("Repository locked (key and filters removed, files re-checked in encrypted state)");
    Ok(())
}

fn cmd_status(files: Vec<String>) -> Result<()> {
    let repo = repo::Repo::discover()?;

    if files.is_empty() {
        // Show repository status
        println!("Repository: {}", repo.workdir().display());
        let is_unlocked = repo.is_unlocked()?;
        println!(
            "Status: {}",
            if is_unlocked { "unlocked" } else { "locked" }
        );

        let filters_configured = repo.filters_configured()?;
        println!(
            "Filters configured: {}",
            if filters_configured { "yes" } else { "no" }
        );

        println!("\nFiles configured for encryption by git filter:");
        let mut has_files = false;
        for file_result in repo.find_filtered_files()? {
            let file = file_result?;
            println!("  🔒 {}", file.display());
            has_files = true;
        }
        if !has_files {
            println!("  (none)");
        }
    } else {
        // Check status for specific files
        for file_str in &files {
            let file_path = std::path::Path::new(file_str);
            let is_filtered = repo.is_filtered_file(file_path)?;
            let status = if is_filtered {
                "🔒 Encrypted in the repository"
            } else {
                "👀 Not encrypted in the repository"
            };
            println!("{:20}: {}", file_str, status);
        }
    }

    Ok(())
}

fn cmd_key(key_cmd: KeyCommands) -> Result<()> {
    match key_cmd {
        KeyCommands::Show { raw } => cmd_key_show(raw),
        KeyCommands::Rotate { skip_confirmation } => cmd_key_rotate(skip_confirmation),
    }
}

fn cmd_key_show(raw: bool) -> Result<()> {
    let repo = repo::Repo::discover()?;
    if !repo.is_unlocked()? {
        anyhow::bail!(
            "Repository is locked (no key file found). Run 'a8c-git-secrets unlock' first."
        );
    }

    let key = repo.load_key().context("Failed to load encryption key")?;
    if raw {
        std::io::stdout()
            .write_all(key.as_bytes())
            .context("Failed to write key to stdout")?;
    } else {
        println!("{}", key.to_base64());
    }

    Ok(())
}

fn cmd_key_rotate(skip_confirmation: bool) -> Result<()> {
    let repo = repo::Repo::discover()?;
    if !repo.is_unlocked()? {
        anyhow::bail!(
            "Repository is locked. Please run 'a8c-git-secrets unlock' first before rotating the key."
        );
    }

    if !skip_confirmation && !confirm(&rotate_confirmation_prompt())? {
        anyhow::bail!("Key rotation cancelled.");
    }

    let new_key = key::Key::generate();
    repo.store_key(&new_key)
        .context("Failed to store new key")?;

    // Re-normalize filtered files to re-encrypt them with the new key
    println!("Re-encrypting secret files with the new key...");
    repo.renormalize_files(repo.find_filtered_files()?)
        .context("Failed to re-normalize encrypted files")?;

    // Print follow-up instructions for the user
    let new_key_b64 = new_key.to_base64();
    let instructions = rotate_instructions(&new_key_b64);
    println!("{}", instructions);

    Ok(())
}

fn cmd_filter(filter_cmd: FilterCommands) -> Result<()> {
    let repo = repo::Repo::discover()?;

    match filter_cmd {
        FilterCommands::Clean => filter::clean_filter(&repo),
        FilterCommands::Smudge => filter::smudge_filter(&repo),
        FilterCommands::Textconv { filename } => filter::diff_textconv(&repo, &filename),
    }
}

// === Helper functions === //

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

/// Format initialization instructions for display to the user
fn init_instructions(key_b64: &str) -> String {
    format!(
        indoc! {r#"
            Repository initialized for a8c-git-secrets

            Your encryption key (base64, save this securely!):
            {key_b64}

            Once you share this key with users you trust, they can unlock their working copy using one of these methods:
              - From environment variable (base64):
                export GIT_SECRETS_KEY='{key_b64}'
                a8c-git-secrets unlock env:GIT_SECRETS_KEY
              - From file (raw binary, 32 bytes):
                echo '{key_b64}' | base64 -d > /path/to/key.bin
                a8c-git-secrets unlock /path/to/key.bin
              - From stdin (raw binary, 32 bytes):
                echo '{key_b64}' | base64 -d | a8c-git-secrets unlock -

            To start adding files to be encrypted in this repository:
              - List files (or file patterns) you want to encrypt in your `.gitattributes` file, like this:
                ```
                secrets-file.json  filter={filter} diff={diff}
                secrets/*  filter={filter} diff={diff}
                ```
              - `git add` and `git commit` those files, alongside the `.gitattributes` file.
                The files having the `filter` attribute set will be encrypted on commit and decrypted on checkout automatically.
              - Run 'a8c-git-secrets status' to validate the list of files that are encrypted.
        "#},
        key_b64 = key_b64,
        filter = repo::FILTER_NAME,
        diff = repo::DIFF_NAME,
    )
}

fn rotate_confirmation_prompt() -> String {
    indoc! {r#"
        WARNING

        This will re-encrypt all secret files in this repository with a new key.

        This means that other users of this repository that had the old key will no
        longer be able to access the content of the secret files commited after that
        change, unless you share the new key with them.

        Note that anyone who has the old key will still be able to decrypt the old
        content of the secret files committed before this rotation in the git history.
        For this reason, especially if you are rotating the encryption key because
        of a leak or of someone leaving the team, it is recommended to _also_ rotate
        the actual secrets contained in those files.

        Are you sure you want to continue and rotate the encryption key? (yes/no):
    "#}
    .to_string()
}
/// Format key rotation instructions for display to the user
fn rotate_instructions(key_b64: &str) -> String {
    format!(
        indoc! {r#"
            Key rotation completed successfully
            Encrypted file(s) have been re-keyed and staged for commit.

            New encryption key (base64, save this securely and share with your team!):
            {key_b64}

            Next steps:
              1. Consider also rotating the actual secrets contained in the secret files
                 (as the old key can still decrypt the old content from git history),
                 and update the content of those files with the new secrets.

              2. Commit the re-keyed secret files:
                 git commit -m "Rotate encryption key and re-encrypt secret files"

              2. Share the new key with your coworkers securely. They will need to:
                 a. Run 'a8c-git-secrets lock' to lock their repository
                 b. Run 'git pull' to get the re-keyed secrets
                 c. Run 'a8c-git-secrets unlock' with the new key to unlock with the new key

            Once all team members have updated to the new key, the old key can be discarded.
        "#},
        key_b64 = key_b64,
    )
}
