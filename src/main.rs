mod crypto;
mod filter;
mod git;
mod key;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{io::Read, path::Path};
use indoc::indoc;

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
    /// Initialize a repository for encryption (generate key and set up filters)
    Init,
    /// Unlock a repository with a key (from stdin, file, or environment variable)
    Unlock {
        /// Key source: '-' for stdin, 'env:VARNAME' for environment variable, or file path
        key_source: String,
    },
    /// Lock a repository (remove key from config)
    Lock,
    /// Show encryption status
    Status {
        /// Files to check (if empty, shows repository status)
        #[arg(value_name = "FILE")]
        files: Vec<String>,
    },
    /// Git filter commands (internal use)
    Filter {
        #[command(subcommand)]
        filter_cmd: FilterCommands,
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
        Commands::Lock => cmd_lock(),
        Commands::Status { files } => cmd_status(files),
        Commands::Filter { filter_cmd } => cmd_filter(filter_cmd),
    }
}

fn cmd_init() -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    // Check if already initialized
    if git::filters_configured(&repo_path)? {
        eprintln!("Repository is already initialized for a8c-git-secrets");
        return Ok(());
    }

    // Generate a new key
    let key = key::generate_key();
    let key_b64 = key::key_to_base64(&key);

    // Store key in git config
    key::store_key_in_config(&repo_path, &key).context("Failed to store key in git config")?;

    // Set up git filters
    git::setup_filters(&repo_path).context("Failed to set up git filters")?;

    let instructions = format!(
        indoc! {r#"
            Repository initialized for a8c-git-secrets

            Your encryption key (save this securely!):
            {key_b64}

            Once you share this key with users you trust, they can run this to unlock their working copy:
              echo '{key_b64}' | a8c-git-secrets unlock -

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
        filter = git::FILTER_NAME,
        diff = git::DIFF_NAME,
    );
    println!("{}", instructions);

    Ok(())
}

fn cmd_unlock(key_source: String) -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    // Read key from input
    let base64_key: String = if key_source == "-" {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("Failed to read key from stdin")?;
        input
    } else if let Some(env_var) = key_source.strip_prefix("env:") {
        // Read from environment variable (format: env:VARNAME)
        if env_var.is_empty() {
            anyhow::bail!("Environment variable name cannot be empty after 'env:'");
        }
        std::env::var(env_var)
            .with_context(|| format!("Failed to read key from environment variable {}", env_var))?
    } else {
        // Read from file
        std::fs::read_to_string(&key_source)
            .with_context(|| format!("Failed to read key from file: {}", key_source))?
    };
    let key = key::key_from_base64(base64_key.trim()).context("Failed to decode key")?;

    // Store key in git config
    key::store_key_in_config(&repo_path, &key).context("Failed to store key in git config")?;

    // Set up git filters if not already configured
    if !git::filters_configured(&repo_path)? {
        git::setup_filters(&repo_path).context("Failed to set up git filters")?;
    }

    // Decrypt existing encrypted files in working directory
    decrypt_working_files(&repo_path, &key).context("Failed to decrypt existing files")?;

    println!("Repository unlocked successfully");
    Ok(())
}

fn cmd_lock() -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    // Remove git filter configuration first (so git won't try to decrypt on checkout)
    git::remove_filters(&repo_path).context("Failed to remove git filters")?;

    // Re-checkout encrypted files to get raw encrypted data from repository
    // This must be done after removing filters, otherwise git will try to decrypt
    git::recheckout_encrypted_files(&repo_path).context("Failed to re-checkout encrypted files")?;

    // Remove the encryption key last
    key::remove_key_from_config(&repo_path).context("Failed to remove key from git config")?;

    println!("Repository locked (key and filters removed, files re-checked out)");
    Ok(())
}

fn cmd_status(files: Vec<String>) -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    if files.is_empty() {
        // Show repository status
        let is_locked = git::is_locked(&repo_path)?;
        let filters_configured = git::filters_configured(&repo_path)?;
        let encrypted_files = git::find_encrypted_files(&repo_path)?;

        println!("Repository: {}", repo_path.display());
        println!("Status: {}", if is_locked { "locked" } else { "unlocked" });
        println!(
            "Filters configured: {}",
            if filters_configured { "yes" } else { "no" }
        );

        if !encrypted_files.is_empty() {
            println!("\nEncrypted files:");
            for file in &encrypted_files {
                println!("  {}", file.display());
            }
        } else {
            println!("\nNo encrypted files found in working directory");
        }
    } else {
        // Check status for specific files
        for file_str in &files {
            let file_path = std::path::Path::new(file_str);
            let is_encrypted = git::is_file_encrypted(&repo_path, file_path)?;
            let status = if is_encrypted {
                "encrypted"
            } else {
                "not encrypted"
            };
            println!("{}: {}", file_str, status);
        }
    }

    Ok(())
}

fn cmd_filter(filter_cmd: FilterCommands) -> Result<()> {
    // Find repository root using git2's discover function
    // This works even when git changes directories or sets GIT_DIR
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    match filter_cmd {
        FilterCommands::Clean => filter::clean_filter(&repo_path),
        FilterCommands::Smudge => filter::smudge_filter(&repo_path),
        FilterCommands::Textconv { filename } => filter::diff_textconv(&repo_path, &filename),
    }
}

/// Decrypt all encrypted files in the working directory
fn decrypt_working_files(repo_path: &Path, key: &[u8; 32]) -> Result<()> {
    use std::fs;

    // Find all files that have the encryption filter attribute set
    let encrypted_files = git::find_encrypted_files(repo_path)?;

    if encrypted_files.is_empty() {
        return Ok(());
    }

    println!("Decrypting {} file(s)...", encrypted_files.len());

    for file_path in encrypted_files {
        let full_path = repo_path.join(&file_path);

        // Skip if file doesn't exist
        if !full_path.exists() {
            continue;
        }

        // Read encrypted content
        let ciphertext = match fs::read(&full_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Warning: Failed to read {}: {}", file_path.display(), e);
                continue;
            }
        };

        // Skip if not encrypted (no magic header)
        if !crypto::is_encrypted(&ciphertext) {
            continue;
        }

        // Decrypt the file
        match crypto::decrypt(key, &ciphertext) {
            Ok(plaintext) => {
                // Write decrypted content
                if let Err(e) = fs::write(&full_path, &plaintext) {
                    eprintln!(
                        "Warning: Failed to write decrypted {}: {}",
                        file_path.display(),
                        e
                    );
                } else {
                    println!("  Decrypted: {}", file_path.display());
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to decrypt {}: {}", file_path.display(), e);
                continue;
            }
        }
    }

    Ok(())
}
