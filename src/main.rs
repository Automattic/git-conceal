mod crypto;
mod filter;
mod git;
mod key;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indoc::indoc;
use std::io::Read;

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
                      It sets up git filters, saves the key you provide in the git config, \
                      and decrypts any encrypted files in the working directory."
    )]
    Unlock {
        /// Key source: '-' for stdin, 'env:VARNAME' for environment variable, or file path
        key_source: String,
    },
    // Lock
    #[command(
        about = "Lock a decrypted repository and restore files to their encrypted state",
        long_about = "Use this command to remove the encryption key and git filters from the local git config \
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
    /// Git filter commands (internal use)
    #[command(hide = true)]
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
        Commands::Lock { force } => cmd_lock(force),
        Commands::Status { files } => cmd_status(files),
        Commands::Filter { filter_cmd } => cmd_filter(filter_cmd),
    }
}

fn cmd_init() -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    // Check if already initialized
    if git::filters_configured(&repo_path)? {
        eprintln!(
            "Repository is already initialized for a8c-git-secrets (filters already configured)"
        );
        return Ok(());
    }
    if git::is_unlocked(&repo_path)? {
        anyhow::bail!("Repository is already configured and unlocked (key in git config)");
    }

    // Generate a new key
    let key = key::generate_key();
    let key_b64 = key::key_to_base64(&key);
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

    // Find encrypted files and check if any have local modifications
    let encrypted_files = git::find_encrypted_files(&repo_path)?;
    let dirty_files = git::dirty_files(&repo_path, &encrypted_files)?;
    if !dirty_files.is_empty() {
        eprintln!("Error: Cannot unlock repository while there are local modifications in some encrypted files:");
        for file in &dirty_files {
            eprintln!("  {}", file.display());
        }
        eprintln!("\nPlease commit, stash or undo your changes before unlocking.");
        anyhow::bail!("Repository has dirty encrypted files");
    }

    let key_b64: String = if key_source == "-" {
        // Read from stdin
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
    let key = key::key_from_base64(key_b64.trim()).context("Failed to decode key")?;

    // Store key in git config
    key::store_key_in_config(&repo_path, &key).context("Failed to store key in git config")?;

    // Set up git filters
    git::setup_filters(&repo_path).context("Failed to set up git filters")?;

    // Force re-checkout of encrypted files to trigger smudge filter (decrypt them)
    git::force_recheckout(&repo_path, encrypted_files)
        .context("Failed to re-checkout encrypted files")?;

    println!("Repository unlocked successfully");
    Ok(())
}

fn cmd_lock(force: bool) -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    // Find encrypted files and check if any have local modifications
    let encrypted_files = git::find_encrypted_files(&repo_path)?;
    if !force {
        let dirty_files = git::dirty_files(&repo_path, &encrypted_files)?;
        if !dirty_files.is_empty() {
            eprintln!("Error: Cannot lock repository while there are local modifications in some encrypted files:");
            for file in &dirty_files {
                eprintln!("  {}", file.display());
            }
            eprintln!("\nPlease commit, stash or undo your changes before locking, or use --force to force lock.");
            anyhow::bail!("Repository has dirty encrypted files");
        }
    }

    // Remove git filter configuration first (so git won't try to decrypt on checkout)
    git::remove_filters(&repo_path).context("Failed to remove git filters")?;

    // Remove the encryption key
    key::remove_key_from_config(&repo_path).context("Failed to remove key from git config")?;

    // Re-checkout encrypted files to get raw encrypted data from repository
    git::force_recheckout(&repo_path, encrypted_files)
        .context("Failed to re-checkout encrypted files")?;

    println!("Repository locked (key and filters removed, files re-checked in encrypted state)");
    Ok(())
}

fn cmd_status(files: Vec<String>) -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    if files.is_empty() {
        // Show repository status
        let is_unlocked = git::is_unlocked(&repo_path)?;
        let filters_configured = git::filters_configured(&repo_path)?;
        let encrypted_files = git::find_encrypted_files(&repo_path)?;

        println!("Repository: {}", repo_path.display());
        println!(
            "Status: {}",
            if is_unlocked { "unlocked" } else { "locked" }
        );
        println!(
            "Filters configured: {}",
            if filters_configured { "yes" } else { "no" }
        );

        if !encrypted_files.is_empty() {
            println!("\nFiles configured for encryption by git filter:");
            for file in &encrypted_files {
                println!("  🔒 {}", file.display());
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
                "🔒 Encrypted by git filter"
            } else {
                "👀 Not encrypted"
            };
            println!("{:20}: {}", file_str, status);
        }
    }

    Ok(())
}

fn cmd_filter(filter_cmd: FilterCommands) -> Result<()> {
    let repo_path =
        git::find_repo_root(&std::env::current_dir()?).context("Not in a git repository")?;

    match filter_cmd {
        FilterCommands::Clean => filter::clean_filter(&repo_path),
        FilterCommands::Smudge => filter::smudge_filter(&repo_path),
        FilterCommands::Textconv { filename } => filter::diff_textconv(&repo_path, &filename),
    }
}
