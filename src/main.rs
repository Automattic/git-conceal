#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Transparent file encryption in Git using symmetric keys
//!
//! This tool provides transparent encryption and decryption of files in Git repositories,
//! similar to git-crypt but using only symmetric keys (no GPG support).
//!
//! Files are automatically encrypted on commit and decrypted on checkout using Git's
//! clean/smudge filter mechanism.

mod commands;
mod crypto;
mod fs_helpers;
mod key;
mod repo;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Binary name, obtained from Cargo.toml at compile time
pub const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

#[derive(Parser)]
#[command(name = BINARY_NAME)]
#[command(about = "Transparent file encryption in Git using symmetric keys")]
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
        long_about = const_format::formatcp!("Use this command to set up a repository to start using {}. \n\
                      It generates an encryption key, sets up git filters locally for the repository, \
                      and provides instructions to save the key and start adding files to be encrypted.", BINARY_NAME)
    )]
    Init,
    // Unlock
    #[command(
        about = "Unlock an encrypted repository and decrypt existing files",
        long_about = "Use this command to unlock a repository that already contains encrypted files. \n\
                      It sets up Git filters, saves the key you provide in a key file, \
                      and decrypts any encrypted files in the working directory."
    )]
    Unlock {
        /// Key source
        #[arg(
            value_name = "KEY",
            long_help = "- 'BASE64KEY': the base64-encoded key passed directly as argument\n\
                         - 'env:VARNAME': read the base64-encoded key from the given environment variable (recommended on CI)\n\
                         - '-': read the raw binary key from stdin (expects raw binary, 32 bytes as input)"
        )]
        key_source: commands::unlock::KeySource,
    },
    // Lock
    #[command(
        about = "Lock a decrypted repository and restore files to their encrypted state",
        long_about = "Use this command to remove the encryption key file and Git filters from the local repository \
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
        /// Output status in JSON format
        #[arg(long)]
        json: bool,
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

/// Key management subcommands
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

/// Git filter subcommands (internal use)
#[derive(Subcommand)]
enum FilterCommands {
    /// Clean filter: encrypt data (used by Git on commit)
    Clean,
    /// Smudge filter: decrypt data (used by Git on checkout)
    Smudge,
    /// Textconv: decrypt file for Git diff (takes filename as argument)
    Textconv {
        /// Filename to decrypt and show in diff
        #[arg(value_name = "FILE")]
        filename: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => commands::init::cmd_init(),
        Commands::Unlock { key_source } => commands::unlock::cmd_unlock(key_source),
        Commands::Lock { force } => commands::lock::cmd_lock(force),
        Commands::Status { files, json } => commands::status::cmd_status(&files, json),
        Commands::Key { key_cmd } => match key_cmd {
            KeyCommands::Show { raw } => commands::key::cmd_key_show(raw),
            KeyCommands::Rotate { skip_confirmation } => {
                commands::key::cmd_key_rotate(skip_confirmation)
            }
        },
        Commands::Filter { filter_cmd } => {
            let repo = repo::Repo::discover()?;
            match filter_cmd {
                FilterCommands::Clean => commands::filter::clean_filter(&repo),
                FilterCommands::Smudge => commands::filter::smudge_filter(&repo),
                FilterCommands::Textconv { filename } => {
                    commands::filter::diff_textconv(&repo, &filename)
                }
            }
        }
    }
}
