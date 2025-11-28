use anyhow::{Context, Result};
use git2::Repository;
use std::path::{Path, PathBuf};

const FILTER_NAME: &str = "a8c-git-secrets";
const DIFF_NAME: &str = "a8c-git-secrets";

/// Find the git repository root using git2's discover function
pub fn find_repo_root(start_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(start_path).context("Not a git repository")?;

    // Get the workdir (working directory) if available, otherwise use the gitdir's parent
    let repo_path = repo
        .workdir()
        .or_else(|| repo.path().parent())
        .ok_or_else(|| anyhow::anyhow!("Could not determine repository root"))?
        .to_path_buf();

    Ok(repo_path)
}

/// Get the path to the a8c-git-secrets binary
fn get_binary_path() -> Result<PathBuf> {
    let binary_name = if cfg!(windows) {
        "a8c-git-secrets.exe"
    } else {
        "a8c-git-secrets"
    };

    // First, try using the current executable path (most reliable)
    if let Ok(exe_path) = std::env::current_exe() {
        // Resolve any symlinks to get the actual path
        if exe_path.exists() {
            // Try to canonicalize to get absolute path
            if let Ok(canonical) = exe_path.canonicalize() {
                return Ok(canonical);
            }
            // If canonicalize fails, use the path as-is if it's absolute
            if exe_path.is_absolute() {
                return Ok(exe_path);
            }
        }
    }

    // Fallback: try to find in PATH
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(if cfg!(windows) { ";" } else { ":" }) {
            let candidate = Path::new(dir).join(binary_name);
            if candidate.exists() {
                // Try to get absolute path
                if let Ok(absolute) = candidate.canonicalize() {
                    return Ok(absolute);
                }
                if candidate.is_absolute() {
                    return Ok(candidate);
                }
            }
        }
    }

    // Last resort: use the binary name (git will look in PATH)
    Ok(PathBuf::from(binary_name))
}

/// Configure git filters for encryption/decryption
pub fn setup_filters(repo_path: &Path) -> Result<()> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let mut config = repo.config().context("Failed to get git config")?;

    let binary_path = get_binary_path().context("Failed to determine binary path")?;
    let binary_str = binary_path.to_string_lossy();

    // Configure clean filter (encrypt on commit)
    config
        .set_str(
            &format!("filter.{}.clean", FILTER_NAME),
            &format!("{} filter clean", binary_str),
        )
        .context("Failed to set clean filter")?;

    // Configure smudge filter (decrypt on checkout)
    config
        .set_str(
            &format!("filter.{}.smudge", FILTER_NAME),
            &format!("{} filter smudge", binary_str),
        )
        .context("Failed to set smudge filter")?;

    // Configure diff filter (decrypt for diff)
    config
        .set_str(
            &format!("diff.{}.textconv", DIFF_NAME),
            &format!("{} filter smudge", binary_str),
        )
        .context("Failed to set diff filter")?;

    // Configure filter to be required
    config
        .set_str(&format!("filter.{}.required", FILTER_NAME), "true")
        .context("Failed to set filter required")?;

    Ok(())
}

/// Check if filters are already configured
pub fn filters_configured(repo_path: &Path) -> Result<bool> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let config = repo.config().context("Failed to get git config")?;

    match config.get_string(&format!("filter.{}.clean", FILTER_NAME)) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check if repository is locked (no key in config)
pub fn is_locked(repo_path: &Path) -> Result<bool> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let config = repo.config().context("Failed to get git config")?;

    match config.get_string("a8c-git-secrets.key") {
        Ok(_) => Ok(false),
        Err(_) => Ok(true),
    }
}

/// Remove git filters configuration
pub fn remove_filters(repo_path: &Path) -> Result<()> {
    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let mut config = repo.config().context("Failed to get git config")?;

    // Remove filter configuration
    let _ = config.remove(&format!("filter.{}.clean", FILTER_NAME));
    let _ = config.remove(&format!("filter.{}.smudge", FILTER_NAME));
    let _ = config.remove(&format!("filter.{}.required", FILTER_NAME));
    let _ = config.remove(&format!("diff.{}.textconv", DIFF_NAME));

    Ok(())
}

/// Re-checkout encrypted files from the repository (to get raw encrypted data)
pub fn recheckout_encrypted_files(repo_path: &Path) -> Result<()> {
    use std::process::Command;

    let encrypted_files = find_encrypted_files(repo_path)?;

    if encrypted_files.is_empty() {
        return Ok(());
    }

    println!("Re-checking out {} encrypted file(s)...", encrypted_files.len());

    // Use git checkout to restore files from HEAD
    // This will get the raw encrypted data from the repository
    for file_path in &encrypted_files {
        let file_str = file_path.to_string_lossy().to_string();
        let status = Command::new("git")
            .arg("checkout")
            .arg("HEAD")
            .arg("--")
            .arg(&file_str)
            .current_dir(repo_path)
            .status()
            .context("Failed to execute git checkout")?;

        if !status.success() {
            eprintln!("Warning: Failed to re-checkout {}", file_path.display());
        } else {
            println!("  Re-checked out: {}", file_path.display());
        }
    }

    Ok(())
}


/// Find all files in the working directory that have the encryption filter attribute set
/// Uses git2's attribute checking to properly handle .gitattributes patterns
pub fn find_encrypted_files(repo_path: &Path) -> Result<Vec<PathBuf>> {
    use walkdir::WalkDir;

    let repo = Repository::open(repo_path).context("Failed to open git repository")?;

    let mut encrypted_files = Vec::new();

    // Walk through all files in the working directory
    for entry in WalkDir::new(repo_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let full_path = entry.path();

        // Get relative path from repo root
        let rel_path = match full_path.strip_prefix(repo_path) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Check if this file has the filter attribute set to our filter name
        // git2's get_attr returns Some(value) if the attribute is set, None otherwise
        match repo.get_attr(rel_path, "filter", git2::AttrCheckFlags::FILE_THEN_INDEX) {
            Ok(Some(attr_value)) => {
                if attr_value == FILTER_NAME {
                    encrypted_files.push(rel_path.to_path_buf());
                }
            }
            Ok(None) => {
                // Attribute not set, skip
            }
            Err(_) => {
                // Error checking attribute, skip
                continue;
            }
        }
    }

    Ok(encrypted_files)
}
