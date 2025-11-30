use crate::key;
use anyhow::{Context, Result};
use git2::Repository;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

/// Name of the git filter used for encryption/decryption
pub const FILTER_NAME: &str = "a8c-git-secrets";

/// Name of the git diff driver used for showing decrypted content in diffs
pub const DIFF_NAME: &str = "a8c-git-secrets";

/// Filename for the encryption key file stored in .git directory
const KEY_FILE_NAME: &str = "a8c-git-secrets.key";

/// Git repository wrapper
///
/// This type encapsulates the repository working directory path,
/// and provides a clean API for git operations in the context of this tool.
#[derive(Clone)]
pub struct Repo {
    workdir: PathBuf,
}

impl Repo {
    /// Discover a git repository starting from the current directory
    ///
    /// Returns a `Repo` instance for non-bare repositories.
    ///
    /// # Errors
    /// Returns an error if not in a git repository, or if the repository is bare.
    /// This tool requires a working directory to encrypt/decrypt files,
    /// so bare repositories are not supported.
    pub fn discover() -> Result<Self> {
        let start_path = std::env::current_dir().context("Failed to get current directory")?;
        let repo = Repository::discover(start_path).context("Not a git repository")?;

        // Reject bare repositories - this tool needs a working directory
        if repo.is_bare() {
            anyhow::bail!(
                "Bare repositories are not supported. \
                 This tool encrypts/decrypts files in the working directory, \
                 which bare repositories don't have. \
                 Please use a non-bare repository with a checked-out working tree."
            );
        }

        // Get the working directory root
        let workdir = repo
            .workdir()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Repository has no working directory. \
                     This tool requires a non-bare repository with a checked-out working tree."
                )
            })?
            .to_path_buf();

        Ok(Self { workdir })
    }

    /// Get the repository working directory path
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// Open the git repository
    ///
    /// Returns a `Repository` instance for the repository at this `Repo`'s working directory.
    ///
    /// # Errors
    /// Returns an error if the repository cannot be opened.
    fn open(&self) -> Result<Repository> {
        Repository::open(&self.workdir).context("Failed to open git repository")
    }

    /// Configure git filters for encryption/decryption
    pub fn setup_filters(&self) -> Result<()> {
        let repo = self.open()?;

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
                &format!("{} filter textconv", binary_str),
            )
            .context("Failed to set diff filter")?;

        // Configure filter to be required
        config
            .set_str(&format!("filter.{}.required", FILTER_NAME), "true")
            .context("Failed to set filter required")?;

        Ok(())
    }

    /// Check if filters are already configured
    pub fn filters_configured(&self) -> Result<bool> {
        let repo = self.open()?;
        let config = repo.config().context("Failed to get git config")?;
        match config.get_string(&format!("filter.{}.clean", FILTER_NAME)) {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.code() == git2::ErrorCode::NotFound {
                    Ok(false)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to check if filters are configured: {}",
                        e
                    ))
                }
            }
        }
    }

    /// Remove git filters configuration
    pub fn remove_filters(&self) -> Result<()> {
        let repo = self.open()?;
        let mut config = repo.config().context("Failed to get git config")?;

        let mut errors = Vec::new();
        let filter_keys = [
            format!("filter.{}.clean", FILTER_NAME),
            format!("filter.{}.smudge", FILTER_NAME),
            format!("filter.{}.required", FILTER_NAME),
            format!("diff.{}.textconv", DIFF_NAME),
        ];

        for key in &filter_keys {
            if let Err(e) = config.remove(key) {
                if e.code() != git2::ErrorCode::NotFound {
                    // NotFound is acceptable (config might not exist), but other errors should be reported
                    errors.push(format!("Failed to remove config key '{}': {}", key, e));
                }
            }
        }

        if !errors.is_empty() {
            anyhow::bail!(
                "Failed to remove some filter configurations:\n{}",
                errors.join("\n")
            );
        }

        Ok(())
    }

    /// Load the encryption key from the key file in .git directory
    pub fn load_key(&self) -> Result<key::Key> {
        let key_file = self.key_file_path()?;
        key::Key::from_file(&key_file).with_context(|| {
            format!(
                "Encryption key not found at {}. Run 'a8c-git-secrets unlock' first.",
                key_file.display()
            )
        })
    }

    /// Store the encryption key in a file in the .git directory with secure permissions
    pub fn store_key(&self, key: &key::Key) -> Result<()> {
        let key_file = self.key_file_path()?;

        // Write the key as raw bytes to the file
        fs::write(&key_file, key.as_bytes())
            .with_context(|| format!("Failed to write key file: {}", key_file.display()))?;

        // Set secure file permissions (read/write for owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_file)
                .with_context(|| {
                    format!(
                        "Failed to get metadata for key file: {}",
                        key_file.display()
                    )
                })?
                .permissions();
            perms.set_mode(0o600); // rw------- (owner read/write only)
            fs::set_permissions(&key_file, perms).with_context(|| {
                format!(
                    "Failed to set permissions on key file: {}",
                    key_file.display()
                )
            })?;
        }

        #[cfg(windows)]
        {
            // On Windows, file permissions work differently through ACLs
            // The file will have default permissions which are typically secure
            // in a .git directory that's already protected
            // Note: More sophisticated Windows ACL manipulation would require winapi crate
        }

        Ok(())
    }

    /// Remove the encryption key file from the .git directory
    pub fn remove_key(&self) -> Result<()> {
        let key_file = self.key_file_path()?;

        // Remove the key file, but it's okay if it doesn't exist
        if key_file.exists() {
            fs::remove_file(&key_file)
                .with_context(|| format!("Failed to remove key file: {}", key_file.display()))?;
        }

        Ok(())
    }

    /// Check if repository is unlocked (key file exists)
    pub fn is_unlocked(&self) -> Result<bool> {
        // Try to load the key - if it succeeds, the repository is unlocked
        match self.load_key() {
            Ok(_) => Ok(true),   // Key file exists, repository is unlocked
            Err(_) => Ok(false), // Key file doesn't exist or can't be loaded, repository is locked
        }
    }

    /// Check if a specific file has the encryption filter attribute set
    pub fn is_file_encrypted(&self, file_path: &Path) -> Result<bool> {
        let rel_path = self.relative_path(file_path);
        self.has_encryption_filter(rel_path)
    }

    /// Find all files in the working directory that have the encryption filter attribute set
    /// Uses git2's attribute checking to properly handle .gitattributes patterns
    pub fn find_encrypted_files(&self) -> Result<Vec<PathBuf>> {
        let mut encrypted_files = Vec::new();

        // Walk through all files in the working directory
        for entry in WalkDir::new(&self.workdir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let full_path = entry.path();

            // Get relative path from repo root
            let rel_path = self.relative_path(full_path);

            // Check if this file has the encryption filter attribute set
            if self.has_encryption_filter(rel_path)? {
                encrypted_files.push(rel_path.to_path_buf());
            }
        }

        Ok(encrypted_files)
    }

    /// Check if any of the given files have local modifications (are "dirty")
    pub fn dirty_files(&self, files: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let repo = self.open()?;

        let mut dirty_files = Vec::new();

        // Check status of each file
        for file_path in files {
            // Get file status
            let status = repo
                .status_file(file_path.as_path())
                .with_context(|| format!("Failed to get status for {}", file_path.display()))?;

            // Check if file has any modifications (workdir or index)
            if status.intersects(
                git2::Status::WT_MODIFIED
                    | git2::Status::WT_DELETED
                    | git2::Status::WT_TYPECHANGE
                    | git2::Status::INDEX_MODIFIED
                    | git2::Status::INDEX_DELETED
                    | git2::Status::INDEX_TYPECHANGE
                    | git2::Status::INDEX_RENAMED
                    | git2::Status::INDEX_NEW,
            ) {
                dirty_files.push(file_path.clone());
            }
        }

        Ok(dirty_files)
    }

    /// Force re-checkout of files from the repository
    /// Removes files from index and checks them out from HEAD, which will trigger git filters
    ///  - To restore the files to their encrypted state after removing filters (during lock)
    ///  - Or to have the files decrypted after adding filters and key (during unlock)
    pub fn force_recheckout(&self, files: Vec<PathBuf>) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }

        println!("Re-checking out {} encrypted file(s)...", files.len());

        // NOTE: `git2`'s `checkout_head` doesn't seem to apply the smudge filter (bug in the implementation?)
        //       despite all our efforts and use of `disable_filters(false)`.
        //       This is why this method is implemented with `Command::new("git")` instead of using `git2` API.

        // Step 1: Remove files from the index (equivalent to `git rm --cached <files>`)
        let mut rm_cmd = Command::new("git");
        rm_cmd.arg("rm").arg("--cached").current_dir(&self.workdir);
        for file_path in &files {
            rm_cmd.arg(file_path.as_path());
        }
        let rm_output = rm_cmd
            .output()
            .context("Failed to execute git rm --cached")?;
        if !rm_output.status.success() {
            anyhow::bail!(
                "git rm --cached failed: {}\nstderr: {}",
                rm_output.status,
                String::from_utf8_lossy(&rm_output.stderr)
            );
        }

        // Step 2: Checkout files from HEAD (equivalent to `git checkout HEAD -- <files>`)
        // This will trigger git filters (smudge filter if filters are configured)
        let mut checkout_cmd = Command::new("git");
        checkout_cmd
            .arg("checkout")
            .arg("HEAD")
            .arg("--")
            .current_dir(&self.workdir);
        for file_path in &files {
            checkout_cmd.arg(file_path.as_path());
        }
        let checkout_output = checkout_cmd
            .output()
            .context("Failed to execute git checkout command")?;
        if !checkout_output.status.success() {
            let stderr = String::from_utf8_lossy(&checkout_output.stderr);
            anyhow::bail!(
                "git checkout HEAD -- <files> failed: {}\nstderr: {}",
                checkout_output.status,
                stderr
            );
        }

        for file_path in &files {
            println!("  Re-checked out: {}", file_path.display());
        }

        Ok(())
    }

    /// Get the path to the key file in the .git directory
    fn key_file_path(&self) -> Result<PathBuf> {
        let repo = self.open()?;
        let git_dir = repo.path();
        Ok(git_dir.join(KEY_FILE_NAME))
    }

    /// Check if a file has the encryption filter attribute set
    fn has_encryption_filter(&self, rel_path: &Path) -> Result<bool> {
        let repo = self.open()?;
        match repo.get_attr(rel_path, "filter", git2::AttrCheckFlags::FILE_THEN_INDEX) {
            Ok(Some(attr_value)) => Ok(attr_value == FILTER_NAME),
            Ok(None) => Ok(false),
            Err(_) => Ok(false), // On error, assume not encrypted
        }
    }

    /// Get relative path from repository working directory root
    /// If the path is already relative or can't be stripped, returns the original path
    fn relative_path<'a>(&self, file_path: &'a Path) -> &'a Path {
        file_path.strip_prefix(&self.workdir).unwrap_or(file_path)
    }
}

// === Private Helper functions === //

/// Get the path to the a8c-git-secrets binary
fn get_binary_path() -> Result<PathBuf> {
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
            // If we have a relative path that exists, try to make it absolute
            if let Ok(cwd) = std::env::current_dir() {
                let absolute = cwd.join(&exe_path);
                if absolute.exists() {
                    return Ok(absolute);
                }
            }
        }
    }

    // Fallback: use the binary name (git will look in PATH)
    // This is less ideal but acceptable if the binary is in PATH
    let binary_name = if cfg!(windows) {
        "a8c-git-secrets.exe"
    } else {
        "a8c-git-secrets"
    };

    Ok(PathBuf::from(binary_name))
}
