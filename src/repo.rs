use crate::key;
use anyhow::{Context, Result};
use git2::Repository;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        Self::from_repository(&repo)
    }

    /// Create a Repo instance from a git2 Repository
    ///
    /// Validates that the repository is not bare and has a working directory.
    ///
    /// # Errors
    /// Returns an error if the repository is bare or has no working directory.
    fn from_repository(repo: &Repository) -> Result<Self> {
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
    pub fn is_filtered_file(&self, file_path: &Path) -> Result<bool> {
        let rel_path = self.relative_path(file_path);
        self.has_encryption_filter(rel_path)
    }

    /// Find all files in the repository that have the encryption filter attribute set
    ///
    /// Returns an iterator that yields filtered files as they are discovered.
    /// Only includes files that are tracked by git (in the index).
    /// Untracked files are not included because they haven't been processed by git filters
    /// yet and aren't in the object database.
    ///
    /// Uses git2's attribute checking to properly handle .gitattributes patterns.
    pub fn find_filtered_files(&self) -> Result<IndexFilteredFilesIterator<'_>> {
        let git_repo = self.open()?;
        let index = git_repo.index().context("Failed to get git index")?;
        let length = index.len();
        Ok(IndexFilteredFilesIterator {
            repo: self,
            git_index: index,
            range: 0..length,
        })
    }

    /// Check if there are any untracked, unignored files in the working directory
    pub fn has_untracked_files(&self) -> Result<bool> {
        let repo = self.open()?;

        let mut status_opts = git2::StatusOptions::new();
        status_opts
            .include_untracked(true)
            .include_ignored(false)
            .include_unmodified(false);

        let statuses = repo
            .statuses(Some(&mut status_opts))
            .context("Failed to get git status")?;

        // Check if there are any untracked files (WT_NEW)
        for entry in statuses.iter() {
            if entry.status().intersects(git2::Status::WT_NEW) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get all filtered files that have local modifications (are "dirty")
    pub fn dirty_filtered_files(&self) -> Result<Vec<PathBuf>> {
        let repo = self.open()?;

        let mut status_opts = git2::StatusOptions::new();
        status_opts
            .include_untracked(false)
            .include_ignored(false)
            .include_unmodified(false)
            .renames_head_to_index(true)
            .renames_index_to_workdir(true);

        let statuses = repo
            .statuses(Some(&mut status_opts))
            .context("Failed to get git status")?;

        let mut dirty_filtered = Vec::new();
        let status_flags = git2::Status::WT_MODIFIED
            | git2::Status::WT_DELETED
            | git2::Status::WT_TYPECHANGE
            | git2::Status::INDEX_MODIFIED
            | git2::Status::INDEX_DELETED
            | git2::Status::INDEX_TYPECHANGE
            | git2::Status::INDEX_RENAMED
            | git2::Status::INDEX_NEW;

        for entry in statuses.iter() {
            if entry.status().intersects(status_flags) {
                if let Some(path) = entry.path() {
                    let file_path = PathBuf::from(path);
                    if self.is_filtered_file(&file_path)? {
                        dirty_filtered.push(file_path);
                    }
                }
            }
        }

        Ok(dirty_filtered)
    }

    /// Force re-checkout of files from the repository
    /// Removes files from index and checks them out from HEAD, which will trigger git filters
    ///  - To restore the files to their encrypted state after removing filters (during lock)
    ///  - Or to have the files decrypted after adding filters and key (during unlock)
    ///
    /// Processes files from the iterator, building both git commands in a single loop
    /// before executing them.
    pub fn force_recheckout<I>(&self, files: I) -> Result<()>
    where
        I: Iterator<Item = Result<PathBuf>>,
    {
        // NOTE: `git2`'s `checkout_head` doesn't seem to apply the smudge filter (bug in the implementation?)
        //       despite all our efforts and use of `disable_filters(false)`.
        //       This is why this method is implemented with `Command::new("git")` instead of using `git2` API.

        println!("Re-checking out encrypted files...");

        // Step 1: Remove files from the index (equivalent to `git rm --cached <files>`)
        let mut rm_cmd = Command::new("git");
        rm_cmd.arg("rm").arg("--cached").current_dir(&self.workdir);
        // Step 2: Checkout files from HEAD (equivalent to `git checkout HEAD -- <files>`)
        // This will trigger git filters (smudge filter if filters are configured)
        let mut checkout_cmd = Command::new("git");
        checkout_cmd
            .arg("checkout")
            .arg("HEAD")
            .arg("--")
            .current_dir(&self.workdir);

        // Add all files to both commands in a single loop
        let mut has_files = false;
        for file_result in files {
            let file_path = file_result?;
            println!("  Will re-checkout: {}", file_path.display());
            rm_cmd.arg(file_path.as_path());
            checkout_cmd.arg(file_path.as_path());
            has_files = true;
        }
        if !has_files {
            println!(" -- No encrypted files found in the repository.");
            return Ok(());
        }

        // Execute rm command
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

        // Execute checkout command
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

        Ok(())
    }

    /// Re-normalize files in the git index
    ///
    /// Runs `git add --renormalize` on the specified files, which will re-apply
    /// git filters (clean filter) to re-encrypt files with the current key.
    /// This is useful after rotating the encryption key to re-encrypt all
    /// filtered files with the new key.
    ///
    /// # Errors
    /// Returns an error if the git command fails or if any of the files cannot be processed.
    pub fn renormalize_files<I>(&self, files: I) -> Result<()>
    where
        I: Iterator<Item = Result<PathBuf>>,
    {
        let mut add_cmd = Command::new("git");
        add_cmd
            .arg("add")
            .arg("--renormalize")
            .current_dir(&self.workdir);

        let mut has_files = false;
        for file_result in files {
            let file_path = file_result?;
            add_cmd.arg(file_path.as_path());
            has_files = true;
        }

        if !has_files {
            println!(" -- No encrypted files found in the repository.");
            return Ok(());
        }

        let add_output = add_cmd
            .output()
            .context("Failed to execute git add --renormalize")?;
        if !add_output.status.success() {
            anyhow::bail!(
                "git add --renormalize failed: {}\nstderr: {}",
                add_output.status,
                String::from_utf8_lossy(&add_output.stderr)
            );
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
            Err(_) => Ok(false),
        }
    }

    /// Get relative path from repository working directory root
    /// If the path is already relative or can't be stripped, returns the original path
    fn relative_path<'a>(&self, file_path: &'a Path) -> &'a Path {
        file_path.strip_prefix(&self.workdir).unwrap_or(file_path)
    }
}

// === Helper types and functions === //

/// Iterator over filtered files in the git index
///
/// This iterator efficiently yields files that have the encryption filter attribute set
/// by only checking files that are tracked by git (in the index).
/// Untracked files are not included because they haven't been processed by git filters
/// yet and aren't in the object database.
pub struct IndexFilteredFilesIterator<'a> {
    repo: &'a Repo,
    git_index: git2::Index,
    range: Range<usize>,
}

impl<'repo> Iterator for IndexFilteredFilesIterator<'repo> {
    type Item = Result<PathBuf>;

    fn next(&mut self) -> Option<Self::Item> {
        // We can't store the index.iter() iterator due to lifetime constraints
        // so we iterate manually by index.
        for idx in self.range.by_ref() {
            let entry = self.git_index.get(idx)?;
            let path_bytes = entry.path;
            let path_str = match std::str::from_utf8(&path_bytes) {
                Ok(s) => s,
                Err(e) => return Some(Err(anyhow::anyhow!("Invalid UTF-8 in path: {}", e))),
            };

            let file_path = PathBuf::from(path_str);
            match self.repo.has_encryption_filter(&file_path) {
                Ok(true) => return Some(Ok(file_path)),
                Ok(false) => continue, // Not filtered, skip
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }
}

/// Get the path to the a8c-git-secrets binary.
/// Needed internally to configure the git filters.
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

// === Tests === //

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    /// Create a temporary git repository for testing
    fn setup_test_repo() -> Result<(TempDir, Repo)> {
        let temp_dir = TempDir::new()?;
        let repo_path = temp_dir.path();

        // Initialize git repository
        Command::new("git")
            .arg("init")
            .current_dir(repo_path)
            .output()?;

        // Set up minimal git config to avoid warnings
        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(repo_path)
            .output()?;
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(repo_path)
            .output()?;

        // Create an initial commit so we have a HEAD
        fs::write(repo_path.join("README.md"), "Test repo")?;
        Command::new("git")
            .args(["add", "README.md"])
            .current_dir(repo_path)
            .output()?;
        Command::new("git")
            .args(["commit", "-m", "Initial commit"])
            .current_dir(repo_path)
            .output()?;

        // Create Repo instance from the repository
        let repository = Repository::open(repo_path).context("Failed to open git repository")?;
        let repo = Repo::from_repository(&repository)?;

        Ok((temp_dir, repo))
    }

    #[test]
    fn test_repo_discover() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        assert!(repo.workdir().exists());
    }

    #[test]
    fn test_repo_workdir() {
        let (temp_dir, repo) = setup_test_repo().unwrap();
        let workdir = repo.workdir();
        // Canonicalize both paths to handle any normalization differences
        let workdir_canonical = workdir.canonicalize().unwrap();
        let temp_dir_canonical = temp_dir.path().canonicalize().unwrap();
        assert_eq!(workdir_canonical, temp_dir_canonical);
    }

    #[test]
    fn test_store_and_load_key() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let key = key::Key::generate();
        repo.store_key(&key).unwrap();
        let loaded_key = repo.load_key().unwrap();
        assert_eq!(loaded_key.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_load_key_nonexistent() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let result = repo.load_key();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Encryption key not found"));
    }

    #[test]
    fn test_store_key_overwrites() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let key1 = key::Key::generate();
        let key2 = key::Key::generate();

        repo.store_key(&key1).unwrap();
        assert_eq!(repo.load_key().unwrap().as_bytes(), key1.as_bytes());

        repo.store_key(&key2).unwrap();
        assert_eq!(repo.load_key().unwrap().as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_is_unlocked() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();

        // Initially should be locked
        assert!(!repo.is_unlocked().unwrap());

        let key = key::Key::generate();
        repo.store_key(&key).unwrap();

        // Now should be unlocked
        assert!(repo.is_unlocked().unwrap());
    }

    #[test]
    fn test_remove_key() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let key = key::Key::generate();

        // Store key
        repo.store_key(&key).unwrap();
        assert!(repo.is_unlocked().unwrap());

        // Remove key
        repo.remove_key().unwrap();
        assert!(!repo.is_unlocked().unwrap());

        // Removing again should be fine (idempotent)
        repo.remove_key().unwrap();
    }

    #[test]
    fn test_setup_filters() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();

        repo.setup_filters().unwrap();
        assert!(repo.filters_configured().unwrap());
    }

    #[test]
    fn test_filters_configured_initially_false() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        assert!(!repo.filters_configured().unwrap());
    }

    #[test]
    fn test_remove_filters() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();

        // Setup filters
        repo.setup_filters().unwrap();
        assert!(repo.filters_configured().unwrap());

        // Remove filters
        repo.remove_filters().unwrap();
        assert!(!repo.filters_configured().unwrap());

        // Removing again should be fine (idempotent)
        repo.remove_filters().unwrap();
    }

    #[test]
    fn test_is_filtered_file() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let repo_path = repo.workdir();

        // Create .gitattributes
        let gitattributes_content =
            format!("secret.txt filter={} diff={}\n", FILTER_NAME, DIFF_NAME);
        fs::write(repo_path.join(".gitattributes"), gitattributes_content).unwrap();

        // Create files
        fs::write(repo_path.join("secret.txt"), "secret").unwrap();
        fs::write(repo_path.join("public.txt"), "public").unwrap();

        // Check filter status
        assert!(repo
            .is_filtered_file(&repo_path.join("secret.txt"))
            .unwrap());
        assert!(!repo
            .is_filtered_file(&repo_path.join("public.txt"))
            .unwrap());
    }

    #[test]
    fn test_find_filtered_files_empty() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();

        // No files with encryption filter, so should be empty
        let filtered_files: Result<Vec<_>> = repo.find_filtered_files().unwrap().collect();
        assert!(filtered_files.unwrap().is_empty());
    }

    #[test]
    fn test_find_filtered_files_multiple() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let repo_path = repo.workdir();

        // Create .gitattributes with multiple patterns
        let gitattributes_content = format!(
            "secret1.txt filter={} diff={}\n\
             secret2.txt filter={} diff={}\n\
             *.key filter={} diff={}\n",
            FILTER_NAME, DIFF_NAME, FILTER_NAME, DIFF_NAME, FILTER_NAME, DIFF_NAME
        );
        fs::write(repo_path.join(".gitattributes"), gitattributes_content).unwrap();

        // Create files
        fs::write(repo_path.join("secret1.txt"), "secret1").unwrap();
        fs::write(repo_path.join("secret2.txt"), "secret2").unwrap();
        fs::write(repo_path.join("my.key"), "key content").unwrap();
        fs::write(repo_path.join("public.txt"), "public").unwrap();

        // Add files to git so they're tracked
        Command::new("git")
            .args([
                "add",
                ".gitattributes",
                "secret1.txt",
                "secret2.txt",
                "my.key",
                "public.txt",
            ])
            .current_dir(repo_path)
            .output()
            .unwrap();

        // Find filtered files
        let filtered_files: Result<Vec<_>> = repo.find_filtered_files().unwrap().collect();
        let filtered_files = filtered_files.unwrap();
        assert_eq!(filtered_files.len(), 3);
        assert!(filtered_files.contains(&PathBuf::from("secret1.txt")));
        assert!(filtered_files.contains(&PathBuf::from("secret2.txt")));
        assert!(filtered_files.contains(&PathBuf::from("my.key")));
    }

    #[test]
    fn test_dirty_filtered_files_none_dirty() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let repo_path = repo.workdir();

        // Create .gitattributes with encryption filter
        let gitattributes_content =
            format!("secret.txt filter={} diff={}\n", FILTER_NAME, DIFF_NAME);
        fs::write(repo_path.join(".gitattributes"), gitattributes_content).unwrap();

        // Create and commit a filtered file
        fs::write(repo_path.join("secret.txt"), "secret content").unwrap();
        Command::new("git")
            .args(["add", ".gitattributes", "secret.txt"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Add secret file"])
            .current_dir(repo_path)
            .output()
            .unwrap();

        // No files should be dirty
        let dirty_filtered = repo.dirty_filtered_files().unwrap();
        assert!(dirty_filtered.is_empty());
    }

    #[test]
    fn test_dirty_filtered_files_dirty_but_not_filtered() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let repo_path = repo.workdir();

        // Create .gitattributes with encryption filter for secret.txt only
        let gitattributes_content =
            format!("secret.txt filter={} diff={}\n", FILTER_NAME, DIFF_NAME);
        fs::write(repo_path.join(".gitattributes"), gitattributes_content).unwrap();

        // Create and commit both a filtered and non-filtered file
        fs::write(repo_path.join("secret.txt"), "secret content").unwrap();
        fs::write(repo_path.join("public.txt"), "public content").unwrap();
        Command::new("git")
            .args(["add", ".gitattributes", "secret.txt", "public.txt"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Add files"])
            .current_dir(repo_path)
            .output()
            .unwrap();

        // Modify only the non-filtered file
        fs::write(repo_path.join("public.txt"), "modified public content").unwrap();

        // No filtered files should be dirty (only public.txt is dirty, but it's not filtered)
        let dirty_filtered = repo.dirty_filtered_files().unwrap();
        assert!(dirty_filtered.is_empty());
    }

    #[test]
    fn test_dirty_filtered_files_some_dirty_and_filtered() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let repo_path = repo.workdir();

        // Create .gitattributes with encryption filter for secret files
        let gitattributes_content = format!(
            "secret1.txt filter={} diff={}\n\
             secret2.txt filter={} diff={}\n",
            FILTER_NAME, DIFF_NAME, FILTER_NAME, DIFF_NAME
        );
        fs::write(repo_path.join(".gitattributes"), gitattributes_content).unwrap();

        // Create and commit filtered files and a non-filtered file
        fs::write(repo_path.join("secret1.txt"), "secret1 content").unwrap();
        fs::write(repo_path.join("secret2.txt"), "secret2 content").unwrap();
        fs::write(repo_path.join("public.txt"), "public content").unwrap();
        Command::new("git")
            .args([
                "add",
                ".gitattributes",
                "secret1.txt",
                "secret2.txt",
                "public.txt",
            ])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Add files"])
            .current_dir(repo_path)
            .output()
            .unwrap();

        // Modify one filtered file and the non-filtered file
        fs::write(repo_path.join("secret1.txt"), "modified secret1 content").unwrap();
        fs::write(repo_path.join("public.txt"), "modified public content").unwrap();

        // Only the filtered file that was modified should be in the result
        let dirty_filtered = repo.dirty_filtered_files().unwrap();
        assert_eq!(dirty_filtered.len(), 1);
        assert!(dirty_filtered[0].ends_with("secret1.txt"));
    }

    #[test]
    fn test_force_recheckout_empty_list() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();

        // Should succeed with empty iterator
        repo.force_recheckout(std::iter::empty()).unwrap();
    }

    #[test]
    fn test_relative_path() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let repo_path = repo.workdir();

        // Test with absolute path
        let abs_path = repo_path.join("file.txt");
        let rel_path = repo.relative_path(&abs_path);
        assert_eq!(rel_path, Path::new("file.txt"));

        // Test with relative path (should return as-is)
        let rel_path2 = Path::new("file.txt");
        let result = repo.relative_path(rel_path2);
        assert_eq!(result, rel_path2);
    }

    #[test]
    fn test_key_file_path() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();

        let key_path = repo.key_file_path().unwrap();
        assert!(key_path.to_string_lossy().contains(KEY_FILE_NAME));
        assert!(key_path.to_string_lossy().contains(".git"));
    }

    #[test]
    fn test_store_key_creates_file() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let key = key::Key::generate();

        repo.store_key(&key).unwrap();

        let key_path = repo.key_file_path().unwrap();
        assert!(key_path.exists());
        assert_eq!(fs::read(&key_path).unwrap().len(), key::Key::KEY_SIZE);
    }

    #[test]
    fn test_find_filtered_files_in_subdirectory() {
        let (_temp_dir, repo) = setup_test_repo().unwrap();
        let repo_path = repo.workdir();

        // Create .gitattributes
        let gitattributes_content =
            format!("secrets/* filter={} diff={}\n", FILTER_NAME, DIFF_NAME);
        fs::write(repo_path.join(".gitattributes"), gitattributes_content).unwrap();

        // Create subdirectory and file
        fs::create_dir_all(repo_path.join("secrets")).unwrap();
        fs::write(repo_path.join("secrets").join("secret.txt"), "secret").unwrap();

        // Add files to git so they're tracked
        Command::new("git")
            .args(["add", ".gitattributes", "secrets/secret.txt"])
            .current_dir(repo_path)
            .output()
            .unwrap();

        // Find filtered files - should find the tracked file
        let filtered_files: Result<Vec<_>> = repo.find_filtered_files().unwrap().collect();
        let filtered_files = filtered_files.unwrap();
        assert_eq!(filtered_files.len(), 1);
        assert!(filtered_files[0].to_string_lossy().contains("secrets"));
    }
}
