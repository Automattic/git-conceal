use crate::repo;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json;
use std::fmt;
use std::path::PathBuf;

pub fn cmd_status(files: Vec<String>, json: bool) -> Result<()> {
    let repo = repo::Repo::discover()?;

    if files.is_empty() {
        // Show repository status
        let repo_status = if repo.is_unlocked()? {
            LockStatus::Unlocked
        } else {
            LockStatus::Locked
        };
        let filters_configured = repo.filters_configured()?;
        let has_untracked_files = repo.has_untracked_files()?;
        let encrypted_files: Vec<_> = repo
            .find_filtered_files()?
            .collect::<Result<Vec<_>>>()
            .context("Failed to get file path")?;

        let status = RepositoryStatus {
            repository: repo.workdir().to_string_lossy().into_owned(),
            status: repo_status,
            filters_configured,
            encrypted_files,
            has_untracked_files,
        };

        if json {
            println!("{}", serde_json::to_string_pretty(&status)?);
        } else {
            print!("{}", status);
        }
    } else {
        // Check status for specific files
        let file_statuses: Vec<FileStatus> = files
            .iter()
            .map(|file_str| {
                let file_path = std::path::Path::new(file_str);
                let is_filtered = repo.is_filtered_file(file_path)?;
                Ok(FileStatus {
                    file: file_path.to_path_buf(),
                    encrypted: is_filtered,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let status_list = FileStatusList {
            files: file_statuses,
        };

        if json {
            println!("{}", serde_json::to_string_pretty(&status_list)?);
        } else {
            print!("{}", status_list);
        }
    }

    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LockStatus {
    Locked,
    Unlocked,
}

impl fmt::Display for LockStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockStatus::Locked => write!(f, "locked"),
            LockStatus::Unlocked => write!(f, "unlocked"),
        }
    }
}

#[derive(Serialize)]
pub struct RepositoryStatus {
    pub repository: String,
    pub status: LockStatus,
    pub filters_configured: bool,
    pub encrypted_files: Vec<PathBuf>,
    pub has_untracked_files: bool,
}

impl fmt::Display for RepositoryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Repository: {}", self.repository)?;
        writeln!(f, "Status: {}", self.status)?;
        writeln!(
            f,
            "Filters configured: {}",
            if self.filters_configured { "yes" } else { "no" }
        )?;

        writeln!(
            f,
            "\nTracked files configured for encryption by Git filter:"
        )?;
        if self.encrypted_files.is_empty() {
            writeln!(f, "  (none)")?;
        } else {
            for file in &self.encrypted_files {
                writeln!(f, "  🔒 {}", file.to_string_lossy())?;
            }
        }

        // Only show warning if there are actually untracked files
        if self.has_untracked_files {
            writeln!(
                f,
                "\nNote: You have untracked files in your working copy. Even if some\n\
                of those new files match the filter patterns in `.gitattributes`,\n\
                they won't be listed here until you `git add` them to the staging area."
            )?;
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub struct FileStatus {
    pub file: PathBuf,
    pub encrypted: bool,
}

impl fmt::Display for FileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.encrypted {
            "🔒 Encrypted in the repository"
        } else {
            "👀 Not encrypted in the repository"
        };
        write!(f, "{:20}: {}", self.file.to_string_lossy(), status)
    }
}

#[derive(Serialize)]
pub struct FileStatusList {
    pub files: Vec<FileStatus>,
}

impl fmt::Display for FileStatusList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for file_status in &self.files {
            writeln!(f, "{}", file_status)?;
        }
        Ok(())
    }
}
