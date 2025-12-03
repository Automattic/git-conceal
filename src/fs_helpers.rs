//! Filesystem and platform-specific helper functions
//!
//! This module contains helper functions for filesystem operations and
//! platform-specific functionality like setting file permissions and
//! determining binary paths.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::BINARY_NAME;

/// Set Unix file permissions to restrict access to the owner only
///
/// This function sets the file's permissions to 0o600 (rw-------),
/// which allows read and write access only to the file owner.
///
/// # Errors
/// Returns an error if getting file metadata or setting permissions fails.
#[cfg(unix)]
pub fn set_unix_file_permissions(file_path: &Path) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(file_path)
        .with_context(|| {
            format!(
                "Failed to get metadata for key file: {}",
                file_path.display()
            )
        })?
        .permissions();
    perms.set_mode(0o600); // rw------- (owner read/write only)
    fs::set_permissions(file_path, perms).with_context(|| {
        format!(
            "Failed to set permissions on key file: {}",
            file_path.display()
        )
    })?;

    Ok(())
}

/// Set Windows file permissions to restrict access to the current user only
///
/// This function sets the file's ACL (Access Control List) to only allow
/// read and write access to the current user, similar to Unix's 0o600 permissions.
///
/// # Errors
/// Returns an error if Windows API calls fail or if the current user's SID cannot be retrieved.
#[cfg(windows)]
pub fn set_windows_file_permissions(file_path: &Path) -> Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::utilities;
    use windows_permissions::wrappers::SetNamedSecurityInfo;
    use windows_permissions::{LocalBox, SecurityDescriptor};

    // Get current user's SID
    let user_sid = utilities::current_process_sid().context("Failed to get current user SID")?;

    // Create SDDL (Security Descriptor Definition Language) string:
    //  - "D:P" = DACL, Protected (no inheritance from parent)
    //  - "(A;;FA;;;SID)" = Allow entry with Full Access for this SID
    let sddl = format!("D:P(A;;FA;;;{})", user_sid.to_string());

    // Parse SDDL to create SecurityDescriptor
    let sd: LocalBox<SecurityDescriptor> = sddl.parse().context("Failed to parse SDDL string")?;
    // Extract the DACL (Discretionary Access Control List) from it
    let dacl = sd
        .dacl()
        .context("Failed to get DACL from security descriptor")?;

    // Combine flags: set both DACL and ProtectedDacl
    // ProtectedDacl prevents inheritance from parent directories, which is crucial
    // for security-sensitive files like encryption keys
    let sec_info = SecurityInformation::Dacl | SecurityInformation::ProtectedDacl;

    // Apply the DACL to the file
    // This restricts access to only the current user (equivalent to Unix 0o600)
    SetNamedSecurityInfo(
        file_path,
        SeObjectType::SE_FILE_OBJECT,
        sec_info,
        None,       // owner (don't change)
        None,       // group (don't change)
        Some(dacl), // DACL (our restricted permissions)
        None,       // SACL (don't change)
    )
    .context("Failed to apply security descriptor to file")?;

    Ok(())
}

/// Set secure file permissions (platform-specific)
///
/// On Unix systems, sets permissions to 0o600 (owner read/write only).
/// On Windows, sets ACL to only allow the current user read/write/delete access.
///
/// # Errors
/// Returns an error if setting permissions fails on the current platform.
pub fn set_secure_file_permissions(file_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        set_unix_file_permissions(file_path)
    }

    #[cfg(windows)]
    {
        set_windows_file_permissions(file_path)
    }
}

/// Get the path to the binary executable
///
/// Attempts to determine the absolute path to the current binary executable.
/// This is needed to configure git filters with the correct binary path.
///
/// # Strategy
/// 1. First tries to use `std::env::current_exe()` and canonicalize it
/// 2. Falls back to using just the binary name (git will look in PATH)
///
/// # Errors
/// Returns an error if path resolution fails (though fallback should always work).
pub fn get_binary_path() -> Result<PathBuf> {
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
        const_format::formatcp!("{}.exe", BINARY_NAME)
    } else {
        BINARY_NAME
    };

    Ok(PathBuf::from(binary_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn test_set_unix_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_file.txt");

        // Create a test file
        fs::write(&test_file, b"test content").unwrap();

        // Set permissions
        set_unix_file_permissions(&test_file).unwrap();

        // Verify the file still exists and is readable
        assert!(test_file.exists());
        let contents = fs::read(&test_file).unwrap();
        assert_eq!(contents, b"test content");

        // Verify permissions (on Unix)
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&test_file).unwrap();
        let perms = metadata.permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn test_set_windows_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_key.key");

        // Create a test file
        fs::write(&test_file, b"test key data").unwrap();

        // Set Windows permissions
        set_windows_file_permissions(&test_file).unwrap();

        // Verify the file still exists and is readable
        assert!(test_file.exists());
        let contents = fs::read(&test_file).unwrap();
        assert_eq!(contents, b"test key data");

        // Note: Actually verifying the ACL would require additional Windows API calls
        // This test at least verifies the function doesn't crash and the file remains accessible
    }

    #[test]
    fn test_get_binary_path() {
        let path = get_binary_path().unwrap();
        // Should return some path (either absolute or just the binary name)
        assert!(!path.as_os_str().is_empty());
    }
}
