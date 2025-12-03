use serial_test::serial;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Get the path to the git-conceal binary
fn git_conceal_bin() -> String {
    // In integration tests, we need to use the binary from the target directory
    // This works for both debug and release builds
    let target_dir = if cfg!(debug_assertions) {
        "target/debug"
    } else {
        "target/release"
    };
    let bin_path = format!("{}/git-conceal", target_dir);
    // Convert to absolute path for reliability
    std::fs::canonicalize(&bin_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&bin_path))
        .to_string_lossy()
        .to_string()
}

/// Run a command and return the output, panicking on failure
fn run_command(cmd: &mut Command, description: &str) -> (String, String) {
    eprintln!("Running: {}", description);
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {}: {}", description, e));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        panic!(
            "Command failed: {}\nStdout: {}\nStderr: {}",
            description, stdout, stderr
        );
    }

    (stdout, stderr)
}

/// Run a command in a specific directory
fn run_in_dir(dir: &Path, program: &str, args: &[&str], description: &str) -> (String, String) {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.current_dir(dir);
    run_command(&mut cmd, description)
}

/// Verify status output for specific files
/// Runs `git-conceal status` with the given files, parses the output into a map,
/// and compares with expected values.
/// Format: "{filename:20}: {status}" (filename is left-aligned in 20-char field)
fn verify_status_output(
    repo_path: &Path,
    git_conceal: &str,
    files: &[&str],
    description: &str,
    expected_statuses: &HashMap<&str, &str>,
) {
    // Run the status command
    let mut args = vec!["status"];
    args.extend(files.iter().copied());
    let (status_output, _) = run_in_dir(repo_path, git_conceal, &args, description);

    // Parse output into a map: split each line on " : " separator
    let parsed: HashMap<String, String> = status_output
        .lines()
        .filter_map(|line| {
            // Split on " : " (colon with spaces) to separate filename and status
            let parts: Vec<&str> = line.split(": ").collect();
            if parts.len() == 2 {
                Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
            } else {
                None
            }
        })
        .collect();

    // Verify all expected entries match
    for (filename, expected_status) in expected_statuses {
        let actual_status = parsed.get(*filename);
        assert!(
            actual_status.is_some(),
            "Status output should contain entry for file '{}', but got:\n{}\nParsed map: {:?}",
            filename,
            status_output,
            parsed
        );
        assert_eq!(
            actual_status.unwrap(),
            expected_status,
            "Status for '{}' should be '{}', but got '{}'",
            filename,
            expected_status,
            actual_status.unwrap()
        );
    }

    // Verify no extra entries
    assert_eq!(
        parsed.len(),
        expected_statuses.len(),
        "Status output should contain exactly {} entries, but got {}:\n{}\nParsed map: {:?}",
        expected_statuses.len(),
        parsed.len(),
        status_output,
        parsed
    );
}

#[test]
#[serial]
fn test_full_workflow() {
    // Create a temporary directory for the test repository
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let repo_path = temp_dir.path();

    // Step 1: Initialize git repository
    run_in_dir(repo_path, "git", &["init"], "git init");

    // Step 2: Set up basic git config
    run_in_dir(
        repo_path,
        "git",
        &["config", "user.name", "Test User"],
        "git config user.name",
    );
    run_in_dir(
        repo_path,
        "git",
        &["config", "user.email", "test@example.com"],
        "git config user.email",
    );

    // Step 3: Create dummy README and initial commit
    fs::write(repo_path.join("README.md"), "Test Repository\n").expect("Failed to write README.md");
    run_in_dir(repo_path, "git", &["add", "README.md"], "git add README.md");
    run_in_dir(
        repo_path,
        "git",
        &["commit", "-m", "Initial commit"],
        "git commit initial",
    );

    // Step 4: Run git-conceal init
    let git_conceal = git_conceal_bin();
    run_in_dir(repo_path, &git_conceal, &["init"], "git-conceal init");

    // Step 5: export key
    let (key_output, _) = run_in_dir(
        repo_path,
        &git_conceal,
        &["key", "show"],
        "git-conceal key show",
    );
    let key = key_output.trim();
    assert!(!key.is_empty(), "Key should not be empty");

    // Step 6: Create .gitattributes with patterns
    let gitattributes_content = "secrets/* filter=git-conceal diff=git-conceal\n*.secret filter=git-conceal diff=git-conceal\n";
    fs::write(repo_path.join(".gitattributes"), gitattributes_content)
        .expect("Failed to write .gitattributes");

    // Step 7: Create secret files matching the patterns
    fs::create_dir_all(repo_path.join("secrets")).expect("Failed to create secrets directory");

    let secret1_content = "password=super_secret_password_123\napi_key=abc123xyz789\n";
    fs::write(
        repo_path.join("secrets").join("credentials.txt"),
        secret1_content,
    )
    .expect("Failed to write secrets/credentials.txt");

    let secret2_content = "token=my_secret_token_456\n";
    fs::write(repo_path.join("config.secret"), secret2_content)
        .expect("Failed to write config.secret");

    // Create a non-secret file that doesn't match any .gitattributes pattern
    let public_content =
        "This is a public file that should remain in cleartext\napp_name=myapp\nversion=1.0.0\n";
    fs::write(repo_path.join("public.txt"), public_content).expect("Failed to write public.txt");

    // Step 8: Git add and commit the secret files and non-secret file
    run_in_dir(
        repo_path,
        "git",
        &[
            "add",
            ".gitattributes",
            "secrets/credentials.txt",
            "config.secret",
            "public.txt",
        ],
        "git add secret files and non-secret file",
    );
    run_in_dir(
        repo_path,
        "git",
        &["commit", "-m", "Add encrypted files"],
        "git commit secret files",
    );

    // Step 9: Check status before lock
    // Secret files should be encrypted, public file should not be
    verify_status_output(
        repo_path,
        &git_conceal,
        &["secrets/credentials.txt", "config.secret", "public.txt"],
        "git-conceal status before lock",
        &HashMap::from([
            ("secrets/credentials.txt", "🔒 Encrypted in the repository"),
            ("config.secret", "🔒 Encrypted in the repository"),
            ("public.txt", "👀 Not encrypted in the repository"),
        ]),
    );

    // Step 10: Run git-conceal lock
    run_in_dir(repo_path, &git_conceal, &["lock"], "git-conceal lock");

    // Step 11: Check status after lock
    // Status should be the same - it checks if files are filtered, not current state
    verify_status_output(
        repo_path,
        &git_conceal,
        &["secrets/credentials.txt", "config.secret", "public.txt"],
        "git-conceal status after lock",
        &HashMap::from([
            ("secrets/credentials.txt", "🔒 Encrypted in the repository"),
            ("config.secret", "🔒 Encrypted in the repository"),
            ("public.txt", "👀 Not encrypted in the repository"),
        ]),
    );

    // Step 12: Check that secret files contain the \0a8ccrypt\1 header
    // The header is: \0 (1 byte) + "a8ccrypt" (8 bytes) + \1 (1 byte) = 10 bytes
    let secret1_path = repo_path.join("secrets").join("credentials.txt");
    let secret2_path = repo_path.join("config.secret");
    let public_path = repo_path.join("public.txt");

    // Expected header bytes: \0a8ccrypt\1
    let expected_header: Vec<u8> = vec![0x00, 0x61, 0x38, 0x63, 0x63, 0x72, 0x79, 0x70, 0x74, 0x01];

    // Read first 10 bytes of each encrypted file
    let mut secret1_file =
        std::fs::File::open(&secret1_path).expect("Failed to open encrypted secret1");
    let mut secret1_header = vec![0u8; 10];
    secret1_file
        .read_exact(&mut secret1_header)
        .expect("Failed to read first 10 bytes of secret1");

    let mut secret2_file =
        std::fs::File::open(&secret2_path).expect("Failed to open encrypted secret2");
    let mut secret2_header = vec![0u8; 10];
    secret2_file
        .read_exact(&mut secret2_header)
        .expect("Failed to read first 10 bytes of secret2");

    // Compare the headers directly
    assert_eq!(
        secret1_header, expected_header,
        "Secret file 1 should have correct encryption header"
    );
    assert_eq!(
        secret2_header, expected_header,
        "Secret file 2 should have correct encryption header"
    );

    // Verify that the non-secret file is still in cleartext after lock
    let public_after_lock =
        fs::read_to_string(&public_path).expect("Failed to read public.txt after lock");
    assert_eq!(
        public_after_lock, public_content,
        "Non-secret file should remain in cleartext after lock"
    );

    // Step 13: Run git-conceal unlock env:GIT_CONCEAL_KEY
    let mut unlock_cmd = Command::new(&git_conceal);
    unlock_cmd.args(&["unlock", "env:GIT_CONCEAL_KEY"]);
    unlock_cmd.current_dir(repo_path);
    unlock_cmd.env("GIT_CONCEAL_KEY", key);
    run_command(&mut unlock_cmd, "git-conceal unlock env:GIT_CONCEAL_KEY");

    // Step 14: Check status after unlock
    // Status should be the same - it checks if files are filtered, not current state
    verify_status_output(
        repo_path,
        &git_conceal,
        &["secrets/credentials.txt", "config.secret", "public.txt"],
        "git-conceal status after unlock",
        &HashMap::from([
            ("secrets/credentials.txt", "🔒 Encrypted in the repository"),
            ("config.secret", "🔒 Encrypted in the repository"),
            ("public.txt", "👀 Not encrypted in the repository"),
        ]),
    );

    // Step 15: Read the secret files to check they show decrypted content
    let decrypted_secret1 =
        fs::read_to_string(&secret1_path).expect("Failed to read decrypted secret1");
    let decrypted_secret2 =
        fs::read_to_string(&secret2_path).expect("Failed to read decrypted secret2");

    assert_eq!(
        decrypted_secret1, secret1_content,
        "Decrypted secret1 should match original content"
    );
    assert_eq!(
        decrypted_secret2, secret2_content,
        "Decrypted secret2 should match original content"
    );

    // Verify that the non-secret file is still in cleartext after unlock
    let public_after_unlock =
        fs::read_to_string(&public_path).expect("Failed to read public.txt after unlock");
    assert_eq!(
        public_after_unlock, public_content,
        "Non-secret file should remain in cleartext after unlock"
    );

    // Note: The temp dir will be automatically deleted thanks to `TempDir` implementing the `Drop` trait
}
