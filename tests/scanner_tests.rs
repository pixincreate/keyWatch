use key_watch::cli::ScanArgs;
use key_watch::report::create_report;
use key_watch::scanner::{ScannerError, run_scan};
use std::env::temp_dir;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();

    temp_dir().join(format!("keywatch_{name}_{stamp}_{}", std::process::id()))
}

/// Git backs the --staged, --git-history and baseline modes, so its absence
/// is a broken environment rather than a reason to pass silently. Twenty
/// tests used to return Ok(()) here, reporting green while covering nothing.
fn require_git() {
    let output = Command::new("git")
        .arg("--version")
        .output()
        .expect("git is required to test KeyWatch's git-backed scan modes");
    assert!(output.status.success(), "`git --version` failed");
}

fn init_git_repo(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("create repo dir: {error}"))?;

    let status = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git init: {error}"))?;
    if !status.success() {
        return Err("git init failed".to_string());
    }

    for (key, value) in [("user.email", "test@test.com"), ("user.name", "Test")] {
        let status = Command::new("git")
            .args(["config", key, value])
            .current_dir(path)
            .status()
            .map_err(|error| format!("git config {key}: {error}"))?;
        if !status.success() {
            return Err(format!("git config {key} failed"));
        }
    }

    Ok(())
}

fn commit_file(path: &Path, file_name: &str, contents: &str, message: &str) -> Result<(), String> {
    let file_path = path.join(file_name);
    fs::write(&file_path, contents).map_err(|error| format!("write file: {error}"))?;

    let status = Command::new("git")
        .args(["add", file_name])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git add: {error}"))?;
    if !status.success() {
        return Err("git add failed".to_string());
    }

    // --no-verify keeps fixture commits hermetic on machines where a global
    // core.hooksPath installs a secret-scanning pre-commit hook; these tests
    // exercise git-history scanning, not hooks.
    let status = Command::new("git")
        .args(["commit", "-m", message, "--quiet", "--no-verify"])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git commit: {error}"))?;
    if !status.success() {
        return Err("git commit failed".to_string());
    }

    Ok(())
}

fn detectors_config_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("detectors.toml")
}

fn run_git_history_scan(current_dir: &Path, extra_args: &[&str]) -> Result<Output, String> {
    Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--git-history"])
        .args(extra_args)
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(current_dir)
        .output()
        .map_err(|error| format!("run key-watch scan --git-history: {error}"))
}

#[cfg(unix)]
fn symlink_file(original: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(original, link).map_err(|error| format!("create symlink: {error}"))
}

#[test]
fn test_find_secrets_in_file() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_multiple_secrets.txt");

    let content = "\
AWS Key: AKIAABCDEFGHIJKLMNOP\n\
password = 'mySecretPassword'\n\
email = user@example.com\n\
Firebase: AIzaSyC93k4n4BxvV_XYZ1234567890abcdefghijk\n\
SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n\
sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX\n\
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    let finding_types: Vec<&str> = findings
        .iter()
        .map(|finding| finding.finding_type.as_str())
        .collect();
    assert_eq!(
        finding_types,
        vec![
            "AWS Access Key",
            "Password",
            "Generic Key/Secret",
            "Base64 Encoded String",
            "SendGrid API Key",
            "Base64 Encoded String",
            "OpenAI API Key",
            "Kimi/Moonshot API Key",
        ],
        "Should find secrets"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_find_api_tokens() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_api_tokens.txt");

    let content = "\
GitHub: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH\n\
Slack: xoxb-abcdefghijklmnop-qrstuvwxyz-123456789012\n\
Stripe: sk_test_51ABCDEF12345678901234567890\n\
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.finding_type.as_str())
            .collect::<Vec<_>>(),
        vec!["Stripe API Key"],
        "Should find API tokens"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_find_cloud_credentials() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_cloud.txt");

    let content = "\
AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n\
AWS_SECRET_ACCESS_KEY=xJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY42\n\
GCP_API_KEY=AIzaSyC93k4n4BxvV_XYZ1234567890abcdefghijk\n\
AZURE_STORAGE=DefaultEndpointsProtocol=https;AccountName=examplestore;
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.finding_type.as_str())
            .collect::<Vec<_>>(),
        vec![
            "AWS Access Key",
            "Generic Key/Secret",
            "Base64 Encoded String",
            "Generic Key/Secret",
        ],
        "Should find cloud credentials"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_find_private_key() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_private_key.txt");

    let content = "\
-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCxoe3Fy7N9i+Kj\n\
-----END RSA PRIVATE KEY-----\n\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1ldi0xLjAAABgQDQD2FGB3V2t4=\n\
-----END OPENSSH PRIVATE KEY-----\n\
";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.finding_type.as_str())
            .collect::<Vec<_>>(),
        vec![
            "SSH Private Key",
            "Private Key Content",
            "Private Key Content",
            "Base64 Encoded String",
            "SSH Private Key",
            "Private Key Content",
            "Base64 Encoded String",
        ],
        "Should find private keys"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_multiple_detections_in_line() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_multi.txt");

    let content = "password=secret email=user@sampledomain.dev key=AKIATESTKEY123";
    fs::write(&test_file, content).expect("Unable to write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    assert!(
        findings.len() >= 2,
        "Should find multiple secrets on one line"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_directory_scan_with_exclusions() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_test_dir_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");

    fs::write(test_dir.join("secret1.txt"), "AKIATESTKEY123").expect("Write file1");
    fs::write(test_dir.join("secret2.txt"), "password=secret").expect("Write file2");
    fs::create_dir_all(test_dir.join(".git")).expect("Create .git dir");
    fs::write(test_dir.join(".git/secret.txt"), "SHOULD_NOT_FIND").expect("Write git file");

    let options = ScanArgs {
        paths: vec![test_dir.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(
        metadata.files_scanned, 2,
        "Should scan 2 files (.git excluded)"
    );
    assert!(!findings.is_empty(), "Should find secrets");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exclude_pattern_filtering() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_exclude_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");

    fs::write(test_dir.join("secret.txt"), "password=secret123").expect("Write secret");
    fs::write(test_dir.join("debug.log"), "password=debug123").expect("Write log");

    let options = ScanArgs {
        paths: vec![test_dir.to_str().unwrap().to_string()],
        exclude: Some("*.log".to_string()),
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (_findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
    assert!(
        metadata
            .excluded_files
            .iter()
            .any(|f| f.contains("debug.log")),
        "Should exclude *.log"
    );
    assert_eq!(metadata.files_scanned, 1, "Should skip excluded files");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_invalid_cli_exclude_pattern_returns_typed_error() {
    let options = ScanArgs {
        paths: vec![".".to_string()],
        exclude: Some("[".to_string()),
        no_baseline_discovery: true,
        ..Default::default()
    };

    let error = match run_scan(&options, None) {
        Ok(_) => panic!("invalid exclude should fail"),
        Err(error) => error,
    };

    match &error {
        ScannerError::InvalidExcludePattern { pattern, source: _ } => {
            assert_eq!(pattern, "[");
        }
        other_error => panic!("expected invalid exclude pattern error, got {other_error:?}"),
    }
    assert!(
        error
            .to_string()
            .starts_with("Invalid exclude pattern '[': "),
        "legacy display prefix changed: {error}"
    );
}

#[test]
fn test_dot_github_directory_is_scanned() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_dotgithub_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");
    fs::create_dir_all(test_dir.join(".github")).expect("Create .github dir");
    fs::write(test_dir.join(".github/workflow.txt"), "password=secret123").expect("Write file");

    let options = ScanArgs {
        paths: vec![test_dir.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(metadata.files_scanned, 1, "Should scan .github files");
    assert!(!findings.is_empty(), "Should find secrets inside .github");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_scan_no_secrets() {
    let temp_file = temp_dir().join("key_watch_no_secret.txt");
    let content = "This is a plain text file.\nThere is nothing secret here.";
    fs::write(&temp_file, content).expect("Unable to write no-secret file");

    let options = ScanArgs {
        paths: vec![temp_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    assert!(findings.is_empty(), "Should not find secrets in plain text");

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_non_utf8_file_handling() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_binary.bin");

    let content: Vec<u8> = vec![0x80, 0x81, 0x82, 0xff, 0xfe];
    fs::write(&test_file, content).expect("Unable to write binary test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    assert!(findings.is_empty(), "Should gracefully handle binary files");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_multiple_files_scan() {
    let temp_dir = temp_dir();
    let test_file1 = temp_dir.join("keywatch_multi_test1.txt");
    let test_file2 = temp_dir.join("keywatch_multi_test2.txt");

    fs::write(&test_file1, "AWS_KEY=AKIATESTMULTI123").expect("Write test file 1");
    fs::write(&test_file2, "password=secretpassword123").expect("Write test file 2");

    let options = ScanArgs {
        paths: vec![
            test_file1.to_str().unwrap().to_string(),
            test_file2.to_str().unwrap().to_string(),
        ],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.file_path.as_str(), finding.finding_type.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (test_file2.to_str().unwrap(), "Password"),
            (test_file2.to_str().unwrap(), "Generic Key/Secret"),
        ],
        "Should find secrets in multiple files"
    );
    assert_eq!(metadata.files_scanned, 2, "Should scan 2 files");

    fs::remove_file(test_file1).expect("Cleanup");
    fs::remove_file(test_file2).expect("Cleanup");
}

#[test]
fn test_duplicate_paths_are_scanned_once() {
    let temp_file = temp_dir().join("key_watch_duplicate_path.txt");
    fs::write(&temp_file, "password=duplicate-secret").expect("Write test file");

    let options = ScanArgs {
        paths: vec![
            temp_file.to_str().unwrap().to_string(),
            temp_file.to_str().unwrap().to_string(),
        ],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(
        metadata.files_scanned, 1,
        "Duplicate paths should be deduped"
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.file_path == temp_file.to_str().unwrap()),
        "Duplicate paths should only report findings for the deduped file"
    );

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_mixed_file_and_directory_paths_are_scanned_once() {
    let temp_dir = temp_dir();
    let test_dir = temp_dir.join(format!(
        "keywatch_mixed_inputs_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&test_dir).expect("Create test directory");

    let direct_file = test_dir.join("secret.txt");
    fs::write(&direct_file, "password=mixed-secret").expect("Write test file");

    let options = ScanArgs {
        paths: vec![
            direct_file.to_str().unwrap().to_string(),
            test_dir.to_str().unwrap().to_string(),
        ],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
    assert_eq!(
        metadata.files_scanned, 1,
        "File should only be scanned once"
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.file_path == direct_file.to_str().unwrap()),
        "Mixed file/directory inputs should only report findings for the single deduped file"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_nonexistent_paths_are_ignored_without_counting_as_scanned() {
    let missing_path = temp_dir().join(format!(
        "keywatch_missing_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));

    let options = ScanArgs {
        paths: vec![missing_path.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");
    assert!(
        findings.is_empty(),
        "Missing paths should not produce findings"
    );
    assert_eq!(
        metadata.files_scanned, 0,
        "Missing paths should not be counted as scanned"
    );
    assert!(
        metadata.excluded_files.is_empty(),
        "Missing paths should not be marked excluded"
    );
}

#[cfg(unix)]
#[test]
fn test_explicit_symlink_path_is_skipped() -> Result<(), String> {
    let test_dir = unique_temp_dir("explicit_symlink_skip");
    let outside_file = test_dir.join("outside-secret.txt");
    let link_path = test_dir.join("linked-secret.txt");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).map_err(|error| format!("create test dir: {error}"))?;
    fs::write(&outside_file, "AWS Key: AKIAABCDEFGHIJKLMNOP\n")
        .map_err(|error| format!("write outside secret: {error}"))?;
    symlink_file(&outside_file, &link_path)?;

    let options = ScanArgs {
        paths: vec![
            link_path
                .to_str()
                .ok_or("link path should be utf-8")?
                .to_string(),
        ],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");

    assert!(findings.is_empty(), "Symlink target should not be scanned");
    assert_eq!(
        metadata.files_scanned, 0,
        "Symlink should not count as scanned"
    );

    fs::remove_dir_all(&test_dir).map_err(|error| format!("cleanup: {error}"))?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_recursive_symlink_path_is_skipped() -> Result<(), String> {
    let test_dir = unique_temp_dir("recursive_symlink_skip");
    let outside_file = test_dir.join("outside-secret.txt");
    let scan_root = test_dir.join("scan-root");
    let link_path = scan_root.join("linked-secret.txt");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&scan_root).map_err(|error| format!("create scan root: {error}"))?;
    fs::write(&outside_file, "AWS Key: AKIAABCDEFGHIJKLMNOP\n")
        .map_err(|error| format!("write outside secret: {error}"))?;
    symlink_file(&outside_file, &link_path)?;

    let options = ScanArgs {
        paths: vec![
            scan_root
                .to_str()
                .ok_or("scan root should be utf-8")?
                .to_string(),
        ],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");

    assert!(
        findings.is_empty(),
        "Recursive symlink target should not be scanned"
    );
    assert_eq!(
        metadata.files_scanned, 0,
        "Recursive symlink should not count as scanned"
    );

    fs::remove_dir_all(&test_dir).map_err(|error| format!("cleanup: {error}"))?;
    Ok(())
}

#[test]
fn test_detect_aadhaar() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_aadhaar_test.txt");

    let content = "My Aadhaar: 1000-0000-0004\nBackup: 1000 0000 0004\nNo space: 100000000004";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    let aadhaar_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "Aadhaar Card Number")
        .collect();
    assert!(
        !aadhaar_findings.is_empty(),
        "Should detect Aadhaar numbers"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_detect_voter_id() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_voter_id_test.txt");

    let content = "Voter ID: ABC1234567\nAnother: XYZ9876543";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    let voter_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "Voter ID (EPIC)")
        .collect();
    assert!(!voter_findings.is_empty(), "Should detect Voter ID numbers");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_detect_pan_card() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_pan_test.txt");

    let content = "PAN: ABCDE1234F\nBackup PAN: PQRST5678G";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    let pan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "PAN Card Number")
        .collect();
    assert!(!pan_findings.is_empty(), "Should detect PAN card numbers");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_detect_abha() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_abha_test.txt");

    let content = "ABHA: 1234-5678-9012-34\nMy Health ID: 9876-5432-1098-76";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    let abha_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type == "ABHA Health ID")
        .collect();
    assert!(!abha_findings.is_empty(), "Should detect ABHA health IDs");

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_multiple_indian_ids() {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("keywatch_indian_ids.txt");

    let content =
        "Aadhaar: 1000-0000-0004\nVoter ID: ABC1234567\nPAN: XYZZU1234A\nABHA: 1111-2222-3333-44";
    fs::write(&test_file, content).expect("Write test file");

    let options = ScanArgs {
        paths: vec![test_file.to_str().unwrap().to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");
    let finding_types: Vec<_> = findings.iter().map(|f| f.finding_type.clone()).collect();

    assert!(
        finding_types.contains(&"Aadhaar Card Number".to_string()),
        "Should detect Aadhaar"
    );
    assert!(
        finding_types.contains(&"Voter ID (EPIC)".to_string()),
        "Should detect Voter ID"
    );
    assert!(
        finding_types.contains(&"PAN Card Number".to_string()),
        "Should detect PAN"
    );
    assert!(
        finding_types.contains(&"ABHA Health ID".to_string()),
        "Should detect ABHA"
    );

    fs::remove_file(test_file).expect("Cleanup");
}

#[test]
fn test_overlapping_scan_roots_with_exclusions() {
    let temp_dir = temp_dir();
    let root1 = temp_dir.join(format!(
        "keywatch_overlapping_1_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir(&root1).expect("Create test directory 1");

    let root2 = root1.join("subdir");
    fs::create_dir(&root2).expect("Create test directory 2");

    let test_file = root2.join("secret.txt");
    fs::write(&test_file, "password=secret123").expect("Write test file");

    let options = ScanArgs {
        paths: vec![
            root2.to_str().unwrap().to_string(), // Root 2 comes first to try to mess up order
            root1.to_str().unwrap().to_string(),
        ],
        exclude: Some("subdir/secret.txt".to_string()),
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, metadata) = run_scan(&options, None).expect("run_scan should succeed");

    assert!(
        metadata
            .excluded_files
            .iter()
            .any(|f| f.contains("secret.txt")),
        "File should be excluded despite overlapping roots"
    );
    assert!(
        findings.is_empty(),
        "No findings should be present because the file was excluded"
    );

    fs::remove_dir_all(root1).expect("Cleanup");
}

#[test]
fn test_inline_suppression_ignores_marked_lines() -> Result<(), String> {
    let temp_dir = temp_dir();
    let test_file = temp_dir.join("key_watch_inline_suppress.txt");

    let content = "\
AWS Key: AKIAABCDEFGHIJKLMNOP # keywatch:ignore\npassword = 'mySecretPassword'\nemail = user@example.com // keywatch:ignore\nFirebase: AIzaSy012345678901234567890123456789012\n";
    fs::write(&test_file, content)
        .map_err(|error| format!("Unable to write test file: {error}"))?;

    let path_str = test_file.to_string_lossy().to_string();

    let options = ScanArgs {
        paths: vec![path_str],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings, _) = run_scan(&options, None).expect("run_scan should succeed");

    let aws_suppressed = findings
        .iter()
        .any(|f| f.matched_content.contains("AKIAABCDEFGHIJKLMNOP"));
    let email_suppressed = findings
        .iter()
        .any(|f| f.matched_content.contains("user@example.com"));
    let firebase_found = findings.iter().any(|f| {
        f.matched_content
            .contains("AIzaSy012345678901234567890123456789012")
    });

    assert!(
        !aws_suppressed,
        "AWS key with # keywatch:ignore should be suppressed"
    );
    assert!(
        !email_suppressed,
        "Email with // keywatch:ignore should be suppressed"
    );
    assert!(
        firebase_found,
        "Firebase key without suppression should still be found"
    );

    fs::remove_file(test_file).map_err(|error| format!("Cleanup failed: {error}"))?;
    Ok(())
}

#[test]
fn test_stdin_args_validation() {
    let options = ScanArgs {
        stdin: true,
        no_baseline_discovery: true,
        ..Default::default()
    };

    assert!(options.validate().is_ok());
}

#[test]
fn test_stdin_scanning_integration() -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin_path = env!("CARGO_BIN_EXE_key-watch");
    let mut child = Command::new(bin_path)
        .args(["scan", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn key-watch --stdin: {error}"))?;

    let mut stdin = child.stdin.take().ok_or("Failed to capture stdin")?;
    stdin
        .write_all(b"AWS Key: AKIAABCDEFGHIJKLMNOP\npassword = 'secret123'\n")
        .map_err(|error| format!("write to stdin: {error}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let combined = format!("{}{}", stdout, stderr);
    assert!(
        // AWS key + password. The Base64Detector no longer double-counts the
        // AWS key itself: its entropy (~4.0) is below the 4.2 threshold.
        combined.contains("2 potential secret(s)"),
        "Should detect 2 secrets from stdin input\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    Ok(())
}

#[test]
fn test_git_history_args_validation_allows_zero_or_one_path() {
    let zero_paths = ScanArgs {
        git_history: true,
        no_baseline_discovery: true,
        ..Default::default()
    };
    let one_path = ScanArgs {
        paths: vec!["/tmp/requested-root".to_string()],
        git_history: true,
        no_baseline_discovery: true,
        ..Default::default()
    };
    let two_paths = ScanArgs {
        paths: vec![
            "/tmp/requested-root".to_string(),
            "/tmp/other-root".to_string(),
        ],
        git_history: true,
        no_baseline_discovery: true,
        ..Default::default()
    };

    assert!(zero_paths.validate().is_ok());
    assert!(one_path.validate().is_ok());
    assert!(two_paths.validate().is_err());
}

#[test]
fn test_git_history_defaults_to_current_directory_when_no_path_is_provided() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("git_history_default_cwd");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "secrets.txt",
        "AWS Key: AKIAABCDEFGHIJKLMNOP\n",
        "initial",
    )?;

    let output = run_git_history_scan(&repo_dir, &[])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "default cwd git history scan should report findings\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(combined.contains("potential secret(s) detected"));

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_git_history_scans_requested_root_from_a_different_current_directory() -> Result<(), String>
{
    require_git();

    let parent_dir = unique_temp_dir("git_history_requested_root_parent");
    let requested_root = parent_dir.join("requested-repo");
    let _ = fs::remove_dir_all(&parent_dir);
    init_git_repo(&requested_root)?;
    commit_file(
        &requested_root,
        "secrets.txt",
        "AWS Key: AKIAQRSTUVWXYZABCDEF\n",
        "initial",
    )?;

    let output = run_git_history_scan(&parent_dir, &[requested_root.to_str().unwrap()])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "explicit git root scan should report findings\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(combined.contains("potential secret(s) detected"));

    let _ = fs::remove_dir_all(&parent_dir);
    Ok(())
}

#[test]
fn test_git_history_does_not_execute_textconv_helpers() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("git_history_no_textconv");
    let marker_path = repo_dir.join("textconv-helper-ran");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;

    let helper = format!(
        "sh -c 'printf textconv-ran > \"{}\"; cat \"$1\"' -",
        marker_path.display()
    );
    let status = Command::new("git")
        .env("GIT_MASTER", "1")
        .args(["config", "diff.keywatchmarker.textconv", &helper])
        .current_dir(&repo_dir)
        .status()
        .map_err(|error| format!("git config textconv: {error}"))?;
    if !status.success() {
        return Err("git config textconv failed".to_string());
    }

    commit_file(
        &repo_dir,
        ".gitattributes",
        "*.kw diff=keywatchmarker\n",
        "attrs",
    )?;
    commit_file(&repo_dir, "sample.kw", "ordinary text\n", "sample")?;

    let _output = run_git_history_scan(&repo_dir, &[])?;
    assert!(
        !marker_path.exists(),
        "git history scan must not execute configured textconv helpers"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_git_history_scans_merge_commits() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("git_history_merge_commit");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "data.txt", "value = 1\n", "base")?;

    let current_branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(&repo_dir)
        .output()
        .map_err(|error| format!("read branch: {error}"))?;
    let base_branch = String::from_utf8_lossy(&current_branch.stdout)
        .trim()
        .to_string();

    let status = Command::new("git")
        .args(["checkout", "--quiet", "-b", "feature"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|error| format!("checkout feature: {error}"))?;
    if !status.success() {
        return Err("git checkout -b feature failed".to_string());
    }
    commit_file(&repo_dir, "data.txt", "value = feature\n", "feature")?;

    let status = Command::new("git")
        .args(["checkout", "--quiet", &base_branch])
        .current_dir(&repo_dir)
        .status()
        .map_err(|error| format!("checkout {base_branch}: {error}"))?;
    if !status.success() {
        return Err("git checkout base failed".to_string());
    }
    commit_file(&repo_dir, "data.txt", "value = base\n", "conflicting")?;

    // Merging conflicts. The resolution introduces the secret, so it exists
    // only in the merge commit's diff.
    let status = Command::new("git")
        .args(["merge", "--quiet", "feature"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|error| format!("git merge: {error}"))?;
    if status.success() {
        return Err("the fixture merge was expected to conflict".to_string());
    }

    fs::write(
        repo_dir.join("data.txt"),
        "value = resolved\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|error| format!("write resolution: {error}"))?;

    let status = Command::new("git")
        .args(["add", "data.txt"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|error| format!("git add resolution: {error}"))?;
    if !status.success() {
        return Err("git add resolution failed".to_string());
    }

    let status = Command::new("git")
        .args(["commit", "--quiet", "--no-verify", "-m", "evil merge"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|error| format!("git commit merge: {error}"))?;
    if !status.success() {
        return Err("git commit merge failed".to_string());
    }

    let output = run_git_history_scan(&repo_dir, &["--verbose"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "a secret introduced in a merge commit must be found\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("data.txt"),
        "the finding must name the resolved file\nstdout:\n{}",
        stdout
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

fn run_staged_scan(current_dir: &Path, extra_args: &[&str]) -> Result<Output, String> {
    Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged"])
        .args(extra_args)
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(current_dir)
        .output()
        .map_err(|error| format!("run key-watch scan --staged: {error}"))
}

fn stage_file(path: &Path, file_name: &str, contents: &str) -> Result<(), String> {
    let file_path = path.join(file_name);
    fs::write(&file_path, contents).map_err(|error| format!("write {file_name}: {error}"))?;

    let status = Command::new("git")
        .args(["add", file_name])
        .current_dir(path)
        .status()
        .map_err(|error| format!("git add: {error}"))?;
    if !status.success() {
        return Err("git add failed".to_string());
    }

    Ok(())
}

#[test]
fn test_staged_scan_ignores_findings_on_unchanged_lines() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_unchanged_lines");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "secrets.txt",
        "AWS Key: AKIAABCDEFGHIJKLMNOP\n",
        "initial",
    )?;
    stage_file(
        &repo_dir,
        "secrets.txt",
        "AWS Key: AKIAABCDEFGHIJKLMNOP\nplain documentation line\n",
    )?;

    let output = run_staged_scan(&repo_dir, &[])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "pre-existing secret on an unchanged line must not block\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_ignores_deletion_only_changes() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_deletion_only");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "secrets.txt",
        "keep this line\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
        "initial",
    )?;
    stage_file(&repo_dir, "secrets.txt", "keep this line\n")?;

    let output = run_staged_scan(&repo_dir, &[])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "deletion-only staged change must not block\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_reports_added_secret_with_real_path_and_line() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_added_secret");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "config.txt", "line one\nline two\n", "initial")?;
    stage_file(
        &repo_dir,
        "config.txt",
        "line one\nline two\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let output = run_staged_scan(&repo_dir, &["--verbose"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "a staged secret must block\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("\"file_path\": \"config.txt\""),
        "findings must carry the real file path, not <stdin>\nstdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("\"line_number\": 3"),
        "findings must carry the post-image line number\nstdout:\n{}",
        stdout
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_staged_scan_reads_diff_suppressed_blob_by_object_id() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_object_id");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        ".gitattributes",
        "0:config -diff\n",
        "attributes",
    )?;
    commit_file(&repo_dir, "config", "clean\n", "decoy")?;
    stage_file(&repo_dir, "0:config", "AWS Key: AKIAABCDEFGHIJKLMNOP\n")?;

    let output = run_staged_scan(&repo_dir, &["--verbose"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(1)),
        "a secret in a diff-suppressed file must be read by object ID\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("\"file_path\": \"0:config\""),
        "the finding must name the staged file\nstdout:\n{}",
        stdout
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_respects_exclude_patterns() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_exclude");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "fixture.snap", "clean\n", "initial")?;
    stage_file(
        &repo_dir,
        "fixture.snap",
        "clean\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let output = run_staged_scan(&repo_dir, &["--exclude", "*.snap"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "excluded staged paths must not be scanned\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_composes_with_baseline() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_baseline");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "config.txt", "line one\n", "initial")?;
    stage_file(
        &repo_dir,
        "config.txt",
        "line one\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let update = run_staged_scan(
        &repo_dir,
        &["--baseline", "baseline.json", "--update-baseline"],
    )?;
    assert!(
        matches!(update.status.code(), Some(0)),
        "baseline update should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );

    let output = run_staged_scan(&repo_dir, &["--baseline", "baseline.json"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        matches!(output.status.code(), Some(0)),
        "baselined staged findings must be suppressed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_baseline_file_itself_is_never_scanned() {
    let dir = unique_temp_dir("baseline_self_exclusion");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    fs::write(
        dir.join("secrets.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .expect("write secret file");

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "."])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&dir)
            .output()
            .expect("run key-watch")
    };

    let update = run(&["--baseline", "baseline.json", "--update-baseline"]);
    assert!(update.status.success(), "baseline update should succeed");

    // Two consecutive baselined scans must be clean and must not grow the
    // baseline by re-scanning the baseline file's own hash strings.
    let first = run(&["--baseline", "baseline.json"]);
    let size_before = fs::metadata(dir.join("baseline.json")).unwrap().len();
    let second_update = run(&["--baseline", "baseline.json", "--update-baseline"]);
    assert!(second_update.status.success());
    let size_after = fs::metadata(dir.join("baseline.json")).unwrap().len();

    assert!(
        String::from_utf8_lossy(&first.stdout).contains("No secrets found."),
        "baselined findings must be suppressed, got:\n{}",
        String::from_utf8_lossy(&first.stdout)
    );
    assert_eq!(
        size_before, size_after,
        "re-updating the baseline must not ingest the baseline file itself"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_baseline_auto_discovered_from_repo_root() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("baseline_auto_discovery");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::create_dir_all(repo_dir.join("nested")).map_err(|e| e.to_string())?;
    fs::write(
        repo_dir.join("nested/config.txt"),
        "AWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    // No baseline anywhere: --update-baseline creates the conventional file.
    let update = run(&["scan", ".", "--update-baseline"]);
    assert!(
        update.status.success(),
        "default-name update should succeed"
    );
    assert!(
        repo_dir.join(".keywatch-baseline.json").exists(),
        "update should create .keywatch-baseline.json"
    );

    // A nested scan discovers the repo-root baseline and comes back clean.
    let scan = run(&["scan", "nested/config.txt"]);
    assert!(
        String::from_utf8_lossy(&scan.stdout).contains("No secrets found."),
        "discovered baseline should suppress known findings, got:\n{}",
        String::from_utf8_lossy(&scan.stdout)
    );

    // Discovery can be turned off.
    let no_discovery = run(&["scan", "nested/config.txt", "--no-baseline-discovery"]);
    assert_eq!(
        no_discovery.status.code(),
        Some(1),
        "--no-baseline-discovery must ignore the repo baseline"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_uses_discovered_baseline() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_auto_baseline");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "config.txt", "clean line\n", "initial")?;
    stage_file(
        &repo_dir,
        "config.txt",
        "clean line\nAWS Key: AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    let update = run(&["scan", "--staged", "--update-baseline"]);
    assert!(
        update.status.success(),
        "staged baseline update should succeed"
    );

    // The hook's exact invocation now picks the baseline up automatically.
    let staged = run(&["scan", "--staged"]);
    assert!(
        matches!(staged.status.code(), Some(0)),
        "staged scan should discover the repo baseline\nstdout:\n{}",
        String::from_utf8_lossy(&staged.stdout)
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_discovered_baseline_file_is_never_scanned() -> Result<(), String> {
    require_git();

    // A discovered baseline resolves to an absolute path while scanned files
    // are relative, so self-exclusion must compare canonical paths.
    let repo_dir = unique_temp_dir("discovered_baseline_self_scan");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("secrets.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "."])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&["--update-baseline"]).status.success());
    let size_before = fs::metadata(repo_dir.join(".keywatch-baseline.json"))
        .map_err(|e| e.to_string())?
        .len();

    let rescan = run(&[]);
    assert!(
        String::from_utf8_lossy(&rescan.stdout).contains("No secrets found."),
        "scanning the tree must not re-flag the discovered baseline's own hashes, got:\n{}",
        String::from_utf8_lossy(&rescan.stdout)
    );

    assert!(run(&["--update-baseline"]).status.success());
    let size_after = fs::metadata(repo_dir.join(".keywatch-baseline.json"))
        .map_err(|e| e.to_string())?
        .len();
    assert_eq!(
        size_before, size_after,
        "re-updating a discovered baseline must not ingest the baseline itself"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_skips_the_baseline_file() -> Result<(), String> {
    require_git();

    // Committing a baseline must not trip the hook: its stored hashes are
    // added lines in the staged diff and would otherwise be flagged.
    let repo_dir = unique_temp_dir("staged_skips_baseline");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("secrets.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(args)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&["scan", ".", "--update-baseline"]).status.success());

    let status = Command::new("git")
        .args(["add", "secrets.txt", ".keywatch-baseline.json"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success(), "git add should succeed");

    let staged = run(&["scan", "--staged"]);
    assert!(
        matches!(staged.status.code(), Some(0)),
        "staging the baseline must not fail the hook\nstdout:\n{}",
        String::from_utf8_lossy(&staged.stdout)
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_repo_detectors_toml_cannot_disable_hook_scan() -> Result<(), String> {
    require_git();

    // A repository that ships its own detectors.toml replaces the detector
    // set. The hook runs with --no-config-discovery precisely so a scanned
    // repository cannot switch off detection for everyone who clones it.
    let repo_dir = unique_temp_dir("hostile_detectors_toml");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("detectors.toml"),
        "[[detectors]]\nname = \"Noop\"\npattern = \"\\\\bqqqzzz1234\\\\b\"\n\
         finding_type = \"Noop\"\nseverity = \"LOW\"\n",
    )
    .map_err(|e| e.to_string())?;
    stage_file(
        &repo_dir,
        "leak.txt",
        "aws_secret_access_key = xJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY42\n",
    )?;
    let status = Command::new("git")
        .args(["add", "detectors.toml"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success());

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "--staged", "--no-baseline-discovery"])
            .args(extra)
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert_eq!(
        run(&["--no-config-discovery"]).status.code(),
        Some(1),
        "with built-in detectors the staged secret must still be reported"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_reads_blobs_git_renders_as_binary() -> Result<(), String> {
    require_git();

    // `*.env -diff` makes git emit only "Binary files ... differ", so the
    // added lines never appear in the diff. The scan must read the staged
    // blob instead of reporting the file as clean.
    let repo_dir = unique_temp_dir("staged_undiffable_blob");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(repo_dir.join(".gitattributes"), "*.env -diff\n").map_err(|e| e.to_string())?;
    stage_file(
        &repo_dir,
        "secrets.env",
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged", "--no-baseline-discovery", "--verbose"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(&repo_dir)
        .output()
        .expect("run key-watch");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(1),
        "a '-diff' gitattribute must not hide a staged secret\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("\"file_path\": \"secrets.env\""),
        "the finding must be attributed to the real path\nstdout:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_baseline_suppression_is_reported() -> Result<(), String> {
    require_git();

    // A committed baseline is repo-controlled data that silently removes
    // findings; the count must be visible so suppression cannot hide.
    let repo_dir = unique_temp_dir("baseline_suppression_visible");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("secrets.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "."])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&["--update-baseline"]).status.success());
    let scan = run(&[]);
    let stdout = String::from_utf8_lossy(&scan.stdout);

    assert!(
        stdout.contains("Suppressed") && stdout.contains("finding(s)"),
        "the suppressed count must be printed, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_git_history_attributes_real_paths_and_honours_excludes() -> Result<(), String> {
    require_git();

    // History findings used to be keyed under a synthetic "<git-history>"
    // path, which no baseline entry could match, and this mode ignored
    // --exclude entirely.
    let repo_dir = unique_temp_dir("git_history_paths");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "leak.txt",
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
        "add",
    )?;

    let verbose = run_git_history_scan(&repo_dir, &["--verbose", "--no-baseline-discovery"])?;
    let stdout = String::from_utf8_lossy(&verbose.stdout);
    assert!(
        stdout.contains("\"file_path\": \"leak.txt\""),
        "history findings must carry the real path, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("<git-history>"),
        "the synthetic path must be gone, got:\n{stdout}"
    );

    let excluded = run_git_history_scan(
        &repo_dir,
        &["--exclude", "leak.txt", "--no-baseline-discovery"],
    )?;
    assert_eq!(
        excluded.status.code(),
        Some(0),
        "--exclude must apply to git-history scans"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_survives_diff_relative_from_subdirectory() -> Result<(), String> {
    require_git();

    // diff.relative makes git emit cwd-relative paths and drop changes
    // outside the cwd, which silently hid staged secrets.
    let repo_dir = unique_temp_dir("staged_diff_relative");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::create_dir_all(repo_dir.join("sub")).map_err(|e| e.to_string())?;
    fs::write(repo_dir.join("sub/keep.txt"), "clean\n").map_err(|e| e.to_string())?;
    commit_file(&repo_dir, "root.txt", "clean\n", "init")?;
    let status = Command::new("git")
        .args(["config", "diff.relative", "true"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success());
    stage_file(
        &repo_dir,
        "root.txt",
        "clean\naws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged", "--no-baseline-discovery"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(repo_dir.join("sub"))
        .output()
        .expect("run key-watch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "diff.relative must not hide a staged secret outside the cwd"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_prune_baseline_drops_stale_entries() -> Result<(), String> {
    require_git();

    // --update-baseline only ever appends, so entries for deleted files and
    // rotated credentials kept suppressing forever.
    let dir = unique_temp_dir("prune_baseline");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("a.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        dir.join("b.txt"),
        "aws_access_key_id = AKIAJJJJJJJJJJJJJJJJ\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", ".", "--baseline", "bl.json"])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&dir)
            .output()
            .expect("run key-watch")
    };
    let entries = || -> usize {
        let text = fs::read_to_string(dir.join("bl.json")).expect("read baseline");
        text.matches("\"file_path\"").count()
    };

    assert!(run(&["--update-baseline"]).status.success());
    let with_both = entries();
    assert!(with_both >= 2, "expected entries for both files");

    fs::remove_file(dir.join("b.txt")).map_err(|e| e.to_string())?;

    assert!(run(&["--update-baseline"]).status.success());
    assert_eq!(
        entries(),
        with_both,
        "a plain update must not drop the stale entry"
    );

    let pruned = run(&["--update-baseline", "--prune-baseline"]);
    assert!(pruned.status.success());
    assert!(
        entries() < with_both,
        "--prune-baseline must drop entries the scan no longer finds"
    );
    assert!(
        String::from_utf8_lossy(&pruned.stdout).contains("Pruned 1 baseline entry"),
        "the dropped count must be visible, got:\n{}",
        String::from_utf8_lossy(&pruned.stdout)
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn test_staged_scan_survives_hostile_git_config() -> Result<(), String> {
    require_git();

    // Every override in the staged git invocation exists because one of these
    // settings breaks parsing. Without this test, deleting any of them is
    // invisible: the scan reports clean or attributes findings to a mangled
    // path, and no other test notices.
    let repo_dir = unique_temp_dir("hostile_git_config");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    for (key, value) in [
        ("color.ui", "always"),
        ("diff.mnemonicPrefix", "true"),
        ("diff.noprefix", "true"),
        ("core.quotePath", "true"),
        ("diff.relative", "true"),
    ] {
        let status = Command::new("git")
            .args(["config", key, value])
            .current_dir(&repo_dir)
            .status()
            .map_err(|e| e.to_string())?;
        assert!(status.success(), "git config {key} failed");
    }
    commit_file(&repo_dir, "config.txt", "one\ntwo\n", "init")?;
    stage_file(
        &repo_dir,
        "config.txt",
        "one\ntwo\naws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged", "--verbose", "--no-baseline-discovery"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(&repo_dir)
        .output()
        .expect("run key-watch");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "stdout:\n{stdout}");
    assert!(
        stdout.contains("\"file_path\": \"config.txt\""),
        "path attribution must survive prefix settings, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"line_number\": 3"),
        "line attribution must survive, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_staged_scan_outside_a_repository_fails_closed() {
    // templates/pre-commit.sh documents that any exit above 1 blocks the
    // commit; nothing pinned that the scanner actually produces it.
    let dir = unique_temp_dir("staged_outside_repo");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create dir");

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--staged", "--no-baseline-discovery"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .env("GIT_CEILING_DIRECTORIES", &dir)
        .current_dir(&dir)
        .output()
        .expect("run key-watch");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a git failure must exit 2 so the hook fails closed, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_staged_scan_paths_narrow_the_diff() -> Result<(), String> {
    require_git();

    let repo_dir = unique_temp_dir("staged_path_narrowing");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(&repo_dir, "clean.txt", "nothing\n", "init")?;
    stage_file(&repo_dir, "clean.txt", "nothing\nstill nothing\n")?;
    stage_file(
        &repo_dir,
        "secret.txt",
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )?;

    let run = |path: &str| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "--staged", "--no-baseline-discovery", "--", path])
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert_eq!(
        run("clean.txt").status.code(),
        Some(0),
        "narrowing to a clean path must not report the other file"
    );
    assert_eq!(
        run("secret.txt").status.code(),
        Some(1),
        "narrowing to the secret path must still report it"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_trusted_mode_ignores_env_config_inside_the_scan_target() -> Result<(), String> {
    // KEYWATCH_CONFIG_PATH is an operator channel, but a repository can reach
    // it through .envrc/direnv or a devcontainer. Trusted mode must refuse it
    // when it points into the scanned tree — including when the process runs
    // from a completely different directory, which the cwd-only check missed.
    let repo_dir = unique_temp_dir("trusted_env_config");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::write(
        repo_dir.join("leak.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        repo_dir.join("detectors.toml"),
        "[[detectors]]\nname = \"Noop\"\npattern = \"\\\\bqqqzzz1234\\\\b\"\n\
         finding_type = \"Noop\"\nseverity = \"LOW\"\n",
    )
    .map_err(|e| e.to_string())?;

    let elsewhere = unique_temp_dir("trusted_env_cwd");
    let _ = fs::remove_dir_all(&elsewhere);
    fs::create_dir_all(&elsewhere).map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", repo_dir.to_str().unwrap()])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", repo_dir.join("detectors.toml"))
            .current_dir(&elsewhere)
            .output()
            .expect("run key-watch")
    };

    assert_eq!(
        run(&["--no-config-discovery", "--no-baseline-discovery"])
            .status
            .code(),
        Some(1),
        "in trusted mode a config inside the scanned tree must not replace the detector set"
    );
    assert_eq!(
        run(&["--no-baseline-discovery"]).status.code(),
        Some(0),
        "in untrusted mode the env config is still honored (control)"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    let _ = fs::remove_dir_all(&elsewhere);
    Ok(())
}

#[test]
fn test_staged_scan_from_subdirectory_still_skips_the_baseline_file() -> Result<(), String> {
    require_git();

    // Staged diffs emit repository-root-relative paths regardless of the
    // process's directory, so self-exclusion must resolve them against the
    // repository root: from a subdirectory the baseline file was re-scanned,
    // and its own hashes failed the scan.
    let repo_dir = unique_temp_dir("staged_baseline_subdir");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    fs::create_dir_all(repo_dir.join("sub")).map_err(|e| e.to_string())?;
    commit_file(&repo_dir, "config.txt", "clean line\n", "init")?;
    fs::write(
        repo_dir.join("secret.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&repo_dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&["scan", ".", "--update-baseline"]).status.success());
    // Rotate the credential so the baseline gains a second entry; only the
    // baseline change is staged.
    fs::write(
        repo_dir.join("secret.txt"),
        "aws_access_key_id = AKIA1234567890ABCDEF\n",
    )
    .map_err(|e| e.to_string())?;
    assert!(run(&["scan", ".", "--update-baseline"]).status.success());

    let status = Command::new("git")
        .args(["add", ".keywatch-baseline.json"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success(), "git add should succeed");

    let staged = |dir: &Path| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "--staged"])
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(dir)
            .output()
            .expect("run key-watch")
    };

    assert_eq!(
        staged(&repo_dir).status.code(),
        Some(0),
        "from the repository root the baseline stays self-excluded"
    );
    assert_eq!(
        staged(&repo_dir.join("sub")).status.code(),
        Some(0),
        "from a subdirectory the baseline must still be self-excluded"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_prune_baseline_rejects_partial_and_standalone_use() {
    // Pruning rebuilds the baseline from what the scan found, so partial
    // scans must refuse it, and a bare --prune-baseline must error instead
    // of being silently ignored.
    let dir = unique_temp_dir("prune_rejects");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create dir");

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(args)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&dir)
            .output()
            .expect("run key-watch")
    };

    let staged = run(&["scan", "--staged", "--update-baseline", "--prune-baseline"]);
    assert_eq!(staged.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&staged.stderr).contains("cannot be used with"),
        "staged scans must refuse --prune-baseline"
    );

    let bare = run(&["scan", ".", "--prune-baseline"]);
    assert_eq!(bare.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bare.stderr).contains("--update-baseline"),
        "a bare --prune-baseline must error instead of being ignored"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_prune_baseline_warns_when_paths_narrow_the_scan() -> Result<(), String> {
    // A path-narrowed scan rebuilds the baseline from that subtree only;
    // silently dropping everything else would hide the data loss.
    let dir = unique_temp_dir("prune_narrow_warning");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("a.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        dir.join("b.txt"),
        "aws_access_key_id = AKIAJJJJJJJJJJJJJJJJ\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "--baseline", "bl.json"])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&dir)
            .output()
            .expect("run key-watch")
    };

    assert!(run(&[".", "--update-baseline"]).status.success());
    let narrowed = run(&["a.txt", "--update-baseline", "--prune-baseline"]);
    assert!(narrowed.status.success());
    let stdout = String::from_utf8_lossy(&narrowed.stdout);
    assert!(
        stdout.contains("scanned paths only"),
        "a narrowed prune must warn, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Pruned 1 baseline entry"),
        "the dropped count must be visible, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn test_git_history_reports_unscannable_blobs_separately() -> Result<(), String> {
    require_git();

    // A git-rendered binary was never seen by the scanner; listing it under
    // "excluded" would read like an operator decision instead of a gap.
    let repo_dir = unique_temp_dir("history_unscannable");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "blob.bin",
        "bin\u{0}ary\u{0}content",
        "add binary",
    )?;

    let output = run_git_history_scan(&repo_dir, &["--verbose", "--no-baseline-discovery"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("\"unscannable\": {\n    \"count\": 1"),
        "the binary blob must be reported as unscannable, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"excluded\": {\n    \"count\": 0"),
        "unscannable files must not be counted as excluded, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_lockfiles_are_excluded_by_default_in_every_mode() -> Result<(), String> {
    require_git();

    // Lockfile checksums flood reports and baselines with "Random String"
    // findings; they hold checksums and URLs, never credentials.
    let repo_dir = unique_temp_dir("lockfile_default_exclude");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    commit_file(
        &repo_dir,
        "Cargo.lock",
        "# generated by cargo\n\"checksum 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        "lockfile",
    )?;

    let scan = |args: &[&str], dir: &Path| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(args)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(dir)
            .output()
            .expect("run key-watch")
    };

    let whole = scan(
        &["scan", ".", "--verbose", "--no-baseline-discovery"],
        &repo_dir,
    );
    assert_eq!(
        whole.status.code(),
        Some(0),
        "a lockfile must not be scanned by default, got:\n{}",
        String::from_utf8_lossy(&whole.stdout)
    );
    assert!(
        String::from_utf8_lossy(&whole.stdout).contains("\"excluded\": {\n    \"count\": 1"),
        "the lockfile must show up as excluded, got:\n{}",
        String::from_utf8_lossy(&whole.stdout)
    );

    // The hook path: a staged lockfile change must not fail the commit.
    fs::write(
        repo_dir.join("Cargo.lock"),
        "# appended\n\"checksum ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"\n",
    )
    .map_err(|e| e.to_string())?;
    let status = Command::new("git")
        .args(["add", "Cargo.lock"])
        .current_dir(&repo_dir)
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success(), "git add should succeed");

    let staged = scan(&["scan", "--staged", "--no-baseline-discovery"], &repo_dir);
    assert_eq!(
        staged.status.code(),
        Some(0),
        "a staged lockfile change must not fail, got:\n{}",
        String::from_utf8_lossy(&staged.stderr)
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_explicit_baseline_missing_file_errors_unless_creating() -> Result<(), String> {
    // A typo'd --baseline used to scan with a silently empty baseline, so the
    // user believed findings were suppressed. It must error instead — unless
    // --update-baseline is going to create the file.
    let dir = unique_temp_dir("baseline_missing_explicit");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("leak.txt"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
    )
    .map_err(|e| e.to_string())?;

    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_key-watch"))
            .args(["scan", "."])
            .args(extra)
            .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
            .current_dir(&dir)
            .output()
            .expect("run key-watch")
    };

    let missing = run(&["--baseline", "nope.json"]);
    assert_eq!(
        missing.status.code(),
        Some(2),
        "a missing explicit baseline must fail the scan, got:\n{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("Baseline file not found"),
        "the error must name the baseline, got:\n{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    assert!(
        !dir.join("nope.json").exists(),
        "a failing scan must not create the baseline"
    );

    let creating = run(&["--baseline", "nope.json", "--update-baseline"]);
    assert!(
        creating.status.success(),
        "--update-baseline must create the missing baseline, got:\n{}",
        String::from_utf8_lossy(&creating.stderr)
    );
    assert!(dir.join("nope.json").exists(), "baseline should be created");

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn test_binary_file_is_reported_as_unscannable() -> Result<(), String> {
    // A NUL-containing file was silently skipped before — neither scanned
    // nor reported. It now surfaces as unscannable so the gap is visible.
    let dir = unique_temp_dir("binary_unscannable");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(dir.join("blob.bin"), b"text tail\x00binary").map_err(|e| e.to_string())?;

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", ".", "--verbose", "--no-baseline-discovery"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(&dir)
        .output()
        .expect("run key-watch");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout.contains("\"unscannable\": {\n    \"count\": 1"),
        "the binary file must be reported as unscannable, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn test_non_utf8_file_with_secret_is_still_scanned() -> Result<(), String> {
    // Invalid UTF-8 used to make whole-file mode skip the file silently; it
    // is now decoded lossily so the secret on it is still found.
    let dir = unique_temp_dir("non_utf8_secret");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(dir.join("legacy.conf"), b"password = 's\xFFcret'\n").map_err(|e| e.to_string())?;

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", ".", "--no-baseline-discovery"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .current_dir(&dir)
        .output()
        .expect("run key-watch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "the lossy-decoded secret must be reported, got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn test_git_history_survives_hostile_git_config() -> Result<(), String> {
    require_git();

    // The history invocation shares GIT_DIFF_FRAMING_ARGS with --staged;
    // this pins that the shared constant actually covers the log command.
    let repo_dir = unique_temp_dir("history_hostile_git_config");
    let _ = fs::remove_dir_all(&repo_dir);
    init_git_repo(&repo_dir)?;
    for (key, value) in [
        ("color.ui", "always"),
        ("diff.mnemonicPrefix", "true"),
        ("diff.noprefix", "true"),
        ("core.quotePath", "true"),
        ("diff.relative", "true"),
    ] {
        let status = Command::new("git")
            .args(["config", key, value])
            .current_dir(&repo_dir)
            .status()
            .map_err(|e| e.to_string())?;
        assert!(status.success(), "git config {key} failed");
    }
    commit_file(
        &repo_dir,
        "config.txt",
        "one\ntwo\naws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
        "add secret",
    )?;

    let output = run_git_history_scan(&repo_dir, &["--verbose", "--no-baseline-discovery"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "stdout:\n{stdout}");
    assert!(
        stdout.contains("\"file_path\": \"config.txt\""),
        "path attribution must survive hostile config, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"line_number\": 3"),
        "line attribution must survive hostile config, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo_dir);
    Ok(())
}

#[test]
fn test_stdin_with_nul_bytes_scans_through() -> Result<(), String> {
    // stdin scans through NUL bytes (no binary bail-out): a secret after a
    // NUL-containing line is still found.
    use std::io::Write;

    let dir = unique_temp_dir("stdin_nul");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan", "--stdin", "--no-baseline-discovery"])
        .env("KEYWATCH_CONFIG_PATH", detectors_config_path())
        .stdin(std::process::Stdio::piped())
        .current_dir(&dir)
        .spawn()
        .expect("run key-watch");
    {
        // A failed write surfaces as a missing finding below; the child is
        // always waited on regardless.
        let stdin = child.stdin.as_mut().expect("piped stdin");
        let _ = stdin.write_all(b"binary\x00line\naws_access_key_id = AKIA1234567890ABCDEF\n");
    } // stdin dropped: EOF sent before waiting.
    let output = child.wait_with_output().expect("wait for scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "the secret after the NUL line must be found, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn test_scan_reports_are_byte_identical_across_runs() -> Result<(), String> {
    // Detector iteration and rayon scheduling must not leak into the report:
    // the same tree scanned twice produces the same bytes.
    let dir = unique_temp_dir("deterministic_report");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("a.conf"),
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\npassword = 'mySecretPassword'\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        dir.join("b.conf"),
        "xoxb-abcdefghijklmnop-qrstuvwxyz-123456789012\n",
    )
    .map_err(|e| e.to_string())?;

    let options = ScanArgs {
        paths: vec![dir.to_str().expect("temp path should be UTF-8").to_string()],
        no_baseline_discovery: true,
        ..Default::default()
    };

    let (findings_first, metadata_first) =
        run_scan(&options, None).expect("first run_scan should succeed");
    let (findings_second, metadata_second) =
        run_scan(&options, None).expect("second run_scan should succeed");

    let report_first = create_report(findings_first, metadata_first, "0.0s".to_string(), false)
        .expect("first report should serialize");
    let report_second = create_report(findings_second, metadata_second, "0.0s".to_string(), false)
        .expect("second report should serialize");

    assert_eq!(
        report_first, report_second,
        "scanning the same fixture twice must produce byte-identical reports"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
