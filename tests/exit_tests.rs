use std::env::temp_dir;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn unique_test_dir(name: &str) -> PathBuf {
    temp_dir().join(format!(
        "keywatch_{name}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ))
}

fn setup_scan_dir(name: &str, include_detectors: bool) -> PathBuf {
    let dir = unique_test_dir(name);
    fs::create_dir(&dir).expect("Create test dir");

    if include_detectors {
        let detectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("detectors.toml");
        fs::copy(detectors, dir.join("detectors.toml")).expect("Copy detectors.toml");
    }

    dir
}

#[test]
fn test_exit_code_on_secrets() {
    let test_dir = setup_scan_dir("exit_secrets", true);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&temp_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(1),
        "Should exit 1 when secrets are found"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exit_code_on_no_secrets() {
    let test_dir = setup_scan_dir("exit_no_secrets", true);
    let temp_file = test_dir.join("plain.txt");
    fs::write(&temp_file, "This is just plain text.").expect("Write test file");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&temp_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(0),
        "Should exit 0 when no secrets are found"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_runtime_errors_exit_with_code_two() {
    let test_dir = setup_scan_dir("exit_runtime_error", false);
    let temp_file = test_dir.join("secret.txt");
    let invalid_detectors = test_dir.join("invalid-detectors.toml");
    fs::write(&temp_file, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file");
    fs::write(&invalid_detectors, "[[detectors]").expect("Write invalid detector config");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .env("KEYWATCH_CONFIG_PATH", invalid_detectors)
        .arg("scan")
        .arg(&temp_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(status.code(), Some(2), "Should exit 2 on runtime errors");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_embedded_detectors_enable_standalone_scan() {
    // Given a standalone binary with no detector configuration on disk.
    let test_dir = setup_scan_dir("embedded_detectors", false);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file");

    // When the binary scans a file containing a built-in detector match.
    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .env_remove("KEYWATCH_CONFIG_PATH")
        .env("HOME", &test_dir)
        .env("XDG_CONFIG_HOME", &test_dir)
        .env("APPDATA", &test_dir)
        .env("USERPROFILE", &test_dir)
        .arg("scan")
        .arg(&temp_file)
        .output()
        .expect("Run standalone key-watch");

    // Then embedded detectors identify the secret instead of producing a config error.
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains("potential secret(s) detected"));

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_trusted_scan_ignores_environment_detector_config() {
    // Given a detector configuration placed in environment-derived locations
    // that a hook-style trusted scan must not consult.
    let test_dir = setup_scan_dir("trusted_env_detectors", false);
    let noop_detectors = "[[detectors]]\nname = \"Noop\"\npattern = \"ZZZ_NEVER_MATCHES\"\nfinding_type = \"Noop\"\nseverity = \"LOW\"\n";
    for relative in [".config/keywatch", "Library/Application Support/keywatch"] {
        let config_dir = test_dir.join(relative);
        fs::create_dir_all(&config_dir).expect("Create detector config dir");
        fs::write(config_dir.join("detectors.toml"), noop_detectors).expect("Write detectors");
    }
    let secret_file = test_dir.join("secret.txt");
    fs::write(&secret_file, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file");

    // When a trusted scan runs, built-in detectors still report the secret.
    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .env_remove("KEYWATCH_CONFIG_PATH")
        .env("HOME", &test_dir)
        .env("XDG_CONFIG_HOME", test_dir.join(".config"))
        .env("APPDATA", &test_dir)
        .env("USERPROFILE", &test_dir)
        .arg("scan")
        .arg("--no-config-discovery")
        .arg(&secret_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(1),
        "environment-derived detectors must not replace built-ins in trusted mode"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_fail_on_unscannable_reports_binary_content() {
    // Given a file the scanner cannot read because it contains NUL bytes.
    let test_dir = setup_scan_dir("fail_on_unscannable", true);
    let binary_file = test_dir.join("payload.bin");
    fs::write(&binary_file, b"\x00\x01AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write binary file");

    // When scanning without the flag, an unscannable file does not block.
    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&binary_file)
        .status()
        .expect("Run key-watch");
    assert_eq!(status.code(), Some(0));

    // Then scanning with the flag fails, because the content was never verified.
    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg("--fail-on-unscannable")
        .arg(&binary_file)
        .status()
        .expect("Run key-watch");
    assert_eq!(status.code(), Some(1));

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exit_mode_always() {
    let test_dir = setup_scan_dir("exit_always", true);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&temp_file)
        .arg("--exit-mode")
        .arg("always")
        .status()
        .expect("Run key-watch");

    assert_eq!(status.code(), Some(0), "Should exit 0 in always mode");

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_exit_mode_critical_high_vs_low() {
    let high_dir = setup_scan_dir("exit_critical_high", true);
    let high_file = high_dir.join("secret.txt");
    fs::write(&high_file, "AKIAABCDEFGHIJKLMNOP").expect("Write HIGH severity");

    let high_status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&high_dir)
        .arg("scan")
        .arg(&high_file)
        .arg("--exit-mode")
        .arg("critical")
        .status()
        .expect("Run key-watch");

    assert_eq!(
        high_status.code(),
        Some(1),
        "Should exit 1 for HIGH severity findings"
    );

    let low_dir = setup_scan_dir("exit_critical_low", true);
    let low_file = low_dir.join("secret.txt");
    fs::write(&low_file, "user@example.com").expect("Write LOW severity");

    let low_status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&low_dir)
        .arg("scan")
        .arg(&low_file)
        .arg("--exit-mode")
        .arg("critical")
        .status()
        .expect("Run key-watch");

    assert_eq!(
        low_status.code(),
        Some(0),
        "Should exit 0 for non-HIGH findings in critical mode"
    );

    fs::remove_dir_all(high_dir).expect("Cleanup high dir");
    fs::remove_dir_all(low_dir).expect("Cleanup low dir");
}

#[test]
fn test_scan_multiple_paths() {
    let test_dir = setup_scan_dir("scan_multi_paths", true);
    let file1 = test_dir.join("secret1.txt");
    let file2 = test_dir.join("secret2.txt");
    fs::write(&file1, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file 1");
    fs::write(&file2, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file 2");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&file1)
        .arg(&file2)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(1),
        "Should exit 1 when secrets are found in multiple paths"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_scan_output_file() {
    let test_dir = setup_scan_dir("scan_output_file", true);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file");

    let out_file = test_dir.join("report.json");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&temp_file)
        .arg("--output")
        .arg(&out_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(1),
        "Should exit 1 when secrets are found"
    );
    assert!(out_file.exists(), "Output file should be created");

    let report_content = fs::read_to_string(&out_file).expect("Read output file");
    assert!(
        report_content.contains("FAIL"),
        "Report should contain FAIL"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_scan_output_file_when_no_secrets_reports_pass() {
    let test_dir = setup_scan_dir("scan_output_pass", true);
    let temp_file = test_dir.join("plain.txt");
    fs::write(&temp_file, "nothing secret here").expect("Write test file");

    let out_file = test_dir.join("report.json");

    let status = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&temp_file)
        .arg("--output")
        .arg(&out_file)
        .status()
        .expect("Run key-watch");

    assert_eq!(
        status.code(),
        Some(0),
        "Should exit 0 when no secrets are found"
    );
    assert!(out_file.exists(), "Output file should be created");

    let report_content = fs::read_to_string(&out_file).expect("Read output file");
    assert!(
        report_content.contains("PASS"),
        "Report should contain PASS"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_scan_verbose_output() {
    let test_dir = setup_scan_dir("scan_verbose_output", true);
    let temp_file = test_dir.join("secret.txt");
    fs::write(&temp_file, "AWS_KEY=AKIAABCDEFGHIJKLMNOP").expect("Write test file");

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .current_dir(&test_dir)
        .arg("scan")
        .arg(&temp_file)
        .arg("--verbose")
        .output()
        .expect("Run key-watch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Should exit 1 when secrets are found"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("AKIAABCDEFGHIJKLMNOP"),
        "reports must redact matched text by default, got:\n{stdout}"
    );
    assert!(
        stdout.contains("redacted") && stdout.contains("AWS Access Key"),
        "the finding must still be identifiable, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"status\": \"FAIL\""),
        "Verbose output should contain FAIL status"
    );

    fs::remove_dir_all(test_dir).expect("Cleanup");
}

#[test]
fn test_verify_integrity_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .arg("verify-integrity")
        .output()
        .expect("Run verify-integrity");

    assert_eq!(
        output.status.code(),
        Some(0),
        "Should exit 0 for verify-integrity"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Binary permissions verified") && stdout.contains("not world-writable"),
        "the success message must say which check ran, got:\n{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn test_verify_integrity_rejects_world_writable_binary() {
    use std::os::unix::fs::PermissionsExt;

    let dir = unique_test_dir("world_writable_integrity");
    fs::create_dir_all(&dir).expect("Create test dir");
    let binary = dir.join("key-watch");
    fs::copy(env!("CARGO_BIN_EXE_key-watch"), &binary).expect("Copy binary");
    let mut permissions = fs::metadata(&binary)
        .expect("Read binary metadata")
        .permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(&binary, permissions).expect("Mark binary world-writable");

    let output = Command::new(&binary)
        .arg("verify-integrity")
        .output()
        .expect("Run verify-integrity");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a world-writable binary must fail the check, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("world-writable"),
        "the error must name the failed property, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_init_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .arg("init")
        .arg("bash")
        .output()
        .expect("Run init bash");

    assert_eq!(output.status.code(), Some(0), "Should exit 0 for init");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("alias keywatch='key-watch'"),
        "Should contain alias definition"
    );
    assert!(
        stdout.contains("alias kw='key-watch'"),
        "Should contain kw alias"
    );
}

#[test]
fn test_show_secrets_opts_into_raw_matched_content() {
    let dir = setup_scan_dir("show_secrets", true);
    let file = dir.join("leak.txt");
    fs::write(&file, "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n").expect("write");

    let output = Command::new(env!("CARGO_BIN_EXE_key-watch"))
        .args(["scan"])
        .arg(&file)
        .args(["--verbose", "--show-secrets"])
        .output()
        .expect("run key-watch");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("AKIAABCDEFGHIJKLMNOP"),
        "--show-secrets must include raw matched text, got:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}
