pub mod baseline;
pub mod cli;
pub mod config;
pub mod detector;
pub mod hooks;
pub mod report;
mod run_error;
pub mod scanner;
pub mod utils;

pub use hooks::{generate_pre_commit_hook, generate_pre_push_hook};
pub use run_error::RunCliError;

use clap::Parser;
use cli::{CliOptions, Command, ExitMode, HookAction, OutputFormat, ScanArgs, Shell};
use report::Finding;
use std::env;
use std::time::Instant;

use crate::report::Severity;

pub const EXIT_CODE_RUNTIME_ERROR: i32 = 2;

/// Runs the requested command and returns the process exit code.
///
/// Only scanning produces a meaningful code (0 pass, 1 findings). Every other
/// command reports success with 0. `main` owns the actual `process::exit`.
pub fn run_cli() -> Result<i32, RunCliError> {
    let options = CliOptions::parse();
    options.validate()?;

    match options.command {
        Command::Scan(args) => run_scan_command(&args),
        Command::Hook(args) => {
            match args.action {
                HookAction::Install(install_args) => hooks::install_hook(&install_args)?,
                HookAction::Uninstall(uninstall_args) => hooks::uninstall_hook(&uninstall_args)?,
            }
            Ok(0)
        }
        Command::Init { shell } => {
            print_shell_init(&shell)?;
            Ok(0)
        }
        Command::VerifyIntegrity => {
            verify_binary_integrity()?;
            Ok(0)
        }
    }
}

/// Writes a line to stdout.
///
/// `println!` panics if stdout is closed, which happens routinely when output
/// is piped (`key-watch scan . | head`). A closed pipe is a normal way for a
/// reader to stop listening, so it is reported as success; anything else is a
/// real I/O failure and is propagated.
fn emit(line: &str) -> Result<(), RunCliError> {
    utils::emit_line(line).map_err(|source| RunCliError::WriteOutput { source })
}

fn run_scan_command(args: &ScanArgs) -> Result<i32, RunCliError> {
    let start = Instant::now();
    let args = resolve_scan_args(args)?;
    let config = load_scan_config(&args)?;
    let (mut findings, mut scan_metadata) = scanner::run_scan(&args, config.as_ref())?;

    // Pruning rewrites the baseline from what the scan actually found, and a
    // plain update must refresh the recorded line numbers of known findings,
    // so neither may filter the findings first.
    let prune = args.prune_baseline && args.update_baseline;
    let mut loaded_baseline = match args.baseline.as_deref() {
        Some(path) => Some(baseline::Baseline::load(std::path::Path::new(path))?),
        None => None,
    };
    if let Some(baseline) = loaded_baseline
        .as_ref()
        .filter(|_| !prune && !args.update_baseline)
    {
        let before = findings.len();
        findings = baseline.filter_findings(findings);
        scan_metadata.suppressed_by_baseline = before - findings.len();
    }

    if args.update_baseline {
        update_baseline(&args, &findings, &mut loaded_baseline, prune)?;
        return Ok(0);
    }

    emit_scan_result(&args, findings, scan_metadata, start)
}

/// Resolves the baseline like config: an explicit `--baseline` wins,
/// otherwise discover `.keywatch-baseline.json` in the scanned tree.
/// `--update-baseline` with nothing discovered creates the conventional file
/// in the current directory. The resolved path also gets excluded from
/// scanning.
fn resolve_scan_args(args: &ScanArgs) -> Result<ScanArgs, RunCliError> {
    let mut args = args.clone();
    if args.baseline.is_none() && !args.no_baseline_discovery {
        args.baseline = baseline::discover_baseline_path(&args.paths);
        if args.baseline.is_none() && args.update_baseline {
            args.baseline = Some(baseline::DEFAULT_BASELINE_NAME.to_string());
        }
    }

    // Discovery only ever resolves existing files, so a missing baseline here
    // means an explicit --baseline typo. Without --update-baseline nothing
    // will create it, and scanning with a silently-empty baseline would
    // report suppression that never happens.
    if let Some(baseline_path) = args.baseline.as_deref() {
        if !args.update_baseline && !std::path::Path::new(baseline_path).exists() {
            return Err(RunCliError::BaselineNotFound {
                path: baseline_path.to_string(),
            });
        }
    }

    Ok(args)
}

fn load_scan_config(args: &ScanArgs) -> Result<Option<config::KeywatchConfig>, RunCliError> {
    match args.config.is_some() || !args.no_config_discovery {
        true => config::KeywatchConfig::load_for_paths(args.config.as_deref(), &args.paths)
            .map_err(Into::into),
        false => Ok(None),
    }
}

/// Writes the baseline after the scan.
///
/// Pruning rebuilds it from what the scan actually found. The drop count and
/// the narrowed scope stay visible: a narrowed scan would otherwise silently
/// delete entries for locations it never looked at.
fn update_baseline(
    args: &ScanArgs,
    findings: &[Finding],
    loaded_baseline: &mut Option<baseline::Baseline>,
    prune: bool,
) -> Result<(), RunCliError> {
    let baseline_path = args
        .baseline
        .as_ref()
        .ok_or(RunCliError::MissingBaselineForUpdate)?;
    let baseline = loaded_baseline
        .as_mut()
        .ok_or(RunCliError::MissingBaselineForUpdate)?;

    if prune {
        let stale = baseline.entries.len();
        *baseline = baseline::Baseline::from_findings(findings);
        let dropped = stale.saturating_sub(baseline.entries.len());
        if dropped > 0 {
            let noun = if dropped == 1 { "entry" } else { "entries" };
            emit(&format!(
                "Pruned {dropped} baseline {noun} not found by this scan"
            ))?;
        }
        if !scan_covers_paths(&args.paths) {
            emit(
                "WARNING: --prune-baseline rebuilt the baseline from the scanned paths only; findings outside them are no longer baselined",
            )?;
        }
    } else {
        baseline.update_with_findings(findings);
    }

    baseline.save(std::path::Path::new(baseline_path))?;
    emit(&format!("Baseline updated: {baseline_path}"))
}

/// Emits the report, the suppression notice and the summary, writes
/// `--output` when requested, and returns the process exit code.
fn emit_scan_result(
    args: &ScanArgs,
    findings: Vec<Finding>,
    scan_metadata: report::ScanMetadata,
    start: Instant,
) -> Result<i32, RunCliError> {
    let scan_time = format_scan_time(start.elapsed());
    let suppressed = scan_metadata.suppressed_by_baseline;
    let severity_counts = report::get_severity_counts(&findings);
    let mut exit_code = calculate_exit_code(&findings, &args.exit_mode);
    if args.fail_on_unscannable
        && matches!(args.exit_mode, ExitMode::Strict)
        && !scan_metadata.unscannable_files.is_empty()
    {
        exit_code = 1;
    }
    let findings_count = findings.len();
    let report_out = match args.format {
        OutputFormat::Json => {
            report::create_report(findings, scan_metadata, scan_time, args.show_secrets)
        }
        OutputFormat::Sarif => report::create_sarif_report(findings, scan_metadata, scan_time),
    }
    .map_err(|source| RunCliError::ReportSerialize { source })?;

    if suppressed > 0 && !args.verbose {
        emit(&format!(
            "Suppressed {} finding(s) via {}",
            suppressed,
            args.baseline
                .as_deref()
                .map(|path| utils::display_path(std::path::Path::new(path)))
                .unwrap_or_else(|| "baseline".to_string())
        ))?;
    }

    let summary = match findings_count {
        _ if args.verbose => report_out.clone(),
        0 => "No secrets found.".to_string(),
        count => format!(
            "WARNING: {} potential secret(s) detected (CRITICAL: {}, HIGH: {}, MEDIUM: {}, LOW: {})",
            count,
            severity_counts.critical,
            severity_counts.high,
            severity_counts.medium,
            severity_counts.low
        ),
    };
    emit(&summary)?;

    if let Some(ref output_path) = args.output {
        utils::write_to_file(output_path, &report_out).map_err(|source| {
            RunCliError::ReportWrite {
                path: output_path.clone(),
                source,
            }
        })?;
    }

    Ok(exit_code)
}

fn format_scan_time(elapsed: std::time::Duration) -> String {
    format!(
        "{}.{:01}s",
        elapsed.as_secs(),
        elapsed.subsec_millis() / 100
    )
}

/// Whether the scan inputs cover the whole tree around the baseline, i.e.
/// pruning cannot silently drop entries for locations the scan never looked
/// at. An empty path list means the current directory; a lone "." or an
/// explicit path naming the current directory counts as the whole tree.
fn scan_covers_paths(paths: &[String]) -> bool {
    match paths {
        [] => true,
        [single] => {
            single == "."
                || std::fs::canonicalize(single)
                    .ok()
                    .zip(std::env::current_dir().ok())
                    .is_some_and(|(canonical, cwd)| canonical == cwd)
        }
        _ => false,
    }
}

fn print_shell_init(shell: &Shell) -> Result<(), RunCliError> {
    let script = match shell {
        Shell::Fish => "alias keywatch 'key-watch'\nalias kw 'key-watch'\n",
        Shell::Bash | Shell::Zsh | Shell::Posix => {
            "alias keywatch='key-watch'\nalias kw='key-watch'\n"
        }
    };

    emit(script.trim_end())
}

/// Checks the running binary's file permissions, the one property it can
/// verify about itself: no cryptographic checksum is involved, so the report
/// says exactly what was checked. On unix a world-writable binary is an
/// error; other platforms have no equivalent permission bit to test.
fn verify_binary_integrity() -> Result<(), RunCliError> {
    let exe_path = env::current_exe().map_err(|source| RunCliError::ExecutablePath { source })?;
    let metadata = exe_path
        .metadata()
        .map_err(|source| RunCliError::ExecutableMetadata { source })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = metadata.permissions();
        let mode = perms.mode();
        if mode & 0o002 != 0 {
            return Err(RunCliError::WorldWritableBinary {
                path: exe_path.to_string_lossy().into_owned(),
            });
        }
        emit(&format!(
            "Binary permissions verified: {exe_path:?} is not world-writable"
        ))?;
    }
    #[cfg(not(unix))]
    emit(&format!(
        "Binary located: {exe_path:?} (permission checks run on unix only)"
    ))?;

    emit(&format!("Size: {} bytes", metadata.len()))
}

fn calculate_exit_code(findings: &[Finding], exit_mode: &ExitMode) -> i32 {
    if findings.is_empty() {
        return 0;
    }

    match exit_mode {
        ExitMode::Always => 0,
        ExitMode::Critical => {
            let has_critical_or_high = findings
                .iter()
                .any(|finding| matches!(finding.severity, Severity::Critical | Severity::High));
            i32::from(has_critical_or_high)
        }
        ExitMode::Strict => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{Severity, calculate_exit_code};
    use crate::cli::ExitMode;
    use crate::report::Finding;

    #[test]
    fn test_calculate_exit_code_across_modes() {
        let critical = Finding {
            file_path: "critical.txt".to_string(),
            line_number: 1,
            finding_type: "Critical".to_string(),
            severity: Severity::Critical,
            matched_content: "secret".to_string(),
            detector_name: "DetectorCritical".to_string(),
        };
        let high = Finding {
            file_path: "high.txt".to_string(),
            line_number: 1,
            finding_type: "High".to_string(),
            severity: Severity::High,
            matched_content: "secret".to_string(),
            detector_name: "DetectorHigh".to_string(),
        };
        let low = Finding {
            file_path: "low.txt".to_string(),
            line_number: 1,
            finding_type: "Low".to_string(),
            severity: Severity::Low,
            matched_content: "token".to_string(),
            detector_name: "DetectorLow".to_string(),
        };

        assert_eq!(calculate_exit_code(&[], &ExitMode::Strict), 0);
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&low), &ExitMode::Always),
            0
        );
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&low), &ExitMode::Critical),
            0
        );
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&high), &ExitMode::Critical),
            1
        );
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&critical), &ExitMode::Critical),
            1
        );
        assert_eq!(
            calculate_exit_code(std::slice::from_ref(&critical), &ExitMode::Always),
            0
        );
        assert_eq!(
            calculate_exit_code(&[low.clone(), high], &ExitMode::Strict),
            1
        );
        assert_eq!(
            calculate_exit_code(&[low.clone(), critical], &ExitMode::Strict),
            1
        );
    }
}
