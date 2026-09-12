//! The unified git-diff parser behind `--staged` and `--git-history`, plus
//! the blob reader for files git renders as binary.

use crate::detector::Detector;
use crate::report::{Finding, ScanMetadata};
use crate::scanner::ScannerError;
use crate::scanner::files::{is_baseline_file, is_default_excluded_file, matches_exclude_patterns};
use crate::scanner::lines::{
    LineScanContext, LineScratch, read_raw_line, scan_content, scan_line_detectors,
    scan_multiline_chunk,
};
use glob::Pattern;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Runs `command`, feeds its stdout to `scan`, and reaps the child process.
///
/// Both git-backed scan modes share this so the process lifetime is handled
/// in exactly one place: on a scan error the child is killed rather than left
/// writing into a closed pipe, and it is always waited on before the status
/// is checked.
pub(super) fn scan_git_output<T>(
    mut command: std::process::Command,
    nonzero_status: ScannerError,
    scan: impl FnOnce(BufReader<std::process::ChildStdout>) -> Result<T, ScannerError>,
    spawn_failed: impl FnOnce(std::io::Error) -> ScannerError,
) -> Result<T, ScannerError> {
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(spawn_failed)?;

    let stdout = child.stdout.take().ok_or(ScannerError::CaptureGitStdout)?;
    let scanned = scan(BufReader::new(stdout));
    if scanned.is_err() {
        let _ = child.kill();
    }

    let status = child
        .wait()
        .map_err(|source| ScannerError::GitProcess { source })?;
    let scanned = scanned?;

    status.success().then_some(scanned).ok_or(nonzero_status)
}
fn parse_hunk_new_start(header: &str) -> usize {
    let parsed = header
        .split_whitespace()
        .find(|token| token.starts_with('+'))
        .and_then(|token| {
            token[1..]
                .split(',')
                .next()
                .and_then(|start| start.parse().ok())
        });
    match parsed {
        Some(start) => start,
        // Scanning with a wrong offset still reports the secret; the message
        // makes the misattribution visible instead of silently writing 0.
        None => {
            eprintln!("keywatch: unrecognized hunk header, line numbers may be off: {header}");
            0
        }
    }
}

/// Undoes git's C-style path quoting. `core.quotePath=false` (pinned on both
/// git invocations) leaves non-ASCII names unquoted, but names containing
/// quotes or control characters are still emitted as `"b/we\"ird.txt"`.
fn c_unquote(quoted: &str) -> String {
    let inner = quoted
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(quoted);
    let mut unescaped: Vec<u8> = Vec::with_capacity(inner.len());
    let mut bytes = inner.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            unescaped.push(byte);
            continue;
        }
        match bytes.next() {
            Some(b'"') => unescaped.push(b'"'),
            Some(b'\\') => unescaped.push(b'\\'),
            Some(b't') => unescaped.push(b'\t'),
            Some(b'n') => unescaped.push(b'\n'),
            Some(b'r') => unescaped.push(b'\r'),
            Some(first @ b'0'..=b'3') => {
                // Git escapes arbitrary bytes as three-digit octal.
                let mut value = u32::from(first - b'0');
                for _ in 0..2 {
                    match bytes.next() {
                        Some(digit @ b'0'..=b'7') => value = value * 8 + u32::from(digit - b'0'),
                        _ => break,
                    }
                }
                unescaped.push(value as u8);
            }
            Some(other) => {
                // Not a recognized escape; keep both characters.
                unescaped.push(b'\\');
                unescaped.push(other);
            }
            None => unescaped.push(b'\\'),
        }
    }
    String::from_utf8_lossy(&unescaped).into_owned()
}

fn parse_diff_target_path(target: &str) -> Option<String> {
    let target = target.trim_end();
    if target == "/dev/null" {
        return None;
    }
    let unquoted = c_unquote(target);
    let target = unquoted.strip_prefix("b/").unwrap_or(&unquoted);
    Some(target.to_string())
}

/// Parser state for one diff, kept out of the line loop so every framing rule
/// reads on its own. Hunk state is tracked because added content may itself
/// start with "+", "@@" or "diff ".
#[derive(Default)]
struct StagedDiffState {
    current_path: Option<String>,
    in_hunk: bool,
    next_line_number: usize,
    hunk_start: usize,
    hunk_added: Vec<String>,
    total_lines: usize,
    scanned_files: std::collections::BTreeSet<String>,
    excluded_files: Vec<String>,
    unscannable_from_diff: Vec<String>,
}

impl StagedDiffState {
    /// Scans the buffered added lines of the hunk that just ended, or the
    /// whole diff when the stream ends.
    fn flush_hunk(&mut self, multiline_detectors: &[&Detector], findings: &mut Vec<Finding>) {
        if self.hunk_added.is_empty() {
            return;
        }
        if let Some(path) = self.current_path.as_deref() {
            let chunk = self.hunk_added.join("\n");
            let mut reported = HashSet::new();
            scan_multiline_chunk(
                &chunk,
                self.hunk_start.saturating_sub(1),
                path,
                multiline_detectors,
                findings,
                &mut reported,
            );
        }
        self.hunk_added.clear();
    }

    fn handle_added_line(
        &mut self,
        content: &str,
        context: &LineScanContext<'_>,
        scratch: &mut LineScratch,
        findings: &mut Vec<Finding>,
    ) {
        let line_number = self.next_line_number;
        self.next_line_number += 1;
        let Some(path) = self.current_path.as_deref() else {
            return;
        };
        self.total_lines += 1;
        self.scanned_files.insert(path.to_string());
        scan_line_detectors(content, line_number, path, context, scratch, findings);
        self.hunk_added.push(content.to_string());
    }

    /// A `+++ b/path` header selects the post-image path unless an exclusion
    /// or the baseline file itself rules it out.
    fn select_path(
        &mut self,
        target: &str,
        exclude_patterns: &[Pattern],
        excluded_baseline: Option<&PathBuf>,
        base_dir: &Path,
    ) {
        self.current_path = match parse_diff_target_path(target) {
            Some(path)
                if matches_exclude_patterns(&path, &[], exclude_patterns)
                    || is_baseline_file(&path, base_dir, excluded_baseline)
                    || is_default_excluded_file(&path) =>
            {
                self.excluded_files.push(path);
                None
            }
            other => other,
        };
    }

    /// A `Binary files ... differ` marker (a true binary or a `-diff`
    /// gitattribute) yields no hunks. The diff tells us nothing about the
    /// content, so record the path and read the staged blob directly instead
    /// of reporting the file as clean.
    fn record_binary_marker(
        &mut self,
        marker: &str,
        exclude_patterns: &[Pattern],
        excluded_baseline: Option<&PathBuf>,
        base_dir: &Path,
    ) {
        let path = parse_binary_marker_path(marker);
        // A deleted file has no staged content left to read.
        if path == "/dev/null" {
            return;
        }
        if matches_exclude_patterns(&path, &[], exclude_patterns)
            || is_baseline_file(&path, base_dir, excluded_baseline)
            || is_default_excluded_file(&path)
        {
            self.excluded_files.push(path);
        } else {
            self.unscannable_from_diff.push(path);
        }
    }
}

/// Best-effort path from a `Binary files a/x and b/x differ` marker: the
/// post-image side, for surfacing skipped files. Sides that git quoted are
/// separated by a quoted-space-quoted delimiter, which also keeps `" and "`
/// inside a quoted name from splitting the pair.
fn parse_binary_marker_path(marker: &str) -> String {
    let Some(paths) = marker.strip_suffix(" differ") else {
        return marker.to_string();
    };
    let target = if paths.contains("\" and \"") {
        paths
            .rsplit("\" and \"")
            .next()
            .map(|tail| format!("\"{tail}"))
    } else {
        paths.rsplit(" and ").next().map(str::to_string)
    };
    match target {
        Some(target) => {
            let unquoted = c_unquote(&target);
            unquoted.strip_prefix("b/").unwrap_or(&unquoted).to_string()
        }
        None => marker.to_string(),
    }
}

/// Scans only the added lines of the staged diff, attributing findings to the
/// real file path and post-image line number so `--baseline` entries match.
/// Hunk state is tracked because added content may itself start with "+".
/// Lines are decoded lossily so one non-UTF-8 file cannot abort the scan.
pub(super) fn scan_staged_diff<ReaderType: BufRead>(
    mut reader: ReaderType,
    exclude_patterns: &[Pattern],
    excluded_baseline: Option<&PathBuf>,
    base_dir: &Path,
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<StagedScan, ScannerError> {
    let context = LineScanContext::new(line_detectors);
    let mut findings = Vec::new();
    let mut state = StagedDiffState::default();
    let mut scratch = LineScratch::default();
    let mut raw_line: Vec<u8> = Vec::new();

    while read_raw_line(&mut reader, "<staged>", &mut raw_line)? {
        let line = String::from_utf8_lossy(&raw_line);

        if state.in_hunk {
            if let Some(content) = line.strip_prefix('+') {
                state.handle_added_line(content, &context, &mut scratch, &mut findings);
                continue;
            }
            if line.starts_with('-') || line.starts_with('\\') {
                continue;
            }
        }

        if line.starts_with("@@") {
            state.flush_hunk(multiline_detectors, &mut findings);
            state.hunk_start = parse_hunk_new_start(&line);
            state.next_line_number = state.hunk_start;
            state.in_hunk = true;
            continue;
        }

        if line.starts_with("diff ") {
            state.flush_hunk(multiline_detectors, &mut findings);
            state.in_hunk = false;
            state.current_path = None;
            continue;
        }

        if let Some(target) = line.strip_prefix("+++ ") {
            state.select_path(target, exclude_patterns, excluded_baseline, base_dir);
            continue;
        }

        if let Some(marker) = line.strip_prefix("Binary files ") {
            state.record_binary_marker(marker, exclude_patterns, excluded_baseline, base_dir);
        }
    }

    state.flush_hunk(multiline_detectors, &mut findings);

    let metadata = ScanMetadata {
        files_scanned: state.scanned_files.len(),
        total_lines: state.total_lines,
        excluded_files: state.excluded_files,
        unscannable_files: Vec::new(),
        suppressed_by_baseline: 0,
    };

    Ok(StagedScan {
        findings,
        metadata,
        unscannable_from_diff: state.unscannable_from_diff,
    })
}

/// Result of parsing a staged diff. `unscannable_from_diff` are paths git
/// rendered as binary — "undiffable" is the cause (a real binary, or text
/// marked `-diff` in .gitattributes), not an outcome: their content never
/// appears in the diff and must be read from the index instead.
pub(super) struct StagedScan {
    pub(super) findings: Vec<Finding>,
    pub(super) metadata: ScanMetadata,
    pub(super) unscannable_from_diff: Vec<String>,
}

/// Resolves the staged blob object id for a repository-relative path.
///
/// `git ls-files` is asked with the `literal` magic so a path that looks like
/// git syntax (for example `0:name`) is treated as a file name, not as a
/// stage-prefixed revision.
fn staged_blob_oid(path: &str) -> Result<Option<String>, ScannerError> {
    let output = std::process::Command::new("git")
        .args(["ls-files", "--stage", "-z", "--"])
        .arg(format!(":(top,literal){path}"))
        .output()
        .map_err(|source| ScannerError::RunGitCatFile { source })?;
    if !output.status.success() {
        return Ok(None);
    }
    for record in output.stdout.split(|byte| *byte == 0) {
        let record = String::from_utf8_lossy(record);
        let Some((metadata, _file)) = record.split_once('\t') else {
            continue;
        };
        let mut fields = metadata.split(' ');
        let (Some(_mode), Some(oid), Some("0")) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if oid.bytes().any(|byte| byte != b'0') {
            return Ok(Some(oid.to_string()));
        }
    }
    Ok(None)
}

/// Scans the staged blob of each undiffable path via `git cat-file`.
///
/// Without this a `.gitattributes` entry like `*.env -diff` would hide a
/// staged secret completely: git emits only "Binary files ... differ" and the
/// scan would report the file as clean.
pub(super) fn scan_index_blobs(
    paths: &[String],
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, usize, Vec<String>), ScannerError> {
    let context = LineScanContext::new(line_detectors);
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut skipped = Vec::new();

    for path in paths {
        let Some(oid) = staged_blob_oid(path)? else {
            skipped.push(path.clone());
            continue;
        };
        let output = std::process::Command::new("git")
            .args(["cat-file", "blob", &oid])
            .output()
            .map_err(|source| ScannerError::RunGitCatFile { source })?;
        if !output.status.success() {
            skipped.push(path.clone());
            continue;
        }
        // Genuinely binary content (NUL bytes) is skipped, matching file mode.
        if output.stdout.contains(&0) {
            skipped.push(path.clone());
            continue;
        }
        let content = String::from_utf8_lossy(&output.stdout);
        let (blob_findings, blob_lines) =
            scan_content(&content, path, multiline_detectors, &context);
        findings.extend(blob_findings);
        total_lines += blob_lines;
    }

    Ok((findings, total_lines, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::test_support::make_test_detector as make_detector;
    use std::io::Cursor;

    #[test]
    fn test_scan_staged_diff_preserves_plus_prefixed_added_content() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/notes.txt b/notes.txt\n\
            index aabbcc0..ddeeff1 100644\n\
            --- /dev/null\n\
            +++ b/notes.txt\n\
            @@ -0,0 +1,3 @@\n\
            +SECRET_ONE plain\n\
            +++SECRET_TWO starts with pluses\n\
            +@@ SECRET_THREE looks like a hunk header\n";

        let StagedScan {
            findings, metadata, ..
        } = scan_staged_diff(
            Cursor::new(diff),
            &[],
            None,
            Path::new("."),
            &[],
            &line_detectors,
        )
        .unwrap();

        let summary: Vec<(String, usize)> = findings
            .iter()
            .map(|finding| (finding.matched_content.clone(), finding.line_number))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("SECRET_ONE".to_string(), 1),
                ("SECRET_TWO".to_string(), 2),
                ("SECRET_THREE".to_string(), 3),
            ],
            "added lines starting with '+', '@@' must be scanned as content"
        );
        assert!(findings.iter().all(|f| f.file_path == "notes.txt"));
        assert_eq!(metadata.files_scanned, 1);
    }

    #[test]
    fn test_scan_staged_diff_ignores_deleted_files_and_removed_lines() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/gone.txt b/gone.txt\n\
            deleted file mode 100644\n\
            --- a/gone.txt\n\
            +++ /dev/null\n\
            @@ -1,2 +0,0 @@\n\
            -SECRET_GONE\n\
            -goodbye\n";

        let StagedScan {
            findings, metadata, ..
        } = scan_staged_diff(
            Cursor::new(diff),
            &[],
            None,
            Path::new("."),
            &[],
            &line_detectors,
        )
        .unwrap();

        assert!(findings.is_empty(), "removed lines must not be scanned");
        assert_eq!(metadata.files_scanned, 0);
    }

    #[test]
    fn test_scan_staged_diff_attributes_multiple_files() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/first.txt b/first.txt\n\
            --- a/first.txt\n\
            +++ b/first.txt\n\
            @@ -0,0 +7 @@\n\
            +SECRET_A\n\
            diff --git a/second.txt b/second.txt\n\
            --- a/second.txt\n\
            +++ b/second.txt\n\
            @@ -0,0 +2 @@\n\
            +SECRET_B\n";

        let StagedScan {
            findings, metadata, ..
        } = scan_staged_diff(
            Cursor::new(diff),
            &[],
            None,
            Path::new("."),
            &[],
            &line_detectors,
        )
        .unwrap();

        let summary: Vec<(String, usize)> = findings
            .iter()
            .map(|finding| (finding.file_path.clone(), finding.line_number))
            .collect();
        assert_eq!(
            summary,
            vec![("first.txt".to_string(), 7), ("second.txt".to_string(), 2)]
        );
        assert_eq!(metadata.files_scanned, 2);
    }

    #[test]
    fn test_scan_staged_diff_queues_binary_files_for_blob_reading() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/img.png b/img.png\n\
            index aabbcc0..ddeeff1 100644\n\
            Binary files a/img.png and b/img.png differ\n";

        let staged = scan_staged_diff(
            Cursor::new(diff),
            &[],
            None,
            Path::new("."),
            &[],
            &line_detectors,
        )
        .unwrap();

        assert!(staged.findings.is_empty());
        assert!(
            staged.metadata.excluded_files.is_empty(),
            "an undiffable file is not 'excluded' — its blob still gets scanned"
        );
        assert_eq!(
            staged.unscannable_from_diff,
            vec!["img.png".to_string()],
            "binary-rendered files must be queued for a direct blob read, or a \
             '-diff' gitattribute hides a staged secret entirely"
        );
    }

    #[test]
    fn test_scan_staged_diff_respects_excludes_for_binary_files() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let diff = "diff --git a/vendor/blob.bin b/vendor/blob.bin\n\
            Binary files a/vendor/blob.bin and b/vendor/blob.bin differ\n";
        let pattern = Pattern::new("vendor/**").unwrap();

        let staged = scan_staged_diff(
            Cursor::new(diff),
            &[pattern],
            None,
            Path::new("."),
            &[],
            &line_detectors,
        )
        .unwrap();

        assert!(
            staged.unscannable_from_diff.is_empty(),
            "an excluded path must not be re-read from the index"
        );
        assert_eq!(
            staged.metadata.excluded_files,
            vec!["vendor/blob.bin".to_string()]
        );
    }

    #[test]
    fn test_scan_staged_diff_survives_non_utf8_content() {
        let detector = make_detector("Line", r"SECRET_\w+", "Test", "HIGH");
        let line_detectors = vec![&detector];
        let mut diff: Vec<u8> = Vec::new();
        diff.extend_from_slice(b"diff --git a/legacy.csv b/legacy.csv\n");
        diff.extend_from_slice(b"--- a/legacy.csv\n");
        diff.extend_from_slice(b"+++ b/legacy.csv\n");
        diff.extend_from_slice(b"@@ -0,0 +1,2 @@\n");
        diff.extend_from_slice(b"+caf\xE9 latin-1 line\n");
        diff.extend_from_slice(b"+SECRET_AFTER_BINARYISH\n");

        let StagedScan { findings, .. } = scan_staged_diff(
            Cursor::new(diff),
            &[],
            None,
            Path::new("."),
            &[],
            &line_detectors,
        )
        .unwrap();

        assert_eq!(
            findings.len(),
            1,
            "non-UTF-8 content must not abort the scan"
        );
        assert_eq!(findings[0].line_number, 2);
    }

    #[test]
    fn test_scan_staged_diff_multiline_detector_uses_hunk_start_offset() {
        let detector = make_detector("Block", r"(?s)BEGIN KEY.*END KEY", "Test", "HIGH");
        let multiline_detectors = vec![&detector];
        let diff = "diff --git a/key.pem b/key.pem\n\
            --- a/key.pem\n\
            +++ b/key.pem\n\
            @@ -0,0 +5,3 @@\n\
            +BEGIN KEY\n\
            +material\n\
            +END KEY\n";

        let StagedScan { findings, .. } = scan_staged_diff(
            Cursor::new(diff),
            &[],
            None,
            Path::new("."),
            &multiline_detectors,
            &[],
        )
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].line_number, 5,
            "multiline findings must use the hunk's post-image start line"
        );
        assert_eq!(findings[0].file_path, "key.pem");
    }

    #[test]
    fn test_parse_diff_target_path_unquotes_c_quoted_names() {
        assert_eq!(
            parse_diff_target_path("\"b/we\\\"ird.txt\"").as_deref(),
            Some("we\"ird.txt")
        );
        assert_eq!(
            parse_diff_target_path("\"b/tab\\there.txt\"").as_deref(),
            Some("tab\there.txt")
        );
        assert_eq!(
            parse_diff_target_path("b/plain.txt").as_deref(),
            Some("plain.txt")
        );
        assert_eq!(parse_diff_target_path("/dev/null"), None);
    }

    #[test]
    fn test_parse_binary_marker_path_unquotes_and_takes_post_image() {
        assert_eq!(
            parse_binary_marker_path(
                "Binary files \"a/one and two.bin\" and \"b/one and two.bin\" differ"
            ),
            "one and two.bin"
        );
        assert_eq!(
            parse_binary_marker_path("Binary files /dev/null and b/plain.bin differ"),
            "plain.bin"
        );
    }
}
