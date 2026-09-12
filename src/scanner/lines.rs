//! Per-line and chunk scanning: the keyword prefilter, the detector accept
//! chain, and the stream/chunk drivers shared by every scan mode.

use crate::detector::Detector;
use crate::report::Finding;
use crate::scanner::ScannerError;
use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::HashSet;
use std::io::BufRead;

const INLINE_SUPPRESS: &str = "keywatch:ignore";

/// Whether a line carries the inline suppression marker. `lowered_line` must
/// already be lowercased by [`to_lowercase_into`], so callers reuse the
/// buffer they already built instead of lowercasing twice.
fn is_inline_suppressed(lowered_line: &str) -> bool {
    lowered_line.contains(INLINE_SUPPRESS)
}

/// Reads one line into `raw_line` (cleared first), returning `false` at end
/// of stream. Strips a trailing `\n` and `\r`. The caller decodes lossily:
/// one invalid byte must not abort a scan. Shared by the stream and staged
/// parsers so terminator handling exists in exactly one place.
pub(super) fn read_raw_line<ReaderType: BufRead>(
    reader: &mut ReaderType,
    path: &str,
    raw_line: &mut Vec<u8>,
) -> Result<bool, ScannerError> {
    raw_line.clear();
    let bytes_read =
        reader
            .read_until(b'\n', raw_line)
            .map_err(|source| ScannerError::ReadStream {
                path: path.to_string(),
                source,
            })?;
    if bytes_read == 0 {
        return Ok(false);
    }
    if raw_line.last() == Some(&b'\n') {
        raw_line.pop();
    }
    if raw_line.last() == Some(&b'\r') {
        raw_line.pop();
    }
    Ok(true)
}

/// Lowercases `src` into `buf` without allocating a fresh string per line.
/// ASCII input (the overwhelming majority of scanned bytes) takes a
/// byte-per-byte fast path; the Unicode path is char-by-char and an order of
/// magnitude slower.
fn to_lowercase_into(src: &str, buf: &mut String) {
    buf.clear();
    if src.is_ascii() {
        buf.extend(src.bytes().map(|byte| byte.to_ascii_lowercase() as char));
    } else {
        buf.extend(src.chars().flat_map(char::to_lowercase));
    }
}
/// Folds every distinct detector keyword into one Aho-Corasick automaton so a
/// line is checked against all keywords in a single pass instead of one
/// substring search per keyword per detector.
pub(super) struct KeywordPrefilter {
    automaton: Option<AhoCorasick>,
    /// Automaton pattern index -> indices of detectors owning that keyword.
    owners: Vec<Vec<usize>>,
    /// Detectors without keywords always run their regex.
    unconditional: Vec<usize>,
    detector_count: usize,
}

impl KeywordPrefilter {
    pub(super) fn new(line_detectors: &[&Detector]) -> Self {
        let mut patterns: Vec<&str> = Vec::new();
        let mut pattern_indices: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        let mut owners: Vec<Vec<usize>> = Vec::new();
        let mut unconditional = Vec::new();

        for (detector_index, detector) in line_detectors.iter().enumerate() {
            if detector.keywords.is_empty() {
                unconditional.push(detector_index);
                continue;
            }
            for keyword in &detector.keywords {
                let pattern_index = *pattern_indices.entry(keyword.as_str()).or_insert_with(|| {
                    patterns.push(keyword.as_str());
                    owners.push(Vec::new());
                    patterns.len() - 1
                });
                owners[pattern_index].push(detector_index);
            }
        }

        // If the automaton cannot be built, every keyword detector runs
        // unconditionally: slower, but it can never miss a secret.
        let automaton = match AhoCorasick::new(&patterns) {
            Ok(automaton) if !patterns.is_empty() => Some(automaton),
            _ => {
                unconditional = (0..line_detectors.len()).collect();
                None
            }
        };

        Self {
            automaton,
            owners,
            unconditional,
            detector_count: line_detectors.len(),
        }
    }

    /// Whether the combined keywordless gate may filter detectors: the gate
    /// is only sound while the automaton handles exactly the keyword
    /// detectors (on the fail-open path `unconditional` holds every detector,
    /// and gating them would risk missed secrets).
    fn gate_eligible(&self) -> bool {
        self.automaton.is_some()
    }

    /// Clears the keywordless detectors from `candidates` after the combined
    /// gate ruled the line out.
    fn clear_unconditional(&self, candidates: &mut [bool]) {
        for &detector_index in &self.unconditional {
            candidates[detector_index] = false;
        }
    }

    /// Marks the detectors whose keywords occur in `lowered_line` in
    /// `candidates`, a scratch buffer reused across lines.
    fn candidates_into(&self, lowered_line: &str, candidates: &mut Vec<bool>) {
        candidates.clear();
        candidates.resize(self.detector_count, false);
        for &detector_index in &self.unconditional {
            candidates[detector_index] = true;
        }
        if let Some(automaton) = &self.automaton {
            for keyword_match in automaton.find_overlapping_iter(lowered_line) {
                for &detector_index in &self.owners[keyword_match.pattern().as_usize()] {
                    candidates[detector_index] = true;
                }
            }
        }
    }
}

pub(super) struct LineScanContext<'detectors> {
    line_detectors: &'detectors [&'detectors Detector],
    prefilter: KeywordPrefilter,
    /// One combined any-of regex over the keywordless detectors: a single
    /// pass decides whether any of them can match the line, and their
    /// individual regex passes are skipped on lines that cannot. The gate is
    /// exact — is_match is existence, and each pattern is isolated in its own
    /// group so flags cannot leak between branches — so no match is ever
    /// lost; matching lines simply pay the gate plus their real passes.
    /// `None` when a gate cannot be built (fail open).
    unconditional_gate: Option<Regex>,
}

impl<'detectors> LineScanContext<'detectors> {
    pub(super) fn new(line_detectors: &'detectors [&'detectors Detector]) -> Self {
        let prefilter = KeywordPrefilter::new(line_detectors);
        let unconditional_gate = prefilter
            .gate_eligible()
            .then(|| {
                let branches: Vec<&str> = line_detectors
                    .iter()
                    .filter(|detector| detector.keywords.is_empty())
                    .map(|detector| detector.regex.as_str())
                    .collect();
                let combined = format!(
                    "(?:{})",
                    branches
                        .iter()
                        .map(|branch| format!("(?:{branch})"))
                        .collect::<Vec<_>>()
                        .join("|")
                );
                Regex::new(&combined).ok()
            })
            .flatten();
        Self {
            line_detectors,
            prefilter,
            unconditional_gate,
        }
    }
}

/// Per-line scratch buffers, reused across lines to avoid allocating in the
/// hot loop. Each scanning loop owns one (they are not shared across threads).
#[derive(Default)]
pub(super) struct LineScratch {
    lowered_line: String,
    candidates: Vec<bool>,
}
pub(super) fn scan_line_detectors(
    line: &str,
    line_number: usize,
    path: &str,
    context: &LineScanContext<'_>,
    scratch: &mut LineScratch,
    findings: &mut Vec<Finding>,
) {
    to_lowercase_into(line, &mut scratch.lowered_line);
    if is_inline_suppressed(&scratch.lowered_line) {
        return;
    }

    context
        .prefilter
        .candidates_into(&scratch.lowered_line, &mut scratch.candidates);
    let run_unconditional = context
        .unconditional_gate
        .as_ref()
        .is_none_or(|gate| gate.is_match(line));
    if !run_unconditional {
        context
            .prefilter
            .clear_unconditional(&mut scratch.candidates);
    }

    for (detector_index, detector) in context.line_detectors.iter().enumerate() {
        if !scratch.candidates[detector_index] {
            continue;
        }
        for captures in detector.regex.captures_iter(line) {
            let Some(matched) = captures.get(0) else {
                continue;
            };
            if detector.accepts_captures(&captures) {
                findings.push(Finding {
                    file_path: path.to_string(),
                    line_number,
                    matched_content: matched.as_str().to_string(),
                    finding_type: detector.finding_type.clone(),
                    severity: detector.severity,
                    detector_name: detector.name.clone(),
                });
            }
        }
    }
}

pub(super) fn scan_multiline_chunk(
    chunk: &str,
    line_offset: usize,
    path: &str,
    multiline_detectors: &[&Detector],
    findings: &mut Vec<Finding>,
    reported: &mut HashSet<(usize, usize, String)>,
) {
    if multiline_detectors.is_empty() {
        return;
    }
    let lowered_chunk = chunk.to_lowercase();
    for detector in multiline_detectors {
        if detector.has_keywords(&lowered_chunk) {
            for captures in detector.regex.captures_iter(chunk) {
                let Some(matched) = captures.get(0) else {
                    continue;
                };
                let line_in_chunk = chunk[..matched.start()].matches('\n').count() + 1;
                let line_start = chunk[..matched.start()]
                    .rfind('\n')
                    .map(|i| i + 1)
                    .unwrap_or(0);
                // Start position identifies a match exactly; sliding windows
                // re-scan their carry, so the same match can be seen twice.
                if !reported.insert((
                    line_offset + line_in_chunk,
                    matched.start() - line_start,
                    detector.name.clone(),
                )) {
                    continue;
                }
                let line_content = chunk
                    .lines()
                    .nth(line_in_chunk.saturating_sub(1))
                    .unwrap_or_default();
                let line_is_suppressed = is_inline_suppressed(&line_content.to_lowercase());

                if !line_is_suppressed && detector.accepts_captures(&captures) {
                    findings.push(Finding {
                        file_path: path.to_string(),
                        line_number: line_offset + line_in_chunk,
                        matched_content: matched.as_str().to_string(),
                        finding_type: detector.finding_type.clone(),
                        severity: detector.severity,
                        detector_name: detector.name.clone(),
                    });
                }
            }
        }
    }
}
pub(super) fn scan_content(
    content: &str,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext<'_>,
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut total_lines = 0;
    let mut reported = HashSet::new();

    scan_multiline_chunk(
        content,
        0,
        path,
        multiline_detectors,
        &mut findings,
        &mut reported,
    );

    let mut scratch = LineScratch::default();
    for (line_idx, line) in content.lines().enumerate() {
        total_lines += 1;
        scan_line_detectors(
            line,
            line_idx + 1,
            path,
            context,
            &mut scratch,
            &mut findings,
        );
    }

    (findings, total_lines)
}
const CHUNK_SIZE: usize = 1000;
const OVERLAP_LINES: usize = 50;

/// How a streaming scan treats NUL bytes: stdin is scanned through, while
/// a filesystem file containing one is binary and stops the scan.
#[derive(Clone, Copy)]
enum BinaryHandling {
    ScanThrough,
    StopAtNul,
}

/// Outcome of a streaming scan.
pub(super) struct StreamScan {
    pub(super) findings: Vec<Finding>,
    pub(super) total_lines: usize,
    /// A NUL byte was seen: the input is binary. `findings` is empty.
    pub(super) binary: bool,
}

/// Shared streaming core for stdin and file mode. Reads line by line so
/// memory stays bounded regardless of input size, decodes lossily so one
/// invalid byte cannot abort the scan, and runs multiline detectors over
/// sliding windows whose carry keeps boundary-crossing secrets whole.
///
/// Multiline matches are deduplicated by start position: a secret entirely
/// inside the carry would otherwise be reported by both adjacent windows.
/// Matches longer than OVERLAP_LINES that cross a window boundary are still
/// missed - inherent to a fixed window.
fn scan_lines<R: BufRead>(
    reader: &mut R,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext,
    binary_handling: BinaryHandling,
) -> Result<StreamScan, ScannerError> {
    let mut findings = Vec::new();
    let mut reported: HashSet<(usize, usize, String)> = HashSet::new();
    let mut total_lines = 0;
    let mut buffer: Vec<String> = Vec::with_capacity(CHUNK_SIZE + OVERLAP_LINES);
    // Lines preceding buffer[0]: scan_multiline_chunk adds its 1-based
    // in-window line index to this offset.
    let mut lines_before_window = 0;
    let mut scratch = LineScratch::default();
    let mut binary = false;
    let mut raw_line: Vec<u8> = Vec::new();

    loop {
        if !read_raw_line(reader, path, &mut raw_line)? {
            break;
        }
        if matches!(binary_handling, BinaryHandling::StopAtNul) && raw_line.contains(&0) {
            binary = true;
            break;
        }
        total_lines += 1;
        let line = String::from_utf8_lossy(&raw_line).into_owned();
        scan_line_detectors(
            &line,
            total_lines,
            path,
            context,
            &mut scratch,
            &mut findings,
        );
        buffer.push(line);

        if buffer.len() >= CHUNK_SIZE + OVERLAP_LINES {
            let chunk = buffer.join("\n");
            scan_multiline_chunk(
                &chunk,
                lines_before_window,
                path,
                multiline_detectors,
                &mut findings,
                &mut reported,
            );
            lines_before_window += buffer.len() - OVERLAP_LINES;
            buffer.drain(..buffer.len() - OVERLAP_LINES);
        }
    }

    if !binary && !buffer.is_empty() {
        let chunk = buffer.join("\n");
        scan_multiline_chunk(
            &chunk,
            lines_before_window,
            path,
            multiline_detectors,
            &mut findings,
            &mut reported,
        );
    }

    Ok(StreamScan {
        findings,
        total_lines,
        binary,
    })
}

pub(super) fn scan_stream<ReaderType: BufRead>(
    mut reader: ReaderType,
    path: &str,
    multiline_detectors: &[&Detector],
    line_detectors: &[&Detector],
) -> Result<(Vec<Finding>, usize), ScannerError> {
    let context = LineScanContext::new(line_detectors);
    let scanned = scan_lines(
        &mut reader,
        path,
        multiline_detectors,
        &context,
        BinaryHandling::ScanThrough,
    )?;
    Ok((scanned.findings, scanned.total_lines))
}

/// Streams a filesystem file with binary detection: the first NUL byte
/// marks the file binary, stops the scan, and discards partial findings -
/// matching the whole-read behaviour this replaces.
pub(super) fn scan_file_stream<ReaderType: BufRead>(
    reader: &mut ReaderType,
    path: &str,
    multiline_detectors: &[&Detector],
    context: &LineScanContext,
) -> Result<StreamScan, ScannerError> {
    scan_lines(
        reader,
        path,
        multiline_detectors,
        context,
        BinaryHandling::StopAtNul,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::test_support::make_test_detector as make_detector;
    use std::io::Cursor;

    #[test]
    fn test_scan_stream_detects_secrets() {
        let content = "AWS Key: AKIAABCDEFGHIJKLMNOP\npassword = 'mySecretPassword'\n";
        let reader = Cursor::new(content);
        let detectors = [
            make_detector("AWS", r"\bAKIA[A-Z0-9]{16}\b", "AWS Key", "HIGH"),
            make_detector(
                "Password",
                r#"password\s*=\s*['"][^'"]+['"]"#,
                "Password",
                "HIGH",
            ),
        ];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.is_multiline());

        let (findings, total_lines) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();

        assert_eq!(total_lines, 2);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .any(|finding| finding.finding_type == "AWS Key")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.finding_type == "Password")
        );
    }

    #[test]
    fn test_scan_stream_respects_inline_suppression() {
        let content = "password = 'secret123' # keywatch:ignore\n";
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "Password",
            r#"password\s*=\s*['"][^'"]+['"]"#,
            "Password",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.is_multiline());

        let (findings, _) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert!(
            findings.is_empty(),
            "Suppressed line should produce no findings"
        );
    }

    #[test]
    fn test_scan_stream_multiline_detector() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwKVPSmwaFkYLv\n-----END RSA PRIVATE KEY-----\n";
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "PrivateKey",
            r"(?s)-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*-----END (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            "Private Key",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.is_multiline());

        let (findings, _) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "Private Key");
    }

    #[test]
    fn test_scan_stream_large_input_chunked() {
        let mut content = String::new();
        for line_number in 0..2500 {
            content.push_str(&format!(
                "line {}: password = 'secret{}'\n",
                line_number, line_number
            ));
        }
        let reader = Cursor::new(content);
        let detectors = [make_detector(
            "Password",
            r#"password\s*=\s*['"][^'"]+['"]"#,
            "Password",
            "HIGH",
        )];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) = detectors
            .iter()
            .partition(|detector| detector.is_multiline());

        let (findings, total_lines) =
            scan_stream(reader, "<test>", &multiline_detectors, &line_detectors).unwrap();
        assert_eq!(total_lines, 2500);
        assert_eq!(
            findings.len(),
            2500,
            "Should find all 2500 secrets across chunks"
        );
    }

    #[test]
    fn test_prefilter_selects_detectors_with_overlapping_keywords() {
        // detectors.toml has genuinely overlapping keywords ("sk_live" for
        // Plaid, "sk_live_" for Stripe and Paystack). A non-overlapping
        // search reports only the shorter one and the longer detector
        // silently never runs.
        let short = Detector::new(
            "Short",
            r"sk_\w+",
            "Short",
            "HIGH",
            &[],
            &["sk_".to_string()],
            None,
        )
        .unwrap();
        let long = Detector::new(
            "Long",
            r"sk_test_\w+",
            "Long",
            "HIGH",
            &[],
            &["sk_test_".to_string()],
            None,
        )
        .unwrap();
        let detectors = vec![&short, &long];
        let prefilter = KeywordPrefilter::new(&detectors);

        let mut candidates = Vec::new();
        prefilter.candidates_into("sk_test_51abcdef", &mut candidates);

        assert_eq!(
            candidates,
            vec![true, true],
            "both the shorter and longer keyword owners must be selected"
        );
    }

    #[test]
    fn test_scan_stream_multiline_inside_overlap_reports_once() {
        // A multiline secret sitting entirely inside the 50-line carry
        // between two windows is scanned by both; it must be reported once.
        let mut content = String::new();
        for line in 0..1000 {
            content.push_str(&format!("filler {line}\n"));
        }
        content.push_str("BEGIN KEY\nmaterial\nEND KEY\n"); // lines 1001..1003
        for line in 0..1100 {
            content.push_str(&format!("tail {line}\n"));
        }

        let detector = make_detector("Block", r"(?s)BEGIN KEY.*?END KEY", "Block", "HIGH");
        let detectors = [detector];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) =
            detectors.iter().partition(|d| d.is_multiline());
        let (findings, total_lines) = scan_stream(
            Cursor::new(content),
            "<test>",
            &multiline_detectors,
            &line_detectors,
        )
        .unwrap();

        assert_eq!(total_lines, 2103);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.line_number)
                .collect::<Vec<_>>(),
            vec![1001],
            "overlap windows must not duplicate a multiline match"
        );
    }

    #[test]
    fn test_scan_stream_multiline_crossing_window_boundary_reports_once() {
        // The secret starts in window 1 but only completes inside window 2's
        // content: exactly one finding, attributed to the true start line.
        let mut content = String::new();
        for line in 0..1048 {
            content.push_str(&format!("filler {line}\n"));
        }
        content.push_str("BEGIN KEY\nmaterial\nEND KEY\n"); // lines 1049..1051
        for line in 0..1200 {
            content.push_str(&format!("tail {line}\n"));
        }

        let detector = make_detector("Block", r"(?s)BEGIN KEY.*?END KEY", "Block", "HIGH");
        let detectors = [detector];
        let (multiline_detectors, line_detectors): (Vec<_>, Vec<_>) =
            detectors.iter().partition(|d| d.is_multiline());
        let (findings, _) = scan_stream(
            Cursor::new(content),
            "<test>",
            &multiline_detectors,
            &line_detectors,
        )
        .unwrap();

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.line_number)
                .collect::<Vec<_>>(),
            vec![1049]
        );
    }
}
