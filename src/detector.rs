mod error;

pub use error::DetectorInitError;

use crate::report::{ParseSeverityError, Severity};
use regex::{Captures, Regex};
use serde::Deserialize;
use std::{borrow::Cow, fs, str::FromStr};
use thiserror::Error;

const EMBEDDED_DETECTORS_CONFIG: &str = include_str!("../detectors.toml");

/// Filename searched for at the repository root, the user config directory
/// and next to the executable. One constant so a rename cannot split
/// discovery from its error messages.
const DETECTORS_FILE_NAME: &str = "detectors.toml";

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error("invalid pattern in detector '{detector}': {source}")]
    InvalidPattern {
        detector: String,
        source: regex::Error,
    },
    #[error("invalid allowlist pattern in detector '{detector}': {source}")]
    InvalidAllowlistPattern {
        detector: String,
        source: regex::Error,
    },
    #[error("invalid severity in detector '{detector}': {source}")]
    InvalidSeverity {
        detector: String,
        source: ParseSeverityError,
    },
    #[error("invalid validator in detector '{detector}': {source}")]
    InvalidValidator {
        detector: String,
        source: ParseValidatorError,
    },
}

/// Extra structural check a detector can require of its matches, for
/// patterns whose shape alone is too permissive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentValidator {
    /// Payment card numbers carry a Luhn check digit. Without it, a 13-16
    /// digit pattern matches every commit hash fragment, timestamp and
    /// numeric id in a codebase.
    Luhn,
    /// Aadhaar numbers carry a Verhoeff check digit. Without it, every
    /// 12-digit run (the tail of a UUID, a numeric id) reports HIGH.
    Verhoeff,
}

impl FromStr for ContentValidator {
    type Err = ParseValidatorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().as_str() {
            "luhn" => Ok(Self::Luhn),
            "verhoeff" => Ok(Self::Verhoeff),
            other => Err(ParseValidatorError {
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Error)]
#[error("unknown validator '{value}'")]
pub struct ParseValidatorError {
    value: String,
}

/// Verhoeff check tables (the dihedral group D5 permutation). Aadhaar
/// numbers are the common real-world user.
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff checksum, ignoring embedded separators. Only the check digit
/// satisfies the scheme, so random 12-digit runs are rejected ~90% of the
/// time — and a run embedded in a longer id almost always fails outright.
fn passes_verhoeff(matched: &str) -> bool {
    let digits: Vec<u8> = matched
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    if digits.is_empty() {
        return false;
    }
    let mut check = 0u8;
    for (index, digit) in digits.iter().rev().enumerate() {
        check = VERHOEFF_D[check as usize][VERHOEFF_P[index % 8][*digit as usize]];
    }
    check == 0
}

#[cfg(test)]
mod verhoeff_tests {
    use super::passes_verhoeff;
    use crate::detector::ContentValidator;
    use std::str::FromStr;

    #[test]
    fn verhoeff_accepts_the_canonical_examples() {
        // Wikipedia: 2363 passes, 2362 does not; the check digit for 236 is 3.
        assert!(passes_verhoeff("2363"));
        assert!(!passes_verhoeff("2362"));
        assert_eq!(
            ContentValidator::from_str("verhoeff").unwrap(),
            ContentValidator::Verhoeff
        );
    }

    #[test]
    fn verhoeff_rejects_embedded_id_runs() {
        // The false positive this validator exists for: the tail of a UUID.
        assert!(!passes_verhoeff("123456789012"));
        assert!(!passes_verhoeff("446655440000"));
        assert!(passes_verhoeff("100000000004"));
    }

    #[test]
    fn verhoeff_handles_separators_and_partial_digits() {
        // Separators are ignored: a real-world spelled number passes.
        assert!(passes_verhoeff("2341 2341 2346"));
        assert!(passes_verhoeff("2341-2341-2346"));
        // Non-digit characters are filtered, so the digit suffix decides.
        assert!(passes_verhoeff("id: 2363!"));
        assert!(!passes_verhoeff("id: 2362!"));
    }

    #[test]
    fn verhoeff_rejects_degenerate_inputs() {
        assert!(!passes_verhoeff(""));
        assert!(!passes_verhoeff("no digits here"));
        // The p-permutation breaks the all-zeros identity chain, so the
        // classic dummy number does NOT validate: good for a secret scanner.
        assert!(!passes_verhoeff("000000000000"));
        // Single digit: 0 is its own inverse, so "0" validates.
        assert!(passes_verhoeff("0"));
        assert!(!passes_verhoeff("1"));
    }
}

/// Luhn checksum, ignoring embedded separators.
fn passes_luhn(matched: &str) -> bool {
    let digits: Vec<u32> = matched.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| match index % 2 {
            1 if *digit > 4 => digit * 2 - 9,
            1 => digit * 2,
            _ => *digit,
        })
        .sum();
    sum % 10 == 0
}

pub struct Detector {
    pub name: String,
    pub regex: Regex,
    pub finding_type: String,
    pub severity: Severity,
    pub allowlist: Vec<Regex>,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
    pub validator: Option<ContentValidator>,
}

impl Detector {
    pub fn new(
        name: &str,
        pattern: &str,
        finding_type: &str,
        severity: &str,
        allowlist: &[String],
        keywords: &[String],
        entropy_threshold: Option<f64>,
    ) -> Result<Detector, DetectorError> {
        let regex = Regex::new(pattern).map_err(|source| DetectorError::InvalidPattern {
            detector: name.to_string(),
            source,
        })?;

        let parsed_severity =
            Severity::from_str(severity).map_err(|source| DetectorError::InvalidSeverity {
                detector: name.to_string(),
                source,
            })?;

        let mut compiled_allowlist = Vec::new();
        for pattern in allowlist {
            let compiled =
                Regex::new(pattern).map_err(|source| DetectorError::InvalidAllowlistPattern {
                    detector: name.to_string(),
                    source,
                })?;
            compiled_allowlist.push(compiled);
        }

        Ok(Detector {
            name: name.to_string(),
            regex,
            finding_type: finding_type.to_string(),
            severity: parsed_severity,
            allowlist: compiled_allowlist,
            keywords: keywords
                .iter()
                .map(|keyword| keyword.to_lowercase())
                .collect(),
            entropy_threshold,
            validator: None,
        })
    }

    /// Attaches a structural validator. Kept separate from `new` so adding a
    /// check does not touch every construction site.
    pub fn with_validator(mut self, validator: Option<ContentValidator>) -> Self {
        self.validator = validator;
        self
    }

    /// Whether a match satisfies the detector's structural validator.
    pub fn passes_validation(&self, matched: &str) -> bool {
        match self.validator {
            Some(ContentValidator::Luhn) => passes_luhn(matched),
            Some(ContentValidator::Verhoeff) => passes_verhoeff(matched),
            None => true,
        }
    }

    /// `lowercase_content` must already be lowercased. Keywords are stored
    /// lowercased at construction so callers can lowercase once per line
    /// instead of once per detector.
    pub fn has_keywords(&self, lowercase_content: &str) -> bool {
        if self.keywords.is_empty() {
            return true;
        }
        self.keywords
            .iter()
            .any(|keyword| lowercase_content.contains(keyword.as_str()))
    }

    /// Whether a regex match clears every detector gate — allowlist, entropy
    /// and the structural validator. The scanner loops and the tests share
    /// this so the accept chain exists in exactly one place.
    pub fn accepts_match(&self, matched: &str) -> bool {
        self.accepts_parts(matched, matched)
    }

    /// Captures-aware accept gate for a pattern with capture groups: the
    /// allowlist encodes key-name context and always sees the whole match,
    /// while entropy and the validator see the captured value. The value is
    /// the last group that participated, which is group 1 for the common
    /// single-group value pattern; a keyword alternation may add an earlier
    /// group, and a key name such as `api_key` must not supply the entropy
    /// its value lacks. Without a participating group, both checks fall back
    /// to the whole match.
    pub fn accepts_captures(&self, captures: &Captures<'_>) -> bool {
        let Some(matched) = captures.get(0) else {
            return false;
        };
        match (1..captures.len())
            .rev()
            .find_map(|index| captures.get(index))
        {
            Some(value) => self.accepts_parts(matched.as_str(), value.as_str()),
            None => self.accepts_match(matched.as_str()),
        }
    }

    fn accepts_parts(&self, matched: &str, value: &str) -> bool {
        !self
            .allowlist
            .iter()
            .any(|pattern| pattern.is_match(matched))
            && self.has_sufficient_entropy(value)
            && self.passes_validation(value)
    }

    /// Whether the pattern carries the dot-matches-newline flag anywhere —
    /// `(?s)`, a combined group like `(?is)`, or the scoped `(?s:...)` form —
    /// and must therefore run per chunk instead of per line, or multiline
    /// secrets slip past it. Single source for the production partition and
    /// the tests.
    pub fn is_multiline(&self) -> bool {
        let pattern = self.regex.as_str();
        let bytes = pattern.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if bytes[i] == b'(' && bytes[i + 1] == b'?' && (i == 0 || bytes[i - 1] != b'\\') {
                // A flag group: scan its flag characters up to the closing
                // paren or the group separator.
                let mut j = i + 2;
                let mut saw_s = false;
                while j < bytes.len() && bytes[j] != b')' && bytes[j] != b':' {
                    if bytes[j] == b's' {
                        saw_s = true;
                    }
                    j += 1;
                }
                if saw_s {
                    return true;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        false
    }

    pub fn has_sufficient_entropy(&self, matched: &str) -> bool {
        match self.entropy_threshold {
            Some(threshold) => shannon_entropy(matched) >= threshold,
            None => true,
        }
    }
}

fn shannon_entropy(input: &str) -> f64 {
    // Byte-histogram in a fixed array: no allocation per candidate match,
    // and for the ASCII secret shapes the thresholds target, identical to a
    // char-based count.
    let mut counts = [0u32; 256];
    let mut length = 0usize;
    for byte in input.bytes() {
        counts[byte as usize] += 1;
        length += 1;
    }
    if length == 0 {
        return 0.0;
    }
    let input_length = length as f64;
    counts.iter().fold(0.0, |entropy, &count| {
        if count == 0 {
            return entropy;
        }
        let probability = count as f64 / input_length;
        entropy - probability * probability.log2()
    })
}

#[derive(Deserialize)]
struct DetectorsConfig {
    detectors: Vec<DetectorConfig>,
}

#[derive(Deserialize)]
struct DetectorConfig {
    name: String,
    pattern: String,
    finding_type: String,
    severity: String,
    allowlist: Option<Vec<String>>,
    keywords: Option<Vec<String>>,
    entropy: Option<f64>,
    validate: Option<String>,
}

/// True when `path` sits inside `dir`, i.e. the scanned repository supplied
/// it rather than the operator.
fn is_within(path: &std::path::Path, dir: &std::path::Path) -> bool {
    match (fs::canonicalize(path), fs::canonicalize(dir)) {
        (Ok(path), Ok(dir)) => path.starts_with(dir),
        _ => false,
    }
}

/// Highest directory whose contents the scanned tree's owner controls: the
/// enclosing repository root when the target sits inside one, otherwise the
/// target directory itself. A repository that reaches `KEYWATCH_CONFIG_PATH`
/// through `.envrc`/direnv or a devcontainer can point it anywhere in this
/// subtree, so nothing inside it can be trusted in trusted mode.
pub(crate) fn untrusted_root(scan_path: &str, cwd: &std::path::Path) -> std::path::PathBuf {
    let path = std::path::Path::new(scan_path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let start = if absolute.is_dir() {
        absolute
    } else {
        absolute
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| cwd.to_path_buf())
    };

    for dir in start.ancestors().skip(1) {
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
    }
    start
}

fn find_detectors_config(
    include_repository_config: bool,
    untrusted_roots: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    std::env::var("KEYWATCH_CONFIG_PATH")
        .map(std::path::PathBuf::from)
        .ok()
        .filter(|path| path.exists())
        // KEYWATCH_CONFIG_PATH is an operator channel. A repository can reach
        // it through .envrc/direnv or a devcontainer, so in trusted mode a
        // a value pointing back into the tree being scanned — at or below any
        // untrusted root — is ignored.
        .filter(|path| {
            include_repository_config
                || untrusted_roots.is_empty()
                || !untrusted_roots.iter().any(|root| is_within(path, root))
        })
        .filter(|path| !crate::utils::is_world_writable(path))
        .or_else(|| {
            if !include_repository_config {
                return None;
            }

            let repository_config = std::path::PathBuf::from(DETECTORS_FILE_NAME);
            repository_config.exists().then_some(repository_config)
        })
        // Trusted mode uses the embedded detector set. A repository can
        // redirect HOME or XDG_CONFIG_HOME (.envrc, devcontainer) and drop a
        // detectors.toml into the redirected location, which would silently
        // disable the hook; the binary directory is skipped for the same
        // reason. KEYWATCH_CONFIG_PATH above remains the operator channel.
        .or_else(|| {
            if !include_repository_config {
                return None;
            }

            dirs::config_dir()
                .map(|config_directory| config_directory.join("keywatch").join(DETECTORS_FILE_NAME))
                .filter(|path| path.exists())
        })
        .or_else(|| {
            if !include_repository_config {
                return None;
            }

            std::env::current_exe()
                .ok()
                .and_then(|executable_path| {
                    executable_path
                        .parent()
                        .map(|directory| directory.join(DETECTORS_FILE_NAME))
                })
                .filter(|path| path.exists())
        })
}

pub fn initialize_detectors() -> Result<Vec<Detector>, DetectorInitError> {
    initialize_detectors_from_config(true, &[])
}

pub(crate) fn initialize_trusted_detectors(
    untrusted_roots: &[std::path::PathBuf],
) -> Result<Vec<Detector>, DetectorInitError> {
    initialize_detectors_from_config(false, untrusted_roots)
}

fn initialize_detectors_from_config(
    include_repository_config: bool,
    untrusted_roots: &[std::path::PathBuf],
) -> Result<Vec<Detector>, DetectorInitError> {
    let toml_contents = match find_detectors_config(include_repository_config, untrusted_roots) {
        Some(config_path) => Cow::Owned(fs::read_to_string(&config_path).map_err(|source| {
            DetectorInitError::ReadConfig {
                path: config_path,
                source,
            }
        })?),
        None => Cow::Borrowed(EMBEDDED_DETECTORS_CONFIG),
    };

    let config: DetectorsConfig = toml::from_str(&toml_contents)
        .map_err(|source| DetectorInitError::ParseConfig { source })?;

    let mut seen_names = std::collections::HashSet::new();
    for detector_config in &config.detectors {
        if !seen_names.insert(detector_config.name.as_str()) {
            return Err(DetectorInitError::DuplicateName {
                detector: detector_config.name.clone(),
            });
        }
    }

    config
        .detectors
        .into_iter()
        .map(|detector_config| {
            let allowlist = detector_config.allowlist.as_deref().unwrap_or_default();
            let keywords = detector_config.keywords.as_deref().unwrap_or_default();
            let validator = detector_config
                .validate
                .as_deref()
                .map(ContentValidator::from_str)
                .transpose()
                .map_err(|source| DetectorError::InvalidValidator {
                    detector: detector_config.name.clone(),
                    source,
                })?;
            Detector::new(
                &detector_config.name,
                &detector_config.pattern,
                &detector_config.finding_type,
                &detector_config.severity,
                allowlist,
                keywords,
                detector_config.entropy,
            )
            .map(|detector| detector.with_validator(validator))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| DetectorInitError::InvalidDetector { source })
}

#[cfg(test)]
mod accept_unit_tests {
    use super::{Detector, passes_luhn, shannon_entropy};

    fn detector(pattern: &str, keywords: &[&str]) -> Detector {
        let keywords: Vec<String> = keywords.iter().map(|k| k.to_string()).collect();
        Detector::new("T", pattern, "T", "LOW", &[], &keywords, None).expect("valid detector")
    }

    #[test]
    fn luhn_accepts_known_cards_and_separators() {
        assert!(passes_luhn("4111111111111111"));
        assert!(passes_luhn("4111-1111-1111-1111"));
        assert!(passes_luhn("4111 1111 1111 1111"));
        assert!(!passes_luhn("4111111111111112"));
        assert!(!passes_luhn(""));
        assert!(!passes_luhn("no digits"));
        // Below the 13-digit floor.
        assert!(!passes_luhn("41111111111"));
    }

    #[test]
    fn shannon_entropy_matches_information_theory() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
        assert!((shannon_entropy("abab") - 1.0).abs() < 1e-9);
        // 64-char hex: near but under the 4.0 ceiling.
        let hex = "8b0e7153bf7c3706d85c524e440066559a6656c90bd5482a90a29b9fa5ff5180";
        let entropy = shannon_entropy(hex);
        assert!(entropy > 3.5 && entropy < 4.0, "hex entropy was {entropy}");
        // Multi-byte UTF-8 counts bytes.
        assert!(shannon_entropy("\u{1F600}") > 0.0);
    }

    #[test]
    fn is_multiline_matches_only_the_dotall_flag() {
        assert!(detector(r"(?s)BEGIN.*END", &[]).is_multiline());
        assert!(detector(r"(?s:BEGIN.*END)", &[]).is_multiline());
        assert!(detector(r"(?is)BEGIN.*END", &[]).is_multiline());
        assert!(!detector(r"SECRET_\w+", &[]).is_multiline());
        assert!(!detector(r"(?i)secret", &[]).is_multiline());
    }

    #[test]
    fn keywords_are_lowercased_for_the_prefilter() {
        // Contract: callers lowercase content once per line; stored keywords
        // are lowercased at construction.
        let detector = detector(r"SECRET_\w+", &["ApiKey", "SECRET"]);
        assert!(detector.has_keywords("set the apikey value"));
        assert!(detector.has_keywords(&"THE SECRET VALUE".to_lowercase()));
        assert!(!detector.has_keywords("nothing relevant"));
    }
}
