use super::{DETECTORS_FILE_NAME, DetectorError};
use std::io;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DetectorInitError {
    #[error("Failed to read {}: {source}", path.display())]
    ReadConfig { path: PathBuf, source: io::Error },
    #[error("Failed to parse {}: {source}", DETECTORS_FILE_NAME)]
    ParseConfig { source: toml::de::Error },
    #[error("duplicate detector name '{detector}'")]
    DuplicateName { detector: String },
    #[error("{source}")]
    InvalidDetector { source: DetectorError },
}
