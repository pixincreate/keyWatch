use crate::baseline::BaselineError;
use crate::cli::CliValidationError;
use crate::config::ConfigError;
use crate::hooks::HookError;
use crate::scanner::ScannerError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RunCliError {
    #[error("{source}")]
    Cli {
        #[from]
        source: CliValidationError,
    },
    #[error("{source}")]
    Config {
        #[from]
        source: ConfigError,
    },
    #[error("{source}")]
    Scanner {
        #[from]
        source: ScannerError,
    },
    #[error("{source}")]
    Baseline {
        #[from]
        source: BaselineError,
    },
    #[error("{source}")]
    Hooks {
        #[from]
        source: HookError,
    },
    #[error(
        "--update-baseline could not resolve a baseline file: pass --baseline <path>, or run where .keywatch-baseline.json can be discovered or created"
    )]
    MissingBaselineForUpdate,
    #[error("Baseline file not found: '{path}' (pass --update-baseline to create it)")]
    BaselineNotFound { path: String },
    #[error(
        "Binary is world-writable: '{path}'; its permissions do not protect it from modification"
    )]
    WorldWritableBinary { path: String },
    #[error("Failed to serialize report: {source}")]
    ReportSerialize { source: serde_json::Error },
    #[error("Failed to write report to '{path}': {source}")]
    ReportWrite { path: String, source: io::Error },
    #[error("Failed to write output: {source}")]
    WriteOutput { source: io::Error },
    #[error("Failed to get executable path: {source}")]
    ExecutablePath { source: io::Error },
    #[error("Failed to get executable metadata: {source}")]
    ExecutableMetadata { source: io::Error },
}
