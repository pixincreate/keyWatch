use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CliValidationError {
    #[error("Cannot specify both --git-history and --stdin")]
    GitHistoryWithStdin,
    #[error("Cannot specify more than one path with --git-history")]
    GitHistoryWithMultiplePaths,
    #[error("Cannot specify both --staged and --stdin")]
    StagedWithStdin,
    #[error("Cannot specify both --staged and --git-history")]
    StagedWithGitHistory,
    #[error("Cannot specify both --stdin and paths")]
    StdinWithPaths,
    #[error("Must specify paths, use --stdin, --staged, or --git-history")]
    MissingScanInput,
    #[error("--allowed-repos and --blocked-repos are only supported for pre-push hooks")]
    PreCommitRepositoryFilters,
    #[error("--exclude is only supported for pre-commit hooks")]
    PrePushExclude,
}

/// KeyWatch: A secret scanner for your files and directories.
#[derive(Parser, Debug)]
#[command(author, version, about = "Scan files and directories for secrets", long_about = None)]
pub struct CliOptions {
    #[command(subcommand)]
    pub command: Command,
}

impl CliOptions {
    pub fn validate(&self) -> Result<(), CliValidationError> {
        match &self.command {
            Command::Scan(args) => args.validate(),
            Command::Hook(args) => args.validate(),
            _ => Ok(()),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan files or directories
    Scan(ScanArgs),

    /// Manage KeyWatch git hooks
    Hook(HookArgs),

    /// Print shell aliases for keywatch and kw
    Init {
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Verify binary integrity
    VerifyIntegrity,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ScanArgs {
    /// Paths to scan (files or directories)
    pub paths: Vec<String>,

    /// Read input from stdin instead of files
    #[arg(long, default_value_t = false)]
    pub stdin: bool,

    /// Scan git history instead of files
    #[arg(long, default_value_t = false)]
    pub git_history: bool,

    /// Scan only the lines staged for commit (paths narrow the staged diff)
    #[arg(long, default_value_t = false)]
    pub staged: bool,

    /// Output the result to a file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Print the scan results to the console
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Include raw matched text in reports (default: redacted)
    #[arg(long, default_value_t = false)]
    pub show_secrets: bool,

    /// Paths to exclude from scanning (comma-separated, supports glob patterns)
    #[arg(long)]
    pub exclude: Option<String>,

    /// Exit code behavior
    #[arg(long, value_enum, default_value_t = ExitMode::Strict)]
    pub exit_mode: ExitMode,

    /// Path to a baseline file for suppressing known findings
    /// (defaults to a discovered .keywatch-baseline.json)
    #[arg(long)]
    pub baseline: Option<String>,

    /// Disable automatic baseline discovery (an explicit --baseline still loads)
    #[arg(long, default_value_t = false)]
    pub no_baseline_discovery: bool,

    /// Update the baseline file with current findings instead of scanning
    #[arg(long)]
    pub update_baseline: bool,

    /// Rewrite the baseline from the current findings, dropping stale entries
    /// (requires --update-baseline; whole-tree scans only)
    #[arg(
        long,
        requires = "update_baseline",
        conflicts_with_all = ["staged", "stdin", "git_history"]
    )]
    pub prune_baseline: bool,

    /// Path to .keywatch.toml config file
    #[arg(long)]
    pub config: Option<String>,

    /// Disable automatic config discovery (an explicit --config still loads)
    #[arg(long, default_value_t = false)]
    pub no_config_discovery: bool,
    /// Exit 1 when any scanned file could not be read (Strict exit mode only)
    #[arg(long, default_value_t = false)]
    pub fail_on_unscannable: bool,
    /// Output format for the report (json or sarif)
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

impl ScanArgs {
    pub fn validate(&self) -> Result<(), CliValidationError> {
        match (self.git_history, self.staged, self.stdin) {
            (true, true, _) => Err(CliValidationError::StagedWithGitHistory),
            (true, _, true) => Err(CliValidationError::GitHistoryWithStdin),
            (true, false, false) if self.paths.len() > 1 => {
                Err(CliValidationError::GitHistoryWithMultiplePaths)
            }
            (false, true, true) => Err(CliValidationError::StagedWithStdin),
            (false, false, true) if !self.paths.is_empty() => {
                Err(CliValidationError::StdinWithPaths)
            }
            (false, false, false) if self.paths.is_empty() => {
                Err(CliValidationError::MissingScanInput)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Args, Debug)]
pub struct HookArgs {
    #[command(subcommand)]
    pub action: HookAction,
}

impl HookArgs {
    fn validate(&self) -> Result<(), CliValidationError> {
        match &self.action {
            HookAction::Install(args) => args.validate(),
            HookAction::Uninstall(_) => Ok(()),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum HookAction {
    /// Install a KeyWatch git hook
    Install(HookInstallArgs),

    /// Remove a KeyWatch git hook
    Uninstall(HookUninstallArgs),
}

#[derive(Args, Debug)]
pub struct HookInstallArgs {
    /// Type of hook to install
    #[arg(value_enum)]
    pub hook_type: HookType,

    /// Install the hook globally using git core.hooksPath
    #[arg(long, default_value_t = false)]
    pub global: bool,

    /// Allowed repository URLs (comma-separated) - pre-push only
    #[arg(long)]
    pub allowed_repos: Option<String>,

    /// Blocked repository URLs (comma-separated) - pre-push only
    #[arg(long)]
    pub blocked_repos: Option<String>,

    /// Paths to exclude from scanning - pre-commit only
    #[arg(long)]
    pub exclude: Option<String>,
}

impl HookInstallArgs {
    fn validate(&self) -> Result<(), CliValidationError> {
        match self.hook_type {
            HookType::PreCommit => {
                if self.allowed_repos.is_some() || self.blocked_repos.is_some() {
                    return Err(CliValidationError::PreCommitRepositoryFilters);
                }
            }
            HookType::PrePush => {
                if self.exclude.is_some() {
                    return Err(CliValidationError::PrePushExclude);
                }
            }
        }

        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct HookUninstallArgs {
    /// Type of hook to remove
    #[arg(value_enum)]
    pub hook_type: HookType,

    /// Remove the hook globally from git core.hooksPath
    #[arg(long, default_value_t = false)]
    pub global: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum HookType {
    PreCommit,
    PrePush,
}

impl HookType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreCommit => "pre-commit",
            Self::PrePush => "pre-push",
        }
    }
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Posix,
}

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum ExitMode {
    /// Never fails: findings are reported but the exit code stays 0.
    Always,
    Critical,
    #[default]
    Strict,
}

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Json,
    Sarif,
}
