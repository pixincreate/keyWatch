# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `scan --staged` scans only the lines a commit adds
- Baselines are auto-discovered from `.keywatch-baseline.json`; `--no-baseline-discovery` opts out
- `update-baseline` workflow regenerates the baseline via a pull request
- `scan --fail-on-unscannable` fails a strict scan when a file could not be read; the pre-commit hook passes it so an unscannable staged file cannot pass silently

### Changed

- Pre-commit hooks scan the staged diff instead of whole files
- Config discovery searches parent directories up to the repository root
- Hook messages abbreviate the home directory as `~`

### Added

- CI scans this repository with KeyWatch and fails if the committed baseline has drifted
- `--prune-baseline` rewrites the baseline from current findings, dropping entries for deleted files and rotated credentials; requires `--update-baseline` and a whole-tree scan, and prints what it dropped

### Changed

- Reports redact matched text by default; `--show-secrets` opts into raw values, and matches shorter than 8 characters are always described by length only
- Reports summarise exclusions as a count plus a sample instead of listing every path, and report git-rendered binary files as `unscannable` rather than `excluded`
- Lockfiles (`Cargo.lock`, `package-lock.json`, `yarn.lock`, `go.sum`, and other generated manifests) are excluded from scans by default

### Fixed

- `scan --git-history` applies `--exclude`, skips the baseline file, and reports real file paths instead of a synthetic `<git-history>` key that no baseline could match
- `scan --staged` is not fooled by `diff.relative`, which made git drop changes outside the current directory
- `--output` files are readable only by their owner, including when the file already existed with wider permissions
- Config is not trusted from a world-writable directory or file, so a `.keywatch.toml` dropped in `/tmp` cannot weaken scans beneath it
- `KEYWATCH_CONFIG_PATH` is ignored in trusted mode whenever it points inside the tree being scanned, wherever the process runs from
- Baseline suppression reports how many findings it hid, instead of applying silently
- `CreditCardDetector` requires an issuer prefix and a valid Luhn checksum, instead of matching any 13-16 digit run; Discover's 644-649 and 65 ranges are covered
- `HighEntropyDetector` could never fire (its 4.0 threshold is the ceiling for hex) and now runs, restricted to lines naming a credential
- PKCS#8 private key headers (`BEGIN PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`) are detected
- `PhoneNumberDetector` needs punctuation or a country code, so unix timestamps are not phone numbers
- Detectors can require a structural check via `validate = "luhn"`
- Hooks use built-in detectors, so a `detectors.toml` committed to a scanned repository can no longer replace the detector set and disable its own scan
- Files git renders as binary (including text marked `-diff` in `.gitattributes`) are read from the index instead of being reported clean
- `Base64Detector` matches from 28 characters, the length where entropy can actually separate base64 from identifiers
- `scan --staged` no longer misses findings under `color.ui = always` or custom diff prefixes
- Non-UTF-8 files no longer abort a staged scan
- A malformed diff hunk header is reported instead of silently attributing its findings to line 0
- Diff paths that git quoted (names containing quotes or control characters) are unescaped before attribution
- The baseline file is no longer scanned as input to itself, including staged scans run from a subdirectory
- `GenericKeyValueDetector` and `RandomString` no longer flag code identifiers (`let payment_method_token = card_token`, snake_case serde attributes)
- `PasswordDetector` no longer flags `$PWD:`
- `GenericKeyValueDetector` no longer flags bare CamelCase type paths (`token: PaymentTokenData,`)
- `PasswordDetector` no longer flags Rust expressions (`password: Secret<String>`, `password: config.password.clone()`, `Some(Secret::new(...))`) as credentials
- A failed `git cat-file` during a staged scan reports itself instead of claiming `git diff` failed
- Custom rules in `.keywatch.toml` support `allowlist`, `keywords`, `entropy` and `validate`, matching built-in detector definitions
- Pre-push repository filters fail closed on Windows drive-path remotes instead of misparsing the drive letter as a host
- Chunked streaming scans no longer duplicate multiline matches that land inside the window overlap
- Files with invalid UTF-8 are decoded lossily and scanned instead of silently skipped; NUL-containing files are reported as `unscannable`
- `Finding`'s `plugin_name` field is now `detector_name` in the code; the JSON report and baseline schema still emit/accept `plugin_name`
- `CustomRule.description` was parsed but never surfaced and has been dropped (configs carrying it keep parsing)
- False-positive reductions in the built-in detectors: AWS's documentation example key, placeholder values (`changeme`, `your-api-key-here`, `replace-me-please`), RFC 2606 example-domain emails and noreply conventions, fictional 555 phone numbers, npm/shield checksum prefixes, and non-Verhoeff 12-digit runs no longer report as Aadhaar
- `--baseline` naming a missing file is an error instead of silently scanning with an empty baseline
- Baseline files with an unknown format version are rejected instead of silently accepted
- `--update-baseline` refreshes the recorded line numbers of entries it already knows, and saved baselines end with a newline
- SARIF report property order is deterministic
- Piping output to a closed reader no longer panics, including `hook install` and `init`; hook commands now report real output failures instead of discarding them
- Trusted scans (`--no-config-discovery`) no longer read detector configuration from environment-derived locations (`$XDG_CONFIG_HOME`, `$HOME`, the executable directory), so a redirected home directory cannot replace the built-in detector set
- Staged blobs are resolved to object IDs and read with `git cat-file blob <oid>` instead of `:<path>`, so a file whose name resembles a git stage path (`0:config`) can no longer substitute another file's content
- `scan --git-history` reads merge commits (`--diff-merges=first-parent`), so a secret introduced while resolving a conflict is reported
- Files that fail to open or read are counted as `unscannable` instead of being silently skipped
- Ten detectors that matched the wrong shape or nothing at all (`SupabaseServiceRoleKey`, `TerraformCloudToken`, `AzureStorageKey`, `DockerHubToken`, `CircleCIToken`, `DiscordToken`, `NetlifyToken`, `CodecovToken`, `AdyenAPIKey`, `RazorpayKey`) now follow the documented token format, each pinned by a real-format fixture test; the two that matched only non-secrets were removed
- `Email`, `PhoneNumber`, `IPAddress`, `TwilioAPIKey` and `MailgunAPIKey` no longer suppress or match unintended text: the example-domain allowlist is anchored, only the reserved `555-01xx` numbers are ignored, every IPv4 octet is validated, and embedded vendor prefixes require word boundaries
- Entropy and validators run on the captured value rather than the whole match, so `api_key = "aaaaaaaaaa"` is no longer reported; `GCPServiceAccountKey` requires a `private_key` field and `MasterAPIKey`, `AzureDevOpsPAT`, `KimiMoonshotAPIKey` and `CertificateDetector` severities now reflect credential impact

### Performance

- Keyword matching uses a single Aho-Corasick pass per line: ~3x faster file scans, ~9x faster streams
- File scans stream line by line instead of reading whole files into memory
- ~2.5x faster file scans: one combined prefilter pass for the keywordless detectors, an ASCII fast path for line lowering, and a byte-histogram entropy check that no longer allocates per match

## [2.0.1] - 2026-08-02

### Fixed

- GitHub Release asset publishing no longer fails when Action validation generates Python bytecode caches

## [2.0.0] - 2026-08-02

### Breaking Changes

- Public Rust APIs now return module-local typed errors instead of `String` or boxed errors. This affects CLI validation, baseline, configuration, detector initialization, scanner, hook, and `run_cli()` return types and requires a major-version release.

### Added

- **CRITICAL severity support** — findings can now be scored as Critical, High, Medium, or Low
- **Baseline suppression** — `scan --baseline <path>` suppresses known findings from previous scans; `--update-baseline` writes current findings to the baseline file
- **Inline suppression** — add `# keywatch:ignore` or `// keywatch:ignore` on a line to suppress findings
- **Per-detector allowlist** — each detector in `detectors.toml` can define `allowlist` regex patterns to suppress false positives
- **Keyword prefilter** — each detector can define `keywords` for fast prefiltering before regex runs
- **Entropy threshold filtering** — each detector can define `entropy` threshold to reject low-entropy false positives
- **Parallel scanning** — file scanning parallelized with rayon for multi-core speedup
- **Stdin scanning** — `scan --stdin` reads content from stdin instead of files
- **Git history scanning** — `scan --git-history` scans `git log -p` output for committed secrets
- Cloud/monitoring/AI service detectors: Vercel, Netlify, Supabase, Datadog, New Relic, Sentry, PagerDuty, Anthropic, HuggingFace, Groq, Replicate, LangSmith
- **GitHub Action** — composite action (`action.yml`) for CI/CD integration
- **Docker support** — multi-stage Dockerfile with `--locked` flag, stripped binary, non-root user, and git installed for `--git-history` scanning and hook installation
- **Public distribution verification** — the root GitHub Action verifies release binary and detector checksums, while GHCR images publish semver, major, and latest tags with provenance
- `.dockerignore` for optimized Docker builds
- **Config file support** — `.keywatch.toml` with custom rules, detector overrides, and exclude patterns
- **SARIF 2.1.0 output** — `--format sarif` enables GitHub Code Scanning and SARIF viewer integration
- **`--config` CLI flag** — specify a custom path to `.keywatch.toml`
- **Pre-commit `language: system`** — generated hooks use `language: system` for faster execution

### Changed

- `get_severity_counts()` now returns a `SeverityCounts` struct with `critical`, `high`, `medium`, and `low` fields instead of a tuple
- `run_scan()` accepts optional `config` parameter for merging user configuration
- Simplified distribution to a single shipped binary: `key-watch`
- Git hook installation now supports first-class global hooks via `core.hooksPath`
- Installation guidance is now cargo-first, with manual GitHub Releases setup documented step by step
- CLI moved from flat top-level flags to subcommands: `scan`, `hook install|uninstall`, `init`, and `verify-integrity`
- Local hook installation now resolves Git's hooks directory directly, improving worktree and submodule compatibility
- `exit-mode critical` now fails on both HIGH and CRITICAL findings
- Detector descriptions and comments cleaned up for minimal noise
- Release preparation now synchronizes the Action version with Cargo metadata and runs CI before publishing tags
- CI now validates Action shell behavior, checksum failures, release automation, and container smoke behavior

### Fixed

- Cargo-installed and standalone binaries now fall back to embedded detector rules when no external `detectors.toml` is available
- CRITICAL severity was silently downgraded to LOW at runtime
- All clippy warnings resolved (`Default` impl, redundant closures, identity maps)
- Public API unit tests moved to `tests/` directory (only private API tests remain in `src/`)
- Baseline hash domain separator renamed from `SALT` to `DOMAIN_SEPARATOR` for clarity
- `Severity::from_string()` now trims whitespace from input before parsing
- `scan_stream()` chunk overlap fixed for accurate multiline detection on split chunks
- Graceful error handling when `git` is not installed on the system
- `action.yml` removed `eval "$CMD"` pattern for security
- `action.yml` removed hardcoded GitHub authentication header
- `.dockerignore` now preserves `Cargo.lock` for reproducible builds

### Removed

- Duplicate Cargo binary wrappers for `keywatch` and `watch`
- `scripts/install.sh` in favor of documented `cargo install` and manual release-binary setup
- ~1650 lines of redundant context-based detectors; kept only prefix-based detectors plus GenericKeyValueDetector

### Documentation

- README architecture documentation now uses three source-controlled D2 diagrams with generated SVGs for CLI modules and adapters, the scan pipeline, and detector/configuration trust boundaries

## [1.1.0] - 2026-05-05

### Added

- Binary aliases: `keywatch`, `watch` (in addition to `key-watch`)
- Exit code modes: `--exit-mode always|critical|strict`
- Binary integrity verification: `--verify-integrity`
- Repository controls: `--allowed-repos`, `--blocked-repos`
- Multiple file scanning: `--file file1.txt --file file2.txt`
- Indian ID detectors: Aadhaar, Voter ID (EPIC), PAN Card, ABHA Health ID

### Security

- Shell injection protection in generated hooks
- Non-UTF8 file handling (graceful skip)

### Changed

- Simplified README (~60 lines)
- User-friendly output by default (summary, not JSON)
- Default exit mode: strict
- Source builds now require Rust 1.85+ (edition 2024)

### Fixed

- Portable detector loading (exe-relative path)
- Filenames with spaces handling
- Hook repo allow/block rules are now enforced
- Exclude globs now work correctly for directory scans
- Runtime errors now use exit code `2` instead of `1`
- Hook subshell bug: exit now correctly blocks commits/pushes
- Hook detectors.toml check: removed hard CWD requirement (exe-relative works)
- Hook error messages now use correct binary name variable
- Duplicate file paths now deduplicated before scanning

### Removed

- Legacy `hooks/keywatch.sh`
- `.pre-commit-config.yaml`

## [1.0.0] - 2025-02-16

- Initial release
- File/directory scanning
- Verbose JSON output
- Pre-commit/pre-push hooks
