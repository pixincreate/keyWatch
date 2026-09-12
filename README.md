# KeyWatch

A fast secret scanner for files and directories.

## Install

### Recommended: cargo install

```sh
cargo install key-watch
key-watch --version

# Enable aliases for your current shell session
eval "$(key-watch init bash)"
```

To make aliases persistent, add the init line to your shell config file:

```sh
# bash
echo 'eval "$(key-watch init bash)"' >> ~/.bashrc

# zsh
echo 'eval "$(key-watch init zsh)"' >> ~/.zshrc
```

### Manual install from GitHub Releases

1. Download the correct binary for your OS/architecture from GitHub Releases.
2. Move it to a directory on your `PATH`, for example `~/.local/bin`.
3. Make it executable.
4. Verify it runs.
5. Enable aliases with `init`.

```sh
mkdir -p ~/.local/bin
mv ~/Downloads/key-watch ~/.local/bin/key-watch
chmod +x ~/.local/bin/key-watch
~/.local/bin/key-watch --version

# Enable aliases for current shell session
eval "$(~/.local/bin/key-watch init bash)"
```

Requires Rust 1.85+ (edition 2024) when building from source.

The canonical command is `key-watch`.
`keywatch` and `kw` are optional shell aliases exposed via `key-watch init ...`.

## GitHub Action

Use the root Action from a public workflow. The major tag follows compatible `2.x` releases; pin an exact release tag or commit SHA when immutable dependencies are required.

```yaml
name: Secret scan

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  keywatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: keywatch
        uses: pixincreate/KeyWatch@v2
        with:
          paths: "."
          exit-mode: strict
```

The Action installs the synchronized KeyWatch release, verifies SHA-256 checksums for the binary and `detectors.toml`, disables repository detector discovery, and writes a JSON report. It supports Linux x64 and macOS x64/arm64 runners; Windows runners are not supported.

| Input       | Default                | Purpose                                                                  |
| ----------- | ---------------------- | ------------------------------------------------------------------------ |
| `version`   | Action release version | Exact KeyWatch release to install                                        |
| `paths`     | `.`                    | Space-separated paths or globs to scan                                   |
| `args`      | empty                  | Additional scanner arguments that do not override Action-managed options |
| `exit-mode` | `strict`               | `strict`, `critical`, or `always`                                        |
| `output`    | temporary report       | JSON report path                                                         |
| `config`    | empty                  | Explicit trusted `.keywatch.toml` path                                   |
| `verbose`   | `false`                | Deprecated; enabling it is rejected to prevent secret disclosure in logs |

The `findings-count` and `exit-code` outputs are available as `${{ steps.keywatch.outputs['findings-count'] }}` and `${{ steps.keywatch.outputs['exit-code'] }}`.

## Container Image

The GitHub Container Registry image is a separate distribution channel for Linux x64 environments:

```sh
docker pull ghcr.io/pixincreate/keywatch:2
docker run --rm \
  --volume "$PWD:/workspace:ro" \
  --workdir /workspace \
  ghcr.io/pixincreate/keywatch:2 scan .
```

Images are published as `x.y.z`, `x.y`, `x`, and `latest`, with build provenance attached. Exact semver tags are the reproducible choice. After the first publication, a repository owner must make the GHCR package public in the package settings to allow anonymous pulls; no separate GHCR account is required. The image runs as a non-root user and uses the image-owned detector configuration at `/etc/keywatch/detectors.toml`.

## Uninstall

### If installed with `cargo install`

```sh
cargo uninstall key-watch
```

If you added aliases to your shell config, remove the init line you added earlier, for example:

```sh
# bash
sed -i.bak '/key-watch init bash/d' ~/.bashrc

# zsh
sed -i.bak '/key-watch init zsh/d' ~/.zshrc
```

### If installed manually from GitHub Releases

1. Remove the `key-watch` binary from your `PATH` directory.
2. Remove any shell init line you added for aliases.
3. Restart your shell or reload your shell config.

```sh
rm -f ~/.local/bin/key-watch

# If you added aliases for the current shell config, remove that line manually
# then reload your shell config, for example:
source ~/.bashrc
```

## Usage

```sh
# Scan a file
key-watch scan secrets.txt

# Scan a directory
key-watch scan .

# Scan from stdin
cat secrets.txt | key-watch scan --stdin

# Scan git history for committed secrets
key-watch scan --git-history

# Scan only the lines staged for commit
key-watch scan --staged

# Verbose output (JSON)
key-watch scan secrets.txt --verbose

# Install git hook
key-watch hook install pre-commit
key-watch hook install pre-push

# Remove git hook
key-watch hook uninstall pre-commit
key-watch hook uninstall pre-push

# Install git hook globally via core.hooksPath
key-watch hook install pre-commit --global
key-watch hook install pre-push --global

# Remove global hook
key-watch hook uninstall pre-commit --global
key-watch hook uninstall pre-push --global

# Print shell aliases
eval "$(key-watch init bash)"

# Verify binary integrity
key-watch verify-integrity
```

## Options

- `scan <path>...` - Scan one or more files or directories
- `scan --config <path>` - Load configuration from an explicit `.keywatch.toml` path
- `scan --no-config-discovery` - Ignore discovered repository config unless `--config` is explicit
- `scan --format <json|sarif>` - Choose the report format written to stdout or the output file
- `scan --stdin` - Read content from stdin instead of files
- `scan --git-history` - Scan git history (`git log -p`) for committed secrets; findings carry real file paths, and `--exclude` and baselines apply
- `scan --staged [path...]` - Scan only the added lines of the staged diff (run from inside the repository; paths narrow the diff as git pathspecs); findings keep real file paths and line numbers, so `--baseline` and `--exclude` compose. Files git renders as binary (e.g. `-diff` in `.gitattributes`) are read from the index in staged scans and reported under `unscannable` when they cannot be read at all. Note: a multi-line secret added across separate commits can span hunks the diff scan never sees together — the pre-push whole-tree scan remains the backstop for that case
- `scan --fail-on-unscannable` - Treat files that could not be read (git-rendered binaries, permission errors) as a failure in `strict` mode; the installed pre-commit hook passes this flag so an unscannable staged file fails the commit instead of passing silently
- `scan --output <path>` - Save report to file
- `scan --verbose` - Print full JSON output (matched text is redacted; see `--show-secrets`)
- `scan --show-secrets` - Include raw matched text in reports. Off by default: reports are routinely written to files or uploaded as CI artifacts, and `--output` files are created with owner-only permissions
- `scan --exclude <patterns>` - Comma-separated glob patterns to exclude; lockfiles (`Cargo.lock`, `package-lock.json`, `yarn.lock`, `go.sum`, and other generated manifests) are always excluded by basename
- `scan --exit-mode <mode>` - Exit behavior: `always` (always pass), `critical` (fail on HIGH/CRITICAL only), `strict` (fail on any finding, default)
- `scan --baseline <path>` - Suppress known findings from a previous scan. Without this flag, a `.keywatch-baseline.json` is discovered automatically by walking up from the scan target (bounded at the repository root or home directory), so hook scans pick up a committed repo baseline with no configuration
- `scan --no-baseline-discovery` - Ignore a discovered baseline (an explicit `--baseline` still loads)
- `scan --prune-baseline` - With `--update-baseline`, rebuild the baseline from current findings instead of merging, dropping stale entries; requires a whole-tree scan (`--staged`, `--stdin` and `--git-history` are refused, narrowed paths draw a warning), and the dropped count is always printed
- `scan --update-baseline` - Update the baseline with current findings; creates `.keywatch-baseline.json` when no baseline exists. The baseline stores fingerprints (path + finding type + SHA-256 of the match + detector), never secrets, and is meant to be committed. The `update-baseline` workflow can regenerate it via a reviewable pull request
- `hook install <pre-commit|pre-push> [--global]` - Install a git hook
- `hook uninstall <pre-commit|pre-push> [--global]` - Remove a git hook
- `hook install pre-push --allowed-repos <urls>` - Whitelist repos for pre-push hooks
- `hook install pre-push --blocked-repos <urls>` - Block repos for pre-push hooks
- `hook install pre-commit --exclude <patterns>` - Exclude patterns for pre-commit scans
- `init <shell>` - Print shell aliases for `keywatch` and `kw`
- `verify-integrity` - Check the running binary's file permissions (fails when it is world-writable on unix); this is a permission check, not a cryptographic checksum

## Aliases

- `key-watch` is the only shipped binary.
- `keywatch` and `kw` are optional aliases.
- `key-watch init bash|zsh|fish|posix` prints shell aliases you can eval in your shell.
- `watch` is intentionally not used, to avoid colliding with the standard Unix `watch` command.

## Baseline

Use baselines to suppress known findings on subsequent scans:

```sh
# First scan: create a baseline
key-watch scan . --baseline .keywatch.baseline --update-baseline

# Future scans: only report NEW findings
key-watch scan . --baseline .keywatch.baseline
```

## Inline Suppression

Add `keywatch:ignore` to suppress a finding on a specific line:

```sh
password = 'known-test-password' # keywatch:ignore
```

## Exit Codes

| Code | Meaning                                         |
| ---- | ----------------------------------------------- |
| 0    | No secrets found (or `scan --exit-mode always`) |
| 1    | Secret found (strict/critical mode), or an unscannable file with `scan --fail-on-unscannable` |
| 2    | Runtime/configuration error                     |

## Default Behavior

- **Repos**: All allowed (no restrictions)
- **Exit mode**: strict (fail on any finding)

## Git Hooks

- `hook install pre-commit|pre-push` installs a repo-local hook into `.git/hooks/`
- `hook uninstall pre-commit|pre-push` removes a KeyWatch hook from the same target
- `hook install ... --global` installs into Git's global hooks directory
- `hook uninstall ... --global` removes the hook from Git's global hooks directory
- Pre-commit hooks run `key-watch scan --staged`, so only the lines a commit adds are scanned and findings on unchanged lines never block a commit
- Pre-commit `--exclude` patterns are forwarded to `scan --staged --exclude` and matched against staged file paths
- Local hook paths are resolved via `git rev-parse --git-path hooks`, so installs work in worktrees and submodules too
- If `core.hooksPath` is already configured, KeyWatch installs into that directory
- Otherwise KeyWatch creates a managed hooks directory and configures `git config --global core.hooksPath`
- KeyWatch refuses to overwrite a non-KeyWatch global hook file
- KeyWatch also refuses to remove a non-KeyWatch global hook file
- A global `core.hooksPath` makes Git ignore every repository's own `.git/hooks/` scripts (husky, lefthook, plain hook files). To restore a repository's local hooks, run `git config core.hooksPath .git/hooks` inside it — the repo-local setting overrides the global one, and the KeyWatch hook then no longer runs in that repository

## Architecture

KeyWatch is a single Rust CLI organized as a modular monolith. `main.rs` owns startup and maps validation, configuration, or runtime failures to exit code `2`. `run_cli()` validates and routes commands, while the scan coordinator currently terminates successful scan execution with code `0` or `1`. Focused modules own detector loading, repository policy, scanning, baselines, reports, hooks, and filesystem or process adapters.

### CLI Modules and Adapters

![KeyWatch CLI module and adapter architecture](docs/architecture/cli-modules.svg)

The green boxes are internal modules, blue boxes mark entry or output boundaries, and yellow boxes are external runtime or distribution adapters. Rust hook management renders and installs scripts; the shell templates are separate runtime adapters that invoke `key-watch scan`.

### Scan Pipeline

![KeyWatch scan pipeline](docs/architecture/scan-pipeline.svg)

Path scans collect and process files in parallel, while stdin and git history use overlapping stream chunks. Baseline updates short-circuit normal report generation. Scan results exit with code `0` or `1`; validation, configuration, and runtime failures are mapped to code `2` at the process boundary.

### Detector and Configuration Trust Boundaries

![KeyWatch detector and configuration trust boundaries](docs/architecture/detector-config-trust.svg)

Detector definitions and repository policy are separate configuration systems. External detector sources retain precedence, with compiled-in rules as the final fallback. Trusted scans skip repository-owned discovery but still honor explicit configuration and non-repository detector sources.

### Core Data Types

- **Detector** — a named rule: regex, finding type, severity, optional keywords for pre-filtering, an entropy threshold, and an allowlist.
- **Finding** — one detected secret: file path, line number, finding type, severity, matched content, and the detector that produced it.
- **Severity** — `Critical`, `High`, `Medium`, `Low`.
- **KeywatchConfig** — parsed `.keywatch.toml`: custom rules, per-detector overrides, and exclude patterns.
- **Baseline** — versioned collection of fingerprint entries; filters out already-known findings.
- **ScanMetadata** — files scanned, total lines, and excluded files, reported alongside findings.

The canonical diagram sources are in `docs/architecture/*.d2`. Run `scripts/render-diagrams.sh render` with D2 v0.7.1 after editing them, or `scripts/render-diagrams.sh check` to detect stale SVGs.

## Development

```sh
cargo build --release
cargo test
cargo fmt
cargo clippy
```

# LICENSE - GPLv3

[LICENSE](LICENSE)
