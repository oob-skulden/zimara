# Changelog

All notable changes to this project will be documented in this file.

This project follows a pragmatic versioning approach and documents
user-visible changes, security improvements, and behavioral changes.

---

## [0.49.5] - 2025-12-31

### Changed
- Improved execution model using `set -u` and `set -o pipefail` without `set -e`
- All 45 checks now complete execution regardless of individual check failures
- Enhanced reliability for comprehensive security scanning

### Fixed
- Execution flow now ensures complete scan coverage
- Improved error handling for edge cases in file detection

---

## [0.49.1] - 2025-12-30

### Added
- Bash 3.2+ compatibility for legacy system support
- Baseline bypass prevention in structured output modes

### Security
- Hardened JSON/SARIF output to prevent baseline manipulation
- Improved content-aware fingerprinting for secret detection
- Enhanced safe message construction preventing secret value leakage

---

## [0.49.0] - 2025-12-30

### Added
- Structured output formats: JSON and SARIF
- Baseline diffing capabilities for incremental security adoption
- Content-aware fingerprinting for findings
- Multiple output format support (text, JSON, SARIF)

### Security
- Safe message construction in structured outputs
- Prevention of secret value leakage in JSON/SARIF exports
- Comprehensive security fixes for structured output attack vectors

---

## [0.48.0] - 2025-12-29

### Added
- Snippet-enhanced findings showing exact file:line context
- `.zimaraignore` support with hardened input validation
- Output-only scan mode (`--only-output`)
- Trace mode for debugging checks (`--trace-checks`)
- Generator-aware detection for Hugo, Jekyll, Astro, Eleventy, and Next.js static exports

### Changed
- Improved secret detection output formatting for readability
- Refined severity-based exit codes for CI and hooks
- Hardened execution safety and temp file handling

### Security
- Added character whitelisting and pattern limits for `.zimaraignore`
- Prevented argument injection and path traversal via ignore patterns
- Improved PATH sanitization during execution

---

## [0.47.1] - 2025-12-28

### Fixed
- False positives in backup file detection
- Incorrect output directory resolution for Astro builds

### Security
- Hardened git history scanning logic
- Improved handling of symlinks and temp directories

---

## [0.47.0] - 2025-12-24

### Added
- Initial public release
- Core local pre-commit security audit functionality
- 45 security checks covering secrets, keys, git history, and static output
- Severity-based findings with actionable remediation guidance

---