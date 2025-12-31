# Changelog

All notable changes to this project will be documented in this file.

This project follows a pragmatic versioning approach and documents
user-visible changes, security improvements, and behavioral changes.

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

