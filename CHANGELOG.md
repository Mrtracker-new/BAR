# CHANGELOG

All notable changes to BAR (Burn After Reading) are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Regression test suite in `tests/regression/` covering four critical paths:
  - Authentication state file format and security constants
  - Secure file deletion (SecureFileOperations)
  - Temp file cleanup (FileViewer cleanup path)
  - FileManager security constraint enforcement
- `CHANGELOG.md` to track all changes going forward
- `tests/regression/run_regression.py` runner — execute before every merge to main

### Changed
- `.gitignore` updated to allow `.github/workflows/*.yml` through the blanket YAML exclusion

### Security
- GitHub Actions CI/CD pipeline added (`build-release.yml`, `pr-build-check.yml`):
  automatically builds `BAR.exe` and publishes a GitHub Release on every push to main

---

## [2.0.0] — 2025-10-17

### Added
- Panic wipe system with three destruction levels (selective, aggressive, scorched)
- Advanced screenshot protection (blocks Print Screen, Win+Shift+S, clipboard monitoring)
- Hardware fingerprint binding — files are locked to the specific device that created them
- DoD 5220.22-M compliant secure deletion engine

### Changed
- Authentication simplified: Device Setup → Unlock → App (removed redundant login screen)
- Screenshot protection reliability improved
- Code cleanup: removed 500+ lines of overcomplicated legacy logic

### Fixed
- Hardware binding reliability improved
- Multiple stability and crash fixes
- Security bug fixes in encryption path

### Security
- AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation
- Secure memory (SecureBytes / SecureString) for all sensitive in-memory data
- Anti-brute-force: wrong password triggers escalating lockouts and optional data wipe

---

## [1.0.0] — Initial Release

- Initial public release of BAR desktop application
- AES-256 file encryption with device-bound authentication
- Time-bomb, read-limit, and deadman-switch self-destruction modes
- PySide6 GUI for Windows (limited Linux/macOS support)
