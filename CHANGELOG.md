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
- 20 new regression tests for the C1 auth-state HMAC fix (45 total, all passing)
- 13 new regression tests for the C2 secure temp-file deletion fix (48 total, all passing/skipped on headless)

### Fixed
- **[C1 — CRITICAL]** `.auth_attempts` file was plain JSON with no integrity check.
  An attacker with filesystem access could delete or forge it to silently reset the
  failed-password counter, bypassing the MAXIMUM-security 3-strike data-wipe trigger.

  **Fix:** Every write to `.auth_attempts` is now wrapped in a v1 envelope and signed
  with HMAC-SHA256. The key is derived from the device hardware ID using PBKDF2
  (100,000 rounds) with a fixed domain-separation context. Any read that fails MAC
  verification is treated as tampering and triggers an immediate emergency wipe.
  All writes are atomic (write to `.tmp` → `os.replace`). Legacy plain-JSON files
  from existing installations are accepted once and automatically re-signed on the
  next write — no user action required.

### Changed
- `.gitignore` updated to allow `.github/workflows/*.yml` through the blanket YAML exclusion
- On successful authentication, the `.auth_attempts` tracking file is now securely wiped
  (multi-pass overwrite) instead of simply deleted with `unlink()`
- **[C2]** `FileViewer._cleanup_resources()` now calls `SecureFileOperations.secure_delete_file()`
  with `DOD_3_PASS` instead of `os.unlink()` for temp files created during external viewer launch.
  `QApplication.aboutToQuit` is connected to `_cleanup_resources()` on viewer creation to guarantee
  cleanup even when the app is closed before the viewer widget is explicitly closed.
  Three passes chosen over seven: SSD wear-levelling makes additional passes ineffective; three
  passes defeats casual and intermediate forensic recovery tools imperceptibly fast.

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
