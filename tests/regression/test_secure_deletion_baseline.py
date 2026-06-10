"""
Regression Guard — Secure File Deletion
=========================================

Guards against two risks:
1. secure_delete_file() stops actually removing files
2. The temp-file cleanup path in FileViewer reverts to plain os.unlink()

After the temp-file fix lands, the FileViewer cleanup tests will be
updated to assert that SecureFileOperations.secure_delete_file()
is called instead of os.unlink().

Do NOT delete these tests. Do NOT skip them without a written reason.

Author: Rolan Lobo (RNR)
"""

import os
import sys
import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, call

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SRC_ROOT))

try:
    from security.secure_file_ops import (
        SecureFileOperations,
        SecureDeletionMethod,
        FileSecurityLevel,
    )
    SECURE_OPS_AVAILABLE = True
except ImportError as e:
    print(f"⚠ SecureFileOperations not importable: {e}")
    SECURE_OPS_AVAILABLE = False


@unittest.skipUnless(SECURE_OPS_AVAILABLE, "SecureFileOperations not available")
class TestSecureDeleteFileBaseline(unittest.TestCase):
    """
    Regression guard for SecureFileOperations.secure_delete_file().

    Core invariant: after the call returns True, the file MUST NOT exist.
    """

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="bar_test_del_"))
        self.secure_ops = SecureFileOperations(config_dir=self.test_dir / "security")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _make_test_file(self, name: str = "test_target.txt",
                        content: bytes = b"SENSITIVE DATA - DO NOT LEAVE ON DISK") -> Path:
        """Create a temp file with known content."""
        path = self.test_dir / name
        path.write_bytes(content)
        return path

    # ── Core delete behaviour ──────────────────────────────────────────────

    def test_file_does_not_exist_after_basic_delete(self):
        """REGRESSION: File must be gone after BASIC deletion."""
        f = self._make_test_file()
        result = self.secure_ops.secure_delete_file(f, method=SecureDeletionMethod.BASIC)
        self.assertTrue(result, "secure_delete_file should return True on success")
        self.assertFalse(f.exists(), "File must not exist after BASIC secure deletion")

    def test_file_does_not_exist_after_dod3_delete(self):
        """REGRESSION: File must be gone after DoD 3-pass deletion."""
        f = self._make_test_file(name="dod3_target.txt")
        result = self.secure_ops.secure_delete_file(f, method=SecureDeletionMethod.DOD_3_PASS)
        self.assertTrue(result)
        self.assertFalse(f.exists(), "File must not exist after DOD_3_PASS deletion")

    def test_returns_true_on_already_absent_file(self):
        """REGRESSION: Deleting a non-existent file should return True gracefully."""
        ghost = self.test_dir / "i_never_existed.txt"
        self.assertFalse(ghost.exists())
        result = self.secure_ops.secure_delete_file(ghost)
        self.assertTrue(result, "Deleting an already-absent file should return True")

    def test_returns_false_on_directory_path(self):
        """REGRESSION: Passing a directory instead of a file should not crash."""
        subdir = self.test_dir / "a_directory"
        subdir.mkdir()
        # Behaviour: should return False (or raise), never silently succeed
        try:
            result = self.secure_ops.secure_delete_file(subdir)
            # If no exception, result must be False — we should not claim success
            # for deleting a directory via the file-delete path
            self.assertFalse(result,
                             "secure_delete_file on a directory should not return True")
        except (IsADirectoryError, PermissionError, ValueError):
            pass  # Raising is also acceptable

    def test_empty_file_deleted_successfully(self):
        """REGRESSION: Zero-byte files must delete cleanly."""
        f = self._make_test_file(content=b"")
        result = self.secure_ops.secure_delete_file(f, method=SecureDeletionMethod.DOD_3_PASS)
        self.assertTrue(result)
        self.assertFalse(f.exists())

    def test_large_file_deleted_successfully(self):
        """REGRESSION: 1 MB file must delete cleanly with BASIC method."""
        f = self._make_test_file(content=b"A" * (1024 * 1024))
        result = self.secure_ops.secure_delete_file(f, method=SecureDeletionMethod.BASIC)
        self.assertTrue(result)
        self.assertFalse(f.exists())

    def test_statistics_incremented_on_successful_delete(self):
        """REGRESSION: Internal access stats should record the deletion."""
        f = self._make_test_file(name="stats_target.txt")
        before = self.secure_ops._access_stats["files_securely_deleted"]
        self.secure_ops.secure_delete_file(f, method=SecureDeletionMethod.BASIC)
        after = self.secure_ops._access_stats["files_securely_deleted"]
        self.assertEqual(after, before + 1,
                         "files_securely_deleted counter must increment on success")


@unittest.skipUnless(SECURE_OPS_AVAILABLE, "SecureFileOperations not available")
class TestTempFileCleanupBaseline(unittest.TestCase):
    """
    Regression guard for FileViewer._cleanup_resources() temp-file handling.

    BASELINE: Currently uses os.unlink() — plain delete, NOT secure wipe.
    AFTER FIX: Should use SecureFileOperations.secure_delete_file().

    This test class documents the current baseline and will be updated when
    the secure temp-file fix is implemented.
    """

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="bar_test_viewer_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_os_unlink_removes_file(self):
        """
        BASELINE: Verify os.unlink() (current method) removes a file.

        This test exists to confirm the baseline behaviour before the fix.
        After the fix, the equivalent test should verify that
        SecureFileOperations.secure_delete_file() is called instead.
        """
        temp_file = self.test_dir / "viewer_temp_decrypted.txt"
        temp_file.write_bytes(b"DECRYPTED PLAINTEXT - SENSITIVE")

        # This is the current FileViewer cleanup code path
        if temp_file.exists():
            os.unlink(str(temp_file))

        self.assertFalse(temp_file.exists(),
                         "os.unlink must remove the temp file from the filesystem")

    def test_temp_files_list_cleared_after_cleanup(self):
        """
        BASELINE: After cleanup, the temp_files list must be empty.

        Simulates the FileViewer.temp_files.clear() call to ensure
        the list bookkeeping works correctly regardless of wipe method.
        """
        temp_files = []
        for i in range(3):
            f = self.test_dir / f"viewer_temp_{i}.tmp"
            f.write_bytes(b"content")
            temp_files.append(str(f))

        # Simulate _cleanup_resources() logic
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        temp_files.clear()

        self.assertEqual(len(temp_files), 0,
                         "temp_files list must be empty after cleanup")
        for f in (self.test_dir / f"viewer_temp_{i}.tmp" for i in range(3)):
            self.assertFalse(f.exists(), f"{f.name} must be deleted after cleanup")

    def test_cleanup_handles_already_deleted_temp_file(self):
        """
        BASELINE: Cleanup must not crash if a temp file was already removed.

        Mirrors the try/except in FileViewer._cleanup_resources().
        """
        temp_files = [str(self.test_dir / "ghost.tmp")]
        # File was never created — cleanup should not raise

        errors = []
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                errors.append(str(e))
        temp_files.clear()

        self.assertEqual(errors, [],
                         "Cleanup must not raise errors for already-absent files")


if __name__ == "__main__":
    unittest.main(verbosity=2)
