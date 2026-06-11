"""
Regression Guard — Secure Temp File Deletion (C2 Fix)
======================================================

Guards the temp-file cleanup path in FileViewer._cleanup_resources():
- Temp files must be deleted using SecureFileOperations.secure_delete_file()
  (DoD 3-pass), not os.unlink()
- cleanup must clear self.temp_files after running
- If secure deletion fails, the file must still be removed via os.unlink()
  (graceful fallback)
- QApplication.aboutToQuit must trigger cleanup (app-exit path)
- Cleanup must be idempotent (safe to call twice)

These tests use unittest.mock to avoid writing real files to %TEMP% and
to inspect what deletion method was actually called.

NOTE ON SKIPS IN HEADLESS ENVIRONMENTS
FileViewer imports PySide6 which requires a connected display (or a virtual
framebuffer such as Xvfb on Linux).  In a headless CI runner without a
display these tests will be skipped automatically — that is the expected
behaviour and NOT a failure.  Run locally or with a virtual framebuffer to
exercise them.  The production code change in file_viewer.py is in effect
regardless of whether these tests execute in a given environment.

Do NOT delete these tests. Do NOT skip them without a written reason.

Author: Rolan Lobo (RNR)
"""

import os
import sys
import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch, call

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SRC_ROOT))

# Guard the import — PySide6 requires a QApplication for widget instantiation.
# Tests that need it create a minimal app instance.
try:
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

try:
    from gui.file_viewer import FileViewer
    from security.secure_file_ops import SecureFileOperations, SecureDeletionMethod
    FILE_VIEWER_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] FileViewer not importable: {e}")
    FILE_VIEWER_AVAILABLE = False

# One shared QApplication for all tests in this module
_qapp = None


def _get_qapp():
    global _qapp
    if not PYSIDE6_AVAILABLE:
        return None
    if QApplication.instance() is None:
        _qapp = QApplication([])
    else:
        _qapp = QApplication.instance()
    return _qapp


@unittest.skipUnless(FILE_VIEWER_AVAILABLE and PYSIDE6_AVAILABLE,
                     "FileViewer or PySide6 not available")
class TestSecureTempFileDeletion(unittest.TestCase):
    """
    Verify that _cleanup_resources() uses SecureFileOperations.secure_delete_file()
    with DOD_3_PASS rather than os.unlink().
    """

    def setUp(self):
        _get_qapp()
        # Build a mock SecureFileOperations that reports success by default
        self.mock_sfo = MagicMock(spec=SecureFileOperations)
        self.mock_sfo.secure_delete_file.return_value = True

        # Instantiate FileViewer with the mock injected
        self.viewer = FileViewer(secure_file_ops=self.mock_sfo)
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bar_c2_test_"))

    def tearDown(self):
        try:
            self.viewer.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_temp_file(self, content: bytes = b"sensitive plaintext") -> str:
        """Create a real temp file and register it in the viewer."""
        tmp = self.tmp_dir / f"test_{id(self)}.tmp"
        tmp.write_bytes(content)
        path = str(tmp)
        self.viewer.temp_files.append(path)
        return path

    # ── Core deletion method ───────────────────────────────────────────────

    def test_cleanup_calls_secure_delete_not_os_unlink(self):
        """C2: _cleanup_resources() must call secure_delete_file(), not os.unlink()."""
        path = self._make_temp_file()

        with patch("os.unlink") as mock_unlink:
            self.viewer._cleanup_resources()

        self.mock_sfo.secure_delete_file.assert_called_once()
        mock_unlink.assert_not_called()

    def test_cleanup_uses_dod_3_pass_method(self):
        """C2: secure_delete_file() must be called with SecureDeletionMethod.DOD_3_PASS."""
        self._make_temp_file()
        self.viewer._cleanup_resources()

        _, kwargs = self.mock_sfo.secure_delete_file.call_args
        self.assertEqual(
            kwargs.get("method"), SecureDeletionMethod.DOD_3_PASS,
            "Temp file must be wiped with DOD_3_PASS, not any other method"
        )

    def test_cleanup_passes_correct_file_path(self):
        """C2: secure_delete_file() must receive the exact path registered in temp_files."""
        path = self._make_temp_file()
        self.viewer._cleanup_resources()

        args, _ = self.mock_sfo.secure_delete_file.call_args
        self.assertEqual(args[0], path)

    # ── List management ────────────────────────────────────────────────────

    def test_temp_files_list_cleared_after_cleanup(self):
        """C2: self.temp_files must be empty after _cleanup_resources() returns."""
        self._make_temp_file()
        self._make_temp_file()
        self.viewer._cleanup_resources()
        self.assertEqual(self.viewer.temp_files, [],
                         "temp_files list must be empty after cleanup")

    def test_cleanup_with_no_temp_files_does_not_raise(self):
        """C2: Cleanup with an empty temp_files list must not raise."""
        try:
            self.viewer._cleanup_resources()
        except Exception as exc:
            self.fail(f"_cleanup_resources() raised unexpectedly: {exc}")

    def test_multiple_temp_files_all_securely_deleted(self):
        """C2: All registered temp files must be securely deleted, not just the first."""
        paths = [self._make_temp_file() for _ in range(5)]
        self.viewer._cleanup_resources()

        actual_calls = [str(c.args[0]) for c in self.mock_sfo.secure_delete_file.call_args_list]
        for path in paths:
            self.assertIn(path, actual_calls,
                          f"Temp file {path} was not passed to secure_delete_file()")

    # ── Idempotency ────────────────────────────────────────────────────────

    def test_cleanup_is_idempotent(self):
        """C2: Calling _cleanup_resources() twice must not raise or double-delete."""
        self._make_temp_file()
        self.viewer._cleanup_resources()
        try:
            self.viewer._cleanup_resources()  # Second call — list is already empty
        except Exception as exc:
            self.fail(f"Second call to _cleanup_resources() raised: {exc}")

    # ── Graceful fallback ──────────────────────────────────────────────────

    def test_fallback_to_unlink_when_secure_delete_returns_false(self):
        """
        C2: If secure_delete_file() returns False, _cleanup_resources() must
        fall back to os.unlink() so the file is still removed from the listing.
        """
        self.mock_sfo.secure_delete_file.return_value = False
        path = self._make_temp_file()

        with patch("os.path.exists", return_value=True), \
             patch("os.unlink") as mock_unlink:
            self.viewer._cleanup_resources()

        mock_unlink.assert_called_once_with(path)

    def test_exception_in_secure_delete_does_not_abort_remaining_files(self):
        """
        C2: If secure_delete_file() raises for one file, cleanup must continue
        and process the remaining files.
        """
        # First call raises, second call succeeds
        self.mock_sfo.secure_delete_file.side_effect = [
            Exception("simulated disk error"),
            True,
        ]
        self._make_temp_file()  # Will raise
        path2 = self._make_temp_file()  # Must still be attempted

        with patch("os.path.exists", return_value=True), patch("os.unlink"):
            self.viewer._cleanup_resources()

        # The second file must have been attempted
        second_call = self.mock_sfo.secure_delete_file.call_args_list[1]
        self.assertEqual(str(second_call.args[0]), path2)

    # ── aboutToQuit integration ────────────────────────────────────────────

    def test_about_to_quit_connected_to_cleanup(self):
        """
        C2: FileViewer.__init__ must connect QApplication.aboutToQuit to
        _cleanup_resources so cleanup runs on application exit.
        """
        app = QApplication.instance()
        if app is None:
            self.skipTest("No QApplication instance available")

        # Introspect Qt signal connections.  The signal is connected if
        # emitting it triggers the slot; we verify indirectly by checking that
        # _cleanup_resources is callable and confirming the viewer registered
        # with the signal by checking it runs without error when emitted.
        self._make_temp_file()

        # Temporarily replace secure_delete_file to avoid actual disk I/O
        self.mock_sfo.secure_delete_file.return_value = True

        # Emit aboutToQuit — should call _cleanup_resources without raising
        try:
            app.aboutToQuit.emit()
        except Exception as exc:
            self.fail(f"aboutToQuit emission raised: {exc}")

        # temp_files must be cleared (cleanup ran)
        self.assertEqual(self.viewer.temp_files, [],
                         "aboutToQuit must have triggered _cleanup_resources()")


@unittest.skipUnless(FILE_VIEWER_AVAILABLE and PYSIDE6_AVAILABLE,
                     "FileViewer or PySide6 not available")
class TestFileViewerSecureOpsInjection(unittest.TestCase):
    """
    Verify the SecureFileOperations injection contract.
    """

    def setUp(self):
        _get_qapp()

    def test_injected_instance_is_used(self):
        """C2: When a SecureFileOperations instance is injected, it must be stored."""
        mock_sfo = MagicMock(spec=SecureFileOperations)
        mock_sfo.secure_delete_file.return_value = True
        viewer = FileViewer(secure_file_ops=mock_sfo)
        self.assertIs(viewer._secure_file_ops, mock_sfo,
                      "Injected SecureFileOperations must be stored as _secure_file_ops")
        viewer.close()

    def test_owns_flag_false_for_injected_instance(self):
        """
        C2: When a SecureFileOperations is injected, _owns_secure_file_ops must
        be False so the viewer does not call .cleanup() on a shared instance.
        """
        mock_sfo = MagicMock(spec=SecureFileOperations)
        mock_sfo.secure_delete_file.return_value = True
        viewer = FileViewer(secure_file_ops=mock_sfo)
        self.assertFalse(viewer._owns_secure_file_ops)
        viewer.close()
        # The shared instance must NOT have had cleanup() called on it
        mock_sfo.cleanup.assert_not_called()

    def test_fallback_instance_created_when_none_injected(self):
        """
        C2: When no SecureFileOperations is injected (None), a new instance
        must be created automatically — never None — so cleanup always works.
        """
        viewer = FileViewer(secure_file_ops=None)
        self.assertIsNotNone(viewer._secure_file_ops,
                             "_secure_file_ops must never be None")
        self.assertIsInstance(viewer._secure_file_ops, SecureFileOperations)
        self.assertTrue(viewer._owns_secure_file_ops,
                        "Viewer must own the fallback instance it created")
        viewer.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
