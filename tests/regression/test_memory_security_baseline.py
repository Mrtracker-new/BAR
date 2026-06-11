"""
Regression Guard — Memory Security (Metadata Key + Content Buffer)
==================================================================

Guards two memory-hardening changes:

Metadata key (file_manager.py):
- _metadata_key must be stored as SecureBytes, not raw bytes
- clear_metadata_key() must call SecureBytes.clear(), leaving _metadata_key=None
- Both _save_metadata() and _load_metadata() must NOT hold a long-lived reference
  to the raw key material; they use get_bytes() for a function-scoped copy

Content buffer (file_viewer.py):
- display_content() must store content as bytearray, not bytes
- _cleanup_resources() must zero the bytearray before releasing it

All tests use real FileManager instances (no mocking of SecureBytes) to
catch integration failures as well as unit failures.

NOTE ON SKIPS
The FileViewer tests require PySide6 and a display connection. In headless
CI environments they are skipped automatically — that is expected behaviour.

Do NOT delete these tests. Do NOT skip them without a written reason.

Author: Rolan Lobo (RNR)
"""

import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SRC_ROOT))

try:
    from file_manager.file_manager import FileManager
    from security.secure_memory import SecureBytes
    FILE_MANAGER_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] FileManager not importable: {e}")
    FILE_MANAGER_AVAILABLE = False

try:
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

try:
    from gui.file_viewer import FileViewer
    FILE_VIEWER_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] FileViewer not importable: {e}")
    FILE_VIEWER_AVAILABLE = False

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


# ── FileManager / Metadata Key ─────────────────────────────────────────────

@unittest.skipUnless(FILE_MANAGER_AVAILABLE, "FileManager not available")
class TestMetadataKeyMemoryHardening(unittest.TestCase):
    """Verify that the metadata key is stored in SecureBytes and properly erased."""

    _TEST_PASSWORD = "Str0ng!Passw0rd#2025"

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bar_mem_test_"))
        self.fm = FileManager(str(self.tmp_dir))

    def tearDown(self):
        try:
            self.fm.shutdown()
        except Exception:
            pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # ── Storage type ──────────────────────────────────────────────────────

    def test_metadata_key_stored_as_secure_bytes(self):
        """Metadata key must be a SecureBytes instance after set_metadata_key()."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        key_obj = self.fm._metadata_key
        # Use class name check to avoid false-negative caused by the test runner
        # loading the same module under two different sys.path-prefixed identities
        # (e.g. 'security.secure_memory.SecureBytes' vs
        #       'src.security.secure_memory.SecureBytes').
        self.assertEqual(
            type(key_obj).__name__,
            "SecureBytes",
            f"_metadata_key must be SecureBytes, got {type(key_obj).__name__}",
        )

    def test_metadata_key_not_raw_bytes(self):
        """Metadata key must NOT be stored as plain bytes."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        self.assertNotIsInstance(
            self.fm._metadata_key,
            bytes,
            "_metadata_key must not be raw bytes — wrap in SecureBytes",
        )

    def test_metadata_key_flag_set_after_init(self):
        """_metadata_key_set must be True after set_metadata_key() succeeds."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        self.assertTrue(self.fm._metadata_key_set)

    # ── Erasure ───────────────────────────────────────────────────────────

    def test_clear_sets_key_to_none(self):
        """_metadata_key must be None after clear_metadata_key()."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        self.fm.clear_metadata_key()
        self.assertIsNone(self.fm._metadata_key)

    def test_clear_resets_flag(self):
        """_metadata_key_set must be False after clear_metadata_key()."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        self.fm.clear_metadata_key()
        self.assertFalse(self.fm._metadata_key_set)

    def test_clear_is_idempotent(self):
        """Calling clear_metadata_key() twice must not raise."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        self.fm.clear_metadata_key()
        try:
            self.fm.clear_metadata_key()
        except Exception as exc:
            self.fail(f"Second call to clear_metadata_key() raised: {exc}")

    def test_shutdown_clears_key(self):
        """shutdown() must clear the metadata key."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        self.fm.shutdown()
        self.assertIsNone(self.fm._metadata_key)
        self.assertFalse(self.fm._metadata_key_set)

    # ── Round-trip (key is actually usable) ───────────────────────────────

    def test_set_and_use_key_for_encrypt_decrypt(self):
        """A key set via set_metadata_key() must be usable in the full cipher round-trip."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        file_id = "test-file-id"
        metadata = {
            "filename": "test.txt",
            "file_id": file_id,
            "creation_time": "2025-01-01T00:00:00",
            "last_accessed": "2025-01-01T00:00:00",
            "access_count": 0,
            "file_type": "text",
            "security": {
                "expiration_time": None,
                "max_access_count": None,
                "deadman_switch": None,
                "disable_export": False,
            },
        }
        self.fm._save_metadata(file_id, metadata)
        loaded = self.fm._load_metadata(file_id)
        self.assertEqual(loaded["filename"], "test.txt")

    def test_reinitialise_key_replaces_old_one(self):
        """Calling set_metadata_key() a second time must replace the old SecureBytes."""
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        first_obj_id = id(self.fm._metadata_key)
        self.fm.set_metadata_key(self._TEST_PASSWORD)
        second_obj_id = id(self.fm._metadata_key)
        self.assertNotEqual(
            first_obj_id, second_obj_id,
            "A new SecureBytes object must be created on re-initialisation",
        )


# ── FileViewer / Content Buffer ────────────────────────────────────────────

@unittest.skipUnless(FILE_VIEWER_AVAILABLE and PYSIDE6_AVAILABLE,
                     "FileViewer or PySide6 not available")
class TestContentBufferMemoryHardening(unittest.TestCase):
    """Verify that file content is stored as a zeroing-capable bytearray."""

    def setUp(self):
        _get_qapp()
        self.mock_sfo = MagicMock()
        self.mock_sfo.secure_delete_file.return_value = True
        self.viewer = FileViewer(secure_file_ops=self.mock_sfo)

    def tearDown(self):
        try:
            self.viewer.close()
        except Exception:
            pass

    def _minimal_metadata(self, filename: str = "test.txt") -> dict:
        return {
            "filename": filename,
            "file_id": "test-id",
            "creation_time": "2025-01-01T00:00:00",
            "last_accessed": "2025-01-01T00:00:00",
            "access_count": 0,
            "file_type": "text",
            "security": {
                "expiration_time": None,
                "max_access_count": None,
                "deadman_switch": None,
                "disable_export": False,
            },
        }

    # ── Storage type ──────────────────────────────────────────────────────

    def test_content_stored_as_bytearray(self):
        """display_content() must store content as bytearray, not bytes."""
        raw = b"hello world"
        self.viewer.display_content(raw, self._minimal_metadata(), "testuser")
        self.assertIsInstance(
            self.viewer.current_content,
            bytearray,
            "current_content must be bytearray so it can be zeroed",
        )

    def test_content_not_stored_as_bytes(self):
        """current_content must not be the original immutable bytes object."""
        raw = b"hello world"
        self.viewer.display_content(raw, self._minimal_metadata(), "testuser")
        self.assertNotIsInstance(
            self.viewer.current_content,
            bytes,
            "current_content must not be plain bytes (cannot be zeroed)",
        )

    def test_content_value_preserved_after_conversion(self):
        """Converting bytes → bytearray must not alter the content."""
        raw = b"sensitive file content"
        self.viewer.display_content(raw, self._minimal_metadata(), "testuser")
        self.assertEqual(bytes(self.viewer.current_content), raw)

    # ── Zeroing on cleanup ────────────────────────────────────────────────

    def test_content_is_none_after_cleanup(self):
        """_cleanup_resources() must set current_content to None."""
        self.viewer.display_content(b"test data", self._minimal_metadata(), "testuser")
        self.viewer._cleanup_resources()
        self.assertIsNone(self.viewer.current_content)

    def test_content_is_zeroed_before_release(self):
        """
        _cleanup_resources() must zero the bytearray in-place before releasing it.
        We capture a reference to the bytearray object before cleanup and verify
        that all bytes are 0 afterwards (the object still exists via our reference).
        """
        raw = b"super sensitive data"
        self.viewer.display_content(raw, self._minimal_metadata(), "testuser")
        buf = self.viewer.current_content  # Keep a reference to the live object
        self.assertIsInstance(buf, bytearray)

        self.viewer._cleanup_resources()

        # buf still points to the same bytearray — all bytes must be 0
        self.assertTrue(
            all(b == 0 for b in buf),
            "Content bytearray must be zeroed in-place before release",
        )

    def test_cleanup_with_no_content_does_not_raise(self):
        """_cleanup_resources() with no content loaded must not raise."""
        try:
            self.viewer._cleanup_resources()
        except Exception as exc:
            self.fail(f"_cleanup_resources() raised with no content: {exc}")

    # ── bytearray API compatibility ───────────────────────────────────────

    def test_text_decode_works_on_bytearray(self):
        """bytearray.decode() must produce identical output to bytes.decode()."""
        raw = b"text file content\nline two"
        ba = bytearray(raw)
        self.assertEqual(ba.decode("utf-8"), raw.decode("utf-8"))

    def test_image_loadFromData_accepts_bytearray(self):
        """QPixmap.loadFromData() must accept bytearray without raising."""
        from PySide6.QtGui import QPixmap
        # 1×1 white PNG (valid minimal image)
        png_bytes = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
            b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00'
            b'\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18'
            b'\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )
        pm = QPixmap()
        try:
            result = pm.loadFromData(bytearray(png_bytes))
        except Exception as exc:
            self.fail(f"QPixmap.loadFromData(bytearray) raised: {exc}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
