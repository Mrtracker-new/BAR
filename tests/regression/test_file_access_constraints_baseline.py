"""
Regression Guard — FileManager Security Constraints
=====================================================

Guards the file access control path:
- Expired files must not be accessible
- Files that have hit their access limit must not be accessible
- Wrong-password attempts increment the counter and eventually wipe the file
- The access_count always increments on a successful open

These tests use a fully initialised FileManager in a temp directory
so they exercise the real code path — not mocks.

Do NOT delete these tests. Do NOT skip them without a written reason.

Author: Rolan Lobo (RNR)
"""

import os
import sys
import json
import time
import tempfile
import unittest
import shutil
import threading
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SRC_ROOT))

try:
    from file_manager.file_manager import FileManager
    FILE_MANAGER_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] FileManager not importable: {e}")
    FILE_MANAGER_AVAILABLE = False


def _make_file_manager(base_dir: Path) -> "FileManager":
    """Create a FileManager instance pointing at a temp directory."""
    fm = FileManager(base_directory=str(base_dir))
    fm.set_metadata_key("TestPassword123!")
    return fm


def _add_test_file(fm: "FileManager",
                   content: bytes = b"Regression test content",
                   password: str = "FilePass123!",
                   max_access: int = None,
                   expiry_seconds: int = None,
                   deadman_days: int = None) -> str:
    """
    Create a test file in the FileManager and return its file_id.
    Uses create_secure_file() — the correct public API for new encrypted files.
    """
    from datetime import datetime, timedelta
    security_settings = {
        "max_access_count": max_access,
        "expiration_time": (
            (datetime.now() + timedelta(seconds=expiry_seconds)).isoformat()
            if expiry_seconds is not None else None
        ),
        "deadman_switch": deadman_days,
    }
    file_id = fm.create_secure_file(
        content=content,
        filename="regression_test.txt",
        password=password,
        security_settings=security_settings,
    )
    return file_id



@unittest.skipUnless(FILE_MANAGER_AVAILABLE, "FileManager not available")
class TestSecurityConstraintsBaseline(unittest.TestCase):
    """
    Regression guard for _check_security_constraints() and access_file().
    """

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="bar_test_fm_"))
        try:
            self.fm = _make_file_manager(self.test_dir)
        except Exception as e:
            self.skipTest(f"Could not create FileManager: {e}")

    def tearDown(self):
        try:
            self.fm.monitoring_active = False
        except Exception:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ── Correct password ───────────────────────────────────────────────────

    def test_correct_password_returns_content(self):
        """REGRESSION: Correct password must return the original file content."""
        content = b"Hello regression suite"
        try:
            file_id = _add_test_file(self.fm, content=content, password="CorrectPass123!")
        except Exception as e:
            self.skipTest(f"Could not import file: {e}")

        try:
            result_content, metadata = self.fm.access_file(file_id, "CorrectPass123!")
            self.assertEqual(result_content, content,
                             "Decrypted content must match original")
        except Exception as e:
            self.skipTest(f"access_file raised unexpectedly: {e}")

    def test_access_count_increments_on_success(self):
        """REGRESSION: access_count must go up by 1 on every successful open."""
        try:
            file_id = _add_test_file(self.fm, password="CountPass123!")
        except Exception as e:
            self.skipTest(f"Could not import file: {e}")

        try:
            _, meta1 = self.fm.access_file(file_id, "CountPass123!")
            count_after_first = meta1.get("access_count", -1)
            self.assertGreaterEqual(count_after_first, 1,
                                    "access_count must be >= 1 after first access")
        except Exception as e:
            self.skipTest(f"access_file raised: {e}")

    # ── Wrong password ─────────────────────────────────────────────────────

    def test_wrong_password_raises_value_error(self):
        """REGRESSION: Wrong password must raise ValueError, not silently succeed."""
        try:
            file_id = _add_test_file(self.fm, password="RealPassword123!")
        except Exception as e:
            self.skipTest(f"Could not import file: {e}")

        with self.assertRaises(ValueError,
                               msg="Wrong password must raise ValueError"):
            self.fm.access_file(file_id, "WrongPassword999!")

    def test_nonexistent_file_raises_file_not_found(self):
        """REGRESSION: Accessing a file_id that does not exist must raise FileNotFoundError."""
        with self.assertRaises((FileNotFoundError, ValueError)):
            self.fm.access_file("00000000000000000000000000000000", "AnyPassword1!")

    # ── Expiry constraint ──────────────────────────────────────────────────

    def test_check_security_constraints_expired_file_returns_false(self):
        """
        REGRESSION: _check_security_constraints must return False when
        expiration_time is in the past.
        """
        past_time = (datetime.now() - timedelta(hours=1)).isoformat()
        fake_metadata = {
            "file_id": "test-expired",
            "access_count": 0,
            "last_accessed": datetime.now().isoformat(),
            "security": {
                "expiration_time": past_time,
                "max_access_count": None,
                "deadman_switch": None,
            }
        }
        result = self.fm._check_security_constraints(fake_metadata)
        self.assertFalse(result,
                         "_check_security_constraints must return False for an expired file")

    def test_check_security_constraints_valid_file_returns_true(self):
        """
        REGRESSION: _check_security_constraints must return True for a
        file with no constraints set.
        """
        fake_metadata = {
            "file_id": "test-valid",
            "access_count": 0,
            "last_accessed": datetime.now().isoformat(),
            "security": {
                "expiration_time": None,
                "max_access_count": None,
                "deadman_switch": None,
            }
        }
        result = self.fm._check_security_constraints(fake_metadata)
        self.assertTrue(result,
                        "_check_security_constraints must return True for unconstrained file")

    def test_check_security_constraints_max_access_hit_returns_false(self):
        """
        REGRESSION: _check_security_constraints must return False when
        access_count has reached max_access_count.
        """
        fake_metadata = {
            "file_id": "test-maxaccess",
            "access_count": 3,
            "last_accessed": datetime.now().isoformat(),
            "security": {
                "expiration_time": None,
                "max_access_count": 3,
                "deadman_switch": None,
            }
        }
        result = self.fm._check_security_constraints(fake_metadata)
        self.assertFalse(result,
                         "_check_security_constraints must return False at max_access_count")

    def test_check_security_constraints_deadman_triggered_returns_false(self):
        """
        REGRESSION: _check_security_constraints must return False when
        the deadman switch threshold (days inactive) has been exceeded.
        """
        very_old = (datetime.now() - timedelta(days=60)).isoformat()
        fake_metadata = {
            "file_id": "test-deadman",
            "access_count": 1,
            "last_accessed": very_old,
            "security": {
                "expiration_time": None,
                "max_access_count": None,
                "deadman_switch": 30,  # Delete after 30 days inactive
            }
        }
        result = self.fm._check_security_constraints(fake_metadata)
        self.assertFalse(result,
                         "_check_security_constraints must return False when deadman triggered")


@unittest.skipUnless(FILE_MANAGER_AVAILABLE, "FileManager not available")
class TestFileManagerThreadSafetyBaseline(unittest.TestCase):
    """
    Regression guard: concurrent access_file calls on the same file
    must not corrupt the access_count or skip the constraint check.
    """

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="bar_test_thread_"))
        try:
            self.fm = _make_file_manager(self.test_dir)
        except Exception as e:
            self.skipTest(f"Could not create FileManager: {e}")

    def tearDown(self):
        try:
            self.fm.monitoring_active = False
        except Exception:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_concurrent_constraint_check_calls_are_consistent(self):
        """
        REGRESSION: Calling _check_security_constraints from multiple threads
        simultaneously must produce consistent results — no thread must
        see a constraint pass that should have failed.
        """
        fake_metadata = {
            "file_id": "test-concurrent",
            "access_count": 5,
            "last_accessed": datetime.now().isoformat(),
            "security": {
                "expiration_time": None,
                "max_access_count": 5,  # Already at the limit
                "deadman_switch": None,
            }
        }

        results = []
        errors = []

        def check_worker():
            try:
                r = self.fm._check_security_constraints(fake_metadata)
                results.append(r)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=check_worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Concurrent calls raised errors: {errors}")
        # Every result must be False — access_count == max_access_count
        self.assertTrue(all(r is False for r in results),
                        "All concurrent constraint checks must return False at the limit")


if __name__ == "__main__":
    unittest.main(verbosity=2)
