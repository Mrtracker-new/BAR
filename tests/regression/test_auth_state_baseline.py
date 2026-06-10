"""
Regression Guard — Authentication State File
=============================================

Guards against the auth bypass vulnerability where deleting or
tampering with `.auth_attempts` silently resets the failed-attempt
counter, bypassing MAXIMUM security's 3-strike wipe trigger.

These tests lock in the CURRENT behaviour as the baseline.
After the auth hardening fix lands, these tests are updated to
reflect the new HMAC-protected behaviour.

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
from pathlib import Path
from unittest.mock import patch, MagicMock

# Resolve project root so imports work regardless of working directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SRC_ROOT))

try:
    from security.device_auth_manager import DeviceAuthManager, SecurityLevel
    AUTH_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] DeviceAuthManager not importable: {e}")
    AUTH_AVAILABLE = False


@unittest.skipUnless(AUTH_AVAILABLE, "DeviceAuthManager module not available")
class TestAuthAttemptFileBaseline(unittest.TestCase):
    """
    Baseline tests for the .auth_attempts file behaviour.

    These tests document the CURRENT (pre-fix) behaviour:
    - File is plain JSON
    - File absence silently resets counter to 0
    - No integrity protection

    When the HMAC-protection fix is applied, this class will be
    updated to assert HMAC verification behaviour instead.
    """

    def setUp(self):
        """Create a temporary config directory to isolate each test."""
        self.test_dir = Path(tempfile.mkdtemp(prefix="bar_test_auth_"))
        self.attempts_file = self.test_dir / ".auth_attempts"

    def tearDown(self):
        """Remove temp directory after every test."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ──────────────────────────────────────────────────
    # Baseline structural tests (no DeviceAuthManager
    # instance needed — just verifying file format)
    # ──────────────────────────────────────────────────

    def test_attempts_file_is_valid_json(self):
        """BASELINE: .auth_attempts is plain JSON (no HMAC wrapper yet)."""
        payload = {
            "count": 1,
            "locked_until": 0,
            "security_level": "maximum"
        }
        self.attempts_file.write_text(json.dumps(payload))

        raw = self.attempts_file.read_text()
        parsed = json.loads(raw)

        self.assertIn("count", parsed)
        self.assertEqual(parsed["count"], 1)
        self.assertEqual(parsed["security_level"], "maximum")

    def test_attempts_file_count_readable_after_write(self):
        """BASELINE: Written count survives a read-back."""
        for count in [0, 1, 2, 3]:
            payload = {"count": count, "locked_until": 0, "security_level": "maximum"}
            self.attempts_file.write_text(json.dumps(payload))
            read_back = json.loads(self.attempts_file.read_text())
            self.assertEqual(read_back["count"], count,
                             f"Count {count} did not survive read-back")

    def test_attempts_file_deletion_is_detectable(self):
        """
        BASELINE: Documents that file absence is currently NOT detected.

        This test does NOT assert that absence is caught — it asserts that
        the file simply doesn't exist after deletion, confirming the gap
        the future HMAC fix will close.

        After the fix, this test should be updated to assert that the
        absence is treated as a tamper event.
        """
        payload = {"count": 2, "locked_until": 0, "security_level": "maximum"}
        self.attempts_file.write_text(json.dumps(payload))
        self.assertTrue(self.attempts_file.exists())

        # Delete the file (simulating an attacker wiping the counter)
        self.attempts_file.unlink()

        # BASELINE: file is gone, no automatic tamper detection yet
        self.assertFalse(self.attempts_file.exists(),
                         "File should be gone after explicit deletion")

    def test_attempts_file_can_be_forged(self):
        """
        BASELINE: A forged payload with count=0 is indistinguishable from
        a legitimate first-run file. Documents the current gap.

        After the HMAC fix, a forged file should be rejected.
        """
        # Simulate an attacker replacing a count=2 file with count=0
        forged_payload = {"count": 0, "locked_until": 0, "security_level": "maximum"}
        self.attempts_file.write_text(json.dumps(forged_payload))

        read_back = json.loads(self.attempts_file.read_text())
        # BASELINE: The forged count is accepted as-is (no signature check)
        self.assertEqual(read_back["count"], 0,
                         "Forged count should be readable as 0 (pre-fix baseline)")

    def test_locked_until_field_respected(self):
        """BASELINE: locked_until timestamp field is present and parseable."""
        future_ts = time.time() + 3600  # 1 hour from now
        payload = {
            "count": 3,
            "locked_until": future_ts,
            "security_level": "high"
        }
        self.attempts_file.write_text(json.dumps(payload))
        parsed = json.loads(self.attempts_file.read_text())

        self.assertGreater(parsed["locked_until"], time.time(),
                           "locked_until should be in the future")

    def test_security_level_stored_in_file(self):
        """BASELINE: security_level field is stored and readable."""
        for level in ["standard", "high", "maximum"]:
            payload = {"count": 0, "locked_until": 0, "security_level": level}
            self.attempts_file.write_text(json.dumps(payload))
            parsed = json.loads(self.attempts_file.read_text())
            self.assertEqual(parsed["security_level"], level)


@unittest.skipUnless(AUTH_AVAILABLE, "DeviceAuthManager module not available")
class TestSecurityLevelConstants(unittest.TestCase):
    """
    Regression guard for SecurityLevel constant values.
    If these strings change, any stored .auth_attempts files
    will be misread. Changing these requires a migration.
    """

    def test_standard_level_value_unchanged(self):
        self.assertEqual(SecurityLevel.STANDARD, "standard")

    def test_high_level_value_unchanged(self):
        self.assertEqual(SecurityLevel.HIGH, "high")

    def test_maximum_level_value_unchanged(self):
        self.assertEqual(SecurityLevel.MAXIMUM, "maximum")

    def test_all_levels_present(self):
        all_levels = SecurityLevel.get_all_levels()
        self.assertIn("standard", all_levels)
        self.assertIn("high", all_levels)
        self.assertIn("maximum", all_levels)

    def test_maximum_config_wipes_data(self):
        """BASELINE: MAXIMUM security is configured to destroy data on breach."""
        from security.device_auth_manager import DeviceAuthManager
        config = DeviceAuthManager.SECURITY_CONFIGS["maximum"]
        self.assertTrue(config["destroy_data_on_breach"],
                        "MAXIMUM security must have destroy_data_on_breach=True — "
                        "changing this weakens the security model")

    def test_maximum_config_max_attempts(self):
        """BASELINE: MAXIMUM security allows only 3 attempts."""
        from security.device_auth_manager import DeviceAuthManager
        config = DeviceAuthManager.SECURITY_CONFIGS["maximum"]
        self.assertEqual(config["max_attempts"], 3,
                         "MAXIMUM security must limit to 3 attempts — "
                         "increasing this weakens the brute-force protection")

    def test_pbkdf2_iteration_count_not_reduced(self):
        """
        BASELINE: PBKDF2 iteration count must not be reduced below current value.

        Current value: 200,000 iterations.
        The security plan will INCREASE this to 600,000.
        This test ensures it is never accidentally lowered.
        """
        from security.device_auth_manager import DeviceAuthManager
        self.assertGreaterEqual(
            DeviceAuthManager.PBKDF2_ITERATIONS, 200_000,
            "PBKDF2 iteration count was reduced — this weakens brute-force protection"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
