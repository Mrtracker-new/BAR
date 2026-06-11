"""
Regression Guard — Authentication State File (C1 Fix: HMAC-protected)
=======================================================================

Tests updated after the C1 auth-state-hardening fix.

What changed from the BASELINE:
- .auth_attempts is now wrapped in a v1 envelope with an HMAC-SHA256 MAC
- A forged file (bad MAC) is detected and triggers a wipe response
- A missing file is still treated as 0 attempts (safe default, no change)
- Legacy plain-JSON files are accepted once and re-signed on next write
- All writes are atomic (write tmp → os.replace)

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


def _make_manager(tmp_dir: Path) -> "DeviceAuthManager":
    """
    Instantiate DeviceAuthManager pointed at a temp config directory.
    Patches out ConfigManager and HardwareIdentifier so no real device
    config is read or written during tests.
    """
    with patch("security.device_auth_manager.ConfigManager"), \
         patch("security.device_auth_manager.SecureFileOperations"), \
         patch("security.device_auth_manager.HardwareIdentifier"):
        mgr = DeviceAuthManager.__new__(DeviceAuthManager)
        # Minimal manual init to avoid touching the real filesystem
        import logging
        mgr.logger = logging.getLogger("test_DeviceAuthManager")
        mgr._config_dir = tmp_dir
        mgr._hmac_key = None
        mgr._panic_triggered = False
        mgr._master_password = None
        mgr._derived_key = None
        mgr._hardware_fingerprint = None
        mgr._is_initialized = False
        mgr._is_authenticated = False
        mgr._device_name = ""
        mgr._device_config_path = tmp_dir / "device_config.enc"

        # Inject a real HardwareIdentifier stub with a fixed hardware ID
        hw_stub = MagicMock()
        hw_stub.get_hardware_id.return_value = "deadbeef" * 8  # 64-char hex string
        mgr._hardware_id = hw_stub
        return mgr


FIXED_HW_ID = "deadbeef" * 8  # Must match what _make_manager sets above


@unittest.skipUnless(AUTH_AVAILABLE, "DeviceAuthManager module not available")
class TestAttemptsFileV1Format(unittest.TestCase):
    """
    Verify the v1 signed envelope format used by _write_attempts_file().
    """

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bar_auth_hmac_"))
        self.mgr = _make_manager(self.tmp_dir)
        self.attempts_path = self.tmp_dir / ".auth_attempts"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _write(self, payload: dict) -> dict:
        """Write payload and return the deserialized envelope from disk."""
        self.mgr._write_attempts_file(payload, hardware_id=FIXED_HW_ID)
        raw = self.attempts_path.read_text(encoding="utf-8")
        return json.loads(raw)

    # ── Envelope structure ─────────────────────────────────────────────────

    def test_written_file_contains_version_key(self):
        """C1: Written file must contain 'v' version sentinel."""
        env = self._write({"count": 0, "security_level": "maximum"})
        self.assertIn("v", env, "Envelope must contain version key 'v'")
        self.assertEqual(env["v"], 1)

    def test_written_file_contains_payload_key(self):
        """C1: Written file must contain 'd' (data) key with the inner payload."""
        payload = {"count": 1, "security_level": "high", "locked_until": 0}
        env = self._write(payload)
        self.assertIn("d", env)
        self.assertEqual(env["d"]["count"], 1)
        self.assertEqual(env["d"]["security_level"], "high")

    def test_written_file_contains_mac_key(self):
        """C1: Written file must contain 'mac' HMAC field."""
        env = self._write({"count": 0, "security_level": "standard"})
        self.assertIn("mac", env)
        self.assertIsInstance(env["mac"], str)
        self.assertEqual(len(env["mac"]), 64, "HMAC-SHA256 hex digest must be 64 chars")

    def test_written_file_contains_timestamp(self):
        """C1: Written file must contain 'ts' write-time timestamp."""
        before = time.time()
        env = self._write({"count": 0, "security_level": "maximum"})
        after = time.time()
        self.assertIn("ts", env)
        self.assertGreaterEqual(env["ts"], before)
        self.assertLessEqual(env["ts"], after)

    def test_different_counts_produce_different_macs(self):
        """C1: Changing the payload must change the MAC."""
        env0 = self._write({"count": 0, "security_level": "maximum"})
        env1 = self._write({"count": 1, "security_level": "maximum"})
        self.assertNotEqual(env0["mac"], env1["mac"],
                            "Different payloads must produce different MACs")

    def test_atomic_write_no_tmp_left_behind(self):
        """C1: After a successful write, no .tmp file should remain."""
        self.mgr._write_attempts_file({"count": 0}, hardware_id=FIXED_HW_ID)
        tmp_path = self.tmp_dir / ".auth_attempts.tmp"
        self.assertFalse(tmp_path.exists(), "Temp file must not remain after atomic write")


@unittest.skipUnless(AUTH_AVAILABLE, "DeviceAuthManager module not available")
class TestAttemptsFileReadVerify(unittest.TestCase):
    """
    Verify _read_attempts_file() correctly detects valid, tampered, and legacy files.
    """

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bar_auth_read_"))
        self.mgr = _make_manager(self.tmp_dir)
        self.attempts_path = self.tmp_dir / ".auth_attempts"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _write_and_read(self, payload: dict) -> dict:
        self.mgr._write_attempts_file(payload, hardware_id=FIXED_HW_ID)
        return self.mgr._read_attempts_file(hardware_id=FIXED_HW_ID)

    # ── Happy path ─────────────────────────────────────────────────────────

    def test_absent_file_returns_none_data_not_tampered(self):
        """C1: Missing file must return data=None and tampered=False."""
        result = self.mgr._read_attempts_file(hardware_id=FIXED_HW_ID)
        self.assertIsNone(result["data"])
        self.assertFalse(result["tampered"])
        self.assertFalse(result["legacy"])

    def test_valid_signed_file_returns_correct_payload(self):
        """C1: A properly signed file must be read back without error."""
        payload = {"count": 2, "security_level": "maximum", "locked_until": 0}
        result = self._write_and_read(payload)
        self.assertFalse(result["tampered"])
        self.assertFalse(result["legacy"])
        self.assertIsNotNone(result["data"])
        self.assertEqual(result["data"]["count"], 2)
        self.assertEqual(result["data"]["security_level"], "maximum")

    def test_round_trip_preserves_all_fields(self):
        """C1: Every field in the payload survives a write-read round trip."""
        payload = {
            "count": 1,
            "security_level": "high",
            "locked_until": time.time() + 3600,
            "lockout_hours": 1,
            "last_attempt": time.time(),
            "hardware_id": FIXED_HW_ID[:16],
        }
        result = self._write_and_read(payload)
        for key, value in payload.items():
            self.assertIn(key, result["data"], f"Field '{key}' missing after round-trip")
            self.assertAlmostEqual(result["data"][key], value, places=3,
                                   msg=f"Field '{key}' changed value after round-trip")

    # ── Tamper detection ───────────────────────────────────────────────────

    def test_modified_count_detected_as_tampered(self):
        """C1: Changing the count field in an existing signed file must be detected."""
        self.mgr._write_attempts_file({"count": 2, "security_level": "maximum"},
                                       hardware_id=FIXED_HW_ID)
        # Attacker reads the envelope, changes count to 0, writes back
        raw = json.loads(self.attempts_path.read_text())
        raw["d"]["count"] = 0
        self.attempts_path.write_text(json.dumps(raw))

        result = self.mgr._read_attempts_file(hardware_id=FIXED_HW_ID)
        self.assertTrue(result["tampered"],
                        "Modifying the payload must be detected as tampering")
        self.assertIsNone(result["data"])

    def test_replaced_mac_detected_as_tampered(self):
        """C1: Replacing the MAC field with a random hex string must be detected."""
        self.mgr._write_attempts_file({"count": 1, "security_level": "maximum"},
                                       hardware_id=FIXED_HW_ID)
        raw = json.loads(self.attempts_path.read_text())
        raw["mac"] = "aa" * 32  # 64-char fake MAC
        self.attempts_path.write_text(json.dumps(raw))

        result = self.mgr._read_attempts_file(hardware_id=FIXED_HW_ID)
        self.assertTrue(result["tampered"])

    def test_deleted_mac_field_detected_as_tampered(self):
        """C1: Removing the 'mac' field entirely must be detected."""
        self.mgr._write_attempts_file({"count": 1, "security_level": "maximum"},
                                       hardware_id=FIXED_HW_ID)
        raw = json.loads(self.attempts_path.read_text())
        del raw["mac"]
        self.attempts_path.write_text(json.dumps(raw))

        result = self.mgr._read_attempts_file(hardware_id=FIXED_HW_ID)
        self.assertTrue(result["tampered"])

    def test_corrupted_json_detected_as_tampered(self):
        """C1: A file containing garbage bytes must be treated as tampered."""
        self.attempts_path.write_bytes(b"not json at all !!!")
        result = self.mgr._read_attempts_file(hardware_id=FIXED_HW_ID)
        self.assertTrue(result["tampered"])

    def test_wrong_hardware_id_detected_as_tampered(self):
        """
        C1: A file signed with a different hardware ID must be detected.
        Simulates moving the file from another machine.
        """
        self.mgr._write_attempts_file({"count": 1, "security_level": "maximum"},
                                       hardware_id=FIXED_HW_ID)
        # Read using a completely different hardware ID
        result = self.mgr._read_attempts_file(hardware_id="cafecafe" * 8)
        self.assertTrue(result["tampered"],
                        "A file signed for a different hardware ID must be rejected")

    # ── Legacy migration ───────────────────────────────────────────────────

    def test_legacy_plain_json_file_accepted_as_legacy(self):
        """C1: A pre-fix plain-JSON file must be accepted with legacy=True."""
        legacy_payload = {
            "count": 1,
            "security_level": "standard",
            "locked_until": 0,
        }
        self.attempts_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

        result = self.mgr._read_attempts_file(hardware_id=FIXED_HW_ID)
        self.assertFalse(result["tampered"],
                         "Legacy file must NOT be flagged as tampered")
        self.assertTrue(result["legacy"],
                        "Legacy file must be flagged with legacy=True")
        self.assertIsNotNone(result["data"])
        self.assertEqual(result["data"]["count"], 1)

    def test_legacy_file_re_signed_after_write(self):
        """
        C1: After reading a legacy file and writing an update, the new file
        must be in v1 signed format.
        """
        legacy_payload = {"count": 0, "security_level": "maximum", "locked_until": 0}
        self.attempts_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

        # Simulate reading (legacy accepted) then writing the next update
        self.mgr._write_attempts_file(
            {"count": 1, "security_level": "maximum", "locked_until": 0},
            hardware_id=FIXED_HW_ID,
        )

        env = json.loads(self.attempts_path.read_text())
        self.assertEqual(env.get("v"), 1, "File must be upgraded to v1 format after re-write")
        self.assertIn("mac", env, "Re-written file must contain a MAC")


@unittest.skipUnless(AUTH_AVAILABLE, "DeviceAuthManager module not available")
class TestSecurityLevelConstants(unittest.TestCase):
    """
    Regression guard for SecurityLevel constant values.
    These strings are stored in .auth_attempts — changing them breaks
    existing installations.
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
        """REGRESSION: MAXIMUM security must still destroy data on breach."""
        config = DeviceAuthManager.SECURITY_CONFIGS["maximum"]
        self.assertTrue(config["destroy_data_on_breach"],
                        "MAXIMUM security must have destroy_data_on_breach=True")

    def test_maximum_config_max_attempts(self):
        """REGRESSION: MAXIMUM security must still allow only 3 attempts."""
        config = DeviceAuthManager.SECURITY_CONFIGS["maximum"]
        self.assertEqual(config["max_attempts"], 3,
                         "MAXIMUM security must limit to 3 attempts")

    def test_pbkdf2_iteration_count_not_reduced(self):
        """
        REGRESSION: PBKDF2 iteration count must not be reduced below 200,000.
        """
        self.assertGreaterEqual(
            DeviceAuthManager.PBKDF2_ITERATIONS, 200_000,
            "PBKDF2 iteration count must not be reduced"
        )

    def test_attempts_hmac_iterations_not_reduced(self):
        """
        C1: HMAC key derivation iteration count must not be reduced below 100,000.
        """
        self.assertGreaterEqual(
            DeviceAuthManager._ATTEMPTS_HMAC_ITERATIONS, 100_000,
            "HMAC derivation iteration count must not be reduced"
        )

    def test_attempts_file_version_is_one(self):
        """C1: The file format version sentinel must be 1."""
        self.assertEqual(DeviceAuthManager._ATTEMPTS_FILE_VERSION, 1)

    def test_attempts_hmac_context_is_domain_separated(self):
        """C1: HMAC context must contain the domain-separation prefix."""
        ctx = DeviceAuthManager._ATTEMPTS_HMAC_CONTEXT
        self.assertIn(b"BAR|", ctx,
                      "HMAC context must contain the BAR domain prefix")


if __name__ == "__main__":
    unittest.main(verbosity=2)
