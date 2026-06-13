"""
Regression tests -- deletion & forensics hardening.
"""
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestStorageDetection(unittest.TestCase):
    """SecureFileOperations._detect_storage_type()"""

    def _make_sfo(self, wmic_output):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=wmic_output, returncode=0)
            from src.security.secure_file_ops import SecureFileOperations
            with patch.object(SecureFileOperations, "_ensure_config_directory"), \
                 patch.object(SecureFileOperations, "_load_blacklist"):
                sfo = SecureFileOperations.__new__(SecureFileOperations)
                sfo.logger = MagicMock()
                sfo._config_dir = Path(tempfile.mkdtemp())
                sfo._blacklist_file = sfo._config_dir / "bl.enc"
                sfo._access_log_file = sfo._config_dir / "al.log"
                sfo._blacklist = {}
                sfo._access_stats = {
                    "files_accessed": 0, "files_blocked": 0,
                    "files_securely_deleted": 0, "emergency_wipes": 0,
                }
                sfo._lock = threading.RLock()
                sfo._storage_is_ssd = sfo._detect_storage_type()
            return sfo

    def test_ssd_detected_from_wmic_solid(self):
        sfo = self._make_sfo("Node,MediaType\nDESKTOP,SSD\n")
        self.assertTrue(sfo.storage_is_ssd)

    def test_hdd_detected_from_wmic(self):
        sfo = self._make_sfo("Node,MediaType\nDESKTOP,Fixed hard disk\n")
        self.assertFalse(sfo.storage_is_ssd)

    def test_unknown_media_defaults_to_ssd(self):
        sfo = self._make_sfo("Node,MediaType\nDESKTOP,Unknown\n")
        self.assertTrue(sfo.storage_is_ssd)

    def test_detection_failure_defaults_to_ssd(self):
        from src.security.secure_file_ops import SecureFileOperations
        with patch.object(SecureFileOperations, "_ensure_config_directory"), \
             patch.object(SecureFileOperations, "_load_blacklist"):
            sfo = SecureFileOperations.__new__(SecureFileOperations)
            sfo.logger = MagicMock()
            sfo._config_dir = Path(tempfile.mkdtemp())
            sfo._blacklist_file = sfo._config_dir / "bl.enc"
            sfo._access_log_file = sfo._config_dir / "al.log"
            sfo._blacklist = {}
            sfo._access_stats = {
                "files_accessed": 0, "files_blocked": 0,
                "files_securely_deleted": 0, "emergency_wipes": 0,
            }
            sfo._lock = threading.RLock()
            with patch("subprocess.run", side_effect=OSError("no wmic")):
                result = sfo._detect_storage_type()
        self.assertTrue(result)


class TestSecureDeleteFileReturnType(unittest.TestCase):
    """secure_delete_file now returns Dict[str, Any]."""

    def _make_sfo(self, is_ssd):
        from src.security.secure_file_ops import SecureFileOperations
        with patch.object(SecureFileOperations, "_ensure_config_directory"), \
             patch.object(SecureFileOperations, "_load_blacklist"), \
             patch("subprocess.run", return_value=MagicMock(stdout="", returncode=0)):
            sfo = SecureFileOperations.__new__(SecureFileOperations)
            sfo.logger = MagicMock()
            sfo._config_dir = Path(tempfile.mkdtemp())
            sfo._blacklist_file = sfo._config_dir / "bl.enc"
            sfo._access_log_file = sfo._config_dir / "al.log"
            sfo._blacklist = {}
            sfo._access_stats = {
                "files_accessed": 0, "files_blocked": 0,
                "files_securely_deleted": 0, "emergency_wipes": 0,
            }
            sfo._lock = threading.RLock()
            sfo._storage_is_ssd = is_ssd
        return sfo

    def test_returns_dict_with_required_keys(self):
        sfo = self._make_sfo(True)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 64)
            path = f.name
        try:
            result = sfo.secure_delete_file(path)
            self.assertIn("deleted", result)
            self.assertIn("ssd_warning", result)
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_ssd_warning_true_on_ssd(self):
        sfo = self._make_sfo(True)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 64)
            path = f.name
        try:
            result = sfo.secure_delete_file(path)
            self.assertTrue(result["deleted"])
            self.assertTrue(result["ssd_warning"])
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_ssd_warning_false_on_hdd(self):
        sfo = self._make_sfo(False)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 64)
            path = f.name
        try:
            result = sfo.secure_delete_file(path)
            self.assertTrue(result["deleted"])
            self.assertFalse(result["ssd_warning"])
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_result_is_truthy_on_success(self):
        sfo = self._make_sfo(True)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 64)
            path = f.name
        try:
            result = sfo.secure_delete_file(path)
            self.assertTrue(bool(result))
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_nonexistent_file_returns_deleted_true(self):
        sfo = self._make_sfo(True)
        result = sfo.secure_delete_file("/nonexistent/path/no_file_here_xyz.txt")
        self.assertTrue(result["deleted"])


class TestVSSCleanup(unittest.TestCase):
    """EmergencyProtocol._attempt_vss_cleanup()"""

    def _make_ep(self):
        from src.security.emergency_protocol import EmergencyProtocol
        with patch("src.security.emergency_protocol.SecureFileOperations"), \
             patch("src.security.emergency_protocol.HardwareWipe"):
            ep = EmergencyProtocol.__new__(EmergencyProtocol)
            ep.logger = MagicMock()
            ep._dead_mans_timer = None
            ep.base_directory = Path(tempfile.mkdtemp())
            return ep

    def test_non_admin_returns_insufficient_privileges(self):
        ep = self._make_ep()
        with patch("os.name", "nt"), \
             patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
            result = ep._attempt_vss_cleanup()
        self.assertFalse(result["attempted"])
        self.assertEqual(result["reason"], "insufficient_privileges")
        self.assertFalse(result["success"])

    def test_admin_success_runs_vssadmin(self):
        ep = self._make_ep()
        with patch("os.name", "nt"), \
             patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = ep._attempt_vss_cleanup()
        self.assertTrue(result["attempted"])
        self.assertTrue(result["success"])
        cmd = mock_run.call_args[0][0]
        self.assertIn("vssadmin", cmd)

    def test_admin_vssadmin_failure_captures_error(self):
        ep = self._make_ep()
        with patch("os.name", "nt"), \
             patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=5, stderr="Access denied")
            result = ep._attempt_vss_cleanup()
        self.assertTrue(result["attempted"])
        self.assertFalse(result["success"])
        self.assertIn("Access denied", result["error"])

    def test_non_windows_returns_not_windows(self):
        ep = self._make_ep()
        with patch("os.name", "posix"):
            result = ep._attempt_vss_cleanup()
        self.assertFalse(result["attempted"])
        self.assertEqual(result["reason"], "not_windows")


class TestWindowsTracesStructuredResults(unittest.TestCase):
    """_cleanup_windows_traces returns List[Dict] with per-op results."""

    def _make_ep(self):
        from src.security.emergency_protocol import EmergencyProtocol
        with patch("src.security.emergency_protocol.SecureFileOperations"), \
             patch("src.security.emergency_protocol.HardwareWipe"):
            ep = EmergencyProtocol.__new__(EmergencyProtocol)
            ep.logger = MagicMock()
            ep._dead_mans_timer = None
            ep.base_directory = Path(tempfile.mkdtemp())
            return ep

    def test_non_windows_returns_empty_list(self):
        ep = self._make_ep()
        with patch("os.name", "posix"):
            result = ep._cleanup_windows_traces()
        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_returns_list_of_result_dicts(self):
        ep = self._make_ep()
        with patch("os.name", "nt"), \
             patch("builtins.__import__", side_effect=lambda n, *a, **kw: (_ for _ in ()).throw(ImportError("no winreg")) if n == "winreg" else __import__(n, *a, **kw)):
            result = ep._cleanup_windows_traces()
        self.assertIsInstance(result, list)
        for item in result:
            self.assertIn("op", item)
            self.assertIn("success", item)
            self.assertIn("error", item)


class TestScorchedEarthReport(unittest.TestCase):
    """_scorched_earth_destruction returns a Dict report."""

    def _make_ep(self):
        from src.security.emergency_protocol import EmergencyProtocol
        with patch("src.security.emergency_protocol.SecureFileOperations"), \
             patch("src.security.emergency_protocol.HardwareWipe"):
            ep = EmergencyProtocol.__new__(EmergencyProtocol)
            ep.logger = MagicMock()
            ep._dead_mans_timer = None
            ep.base_directory = Path(tempfile.mkdtemp())
            ep.secure_file_ops = MagicMock()
            ep.hardware_wipe = MagicMock()
            return ep

    def test_report_contains_required_keys(self):
        ep = self._make_ep()
        vss_result = {"attempted": False, "success": False, "reason": "not_windows", "error": ""}
        with patch.object(ep, "_attempt_vss_cleanup", return_value=vss_result), \
             patch.object(ep, "_aggressive_destruction"), \
             patch.object(ep, "_complete_application_reset"), \
             patch.object(ep, "_deploy_forensic_countermeasures"), \
             patch.object(ep, "_inject_hardware_entropy"), \
             patch.object(ep, "_cleanup_windows_traces", return_value=[]), \
             patch.object(ep, "_multi_pass_overwrite_sensitive_areas"), \
             patch.object(ep, "_attempt_binary_self_destruct"), \
             patch.object(ep, "_finalize_scorched_earth_destruction"), \
             patch("os.name", "posix"):
            report = ep._scorched_earth_destruction("test", False)
        self.assertIn("vss", report)
        self.assertIn("windows_traces", report)
        self.assertIn("errors", report)

    def test_vss_cleanup_called_before_aggressive(self):
        ep = self._make_ep()
        call_order = []
        vss_result = {"attempted": False, "success": False, "reason": "", "error": ""}
        with patch.object(ep, "_attempt_vss_cleanup",
                          side_effect=lambda: call_order.append("vss") or vss_result), \
             patch.object(ep, "_aggressive_destruction",
                          side_effect=lambda *a, **kw: call_order.append("aggressive")), \
             patch.object(ep, "_complete_application_reset"), \
             patch.object(ep, "_deploy_forensic_countermeasures"), \
             patch.object(ep, "_inject_hardware_entropy"), \
             patch.object(ep, "_cleanup_windows_traces", return_value=[]), \
             patch.object(ep, "_multi_pass_overwrite_sensitive_areas"), \
             patch.object(ep, "_attempt_binary_self_destruct"), \
             patch.object(ep, "_finalize_scorched_earth_destruction"), \
             patch("os.name", "posix"):
            ep._scorched_earth_destruction("test", False)
        self.assertEqual(call_order[0], "vss")
        self.assertEqual(call_order[1], "aggressive")


if __name__ == "__main__":
    unittest.main()
