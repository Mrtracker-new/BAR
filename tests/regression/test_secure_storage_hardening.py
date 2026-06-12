"""Regression tests for secure storage hardening."""

import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ===========================================================================
# Test 1 — Log Redaction Filter
# ===========================================================================
class TestSensitiveDataFilter(unittest.TestCase):
    def _get_filter(self):
        import importlib.util
        fake_qt = MagicMock()
        sys.modules.setdefault("PySide6", fake_qt)
        sys.modules.setdefault("PySide6.QtWidgets", fake_qt)
        spec = importlib.util.spec_from_file_location("_main_mod", _ROOT / "main.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod._SensitiveDataFilter()

    def _make_record(self, msg):
        return logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg=msg,
            args=(), exc_info=None
        )

    def test_hex_id_truncated(self):
        f = self._get_filter()
        record = self._make_record("Imported file: abcdef1234567890 (test.txt)")
        f.filter(record)
        self.assertIn("abcdef12\u2026", record.msg)
        self.assertNotIn("abcdef1234567890", record.msg)

    def test_short_hex_not_truncated(self):
        f = self._get_filter()
        record = self._make_record("token: abc123 seen")
        f.filter(record)
        self.assertIn("abc123", record.msg)

    def test_non_hex_content_untouched(self):
        f = self._get_filter()
        record = self._make_record("Authentication successful for device: MyLaptop")
        f.filter(record)
        self.assertEqual(record.msg, "Authentication successful for device: MyLaptop")

    def test_multiple_ids_all_truncated(self):
        f = self._get_filter()
        record = self._make_record("file1=aabbccdd11223344 file2=eeff00112233445566")
        f.filter(record)
        self.assertNotIn("aabbccdd11223344", record.msg)
        self.assertIn("aabbccdd\u2026", record.msg)

    def test_filter_returns_true(self):
        f = self._get_filter()
        self.assertTrue(f.filter(self._make_record("anything")))


# ===========================================================================
# Test 2 — Plaintext metadata guard
# ===========================================================================
class TestImportFilePlaintextGuard(unittest.TestCase):
    def test_raises_runtime_error_when_key_not_set(self):
        from src.file_manager.file_manager import FileManager
        mgr = FileManager.__new__(FileManager)
        mgr.logger = logging.getLogger("test")
        mgr._metadata_key_set = False
        mgr.metadata_directory = Path(tempfile.mkdtemp())
        mgr._generate_file_id = lambda: "deadbeef" * 4
        mgr._save_metadata = MagicMock()

        export_data = {
            "file_id": "deadbeef" * 4,
            "encryption": {"method": "AES-256-GCM"},
            "filename": "test.txt",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            json.dump(export_data, tf)
            tmp_path = tf.name
        try:
            with self.assertRaises(RuntimeError) as ctx:
                mgr.import_file(tmp_path)
            self.assertIn("Authenticate", str(ctx.exception))
        finally:
            os.unlink(tmp_path)

    def test_no_raise_when_key_set(self):
        from src.file_manager.file_manager import FileManager
        mgr = FileManager.__new__(FileManager)
        mgr.logger = logging.getLogger("test")
        mgr._metadata_key_set = True
        mgr.metadata_directory = Path(tempfile.mkdtemp())
        mgr._generate_file_id = lambda: "cafebabe" * 4
        saved = {}
        mgr._save_metadata = lambda fid, meta: saved.update({fid: meta})

        export_data = {
            "file_id": "cafebabe" * 4,
            "encryption": {"method": "AES-256-GCM"},
            "filename": "test.txt",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            json.dump(export_data, tf)
            tmp_path = tf.name
        try:
            fid = mgr.import_file(tmp_path)
            self.assertIsNotNone(fid)
        finally:
            os.unlink(tmp_path)


# ===========================================================================
# Test 3 — PBKDF2 iteration constants
# ===========================================================================
class TestPBKDF2IterationConstants(unittest.TestCase):
    def test_encryption_manager_constant(self):
        from src.crypto.encryption import EncryptionManager
        self.assertEqual(EncryptionManager.PBKDF2_ITERATIONS, 600_000)

    def test_device_auth_manager_constant(self):
        from src.security.device_auth_manager import DeviceAuthManager
        self.assertEqual(DeviceAuthManager.PBKDF2_ITERATIONS, 600_000)

    def test_derive_key_iterations_param_changes_output(self):
        from src.crypto.encryption import EncryptionManager
        salt = os.urandom(32)
        k1 = EncryptionManager.derive_key("ValidP@ss123", salt, skip_validation=True, iterations=100)
        k2 = EncryptionManager.derive_key("ValidP@ss123", salt, skip_validation=True, iterations=200)
        self.assertNotEqual(k1, k2)

    def test_encrypt_decrypt_roundtrip_at_600k(self):
        from src.crypto.encryption import EncryptionManager
        password = "ValidP@ssword!99"
        content = b"secret content"
        envelope = EncryptionManager.encrypt_file_content(content, password)
        self.assertEqual(envelope["kdf_iterations"], 600_000)
        decrypted = EncryptionManager.decrypt_file_content(envelope, password)
        self.assertEqual(decrypted, content)

    def test_decrypt_honours_custom_iterations_in_envelope(self):
        from src.crypto.encryption import EncryptionManager
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        password = "ValidP@ssword!99"
        content = b"old format content"
        salt = os.urandom(32)
        custom_iterations = 300_000

        key = EncryptionManager.derive_key(password, salt, skip_validation=True, iterations=custom_iterations)
        nonce = os.urandom(12)
        aad = b"BAR|v2|" + salt
        ciphertext = AESGCM(key).encrypt(nonce, content, aad)

        envelope = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "salt": base64.b64encode(salt).decode(),
            "kdf_iterations": custom_iterations,
            "encryption_method": "AES-256-GCM",
        }
        decrypted = EncryptionManager.decrypt_file_content(envelope, password)
        self.assertEqual(decrypted, content)


# ===========================================================================
# Test 4 — config.json HMAC integrity
# ===========================================================================
class TestConfigHMACIntegrity(unittest.TestCase):
    def _make_mgr(self, tmp_dir):
        from src.config.config_manager import ConfigManager
        mgr = ConfigManager.__new__(ConfigManager)
        mgr.base_directory = Path(tmp_dir)
        mgr.config_file = Path(tmp_dir) / "config.json"
        mgr.file_validator = MagicMock()
        mgr.logger = logging.getLogger("test_config")
        return mgr

    def _sample_cfg(self, tmp):
        return {"theme": "dark", "file_storage_path": tmp,
                "auto_lock_timeout": 5, "check_updates": False,
                "logging_level": "INFO", "default_security": {}}

    def test_save_creates_sig_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = self._make_mgr(tmp)
            mgr._save_config(self._sample_cfg(tmp))
            sig_path = mgr.config_file.with_suffix(".json.sig")
            self.assertTrue(sig_path.exists())
            self.assertEqual(len(sig_path.read_text().strip()), 64)

    def test_verify_passes_on_unmodified(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = self._make_mgr(tmp)
            mgr._save_config(self._sample_cfg(tmp))
            raw = mgr.config_file.read_bytes()
            self.assertTrue(mgr._verify_config_integrity(raw))

    def test_verify_fails_on_tampered(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = self._make_mgr(tmp)
            mgr._save_config(self._sample_cfg(tmp))
            mgr.config_file.write_text('{"theme":"light"}', encoding="utf-8")
            raw = mgr.config_file.read_bytes()
            self.assertFalse(mgr._verify_config_integrity(raw))

    def test_verify_passes_when_no_sig(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = self._make_mgr(tmp)
            mgr.config_file.write_text('{"theme":"dark"}', encoding="utf-8")
            self.assertTrue(mgr._verify_config_integrity(mgr.config_file.read_bytes()))

    def test_load_falls_back_on_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = self._make_mgr(tmp)
            mgr._save_config(self._sample_cfg(tmp))
            mgr.config_file.write_text(
                '{"theme":"light","auto_lock_timeout":99,"file_storage_path":"'
                + tmp + '","check_updates":false,"logging_level":"INFO","default_security":{}}',
                encoding="utf-8"
            )
            default_cfg = self._sample_cfg(tmp)
            with patch.object(mgr, "_create_default_config", return_value=default_cfg) as mock_d:
                result = mgr._load_config()
                mock_d.assert_called_once()
            self.assertNotEqual(result.get("auto_lock_timeout"), 99)


if __name__ == "__main__":
    unittest.main()
