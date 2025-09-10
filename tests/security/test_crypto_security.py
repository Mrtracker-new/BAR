import unittest
import os
import sys
import time
import hashlib
import base64
from unittest.mock import patch, MagicMock

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from crypto.encryption import EncryptionManager
from security.secure_memory import SecureBytes, SecureString, secure_compare, secure_random_string
from security.secure_delete import SecureDelete


class TestCryptographicSecurity(unittest.TestCase):
    """Test suite for cryptographic security functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.encryption_manager = EncryptionManager()
        self.test_password = "TestPassword123!@#"
        self.test_data = b"This is sensitive test data that should be encrypted."
    
    def test_secure_random_generation(self):
        """Test that secure random generation produces different values."""
        # Test salt generation
        salt1 = EncryptionManager.generate_salt()
        salt2 = EncryptionManager.generate_salt()
        
        self.assertEqual(len(salt1), EncryptionManager.SALT_SIZE)
        self.assertEqual(len(salt2), EncryptionManager.SALT_SIZE)
        self.assertNotEqual(salt1, salt2)
        
        # Test nonce generation
        nonce1 = EncryptionManager.generate_nonce()
        nonce2 = EncryptionManager.generate_nonce()
        
        self.assertEqual(len(nonce1), EncryptionManager.NONCE_SIZE)
        self.assertEqual(len(nonce2), EncryptionManager.NONCE_SIZE)
        self.assertNotEqual(nonce1, nonce2)
    
    def test_key_derivation_security(self):
        """Test key derivation with secure parameters."""
        salt = EncryptionManager.generate_salt()
        
        # Test that same password and salt produce same key
        key1 = EncryptionManager.derive_key(self.test_password, salt)
        key2 = EncryptionManager.derive_key(self.test_password, salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), EncryptionManager.KEY_SIZE)
        
        # Test that different salts produce different keys
        salt2 = EncryptionManager.generate_salt()
        key3 = EncryptionManager.derive_key(self.test_password, salt2)
        
        self.assertNotEqual(key1, key3)
    
    def test_encryption_decryption_security(self):
        """Test encryption/decryption security properties."""
        # Test basic encryption/decryption
        encrypted = EncryptionManager.encrypt_file_content(self.test_data, self.test_password)
        decrypted = EncryptionManager.decrypt_file_content(encrypted, self.test_password)
        
        self.assertEqual(decrypted, self.test_data)
        
        # Test that encrypted data doesn't contain plaintext
        encrypted_bytes = base64.b64decode(encrypted['ciphertext'])
        self.assertNotIn(self.test_data, encrypted_bytes)
        
        # Test that different passwords fail decryption
        with self.assertRaises(ValueError):
            EncryptionManager.decrypt_file_content(encrypted, "WrongPassword")
        
        # Test that tampering with ciphertext fails decryption
        tampered = encrypted.copy()
        tampered_bytes = base64.b64decode(tampered['ciphertext'])
        tampered_bytes = bytearray(tampered_bytes)
        tampered_bytes[0] ^= 1  # Flip one bit
        tampered['ciphertext'] = base64.b64encode(tampered_bytes).decode('utf-8')
        
        with self.assertRaises(ValueError):
            EncryptionManager.decrypt_file_content(tampered, self.test_password)
    
    def test_encryption_input_validation(self):
        """Test input validation in encryption functions."""
        # Test invalid content type
        with self.assertRaises(TypeError):
            EncryptionManager.encrypt_file_content("string", self.test_password)
        
        # Test invalid password type
        with self.assertRaises(TypeError):
            EncryptionManager.encrypt_file_content(self.test_data, 123)
        
        # Test empty password
        with self.assertRaises(ValueError):
            EncryptionManager.encrypt_file_content(self.test_data, "")
        
        # Test empty content
        with self.assertRaises(ValueError):
            EncryptionManager.encrypt_file_content(b"", self.test_password)
        
        # Test oversized content
        large_content = b"x" * (1024 * 1024 * 1024 + 1)  # 1GB + 1 byte
        with self.assertRaises(ValueError):
            EncryptionManager.encrypt_file_content(large_content, self.test_password)
    
    def test_decryption_input_validation(self):
        """Test input validation in decryption functions."""
        valid_encrypted = EncryptionManager.encrypt_file_content(self.test_data, self.test_password)
        
        # Test invalid encrypted_content type
        with self.assertRaises(TypeError):
            EncryptionManager.decrypt_file_content("not_dict", self.test_password)
        
        # Test invalid password type
        with self.assertRaises(TypeError):
            EncryptionManager.decrypt_file_content(valid_encrypted, 123)
        
        # Test empty password
        with self.assertRaises(ValueError):
            EncryptionManager.decrypt_file_content(valid_encrypted, "")
        
        # Test missing required fields
        incomplete_encrypted = {'ciphertext': 'test'}
        with self.assertRaises(ValueError):
            EncryptionManager.decrypt_file_content(incomplete_encrypted, self.test_password)
        
        # Test invalid base64
        invalid_b64 = valid_encrypted.copy()
        invalid_b64['ciphertext'] = 'invalid_base64!'
        with self.assertRaises(ValueError):
            EncryptionManager.decrypt_file_content(invalid_b64, self.test_password)
    
    def test_password_hashing_security(self):
        """Test password hashing security properties."""
        # Test basic password hashing
        password_hash = EncryptionManager.hash_password(self.test_password)
        
        self.assertIn('hash', password_hash)
        self.assertIn('salt', password_hash)
        self.assertIn('method', password_hash)
        self.assertIn('iterations', password_hash)
        
        # Test password verification
        self.assertTrue(EncryptionManager.verify_password(self.test_password, password_hash))
        self.assertFalse(EncryptionManager.verify_password("WrongPassword", password_hash))
        
        # Test that same password produces different hashes (different salts)
        hash1 = EncryptionManager.hash_password(self.test_password)
        hash2 = EncryptionManager.hash_password(self.test_password)
        
        self.assertNotEqual(hash1['hash'], hash2['hash'])
        self.assertNotEqual(hash1['salt'], hash2['salt'])


class TestSecureMemoryManagement(unittest.TestCase):
    """Test suite for secure memory management."""
    
    def test_secure_bytes_basic_functionality(self):
        """Test basic SecureBytes functionality."""
        test_data = b"sensitive data"
        
        with SecureBytes(test_data) as sb:
            self.assertEqual(sb.get_bytes(), test_data)
            self.assertEqual(len(sb), len(test_data))
            self.assertTrue(bool(sb))
        
        # Test string input
        test_string = "sensitive string"
        with SecureBytes(test_string) as sb:
            self.assertEqual(sb.get_string(), test_string)
    
    def test_secure_string_functionality(self):
        """Test SecureString functionality."""
        test_string = "sensitive password"
        
        with SecureString(test_string) as ss:
            self.assertEqual(ss.get_value(), test_string)
            self.assertEqual(ss.get_string(), test_string)
        
        # Test set_value
        ss = SecureString("initial")
        ss.set_value("updated")
        self.assertEqual(ss.get_value(), "updated")
        ss.clear()
    
    def test_secure_memory_clearing(self):
        """Test that secure memory is properly cleared."""
        test_data = "sensitive data"
        
        sb = SecureBytes(test_data)
        self.assertTrue(bool(sb))
        
        sb.clear()
        self.assertFalse(bool(sb))
        self.assertEqual(len(sb), 0)
    
    def test_secure_compare_function(self):
        """Test constant-time comparison function."""
        # Test identical strings
        self.assertTrue(secure_compare("test", "test"))
        self.assertTrue(secure_compare(b"test", b"test"))
        
        # Test different strings
        self.assertFalse(secure_compare("test1", "test2"))
        self.assertFalse(secure_compare(b"test1", b"test2"))
        
        # Test mixed types
        self.assertTrue(secure_compare("test", b"test"))
        self.assertFalse(secure_compare("test1", b"test2"))
        
        # Test empty strings
        self.assertTrue(secure_compare("", ""))
        self.assertFalse(secure_compare("", "test"))
    
    def test_secure_random_string_generation(self):
        """Test secure random string generation."""
        # Test default charset
        random1 = secure_random_string(16)
        random2 = secure_random_string(16)
        
        self.assertEqual(len(random1), 16)
        self.assertEqual(len(random2), 16)
        self.assertNotEqual(random1, random2)
        
        # Test custom charset
        hex_string = secure_random_string(8, "0123456789ABCDEF")
        self.assertEqual(len(hex_string), 8)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in hex_string))


class TestSecureFileDeltion(unittest.TestCase):
    """Test suite for secure file deletion."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.secure_delete = SecureDelete()
        self.test_file = "test_secure_delete.tmp"
        self.test_content = b"This is sensitive data that should be securely deleted."
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.test_file):
            try:
                os.remove(self.test_file)
            except OSError:
                pass
    
    def test_secure_file_deletion(self):
        """Test secure file deletion functionality."""
        # Create test file
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)
        
        self.assertTrue(os.path.exists(self.test_file))
        
        # Securely delete file
        result = self.secure_delete.secure_delete_file(self.test_file)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.test_file))
    
    def test_secure_deletion_uses_multiple_passes(self):
        """Test that secure deletion uses multiple passes."""
        # This test verifies that the default number of passes is appropriate for security
        self.assertEqual(SecureDelete.DEFAULT_PASSES, 7)
    
    def test_secure_deletion_nonexistent_file(self):
        """Test secure deletion of non-existent file."""
        result = self.secure_delete.secure_delete_file("nonexistent_file.tmp")
        self.assertFalse(result)


class TestTimingAttackResistance(unittest.TestCase):
    """Test suite for timing attack resistance."""
    
    def test_constant_time_comparison(self):
        """Test that comparison functions are resistant to timing attacks."""
        # This is a basic test - full timing analysis would require more sophisticated tools
        correct_password = "correct_password_123"
        wrong_password1 = "wrong_password_456"
        wrong_password2 = "x"  # Very different length
        
        # Time multiple comparisons
        times = []
        for _ in range(100):
            start_time = time.perf_counter()
            secure_compare(correct_password, wrong_password1)
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        avg_time1 = sum(times) / len(times)
        
        times = []
        for _ in range(100):
            start_time = time.perf_counter()
            secure_compare(correct_password, wrong_password2)
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        avg_time2 = sum(times) / len(times)
        
        # The timing difference should be minimal (within reasonable bounds)
        # This is not a perfect test but provides basic validation
        time_ratio = max(avg_time1, avg_time2) / min(avg_time1, avg_time2)
        self.assertLess(time_ratio, 10.0)  # Should not differ by more than 10x


class TestCryptographicRandomness(unittest.TestCase):
    """Test suite for cryptographic randomness quality."""
    
    def test_randomness_distribution(self):
        """Test basic randomness distribution properties."""
        # Generate multiple random bytes and test basic properties
        random_data = [os.urandom(256) for _ in range(100)]
        
        # Test that all samples are different
        unique_samples = set(random_data)
        self.assertEqual(len(unique_samples), len(random_data))
        
        # Test byte distribution (should be roughly uniform)
        all_bytes = b''.join(random_data)
        byte_counts = [0] * 256
        
        for byte_val in all_bytes:
            byte_counts[byte_val] += 1
        
        # Check that no byte value is completely missing or overly represented
        min_count = min(byte_counts)
        max_count = max(byte_counts)
        
        self.assertGreater(min_count, 0)  # No byte value should be completely missing
        self.assertLess(max_count / min_count, 10)  # No byte should be 10x more common


if __name__ == '__main__':
    # Create test directory if it doesn't exist
    os.makedirs('tests/security', exist_ok=True)
    
    unittest.main()
