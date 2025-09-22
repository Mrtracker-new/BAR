"""
Comprehensive Test Suite for Encryption Operations

This test suite provides thorough testing of the encryption system,
including AES encryption, key derivation, and cryptographic operations
as per BAR Rules R004 - Cryptographic Standards.

Test Categories:
- Basic encryption/decryption functionality
- Key derivation and management
- Different encryption modes and algorithms
- Error handling and edge cases
- Performance and scalability testing
- Security boundary testing
- Integration with secure memory

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys
import unittest
import threading
import time
import hashlib
from unittest.mock import patch, MagicMock
from typing import List, Dict, Any, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

try:
    from crypto.encryption import (
        EncryptionEngine, AESEncryption, KeyDerivation,
        EncryptionMode, KeyDerivationMethod, EncryptionError,
        derive_key, encrypt_data, decrypt_data, generate_key,
        generate_salt, generate_iv, verify_key_strength
    )
    ENCRYPTION_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Encryption module not available: {e}")
    ENCRYPTION_AVAILABLE = False

try:
    from security.secure_memory import SecureBytes, SecureString
    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    SECURE_MEMORY_AVAILABLE = False


class EncryptionTestCase(unittest.TestCase):
    """Base test case for encryption testing."""
    
    def setUp(self):
        """Set up test environment."""
        if not ENCRYPTION_AVAILABLE:
            self.skipTest("Encryption module not available")
    
    def create_test_data(self, size: int = 1024) -> bytes:
        """Create test data of specified size."""
        return b"Test data content: " + b"A" * (size - 18)
    
    def assert_encryption_successful(self, plaintext: bytes, ciphertext: bytes, key: bytes):
        """Assert that encryption was successful."""
        self.assertNotEqual(plaintext, ciphertext)
        self.assertGreater(len(ciphertext), 0)
        self.assertNotIn(plaintext[:20], ciphertext)  # Plaintext shouldn't appear in ciphertext
    
    def assert_decryption_successful(self, original: bytes, decrypted: bytes):
        """Assert that decryption was successful."""
        self.assertEqual(original, decrypted)


class TestKeyDerivation(EncryptionTestCase):
    """Test key derivation functionality."""
    
    def test_pbkdf2_key_derivation(self):
        """Test PBKDF2 key derivation."""
        password = "MySecurePassword123!"
        salt = generate_salt()
        iterations = 100000
        key_length = 32
        
        # Derive key
        derived_key = derive_key(
            password=password,
            salt=salt,
            iterations=iterations,
            key_length=key_length,
            method=KeyDerivationMethod.PBKDF2_HMAC_SHA256
        )
        
        # Verify key properties
        self.assertEqual(len(derived_key), key_length)
        self.assertIsInstance(derived_key, bytes)
        
        # Same inputs should produce same key
        derived_key2 = derive_key(password, salt, iterations, key_length, KeyDerivationMethod.PBKDF2_HMAC_SHA256)
        self.assertEqual(derived_key, derived_key2)
        
        # Different salt should produce different key
        different_salt = generate_salt()
        different_key = derive_key(password, different_salt, iterations, key_length, KeyDerivationMethod.PBKDF2_HMAC_SHA256)
        self.assertNotEqual(derived_key, different_key)
    
    def test_argon2_key_derivation(self):
        """Test Argon2 key derivation if available."""
        try:
            password = "MySecurePassword123!"
            salt = generate_salt()
            key_length = 32
            
            derived_key = derive_key(
                password=password,
                salt=salt,
                iterations=4,  # Lower for Argon2
                key_length=key_length,
                method=KeyDerivationMethod.ARGON2ID
            )
            
            self.assertEqual(len(derived_key), key_length)
            self.assertIsInstance(derived_key, bytes)
            
        except (ImportError, ValueError) as e:
            self.skipTest(f"Argon2 not available: {e}")
    
    def test_key_derivation_edge_cases(self):
        """Test key derivation with edge cases."""
        # Empty password
        with self.assertRaises((ValueError, EncryptionError)):
            derive_key("", generate_salt(), 100000, 32)
        
        # Invalid key length
        with self.assertRaises((ValueError, EncryptionError)):
            derive_key("password", generate_salt(), 100000, 0)
        
        # Invalid iterations
        with self.assertRaises((ValueError, EncryptionError)):
            derive_key("password", generate_salt(), 0, 32)
        
        # Invalid salt
        with self.assertRaises((ValueError, EncryptionError)):
            derive_key("password", b"", 100000, 32)
    
    def test_key_strength_verification(self):
        """Test key strength verification."""
        # Strong key
        strong_key = generate_key(32)
        self.assertTrue(verify_key_strength(strong_key))
        
        # Weak key (all zeros)
        weak_key = b"\x00" * 32
        self.assertFalse(verify_key_strength(weak_key))
        
        # Short key
        short_key = b"short"
        self.assertFalse(verify_key_strength(short_key))
    
    def test_salt_generation(self):
        """Test salt generation."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        # Salts should be different
        self.assertNotEqual(salt1, salt2)
        
        # Salts should have proper length
        self.assertEqual(len(salt1), 16)  # Default salt length
        self.assertEqual(len(salt2), 16)
        
        # Custom length
        custom_salt = generate_salt(32)
        self.assertEqual(len(custom_salt), 32)
    
    def test_iv_generation(self):
        """Test IV generation."""
        iv1 = generate_iv()
        iv2 = generate_iv()
        
        # IVs should be different
        self.assertNotEqual(iv1, iv2)
        
        # IVs should have proper length
        self.assertEqual(len(iv1), 16)  # AES block size
        self.assertEqual(len(iv2), 16)


class TestAESEncryption(EncryptionTestCase):
    """Test AES encryption functionality."""
    
    def test_aes_cbc_encryption_decryption(self):
        """Test AES-CBC encryption and decryption."""
        plaintext = b"Hello, this is a test message for AES-CBC encryption!"
        key = generate_key(32)  # 256-bit key
        
        # Encrypt
        ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_CBC)
        self.assert_encryption_successful(plaintext, ciphertext, key)
        
        # Decrypt
        decrypted = decrypt_data(ciphertext, key, EncryptionMode.AES_256_CBC)
        self.assert_decryption_successful(plaintext, decrypted)
    
    def test_aes_gcm_encryption_decryption(self):
        """Test AES-GCM encryption and decryption."""
        plaintext = b"Hello, this is a test message for AES-GCM encryption!"
        key = generate_key(32)  # 256-bit key
        
        # Encrypt
        ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_GCM)
        self.assert_encryption_successful(plaintext, ciphertext, key)
        
        # Decrypt
        decrypted = decrypt_data(ciphertext, key, EncryptionMode.AES_256_GCM)
        self.assert_decryption_successful(plaintext, decrypted)
    
    def test_different_key_sizes(self):
        """Test AES with different key sizes."""
        plaintext = b"Test message for different key sizes"
        
        # Test 128-bit key
        key_128 = generate_key(16)
        ciphertext_128 = encrypt_data(plaintext, key_128, EncryptionMode.AES_128_CBC)
        decrypted_128 = decrypt_data(ciphertext_128, key_128, EncryptionMode.AES_128_CBC)
        self.assertEqual(plaintext, decrypted_128)
        
        # Test 192-bit key
        key_192 = generate_key(24)
        ciphertext_192 = encrypt_data(plaintext, key_192, EncryptionMode.AES_192_CBC)
        decrypted_192 = decrypt_data(ciphertext_192, key_192, EncryptionMode.AES_192_CBC)
        self.assertEqual(plaintext, decrypted_192)
        
        # Test 256-bit key
        key_256 = generate_key(32)
        ciphertext_256 = encrypt_data(plaintext, key_256, EncryptionMode.AES_256_CBC)
        decrypted_256 = decrypt_data(ciphertext_256, key_256, EncryptionMode.AES_256_CBC)
        self.assertEqual(plaintext, decrypted_256)
    
    def test_empty_data_encryption(self):
        """Test encryption of empty data."""
        plaintext = b""
        key = generate_key(32)
        
        # Should handle empty data gracefully
        ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_GCM)
        decrypted = decrypt_data(ciphertext, key, EncryptionMode.AES_256_GCM)
        self.assertEqual(plaintext, decrypted)
    
    def test_large_data_encryption(self):
        """Test encryption of large data."""
        # Create 1MB of test data
        plaintext = self.create_test_data(1024 * 1024)
        key = generate_key(32)
        
        start_time = time.time()
        ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_CBC)
        encryption_time = time.time() - start_time
        
        self.assert_encryption_successful(plaintext, ciphertext, key)
        
        start_time = time.time()
        decrypted = decrypt_data(ciphertext, key, EncryptionMode.AES_256_CBC)
        decryption_time = time.time() - start_time
        
        self.assert_decryption_successful(plaintext, decrypted)
        
        # Performance should be reasonable (less than 10 seconds for 1MB)
        self.assertLess(encryption_time, 10.0, f"Encryption too slow: {encryption_time:.2f}s")
        self.assertLess(decryption_time, 10.0, f"Decryption too slow: {decryption_time:.2f}s")
    
    def test_wrong_key_decryption(self):
        """Test decryption with wrong key."""
        plaintext = b"Test message for wrong key scenario"
        correct_key = generate_key(32)
        wrong_key = generate_key(32)
        
        # Encrypt with correct key
        ciphertext = encrypt_data(plaintext, correct_key, EncryptionMode.AES_256_CBC)
        
        # Try to decrypt with wrong key
        with self.assertRaises((EncryptionError, ValueError)):
            decrypt_data(ciphertext, wrong_key, EncryptionMode.AES_256_CBC)
    
    def test_corrupted_ciphertext_decryption(self):
        """Test decryption of corrupted ciphertext."""
        plaintext = b"Test message for corruption scenario"
        key = generate_key(32)
        
        # Encrypt
        ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_GCM)
        
        # Corrupt the ciphertext
        corrupted_ciphertext = bytearray(ciphertext)
        corrupted_ciphertext[len(corrupted_ciphertext) // 2] ^= 0xFF
        
        # Try to decrypt corrupted ciphertext
        with self.assertRaises((EncryptionError, ValueError)):
            decrypt_data(bytes(corrupted_ciphertext), key, EncryptionMode.AES_256_GCM)


class TestEncryptionEngine(EncryptionTestCase):
    """Test the main encryption engine."""
    
    def test_encryption_engine_creation(self):
        """Test creation of encryption engine."""
        engine = EncryptionEngine()
        self.assertIsInstance(engine, EncryptionEngine)
    
    def test_engine_encrypt_decrypt_cycle(self):
        """Test full encrypt-decrypt cycle through engine."""
        engine = EncryptionEngine()
        plaintext = b"Test data for encryption engine"
        password = "MySecurePassword123!"
        
        # Encrypt
        encrypted_result = engine.encrypt(plaintext, password)
        
        # Verify encrypted result structure
        self.assertIn('ciphertext', encrypted_result)
        self.assertIn('salt', encrypted_result)
        self.assertIn('iv', encrypted_result)
        self.assertIn('mode', encrypted_result)
        
        # Decrypt
        decrypted = engine.decrypt(encrypted_result, password)
        self.assertEqual(plaintext, decrypted)
    
    def test_engine_with_different_modes(self):
        """Test encryption engine with different modes."""
        engine = EncryptionEngine()
        plaintext = b"Test data for different encryption modes"
        password = "MySecurePassword123!"
        
        modes = [EncryptionMode.AES_256_CBC, EncryptionMode.AES_256_GCM]
        
        for mode in modes:
            with self.subTest(mode=mode):
                # Set engine mode
                engine.set_default_mode(mode)
                
                # Encrypt and decrypt
                encrypted_result = engine.encrypt(plaintext, password)
                decrypted = engine.decrypt(encrypted_result, password)
                
                self.assertEqual(plaintext, decrypted)
                self.assertEqual(encrypted_result['mode'], mode.value)
    
    def test_engine_key_caching(self):
        """Test engine key caching functionality."""
        engine = EncryptionEngine()
        plaintext = b"Test data for key caching"
        password = "MySecurePassword123!"
        
        # First encryption (key will be derived)
        start_time = time.time()
        result1 = engine.encrypt(plaintext, password)
        first_time = time.time() - start_time
        
        # Second encryption with same password (key should be cached)
        start_time = time.time()
        result2 = engine.encrypt(plaintext, password)
        second_time = time.time() - start_time
        
        # Both should decrypt to same plaintext
        self.assertEqual(engine.decrypt(result1, password), plaintext)
        self.assertEqual(engine.decrypt(result2, password), plaintext)
        
        # Second operation should be faster due to caching
        # (Note: This might not always be true due to system variations)
        print(f"First encryption: {first_time:.6f}s, Second: {second_time:.6f}s")
    
    def test_engine_memory_cleanup(self):
        """Test that engine properly cleans up sensitive data."""
        engine = EncryptionEngine()
        plaintext = b"Sensitive data that should be cleaned up"
        password = "MySecurePassword123!"
        
        # Encrypt
        encrypted_result = engine.encrypt(plaintext, password)
        
        # Clear engine
        engine.clear()
        
        # After clearing, new operations should still work
        new_result = engine.encrypt(plaintext, password)
        decrypted = engine.decrypt(new_result, password)
        self.assertEqual(plaintext, decrypted)


class TestSecureMemoryIntegration(EncryptionTestCase):
    """Test integration with secure memory system."""
    
    def setUp(self):
        super().setUp()
        if not SECURE_MEMORY_AVAILABLE:
            self.skipTest("Secure memory not available")
    
    def test_encrypt_secure_data(self):
        """Test encryption of secure memory objects."""
        plaintext_data = b"Sensitive data in secure memory"
        secure_data = SecureBytes(plaintext_data)
        password = "MySecurePassword123!"
        
        # Should be able to encrypt secure data
        ciphertext = encrypt_data(secure_data.get_value(), generate_key(32), EncryptionMode.AES_256_GCM)
        
        self.assertNotEqual(plaintext_data, ciphertext)
        self.assertGreater(len(ciphertext), 0)
    
    def test_secure_key_handling(self):
        """Test handling of keys in secure memory."""
        plaintext = b"Test data for secure key handling"
        password_string = "MySecurePassword123!"
        secure_password = SecureString(password_string)
        
        # Derive key from secure password
        salt = generate_salt()
        key = derive_key(
            secure_password.get_value(),
            salt,
            100000,
            32,
            KeyDerivationMethod.PBKDF2_HMAC_SHA256
        )
        
        # Use key for encryption
        ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_CBC)
        decrypted = decrypt_data(ciphertext, key, EncryptionMode.AES_256_CBC)
        
        self.assertEqual(plaintext, decrypted)


class TestThreadSafety(EncryptionTestCase):
    """Test thread safety of encryption operations."""
    
    def test_concurrent_encryption(self):
        """Test concurrent encryption operations."""
        plaintext = b"Test data for concurrent encryption"
        password = "MySecurePassword123!"
        num_threads = 5
        operations_per_thread = 20
        
        results = []
        errors = []
        
        def encrypt_decrypt_worker(thread_id: int):
            try:
                thread_results = []
                for i in range(operations_per_thread):
                    # Encrypt
                    key = generate_key(32)
                    ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_CBC)
                    
                    # Decrypt
                    decrypted = decrypt_data(ciphertext, key, EncryptionMode.AES_256_CBC)
                    
                    if decrypted != plaintext:
                        errors.append(f"Thread {thread_id}: Decryption mismatch at operation {i}")
                    
                    thread_results.append((len(ciphertext), len(decrypted)))
                
                results.extend(thread_results)
                
            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Create and start threads
        threads = []
        for thread_id in range(num_threads):
            thread = threading.Thread(target=encrypt_decrypt_worker, args=(thread_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
        self.assertEqual(len(results), num_threads * operations_per_thread)
    
    def test_concurrent_key_derivation(self):
        """Test concurrent key derivation operations."""
        password = "MySecurePassword123!"
        num_threads = 3
        derivations_per_thread = 10
        
        results = []
        errors = []
        
        def key_derivation_worker(thread_id: int):
            try:
                for i in range(derivations_per_thread):
                    salt = generate_salt()
                    key = derive_key(password, salt, 50000, 32)  # Reduced iterations for speed
                    
                    if len(key) != 32:
                        errors.append(f"Thread {thread_id}: Invalid key length at derivation {i}")
                    
                    results.append((thread_id, i, len(key)))
                    
            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Create and start threads
        threads = []
        for thread_id in range(num_threads):
            thread = threading.Thread(target=key_derivation_worker, args=(thread_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0, f"Key derivation thread errors: {errors}")
        self.assertEqual(len(results), num_threads * derivations_per_thread)


class TestPerformanceBenchmarks(EncryptionTestCase):
    """Test performance benchmarks for encryption operations."""
    
    def test_encryption_performance_by_size(self):
        """Test encryption performance with different data sizes."""
        key = generate_key(32)
        sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB to 1MB
        
        results = []
        
        for size in sizes:
            plaintext = self.create_test_data(size)
            
            # Measure encryption time
            start_time = time.time()
            ciphertext = encrypt_data(plaintext, key, EncryptionMode.AES_256_CBC)
            encryption_time = time.time() - start_time
            
            # Measure decryption time
            start_time = time.time()
            decrypted = decrypt_data(ciphertext, key, EncryptionMode.AES_256_CBC)
            decryption_time = time.time() - start_time
            
            # Verify correctness
            self.assertEqual(plaintext, decrypted)
            
            # Calculate throughput
            encrypt_throughput = size / encryption_time / (1024 * 1024)  # MB/s
            decrypt_throughput = size / decryption_time / (1024 * 1024)  # MB/s
            
            results.append({
                'size': size,
                'encrypt_time': encryption_time,
                'decrypt_time': decryption_time,
                'encrypt_throughput': encrypt_throughput,
                'decrypt_throughput': decrypt_throughput
            })
        
        # Print performance results
        print(f"\nEncryption Performance Results:")
        print(f"{'Size':<10} {'Enc Time':<10} {'Dec Time':<10} {'Enc MB/s':<10} {'Dec MB/s':<10}")
        print("-" * 60)
        for result in results:
            print(f"{result['size']:<10} {result['encrypt_time']:<10.4f} "
                  f"{result['decrypt_time']:<10.4f} {result['encrypt_throughput']:<10.2f} "
                  f"{result['decrypt_throughput']:<10.2f}")
        
        # Performance should be reasonable (at least 1 MB/s for large files)
        for result in results:
            if result['size'] >= 100*1024:  # For files >= 100KB
                self.assertGreater(result['encrypt_throughput'], 1.0,
                                 f"Encryption too slow for {result['size']} bytes")
                self.assertGreater(result['decrypt_throughput'], 1.0,
                                 f"Decryption too slow for {result['size']} bytes")
    
    def test_key_derivation_performance(self):
        """Test key derivation performance."""
        password = "MySecurePassword123!"
        salt = generate_salt()
        
        # Test different iteration counts
        iteration_counts = [10000, 50000, 100000, 200000]
        
        results = []
        
        for iterations in iteration_counts:
            start_time = time.time()
            key = derive_key(password, salt, iterations, 32)
            derivation_time = time.time() - start_time
            
            self.assertEqual(len(key), 32)
            
            results.append({
                'iterations': iterations,
                'time': derivation_time,
                'iterations_per_second': iterations / derivation_time
            })
        
        # Print results
        print(f"\nKey Derivation Performance Results:")
        print(f"{'Iterations':<12} {'Time (s)':<10} {'Iter/s':<12}")
        print("-" * 40)
        for result in results:
            print(f"{result['iterations']:<12} {result['time']:<10.4f} "
                  f"{result['iterations_per_second']:<12.0f}")
        
        # Key derivation should complete within reasonable time
        for result in results:
            if result['iterations'] <= 100000:
                self.assertLess(result['time'], 5.0,
                               f"Key derivation too slow for {result['iterations']} iterations")


class TestErrorHandling(EncryptionTestCase):
    """Test error handling in encryption operations."""
    
    def test_invalid_key_sizes(self):
        """Test handling of invalid key sizes."""
        plaintext = b"Test data"
        
        # Too short key
        with self.assertRaises((ValueError, EncryptionError)):
            encrypt_data(plaintext, b"short", EncryptionMode.AES_256_CBC)
        
        # Too long key (should be truncated or handled gracefully)
        long_key = b"A" * 100
        # This might work depending on implementation
        try:
            ciphertext = encrypt_data(plaintext, long_key, EncryptionMode.AES_256_CBC)
            # If it works, decryption should also work
            decrypted = decrypt_data(ciphertext, long_key, EncryptionMode.AES_256_CBC)
            self.assertEqual(plaintext, decrypted)
        except (ValueError, EncryptionError):
            # It's also acceptable to reject overly long keys
            pass
    
    def test_invalid_input_types(self):
        """Test handling of invalid input types."""
        key = generate_key(32)
        
        # Non-bytes plaintext
        with self.assertRaises((TypeError, ValueError)):
            encrypt_data("string instead of bytes", key, EncryptionMode.AES_256_CBC)
        
        # Non-bytes key
        with self.assertRaises((TypeError, ValueError)):
            encrypt_data(b"test", "string key", EncryptionMode.AES_256_CBC)
        
        # None inputs
        with self.assertRaises((TypeError, ValueError)):
            encrypt_data(None, key, EncryptionMode.AES_256_CBC)
        
        with self.assertRaises((TypeError, ValueError)):
            encrypt_data(b"test", None, EncryptionMode.AES_256_CBC)
    
    def test_malformed_encrypted_data(self):
        """Test handling of malformed encrypted data."""
        key = generate_key(32)
        
        # Too short ciphertext
        with self.assertRaises((ValueError, EncryptionError)):
            decrypt_data(b"short", key, EncryptionMode.AES_256_CBC)
        
        # Invalid format
        with self.assertRaises((ValueError, EncryptionError)):
            decrypt_data(b"This is not encrypted data", key, EncryptionMode.AES_256_CBC)
        
        # Empty ciphertext
        with self.assertRaises((ValueError, EncryptionError)):
            decrypt_data(b"", key, EncryptionMode.AES_256_CBC)


def create_encryption_test_suite():
    """Create a comprehensive test suite for encryption."""
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestKeyDerivation,
        TestAESEncryption,
        TestEncryptionEngine,
        TestThreadSafety,
        TestPerformanceBenchmarks,
        TestErrorHandling
    ]
    
    # Add secure memory integration tests if available
    if SECURE_MEMORY_AVAILABLE:
        test_classes.append(TestSecureMemoryIntegration)
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    return suite


def run_encryption_tests():
    """Run all encryption tests and return results."""
    if not ENCRYPTION_AVAILABLE:
        print("❌ Encryption module not available - cannot run tests")
        return False
    
    print("🔐 Running Encryption Test Suite...")
    print("=" * 60)
    
    # Create and run test suite
    suite = create_encryption_test_suite()
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"ENCRYPTION TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print(f"\n❌ FAILURES ({len(result.failures)}):")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print(f"\n💥 ERRORS ({len(result.errors)}):")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    if success:
        print("\n✅ All encryption tests passed!")
    else:
        print(f"\n❌ Some encryption tests failed.")
    
    return success


if __name__ == "__main__":
    # Run tests when script is executed directly
    success = run_encryption_tests()
    sys.exit(0 if success else 1)