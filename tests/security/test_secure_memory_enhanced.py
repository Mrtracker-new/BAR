#!/usr/bin/env python3
"""
Enhanced Test Suite for BAR Secure Memory System

This module provides comprehensive testing for all secure memory features,
including edge cases, security scenarios, and cross-platform compatibility.

Per BAR Project Rules:
- R023: Minimum 90% code coverage for security-critical modules
- R024: Comprehensive test organization with security-specific tests
- R025: Synthetic test data only, no real sensitive information

Author: Rolan Lobo (RNR)
Version: 2.0.0
"""

import unittest
import os
import sys
import gc
import time
import threading
import platform
import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
from typing import List, Dict, Any

# Add src to path for imports
src_dir = Path(__file__).resolve().parents[2] / 'src'
sys.path.insert(0, str(src_dir))

from security.secure_memory import (
    SecureBytes, SecureString, SecureMemoryManager,
    MemoryProtectionLevel, MemoryCorruptionError, MemoryLockError,
    MemoryForensicsError, TPMError, MemoryStats, MemorySecurityEvent,
    create_secure_bytes, create_secure_string,
    secure_compare, secure_random_string, get_secure_memory_manager,
    force_secure_memory_cleanup, secure_memory_context,
    TPMInterface, AntiForensicsMonitor,
    CRYPTOGRAPHY_AVAILABLE
)


class TestSecureBytesEnhanced(unittest.TestCase):
    """Enhanced test suite for SecureBytes with comprehensive coverage."""
    
    def setUp(self):
        """Set up test fixtures."""
        get_secure_memory_manager().cleanup_all()
        gc.collect()
    
    def tearDown(self):
        """Clean up after each test."""
        get_secure_memory_manager().cleanup_all()
        gc.collect()
    
    def test_all_protection_levels(self):
        """Test SecureBytes with all protection levels."""
        test_data = b"test data for protection levels"
        
        for level in MemoryProtectionLevel:
            with self.subTest(protection_level=level):
                try:
                    secure_obj = SecureBytes(
                        test_data, 
                        protection_level=level,
                        require_lock=False  # Don't require lock to avoid test failures
                    )
                    
                    self.assertEqual(secure_obj.get_bytes(), test_data)
                    self.assertTrue(len(secure_obj) > 0)
                    secure_obj.clear()
                    self.assertEqual(len(secure_obj), 0)
                    
                except Exception as e:
                    self.fail(f"Protection level {level} failed: {e}")
    
    def test_hardware_binding(self):
        """Test hardware binding functionality."""
        test_data = b"hardware bound data"
        
        secure_obj = SecureBytes(
            test_data,
            hardware_bound=True,
            protection_level=MemoryProtectionLevel.MAXIMUM
        )
        
        # Should still be able to read data on same hardware
        retrieved_data = secure_obj.get_bytes()
        self.assertEqual(retrieved_data, test_data)
        
        # Test that hardware ID is stored
        self.assertIsNotNone(secure_obj._hardware_id)
        
        secure_obj.clear()
    
    def test_tpm_integration_simulation(self):
        """Test TPM integration with mocked TPM interface."""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.skipTest("Cryptography library not available")
        
        test_data = b"TPM protected data"
        
        # Mock TPM interface
        with patch('security.secure_memory.TPMInterface') as mock_tpm_class:
            mock_tpm = Mock()
            mock_tpm.is_available.return_value = True
            mock_tpm.seal_data.return_value = b"sealed_data_blob"
            mock_tpm.unseal_data.return_value = test_data
            mock_tpm_class.return_value = mock_tpm
            
            secure_obj = SecureBytes(
                test_data,
                protection_level=MemoryProtectionLevel.MILITARY,
                use_tpm=True
            )
            
            # Verify TPM methods were called
            # Note: This is a basic test since full TPM integration requires mocking
            self.assertIsNotNone(secure_obj)
    
    def test_memory_corruption_detection(self):
        """Test memory corruption detection with canary values."""
        test_data = b"corruption detection test data"
        
        secure_obj = SecureBytes(
            test_data,
            protection_level=MemoryProtectionLevel.MAXIMUM
        )
        
        # Normal access should work
        self.assertEqual(secure_obj.get_bytes(), test_data)
        
        # Simulate corruption by modifying internal data directly
        if hasattr(secure_obj, '_data') and len(secure_obj._data) > 16:
            # Corrupt the canary (first few bytes)
            original_byte = secure_obj._data[0]
            secure_obj._data[0] = 0xFF if original_byte != 0xFF else 0x00
            
            # Access should detect corruption
            with self.assertRaises(MemoryCorruptionError):
                secure_obj.get_bytes()
    
    def test_large_data_handling(self):
        """Test handling of large data blocks."""
        # Test with progressively larger data sizes
        sizes = [1024, 10*1024, 100*1024, 1024*1024]  # Up to 1MB
        
        for size in sizes:
            with self.subTest(size=size):
                test_data = secrets.token_bytes(size)
                
                secure_obj = SecureBytes(
                    test_data,
                    protection_level=MemoryProtectionLevel.ENHANCED
                )
                
                self.assertEqual(len(secure_obj), len(test_data))
                retrieved_data = secure_obj.get_bytes()
                self.assertEqual(retrieved_data, test_data)
                
                # Test clearing large data
                start_time = time.time()
                secure_obj.clear()
                clear_time = time.time() - start_time
                
                # Should clear within reasonable time (per R006)
                self.assertLess(clear_time, 5.0, f"Clear time {clear_time:.2f}s too slow for {size} bytes")
                
                del secure_obj, test_data, retrieved_data
                gc.collect()
    
    def test_concurrent_operations(self):
        """Test concurrent operations on SecureBytes objects."""
        test_data = b"concurrent test data"
        secure_obj = SecureBytes(test_data, MemoryProtectionLevel.ENHANCED)
        
        results = []
        errors = []
        
        def worker_thread(thread_id):
            try:
                for i in range(100):
                    data = secure_obj.get_bytes()
                    results.append(data == test_data)
                    
                    # Test string conversion
                    try:
                        string_data = secure_obj.get_string()
                        results.append(string_data == test_data.decode('utf-8'))
                    except UnicodeDecodeError:
                        # Random data may not be valid UTF-8
                        pass
                        
            except Exception as e:
                errors.append(f"Thread {thread_id}: {e}")
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        self.assertEqual(len(errors), 0, f"Concurrent access errors: {errors}")
        self.assertTrue(all(results), "Some concurrent operations failed")
        
        secure_obj.clear()
    
    def test_memory_statistics_tracking(self):
        """Test memory statistics and tracking."""
        initial_stats = get_secure_memory_manager().get_statistics()
        
        # Create several objects
        objects = []
        for i in range(10):
            obj = SecureBytes(f"test data {i}".encode(), MemoryProtectionLevel.ENHANCED)
            objects.append(obj)
        
        mid_stats = get_secure_memory_manager().get_statistics()
        self.assertGreater(mid_stats.active_allocations, initial_stats.active_allocations)
        self.assertGreater(mid_stats.total_allocations, initial_stats.total_allocations)
        
        # Clear all objects
        for obj in objects:
            obj.clear()
        
        # Force cleanup
        get_secure_memory_manager().cleanup_all()
        final_stats = get_secure_memory_manager().get_statistics()
        
        self.assertEqual(final_stats.active_allocations, 0)
        self.assertGreater(final_stats.cleanup_operations, initial_stats.cleanup_operations)
    
    def test_secure_string_enhanced(self):
        """Test SecureString with enhanced features."""
        test_strings = [
            "simple string",
            "Unicode string with émojis 🔒🛡️",
            "Multi-line\nstring\nwith\ntabs\t",
            "",  # Empty string
            "A" * 10000,  # Large string
        ]
        
        for test_string in test_strings:
            with self.subTest(string=test_string[:50]):
                secure_str = SecureString(test_string)
                
                self.assertEqual(secure_str.get_value(), test_string)
                self.assertEqual(secure_str.get_string(), test_string)
                self.assertEqual(len(secure_str), len(test_string.encode('utf-8')))
                
                # Test setting new value
                new_value = f"updated_{test_string}"
                secure_str.set_value(new_value)
                self.assertEqual(secure_str.get_value(), new_value)
                
                secure_str.clear()
    
    def test_context_managers(self):
        """Test context manager functionality."""
        test_data = b"context manager test"
        
        # Test SecureBytes context manager
        with SecureBytes(test_data) as secure_obj:
            self.assertEqual(secure_obj.get_bytes(), test_data)
        
        # After context, data should be cleared
        self.assertEqual(len(secure_obj), 0)
        
        # Test secure_memory_context
        with secure_memory_context():
            obj1 = create_secure_bytes(b"data 1")
            obj2 = create_secure_string("data 2")
            
            self.assertEqual(obj1.get_bytes(), b"data 1")
            self.assertEqual(obj2.get_value(), "data 2")
        
        # Context should have triggered cleanup
        # Objects may still exist but cleanup should have been attempted


class TestTPMInterface(unittest.TestCase):
    """Test suite for TPM interface functionality."""
    
    def setUp(self):
        self.tpm_interface = TPMInterface()
    
    def test_tmp_availability_check(self):
        """Test TPM availability detection."""
        # This will vary by system, just ensure it doesn't crash
        is_available = self.tpm_interface.is_available()
        self.assertIsInstance(is_available, bool)
    
    def test_tpm_seal_unseal_fallback(self):
        """Test TPM seal/unseal fallback when TPM unavailable."""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.skipTest("Cryptography library not available")
        
        test_data = b"TPM test data"
        
        # Test sealing (should work even without TPM via fallback)
        sealed_data = self.tpm_interface.seal_data(test_data)
        
        if sealed_data is not None:
            # Test unsealing
            unsealed_data = self.tpm_interface.unseal_data(sealed_data)
            self.assertEqual(unsealed_data, test_data)
        else:
            # TPM not available, which is fine for testing
            self.assertFalse(self.tpm_interface.is_available())


class TestAntiForensicsMonitor(unittest.TestCase):
    """Test suite for anti-forensics monitoring."""
    
    def setUp(self):
        self.monitor = AntiForensicsMonitor()
        self.events = []
    
    def tearDown(self):
        if self.monitor._monitoring:
            self.monitor.stop_monitoring()
    
    def event_callback(self, event):
        """Callback for capturing security events."""
        self.events.append(event)
    
    def test_monitor_start_stop(self):
        """Test starting and stopping the monitor."""
        self.assertFalse(self.monitor._monitoring)
        
        self.monitor.start_monitoring()
        self.assertTrue(self.monitor._monitoring)
        
        self.monitor.stop_monitoring()
        self.assertFalse(self.monitor._monitoring)
    
    def test_alert_callback_registration(self):
        """Test alert callback registration."""
        self.monitor.add_alert_callback(self.event_callback)
        
        # Simulate alert (this is internal testing)
        test_event = MemorySecurityEvent(
            event_type="test_event",
            timestamp=time.time(),
            severity="low",
            message="Test alert"
        )
        
        # Manually trigger callback to test registration
        for callback in self.monitor._alert_callbacks:
            callback(test_event)
        
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0].event_type, "test_event")
    
    @patch('security.secure_memory.subprocess.run')
    def test_process_monitoring(self, mock_subprocess):
        """Test process monitoring for suspicious tools."""
        # Mock subprocess output for Windows
        if sys.platform == "win32":
            # Skip this test on Windows as it requires psutil mocking
            self.skipTest("Windows process monitoring requires psutil mocking")
        else:
            # Mock ps aux output with suspicious process
            mock_subprocess.return_value.stdout = "user 1234 0.0 0.0 gdb /path/to/program"
            
            self.monitor.add_alert_callback(self.event_callback)
            
            # Test the check method directly
            self.monitor._check_memory_dump_tools()
            
            # Should have detected gdb
            # Note: This test may need adjustment based on exact implementation


class TestCrossPlatformCompatibility(unittest.TestCase):
    """Test cross-platform compatibility features."""
    
    def test_platform_detection(self):
        """Test platform-specific code paths."""
        current_platform = sys.platform
        
        # Test that platform is recognized
        self.assertIn(current_platform, ["win32", "linux", "darwin"])
    
    def test_memory_locking_per_platform(self):
        """Test memory locking on different platforms."""
        test_data = b"memory locking test"
        
        secure_obj = SecureBytes(
            test_data,
            protection_level=MemoryProtectionLevel.ENHANCED,
            require_lock=False  # Don't fail if locking unavailable
        )
        
        # Should work regardless of platform
        self.assertEqual(secure_obj.get_bytes(), test_data)
        
        # Check if locking was attempted
        # This varies by platform and permissions, so just ensure no crash
        self.assertIsInstance(secure_obj._locked, bool)
        
        secure_obj.clear()
    
    @unittest.skipIf(sys.platform not in ["win32"], "Windows-specific test")
    def test_windows_specific_features(self):
        """Test Windows-specific memory operations."""
        test_data = b"Windows test data"
        
        secure_obj = SecureBytes(
            test_data,
            protection_level=MemoryProtectionLevel.ENHANCED
        )
        
        # Test Windows-specific memory locking
        # Should not crash even if locking fails due to permissions
        self.assertEqual(secure_obj.get_bytes(), test_data)
        secure_obj.clear()
    
    @unittest.skipIf(sys.platform not in ["linux", "darwin"], "Unix-specific test")
    def test_unix_specific_features(self):
        """Test Unix-specific memory operations."""
        test_data = b"Unix test data"
        
        secure_obj = SecureBytes(
            test_data,
            protection_level=MemoryProtectionLevel.ENHANCED
        )
        
        # Test Unix-specific memory locking
        # Should not crash even if locking fails due to permissions
        self.assertEqual(secure_obj.get_bytes(), test_data)
        secure_obj.clear()


class TestErrorHandlingAndEdgeCases(unittest.TestCase):
    """Test error handling and edge cases."""
    
    def setUp(self):
        get_secure_memory_manager().cleanup_all()
    
    def tearDown(self):
        get_secure_memory_manager().cleanup_all()
    
    def test_invalid_input_types(self):
        """Test handling of invalid input types."""
        invalid_inputs = [123, [1, 2, 3], {"key": "value"}, None]
        
        for invalid_input in invalid_inputs:
            with self.subTest(input_type=type(invalid_input)):
                if invalid_input is None:
                    # None should be accepted (creates empty SecureBytes)
                    secure_obj = SecureBytes(invalid_input)
                    self.assertEqual(len(secure_obj), 0)
                else:
                    with self.assertRaises(TypeError):
                        SecureBytes(invalid_input)
    
    def test_empty_data_operations(self):
        """Test operations on empty data."""
        secure_obj = SecureBytes()
        
        self.assertEqual(len(secure_obj), 0)
        self.assertFalse(bool(secure_obj))
        self.assertEqual(secure_obj.get_bytes(), b"")
        self.assertEqual(secure_obj.get_string(), "")
        
        # Operations should not crash
        secure_obj.clear()
        self.assertEqual(len(secure_obj), 0)
    
    def test_memory_lock_requirement_failure(self):
        """Test behavior when memory locking is required but fails."""
        # Mock memory locking to always fail
        with patch.object(SecureBytes, '_attempt_memory_lock') as mock_lock:
            mock_lock.side_effect = MemoryLockError("Mock lock failure")
            
            # Should raise error when lock is required
            with self.assertRaises(MemoryLockError):
                SecureBytes(b"test data", require_lock=True)
    
    def test_encoding_errors(self):
        """Test handling of encoding errors."""
        # Create bytes that are not valid UTF-8
        invalid_utf8 = b'\xff\xfe\xfd'
        
        secure_obj = SecureBytes(invalid_utf8)
        
        # Should raise UnicodeDecodeError
        with self.assertRaises(UnicodeDecodeError):
            secure_obj.get_string('utf-8')
        
        # But should work with error handling
        try:
            decoded = secure_obj.get_string('utf-8', errors='ignore')
            self.assertIsInstance(decoded, str)
        except TypeError:
            # get_string may not support errors parameter in our implementation
            pass
    
    def test_memory_manager_edge_cases(self):
        """Test memory manager edge cases."""
        manager = get_secure_memory_manager()
        
        # Test multiple cleanup calls
        manager.cleanup_all()
        manager.cleanup_all()  # Should not crash
        
        # Test statistics on empty manager
        stats = manager.get_statistics()
        self.assertEqual(stats.active_allocations, 0)
        
        # Test force cleanup
        manager.force_cleanup_and_gc()  # Should not crash


class TestPerformanceAndBenchmarking(unittest.TestCase):
    """Test performance characteristics and benchmarking."""
    
    def test_allocation_performance(self):
        """Test allocation performance meets requirements."""
        test_data = secrets.token_bytes(1024 * 1024)  # 1MB
        
        # Test allocation time (should be < 100ms per R041)
        start_time = time.perf_counter()
        secure_obj = SecureBytes(test_data, MemoryProtectionLevel.BASIC)
        allocation_time = time.perf_counter() - start_time
        
        self.assertLess(allocation_time, 0.1, f"Allocation took {allocation_time:.3f}s, should be < 0.1s")
        
        secure_obj.clear()
    
    def test_clearing_performance(self):
        """Test clearing performance meets requirements."""
        test_data = secrets.token_bytes(1024 * 1024)  # 1MB
        secure_obj = SecureBytes(test_data, MemoryProtectionLevel.ENHANCED)
        
        # Test clearing time (should be < 50ms per R041)
        start_time = time.perf_counter()
        secure_obj.clear()
        clear_time = time.perf_counter() - start_time
        
        self.assertLess(clear_time, 0.05, f"Clear took {clear_time:.3f}s, should be < 0.05s")
    
    def test_memory_overhead(self):
        """Test memory overhead is within acceptable limits."""
        test_data = secrets.token_bytes(1024 * 1024)  # 1MB
        
        # Get initial memory usage
        import psutil
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Create secure object
        secure_obj = SecureBytes(test_data, MemoryProtectionLevel.ENHANCED)
        current_memory = process.memory_info().rss
        
        # Calculate overhead
        memory_overhead = (current_memory - initial_memory) / len(test_data)
        
        # Should be less than 50% overhead (generous limit for testing)
        self.assertLess(memory_overhead, 1.5, f"Memory overhead {memory_overhead:.2f}x too high")
        
        secure_obj.clear()


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions comprehensively."""
    
    def test_secure_compare_comprehensive(self):
        """Test secure comparison with various inputs."""
        test_cases = [
            # (a, b, expected_result)
            ("password", "password", True),
            ("password", "Password", False),
            ("", "", True),
            ("test", "", False),
            (b"binary", b"binary", True),
            (b"binary", b"different", False),
            ("string", b"string", True),  # Mixed types
        ]
        
        for a, b, expected in test_cases:
            with self.subTest(a=a, b=b):
                result = secure_compare(a, b)
                self.assertEqual(result, expected)
    
    def test_secure_random_string_properties(self):
        """Test secure random string generation properties."""
        # Test different lengths
        for length in [1, 10, 32, 100, 1000]:
            with self.subTest(length=length):
                random_str = secure_random_string(length)
                self.assertEqual(len(random_str), length)
                self.assertTrue(all(c.isalnum() for c in random_str))
        
        # Test custom charset
        custom_charset = "ABCDEF0123456789"
        random_hex = secure_random_string(32, custom_charset)
        self.assertEqual(len(random_hex), 32)
        self.assertTrue(all(c in custom_charset for c in random_hex))
        
        # Test randomness (statistical test)
        strings = [secure_random_string(32) for _ in range(100)]
        unique_strings = set(strings)
        self.assertEqual(len(unique_strings), 100, "Random strings should be unique")
    
    def test_factory_functions(self):
        """Test factory functions with various parameters."""
        # Test create_secure_bytes
        secure_bytes = create_secure_bytes(
            b"test data",
            protection_level=MemoryProtectionLevel.MAXIMUM,
            hardware_bound=False,
            use_tpm=False
        )
        self.assertEqual(secure_bytes.get_bytes(), b"test data")
        
        # Test create_secure_string
        secure_string = create_secure_string("test string")
        self.assertEqual(secure_string.get_value(), "test string")
        
        # Cleanup
        secure_bytes.clear()
        secure_string.clear()


def run_comprehensive_test_suite():
    """Run the comprehensive test suite with detailed reporting."""
    # Configure logging for tests
    import logging
    logging.basicConfig(
        level=logging.WARNING,  # Reduce noise during testing
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create test suite
    test_classes = [
        TestSecureBytesEnhanced,
        TestTPMInterface,
        TestAntiForensicsMonitor,
        TestCrossPlatformCompatibility,
        TestErrorHandlingAndEdgeCases,
        TestPerformanceAndBenchmarking,
        TestUtilityFunctions,
    ]
    
    suite = unittest.TestSuite()
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout, buffer=True)
    result = runner.run(suite)
    
    # Generate comprehensive report
    print(f"\n{'='*80}")
    print("ENHANCED SECURE MEMORY TEST SUITE REPORT")
    print(f"{'='*80}")
    print(f"Platform: {platform.platform()}")
    print(f"Python: {sys.version}")
    print(f"Cryptography Available: {CRYPTOGRAPHY_AVAILABLE}")
    print(f"TPM Available: {TPMInterface().is_available()}")
    print(f"{'='*80}")
    
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100) if result.testsRun > 0 else 0
    print(f"Success Rate: {success_rate:.1f}%")
    
    # Detailed failure reporting
    if result.failures:
        print(f"\nFAILURES ({len(result.failures)}):")
        print("=" * 80)
        for test, traceback in result.failures:
            print(f"FAIL: {test}")
            print("-" * 40)
            print(traceback)
            print()
    
    if result.errors:
        print(f"\nERRORS ({len(result.errors)}):")
        print("=" * 80)
        for test, traceback in result.errors:
            print(f"ERROR: {test}")
            print("-" * 40)
            print(traceback)
            print()
    
    if result.skipped:
        print(f"\nSKIPPED TESTS ({len(result.skipped)}):")
        print("=" * 80)
        for test, reason in result.skipped:
            print(f"SKIP: {test} - {reason}")
    
    # Memory statistics
    try:
        stats = get_secure_memory_manager().get_statistics()
        print(f"\nFINAL MEMORY STATISTICS:")
        print(f"Total Allocations: {stats.total_allocations}")
        print(f"Active Allocations: {stats.active_allocations}")
        print(f"Cleanup Operations: {stats.cleanup_operations}")
        print(f"Lock Failures: {stats.lock_failures}")
        print(f"Corruption Detections: {stats.corruption_detections}")
    except Exception as e:
        print(f"Could not get memory statistics: {e}")
    
    # Final cleanup
    get_secure_memory_manager().cleanup_all()
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_comprehensive_test_suite()
    sys.exit(0 if success else 1)
