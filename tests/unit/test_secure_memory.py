"""
Comprehensive Test Suite for Secure Memory Operations

This test suite provides thorough testing of the secure memory system,
including SecureBytes, SecureString, and memory protection mechanisms
as per BAR Rules R006 - Memory Security.

Test Categories:
- Basic secure memory functionality
- Memory protection and encryption
- Memory wiping and cleanup
- Thread safety and concurrent access
- Performance and memory usage
- Security boundary testing
- Integration with validation system

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys
import unittest
import threading
import time
import gc
from unittest.mock import patch, MagicMock
from typing import List, Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

try:
    from security.secure_memory import (
        SecureBytes, SecureString, create_secure_string, create_secure_bytes,
        secure_compare, get_secure_memory_manager, clear_secure_memory,
        MemoryProtectionLevel, SecureMemoryError
    )
    SECURE_MEMORY_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Secure memory module not available: {e}")
    SECURE_MEMORY_AVAILABLE = False


class SecureMemoryTestCase(unittest.TestCase):
    """Base test case for secure memory testing."""
    
    def setUp(self):
        """Set up test environment."""
        if not SECURE_MEMORY_AVAILABLE:
            self.skipTest("Secure memory module not available")
        
        # Clear any existing secure memory before each test
        clear_secure_memory()
        
    def tearDown(self):
        """Clean up after each test."""
        # Ensure all secure memory is cleared
        clear_secure_memory()
        gc.collect()
    
    def assert_memory_cleared(self, secure_obj):
        """Assert that secure memory object has been properly cleared."""
        with self.assertRaises((SecureMemoryError, ValueError)):
            _ = secure_obj.get_value()
    
    def create_test_data(self, size: int = 1024) -> bytes:
        """Create test data of specified size."""
        return b"A" * size


class TestSecureBytes(SecureMemoryTestCase):
    """Test SecureBytes functionality."""
    
    def test_basic_creation_and_access(self):
        """Test basic SecureBytes creation and data access."""
        test_data = b"Hello, Secure World!"
        secure_bytes = SecureBytes(test_data)
        
        # Test data retrieval
        retrieved = secure_bytes.get_value()
        self.assertEqual(retrieved, test_data)
        
        # Test size
        self.assertEqual(len(secure_bytes), len(test_data))
        
        # Test bool conversion
        self.assertTrue(secure_bytes)
        
        # Test string representation (should not expose data)
        str_repr = str(secure_bytes)
        self.assertNotIn("Hello", str_repr)
        self.assertIn("SecureBytes", str_repr)
    
    def test_empty_secure_bytes(self):
        """Test empty SecureBytes handling."""
        secure_bytes = SecureBytes(b"")
        
        self.assertEqual(len(secure_bytes), 0)
        self.assertFalse(secure_bytes)
        self.assertEqual(secure_bytes.get_value(), b"")
    
    def test_large_data_handling(self):
        """Test SecureBytes with large data."""
        large_data = self.create_test_data(10 * 1024 * 1024)  # 10MB
        secure_bytes = SecureBytes(large_data)
        
        retrieved = secure_bytes.get_value()
        self.assertEqual(len(retrieved), len(large_data))
        self.assertEqual(retrieved[:100], large_data[:100])
        self.assertEqual(retrieved[-100:], large_data[-100:])
    
    def test_memory_clearing(self):
        """Test that memory is properly cleared on destruction."""
        test_data = b"Sensitive data that should be wiped"
        secure_bytes = SecureBytes(test_data)
        
        # Verify data is accessible
        self.assertEqual(secure_bytes.get_value(), test_data)
        
        # Clear the data
        secure_bytes.clear()
        
        # Verify data is no longer accessible
        self.assert_memory_cleared(secure_bytes)
    
    def test_context_manager(self):
        """Test SecureBytes as context manager."""
        test_data = b"Context manager test data"
        
        with SecureBytes(test_data) as secure_bytes:
            retrieved = secure_bytes.get_value()
            self.assertEqual(retrieved, test_data)
        
        # After context exit, memory should be cleared
        self.assert_memory_cleared(secure_bytes)
    
    def test_copy_protection(self):
        """Test that SecureBytes prevents unauthorized copying."""
        test_data = b"Protected data"
        secure_bytes = SecureBytes(test_data)
        
        # Test that direct copy is not allowed
        with self.assertRaises((AttributeError, SecureMemoryError)):
            copied = secure_bytes.copy()
    
    def test_serialization_protection(self):
        """Test that SecureBytes prevents serialization."""
        import pickle
        
        test_data = b"Should not be serializable"
        secure_bytes = SecureBytes(test_data)
        
        # Test that pickling is not allowed
        with self.assertRaises((TypeError, SecureMemoryError)):
            pickle.dumps(secure_bytes)
    
    def test_memory_protection_levels(self):
        """Test different memory protection levels."""
        test_data = b"Protected with different levels"
        
        # Test basic protection
        secure_basic = SecureBytes(test_data, protection_level=MemoryProtectionLevel.BASIC)
        self.assertEqual(secure_basic.get_value(), test_data)
        
        # Test enhanced protection
        secure_enhanced = SecureBytes(test_data, protection_level=MemoryProtectionLevel.ENHANCED)
        self.assertEqual(secure_enhanced.get_value(), test_data)
        
        # Test maximum protection
        secure_maximum = SecureBytes(test_data, protection_level=MemoryProtectionLevel.MAXIMUM)
        self.assertEqual(secure_maximum.get_value(), test_data)


class TestSecureString(SecureMemoryTestCase):
    """Test SecureString functionality."""
    
    def test_basic_string_operations(self):
        """Test basic SecureString operations."""
        test_string = "Hello, Secure String!"
        secure_string = SecureString(test_string)
        
        # Test data retrieval
        retrieved = secure_string.get_value()
        self.assertEqual(retrieved, test_string)
        
        # Test length
        self.assertEqual(len(secure_string), len(test_string))
        
        # Test bool conversion
        self.assertTrue(secure_string)
    
    def test_unicode_handling(self):
        """Test SecureString with Unicode characters."""
        unicode_strings = [
            "Hello, 世界!",
            "café résumé naïve",
            "🔒🔑💻🚨",
            "Здравствуй мир",
            "مرحبا بالعالم"
        ]
        
        for test_string in unicode_strings:
            with self.subTest(string=test_string):
                secure_string = SecureString(test_string)
                retrieved = secure_string.get_value()
                self.assertEqual(retrieved, test_string)
    
    def test_empty_string(self):
        """Test empty SecureString handling."""
        secure_string = SecureString("")
        
        self.assertEqual(len(secure_string), 0)
        self.assertFalse(secure_string)
        self.assertEqual(secure_string.get_value(), "")
    
    def test_string_modification(self):
        """Test SecureString modification operations."""
        secure_string = SecureString("initial value")
        
        # Test value update
        new_value = "updated value"
        secure_string.set_value(new_value)
        
        retrieved = secure_string.get_value()
        self.assertEqual(retrieved, new_value)
    
    def test_password_operations(self):
        """Test SecureString with password-like operations."""
        password = "MySecur3P@ssw0rd!"
        secure_password = SecureString(password)
        
        # Test that string representation doesn't leak password
        str_repr = str(secure_password)
        self.assertNotIn(password, str_repr)
        self.assertIn("SecureString", str_repr)
        
        # Test secure comparison
        same_password = SecureString(password)
        different_password = SecureString("DifferentP@ssw0rd!")
        
        self.assertTrue(secure_compare(secure_password.get_value(), same_password.get_value()))
        self.assertFalse(secure_compare(secure_password.get_value(), different_password.get_value()))


class TestSecureComparison(SecureMemoryTestCase):
    """Test secure comparison functions."""
    
    def test_secure_compare_strings(self):
        """Test secure string comparison."""
        # Test equal strings
        self.assertTrue(secure_compare("hello", "hello"))
        self.assertTrue(secure_compare("", ""))
        
        # Test different strings
        self.assertFalse(secure_compare("hello", "world"))
        self.assertFalse(secure_compare("hello", "Hello"))
        
        # Test different lengths
        self.assertFalse(secure_compare("short", "longer_string"))
    
    def test_secure_compare_bytes(self):
        """Test secure bytes comparison."""
        # Test equal bytes
        self.assertTrue(secure_compare(b"hello", b"hello"))
        self.assertTrue(secure_compare(b"", b""))
        
        # Test different bytes
        self.assertFalse(secure_compare(b"hello", b"world"))
        
        # Test different lengths
        self.assertFalse(secure_compare(b"short", b"longer_bytes"))
    
    def test_secure_compare_mixed_types(self):
        """Test secure comparison with mixed types."""
        # Should handle type mismatches gracefully
        self.assertFalse(secure_compare("hello", b"hello"))
        self.assertFalse(secure_compare(b"hello", "hello"))
        self.assertFalse(secure_compare("hello", 123))
    
    def test_timing_attack_resistance(self):
        """Test that secure comparison is timing attack resistant."""
        import time
        
        # Create strings of different lengths but measure comparison time
        short_string = "a"
        long_string = "a" * 1000
        different_long = "b" * 1000
        
        # Time comparisons multiple times
        times_short = []
        times_long = []
        
        for _ in range(100):
            # Time short comparison
            start = time.perf_counter()
            secure_compare(short_string, "b")
            end = time.perf_counter()
            times_short.append(end - start)
            
            # Time long comparison
            start = time.perf_counter()
            secure_compare(long_string, different_long)
            end = time.perf_counter()
            times_long.append(end - start)
        
        # The timing difference should not be too dramatic
        avg_short = sum(times_short) / len(times_short)
        avg_long = sum(times_long) / len(times_long)
        
        # Allow for some variance but not orders of magnitude
        if avg_short > 0:
            ratio = avg_long / avg_short
            self.assertLess(ratio, 10, "Timing difference too large - potential timing attack vector")


class TestMemoryManager(SecureMemoryTestCase):
    """Test secure memory manager functionality."""
    
    def test_memory_manager_singleton(self):
        """Test that memory manager is a singleton."""
        manager1 = get_secure_memory_manager()
        manager2 = get_secure_memory_manager()
        
        self.assertIs(manager1, manager2)
    
    def test_memory_registration(self):
        """Test memory object registration with manager."""
        test_data = b"Managed secure data"
        secure_bytes = SecureBytes(test_data)
        
        manager = get_secure_memory_manager()
        
        # The object should be automatically registered
        self.assertGreater(manager.get_active_count(), 0)
    
    def test_memory_cleanup(self):
        """Test global memory cleanup."""
        # Create multiple secure objects
        secure_objects = []
        for i in range(10):
            secure_objects.append(SecureBytes(f"Data {i}".encode()))
        
        # Verify objects are accessible
        for i, obj in enumerate(secure_objects):
            self.assertEqual(obj.get_value(), f"Data {i}".encode())
        
        # Clear all secure memory
        clear_secure_memory()
        
        # Verify all objects are cleared
        for obj in secure_objects:
            self.assert_memory_cleared(obj)
    
    def test_memory_statistics(self):
        """Test memory usage statistics."""
        manager = get_secure_memory_manager()
        
        initial_count = manager.get_active_count()
        
        # Create secure objects
        secure_objects = [SecureBytes(f"Data {i}".encode()) for i in range(5)]
        
        # Count should increase
        self.assertEqual(manager.get_active_count(), initial_count + 5)
        
        # Clear some objects
        for obj in secure_objects[:3]:
            obj.clear()
        
        # Count should decrease
        self.assertLessEqual(manager.get_active_count(), initial_count + 2)


class TestThreadSafety(SecureMemoryTestCase):
    """Test thread safety of secure memory operations."""
    
    def test_concurrent_creation(self):
        """Test concurrent creation of secure objects."""
        results = []
        errors = []
        
        def create_secure_objects(thread_id: int):
            try:
                thread_objects = []
                for i in range(100):
                    data = f"Thread {thread_id} - Data {i}".encode()
                    secure_obj = SecureBytes(data)
                    thread_objects.append(secure_obj)
                
                # Verify all objects are accessible
                for i, obj in enumerate(thread_objects):
                    expected = f"Thread {thread_id} - Data {i}".encode()
                    actual = obj.get_value()
                    if actual != expected:
                        errors.append(f"Thread {thread_id}: Data mismatch at index {i}")
                
                results.append((thread_id, len(thread_objects)))
                
            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Create multiple threads
        threads = []
        for thread_id in range(5):
            thread = threading.Thread(target=create_secure_objects, args=(thread_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
        self.assertEqual(len(results), 5, "Not all threads completed successfully")
        
        # Each thread should have created 100 objects
        for thread_id, count in results:
            self.assertEqual(count, 100, f"Thread {thread_id} created {count} objects instead of 100")
    
    def test_concurrent_access(self):
        """Test concurrent access to the same secure object."""
        shared_data = b"Shared secure data for concurrent access"
        shared_object = SecureBytes(shared_data)
        
        access_results = []
        access_errors = []
        
        def access_shared_object(thread_id: int, access_count: int):
            try:
                for i in range(access_count):
                    data = shared_object.get_value()
                    if data != shared_data:
                        access_errors.append(f"Thread {thread_id}: Data corruption at access {i}")
                    access_results.append((thread_id, i, len(data)))
            except Exception as e:
                access_errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Create multiple threads accessing the same object
        threads = []
        for thread_id in range(3):
            thread = threading.Thread(target=access_shared_object, args=(thread_id, 50))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(access_errors), 0, f"Concurrent access errors: {access_errors}")
        self.assertEqual(len(access_results), 150, "Not all access operations completed")


class TestMemoryPerformance(SecureMemoryTestCase):
    """Test performance characteristics of secure memory."""
    
    def test_creation_performance(self):
        """Test performance of secure object creation."""
        import time
        
        data_sizes = [100, 1024, 10*1024, 100*1024]  # Various sizes
        
        for size in data_sizes:
            with self.subTest(size=size):
                test_data = self.create_test_data(size)
                
                start_time = time.perf_counter()
                secure_obj = SecureBytes(test_data)
                end_time = time.perf_counter()
                
                creation_time = end_time - start_time
                
                # Creation should be reasonably fast (less than 100ms for 100KB)
                max_time = 0.1 if size <= 100*1024 else 1.0
                self.assertLess(creation_time, max_time, 
                               f"Creation too slow for {size} bytes: {creation_time:.4f}s")
                
                secure_obj.clear()
    
    def test_access_performance(self):
        """Test performance of data access."""
        import time
        
        test_data = self.create_test_data(10*1024)  # 10KB
        secure_obj = SecureBytes(test_data)
        
        # Test multiple accesses
        access_times = []
        for _ in range(100):
            start_time = time.perf_counter()
            data = secure_obj.get_value()
            end_time = time.perf_counter()
            
            access_times.append(end_time - start_time)
            self.assertEqual(len(data), len(test_data))
        
        avg_access_time = sum(access_times) / len(access_times)
        
        # Access should be fast (less than 10ms average)
        self.assertLess(avg_access_time, 0.01, 
                       f"Data access too slow: {avg_access_time:.6f}s average")
    
    def test_memory_usage(self):
        """Test memory usage characteristics."""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss
            
            # Create many secure objects
            secure_objects = []
            for i in range(1000):
                data = f"Memory test data {i}".encode() * 100  # ~2KB each
                secure_objects.append(SecureBytes(data))
            
            peak_memory = process.memory_info().rss
            memory_growth = peak_memory - initial_memory
            
            # Clear all objects
            for obj in secure_objects:
                obj.clear()
            del secure_objects
            gc.collect()
            
            final_memory = process.memory_info().rss
            
            # Memory should be mostly reclaimed
            memory_leaked = final_memory - initial_memory
            max_acceptable_leak = 50 * 1024 * 1024  # 50MB
            
            self.assertLess(memory_leaked, max_acceptable_leak,
                           f"Excessive memory leak: {memory_leaked / 1024 / 1024:.1f} MB")
            
        except ImportError:
            self.skipTest("psutil not available for memory testing")


class TestSecurityBoundaries(SecureMemoryTestCase):
    """Test security boundaries and edge cases."""
    
    def test_invalid_input_handling(self):
        """Test handling of invalid inputs."""
        # Test None input
        with self.assertRaises((TypeError, ValueError)):
            SecureBytes(None)
        
        # Test invalid type input
        with self.assertRaises((TypeError, ValueError)):
            SecureBytes(123)
        
        # Test invalid protection level
        with self.assertRaises((ValueError, TypeError)):
            SecureBytes(b"test", protection_level="invalid")
    
    def test_double_clear_protection(self):
        """Test protection against double-clearing."""
        secure_obj = SecureBytes(b"test data")
        
        # First clear should work
        secure_obj.clear()
        self.assert_memory_cleared(secure_obj)
        
        # Second clear should not cause errors
        secure_obj.clear()  # Should be safe
    
    def test_access_after_clear(self):
        """Test access attempts after clearing."""
        secure_obj = SecureBytes(b"cleared data")
        secure_obj.clear()
        
        # Any access should raise an error
        with self.assertRaises((SecureMemoryError, ValueError)):
            secure_obj.get_value()
        
        with self.assertRaises((SecureMemoryError, ValueError)):
            len(secure_obj)
    
    def test_memory_exhaustion_handling(self):
        """Test handling of memory exhaustion scenarios."""
        # This test is platform-dependent and may not work everywhere
        try:
            # Try to create an extremely large secure object
            huge_size = 10 * 1024 * 1024 * 1024  # 10GB
            with self.assertRaises((MemoryError, OSError, SecureMemoryError)):
                SecureBytes(b"x" * huge_size)
        except MemoryError:
            # This is expected behavior
            pass


def create_secure_memory_test_suite():
    """Create a comprehensive test suite for secure memory."""
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestSecureBytes,
        TestSecureString,
        TestSecureComparison,
        TestMemoryManager,
        TestThreadSafety,
        TestMemoryPerformance,
        TestSecurityBoundaries
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    return suite


def run_secure_memory_tests():
    """Run all secure memory tests and return results."""
    if not SECURE_MEMORY_AVAILABLE:
        print("❌ Secure memory module not available - cannot run tests")
        return False
    
    print("🔒 Running Secure Memory Test Suite...")
    print("=" * 60)
    
    # Create and run test suite
    suite = create_secure_memory_test_suite()
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"SECURE MEMORY TEST SUMMARY")
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
        print("\n✅ All secure memory tests passed!")
    else:
        print(f"\n❌ Some secure memory tests failed.")
    
    return success


if __name__ == "__main__":
    # Run tests when script is executed directly
    success = run_secure_memory_tests()
    sys.exit(0 if success else 1)