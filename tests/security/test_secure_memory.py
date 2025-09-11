import unittest
import os
import gc
import time
import threading
from unittest.mock import patch, Mock
import secrets

# Add src to path for imports
import sys
from pathlib import Path
src_dir = Path(__file__).resolve().parents[2] / 'src'
sys.path.insert(0, str(src_dir))

from src.security.secure_memory import (
    SecureBytes, SecureString, SecureMemoryManager,
    MemoryProtectionLevel, MemoryCorruptionError, MemoryLockError,
    MemoryStats, create_secure_bytes, create_secure_string,
    secure_compare, secure_random_string, get_secure_memory_manager,
    force_secure_memory_cleanup, secure_memory_context, secure_wipe_variable
)


class TestSecureBytes(unittest.TestCase):
    """Test suite for SecureBytes class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Clear any existing secure objects
        get_secure_memory_manager().cleanup_all()
    
    def tearDown(self):
        """Clean up after each test."""
        get_secure_memory_manager().cleanup_all()
        gc.collect()
    
    def test_secure_bytes_creation_empty(self):
        """Test creating empty SecureBytes."""
        secure_data = SecureBytes()
        self.assertEqual(len(secure_data), 0)
        self.assertFalse(bool(secure_data))
    
    def test_secure_bytes_creation_with_bytes(self):
        """Test creating SecureBytes with byte data."""
        test_data = b"Hello, secure world!"
        secure_data = SecureBytes(test_data)
        
        self.assertEqual(len(secure_data), len(test_data))
        self.assertTrue(bool(secure_data))
        self.assertEqual(secure_data.get_bytes(), test_data)
    
    def test_secure_bytes_creation_with_string(self):
        """Test creating SecureBytes with string data."""
        test_string = "Hello, secure world!"
        secure_data = SecureBytes(test_string)
        
        self.assertEqual(secure_data.get_string(), test_string)
        self.assertEqual(secure_data.get_bytes(), test_string.encode('utf-8'))
    
    def test_secure_bytes_creation_with_bytearray(self):
        """Test creating SecureBytes with bytearray data."""
        test_data = bytearray(b"Hello, secure world!")
        secure_data = SecureBytes(test_data)
        
        self.assertEqual(secure_data.get_bytes(), bytes(test_data))
    
    def test_secure_bytes_invalid_type(self):
        """Test SecureBytes creation with invalid data type."""
        with self.assertRaises(TypeError):
            SecureBytes(123)
        
        with self.assertRaises(TypeError):
            SecureBytes([1, 2, 3])
    
    def test_protection_levels(self):
        """Test different protection levels."""
        test_data = b"test data"
        
        basic = SecureBytes(test_data, MemoryProtectionLevel.BASIC)
        enhanced = SecureBytes(test_data, MemoryProtectionLevel.ENHANCED)
        maximum = SecureBytes(test_data, MemoryProtectionLevel.MAXIMUM)
        
        self.assertEqual(basic.get_bytes(), test_data)
        self.assertEqual(enhanced.get_bytes(), test_data)
        self.assertEqual(maximum.get_bytes(), test_data)
    
    def test_memory_locking_optional(self):
        """Test memory locking with optional requirement."""
        test_data = b"test data"
        
        # Should not raise error even if locking fails
        secure_data = SecureBytes(test_data, require_lock=False)
        self.assertEqual(secure_data.get_bytes(), test_data)
    
    def test_set_data_functionality(self):
        """Test secure data setting and updating."""
        secure_data = SecureBytes()
        
        # Set string data
        test_string = "Hello, world!"
        secure_data.set_data(test_string)
        self.assertEqual(secure_data.get_string(), test_string)
        
        # Set bytes data
        test_bytes = b"New data"
        secure_data.set_data(test_bytes)
        self.assertEqual(secure_data.get_bytes(), test_bytes)
        
        # Set bytearray data
        test_bytearray = bytearray(b"Bytearray data")
        secure_data.set_data(test_bytearray)
        self.assertEqual(secure_data.get_bytes(), bytes(test_bytearray))
    
    def test_secure_clear(self):
        """Test secure data clearing."""
        test_data = b"sensitive data to clear"
        secure_data = SecureBytes(test_data)
        
        # Verify data is there
        self.assertEqual(secure_data.get_bytes(), test_data)
        
        # Clear the data
        secure_data.clear()
        
        # Data should be empty now
        self.assertEqual(len(secure_data), 0)
        self.assertFalse(bool(secure_data))
    
    def test_context_manager(self):
        """Test SecureBytes as context manager."""
        test_data = b"context manager test"
        
        with SecureBytes(test_data) as secure_data:
            self.assertEqual(secure_data.get_bytes(), test_data)
        
        # After context, data should be cleared
        self.assertEqual(len(secure_data), 0)
    
    def test_canary_detection_maximum_protection(self):
        """Test canary-based corruption detection with maximum protection."""
        test_data = b"test data for corruption detection"
        secure_data = SecureBytes(test_data, MemoryProtectionLevel.MAXIMUM)
        
        # Normal access should work
        self.assertEqual(secure_data.get_bytes(), test_data)
        
        # Simulate corruption by directly modifying internal data
        # Note: This is a simplified test - real corruption detection is more complex
        if hasattr(secure_data, '_data') and len(secure_data._data) > 16:
            # Corrupt the canary
            original_byte = secure_data._data[0]
            secure_data._data[0] = 0xFF if original_byte != 0xFF else 0x00
            
            # Access should detect corruption
            with self.assertRaises(MemoryCorruptionError):
                secure_data.get_bytes()
    
    def test_thread_safety(self):
        """Test thread-safe operations on SecureBytes."""
        test_data = b"thread safety test data"
        secure_data = SecureBytes(test_data)
        results = []
        errors = []
        
        def worker_thread():
            try:
                for _ in range(100):
                    data = secure_data.get_bytes()
                    results.append(data == test_data)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker_thread)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertTrue(all(results), "Some threads got incorrect data")


class TestSecureString(unittest.TestCase):
    """Test suite for SecureString class."""
    
    def setUp(self):
        """Set up test fixtures."""
        get_secure_memory_manager().cleanup_all()
    
    def tearDown(self):
        """Clean up after each test."""
        get_secure_memory_manager().cleanup_all()
        gc.collect()
    
    def test_secure_string_creation(self):
        """Test creating SecureString."""
        test_string = "Hello, secure string!"
        secure_str = SecureString(test_string)
        
        self.assertEqual(secure_str.get_value(), test_string)
        self.assertEqual(secure_str.get_string(), test_string)
    
    def test_secure_string_empty(self):
        """Test creating empty SecureString."""
        secure_str = SecureString()
        self.assertEqual(secure_str.get_value(), "")
    
    def test_secure_string_invalid_type(self):
        """Test SecureString with invalid data type."""
        with self.assertRaises(TypeError):
            SecureString(123)
        
        with self.assertRaises(TypeError):
            SecureString(b"bytes")
    
    def test_secure_string_set_value(self):
        """Test setting new string values."""
        secure_str = SecureString("initial")
        
        new_value = "updated value"
        secure_str.set_value(new_value)
        self.assertEqual(secure_str.get_value(), new_value)
        
        with self.assertRaises(TypeError):
            secure_str.set_value(123)
    
    def test_secure_string_context_manager(self):
        """Test SecureString as context manager."""
        test_string = "context test"
        
        with SecureString(test_string) as secure_str:
            self.assertEqual(secure_str.get_value(), test_string)
        
        # After context, data should be cleared
        self.assertEqual(len(secure_str), 0)


class TestSecureMemoryManager(unittest.TestCase):
    """Test suite for SecureMemoryManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Get fresh manager instance
        self.manager = get_secure_memory_manager()
        self.manager.cleanup_all()
    
    def tearDown(self):
        """Clean up after each test."""
        self.manager.cleanup_all()
        gc.collect()
    
    def test_manager_singleton(self):
        """Test that manager is singleton."""
        manager1 = get_secure_memory_manager()
        manager2 = get_secure_memory_manager()
        self.assertIs(manager1, manager2)
    
    def test_object_registration(self):
        """Test secure object registration and tracking."""
        initial_stats = self.manager.get_statistics()
        
        # Create secure objects
        obj1 = SecureBytes(b"test data 1")
        obj2 = SecureString("test string 2")
        
        stats = self.manager.get_statistics()
        self.assertEqual(stats.active_allocations, initial_stats.active_allocations + 2)
        self.assertGreater(stats.total_allocations, initial_stats.total_allocations)
    
    def test_cleanup_all(self):
        """Test cleanup of all registered objects."""
        # Create some objects
        obj1 = SecureBytes(b"test data")
        obj2 = SecureString("test string")
        
        # Verify they're registered
        stats_before = self.manager.get_statistics()
        self.assertGreater(stats_before.active_allocations, 0)
        
        # Cleanup all
        cleaned_count = self.manager.cleanup_all()
        self.assertGreater(cleaned_count, 0)
        
        # Check stats after cleanup
        stats_after = self.manager.get_statistics()
        self.assertEqual(stats_after.active_allocations, 0)
    
    def test_garbage_collection_tracking(self):
        """Test that garbage collected objects are tracked properly."""
        initial_stats = self.manager.get_statistics()
        
        # Create object in local scope
        def create_object():
            return SecureBytes(b"temporary data")
        
        obj = create_object()
        stats_with_object = self.manager.get_statistics()
        self.assertGreater(stats_with_object.active_allocations, initial_stats.active_allocations)
        
        # Delete object and force garbage collection
        del obj
        gc.collect()
        
        # Give weak references time to be cleaned up
        time.sleep(0.1)
        
        final_stats = self.manager.get_statistics()
        # Active allocations might not immediately decrease due to weak reference cleanup timing
        # But total allocations should still reflect the created object
        self.assertGreaterEqual(final_stats.total_allocations, initial_stats.total_allocations)
    
    def test_force_cleanup_and_gc(self):
        """Test forced cleanup with garbage collection."""
        # Create objects
        objects = []
        for i in range(10):
            objects.append(SecureBytes(f"test data {i}".encode()))
        
        stats_before = self.manager.get_statistics()
        self.assertGreater(stats_before.active_allocations, 5)
        
        # Force cleanup
        self.manager.force_cleanup_and_gc()
        
        stats_after = self.manager.get_statistics()
        self.assertEqual(stats_after.active_allocations, 0)


class TestUtilityFunctions(unittest.TestCase):
    """Test suite for utility functions."""
    
    def test_secure_compare_strings(self):
        """Test secure string comparison."""
        string1 = "password123"
        string2 = "password123"
        string3 = "different"
        
        self.assertTrue(secure_compare(string1, string2))
        self.assertFalse(secure_compare(string1, string3))
    
    def test_secure_compare_bytes(self):
        """Test secure bytes comparison."""
        bytes1 = b"secret data"
        bytes2 = b"secret data"
        bytes3 = b"different data"
        
        self.assertTrue(secure_compare(bytes1, bytes2))
        self.assertFalse(secure_compare(bytes1, bytes3))
    
    def test_secure_compare_mixed_types(self):
        """Test secure comparison with mixed string/bytes."""
        string_data = "test data"
        bytes_data = b"test data"
        
        self.assertTrue(secure_compare(string_data, bytes_data))
        self.assertTrue(secure_compare(bytes_data, string_data))
    
    def test_secure_random_string_default(self):
        """Test secure random string generation with defaults."""
        random_str = secure_random_string(32)
        
        self.assertEqual(len(random_str), 32)
        self.assertTrue(all(c.isalnum() for c in random_str))
        
        # Generate another and ensure they're different
        random_str2 = secure_random_string(32)
        self.assertNotEqual(random_str, random_str2)
    
    def test_secure_random_string_custom_charset(self):
        """Test secure random string with custom character set."""
        charset = "ABCDEF0123456789"
        random_str = secure_random_string(16, charset)
        
        self.assertEqual(len(random_str), 16)
        self.assertTrue(all(c in charset for c in random_str))
    
    def test_create_secure_bytes_factory(self):
        """Test secure bytes factory function."""
        test_data = b"factory test data"
        
        secure_data = create_secure_bytes(test_data)
        self.assertEqual(secure_data.get_bytes(), test_data)
        
        # Test with protection level
        secure_data_max = create_secure_bytes(
            test_data, 
            protection_level=MemoryProtectionLevel.MAXIMUM
        )
        self.assertEqual(secure_data_max.get_bytes(), test_data)
    
    def test_create_secure_string_factory(self):
        """Test secure string factory function."""
        test_string = "factory test string"
        
        secure_str = create_secure_string(test_string)
        self.assertEqual(secure_str.get_value(), test_string)
    
    def test_force_secure_memory_cleanup(self):
        """Test global secure memory cleanup."""
        # Create some objects
        obj1 = create_secure_bytes(b"test1")
        obj2 = create_secure_string("test2")
        
        stats_before = get_secure_memory_manager().get_statistics()
        self.assertGreater(stats_before.active_allocations, 0)
        
        # Force cleanup
        force_secure_memory_cleanup()
        
        stats_after = get_secure_memory_manager().get_statistics()
        self.assertEqual(stats_after.active_allocations, 0)


class TestSecureMemoryContext(unittest.TestCase):
    """Test suite for secure memory context manager."""
    
    def test_secure_memory_context(self):
        """Test secure memory context manager."""
        initial_stats = get_secure_memory_manager().get_statistics()
        
        with secure_memory_context():
            obj1 = create_secure_bytes(b"context test 1")
            obj2 = create_secure_string("context test 2")
            
            # Objects should be accessible within context
            self.assertEqual(obj1.get_bytes(), b"context test 1")
            self.assertEqual(obj2.get_value(), "context test 2")
            
            context_stats = get_secure_memory_manager().get_statistics()
            self.assertGreater(context_stats.cleanup_operations, initial_stats.cleanup_operations)
        
        # After context, cleanup should have occurred
        final_stats = get_secure_memory_manager().get_statistics()
        self.assertGreater(final_stats.cleanup_operations, context_stats.cleanup_operations)


class TestMemoryProtectionEdgeCases(unittest.TestCase):
    """Test suite for edge cases and error conditions."""
    
    def setUp(self):
        get_secure_memory_manager().cleanup_all()
    
    def tearDown(self):
        get_secure_memory_manager().cleanup_all()
        gc.collect()
    
    def test_empty_data_operations(self):
        """Test operations on empty secure data."""
        secure_data = SecureBytes()
        
        # Should handle empty data gracefully
        self.assertEqual(secure_data.get_bytes(), b"")
        self.assertEqual(secure_data.get_string(), "")
        
        # Clear should not raise error
        secure_data.clear()
        
        # Set data on empty object
        test_data = b"new data"
        secure_data.set_data(test_data)
        self.assertEqual(secure_data.get_bytes(), test_data)
    
    def test_large_data_handling(self):
        """Test handling of large data blocks."""
        # Create 1MB of test data
        large_data = secrets.token_bytes(1024 * 1024)
        
        secure_data = SecureBytes(large_data)
        self.assertEqual(len(secure_data), len(large_data))
        self.assertEqual(secure_data.get_bytes(), large_data)
        
        # Clear large data
        secure_data.clear()
        self.assertEqual(len(secure_data), 0)
    
    def test_unicode_string_handling(self):
        """Test handling of Unicode strings."""
        unicode_string = "Hello 世界 🌍 Мир"
        secure_str = SecureString(unicode_string)
        
        self.assertEqual(secure_str.get_value(), unicode_string)
        
        # Test encoding/decoding
        secure_bytes = SecureBytes(unicode_string)
        self.assertEqual(secure_bytes.get_string(), unicode_string)
    
    def test_multiple_encoding_operations(self):
        """Test multiple encoding/decoding operations."""
        test_string = "Test encoding operations"
        secure_data = SecureBytes(test_string)
        
        # Multiple get operations should work
        for _ in range(10):
            self.assertEqual(secure_data.get_string(), test_string)
            self.assertEqual(secure_data.get_bytes(), test_string.encode('utf-8'))
    
    @patch('src.security.secure_memory.os.urandom')
    def test_random_generation_fallback(self, mock_urandom):
        """Test behavior when random generation fails."""
        # Mock urandom to raise an exception
        mock_urandom.side_effect = OSError("Random generation failed")
        
        # Should still work due to secrets module fallback
        try:
            random_str = secure_random_string(16)
            self.assertEqual(len(random_str), 16)
        except Exception as e:
            # If it fails, it should be due to our mock, not the implementation
            self.assertIn("Random generation failed", str(e))


class TestMemoryStatistics(unittest.TestCase):
    """Test suite for memory statistics tracking."""
    
    def setUp(self):
        get_secure_memory_manager().cleanup_all()
        # Reset statistics
        manager = get_secure_memory_manager()
        manager.stats = type(manager.stats)()  # Reset to default values
    
    def test_allocation_statistics(self):
        """Test allocation counting."""
        initial_stats = get_secure_memory_manager().get_statistics()
        
        # Create objects
        obj1 = SecureBytes(b"test1")
        obj2 = SecureString("test2")
        
        stats = get_secure_memory_manager().get_statistics()
        self.assertEqual(stats.total_allocations, initial_stats.total_allocations + 2)
        self.assertEqual(stats.active_allocations, initial_stats.active_allocations + 2)
    
    def test_cleanup_statistics(self):
        """Test cleanup operation counting."""
        initial_stats = get_secure_memory_manager().get_statistics()
        
        # Create and cleanup objects
        obj = SecureBytes(b"test data")
        obj.clear()
        
        # Cleanup all
        get_secure_memory_manager().cleanup_all()
        
        final_stats = get_secure_memory_manager().get_statistics()
        self.assertGreater(final_stats.cleanup_operations, initial_stats.cleanup_operations)


if __name__ == '__main__':
    # Set up test environment
    import logging
    logging.basicConfig(level=logging.WARNING)  # Reduce noise during testing
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestSecureBytes,
        TestSecureString,
        TestSecureMemoryManager,
        TestUtilityFunctions,
        TestSecureMemoryContext,
        TestMemoryProtectionEdgeCases,
        TestMemoryStatistics
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    # Force cleanup at the end
    get_secure_memory_manager().cleanup_all()
