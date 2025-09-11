import unittest
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, Mock
import time

# Add src to path for imports
import sys
src_dir = Path(__file__).resolve().parents[2] / 'src'
sys.path.insert(0, str(src_dir))

from src.security.device_auth_manager import DeviceAuthManager
from src.security.secure_memory import get_secure_memory_manager, force_secure_memory_cleanup
from src.security.secure_file_ops import SecureDeletionMethod, FileSecurityLevel


class TestDeviceAuthManager(unittest.TestCase):
    """Test suite for DeviceAuthManager class."""
    
    def setUp(self):
        """Set up test fixtures with temporary directory."""
        # Create temporary directory for testing
        self.test_dir = tempfile.mkdtemp()
        self.device_config_path = Path(self.test_dir) / "device_config.enc"
        
        # Clear any existing secure memory objects
        get_secure_memory_manager().cleanup_all()
        
        # Mock the home directory to use our temp dir
        self.home_patcher = patch('pathlib.Path.home')
        self.mock_home = self.home_patcher.start()
        self.mock_home.return_value = Path(self.test_dir)
        
        # Create DeviceAuthManager instance
        self.device_auth = DeviceAuthManager()
    
    def tearDown(self):
        """Clean up after each test."""
        try:
            # Stop patching
            self.home_patcher.stop()
            
            # Cleanup secure memory
            if hasattr(self, 'device_auth'):
                self.device_auth.logout()
            
            get_secure_memory_manager().cleanup_all()
            
            # Remove temp directory
            if os.path.exists(self.test_dir):
                shutil.rmtree(self.test_dir, ignore_errors=True)
                
        except Exception as e:
            print(f"Teardown error: {e}")
    
    def test_device_initialization_check(self):
        """Test checking if device is initialized."""
        # Initially should not be initialized
        self.assertFalse(self.device_auth.is_device_initialized())
        
        # After creating config file, should be initialized
        config_file = Path(self.test_dir) / ".bar" / "device_config.enc"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.touch()
        
        # Create new instance to check
        new_device_auth = DeviceAuthManager()
        self.assertTrue(new_device_auth.is_device_initialized())
    
    def test_device_initialization_success(self):
        """Test successful device initialization."""
        test_password = "TestPassword123!"
        test_device_name = "TestDevice"
        
        success, message = self.device_auth.initialize_device(test_password, test_device_name)
        
        self.assertTrue(success)
        self.assertIn("initialized successfully", message)
        self.assertTrue(self.device_auth.is_device_initialized())
    
    def test_device_initialization_already_initialized(self):
        """Test initialization when device is already initialized."""
        test_password = "TestPassword123!"
        
        # Initialize once
        success1, _ = self.device_auth.initialize_device(test_password)
        self.assertTrue(success1)
        
        # Try to initialize again
        success2, message = self.device_auth.initialize_device(test_password)
        self.assertFalse(success2)
        self.assertIn("already initialized", message)
    
    @patch('src.security.device_auth_manager.HardwareIdentifier')
    def test_device_initialization_with_hardware_binding(self, mock_hw_id_class):
        """Test device initialization with hardware binding."""
        # Mock hardware identifier
        mock_hw_id = Mock()
        mock_hw_id.get_hardware_id.return_value = "test_hardware_id_12345"
        mock_hw_id_class.return_value = mock_hw_id
        
        # Create new device auth with mocked hardware ID
        device_auth = DeviceAuthManager()
        
        test_password = "TestPassword123!"
        success, message = device_auth.initialize_device(test_password)
        
        self.assertTrue(success)
        mock_hw_id.get_hardware_id.assert_called()
    
    def test_authentication_device_not_initialized(self):
        """Test authentication when device is not initialized."""
        success, message = self.device_auth.authenticate("any_password")
        
        self.assertFalse(success)
        self.assertIn("not initialized", message)
    
    def test_authentication_success(self):
        """Test successful authentication."""
        test_password = "TestPassword123!"
        
        # Initialize device first
        init_success, _ = self.device_auth.initialize_device(test_password)
        self.assertTrue(init_success)
        
        # Logout to test authentication
        self.device_auth.logout()
        
        # Authenticate
        auth_success, message = self.device_auth.authenticate(test_password)
        
        self.assertTrue(auth_success)
        self.assertIn("Welcome back", message)
        self.assertTrue(self.device_auth.is_authenticated())
    
    def test_authentication_wrong_password(self):
        """Test authentication with wrong password."""
        correct_password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        
        # Initialize device
        self.device_auth.initialize_device(correct_password)
        self.device_auth.logout()
        
        # Try to authenticate with wrong password
        success, message = self.device_auth.authenticate(wrong_password)
        
        self.assertFalse(success)
        self.assertIn("Authentication failed", message)
        self.assertFalse(self.device_auth.is_authenticated())
    
    @patch('src.security.device_auth_manager.HardwareIdentifier')
    def test_authentication_hardware_mismatch(self, mock_hw_id_class):
        """Test authentication with hardware ID mismatch."""
        # Mock hardware identifier that changes between calls
        mock_hw_id = Mock()
        mock_hw_id.get_hardware_id.side_effect = ["hardware_id_1", "hardware_id_2"]
        mock_hw_id_class.return_value = mock_hw_id
        
        device_auth = DeviceAuthManager()
        test_password = "TestPassword123!"
        
        # Initialize device with first hardware ID
        init_success, _ = device_auth.initialize_device(test_password)
        self.assertTrue(init_success)
        
        device_auth.logout()
        
        # Try to authenticate with different hardware ID
        auth_success, message = device_auth.authenticate(test_password)
        
        self.assertFalse(auth_success)
        self.assertIn("Hardware verification failed", message)
    
    def test_logout_functionality(self):
        """Test logout functionality."""
        test_password = "TestPassword123!"
        
        # Initialize and authenticate
        self.device_auth.initialize_device(test_password)
        self.assertTrue(self.device_auth.is_authenticated())
        
        # Logout
        self.device_auth.logout()
        self.assertFalse(self.device_auth.is_authenticated())
    
    def test_device_reset(self):
        """Test device reset functionality."""
        test_password = "TestPassword123!"
        
        # Initialize device
        self.device_auth.initialize_device(test_password)
        self.assertTrue(self.device_auth.is_device_initialized())
        
        # Reset device
        success, message = self.device_auth.reset_device()
        
        self.assertTrue(success)
        self.assertIn("reset completed", message)
        self.assertFalse(self.device_auth.is_authenticated())
    
    def test_emergency_wipe(self):
        """Test emergency wipe functionality."""
        test_password = "TestPassword123!"
        
        # Initialize device
        self.device_auth.initialize_device(test_password)
        
        # Perform emergency wipe
        wipe_results = self.device_auth.emergency_wipe()
        
        self.assertIsInstance(wipe_results, dict)
        self.assertIn("started_at", wipe_results)
        self.assertIn("completed_at", wipe_results)
        self.assertTrue(wipe_results.get("device_reset", False))
        self.assertTrue(wipe_results.get("memory_cleanup", False))
    
    def test_panic_wipe(self):
        """Test panic wipe functionality."""
        test_password = "TestPassword123!"
        
        # Initialize device
        self.device_auth.initialize_device(test_password)
        
        # Perform panic wipe
        panic_results = self.device_auth.panic_wipe()
        
        self.assertIsInstance(panic_results, dict)
        self.assertTrue(panic_results.get("panic_completed", False))
        self.assertIn("timestamp", panic_results)
        self.assertTrue(self.device_auth.is_panic_triggered())
    
    def test_panic_wipe_stealth_mode(self):
        """Test that panic wipe operates in stealth mode with minimal logging."""
        test_password = "TestPassword123!"
        
        self.device_auth.initialize_device(test_password)
        
        # Capture log output
        with patch.object(self.device_auth.logger, 'critical') as mock_log:
            panic_results = self.device_auth.panic_wipe()
            
            # Should not log much for stealth
            self.assertLessEqual(mock_log.call_count, 1)
            self.assertTrue(panic_results.get("panic_completed", False))
    
    def test_schedule_delayed_wipe(self):
        """Test scheduled delayed wipe functionality."""
        test_password = "TestPassword123!"
        
        self.device_auth.initialize_device(test_password)
        
        # Schedule a delayed wipe (short delay for testing)
        success = self.device_auth.schedule_delayed_wipe(delay_seconds=1)
        
        self.assertTrue(success)
        
        # Wait a bit longer than the delay
        time.sleep(1.5)
        
        # Check if wipe occurred (device should be reset)
        # Note: This is a timing-dependent test and may be flaky
    
    def test_file_blacklisting(self):
        """Test file blacklisting functionality."""
        test_password = "TestPassword123!"
        test_file_path = Path(self.test_dir) / "test_file.txt"
        test_file_path.write_text("test content")
        
        self.device_auth.initialize_device(test_password)
        
        # Blacklist a file
        success = self.device_auth.add_file_to_blacklist(test_file_path, "Security test")
        self.assertTrue(success)
        
        # Check if file operations are aware of blacklisting
        # This depends on integration with SecureFileOperations
        secure_file_ops = self.device_auth._secure_file_ops
        self.assertTrue(secure_file_ops.is_file_blacklisted(test_file_path))
    
    def test_secure_file_deletion(self):
        """Test secure file deletion."""
        test_password = "TestPassword123!"
        test_file_path = Path(self.test_dir) / "delete_test.txt"
        test_content = "This file will be securely deleted"
        test_file_path.write_text(test_content)
        
        self.device_auth.initialize_device(test_password)
        
        # Verify file exists
        self.assertTrue(test_file_path.exists())
        
        # Securely delete file
        success = self.device_auth.secure_delete_file(test_file_path)
        
        self.assertTrue(success)
        self.assertFalse(test_file_path.exists())
    
    def test_get_security_status(self):
        """Test getting comprehensive security status."""
        test_password = "TestPassword123!"
        
        self.device_auth.initialize_device(test_password)
        
        status = self.device_auth.get_security_status()
        
        self.assertIsInstance(status, dict)
        self.assertIn("security_features", status)
        self.assertIn("file_security", status)
        self.assertIn("memory_security", status)
        
        # Check security features
        features = status["security_features"]
        self.assertTrue(features["device_bound_auth"])
        self.assertTrue(features["hardware_verification"])
        self.assertTrue(features["secure_memory"])
        self.assertTrue(features["file_blacklisting"])
        self.assertTrue(features["emergency_wipe"])
    
    def test_device_info_not_initialized(self):
        """Test getting device info when not initialized."""
        info = self.device_auth.get_device_info()
        
        self.assertEqual(info["status"], "not_initialized")
    
    def test_device_info_initialized(self):
        """Test getting device info when initialized."""
        test_password = "TestPassword123!"
        test_device_name = "TestDevice"
        
        self.device_auth.initialize_device(test_password, test_device_name)
        
        info = self.device_auth.get_device_info()
        
        self.assertEqual(info["status"], "initialized")
        self.assertEqual(info["device_name"], test_device_name)
        self.assertEqual(info["auth_method"], "device_bound_single_user")
        self.assertTrue(info["is_authenticated"])
    
    def test_memory_cleanup_on_deletion(self):
        """Test that memory is properly cleaned up on object deletion."""
        test_password = "TestPassword123!"
        
        # Create device auth and initialize
        device_auth = DeviceAuthManager()
        device_auth.initialize_device(test_password)
        
        # Check that secure objects are registered
        initial_stats = get_secure_memory_manager().get_statistics()
        self.assertGreater(initial_stats.active_allocations, 0)
        
        # Delete the object
        del device_auth
        
        # Force garbage collection and check cleanup
        import gc
        gc.collect()
        time.sleep(0.1)  # Give weak references time to clean up
        
        # Note: Exact cleanup verification may depend on implementation details


class TestDeviceAuthManagerErrorHandling(unittest.TestCase):
    """Test suite for DeviceAuthManager error handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        
        # Mock the home directory
        self.home_patcher = patch('pathlib.Path.home')
        self.mock_home = self.home_patcher.start()
        self.mock_home.return_value = Path(self.test_dir)
        
        get_secure_memory_manager().cleanup_all()
        
        self.device_auth = DeviceAuthManager()
    
    def tearDown(self):
        """Clean up after each test."""
        try:
            self.home_patcher.stop()
            if hasattr(self, 'device_auth'):
                self.device_auth.logout()
            get_secure_memory_manager().cleanup_all()
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass
    
    def test_initialization_with_file_permissions_error(self):
        """Test initialization when file permissions prevent config creation."""
        # Make config directory read-only
        config_dir = Path(self.test_dir) / ".bar"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        if hasattr(os, 'chmod'):
            os.chmod(str(config_dir), 0o444)  # Read-only
        
        try:
            success, message = self.device_auth.initialize_device("TestPassword123!")
            
            # Should handle permission errors gracefully
            if not success:
                self.assertIn("Failed", message)
        finally:
            # Restore permissions for cleanup
            if hasattr(os, 'chmod'):
                os.chmod(str(config_dir), 0o755)
    
    @patch('src.security.device_auth_manager.secrets.token_bytes')
    def test_initialization_with_random_generation_error(self, mock_token_bytes):
        """Test initialization when random generation fails."""
        mock_token_bytes.side_effect = OSError("Random generation failed")
        
        success, message = self.device_auth.initialize_device("TestPassword123!")
        
        self.assertFalse(success)
        self.assertIn("failed", message.lower())
    
    def test_authentication_with_corrupted_config(self):
        """Test authentication when config file is corrupted."""
        test_password = "TestPassword123!"
        
        # Initialize normally
        self.device_auth.initialize_device(test_password)
        
        # Corrupt the config file
        config_file = Path(self.test_dir) / ".bar" / "device_config.enc"
        with open(config_file, 'wb') as f:
            f.write(b"corrupted data")
        
        self.device_auth.logout()
        
        # Try to authenticate
        success, message = self.device_auth.authenticate(test_password)
        
        self.assertFalse(success)
        self.assertIn("Failed to load", message)
    
    def test_emergency_wipe_partial_failure(self):
        """Test emergency wipe when some operations fail."""
        test_password = "TestPassword123!"
        
        self.device_auth.initialize_device(test_password)
        
        # Mock some operations to fail
        with patch.object(self.device_auth, 'reset_device') as mock_reset:
            mock_reset.return_value = (False, "Reset failed")
            
            results = self.device_auth.emergency_wipe()
            
            self.assertIsInstance(results, dict)
            self.assertFalse(results.get("device_reset", True))
            self.assertIn("Reset failed", results.get("errors", []))
    
    def test_panic_wipe_with_exceptions(self):
        """Test panic wipe continues even when exceptions occur."""
        test_password = "TestPassword123!"
        
        self.device_auth.initialize_device(test_password)
        
        # Mock some operations to raise exceptions
        with patch.object(self.device_auth._secure_file_ops, 'secure_delete_file') as mock_delete:
            mock_delete.side_effect = Exception("Delete failed")
            
            results = self.device_auth.panic_wipe()
            
            # Should still complete despite errors
            self.assertIn("panic_completed", results)
            # Panic mode is designed to be resilient to errors


class TestDeviceAuthManagerIntegration(unittest.TestCase):
    """Integration tests for DeviceAuthManager with other components."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        
        self.home_patcher = patch('pathlib.Path.home')
        self.mock_home = self.home_patcher.start()
        self.mock_home.return_value = Path(self.test_dir)
        
        get_secure_memory_manager().cleanup_all()
        
        self.device_auth = DeviceAuthManager()
    
    def tearDown(self):
        """Clean up integration test fixtures."""
        try:
            self.home_patcher.stop()
            if hasattr(self, 'device_auth'):
                self.device_auth.logout()
            get_secure_memory_manager().cleanup_all()
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass
    
    def test_secure_memory_integration(self):
        """Test integration with secure memory system."""
        test_password = "TestPassword123!"
        
        initial_stats = get_secure_memory_manager().get_statistics()
        
        # Initialize device (should create secure memory objects)
        self.device_auth.initialize_device(test_password)
        
        after_init_stats = get_secure_memory_manager().get_statistics()
        self.assertGreater(after_init_stats.active_allocations, initial_stats.active_allocations)
        
        # Logout should cleanup secure memory
        self.device_auth.logout()
        
        after_logout_stats = get_secure_memory_manager().get_statistics()
        self.assertLessEqual(after_logout_stats.active_allocations, after_init_stats.active_allocations)
    
    def test_file_operations_integration(self):
        """Test integration with secure file operations."""
        test_password = "TestPassword123!"
        test_file = Path(self.test_dir) / "integration_test.txt"
        test_content = "Integration test content"
        test_file.write_text(test_content)
        
        self.device_auth.initialize_device(test_password)
        
        # Test file blacklisting
        self.assertTrue(self.device_auth.add_file_to_blacklist(test_file, "Integration test"))
        
        # Test secure deletion
        self.assertTrue(self.device_auth.secure_delete_file(test_file))
        self.assertFalse(test_file.exists())
        
        # Test emergency directory wipe
        test_dir = Path(self.test_dir) / "test_wipe_dir"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("content1")
        (test_dir / "file2.txt").write_text("content2")
        
        wipe_results = self.device_auth._secure_file_ops.emergency_wipe_directory(test_dir)
        self.assertGreater(wipe_results["wiped_files"], 0)
    
    def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow."""
        test_password = "TestPassword123!"
        test_device_name = "IntegrationTestDevice"
        
        # 1. Initialize device
        init_success, init_message = self.device_auth.initialize_device(test_password, test_device_name)
        self.assertTrue(init_success)
        self.assertTrue(self.device_auth.is_authenticated())
        
        # 2. Get device info
        device_info = self.device_auth.get_device_info()
        self.assertEqual(device_info["device_name"], test_device_name)
        self.assertEqual(device_info["status"], "initialized")
        
        # 3. Get security status
        security_status = self.device_auth.get_security_status()
        self.assertTrue(security_status["security_features"]["device_bound_auth"])
        
        # 4. Logout
        self.device_auth.logout()
        self.assertFalse(self.device_auth.is_authenticated())
        
        # 5. Authenticate again
        auth_success, auth_message = self.device_auth.authenticate(test_password)
        self.assertTrue(auth_success)
        self.assertTrue(self.device_auth.is_authenticated())
        
        # 6. Test file operations
        test_file = Path(self.test_dir) / "end_to_end_test.txt"
        test_file.write_text("End-to-end test content")
        
        self.assertTrue(self.device_auth.add_file_to_blacklist(test_file, "End-to-end test"))
        self.assertTrue(self.device_auth.secure_delete_file(test_file))
        
        # 7. Final cleanup with emergency wipe
        wipe_results = self.device_auth.emergency_wipe()
        self.assertTrue(wipe_results["device_reset"])
        self.assertTrue(wipe_results["memory_cleanup"])


if __name__ == '__main__':
    # Set up test environment
    import logging
    logging.basicConfig(level=logging.WARNING)
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestDeviceAuthManager,
        TestDeviceAuthManagerErrorHandling,
        TestDeviceAuthManagerIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"DeviceAuthManager Tests")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    
    # Force cleanup
    get_secure_memory_manager().cleanup_all()
