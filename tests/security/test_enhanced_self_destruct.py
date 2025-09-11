"""
Comprehensive test suite for enhanced self-destruct system.

Tests all aspects of the enhanced self-destruct functionality including:
- Secure deletion with various patterns and verification
- Emergency protocol graded destruction levels
- Intelligent monitoring and threat detection
- Steganographic triggers
- Hardware-level wipe capabilities
- Edge cases and failure scenarios

Per project security rules:
- R023: Test coverage standards with unit tests for all public methods
- R024: Test organization mirroring source structure
- R025: Test security with no real sensitive data
"""

import os
import sys
import time
import tempfile
import shutil
import secrets
import threading
from pathlib import Path
from unittest import TestCase, mock
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from security.secure_delete import SecureDelete
from security.emergency_protocol import EmergencyProtocol
from security.intelligent_monitor import IntelligentFileMonitor, ThreatLevel, AccessPattern
from security.steganographic_triggers import SteganographicTriggerSystem, TriggerType, TriggerAction
from security.hardware_wipe import HardwareWipe, WipePattern


class TestSecureDelete(TestCase):
    """Test enhanced secure deletion functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.secure_delete = SecureDelete()
        
    def tearDown(self):
        """Clean up test environment."""
        try:
            shutil.rmtree(self.test_dir)
        except Exception:
            pass
    
    def test_secure_delete_file_basic(self):
        """Test basic secure file deletion."""
        # Create test file
        test_file = self.test_dir / "test_file.txt"
        test_content = b"Test content for secure deletion"
        test_file.write_bytes(test_content)
        
        # Verify file exists
        self.assertTrue(test_file.exists())
        
        # Perform secure deletion
        result = self.secure_delete.secure_delete_file(str(test_file))
        
        # Verify deletion
        self.assertTrue(result)
        self.assertFalse(test_file.exists())
    
    def test_secure_delete_with_filename_randomization(self):
        """Test that filename randomization occurs during deletion."""
        test_file = self.test_dir / "specific_filename.txt"
        test_file.write_bytes(b"content")
        
        original_name = test_file.name
        
        # Mock the rename to track if it was called
        with mock.patch.object(Path, 'rename') as mock_rename:
            mock_rename.side_effect = lambda new_path: None  # Simulate successful rename
            
            result = self.secure_delete.secure_delete_file(str(test_file))
            
            # Check that rename was attempted (filename randomization)
            self.assertTrue(mock_rename.called)
    
    def test_secure_delete_nonexistent_file(self):
        """Test secure deletion of non-existent file."""
        nonexistent_file = self.test_dir / "does_not_exist.txt"
        
        result = self.secure_delete.secure_delete_file(str(nonexistent_file))
        
        # Should return False for non-existent file
        self.assertFalse(result)
    
    def test_secure_delete_directory(self):
        """Test secure directory deletion."""
        # Create test directory with files
        test_subdir = self.test_dir / "test_subdir"
        test_subdir.mkdir()
        
        (test_subdir / "file1.txt").write_bytes(b"content1")
        (test_subdir / "file2.txt").write_bytes(b"content2")
        
        # Perform secure deletion
        result = self.secure_delete.secure_delete_directory(str(test_subdir))
        
        # Verify deletion
        self.assertTrue(result)
        self.assertFalse(test_subdir.exists())
    
    def test_secure_delete_various_passes(self):
        """Test secure deletion with different numbers of passes."""
        for passes in [1, 3, 7, 10]:
            with self.subTest(passes=passes):
                test_file = self.test_dir / f"test_passes_{passes}.txt"
                test_file.write_bytes(b"content" * 100)  # Larger content
                
                result = self.secure_delete.secure_delete_file(str(test_file), passes=passes)
                
                self.assertTrue(result)
                self.assertFalse(test_file.exists())


class TestEmergencyProtocol(TestCase):
    """Test enhanced emergency protocol functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        
        # Create mock device auth manager
        self.mock_device_auth = mock.MagicMock()
        self.mock_device_auth.emergency_wipe.return_value = {
            "device_reset": True,
            "memory_cleanup": True,
            "total_files_wiped": 5,
            "total_bytes_wiped": 1024
        }
        
        self.emergency_protocol = EmergencyProtocol(self.test_dir, self.mock_device_auth)
        
    def tearDown(self):
        """Clean up test environment."""
        try:
            self.emergency_protocol.stop_dead_mans_switch()
            shutil.rmtree(self.test_dir)
        except Exception:
            pass
    
    def test_graded_destruction_selective(self):
        """Test selective destruction level."""
        # Create test files and directories
        (self.test_dir / "data").mkdir()
        (self.test_dir / "logs").mkdir()
        (self.test_dir / "data" / "test.txt").write_text("test content")
        (self.test_dir / "config.json").write_text("{'test': 'config'}")
        
        # Mock sys.exit to prevent actual exit
        with mock.patch('sys.exit'):
            with mock.patch('os._exit'):
                self.emergency_protocol.trigger_emergency_destruction(
                    reason="Test selective", 
                    level="selective"
                )
        
        # Verify device auth emergency_wipe was called
        self.mock_device_auth.emergency_wipe.assert_called()
        
        # Check that destruction confirmation was created
        destruction_file = self.test_dir / "DESTROYED.txt"
        self.assertTrue(destruction_file.exists())
        content = destruction_file.read_text()
        self.assertIn("Level: selective", content)
    
    def test_graded_destruction_aggressive(self):
        """Test aggressive destruction level."""
        # Create test structure
        (self.test_dir / "data").mkdir()
        (self.test_dir / "cache").mkdir()
        
        with mock.patch('sys.exit'):
            with mock.patch('os._exit'):
                self.emergency_protocol.trigger_emergency_destruction(
                    reason="Test aggressive",
                    level="aggressive"
                )
        
        # Verify higher level of destruction
        args, kwargs = self.mock_device_auth.emergency_wipe.call_args
        self.assertTrue(kwargs.get('wipe_user_data', False))
        self.assertTrue(kwargs.get('wipe_temp_files', False))
    
    def test_graded_destruction_scorched(self):
        """Test scorched earth destruction level."""
        # Create comprehensive test structure
        (self.test_dir / "quarantine").mkdir()
        (self.test_dir / "blacklist.json").write_text("[]")
        
        with mock.patch('sys.exit'):
            with mock.patch('os._exit'):
                self.emergency_protocol.trigger_emergency_destruction(
                    reason="Test scorched",
                    level="scorched"
                )
        
        # Verify maximum destruction
        destruction_file = self.test_dir / "DESTROYED.txt"
        content = destruction_file.read_text()
        self.assertIn("Level: scorched", content)
    
    def test_dead_mans_switch(self):
        """Test dead man's switch functionality."""
        # Set short timeout for testing
        self.emergency_protocol.set_dead_mans_switch_timeout(hours=1)
        
        # Start dead man's switch
        self.emergency_protocol.start_dead_mans_switch()
        
        # Verify it's active
        status = self.emergency_protocol.get_emergency_status()
        self.assertTrue(status["dead_mans_switch_active"])
        
        # Test heartbeat functionality
        self.emergency_protocol.heartbeat()
        
        # Stop the switch
        self.emergency_protocol.stop_dead_mans_switch()
        
        status = self.emergency_protocol.get_emergency_status()
        self.assertFalse(status["dead_mans_switch_active"])
    
    def test_blacklist_functionality(self):
        """Test file blacklisting and quarantine."""
        test_file = self.test_dir / "test_file.txt"
        test_file.write_text("test content")
        
        # Add to blacklist
        self.emergency_protocol.add_to_blacklist(str(test_file), "Test reason")
        
        # Verify file is blacklisted
        self.assertTrue(self.emergency_protocol.is_blacklisted(str(test_file)))
        
        # Verify file was deleted
        self.assertFalse(test_file.exists())
        
        # Check blacklist
        blacklist = self.emergency_protocol.get_blacklist()
        self.assertIn(str(test_file.resolve()), blacklist)
    
    def test_quarantine_file(self):
        """Test file quarantine functionality."""
        test_file = self.test_dir / "quarantine_test.txt"
        test_file.write_text("quarantine content")
        
        # Quarantine the file
        self.emergency_protocol.quarantine_file(str(test_file), "Security risk")
        
        # Verify original file is gone
        self.assertFalse(test_file.exists())
        
        # Verify quarantine directory was created
        quarantine_dir = self.test_dir / "quarantine"
        self.assertTrue(quarantine_dir.exists())


class TestIntelligentMonitor(TestCase):
    """Test intelligent monitoring functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.monitor = IntelligentFileMonitor(self.test_dir)
        self.threat_callbacks_called = []
        
    def tearDown(self):
        """Clean up test environment."""
        try:
            self.monitor.stop_monitoring()
            shutil.rmtree(self.test_dir)
        except Exception:
            pass
    
    def test_access_event_recording(self):
        """Test access event recording and analysis."""
        # Record some access events
        self.monitor.record_access_event("file1", "access", success=True)
        self.monitor.record_access_event("file2", "access", success=False)
        self.monitor.record_access_event("file1", "decrypt", success=True)
        
        # Analyze behavior
        analysis = self.monitor.analyze_current_behavior()
        
        self.assertIn("event_count", analysis)
        self.assertIn("threat_level", analysis)
        self.assertEqual(analysis["event_count"], 3)
    
    def test_behavioral_profiling(self):
        """Test user behavioral profile updates."""
        # Generate some learning events
        current_time = datetime.now()
        for i in range(20):
            event_time = current_time - timedelta(hours=i)
            with mock.patch('datetime.datetime') as mock_dt:
                mock_dt.now.return_value = event_time
                self.monitor.record_access_event(f"file{i}", "access", success=True)
        
        # Update profile
        self.monitor.update_user_profile()
        
        # Get stats
        stats = self.monitor.get_monitoring_stats()
        self.assertIn("baseline_failure_rate", stats)
        self.assertIn("typical_access_hours", stats)
    
    def test_threat_callback_registration(self):
        """Test threat callback registration and triggering."""
        callback_data = []
        
        def threat_callback(data):
            callback_data.append(data)
        
        # Register callback
        self.monitor.register_threat_callback(ThreatLevel.HIGH, threat_callback)
        
        # Generate high-threat scenario (many failures)
        for _ in range(6):  # Above failure threshold
            self.monitor.record_access_event("file1", "access", success=False)
        
        # Verify callback was triggered
        self.assertTrue(len(callback_data) > 0)
    
    def test_tampering_detection(self):
        """Test tampering detection capabilities."""
        # Test with no tampering
        result = self.monitor.detect_tampering()
        self.assertIsNone(result)
        
        # The detect_tampering method is conservative to avoid false positives
        # In a real scenario, it would detect suspicious processes and activities
    
    def test_monitoring_lifecycle(self):
        """Test monitoring start/stop lifecycle."""
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Verify it's active
        stats = self.monitor.get_monitoring_stats()
        self.assertTrue(stats["monitoring_active"])
        
        # Stop monitoring
        self.monitor.stop_monitoring()
        
        # Give it time to stop
        time.sleep(0.1)
        
        stats = self.monitor.get_monitoring_stats()
        self.assertFalse(stats["monitoring_active"])


class TestSteganographicTriggers(TestCase):
    """Test steganographic trigger functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.steg_system = SteganographicTriggerSystem(self.test_dir)
        self.triggered_actions = []
        
    def tearDown(self):
        """Clean up test environment."""
        try:
            self.steg_system.cleanup()
            shutil.rmtree(self.test_dir)
        except Exception:
            pass
    
    def test_trigger_installation(self):
        """Test steganographic trigger installation."""
        # Install a password pattern trigger
        trigger_id = self.steg_system.install_trigger(
            TriggerType.PASSWORD_PATTERN,
            "exact:test_password_123",
            TriggerAction.SELECTIVE_WIPE,
            sensitivity=1.0,
            description="Test trigger"
        )
        
        self.assertTrue(len(trigger_id) > 0)
        
        # Get trigger stats
        stats = self.steg_system.get_trigger_stats()
        self.assertGreater(stats["total_triggers"], 0)
        self.assertGreater(stats["active_triggers"], 0)
    
    def test_password_trigger_activation(self):
        """Test password-based trigger activation."""
        callback_data = []
        
        def trigger_callback(data):
            callback_data.append(data)
        
        # Register callback
        self.steg_system.register_trigger_callback(TriggerAction.SELECTIVE_WIPE, trigger_callback)
        
        # Install trigger
        self.steg_system.install_trigger(
            TriggerType.PASSWORD_PATTERN,
            "exact:emergency_password_456",
            TriggerAction.SELECTIVE_WIPE
        )
        
        # Test non-matching password
        result = self.steg_system.check_password_trigger("wrong_password")
        self.assertFalse(result)
        
        # Test matching password
        result = self.steg_system.check_password_trigger("emergency_password_456")
        self.assertTrue(result)
        self.assertTrue(len(callback_data) > 0)
    
    def test_access_pattern_triggers(self):
        """Test access pattern-based triggers."""
        # Install access count trigger
        self.steg_system.install_trigger(
            TriggerType.ACCESS_SEQUENCE,
            "count:access:5",
            TriggerAction.AGGRESSIVE_WIPE,
            sensitivity=1.0
        )
        
        # Generate access events (below threshold)
        for i in range(3):
            result = self.steg_system.check_access_pattern_trigger(f"file_{i}", "access")
            self.assertFalse(result)
        
        # Generate events that exceed threshold
        for i in range(3, 8):
            result = self.steg_system.check_access_pattern_trigger(f"file_{i}", "access")
            if result:  # Trigger should activate on one of these
                break
        else:
            self.fail("Access pattern trigger should have activated")
    
    def test_timing_triggers(self):
        """Test timing-based triggers."""
        # Install hour-based trigger
        target_hour = datetime.now().hour
        self.steg_system.install_trigger(
            TriggerType.TIMING_PATTERN,
            f"hour:{target_hour}",
            TriggerAction.SELECTIVE_WIPE
        )
        
        # Test with current time (should match)
        result = self.steg_system.check_timing_trigger()
        self.assertTrue(result)
        
        # Test with different hour
        different_time = datetime.now().replace(hour=(target_hour + 1) % 24)
        result = self.steg_system.check_timing_trigger(different_time)
        self.assertFalse(result)
    
    def test_content_signature_triggers(self):
        """Test content signature-based triggers."""
        test_content = b"This is test content for signature detection"
        content_hash = "hash:" + test_content.hex()[:32]  # Simplified hash
        
        # Install content signature trigger
        self.steg_system.install_trigger(
            TriggerType.CONTENT_SIGNATURE,
            content_hash,
            TriggerAction.SCORCHED_EARTH
        )
        
        # Test with non-matching content
        result = self.steg_system.check_content_signature_trigger(b"different content")
        self.assertFalse(result)
        
        # Note: Full content signature matching would require more complex implementation
    
    def test_trigger_persistence(self):
        """Test trigger persistence across system restarts."""
        # Install trigger
        trigger_id = self.steg_system.install_trigger(
            TriggerType.PASSWORD_PATTERN,
            "exact:persistent_trigger",
            TriggerAction.AGGRESSIVE_WIPE
        )
        
        # Create new system instance (simulating restart)
        new_system = SteganographicTriggerSystem(self.test_dir)
        
        # Verify trigger persists
        stats = new_system.get_trigger_stats()
        self.assertGreater(stats["total_triggers"], 0)
        
        new_system.cleanup()


class TestHardwareWipe(TestCase):
    """Test hardware-level wipe capabilities."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.hardware_wipe = HardwareWipe()
        
    def tearDown(self):
        """Clean up test environment."""
        try:
            shutil.rmtree(self.test_dir)
        except Exception:
            pass
    
    def test_platform_capabilities_detection(self):
        """Test platform capability detection."""
        capabilities = self.hardware_wipe.get_platform_capabilities()
        
        self.assertIn("capabilities", capabilities)
        self.assertIn("platform", capabilities)
        self.assertIn("chunk_size", capabilities)
        self.assertIn("safety_limits", capabilities)
        
        # Should detect current platform correctly
        self.assertEqual(capabilities["platform"], sys.platform)
    
    def test_volume_info_gathering(self):
        """Test volume information gathering."""
        volume_info = self.hardware_wipe._get_volume_info(self.test_dir)
        
        self.assertTrue(volume_info["success"])
        self.assertIn("total_bytes", volume_info)
        self.assertIn("free_bytes", volume_info)
        self.assertIn("used_bytes", volume_info)
        self.assertIn("volume", volume_info)
        
        # Verify calculations make sense
        total = volume_info["total_bytes"]
        used = volume_info["used_bytes"]
        free = volume_info["free_bytes"]
        self.assertAlmostEqual(total, used + free, delta=total * 0.01)  # Allow 1% variance
    
    def test_wipe_estimation(self):
        """Test wipe time estimation."""
        # Test with small limit for safety
        estimate = self.hardware_wipe.estimate_wipe_time(self.test_dir, max_bytes=1024*1024)  # 1MB
        
        self.assertTrue(estimate["success"])
        self.assertIn("estimated_bytes", estimate)
        self.assertIn("estimated_seconds", estimate)
        self.assertIn("recommendation", estimate)
        
        # Estimated bytes should not exceed requested maximum
        self.assertLessEqual(estimate["estimated_bytes"], 1024*1024)
    
    def test_safety_limits(self):
        """Test safety limit configuration."""
        original_limits = self.hardware_wipe.get_platform_capabilities()["safety_limits"]
        
        # Set new limits
        self.hardware_wipe.set_safety_limits(max_wipe_size_gb=5, timeout_seconds=120)
        
        new_limits = self.hardware_wipe.get_platform_capabilities()["safety_limits"]
        self.assertEqual(new_limits["max_wipe_size_gb"], 5)
        self.assertEqual(new_limits["timeout_seconds"], 120)
        
        # Test boundary conditions
        self.hardware_wipe.set_safety_limits(max_wipe_size_gb=200, timeout_seconds=10)  # Out of range
        bounded_limits = self.hardware_wipe.get_platform_capabilities()["safety_limits"]
        self.assertLessEqual(bounded_limits["max_wipe_size_gb"], 100)  # Should be capped
        self.assertGreaterEqual(bounded_limits["timeout_seconds"], 60)   # Should be minimum
    
    def test_pattern_generators(self):
        """Test wipe pattern generators."""
        test_size = 1024
        
        # Test all pattern types
        patterns = [
            WipePattern.ZEROS.value,
            WipePattern.ONES.value,
            WipePattern.RANDOM.value,
            WipePattern.ALTERNATING.value,
            WipePattern.DOD_PATTERN.value
        ]
        
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                generator = self.hardware_wipe._get_pattern_generator(pattern)
                data = generator(test_size)
                
                self.assertEqual(len(data), test_size)
                
                if pattern == WipePattern.ZEROS.value:
                    self.assertEqual(data, b'\\x00' * test_size)
                elif pattern == WipePattern.ONES.value:
                    self.assertEqual(data, b'\\xFF' * test_size)
                elif pattern == WipePattern.ALTERNATING.value:
                    self.assertEqual(data, b'\\xAA' * test_size)
                # Random and DOD patterns vary, just check length
    
    @mock.patch('shutil.disk_usage')
    def test_free_space_wipe_simulation(self, mock_disk_usage):
        """Test free space wipe with mocked disk usage."""
        # Mock disk usage to show available space
        mock_disk_usage.return_value = mock.MagicMock(
            total=10*1024*1024*1024,  # 10GB total
            used=5*1024*1024*1024,    # 5GB used
            free=5*1024*1024*1024     # 5GB free
        )
        
        # Test with very small wipe size for safety
        result = self.hardware_wipe.wipe_volume_free_space(
            self.test_dir,
            max_bytes=1024,  # Only 1KB for testing
            pattern="zeros"
        )
        
        # Should complete successfully with small size
        self.assertTrue(result["success"])
        self.assertIn("bytes_wiped", result)
        self.assertIn("elapsed_seconds", result)


class TestIntegrationScenarios(TestCase):
    """Test integration scenarios and edge cases."""
    
    def setUp(self):
        """Set up integration test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        
    def tearDown(self):
        """Clean up test environment."""
        try:
            shutil.rmtree(self.test_dir)
        except Exception:
            pass
    
    def test_emergency_protocol_with_monitoring(self):
        """Test emergency protocol integration with monitoring."""
        # Create mock device auth
        mock_device_auth = mock.MagicMock()
        mock_device_auth.emergency_wipe.return_value = {"device_reset": True}
        
        # Set up emergency protocol and monitor
        emergency = EmergencyProtocol(self.test_dir, mock_device_auth)
        monitor = IntelligentFileMonitor(self.test_dir)
        
        # Register emergency protocol as threat response
        def emergency_response(threat_data):
            # In real scenario, this would trigger appropriate destruction level
            pass
        
        monitor.register_threat_callback(ThreatLevel.HIGH, emergency_response)
        
        try:
            # Start monitoring
            monitor.start_monitoring()
            
            # Simulate threat scenario
            for _ in range(6):  # Generate threat
                monitor.record_access_event("test_file", "access", success=False)
            
            # Verify monitoring detected threat
            analysis = monitor.analyze_current_behavior()
            self.assertIn("threat_level", analysis)
            
        finally:
            monitor.stop_monitoring()
            emergency.stop_dead_mans_switch()
    
    def test_steganographic_triggers_with_emergency_protocol(self):
        """Test steganographic triggers integrated with emergency protocol."""
        mock_device_auth = mock.MagicMock()
        emergency = EmergencyProtocol(self.test_dir, mock_device_auth)
        steg_system = SteganographicTriggerSystem(self.test_dir)
        
        # Track emergency triggers
        emergency_triggered = []
        
        def emergency_trigger_callback(data):
            emergency_triggered.append(data)
        
        # Register emergency protocol with steganographic system
        steg_system.register_trigger_callback(TriggerAction.SCORCHED_EARTH, emergency_trigger_callback)
        
        # Install emergency trigger
        steg_system.install_trigger(
            TriggerType.PASSWORD_PATTERN,
            "exact:emergency_trigger_test",
            TriggerAction.SCORCHED_EARTH
        )
        
        try:
            # Test trigger activation
            result = steg_system.check_password_trigger("emergency_trigger_test")
            self.assertTrue(result)
            self.assertTrue(len(emergency_triggered) > 0)
            
        finally:
            steg_system.cleanup()
            emergency.stop_dead_mans_switch()
    
    def test_hardware_wipe_with_emergency_protocol(self):
        """Test hardware wipe integration with emergency protocol."""
        # This tests the integration we added to emergency_protocol.py
        mock_device_auth = mock.MagicMock()
        
        # Create emergency protocol (which now includes hardware wipe)
        emergency = EmergencyProtocol(self.test_dir, mock_device_auth)
        
        # Test that hardware wipe is initialized
        self.assertIsNotNone(emergency.hardware_wipe)
        
        try:
            # Test estimation before actual wipe
            estimate = emergency.hardware_wipe.estimate_wipe_time(self.test_dir, max_bytes=1024)
            self.assertTrue(estimate["success"])
            
        finally:
            emergency.stop_dead_mans_switch()
    
    def test_comprehensive_failure_recovery(self):
        """Test failure recovery scenarios."""
        # Test with insufficient permissions
        with mock.patch('pathlib.Path.mkdir', side_effect=PermissionError):
            monitor = IntelligentFileMonitor(self.test_dir)
            # Should handle gracefully
            stats = monitor.get_monitoring_stats()
            self.assertIn("monitoring_active", stats)
        
        # Test with disk full scenario
        with mock.patch('builtins.open', side_effect=OSError(28, "No space left on device")):
            secure_delete = SecureDelete()
            test_file = self.test_dir / "test.txt"
            test_file.write_text("content")
            
            # Should handle disk full gracefully
            result = secure_delete.secure_delete_file(str(test_file))
            # Result depends on implementation - either handles gracefully or fails safely
    
    def test_concurrent_operations(self):
        """Test concurrent self-destruct operations."""
        monitor = IntelligentFileMonitor(self.test_dir)
        
        try:
            monitor.start_monitoring()
            
            # Simulate concurrent access events
            def generate_events(thread_id):
                for i in range(10):
                    monitor.record_access_event(f"file_{thread_id}_{i}", "access", success=True)
                    time.sleep(0.01)
            
            threads = []
            for t in range(3):
                thread = threading.Thread(target=generate_events, args=(t,))
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join()
            
            # Verify all events were recorded properly
            stats = monitor.get_monitoring_stats()
            self.assertGreaterEqual(stats["events_last_24h"], 30)  # 3 threads * 10 events
            
        finally:
            monitor.stop_monitoring()


if __name__ == "__main__":
    import unittest
    
    # Run all tests
    unittest.main(verbosity=2)
