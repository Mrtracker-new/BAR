#!/usr/bin/env python3
"""
BAR Secure Memory Integration Example

This module demonstrates how to integrate secure memory with other BAR security
components, following the project rules for modular architecture and security.

Per BAR Project Rules:
- R001: Modular Architecture Enforcement
- R002: Security-First Design
- R028-R031: Security and Architecture Violations Prevention

Author: Rolan Lobo (RNR)
Version: 2.0.0
"""

import os
import sys
import time
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.secure_memory import (
    SecureBytes, SecureString, MemoryProtectionLevel,
    create_secure_bytes, create_secure_string,
    get_secure_memory_manager, secure_memory_context,
    TPMInterface, AntiForensicsMonitor
)
from security.device_auth_manager import DeviceAuthManager
from security.hardware_id import HardwareIdentifier
from config.config_manager import ConfigManager
from crypto.encryption import EncryptionManager


class SecureAuthenticationSession:
    """Enhanced authentication session with secure memory integration.
    
    This class demonstrates how secure memory integrates with device authentication
    while maintaining security boundaries and proper error handling.
    """
    
    def __init__(self):
        """Initialize secure authentication session."""
        self.logger = logging.getLogger("SecureAuthenticationSession")
        
        # Initialize security components
        self._device_auth = DeviceAuthManager()
        self._hardware_id = HardwareIdentifier()
        self._encryption_manager = EncryptionManager()
        self._tpm_interface = TPMInterface()
        
        # Secure storage for session data
        self._session_password: Optional[SecureString] = None
        self._session_key: Optional[SecureBytes] = None
        self._hardware_fingerprint: Optional[SecureString] = None
        
        # Session state
        self._authenticated = False
        self._session_id = None
        
        self.logger.info("Secure authentication session initialized")
    
    def authenticate_with_secure_memory(self, password: str) -> Tuple[bool, str]:
        """Authenticate user with secure memory protection.
        
        Args:
            password: User password (will be stored securely)
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Store password in secure memory immediately
            with secure_memory_context():
                self._session_password = create_secure_string(
                    password,
                    protection_level=MemoryProtectionLevel.MILITARY if self._tpm_interface.is_available() 
                    else MemoryProtectionLevel.MAXIMUM
                )
                
                # Collect hardware fingerprint securely
                hw_fingerprint = self._hardware_id.get_hardware_id()
                self._hardware_fingerprint = create_secure_string(hw_fingerprint)
                
                # Attempt authentication with secure components
                auth_success, auth_message = self._device_auth.authenticate(
                    self._session_password.get_value()
                )
                
                if auth_success:
                    # Generate secure session key
                    self._generate_secure_session_key()
                    self._authenticated = True
                    self._session_id = self._encryption_manager.generate_token(16)
                    
                    self.logger.info("Secure authentication successful")
                    return True, f"Authentication successful. Session: {self._session_id[:8]}..."
                else:
                    self.logger.warning("Authentication failed")
                    return False, f"Authentication failed: {auth_message}"
                    
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False, f"Authentication error: {str(e)}"
    
    def _generate_secure_session_key(self):
        """Generate secure session key using multiple entropy sources."""
        try:
            # Combine multiple entropy sources
            password_bytes = self._session_password.get_bytes()
            hw_bytes = self._hardware_fingerprint.get_bytes()
            
            # Use encryption manager to derive secure key
            session_salt = self._encryption_manager.generate_salt()
            
            # Create key material from multiple sources
            key_material = password_bytes + hw_bytes + session_salt
            
            # Store in secure memory with TPM protection if available
            self._session_key = create_secure_bytes(
                key_material,
                protection_level=MemoryProtectionLevel.MILITARY,
                use_tmp=self._tmp_interface.is_available(),
                hardware_bound=True
            )
            
            self.logger.debug("Secure session key generated")
            
        except Exception as e:
            self.logger.error(f"Session key generation failed: {e}")
            raise
    
    def encrypt_session_data(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Encrypt data using secure session key.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data dictionary or None if failed
        """
        if not self._authenticated or not self._session_key:
            self.logger.error("Session not authenticated or key not available")
            return None
        
        try:
            # Get session key securely
            session_key_bytes = self._session_key.get_bytes()
            
            # Encrypt using session key
            encrypted_result = self._encryption_manager.encrypt_data(
                data=data,
                key=session_key_bytes[:32],  # Use first 32 bytes for AES-256
                aad=f"session_{self._session_id}".encode()
            )
            
            self.logger.debug(f"Encrypted {len(data)} bytes of session data")
            return encrypted_result
            
        except Exception as e:
            self.logger.error(f"Session data encryption failed: {e}")
            return None
    
    def decrypt_session_data(self, encrypted_data: Dict[str, Any]) -> Optional[bytes]:
        """Decrypt data using secure session key.
        
        Args:
            encrypted_data: Previously encrypted data
            
        Returns:
            Decrypted data or None if failed
        """
        if not self._authenticated or not self._session_key:
            self.logger.error("Session not authenticated or key not available")
            return None
        
        try:
            # Get session key securely
            session_key_bytes = self._session_key.get_bytes()
            
            # Decrypt using session key
            decrypted_data = self._encryption_manager.decrypt_data(
                encrypted_data=encrypted_data,
                key=session_key_bytes[:32],
                aad=f"session_{self._session_id}".encode()
            )
            
            self.logger.debug(f"Decrypted {len(decrypted_data)} bytes of session data")
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"Session data decryption failed: {e}")
            return None
    
    def cleanup_session(self):
        """Securely cleanup session data and resources."""
        try:
            self.logger.info("Cleaning up secure session")
            
            # Clear secure memory objects
            if self._session_password:
                self._session_password.clear()
                self._session_password = None
            
            if self._session_key:
                self._session_key.clear()
                self._session_key = None
            
            if self._hardware_fingerprint:
                self._hardware_fingerprint.clear()
                self._hardware_fingerprint = None
            
            # Reset session state
            self._authenticated = False
            self._session_id = None
            
            # Force secure memory cleanup
            get_secure_memory_manager().cleanup_all()
            
            self.logger.info("Session cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Session cleanup error: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with automatic cleanup."""
        self.cleanup_session()


class SecureConfigurationManager:
    """Configuration manager with secure memory integration.
    
    Demonstrates how to securely store and manage configuration data
    using secure memory while integrating with the BAR config system.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize secure configuration manager."""
        self.logger = logging.getLogger("SecureConfigurationManager")
        
        # Initialize configuration manager
        if config_path:
            self._config_manager = ConfigManager(base_directory=str(config_path))
        else:
            self._config_manager = ConfigManager()
        
        # Secure storage for sensitive configuration values
        self._secure_configs: Dict[str, SecureString] = {}
        
        # Hardware binding for configuration protection
        self._hardware_id = HardwareIdentifier()
        
        self.logger.info("Secure configuration manager initialized")
    
    def set_secure_config(self, key: str, value: str, protection_level: MemoryProtectionLevel = MemoryProtectionLevel.ENHANCED):
        """Set a configuration value with secure memory protection.
        
        Args:
            key: Configuration key
            value: Configuration value (will be stored securely)
            protection_level: Level of memory protection to apply
        """
        try:
            # Store in secure memory
            secure_value = create_secure_string(value, protection_level=protection_level)
            self._secure_configs[key] = secure_value
            
            # Also store encrypted version in regular config for persistence
            encrypted_value = self._encrypt_config_value(value)
            self._config_manager.set_value("secure_configs", key, encrypted_value)
            
            self.logger.debug(f"Secure configuration set: {key}")
            
        except Exception as e:
            self.logger.error(f"Failed to set secure config {key}: {e}")
            raise
    
    def get_secure_config(self, key: str, default: str = "") -> str:
        """Get a securely stored configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            # First check secure memory
            if key in self._secure_configs:
                return self._secure_configs[key].get_value()
            
            # If not in memory, try to load from encrypted storage
            encrypted_value = self._config_manager.get_value("secure_configs", key)
            if encrypted_value:
                decrypted_value = self._decrypt_config_value(encrypted_value)
                if decrypted_value:
                    # Store in secure memory for future access
                    self.set_secure_config(key, decrypted_value)
                    return decrypted_value
            
            return default
            
        except Exception as e:
            self.logger.error(f"Failed to get secure config {key}: {e}")
            return default
    
    def _encrypt_config_value(self, value: str) -> str:
        """Encrypt configuration value for persistent storage."""
        try:
            # Use hardware-bound encryption
            hw_id = self._hardware_id.get_hardware_id()
            
            # Create encryption manager
            encryption_manager = EncryptionManager()
            
            # Encrypt with hardware binding
            encrypted_data = encryption_manager.encrypt_file_content(
                content=value.encode('utf-8'),
                password=hw_id
            )
            
            # Return as JSON string for storage
            import json
            return json.dumps(encrypted_data)
            
        except Exception as e:
            self.logger.error(f"Config encryption failed: {e}")
            raise
    
    def _decrypt_config_value(self, encrypted_value: str) -> Optional[str]:
        """Decrypt configuration value from persistent storage."""
        try:
            # Parse encrypted data
            import json
            encrypted_data = json.loads(encrypted_value)
            
            # Use hardware-bound decryption
            hw_id = self._hardware_id.get_hardware_id()
            
            # Create encryption manager
            encryption_manager = EncryptionManager()
            
            # Decrypt with hardware binding
            decrypted_bytes = encryption_manager.decrypt_file_content(
                encrypted_content=encrypted_data,
                password=hw_id
            )
            
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Config decryption failed: {e}")
            return None
    
    def clear_secure_configs(self):
        """Clear all secure configuration data."""
        try:
            for key, secure_value in self._secure_configs.items():
                secure_value.clear()
            
            self._secure_configs.clear()
            self.logger.info("Secure configurations cleared")
            
        except Exception as e:
            self.logger.error(f"Failed to clear secure configs: {e}")
    
    def __del__(self):
        """Cleanup on deletion."""
        try:
            self.clear_secure_configs()
        except:
            pass


class EmergencySecureWipe:
    """Emergency security protocol with comprehensive secure memory wipe.
    
    Integrates with secure memory system to provide emergency data
    destruction capabilities following BAR security protocols.
    """
    
    def __init__(self):
        """Initialize emergency secure wipe system."""
        self.logger = logging.getLogger("EmergencySecureWipe")
        
        # Initialize security components
        self._memory_manager = get_secure_memory_manager()
        self._anti_forensics = AntiForensicsMonitor()
        
        # Setup emergency monitoring
        self._anti_forensics.add_alert_callback(self._handle_security_alert)
        self._emergency_triggered = False
        
        self.logger.info("Emergency secure wipe system initialized")
    
    def _handle_security_alert(self, event):
        """Handle security alerts and trigger emergency wipe if needed."""
        self.logger.warning(f"Security alert: {event.event_type} - {event.message}")
        
        # Trigger emergency wipe for critical alerts
        if event.severity == "critical" and not self._emergency_triggered:
            self.logger.critical("Critical security alert - triggering emergency wipe")
            self.trigger_emergency_wipe("Critical security alert detected")
    
    def trigger_emergency_wipe(self, reason: str = "Manual trigger"):
        """Trigger comprehensive emergency security wipe.
        
        Args:
            reason: Reason for triggering emergency wipe
        """
        if self._emergency_triggered:
            self.logger.warning("Emergency wipe already in progress")
            return
        
        self._emergency_triggered = True
        self.logger.critical(f"EMERGENCY WIPE TRIGGERED: {reason}")
        
        try:
            # Phase 1: Secure memory cleanup
            self.logger.critical("Phase 1: Secure memory wipe")
            cleaned_objects = self._memory_manager.cleanup_all()
            self.logger.critical(f"Wiped {cleaned_objects} secure memory objects")
            
            # Phase 2: Force garbage collection and memory cleanup
            self.logger.critical("Phase 2: Force garbage collection")
            self._memory_manager.force_cleanup_and_gc()
            
            # Phase 3: Clear any remaining sensitive data structures
            self.logger.critical("Phase 3: Clear sensitive data structures")
            self._clear_sensitive_data_structures()
            
            # Phase 4: OS-level secure deletion if possible
            self.logger.critical("Phase 4: OS-level secure operations")
            self._perform_os_level_cleanup()
            
            self.logger.critical("EMERGENCY WIPE COMPLETED")
            
        except Exception as e:
            self.logger.error(f"Emergency wipe error: {e}")
        finally:
            self._emergency_triggered = False
    
    def _clear_sensitive_data_structures(self):
        """Clear known sensitive data structures."""
        try:
            # Clear any global sensitive variables
            import gc
            
            # Force collection of all generations
            for generation in range(3):
                collected = gc.collect()
                self.logger.debug(f"GC generation {generation}: collected {collected} objects")
            
            # Clear referrer cycles
            gc.collect()
            
        except Exception as e:
            self.logger.error(f"Data structure clearing failed: {e}")
    
    def _perform_os_level_cleanup(self):
        """Perform OS-level cleanup operations."""
        try:
            # Platform-specific secure cleanup
            if sys.platform == "win32":
                self._windows_secure_cleanup()
            elif sys.platform in ("linux", "darwin"):
                self._unix_secure_cleanup()
            
        except Exception as e:
            self.logger.error(f"OS-level cleanup failed: {e}")
    
    def _windows_secure_cleanup(self):
        """Windows-specific secure cleanup."""
        try:
            # Clear clipboard
            import ctypes
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            
            user32.OpenClipboard(0)
            user32.EmptyClipboard()
            user32.CloseClipboard()
            
            self.logger.debug("Windows clipboard cleared")
            
        except Exception as e:
            self.logger.debug(f"Windows cleanup failed: {e}")
    
    def _unix_secure_cleanup(self):
        """Unix-specific secure cleanup."""
        try:
            # Clear any temporary files
            import tempfile
            temp_dir = Path(tempfile.gettempdir())
            
            # This is a basic example - real implementation would be more comprehensive
            self.logger.debug(f"Checked temporary directory: {temp_dir}")
            
        except Exception as e:
            self.logger.debug(f"Unix cleanup failed: {e}")
    
    def start_monitoring(self):
        """Start emergency monitoring."""
        if not self._anti_forensics._monitoring:
            self._anti_forensics.start_monitoring()
            self.logger.info("Emergency monitoring started")
    
    def stop_monitoring(self):
        """Stop emergency monitoring."""
        if self._anti_forensics._monitoring:
            self._anti_forensics.stop_monitoring()
            self.logger.info("Emergency monitoring stopped")


def demonstrate_integration():
    """Demonstrate integration of secure memory with BAR security components."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("SecureMemoryDemo")
    
    logger.info("=" * 60)
    logger.info("BAR SECURE MEMORY INTEGRATION DEMONSTRATION")
    logger.info("=" * 60)
    
    try:
        # Demo 1: Secure Authentication Session
        logger.info("\n1. Demonstrating Secure Authentication Session")
        logger.info("-" * 40)
        
        with SecureAuthenticationSession() as auth_session:
            # Simulate authentication (would use real password in practice)
            test_password = "demo_password_123"
            success, message = auth_session.authenticate_with_secure_memory(test_password)
            logger.info(f"Authentication result: {success} - {message}")
            
            if success:
                # Demonstrate session encryption
                test_data = b"Sensitive session data that needs protection"
                encrypted = auth_session.encrypt_session_data(test_data)
                if encrypted:
                    logger.info("Session data encrypted successfully")
                    
                    # Decrypt and verify
                    decrypted = auth_session.decrypt_session_data(encrypted)
                    if decrypted == test_data:
                        logger.info("Session data decrypted and verified successfully")
        
        logger.info("Secure authentication session completed and cleaned up")
        
        # Demo 2: Secure Configuration Management
        logger.info("\n2. Demonstrating Secure Configuration Management")
        logger.info("-" * 40)
        
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            config_mgr = SecureConfigurationManager(Path(temp_dir))
            
            # Store sensitive configuration
            config_mgr.set_secure_config("api_key", "secret_api_key_12345", MemoryProtectionLevel.MAXIMUM)
            config_mgr.set_secure_config("database_password", "super_secret_db_pass", MemoryProtectionLevel.MILITARY)
            
            # Retrieve and verify
            retrieved_api_key = config_mgr.get_secure_config("api_key")
            logger.info(f"Retrieved API key: {'*' * len(retrieved_api_key)} (masked)")
            
            config_mgr.clear_secure_configs()
            logger.info("Secure configurations cleared")
        
        # Demo 3: Emergency Secure Wipe
        logger.info("\n3. Demonstrating Emergency Secure Wipe")
        logger.info("-" * 40)
        
        emergency_wipe = EmergencySecureWipe()
        
        # Create some secure data to wipe
        test_secure_data = [
            create_secure_string(f"Test data {i}") for i in range(5)
        ]
        
        initial_stats = get_secure_memory_manager().get_statistics()
        logger.info(f"Initial secure objects: {initial_stats.active_allocations}")
        
        # Trigger emergency wipe
        emergency_wipe.trigger_emergency_wipe("Demonstration purposes")
        
        final_stats = get_secure_memory_manager().get_statistics()
        logger.info(f"Final secure objects: {final_stats.active_allocations}")
        
        logger.info("\n" + "=" * 60)
        logger.info("INTEGRATION DEMONSTRATION COMPLETED SUCCESSFULLY")
        logger.info("=" * 60)
        
        # Display final memory statistics
        stats = get_secure_memory_manager().get_statistics()
        logger.info(f"\nFinal Memory Statistics:")
        logger.info(f"  Total allocations: {stats.total_allocations}")
        logger.info(f"  Active allocations: {stats.active_allocations}")
        logger.info(f"  Cleanup operations: {stats.cleanup_operations}")
        logger.info(f"  Memory monitoring alerts: {stats.memory_monitoring_alerts}")
        
    except Exception as e:
        logger.error(f"Integration demonstration failed: {e}")
        raise
    finally:
        # Final cleanup
        get_secure_memory_manager().cleanup_all()


if __name__ == "__main__":
    demonstrate_integration()
