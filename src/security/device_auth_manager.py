import os
import json
import logging
import secrets
import hashlib
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend

from .secure_memory import (
    SecureBytes, SecureString, create_secure_bytes, create_secure_string,
    secure_compare, secure_random_string, MemoryProtectionLevel,
    get_secure_memory_manager, force_secure_memory_cleanup
)
from .hardware_id import HardwareIdentifier
from .secure_file_ops import SecureFileOperations, SecureDeletionMethod, FileSecurityLevel
from ..config.config_manager import ConfigManager


class DeviceAuthManager:
    """Enhanced device authentication manager using secure memory for single-user device-bound authentication.
    
    Features:
    - Single user per device (no multi-user support)
    - Hardware-bound authentication (cannot transfer to other devices)
    - No password recovery (forgot password = device reset required)
    - All sensitive data stored in secure memory with maximum protection
    - Military-grade encryption with PBKDF2 key derivation
    - Emergency wipe capabilities
    
    Per R005 - Key Management: Uses proper key derivation and secure storage.
    Per R006 - Memory Security: All sensitive data stored in SecureBytes/SecureString.
    Per R008 - Plausible Deniability: Single-user system prevents multi-user data leakage.
    """
    
    # Security constants - per R004 Cryptographic Standards
    PBKDF2_ITERATIONS = 200000  # High iteration count for security
    SALT_SIZE = 32  # 256-bit salt
    KEY_SIZE = 32   # 256-bit key
    IV_SIZE = 16    # 128-bit IV for AES
    HARDWARE_TAG_SIZE = 32  # 256-bit HMAC tag for hardware verification
    
    def __init__(self):
        """Initialize the device authentication manager with secure memory."""
        self.logger = logging.getLogger("DeviceAuthManager")
        # Initialize config directory for secure storage
        self._config_dir = Path.home() / ".bar"
        self._config_manager = ConfigManager(base_directory=str(self._config_dir))
        self._hardware_id = HardwareIdentifier()
        self._secure_file_ops = SecureFileOperations()
        
        # Emergency wipe settings
        self._emergency_contacts = []  # For future emergency notification features
        self._panic_triggered = False
        
        # Secure storage for sensitive data - all using maximum protection
        self._master_password = None  # Will be SecureString when set
        self._derived_key = None      # Will be SecureBytes when set
        self._hardware_fingerprint = None  # Will be SecureString when set
        
        # Device state
        self._is_initialized = False
        self._is_authenticated = False
        self._device_name = ""
        
        # Configuration paths
        self._device_config_path = self._config_dir / "device_config.enc"
        self._ensure_config_directory()
        
        self.logger.debug("DeviceAuthManager initialized with secure memory protection")
    
    def _ensure_config_directory(self):
        """Ensure the configuration directory exists with proper permissions."""
        config_dir = self._device_config_path.parent
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        
        # Set restrictive permissions on config directory (owner only)
        if hasattr(os, 'chmod'):
            os.chmod(str(config_dir), 0o700)
    
    def is_device_initialized(self) -> bool:
        """Check if the device has been initialized with a user account.
        
        Returns:
            True if device is initialized, False if first-time setup required
        """
        return self._device_config_path.exists()
    
    def initialize_device(self, password: str, device_name: Optional[str] = None) -> Tuple[bool, str]:
        """Initialize the device with single-user authentication.
        
        This is a one-time setup that creates the hardware-bound user account.
        After initialization, only this password will work on this specific device.
        
        Args:
            password: Master password for device access
            device_name: Optional human-readable device name
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if self.is_device_initialized():
                return False, "Device is already initialized. Use reset_device() to reinitialize."
            
            self.logger.info("Starting device initialization")
            
            # Store password in secure memory with maximum protection
            self._master_password = create_secure_string(password)
            
            # Generate hardware fingerprint and store securely
            hw_fingerprint = self._hardware_id.get_hardware_id()
            self._hardware_fingerprint = create_secure_string(hw_fingerprint)
            
            # Generate cryptographic salt using secure random
            salt_bytes = secrets.token_bytes(self.SALT_SIZE)
            salt = create_secure_bytes(
                salt_bytes, 
                protection_level=MemoryProtectionLevel.MAXIMUM
            )
            
            # Derive encryption key from password + hardware ID
            self._derived_key = self._derive_key(password, hw_fingerprint, salt_bytes)
            
            # Create device configuration
            device_config = {
                "device_id": secure_random_string(32),
                "device_name": device_name or f"BAR-Device-{secure_random_string(8)}",
                "hardware_id": hw_fingerprint,
                "salt": salt_bytes.hex(),  # Store salt for key derivation
                "created_at": int(secrets.randbits(64)),  # Timestamp in secure random bits
                "version": "1.0",
                "auth_method": "device_bound_single_user"
            }
            
            # Create verification hash for authentication
            verification_data = f"{password}|{hw_fingerprint}|{device_config['device_id']}"
            verification_hash = hashlib.sha256(verification_data.encode('utf-8')).hexdigest()
            device_config["verification_hash"] = verification_hash
            
            # Encrypt and save device configuration
            success = self._save_encrypted_config(device_config, self._derived_key.get_bytes())
            
            if success:
                self._is_initialized = True
                self._is_authenticated = True  # Automatically authenticate after initialization
                self._device_name = device_config["device_name"]
                self.logger.info(f"Device successfully initialized and authenticated: {self._device_name}")
                return True, f"Device '{self._device_name}' initialized successfully"
            else:
                # Clean up on failure
                self._cleanup_sensitive_data()
                return False, "Failed to save device configuration"
                
        except Exception as e:
            self.logger.error(f"Device initialization failed: {e}")
            self._cleanup_sensitive_data()
            return False, f"Initialization failed: {str(e)}"
    
    def authenticate(self, password: str) -> Tuple[bool, str]:
        """Authenticate user with device-bound verification.
        
        Verifies:
        1. Device is initialized
        2. Hardware matches stored hardware ID
        3. Password is correct
        
        Args:
            password: Password to authenticate with
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if not self.is_device_initialized():
                return False, "Device not initialized. First-time setup required."
            
            self.logger.debug("Starting authentication process")
            
            # Store password in secure memory
            secure_password = create_secure_string(password)
            
            # Get current hardware fingerprint
            current_hw_id = self._hardware_id.get_hardware_id()
            secure_hw_id = create_secure_string(current_hw_id)
            
            # First, check file format and verify hardware tag if present
            try:
                with open(self._device_config_path, 'rb') as f:
                    file_size = f.seek(0, 2)  # Seek to end to get file size
                    f.seek(0)  # Reset to beginning
                    
                    # Read salt (always present)
                    stored_salt = f.read(self.SALT_SIZE)
                    if len(stored_salt) != self.SALT_SIZE:
                        return False, "Failed to load device configuration: invalid format"
                    
                    # Check if this uses new format with hardware tag
                    has_hardware_tag = file_size >= (self.SALT_SIZE + self.HARDWARE_TAG_SIZE + self.IV_SIZE + 16)
                    
                    if has_hardware_tag:
                        # Read and verify hardware tag before attempting decryption
                        stored_hardware_tag = f.read(self.HARDWARE_TAG_SIZE)
                        if len(stored_hardware_tag) != self.HARDWARE_TAG_SIZE:
                            return False, "Failed to load device configuration: invalid format"
                        
                        # Compute expected hardware tag
                        expected_hardware_tag = self._compute_hardware_tag(current_hw_id, stored_salt)
                        
                        # Verify hardware tag in constant time
                        if not secure_compare(expected_hardware_tag, stored_hardware_tag):
                            self.logger.warning("Hardware verification failed during authentication")
                            return False, "Hardware verification failed. This device is not authorized."
                        
                        self.logger.debug("Hardware tag verification passed")
                    else:
                        self.logger.debug("Using legacy format without hardware tag")
                        
            except Exception as e:
                return False, f"Failed to load device configuration: {e}"
            
            # Now try to decrypt the configuration with the current hardware ID
            temp_derived_key = self._derive_key(password, current_hw_id, stored_salt)
            config_data = self._load_encrypted_config(temp_derived_key.get_bytes())
            
            if not config_data:
                # If we got here and hardware tag was verified, it's likely a password issue
                if has_hardware_tag:
                    self.logger.warning("Authentication failed - unable to decrypt configuration after hardware verification passed")
                    return False, "Authentication failed. Incorrect password."
                else:
                    # Legacy format - could be hardware or password issue
                    self.logger.warning("Authentication failed - unable to decrypt configuration (legacy format)")
                    return False, "Authentication failed. Incorrect password."
            
            # Successfully decrypted - now verify hardware binding as additional check
            stored_hw_id = config_data.get("hardware_id", "")
            if not secure_compare(current_hw_id, stored_hw_id):
                # This should not happen if decryption succeeded, but check anyway
                self.logger.warning("Hardware ID mismatch after successful decryption - unusual")
                return False, "Hardware verification failed. This password is bound to a different device."
            
            # Verify password by reconstructing and comparing verification hash
            verification_data = f"{password}|{current_hw_id}|{config_data['device_id']}"
            computed_hash = hashlib.sha256(verification_data.encode('utf-8')).hexdigest()
            stored_hash = config_data.get("verification_hash", "")
            
            if not secure_compare(computed_hash, stored_hash):
                self.logger.warning("Authentication failed - incorrect password")
                return False, "Authentication failed. Incorrect password."
            
            # Authentication successful - store session data securely
            self._master_password = secure_password
            self._hardware_fingerprint = secure_hw_id
            self._is_authenticated = True
            self._device_name = config_data.get("device_name", "Unknown Device")
            
            # Derive session key for secure operations
            salt = create_secure_bytes(
                secrets.token_bytes(self.SALT_SIZE),
                protection_level=MemoryProtectionLevel.MAXIMUM
            )
            self._derived_key = self._derive_key(password, current_hw_id, salt.get_bytes())
            
            self.logger.info(f"Authentication successful for device: {self._device_name}")
            return True, f"Welcome back to {self._device_name}"
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            self._cleanup_sensitive_data()
            return False, f"Authentication error: {str(e)}"
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        return self._is_authenticated and self._master_password is not None
    
    def logout(self):
        """Securely logout by clearing all sensitive data from memory."""
        self.logger.info("Logging out - clearing sensitive data")
        self._cleanup_sensitive_data()
        self._is_authenticated = False
    
    def reset_device(self, emergency: bool = False) -> Tuple[bool, str]:
        """Reset device by securely wiping all data and configuration.
        
        WARNING: This permanently destroys all user data and cannot be undone.
        Use when password is forgotten or for emergency wipe.
        
        Args:
            emergency: If True, performs emergency wipe without confirmations
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            wipe_type = "Emergency" if emergency else "Standard"
            self.logger.warning(f"{wipe_type} device reset initiated")
            
            # Clear all sensitive data from memory
            self._cleanup_sensitive_data()
            
            # Securely delete configuration file
            if self._device_config_path.exists():
                success = self._secure_delete_file(self._device_config_path)
                if not success and not emergency:
                    return False, "Failed to securely delete device configuration"
            
            # Clear any cached configuration
            self._config_manager.clear_all_cached_config()
            
            # Force complete memory cleanup
            force_secure_memory_cleanup()
            
            # Reset state
            self._is_initialized = False
            self._is_authenticated = False
            self._device_name = ""
            
            self.logger.info(f"{wipe_type} device reset completed successfully")
            return True, f"{wipe_type} reset completed. All data permanently destroyed."
            
        except Exception as e:
            self.logger.error(f"Device reset error: {e}")
            return False, f"Reset failed: {str(e)}"
    
    def emergency_wipe(self, wipe_user_data: bool = True, wipe_temp_files: bool = True) -> Dict[str, Any]:
        """Emergency wipe all sensitive data immediately.
        
        This is a panic function that destroys all data without confirmations.
        Per R007 - Memory Security: Provides emergency data destruction.
        
        Args:
            wipe_user_data: Whether to wipe user data directories
            wipe_temp_files: Whether to wipe temporary files
        
        Returns:
            Dictionary with emergency wipe results
        """
        self._panic_triggered = True
        self.logger.critical("🚨 EMERGENCY WIPE ACTIVATED - DESTROYING ALL DATA 🚨")
        
        wipe_results = {
            "started_at": time.time(),
            "device_reset": False,
            "memory_cleanup": False,
            "user_data_wipe": False,
            "temp_files_wipe": False,
            "config_wipe": False,
            "environment_cleanup": False,
            "total_files_wiped": 0,
            "total_bytes_wiped": 0,
            "errors": [],
            "completed_at": None
        }
        
        try:
            # Step 1: Emergency device reset
            try:
                success, message = self.reset_device(emergency=True)
                wipe_results["device_reset"] = success
                if not success:
                    wipe_results["errors"].append(message)
            except Exception as e:
                wipe_results["errors"].append(f"Device reset error: {str(e)}")
            
            # Step 2: Wipe user data directories
            if wipe_user_data:
                try:
                    user_data_dirs = [
                        Path.home() / ".bar",
                        Path.home() / "Documents" / "BAR",
                        Path.home() / "AppData" / "Local" / "BAR" if os.name == 'nt' else Path.home() / ".local" / "share" / "bar"
                    ]
                    
                    for data_dir in user_data_dirs:
                        if data_dir.exists():
                            results = self._secure_file_ops.emergency_wipe_directory(
                                data_dir, 
                                recursive=True, 
                                method=SecureDeletionMethod.DOD_7_PASS
                            )
                            wipe_results["total_files_wiped"] += results["wiped_files"]
                            wipe_results["total_bytes_wiped"] += results["total_bytes"]
                            wipe_results["errors"].extend(results["errors"])
                    
                    wipe_results["user_data_wipe"] = True
                    
                except Exception as e:
                    wipe_results["errors"].append(f"User data wipe error: {str(e)}")
            
            # Step 3: Wipe temporary files
            if wipe_temp_files:
                try:
                    temp_dirs = [
                        Path.home() / "AppData" / "Local" / "Temp" if os.name == 'nt' else Path("/tmp"),
                        Path(os.environ.get('TEMP', '/tmp')) if os.environ.get('TEMP') else None
                    ]
                    
                    for temp_dir in temp_dirs:
                        if temp_dir and temp_dir.exists():
                            # Only wipe BAR-related temp files to avoid system issues
                            bar_temp_files = list(temp_dir.glob("*BAR*")) + list(temp_dir.glob("*bar*"))
                            for temp_file in bar_temp_files:
                                if temp_file.is_file():
                                    try:
                                        if self._secure_file_ops.secure_delete_file(
                                            temp_file, 
                                            method=SecureDeletionMethod.DOD_3_PASS,
                                            verify=False
                                        ):
                                            wipe_results["total_files_wiped"] += 1
                                    except Exception as e:
                                        wipe_results["errors"].append(f"Temp file wipe error: {str(e)}")
                    
                    wipe_results["temp_files_wipe"] = True
                    
                except Exception as e:
                    wipe_results["errors"].append(f"Temp files wipe error: {str(e)}")
            
            # Step 4: Force memory cleanup
            try:
                # Clear all sensitive data from memory
                self._cleanup_sensitive_data()
                
                # Force multiple garbage collections
                import gc
                for _ in range(5):
                    collected = gc.collect()
                    self.logger.debug(f"Emergency GC collected {collected} objects")
                
                # Force secure memory cleanup
                force_secure_memory_cleanup()
                wipe_results["memory_cleanup"] = True
                
            except Exception as e:
                wipe_results["errors"].append(f"Memory cleanup error: {str(e)}")
            
            # Step 5: Clear environment variables
            try:
                sensitive_env_vars = [
                    'BAR_PASSWORD', 'BAR_KEY', 'BAR_TOKEN', 'BAR_CONFIG',
                    'BAR_USER', 'BAR_SESSION', 'BAR_AUTH', 'BAR_SECRET'
                ]
                
                for var in sensitive_env_vars:
                    if var in os.environ:
                        # Overwrite with dummy data before deletion
                        os.environ[var] = "EMERGENCY_WIPED_" + secrets.token_hex(16)
                        del os.environ[var]
                
                wipe_results["environment_cleanup"] = True
                
            except Exception as e:
                wipe_results["errors"].append(f"Environment cleanup error: {str(e)}")
            
            # Step 6: Final cleanup
            try:
                self._secure_file_ops.cleanup()
            except Exception as e:
                wipe_results["errors"].append(f"File ops cleanup error: {str(e)}")
            
            wipe_results["completed_at"] = time.time()
            duration = wipe_results["completed_at"] - wipe_results["started_at"]
            
            self.logger.critical(
                f"🚨 EMERGENCY WIPE COMPLETED in {duration:.2f}s - "
                f"Files: {wipe_results['total_files_wiped']}, "
                f"Bytes: {wipe_results['total_bytes_wiped']}, "
                f"Errors: {len(wipe_results['errors'])}"
            )
            
            return wipe_results
            
        except Exception as e:
            wipe_results["errors"].append(f"Critical emergency wipe error: {str(e)}")
            wipe_results["completed_at"] = time.time()
            self.logger.critical(f"🚨 EMERGENCY WIPE FAILED: {e}")
            return wipe_results
    
    def panic_wipe(self) -> Dict[str, Any]:
        """Immediate panic wipe with minimal logging for stealth.
        
        This is the fastest possible data destruction method for emergency situations.
        Designed to be called from UI panic buttons or hotkeys.
        
        Returns:
            Minimal results dictionary
        """
        try:
            # Minimal logging to avoid detection
            self._panic_triggered = True
            
            # Immediate memory cleanup
            self._cleanup_sensitive_data()
            force_secure_memory_cleanup()
            
            # Quick device reset
            self.reset_device(emergency=True)
            
            # Quick user data wipe (most critical data)
            critical_paths = [
                self._device_config_path,
                Path.home() / ".bar" / "device_config.enc",
                Path.home() / ".bar" / "security"
            ]
            
            wiped_count = 0
            for path in critical_paths:
                if path.exists():
                    try:
                        if path.is_file():
                            self._secure_file_ops.secure_delete_file(
                                path, 
                                method=SecureDeletionMethod.DOD_3_PASS,
                                verify=False
                            )
                            wiped_count += 1
                        elif path.is_dir():
                            results = self._secure_file_ops.emergency_wipe_directory(
                                path, 
                                recursive=True,
                                method=SecureDeletionMethod.DOD_3_PASS
                            )
                            wiped_count += results["wiped_files"]
                    except Exception:
                        pass  # Silent failure for stealth
            
            return {
                "panic_completed": True, 
                "files_wiped": wiped_count,
                "timestamp": time.time()
            }
            
        except Exception:
            return {
                "panic_completed": False,
                "timestamp": time.time()
            }
    
    def schedule_delayed_wipe(self, delay_seconds: int = 300) -> bool:
        """Schedule a delayed emergency wipe (dead man's switch concept).
        
        Args:
            delay_seconds: Seconds to wait before wiping (default 5 minutes)
            
        Returns:
            True if scheduled successfully, False otherwise
        """
        try:
            import threading
            
            def delayed_wipe():
                time.sleep(delay_seconds)
                self.logger.warning(f"Executing delayed emergency wipe after {delay_seconds}s")
                self.emergency_wipe()
            
            wipe_thread = threading.Thread(target=delayed_wipe, daemon=True)
            wipe_thread.start()
            
            self.logger.info(f"Delayed emergency wipe scheduled for {delay_seconds} seconds")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to schedule delayed wipe: {e}")
            return False
    
    def add_file_to_blacklist(self, file_path: Union[str, Path], reason: str) -> bool:
        """Add a file to the security blacklist for automatic secure deletion.
        
        Args:
            file_path: Path to file to blacklist
            reason: Reason for blacklisting
            
        Returns:
            True if successfully blacklisted, False otherwise
        """
        try:
            return self._secure_file_ops.add_to_blacklist(
                file_path,
                reason=reason,
                security_level=FileSecurityLevel.SECRET,
                deletion_method=SecureDeletionMethod.DOD_7_PASS
            )
        except Exception as e:
            self.logger.error(f"Failed to blacklist file {file_path}: {e}")
            return False
    
    def secure_delete_file(self, file_path: Union[str, Path]) -> bool:
        """Securely delete a file using military-grade methods.
        
        Args:
            file_path: Path to file to delete
            
        Returns:
            True if successfully deleted, False otherwise
        """
        try:
            return self._secure_file_ops.secure_delete_file(
                file_path,
                method=SecureDeletionMethod.DOD_7_PASS,
                verify=True
            )
        except Exception as e:
            self.logger.error(f"Failed to securely delete file {file_path}: {e}")
            return False
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status information.
        
        Returns:
            Dictionary containing security status
        """
        try:
            # Get basic device info
            device_info = self.get_device_info()
            
            # Get secure file operations statistics
            file_stats = self._secure_file_ops.get_statistics()
            
            # Get secure memory statistics
            memory_stats = get_secure_memory_manager().get_statistics()
            
            return {
                **device_info,
                "security_features": {
                    "device_bound_auth": True,
                    "hardware_verification": True,
                    "secure_memory": True,
                    "file_blacklisting": True,
                    "emergency_wipe": True,
                    "panic_mode": self._panic_triggered
                },
                "file_security": file_stats,
                "memory_security": {
                    "active_allocations": memory_stats.active_allocations,
                    "total_allocations": memory_stats.total_allocations,
                    "cleanup_operations": memory_stats.cleanup_operations,
                    "corruption_detections": memory_stats.corruption_detections
                },
                "last_updated": time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting security status: {e}")
            return {
                "status": "error",
                "message": str(e),
                "timestamp": time.time()
            }
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get current device information (non-sensitive data only).
        
        Returns:
            Dictionary containing device information
        """
        if not self.is_device_initialized():
            return {"status": "not_initialized"}
        
        try:
            # If authenticated, we have the derived key and can decrypt the config
            if self._is_authenticated and self._derived_key:
                config_data = self._load_encrypted_config(self._derived_key.get_bytes())
                if config_data:
                    return {
                        "status": "initialized",
                        "device_name": config_data.get("device_name", "Unknown"),
                        "device_id": config_data.get("device_id", "Unknown")[:8] + "...",  # Truncated for security
                        "auth_method": config_data.get("auth_method", "unknown"),
                        "version": config_data.get("version", "unknown"),
                        "is_authenticated": self._is_authenticated,
                        "hardware_verified": self._hardware_id.verify_hardware_id(config_data.get("hardware_id", ""))
                    }
            
            # If not authenticated, return minimal info
            return {
                "status": "initialized",
                "device_name": self._device_name or "Unknown",
                "device_id": "[Encrypted]",
                "auth_method": "device_bound_single_user",
                "version": "1.0",
                "is_authenticated": self._is_authenticated,
                "hardware_verified": False  # Cannot verify without decryption
            }
            
        except Exception as e:
            self.logger.error(f"Error getting device info: {e}")
            return {"status": "error", "message": str(e)}
    
    def _compute_hardware_tag(self, hardware_id: str, salt: bytes) -> bytes:
        """Compute hardware tag for early hardware mismatch detection.
        
        Creates an HMAC tag that can be verified without decrypting the full config.
        This allows us to distinguish between hardware mismatch and wrong password.
        
        Args:
            hardware_id: Hardware identifier string
            salt: Salt bytes used for key derivation
            
        Returns:
            HMAC tag bytes for hardware verification
        """
        try:
            # Derive a key for HMAC from hardware ID and salt using PBKDF2
            combined_data = f"hardware_tag|{hardware_id}".encode('utf-8')
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key for HMAC
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS // 4,  # Faster for tag computation
                backend=default_backend()
            )
            
            tag_key = kdf.derive(combined_data)
            
            # Create HMAC of hardware ID with the derived key
            h = hmac.HMAC(tag_key, hashes.SHA256(), backend=default_backend())
            h.update(hardware_id.encode('utf-8'))
            
            return h.finalize()
            
        except Exception as e:
            self.logger.error(f"Hardware tag computation failed: {e}")
            # Return a deterministic but unpredictable fallback
            fallback_data = f"fallback|{hardware_id}".encode('utf-8')
            return hashlib.sha256(fallback_data).digest()
    
    def _derive_key(self, password: str, hardware_id: str, salt: bytes) -> SecureBytes:
        """Derive encryption key from password and hardware ID using PBKDF2.
        
        Per R005 - Key Management: Uses PBKDF2 with high iteration count.
        
        Args:
            password: User password
            hardware_id: Hardware identifier
            salt: Random salt
            
        Returns:
            SecureBytes containing derived key
        """
        # Combine password and hardware ID for additional security
        combined_data = f"{password}|{hardware_id}".encode('utf-8')
        
        # Use PBKDF2 with SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        key_bytes = kdf.derive(combined_data)
        
        # Store in secure memory with maximum protection
        return create_secure_bytes(
            key_bytes, 
            protection_level=MemoryProtectionLevel.MAXIMUM,
            require_lock=True
        )
    
    def _save_encrypted_config(self, config_data: Dict[str, Any], key: bytes) -> bool:
        """Save configuration data in encrypted format.
        
        Args:
            config_data: Configuration dictionary to save
            key: Encryption key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert config to JSON
            config_json = json.dumps(config_data, separators=(',', ':'))
            config_bytes = config_json.encode('utf-8')
            
            # Generate random IV
            iv = secrets.token_bytes(self.IV_SIZE)
            
            # Encrypt using AES-256-CBC
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad data to block size (PKCS7 padding)
            block_size = 16
            padding_length = block_size - (len(config_bytes) % block_size)
            padded_data = config_bytes + bytes([padding_length]) * padding_length
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Extract salt from config and store it unencrypted (needed for key derivation)
            salt_hex = config_data.get('salt', '')
            salt_bytes = bytes.fromhex(salt_hex) if salt_hex else b'\x00' * self.SALT_SIZE
            
            # Compute hardware tag for early hardware mismatch detection
            hardware_id = config_data.get('hardware_id', '')
            hardware_tag = self._compute_hardware_tag(hardware_id, salt_bytes)
            
            # Save salt + hardware_tag + IV + encrypted data
            with open(self._device_config_path, 'wb') as f:
                f.write(salt_bytes)     # First 32 bytes: salt
                f.write(hardware_tag)   # Next 32 bytes: hardware tag
                f.write(iv)             # Next 16 bytes: IV
                f.write(encrypted_data) # Rest: encrypted config
            
            # Set restrictive permissions (owner only)
            if hasattr(os, 'chmod'):
                os.chmod(str(self._device_config_path), 0o600)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save encrypted config: {e}")
            return False
    
    def _load_encrypted_config(self, key: Optional[bytes] = None) -> Optional[Dict[str, Any]]:
        """Load and decrypt configuration data.
        
        Args:
            key: Optional decryption key. If not provided, returns metadata only.
        
        Returns:
            Configuration dictionary or None if failed
        """
        try:
            if not self._device_config_path.exists():
                return None
            
            with open(self._device_config_path, 'rb') as f:
                # Read the file header to determine format
                file_size = f.seek(0, 2)  # Seek to end to get file size
                f.seek(0)  # Reset to beginning
                
                # Minimum expected sizes:
                # Old format: SALT(32) + IV(16) + ENCRYPTED_DATA(>=16) = 64+ bytes
                # New format: SALT(32) + HARDWARE_TAG(32) + IV(16) + ENCRYPTED_DATA(>=16) = 96+ bytes
                
                salt_bytes = f.read(self.SALT_SIZE)
                if len(salt_bytes) != self.SALT_SIZE:
                    self.logger.error("Invalid config file: cannot read salt")
                    return None
                
                # Check if this is the new format with hardware tag
                has_hardware_tag = file_size >= (self.SALT_SIZE + self.HARDWARE_TAG_SIZE + self.IV_SIZE + 16)
                
                if has_hardware_tag:
                    # New format: read hardware tag, then IV, then encrypted data
                    hardware_tag = f.read(self.HARDWARE_TAG_SIZE)
                    iv = f.read(self.IV_SIZE)
                    encrypted_data = f.read()
                    
                    if len(hardware_tag) != self.HARDWARE_TAG_SIZE or len(iv) != self.IV_SIZE or not encrypted_data:
                        self.logger.error("Invalid encrypted config file format (new format)")
                        return None
                else:
                    # Old format: read IV directly after salt, then encrypted data
                    hardware_tag = None
                    iv = f.read(self.IV_SIZE)
                    encrypted_data = f.read()
                    
                    if len(iv) != self.IV_SIZE or not encrypted_data:
                        self.logger.error("Invalid encrypted config file format (old format)")
                        return None
            
            # If no key provided, return minimal info including salt and hardware tag
            if key is None:
                result = {
                    "status": "encrypted", 
                    "config_exists": True, 
                    "salt": salt_bytes.hex(),
                    "has_hardware_tag": has_hardware_tag
                }
                if hardware_tag is not None:
                    result["hardware_tag"] = hardware_tag.hex()
                return result
            
            # Decrypt the configuration
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = decrypted_padded[-1]
            decrypted_data = decrypted_padded[:-padding_length]
            
            # Parse JSON
            config_json = decrypted_data.decode('utf-8')
            config_data = json.loads(config_json)
            
            return config_data
            
        except Exception as e:
            self.logger.error(f"Failed to load encrypted config: {e}")
            return None
    
    def _secure_delete_file(self, file_path: Path) -> bool:
        """Securely delete a file using multiple overwrite passes.
        
        Per R006 - Memory Security: Secure file deletion to prevent recovery.
        
        Args:
            file_path: Path to file to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not file_path.exists():
                return True
            
            file_size = file_path.stat().st_size
            
            # Multiple overwrite passes
            patterns = [b'\x00', b'\xFF', b'\xAA', b'\x55']
            
            with open(file_path, 'r+b') as f:
                for pattern in patterns:
                    f.seek(0)
                    f.write(pattern * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Final pass with random data
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            # Delete the file
            file_path.unlink()
            return True
            
        except Exception as e:
            self.logger.error(f"Secure file deletion failed: {e}")
            return False
    
    def _cleanup_sensitive_data(self):
        """Securely clear all sensitive data from memory.
        
        Per R006 - Memory Security: Must clear sensitive data immediately after use.
        """
        try:
            if self._master_password:
                self._master_password.clear()
                self._master_password = None
            
            if self._derived_key:
                self._derived_key.clear()
                self._derived_key = None
            
            if self._hardware_fingerprint:
                self._hardware_fingerprint.clear()
                self._hardware_fingerprint = None
            
            # Force cleanup of any registered secure objects
            get_secure_memory_manager().cleanup_all()
            
        except Exception as e:
            self.logger.warning(f"Error during sensitive data cleanup: {e}")
    
    def is_panic_triggered(self) -> bool:
        """Check if panic mode has been triggered.
        
        Returns:
            True if panic mode is active, False otherwise
        """
        return self._panic_triggered
    
    def __del__(self):
        """Ensure cleanup on object deletion."""
        try:
            self._cleanup_sensitive_data()
            if hasattr(self, '_secure_file_ops'):
                self._secure_file_ops.cleanup()
        except Exception:
            pass  # Ignore errors during cleanup
