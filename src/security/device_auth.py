import os
import json
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from .secure_memory import SecureString, secure_compare
from .hardware_id import HardwareIdentifier
from .secure_delete import SecureDelete
from src.crypto.encryption import EncryptionManager


class SecurityLevel:
    """Security level configurations for authentication protection."""
    
    STANDARD = "standard"
    HIGH = "high"
    MAXIMUM = "maximum"
    
    @classmethod
    def get_all_levels(cls):
        return [cls.STANDARD, cls.HIGH, cls.MAXIMUM]
    
    @classmethod
    def get_description(cls, level: str) -> str:
        descriptions = {
            cls.STANDARD: "Standard security with temporary lockouts after 5 failed attempts",
            cls.HIGH: "High security with progressive lockouts and 24-hour maximum",
            cls.MAXIMUM: "Maximum security with data corruption after 3 failed attempts"
        }
        return descriptions.get(level, "Unknown security level")


class DeviceAuthManager:
    """Manages device-bound single-user authentication for BAR application.
    
    Enhanced with persistent attack protection and configurable security levels:
    - One user per device (no multi-user system)
    - Hardware-bound authentication (cannot be transferred)
    - No password recovery (forgot password = application reset required)
    - Persistent attack tracking across application restarts
    - User-configurable security levels with data protection options
    - Emergency data destruction capabilities
    """
    
    # Security constants
    MASTER_KEY_SIZE = 64  # 512 bits for master key
    VERIFICATION_ROUNDS = 5  # Multiple verification rounds
    HARDWARE_TAG_SIZE = 16  # Hardware verification tag size
    
    # Security level configurations
    SECURITY_CONFIGS = {
        SecurityLevel.STANDARD: {
            "max_attempts": 5,
            "lockout_duration_minutes": 60,
            "destroy_data_on_breach": False,
            "progressive_lockout": False
        },
        SecurityLevel.HIGH: {
            "max_attempts": 4,
            "lockout_duration_minutes": 60,
            "max_lockout_duration_minutes": 1440,  # 24 hours
            "destroy_data_on_breach": False,
            "progressive_lockout": True
        },
        SecurityLevel.MAXIMUM: {
            "max_attempts": 3,
            "lockout_duration_minutes": 0,  # No temporary lockout
            "destroy_data_on_breach": True,
            "progressive_lockout": False
        }
    }
    
    def __init__(self, base_directory: str):
        """Initialize the device authentication manager.
        
        Args:
            base_directory: Directory to store device authentication data
        """
        self.base_directory = Path(base_directory)
        self.device_config_path = self.base_directory / "device.json"
        self.master_key_path = self.base_directory / "master.key" 
        self.security_config_path = self.base_directory / "security.dat"  # Encrypted security settings
        
        # Ensure directory exists
        self.base_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.hardware_id = HardwareIdentifier()
        self.encryption_manager = EncryptionManager()
        self.secure_delete = SecureDelete()
        
        # Authentication state
        self._authenticated = False
        self._master_key = None
        self._security_level = SecurityLevel.STANDARD
        self._persistent_security_data = None
        
        # Load persistent security configuration
        try:
            self._load_persistent_security_data()
        except Exception:
            # Ignore errors during initialization - will be handled during authentication
            pass
        
    def is_device_initialized(self) -> bool:
        """Check if the device has been initialized with authentication.
        
        Returns:
            True if device is initialized, False if first-time setup needed
        """
        return self.device_config_path.exists() and self.master_key_path.exists()
    
    def initialize_device(self, master_password: str, device_name: str = None, security_level: str = SecurityLevel.STANDARD) -> Tuple[bool, str]:
        """Initialize the device for first-time use.
        
        Args:
            master_password: The master password for this device
            device_name: Optional human-readable device name
            security_level: Security level configuration (standard, high, maximum)
            
        Returns:
            Tuple of (success, message/error)
        """
        if self.is_device_initialized():
            return False, "Device is already initialized"
            
        # Validate security level
        if security_level not in SecurityLevel.get_all_levels():
            return False, f"Invalid security level. Must be one of: {SecurityLevel.get_all_levels()}"
            
        # Validate password strength
        if not self._validate_password_strength(master_password):
            return False, "Password does not meet security requirements"
        
        try:
            # Generate hardware-bound device ID
            hardware_id = self.hardware_id.get_hardware_id()
            
            # Generate master encryption key
            master_salt = secrets.token_bytes(32)
            master_key = self._derive_master_key(master_password, master_salt, hardware_id)
            
            # Generate verification data
            verification_salt = secrets.token_bytes(32) 
            verification_hash = self._create_verification_hash(
                master_password, verification_salt, hardware_id
            )
            
            # Create device configuration
            device_config = {
                "version": "2.0.0",
                "device_id": hashlib.sha256(hardware_id.encode()).hexdigest()[:16],
                "device_name": device_name or f"BAR-Device-{secrets.token_hex(4)}",
                "initialized_at": datetime.now().isoformat(),
                "hardware_fingerprint": hashlib.sha256(hardware_id.encode()).hexdigest(),
                "master_salt": master_salt.hex(),
                "verification_salt": verification_salt.hex(),
                "verification_hash": verification_hash.hex(),
                "failed_attempts": 0,
                "locked_until": None,
                "security_level": security_level,
                "features": {
                    "hardware_binding": True,
                    "secure_deletion": True,
                    "anti_forensics": True,
                    "emergency_wipe": True,
                    "persistent_attack_protection": True
                }
            }
            
            # Create persistent security configuration
            persistent_security = {
                "version": "2.0.0",
                "security_level": security_level,
                "total_failed_attempts": 0,
                "first_failed_attempt": None,
                "last_failed_attempt": None,
                "lockout_count": 0,
                "hardware_fingerprint": hashlib.sha256(hardware_id.encode()).hexdigest(),
                "created_at": datetime.now().isoformat()
            }
            
            # Save encrypted master key
            key_data = {
                "encrypted_key": self.encryption_manager.encrypt_file_content(
                    master_key, master_password + hardware_id
                ),
                "created_at": datetime.now().isoformat(),
                "key_version": "2.0.0"
            }
            
            # Write configuration and key files
            with open(self.device_config_path, 'w') as f:
                json.dump(device_config, f, indent=2)
                
            with open(self.master_key_path, 'w') as f:
                json.dump(key_data, f, indent=2)
            
            # Save persistent security configuration (encrypted)
            self._save_persistent_security_data(persistent_security, hardware_id)
            
            # Set security level
            self._security_level = security_level
            
            # Set secure file permissions (Windows)
            if os.name == 'nt':
                import stat
                os.chmod(self.device_config_path, stat.S_IREAD | stat.S_IWRITE)
                os.chmod(self.master_key_path, stat.S_IREAD | stat.S_IWRITE)
                os.chmod(self.security_config_path, stat.S_IREAD | stat.S_IWRITE)
            
            return True, f"Device '{device_config['device_name']}' initialized successfully"
            
        except Exception as e:
            return False, f"Device initialization failed: {str(e)}"
    
    def authenticate(self, password: str) -> Tuple[bool, str]:
        """Authenticate user with master password using enhanced persistent security.
        
        Args:
            password: Master password to authenticate
            
        Returns:
            Tuple of (success, message/error)
        """
        if not self.is_device_initialized():
            return False, "Device not initialized"
            
        if self._authenticated:
            return True, "Already authenticated"
        
        try:
            # Load device configuration and persistent security data
            with open(self.device_config_path, 'r') as f:
                device_config = json.load(f)
                
            current_hardware = self.hardware_id.get_hardware_id()
            
            # Verify hardware binding first
            expected_fingerprint = device_config["hardware_fingerprint"]
            current_fingerprint = hashlib.sha256(current_hardware.encode()).hexdigest()
            
            if not secure_compare(current_fingerprint.encode(), expected_fingerprint.encode()):
                return False, "Hardware verification failed. This device is not authorized."
            
            # Load persistent security data
            security_data = self._load_persistent_security_data()
            if not security_data:
                # Create default security data if not exists (first time or corrupted)
                security_data = self._create_default_security_data(device_config, current_hardware)
                if not security_data:
                    return False, "Security configuration corrupted. Device reset required."
                
            # Get security configuration
            security_level = device_config.get("security_level", SecurityLevel.STANDARD)
            security_config = self.SECURITY_CONFIGS.get(security_level, self.SECURITY_CONFIGS[SecurityLevel.STANDARD])
            
            # Check for lockout status
            lockout_result = self._check_lockout_status(device_config, security_data, security_config)
            if lockout_result[0] is False:
                return lockout_result
            
            # Verify master password
            verification_salt = bytes.fromhex(device_config["verification_salt"])
            stored_hash = bytes.fromhex(device_config["verification_hash"])
            
            computed_hash = self._create_verification_hash(
                password, verification_salt, current_hardware
            )
            
            if not secure_compare(computed_hash, stored_hash):
                # Handle failed authentication
                return self._handle_authentication_failure(device_config, security_data, security_config, current_hardware)
            
            # Load and decrypt master key
            with open(self.master_key_path, 'r') as f:
                key_data = json.load(f)
            
            try:
                master_key = self.encryption_manager.decrypt_file_content(
                    key_data["encrypted_key"], password + current_hardware
                )
            except Exception:
                # Handle failed authentication (wrong password or corrupted key)
                return self._handle_authentication_failure(device_config, security_data, security_config, current_hardware)
            
            # Authentication successful - reset security counters
            self._authenticated = True
            self._master_key = master_key
            self._security_level = security_level
            
            # Reset failed attempts
            device_config["failed_attempts"] = 0
            device_config["locked_until"] = None
            device_config["last_auth"] = datetime.now().isoformat()
            
            security_data["total_failed_attempts"] = 0
            security_data["first_failed_attempt"] = None
            security_data["last_failed_attempt"] = None
            security_data["lockout_count"] = 0
            
            # Save updated configurations
            with open(self.device_config_path, 'w') as f:
                json.dump(device_config, f, indent=2)
                
            self._save_persistent_security_data(security_data, current_hardware)
            
            return True, "Authentication successful"
            
        except Exception as e:
            return False, f"Authentication error: {str(e)}"
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        return self._authenticated
    
    def get_master_key(self) -> Optional[bytes]:
        """Get the master encryption key (only if authenticated).
        
        Returns:
            Master key bytes if authenticated, None otherwise
        """
        return self._master_key if self._authenticated else None
    
    def logout(self):
        """Log out and clear authentication state."""
        self._authenticated = False
        if self._master_key:
            # Securely clear master key from memory
            if isinstance(self._master_key, (bytes, bytearray)):
                # Multiple-pass secure overwrite
                key_len = len(self._master_key)
                # Create a mutable copy if it's bytes
                if isinstance(self._master_key, bytes):
                    temp_key = bytearray(self._master_key)
                    self._master_key = temp_key
                
                # Overwrite with zeros
                for i in range(key_len):
                    self._master_key[i] = 0
                # Overwrite with ones
                for i in range(key_len):
                    self._master_key[i] = 255
                # Overwrite with random data
                random_data = secrets.token_bytes(key_len)
                for i in range(key_len):
                    self._master_key[i] = random_data[i]
                # Final overwrite with zeros
                for i in range(key_len):
                    self._master_key[i] = 0
            self._master_key = None
    
    def change_master_password(self, current_password: str, new_password: str) -> Tuple[bool, str]:
        """Change the master password.
        
        Args:
            current_password: Current master password
            new_password: New master password
            
        Returns:
            Tuple of (success, message/error)
        """
        if not self._authenticated:
            return False, "Not authenticated"
            
        if not self._validate_password_strength(new_password):
            return False, "New password does not meet security requirements"
        
        try:
            # Load current config
            with open(self.device_config_path, 'r') as f:
                device_config = json.load(f)
            
            # Get hardware ID
            hardware_id = self.hardware_id.get_hardware_id()
            
            # Create new verification data
            new_verification_salt = secrets.token_bytes(32)
            new_verification_hash = self._create_verification_hash(
                new_password, new_verification_salt, hardware_id
            )
            
            # Re-encrypt master key with new password
            new_key_data = {
                "encrypted_key": self.encryption_manager.encrypt_file_content(
                    self._master_key, new_password + hardware_id
                ),
                "created_at": datetime.now().isoformat(),
                "key_version": "2.0.0"
            }
            
            # Update configuration
            device_config["verification_salt"] = new_verification_salt.hex()
            device_config["verification_hash"] = new_verification_hash.hex()
            device_config["password_changed"] = datetime.now().isoformat()
            
            # Save updated files
            with open(self.device_config_path, 'w') as f:
                json.dump(device_config, f, indent=2)
                
            with open(self.master_key_path, 'w') as f:
                json.dump(new_key_data, f, indent=2)
            
            return True, "Master password changed successfully"
            
        except Exception as e:
            return False, f"Failed to change password: {str(e)}"
    
    def reset_device(self, confirm_phrase: str) -> Tuple[bool, str]:
        """Reset device and destroy all data (use when password is forgotten).
        
        Args:
            confirm_phrase: Must be "DESTROY ALL DATA" to confirm
            
        Returns:
            Tuple of (success, message/error)
        """
        if confirm_phrase != "DESTROY ALL DATA":
            return False, "Incorrect confirmation phrase"
        
        try:
            # Securely delete all authentication files
            files_to_delete = [
                self.device_config_path,
                self.master_key_path
            ]
            
            for file_path in files_to_delete:
                if file_path.exists():
                    self.secure_delete.secure_delete_file(str(file_path))
            
            # Securely delete entire data directory
            data_dir = self.base_directory / "data"
            if data_dir.exists():
                self.secure_delete.secure_delete_directory(str(data_dir))
            
            # Clear authentication state
            self.logout()
            
            return True, "Device reset complete. All data has been securely destroyed."
            
        except Exception as e:
            return False, f"Device reset failed: {str(e)}"
    
    def emergency_wipe(self) -> bool:
        """Emergency wipe of all sensitive data.
        
        Returns:
            True if wipe successful, False otherwise
        """
        try:
            # Immediate logout
            self.logout()
            
            # Wipe all application data
            app_dirs = [
                self.base_directory / "data",
                self.base_directory / "logs",
                self.base_directory / "temp"
            ]
            
            for dir_path in app_dirs:
                if dir_path.exists():
                    self.secure_delete.secure_delete_directory(str(dir_path))
            
            # Wipe authentication files
            auth_files = [self.device_config_path, self.master_key_path, self.security_config_path]
            for file_path in auth_files:
                if file_path.exists():
                    self.secure_delete.secure_delete_file(str(file_path))
            
            return True
            
        except Exception:
            return False
    
    def get_device_info(self) -> Optional[Dict[str, Any]]:
        """Get device information (only if authenticated).
        
        Returns:
            Device info dict if authenticated, None otherwise
        """
        if not self._authenticated or not self.is_device_initialized():
            return None
            
        try:
            with open(self.device_config_path, 'r') as f:
                device_config = json.load(f)
            
            # Return safe device info (remove sensitive data)
            return {
                "device_id": device_config["device_id"],
                "device_name": device_config["device_name"],
                "initialized_at": device_config["initialized_at"],
                "last_auth": device_config.get("last_auth", "Never"),
                "security_level": device_config["security_level"],
                "features": device_config["features"]
            }
            
        except Exception:
            return None
    
    def _validate_password_strength(self, password: str) -> bool:
        """Validate password meets security requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            True if password is strong enough, False otherwise
        """
        if len(password) < 12:  # Minimum 12 characters
            return False
            
        # Check for character diversity
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_lower and has_upper and has_digit and has_special
    
    def _derive_master_key(self, password: str, salt: bytes, hardware_id: str) -> bytes:
        """Derive master encryption key from password and hardware ID.
        
        Args:
            password: Master password
            salt: Random salt
            hardware_id: Hardware identifier
            
        Returns:
            Derived master key
        """
        # Use secure memory for sensitive data
        from .secure_memory import SecureBytes
        
        with SecureBytes(f"{password}:{hardware_id}") as secure_input:
            combined_input = secure_input.get_bytes()
            
            # Use high-iteration PBKDF2 for key derivation
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.MASTER_KEY_SIZE,
                salt=salt,
                iterations=600000,  # Very high iteration count for security
            )
            
            return kdf.derive(combined_input)
    
    def _create_verification_hash(self, password: str, salt: bytes, hardware_id: str) -> bytes:
        """Create verification hash for password checking.
        
        Args:
            password: Password to hash
            salt: Random salt
            hardware_id: Hardware identifier
            
        Returns:
            Verification hash
        """
        # Use secure memory for sensitive data
        from .secure_memory import SecureBytes
        
        with SecureBytes(f"{password}:{hardware_id}") as secure_input:
            current_hash = secure_input.get_bytes()
            
            # Multiple rounds of hashing for security
            for _ in range(self.VERIFICATION_ROUNDS):
                current_hash = hashlib.pbkdf2_hmac(
                    'sha256', current_hash, salt, 300000  # 300k iterations per round
                )
        
        return current_hash
    
    def _load_persistent_security_data(self) -> Optional[Dict[str, Any]]:
        """Load persistent security data from encrypted file.
        
        Returns:
            Dictionary with persistent security data or None if failed/missing
        """
        try:
            # If security config file doesn't exist, that's okay - return None
            if not self.security_config_path.exists():
                return None
                
            # If file is empty, return None
            if self.security_config_path.stat().st_size == 0:
                return None
                
            current_hardware = self.hardware_id.get_hardware_id()
            
            # Read encrypted security data
            with open(self.security_config_path, 'r', encoding='utf-8') as f:
                encrypted_json = f.read()
            
            # Handle empty file
            if not encrypted_json.strip():
                return None
            
            # Parse the encrypted data structure
            try:
                encrypted_data_dict = json.loads(encrypted_json)
            except json.JSONDecodeError:
                return None
            
            # Decrypt using hardware-bound key
            try:
                decrypted_json_bytes = self.encryption_manager.decrypt_file_content(
                    encrypted_data_dict, current_hardware
                )
                
                if not decrypted_json_bytes:
                    return None
                    
                security_data = json.loads(decrypted_json_bytes.decode('utf-8'))
                
                # Verify hardware fingerprint if present
                stored_fingerprint = security_data.get("hardware_fingerprint", "")
                if stored_fingerprint:
                    current_fingerprint = hashlib.sha256(current_hardware.encode()).hexdigest()
                    
                    if not secure_compare(stored_fingerprint.encode(), current_fingerprint.encode()):
                        return None
                    
                self._persistent_security_data = security_data
                return security_data
                
            except Exception:
                # Decryption or JSON parsing failed - probably corrupted or wrong key
                return None
                
        except Exception:
            # File system or other error
            return None
    
    def _save_persistent_security_data(self, security_data: Dict[str, Any], hardware_id: str) -> bool:
        """Save persistent security data to encrypted file.
        
        Args:
            security_data: Security data to save
            hardware_id: Hardware identifier for encryption
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Update hardware fingerprint
            security_data["hardware_fingerprint"] = hashlib.sha256(hardware_id.encode()).hexdigest()
            
            # Encrypt security data with hardware-bound key
            json_data = json.dumps(security_data, indent=2).encode('utf-8')
            encrypted_result = self.encryption_manager.encrypt_file_content(json_data, hardware_id)
            
            # Convert the dictionary result to JSON for storage
            encrypted_json = json.dumps(encrypted_result, indent=2)
            
            # Save to file
            with open(self.security_config_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_json)
                
            self._persistent_security_data = security_data
            return True
            
        except Exception as e:
            return False
    
    def _check_lockout_status(self, device_config: Dict[str, Any], security_data: Dict[str, Any], security_config: Dict[str, Any]) -> Tuple[bool, str]:
        """Check if device is currently locked out.
        
        Args:
            device_config: Device configuration
            security_data: Persistent security data
            security_config: Security level configuration
            
        Returns:
            Tuple of (allowed, message)
        """
        try:
            # Check temporary lockout from device config
            if device_config.get("locked_until"):
                locked_until = datetime.fromisoformat(device_config["locked_until"])
                if datetime.now() < locked_until:
                    remaining_minutes = int((locked_until - datetime.now()).total_seconds() / 60)
                    return False, f"Device temporarily locked. Try again in {remaining_minutes} minutes."
                    
            # Check if data has been corrupted due to security breach
            if security_data.get("data_corrupted", False):
                return False, "Security breach detected. All data has been destroyed for protection."
                
            return True, "Access allowed"
            
        except Exception:
            return False, "Lockout status check failed"
    
    def _handle_authentication_failure(self, device_config: Dict[str, Any], security_data: Dict[str, Any], security_config: Dict[str, Any], hardware_id: str) -> Tuple[bool, str]:
        """Handle failed authentication attempt with enhanced security.
        
        Args:
            device_config: Device configuration
            security_data: Persistent security data
            security_config: Security level configuration
            hardware_id: Hardware identifier
            
        Returns:
            Tuple of (success, message)
        """
        try:
            now = datetime.now()
            
            # Update attempt counters
            device_config["failed_attempts"] = device_config.get("failed_attempts", 0) + 1
            security_data["total_failed_attempts"] = security_data.get("total_failed_attempts", 0) + 1
            
            # Record timing
            if not security_data.get("first_failed_attempt"):
                security_data["first_failed_attempt"] = now.isoformat()
            security_data["last_failed_attempt"] = now.isoformat()
            
            max_attempts = security_config["max_attempts"]
            
            # Check if maximum attempts exceeded
            if security_data["total_failed_attempts"] >= max_attempts:
                if security_config["destroy_data_on_breach"]:
                    # MAXIMUM security level - destroy all data
                    return self._execute_security_breach_protocol(device_config, security_data, hardware_id)
                else:
                    # Apply lockout
                    return self._apply_security_lockout(device_config, security_data, security_config, hardware_id)
            
            # Save updated counters
            with open(self.device_config_path, 'w') as f:
                json.dump(device_config, f, indent=2)
                
            self._save_persistent_security_data(security_data, hardware_id)
            
            attempts_left = max_attempts - security_data["total_failed_attempts"]
            
            if security_config["destroy_data_on_breach"]:
                return False, f"⚠️ CRITICAL: Incorrect password. {attempts_left} attempts remaining before DATA DESTRUCTION."
            else:
                return False, f"Incorrect password. {attempts_left} attempts remaining before device lockout."
                
        except Exception as e:
            return False, f"Authentication failure handling error: {str(e)}"
    
    def _apply_security_lockout(self, device_config: Dict[str, Any], security_data: Dict[str, Any], security_config: Dict[str, Any], hardware_id: str) -> Tuple[bool, str]:
        """Apply security lockout based on configuration.
        
        Args:
            device_config: Device configuration
            security_data: Persistent security data
            security_config: Security level configuration
            hardware_id: Hardware identifier
            
        Returns:
            Tuple of (success, message)
        """
        try:
            from datetime import timedelta
            
            lockout_count = security_data.get("lockout_count", 0)
            security_data["lockout_count"] = lockout_count + 1
            
            if security_config.get("progressive_lockout", False):
                # Progressive lockout - increase duration each time
                base_minutes = security_config["lockout_duration_minutes"]
                max_minutes = security_config.get("max_lockout_duration_minutes", base_minutes * 4)
                lockout_minutes = min(base_minutes * (2 ** lockout_count), max_minutes)
            else:
                lockout_minutes = security_config["lockout_duration_minutes"]
            
            # Set lockout time
            locked_until = datetime.now() + timedelta(minutes=lockout_minutes)
            device_config["locked_until"] = locked_until.isoformat()
            
            # Save configurations
            with open(self.device_config_path, 'w') as f:
                json.dump(device_config, f, indent=2)
                
            self._save_persistent_security_data(security_data, hardware_id)
            
            hours = lockout_minutes // 60
            minutes = lockout_minutes % 60
            
            if hours > 0:
                time_str = f"{hours} hours and {minutes} minutes" if minutes > 0 else f"{hours} hours"
            else:
                time_str = f"{minutes} minutes"
                
            return False, f"🔒 Device locked for {time_str} due to repeated failed attempts."
            
        except Exception as e:
            return False, f"Lockout application failed: {str(e)}"
    
    def _execute_security_breach_protocol(self, device_config: Dict[str, Any], security_data: Dict[str, Any], hardware_id: str) -> Tuple[bool, str]:
        """Execute security breach protocol - destroy all sensitive data.
        
        Args:
            device_config: Device configuration
            security_data: Persistent security data
            hardware_id: Hardware identifier
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Mark data as corrupted in security data
            security_data["data_corrupted"] = True
            security_data["breach_detected_at"] = datetime.now().isoformat()
            
            # Save the breach record
            self._save_persistent_security_data(security_data, hardware_id)
            
            # Execute emergency wipe protocol
            wipe_success = self.emergency_wipe()
            
            if wipe_success:
                return False, "🚨 SECURITY BREACH: Maximum authentication attempts exceeded. All data has been securely destroyed."
            else:
                return False, "🚨 SECURITY BREACH: Authentication failed. Data destruction attempted but may be incomplete."
                
        except Exception as e:
            return False, f"Security breach protocol failed: {str(e)}"
    
    def get_security_status(self) -> Optional[Dict[str, Any]]:
        """Get current security status information.
        
        Returns:
            Dictionary with security status or None if not authenticated
        """
        if not self._authenticated:
            return None
            
        try:
            # Load current security data
            security_data = self._load_persistent_security_data()
            if not security_data:
                return None
                
            with open(self.device_config_path, 'r') as f:
                device_config = json.load(f)
                
            security_level = device_config.get("security_level", SecurityLevel.STANDARD)
            security_config = self.SECURITY_CONFIGS.get(security_level, self.SECURITY_CONFIGS[SecurityLevel.STANDARD])
            
            return {
                "security_level": security_level,
                "security_description": SecurityLevel.get_description(security_level),
                "max_attempts": security_config["max_attempts"],
                "current_failed_attempts": security_data.get("total_failed_attempts", 0),
                "destroy_data_on_breach": security_config["destroy_data_on_breach"],
                "progressive_lockout": security_config.get("progressive_lockout", False),
                "lockout_count": security_data.get("lockout_count", 0),
                "data_corrupted": security_data.get("data_corrupted", False)
            }
            
        except Exception:
            return None
    
    def _compute_hardware_tag(self, salt: bytes, hardware_id: str) -> bytes:
        """Compute hardware verification tag.
        
        Args:
            salt: Random salt used for key derivation
            hardware_id: Hardware identifier
            
        Returns:
            Hardware verification tag
        """
        import hmac
        
        # Create HMAC tag using salt and hardware ID
        tag = hmac.new(
            key=salt,
            msg=hardware_id.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()[:self.HARDWARE_TAG_SIZE]
        
        return tag
    
    def _load_config_header(self) -> Optional[Dict[str, Any]]:
        """Load configuration file header to determine format and extract metadata.
        
        Returns:
            Dictionary with config header info or None if failed
        """
        try:
            if not self.device_config_path.exists():
                return None
            
            # For this simple implementation, device_auth.py uses JSON format
            # So we just need to check if it exists and return basic info
            with open(self.device_config_path, 'r') as f:
                device_config = json.load(f)
            
            # Extract salt if available
            salt_hex = device_config.get("master_salt", "")
            
            return {
                "has_hardware_tag": False,  # This implementation uses JSON format
                "salt": salt_hex,
                "config_exists": True,
                "format": "json_legacy"
            }
            
        except Exception as e:
            return None
    
    def _create_default_security_data(self, device_config: Dict[str, Any], hardware_id: str) -> Optional[Dict[str, Any]]:
        """Create default security data when none exists.
        
        Args:
            device_config: Device configuration
            hardware_id: Hardware identifier
            
        Returns:
            Default security data dictionary or None if failed
        """
        try:
            security_level = device_config.get("security_level", SecurityLevel.STANDARD)
            
            security_data = {
                "version": "2.0.0",
                "security_level": security_level,
                "total_failed_attempts": 0,
                "first_failed_attempt": None,
                "last_failed_attempt": None,
                "lockout_count": 0,
                "hardware_fingerprint": hashlib.sha256(hardware_id.encode()).hexdigest(),
                "created_at": datetime.now().isoformat()
            }
            
            # Try to save the new security data
            if self._save_persistent_security_data(security_data, hardware_id):
                return security_data
            else:
                return None
                
        except Exception as e:
            return None
    
    def __del__(self):
        """Ensure cleanup on object destruction."""
        self.logout()
