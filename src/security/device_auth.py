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
from ..crypto.encryption import EncryptionManager


class DeviceAuthManager:
    """Manages device-bound single-user authentication for BAR application.
    
    This system provides:
    - One user per device (no multi-user system)
    - Hardware-bound authentication (cannot be transferred)
    - No password recovery (forgot password = application reset required)
    - Secure initialization on first run
    - Emergency data destruction capabilities
    """
    
    # Security constants
    MASTER_KEY_SIZE = 64  # 512 bits for master key
    VERIFICATION_ROUNDS = 5  # Multiple verification rounds
    MAX_AUTH_ATTEMPTS = 5  # Maximum authentication attempts before device lock
    
    def __init__(self, base_directory: str):
        """Initialize the device authentication manager.
        
        Args:
            base_directory: Directory to store device authentication data
        """
        self.base_directory = Path(base_directory)
        self.device_config_path = self.base_directory / "device.json"
        self.master_key_path = self.base_directory / "master.key" 
        
        # Ensure directory exists
        self.base_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.hardware_id = HardwareIdentifier()
        self.encryption_manager = EncryptionManager()
        self.secure_delete = SecureDelete()
        
        # Authentication state
        self._authenticated = False
        self._master_key = None
        self._failed_attempts = 0
        
    def is_device_initialized(self) -> bool:
        """Check if the device has been initialized with authentication.
        
        Returns:
            True if device is initialized, False if first-time setup needed
        """
        return self.device_config_path.exists() and self.master_key_path.exists()
    
    def initialize_device(self, master_password: str, device_name: str = None) -> Tuple[bool, str]:
        """Initialize the device for first-time use.
        
        Args:
            master_password: The master password for this device
            device_name: Optional human-readable device name
            
        Returns:
            Tuple of (success, message/error)
        """
        if self.is_device_initialized():
            return False, "Device is already initialized"
            
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
                "security_level": "maximum",
                "features": {
                    "hardware_binding": True,
                    "secure_deletion": True,
                    "anti_forensics": True,
                    "emergency_wipe": True
                }
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
            
            # Set secure file permissions (Windows)
            if os.name == 'nt':
                import stat
                os.chmod(self.device_config_path, stat.S_IREAD | stat.S_IWRITE)
                os.chmod(self.master_key_path, stat.S_IREAD | stat.S_IWRITE)
            
            return True, f"Device '{device_config['device_name']}' initialized successfully"
            
        except Exception as e:
            return False, f"Device initialization failed: {str(e)}"
    
    def authenticate(self, password: str) -> Tuple[bool, str]:
        """Authenticate user with master password.
        
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
            # Load device configuration
            with open(self.device_config_path, 'r') as f:
                device_config = json.load(f)
            
            # Check if device is locked
            if device_config.get("locked_until"):
                locked_until = datetime.fromisoformat(device_config["locked_until"])
                if datetime.now() < locked_until:
                    remaining_minutes = int((locked_until - datetime.now()).total_seconds() / 60)
                    return False, f"Device locked. Try again in {remaining_minutes} minutes."
            
            # Verify hardware binding
            current_hardware = self.hardware_id.get_hardware_id()
            expected_fingerprint = device_config["hardware_fingerprint"]
            current_fingerprint = hashlib.sha256(current_hardware.encode()).hexdigest()
            
            if not secure_compare(current_fingerprint.encode(), expected_fingerprint.encode()):
                return False, "Hardware binding verification failed. This device is not authorized."
            
            # Verify master password
            verification_salt = bytes.fromhex(device_config["verification_salt"])
            stored_hash = bytes.fromhex(device_config["verification_hash"])
            
            computed_hash = self._create_verification_hash(
                password, verification_salt, current_hardware
            )
            
            if not secure_compare(computed_hash, stored_hash):
                # Increment failed attempts
                device_config["failed_attempts"] = device_config.get("failed_attempts", 0) + 1
                
                if device_config["failed_attempts"] >= self.MAX_AUTH_ATTEMPTS:
                    # Lock device for 1 hour
                    from datetime import timedelta
                    locked_until = datetime.now() + timedelta(hours=1)
                    device_config["locked_until"] = locked_until.isoformat()
                    
                    # Save updated config
                    with open(self.device_config_path, 'w') as f:
                        json.dump(device_config, f, indent=2)
                    
                    return False, f"Device locked due to {self.MAX_AUTH_ATTEMPTS} failed attempts"
                
                # Save failed attempt count
                with open(self.device_config_path, 'w') as f:
                    json.dump(device_config, f, indent=2)
                
                attempts_left = self.MAX_AUTH_ATTEMPTS - device_config["failed_attempts"]
                return False, f"Incorrect password. {attempts_left} attempts remaining."
            
            # Load and decrypt master key
            with open(self.master_key_path, 'r') as f:
                key_data = json.load(f)
            
            try:
                master_key = self.encryption_manager.decrypt_file_content(
                    key_data["encrypted_key"], password + current_hardware
                )
            except Exception:
                return False, "Failed to decrypt master key"
            
            # Authentication successful
            self._authenticated = True
            self._master_key = master_key
            
            # Reset failed attempts and unlock status
            device_config["failed_attempts"] = 0
            device_config["locked_until"] = None
            device_config["last_auth"] = datetime.now().isoformat()
            
            with open(self.device_config_path, 'w') as f:
                json.dump(device_config, f, indent=2)
            
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
            auth_files = [self.device_config_path, self.master_key_path]
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
    
    def __del__(self):
        """Ensure cleanup on object destruction."""
        self.logout()
