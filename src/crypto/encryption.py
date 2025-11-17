import os
import base64
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.fernet import Fernet
import secrets

from src.security.hardware_id import HardwareIdentifier
from src.security.secure_memory import SecureBytes, secure_compare, secure_zero_memory
from src.security.input_validator import (
    get_crypto_validator, get_global_validator, 
    CryptographicValidationError, validate_bytes, validate_string
)


class EncryptionManager:
    """Handles all encryption/decryption operations for the BAR application."""
    
    # Constants for encryption
    SALT_SIZE = 32  # 256 bits
    KEY_SIZE = 32   # 256 bits for AES-256
    NONCE_SIZE = 12  # 96 bits for AES-GCM
    PBKDF2_ITERATIONS = 300000  # Increased iteration count for stronger security
    
    def __init__(self):
        """Initialize the encryption manager."""
        pass
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt for key derivation."""
        return os.urandom(EncryptionManager.SALT_SIZE)
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a random nonce for AES-GCM."""
        return os.urandom(EncryptionManager.NONCE_SIZE)
    
    @staticmethod
    def derive_key(password: str, salt: bytes, skip_validation: bool = False) -> bytes:
        """Derive an encryption key from a password and salt using PBKDF2.
        
        Args:
            password: Password string to derive key from
            salt: Random salt bytes for key derivation
            skip_validation: If True, skip password validation (for already-authenticated passwords)
            
        Returns:
            Derived key bytes
            
        Raises:
            CryptographicValidationError: If input validation fails
        
        Note:
            This method uses secure memory handling to prevent password exposure.
            skip_validation should ONLY be True for passwords that have already been 
            authenticated (e.g., for deriving metadata keys from master password).
        """
        # Comprehensive input validation per BAR Rules R030
        crypto_validator = get_crypto_validator()
        
        # Validate password (unless skipped for already-authenticated passwords)
        if not skip_validation:
            # SECURITY: Enforcing minimum 12 characters and complexity to prevent brute force
            password_result = crypto_validator.validate_password(
                password,
                field_name="password",
                min_length=12,  # Minimum 12 characters for security
                max_length=1024,
                require_complexity=True  # Enforce complexity and entropy requirements
            )
            if not password_result.is_valid:
                raise CryptographicValidationError(
                    password_result.error_message,
                    field_name="password",
                    violation_type=password_result.violation_type
                )
            password_str = password_result.sanitized_value
        else:
            # Trusted password - basic validation only
            if not isinstance(password, str) or len(password) == 0:
                raise CryptographicValidationError(
                    "Password must be a non-empty string",
                    field_name="password",
                    violation_type="invalid_type"
                )
            password_str = password
        
        # Validate salt
        salt_result = crypto_validator.validate_salt(
            salt,
            min_size=16,  # Minimum 16 bytes for security
            field_name="salt"
        )
        if not salt_result.is_valid:
            raise CryptographicValidationError(
                salt_result.error_message,
                field_name="salt",
                violation_type=salt_result.violation_type
            )
        # Use secure memory for validated password handling
        with SecureBytes(password_str) as secure_password:
            password_bytes = secure_password.get_bytes()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=EncryptionManager.KEY_SIZE,
                salt=salt_result.sanitized_value,
                iterations=EncryptionManager.PBKDF2_ITERATIONS,
            )
            
            derived_key = kdf.derive(password_bytes)
            
            # Securely clear the password bytes
            if isinstance(password_bytes, bytearray):
                secure_zero_memory(password_bytes)
            
            return derived_key
    
    @staticmethod
    def encrypt_data(data: bytes, key: bytes, aad: Optional[bytes] = None) -> Dict[str, bytes]:
        """Encrypt data using AES-256-GCM with optional associated data (AAD).
        
        Args:
            data: The data to encrypt
            key: The encryption key
            aad: Optional associated data to bind to the ciphertext (not stored)
            
        Returns:
            A dictionary containing the encrypted data and nonce
            
        Raises:
            CryptographicValidationError: If input validation fails
        """
        # Comprehensive input validation per BAR Rules R030
        crypto_validator = get_crypto_validator()
        
        # Validate data
        data_result = validate_bytes(
            data,
            field_name="data",
            min_length=0,  # Allow empty data
            max_length=1024 * 1024 * 1024  # 1GB max
        )
        if not data_result.is_valid:
            raise CryptographicValidationError(
                data_result.error_message,
                field_name="data",
                violation_type=data_result.violation_type
            )
        
        # Validate encryption key
        key_result = crypto_validator.validate_encryption_key(
            key,
            algorithm="AES",
            field_name="key"
        )
        if not key_result.is_valid:
            raise CryptographicValidationError(
                key_result.error_message,
                field_name="key",
                violation_type=key_result.violation_type
            )
        
        # Validate AAD if provided
        if aad is not None:
            aad_result = validate_bytes(
                aad,
                field_name="aad",
                max_length=1024 * 1024  # 1MB max for AAD
            )
            if not aad_result.is_valid:
                raise CryptographicValidationError(
                    aad_result.error_message,
                    field_name="aad",
                    violation_type=aad_result.violation_type
                )
            aad = aad_result.sanitized_value
        nonce = EncryptionManager.generate_nonce()
        aesgcm = AESGCM(key_result.sanitized_value)
        ciphertext = aesgcm.encrypt(nonce, data_result.sanitized_value, aad)
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce
        }
    
    @staticmethod
    def decrypt_data(encrypted_data: Dict[str, bytes], key: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary containing ciphertext and nonce
            key: The decryption key
            aad: Optional associated data; must match that used during encryption
            
        Returns:
            The decrypted data
            
        Raises:
            CryptographicValidationError: If input validation fails
            ValueError: If decryption fails (authentication failure)
        """
        # Comprehensive input validation per BAR Rules R030
        crypto_validator = get_crypto_validator()
        
        # Validate encrypted_data structure
        if not isinstance(encrypted_data, dict):
            raise CryptographicValidationError(
                "Encrypted data must be a dictionary",
                field_name="encrypted_data",
                violation_type="invalid_type"
            )
        
        # Validate required fields
        required_fields = ['ciphertext', 'nonce']
        for field in required_fields:
            if field not in encrypted_data:
                raise CryptographicValidationError(
                    f"Missing required field: {field}",
                    field_name="encrypted_data",
                    violation_type="missing_field"
                )
        
        # Validate ciphertext
        ciphertext_result = validate_bytes(
            encrypted_data['ciphertext'],
            field_name="ciphertext",
            min_length=1,  # Must have some data
            max_length=1024 * 1024 * 1024  # 1GB max
        )
        if not ciphertext_result.is_valid:
            raise CryptographicValidationError(
                ciphertext_result.error_message,
                field_name="ciphertext",
                violation_type=ciphertext_result.violation_type
            )
        
        # Validate nonce
        nonce_result = crypto_validator.validate_nonce(
            encrypted_data['nonce'],
            algorithm="GCM",
            field_name="nonce"
        )
        if not nonce_result.is_valid:
            raise CryptographicValidationError(
                nonce_result.error_message,
                field_name="nonce",
                violation_type=nonce_result.violation_type
            )
        
        # Validate decryption key
        key_result = crypto_validator.validate_encryption_key(
            key,
            algorithm="AES",
            field_name="key"
        )
        if not key_result.is_valid:
            raise CryptographicValidationError(
                key_result.error_message,
                field_name="key",
                violation_type=key_result.violation_type
            )
        
        # Validate AAD if provided
        if aad is not None:
            aad_result = validate_bytes(
                aad,
                field_name="aad",
                max_length=1024 * 1024  # 1MB max for AAD
            )
            if not aad_result.is_valid:
                raise CryptographicValidationError(
                    aad_result.error_message,
                    field_name="aad",
                    violation_type=aad_result.violation_type
                )
            aad = aad_result.sanitized_value
        ciphertext = ciphertext_result.sanitized_value
        nonce = nonce_result.sanitized_value
        
        aesgcm = AESGCM(key_result.sanitized_value)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception:
            # Do not leak specific errors from crypto operations
            raise ValueError("Decryption failed")
    
    @staticmethod
    def encrypt_file_content(content: bytes, password: str) -> Dict[str, Any]:
        """Encrypt file content with a password.
        
        Args:
            content: The file content to encrypt
            password: The password to derive the encryption key from
            
        Returns:
            A dictionary containing all necessary data for decryption
            
        Raises:
            ValueError: If input parameters are invalid
            TypeError: If input types are incorrect
        """
        # Comprehensive input validation per BAR Rules R030
        crypto_validator = get_crypto_validator()
        
        # Validate content
        content_result = validate_bytes(
            content,
            field_name="content",
            min_length=1,  # Content cannot be empty
            max_length=1024 * 1024 * 1024  # 1GB limit
        )
        if not content_result.is_valid:
            raise CryptographicValidationError(
                content_result.error_message,
                field_name="content",
                violation_type=content_result.violation_type
            )
        
        # Validate password with strong security requirements
        # SECURITY: Enforcing minimum 12 characters and complexity to prevent brute force
        password_result = crypto_validator.validate_password(
            password,
            field_name="password",
            min_length=12,  # Minimum 12 characters for security
            max_length=1024,
            require_complexity=True  # Enforce complexity and entropy requirements
        )
        if not password_result.is_valid:
            raise CryptographicValidationError(
                password_result.error_message,
                field_name="password",
                violation_type=password_result.violation_type
            )
        salt = EncryptionManager.generate_salt()
        key = EncryptionManager.derive_key(password_result.sanitized_value, salt)
        # Bind ciphertext to context using AAD derived from salt and app/version marker
        aad = b"BAR|v2|" + salt
        encrypted_data = EncryptionManager.encrypt_data(content_result.sanitized_value, key, aad)
        
        # Convert binary data to base64 for storage
        result = {
            'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('utf-8'),
            'nonce': base64.b64encode(encrypted_data['nonce']).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'encryption_time': datetime.now().isoformat(),
            'encryption_method': 'AES-256-GCM',
            'kdf_method': 'PBKDF2-HMAC-SHA256',
            'kdf_iterations': EncryptionManager.PBKDF2_ITERATIONS
        }
        
        return result
    
    @staticmethod
    def decrypt_file_content(encrypted_content: Dict[str, Any], password: str) -> bytes:
        """Decrypt file content with a password.
        
        Args:
            encrypted_content: Dictionary containing encrypted data and metadata
            password: The password to derive the decryption key from
            
        Returns:
            The decrypted file content
            
        Raises:
            ValueError: If decryption fails or input is invalid
            TypeError: If input types are incorrect
        """
        # Comprehensive input validation per BAR Rules R030
        crypto_validator = get_crypto_validator()
        
        # Validate encrypted_content structure
        if not isinstance(encrypted_content, dict):
            raise CryptographicValidationError(
                "Encrypted content must be a dictionary",
                field_name="encrypted_content",
                violation_type="invalid_type"
            )
        
        # Validate password with strong security requirements
        # SECURITY: During decryption, we still validate the password meets minimum standards
        # This helps detect if stored passwords were created with weak validation
        password_result = crypto_validator.validate_password(
            password,
            field_name="password",
            min_length=1,  # Allow any length for decryption (backward compatibility)
            max_length=1024,
            require_complexity=False  # Don't enforce complexity on decryption
        )
        if not password_result.is_valid:
            raise CryptographicValidationError(
                password_result.error_message,
                field_name="password",
                violation_type=password_result.violation_type
            )
        
        # Validate required fields
        required_fields = ['ciphertext', 'nonce', 'salt']
        for field in required_fields:
            if field not in encrypted_content:
                raise CryptographicValidationError(
                    f"Missing required field: {field}",
                    field_name="encrypted_content",
                    violation_type="missing_field"
                )
        
        # Validate field types and base64 encoding
        for field in required_fields:
            if not isinstance(encrypted_content[field], str):
                raise CryptographicValidationError(
                    f"Field {field} must be a base64 encoded string",
                    field_name=field,
                    violation_type="invalid_type"
                )
            
            # Validate base64 string format
            # Base64 encoding increases size by ~33%, so for 1GB files we need ~1.4GB limit
            # Using 2GB to be safe and support the full 1GB file limit
            field_result = validate_string(
                encrypted_content[field],
                field_name=field,
                max_length=2 * 1024 * 1024 * 1024,  # 2GB limit for base64 data (supports 1GB files)
                require_ascii=True
            )
            if not field_result.is_valid:
                raise CryptographicValidationError(
                    field_result.error_message,
                    field_name=field,
                    violation_type=field_result.violation_type
                )
        # Convert base64 data back to binary with comprehensive validation
        try:
            ciphertext = base64.b64decode(encrypted_content['ciphertext'])
            nonce = base64.b64decode(encrypted_content['nonce'])
            salt = base64.b64decode(encrypted_content['salt'])
        except Exception as e:
            raise CryptographicValidationError(
                f"Invalid base64 encoding in encrypted data: {str(e)}",
                field_name="encrypted_content",
                violation_type="base64_decode_error"
            )
        
        # Validate decoded data using basic checks only
        # SECURITY NOTE: During decryption, we use minimal validation because this data
        # comes from our own encrypted files. Overly strict validation (like "dangerous pattern"
        # detection) can reject legitimate random cryptographic data.
        # We only verify size/type, not "safety" - the encryption scheme itself provides safety.
        
        # Basic nonce validation - just check size
        if not isinstance(nonce, bytes) or len(nonce) not in [12, 16]:  # GCM standard sizes
            raise CryptographicValidationError(
                f"Invalid nonce size: {len(nonce)} bytes",
                field_name="nonce",
                violation_type="invalid_nonce_size"
            )
        
        # Basic salt validation - just check minimum size
        if not isinstance(salt, bytes) or len(salt) < 16:
            raise CryptographicValidationError(
                f"Invalid salt size: {len(salt)} bytes (minimum 16)",
                field_name="salt",
                violation_type="invalid_salt_size"
            )
        
        ciphertext_result = validate_bytes(
            ciphertext,
            field_name="ciphertext",
            min_length=1,
            max_length=1024 * 1024 * 1024  # 1GB max
        )
        if not ciphertext_result.is_valid:
            raise CryptographicValidationError(
                ciphertext_result.error_message,
                field_name="ciphertext",
                violation_type=ciphertext_result.violation_type
            )
        
        # Derive the key and decrypt using validated data
        # SECURITY: Skip password validation during decryption to allow any password
        # (even weak ones that wouldn't be accepted for new files) to decrypt existing files.
        # This is safe because we're just checking if the password decrypts the file.
        key = EncryptionManager.derive_key(
            password_result.sanitized_value, 
            salt,  # Use the salt directly (already validated above)
            skip_validation=True  # Already validated above with require_complexity=False
        )
        encrypted_data = {
            'ciphertext': ciphertext_result.sanitized_value,
            'nonce': nonce  # Use the nonce directly (already validated above)
        }
        # Reconstruct AAD exactly as used during encryption
        aad = b"BAR|v2|" + salt  # Use the salt directly
        
        return EncryptionManager.decrypt_data(encrypted_data, key, aad)
    
    @staticmethod
    def generate_secure_key() -> str:
        """Generate a secure random key for file encryption.
        
        Returns:
            A secure random key as a URL-safe base64 encoded string (32 bytes)
        """
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token.
        
        Args:
            length: Length of the token in bytes (default: 32)
            
        Returns:
            Hex-encoded secure random token
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_password(password: str, bind_to_hardware: bool = True) -> Dict[str, str]:
        """Create a secure hash of a password for storage.
        
        Args:
            password: The password to hash
            bind_to_hardware: Whether to bind the password hash to the current hardware
            
        Returns:
            A dictionary containing the password hash and salt
        """
        salt = EncryptionManager.generate_salt()
        
        # If hardware binding is enabled, incorporate hardware ID into the password
        if bind_to_hardware:
            hw_id = HardwareIdentifier().get_hardware_id()
            # Combine password with hardware ID
            combined_password = f"{password}:{hw_id}"
        else:
            combined_password = password
        
        # Skip validation - password has already been validated during setup/authentication
        key = EncryptionManager.derive_key(combined_password, salt, skip_validation=True)
        
        result = {
            'hash': base64.b64encode(key).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'method': 'PBKDF2-HMAC-SHA256',
            'iterations': EncryptionManager.PBKDF2_ITERATIONS,
            'hardware_bound': bind_to_hardware
        }
        
        # If hardware binding is enabled, store the hardware ID hash
        if bind_to_hardware:
            result['hardware_id_hash'] = hashlib.sha256(hw_id.encode('utf-8')).hexdigest()
            
        return result
    
    @staticmethod
    def verify_password(password: str, password_hash: Dict[str, str]) -> bool:
        """Verify a password against a stored hash.
        
        Args:
            password: The password to verify
            password_hash: Dictionary containing the stored hash and metadata
            
        Returns:
            True if the password matches, False otherwise
        """
        salt = base64.b64decode(password_hash['salt'])
        stored_hash = base64.b64decode(password_hash['hash'])
        
        # Check if the password is hardware-bound
        is_hardware_bound = password_hash.get('hardware_bound', False)
        
        if is_hardware_bound:
            # Get current hardware ID
            hw_id = HardwareIdentifier().get_hardware_id()
            
            # Verify hardware ID if it's stored in the hash
            if 'hardware_id_hash' in password_hash:
                current_hw_hash = hashlib.sha256(hw_id.encode('utf-8')).hexdigest()
                if not secure_compare(current_hw_hash.encode(), password_hash['hardware_id_hash'].encode()):
                    # Hardware ID doesn't match, authentication fails
                    return False
            
            # Combine password with hardware ID as was done during hashing
            combined_password = f"{password}:{hw_id}"
        else:
            combined_password = password
        
        # Derive the key from the provided password
        # Skip validation - this is for verification, not creating new passwords
        derived_key = EncryptionManager.derive_key(combined_password, salt, skip_validation=True)
        
        # Compare in constant time to prevent timing attacks
        result = secure_compare(derived_key, stored_hash)
        
        # Securely clear derived key from memory
        if isinstance(derived_key, bytearray):
            secure_zero_memory(derived_key)
        
        return result
