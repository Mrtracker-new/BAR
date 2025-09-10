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

from ..security.hardware_id_bridge import HardwareIdentifier
from ..security.secure_memory import SecureBytes, secure_compare, secure_zero_memory


class EncryptionManager:
    """Handles all encryption/decryption operations for the BAR application."""
    
    # Constants for encryption
    SALT_SIZE = 32  # 256 bits
    KEY_SIZE = 32   # 256 bits for AES-256
    NONCE_SIZE = 12  # 96 bits for AES-GCM
    PBKDF2_ITERATIONS = 100000  # High iteration count for security
    
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
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive an encryption key from a password and salt using PBKDF2.
        
        Args:
            password: Password string to derive key from
            salt: Random salt bytes for key derivation
            
        Returns:
            Derived key bytes
        
        Note:
            This method uses secure memory handling to prevent password exposure
        """
        # Use secure memory for password handling
        with SecureBytes(password) as secure_password:
            password_bytes = secure_password.get_bytes()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=EncryptionManager.KEY_SIZE,
                salt=salt,
                iterations=EncryptionManager.PBKDF2_ITERATIONS,
            )
            
            derived_key = kdf.derive(password_bytes)
            
            # Securely clear the password bytes
            if isinstance(password_bytes, bytearray):
                secure_zero_memory(password_bytes)
            
            return derived_key
    
    @staticmethod
    def encrypt_data(data: bytes, key: bytes) -> Dict[str, bytes]:
        """Encrypt data using AES-256-GCM.
        
        Args:
            data: The data to encrypt
            key: The encryption key
            
        Returns:
            A dictionary containing the encrypted data, nonce, and tag
        """
        nonce = EncryptionManager.generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce
        }
    
    @staticmethod
    def decrypt_data(encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary containing ciphertext and nonce
            key: The decryption key
            
        Returns:
            The decrypted data
            
        Raises:
            ValueError: If decryption fails (authentication failure)
        """
        ciphertext = encrypted_data['ciphertext']
        nonce = encrypted_data['nonce']
        
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
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
        # Input validation
        if not isinstance(content, bytes):
            raise TypeError("Content must be bytes")
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        if len(content) == 0:
            raise ValueError("Content cannot be empty")
        if len(content) > 1024 * 1024 * 1024:  # 1GB limit
            raise ValueError("Content size exceeds maximum limit (1GB)")
        salt = EncryptionManager.generate_salt()
        key = EncryptionManager.derive_key(password, salt)
        encrypted_data = EncryptionManager.encrypt_data(content, key)
        
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
        # Input validation
        if not isinstance(encrypted_content, dict):
            raise TypeError("Encrypted content must be a dictionary")
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        
        # Validate required fields
        required_fields = ['ciphertext', 'nonce', 'salt']
        for field in required_fields:
            if field not in encrypted_content:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate field types
        for field in required_fields:
            if not isinstance(encrypted_content[field], str):
                raise ValueError(f"Field {field} must be a base64 encoded string")
        # Convert base64 data back to binary with validation
        try:
            ciphertext = base64.b64decode(encrypted_content['ciphertext'])
            nonce = base64.b64decode(encrypted_content['nonce'])
            salt = base64.b64decode(encrypted_content['salt'])
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding in encrypted data: {str(e)}")
        
        # Validate decoded sizes
        if len(nonce) != EncryptionManager.NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: expected {EncryptionManager.NONCE_SIZE}, got {len(nonce)}")
        if len(salt) != EncryptionManager.SALT_SIZE:
            raise ValueError(f"Invalid salt size: expected {EncryptionManager.SALT_SIZE}, got {len(salt)}")
        if len(ciphertext) == 0:
            raise ValueError("Ciphertext cannot be empty")
        
        # Derive the key and decrypt
        key = EncryptionManager.derive_key(password, salt)
        encrypted_data = {
            'ciphertext': ciphertext,
            'nonce': nonce
        }
        
        return EncryptionManager.decrypt_data(encrypted_data, key)
    
    @staticmethod
    def generate_secure_key() -> str:
        """Generate a secure random key for file encryption.
        
        Returns:
            A secure random key as a URL-safe base64 encoded string
        """
        return Fernet.generate_key().decode('utf-8')
    
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
        
        key = EncryptionManager.derive_key(combined_password, salt)
        
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
                if current_hw_hash != password_hash['hardware_id_hash']:
                    # Hardware ID doesn't match, authentication fails
                    return False
            
            # Combine password with hardware ID as was done during hashing
            combined_password = f"{password}:{hw_id}"
        else:
            combined_password = password
        
        # Derive the key from the provided password
        derived_key = EncryptionManager.derive_key(combined_password, salt)
        
        # Compare in constant time to prevent timing attacks
        result = secure_compare(derived_key, stored_hash)
        
        # Securely clear derived key from memory
        if isinstance(derived_key, bytearray):
            secure_zero_memory(derived_key)
        
        return result
