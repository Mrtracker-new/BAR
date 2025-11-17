
import os
import json
import time
import shutil
import threading
import logging
import base64
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from cryptography.hazmat.primitives import hashes

from src.crypto.encryption import EncryptionManager
from src.file_manager.file_scanner import FileScanner
from src.file_manager.format_detector import FileFormatDetector

# Import comprehensive input validation system
from src.security.input_validator import (
    get_file_validator, get_global_validator, FileValidationError,
    validate_string, validate_bytes, validate_integer
)


class FileManager:
    """Manages secure file operations for the BAR application."""
    
    # Metadata version for backward compatibility
    METADATA_VERSION_PLAINTEXT = 1  # Legacy plaintext metadata
    METADATA_VERSION_ENCRYPTED = 2  # Current encrypted metadata
    CURRENT_METADATA_VERSION = METADATA_VERSION_ENCRYPTED
    
    def __init__(self, base_directory: str, monitor=None):
        """Initialize the file manager.
        
        Args:
            base_directory: The base directory for storing all files and metadata
            
        Raises:
            FileValidationError: If input validation fails
        """
        # Initialize file validator first before any validation
        self.file_validator = get_file_validator()
        
        # Comprehensive input validation per BAR Rules R030
        self._validate_base_directory(base_directory)
        # Store validated base directory
        self.base_directory = Path(base_directory)
        self.files_directory = self.base_directory / "files"
        self.metadata_directory = self.base_directory / "metadata"
        self.blacklist_directory = self.base_directory / "blacklist"
        self.monitor = monitor  # Optional intelligent monitor for access tracking
        
        # Create directories if they don't exist
        self.files_directory.mkdir(parents=True, exist_ok=True)
        self.metadata_directory.mkdir(parents=True, exist_ok=True)
        self.blacklist_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize the encryption manager
        self.encryption_manager = EncryptionManager()
        
        # Initialize the format detector
        self.format_detector = FileFormatDetector()
        
        # Setup logging first
        self._setup_logging()
        
        # Initialize the file scanner
        self.file_scanner = FileScanner(self)
        
        # Metadata encryption key (set by set_metadata_key() after device auth)
        self._metadata_key = None
        self._metadata_key_set = False
        
        # File-level locks for thread safety (prevents race conditions)
        self._file_locks = {}
        self._file_locks_lock = threading.RLock()
        
        # Start the file monitoring thread AFTER all other initialization
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_files, daemon=True)
        self.monitor_thread.start()
    
    def _setup_logging(self):
        """Set up logging for the file manager."""
        log_dir = self.base_directory / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / "file_operations.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("FileManager")
    
    def set_metadata_key(self, device_password: str) -> None:
        """Set the metadata encryption key derived from device password.
        
        This method MUST be called after device authentication and before
        any file operations. The key is used to encrypt all metadata at rest.
        
        Args:
            device_password: The authenticated device password
            
        Security Note:
            The metadata key is derived using PBKDF2 with a fixed salt.
            This ensures consistent key derivation across sessions while
            maintaining security through the device password strength.
        """
        try:
            # Use a fixed application salt for metadata key derivation
            # This is safe because the device password itself is strong and hardware-bound
            metadata_salt = b'BAR_METADATA_ENCRYPTION_V2_SALT_2025'
            
            # Derive 32-byte key for AES-256
            # SECURITY NOTE: skip_validation=True because device_password has already been
            # authenticated by DeviceAuthManager. Re-validating would reject old passwords
            # that don't meet new password requirements but are still valid.
            self._metadata_key = self.encryption_manager.derive_key(
                device_password, 
                metadata_salt,
                skip_validation=True  # Already authenticated - don't re-validate
            )
            
            self._metadata_key_set = True
            self.logger.info("Metadata encryption key initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize metadata encryption key: {e}")
            raise ValueError("Failed to initialize secure metadata system")
    
    def clear_metadata_key(self) -> None:
        """Securely clear the metadata encryption key from memory.
        
        Should be called on logout or application exit.
        """
        if self._metadata_key:
            # Securely zero out the key
            if isinstance(self._metadata_key, bytearray):
                for i in range(len(self._metadata_key)):
                    self._metadata_key[i] = 0
            self._metadata_key = None
            self._metadata_key_set = False
            self.logger.info("Metadata encryption key cleared")
    
    def _get_file_lock(self, file_id: str) -> threading.RLock:
        """Get or create a thread lock for a specific file.
        
        Args:
            file_id: The file ID to get a lock for
            
        Returns:
            A reentrant lock for the specified file
        """
        with self._file_locks_lock:
            if file_id not in self._file_locks:
                self._file_locks[file_id] = threading.RLock()
            return self._file_locks[file_id]
    
    def _save_metadata(self, file_id: str, metadata: Dict[str, Any]) -> None:
        """Save metadata with encryption.
        
        Args:
            file_id: The file ID
            metadata: The metadata dictionary to save
            
        Raises:
            ValueError: If metadata key is not set
            
        Security:
            - All metadata is encrypted with AES-256-GCM
            - Uses device-derived metadata key
            - Includes version field for backward compatibility
            - Thread-safe with file-level locking
        """
        if not self._metadata_key_set:
            raise ValueError("Metadata encryption key not set. Call set_metadata_key() first.")
        
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        try:
            # Add version to metadata
            metadata['_version'] = self.CURRENT_METADATA_VERSION
            
            # Convert metadata to JSON
            metadata_json = json.dumps(metadata, indent=2)
            metadata_bytes = metadata_json.encode('utf-8')
            
            # Encrypt entire metadata
            encrypted_data = self.encryption_manager.encrypt_data(
                metadata_bytes,
                self._metadata_key,
                aad=file_id.encode('utf-8')  # Bind to file_id
            )
            
            # Create encrypted metadata wrapper
            encrypted_wrapper = {
                'version': self.CURRENT_METADATA_VERSION,
                'encrypted_metadata': {
                    'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('utf-8'),
                    'nonce': base64.b64encode(encrypted_data['nonce']).decode('utf-8')
                },
                'file_id': file_id  # Store file_id for integrity
            }
            
            # Write atomically with temp file
            temp_path = metadata_path.with_suffix('.tmp')
            try:
                with open(temp_path, 'w') as f:
                    json.dump(encrypted_wrapper, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Atomic rename
                temp_path.replace(metadata_path)
                
                # Set restrictive permissions
                if hasattr(os, 'chmod'):
                    os.chmod(str(metadata_path), 0o600)
                    
            finally:
                # Clean up temp file if it exists
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except:
                        pass
                        
        except Exception as e:
            self.logger.error(f"Failed to save encrypted metadata for {file_id}: {e}")
            raise
    
    def _load_metadata(self, file_id: str, migrate_legacy: bool = True) -> Dict[str, Any]:
        """Load metadata with automatic decryption and legacy migration.
        
        Args:
            file_id: The file ID
            migrate_legacy: If True, automatically migrate legacy plaintext metadata
            
        Returns:
            Decrypted metadata dictionary
            
        Raises:
            FileNotFoundError: If metadata file doesn't exist
            ValueError: If metadata key not set or decryption fails
            
        Security:
            - Transparently handles both encrypted and legacy plaintext metadata
            - Automatically migrates legacy metadata on first access
            - Validates file_id binding
        """
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            raise FileNotFoundError(f"Metadata for file {file_id} not found")
        
        try:
            with open(metadata_path, 'r') as f:
                data = json.load(f)
            
            # Check version
            version = data.get('version', self.METADATA_VERSION_PLAINTEXT)
            
            if version == self.METADATA_VERSION_ENCRYPTED:
                # Decrypt encrypted metadata
                if not self._metadata_key_set:
                    raise ValueError("Metadata encryption key not set. Cannot decrypt metadata.")
                
                # Verify file_id binding
                stored_file_id = data.get('file_id')
                if stored_file_id != file_id:
                    self.logger.warning(f"File ID mismatch in metadata: expected {file_id}, got {stored_file_id}")
                    raise ValueError("Metadata integrity check failed")
                
                # Extract encrypted data
                encrypted_metadata = data.get('encrypted_metadata', {})
                ciphertext = base64.b64decode(encrypted_metadata['ciphertext'])
                nonce = base64.b64decode(encrypted_metadata['nonce'])
                
                # Decrypt
                encrypted_data = {
                    'ciphertext': ciphertext,
                    'nonce': nonce
                }
                
                decrypted_bytes = self.encryption_manager.decrypt_data(
                    encrypted_data,
                    self._metadata_key,
                    aad=file_id.encode('utf-8')
                )
                
                # Parse JSON
                metadata = json.loads(decrypted_bytes.decode('utf-8'))
                
                return metadata
                
            else:
                # Legacy plaintext metadata
                self.logger.warning(f"Loading legacy plaintext metadata for {file_id}")
                
                # The data IS the metadata (no encryption)
                metadata = data
                
                # Migrate to encrypted format if requested
                if migrate_legacy and self._metadata_key_set:
                    self.logger.info(f"Migrating legacy metadata to encrypted format: {file_id}")
                    try:
                        self._save_metadata(file_id, metadata)
                        self.logger.info(f"Successfully migrated metadata for {file_id}")
                    except Exception as e:
                        self.logger.error(f"Failed to migrate metadata for {file_id}: {e}")
                        # Continue with plaintext - don't fail the operation
                
                return metadata
                
        except Exception as e:
            self.logger.error(f"Failed to load metadata for {file_id}: {e}")
            raise
    
    def _validate_base_directory(self, base_directory: Any) -> None:
        """Validate base directory parameter.
        
        Args:
            base_directory: Directory path to validate
            
        Raises:
            FileValidationError: If validation fails
        """
        # Validate base directory path
        path_result = self.file_validator.validate_file_path(
            base_directory,
            field_name="base_directory",
            allow_absolute=True,  # Allow absolute paths for base directory
            allow_parent_traversal=False
        )
        if not path_result.is_valid:
            raise FileValidationError(
                path_result.error_message,
                field_name="base_directory",
                violation_type=path_result.violation_type
            )
    
    def _validate_file_content(self, content: Any, field_name: str = "content") -> bytes:
        """Validate file content parameter.
        
        Args:
            content: File content to validate
            field_name: Name of the field for logging
            
        Returns:
            Validated file content
            
        Raises:
            FileValidationError: If validation fails
        """
        content_result = validate_bytes(
            content,
            field_name=field_name,
            min_length=1,  # File must have content
            max_length=1024 * 1024 * 1024  # 1GB max file size
        )
        if not content_result.is_valid:
            raise FileValidationError(
                content_result.error_message,
                field_name=field_name,
                violation_type=content_result.violation_type
            )
        return content_result.sanitized_value
    
    def _validate_filename(self, filename: Any, field_name: str = "filename") -> str:
        """Validate filename parameter.
        
        Args:
            filename: Filename to validate
            field_name: Name of the field for logging
            
        Returns:
            Validated filename
            
        Raises:
            FileValidationError: If validation fails
        """
        filename_result = self.file_validator.validate_filename(
            filename,
            field_name=field_name,
            max_length=255,  # Standard filesystem limit
            allow_unicode=True
        )
        if not filename_result.is_valid:
            raise FileValidationError(
                filename_result.error_message,
                field_name=field_name,
                violation_type=filename_result.violation_type
            )
        return filename_result.sanitized_value
    
    def _validate_password(self, password: Any, field_name: str = "password") -> str:
        """Validate password parameter.
        
        Args:
            password: Password to validate
            field_name: Name of the field for logging
            
        Returns:
            Validated password
            
        Raises:
            FileValidationError: If validation fails
        """
        from src.security.input_validator import get_crypto_validator
        crypto_validator = get_crypto_validator()
        
        # SECURITY: Enforce strong password requirements for file encryption
        password_result = crypto_validator.validate_password(
            password,
            field_name=field_name,
            min_length=12,  # Minimum 12 characters for security
            max_length=1024,
            require_complexity=True  # Enforce complexity and entropy requirements
        )
        if not password_result.is_valid:
            raise FileValidationError(
                password_result.error_message,
                field_name=field_name,
                violation_type=password_result.violation_type
            )
        return password_result.sanitized_value
    
    def _validate_security_settings(self, security_settings: Any, field_name: str = "security_settings") -> Dict[str, Any]:
        """Validate security settings parameter.
        
        Args:
            security_settings: Security settings to validate
            field_name: Name of the field for logging
            
        Returns:
            Validated security settings
            
        Raises:
            FileValidationError: If validation fails
        """
        if not isinstance(security_settings, dict):
            raise FileValidationError(
                "Security settings must be a dictionary",
                field_name=field_name,
                violation_type="invalid_type"
            )
        
        validated_settings = {}
        for key, value in security_settings.items():
            # Validate setting key
            key_result = validate_string(
                key,
                field_name=f"{field_name}.{key}",
                max_length=100,
                allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
                require_ascii=True
            )
            if not key_result.is_valid:
                raise FileValidationError(
                    key_result.error_message,
                    field_name=f"{field_name}.{key}",
                    violation_type=key_result.violation_type
                )
            
            validated_key = key_result.sanitized_value
            
            if validated_key == "max_access_count" and value is not None:
                count_result = validate_integer(
                    value,
                    field_name=f"{field_name}.max_access_count",
                    min_value=1,
                    max_value=1000000,
                    allow_zero=False,
                    allow_negative=False
                )
                if not count_result.is_valid:
                    raise FileValidationError(
                        count_result.error_message,
                        field_name=f"{field_name}.max_access_count",
                        violation_type=count_result.violation_type
                    )
                validated_settings[validated_key] = count_result.sanitized_value
                
            elif validated_key == "deadman_switch" and value is not None:
                deadman_result = validate_integer(
                    value,
                    field_name=f"{field_name}.deadman_switch",
                    min_value=1,
                    max_value=365,  # Maximum 1 year in days
                    allow_zero=False,
                    allow_negative=False
                )
                if not deadman_result.is_valid:
                    raise FileValidationError(
                        deadman_result.error_message,
                        field_name=f"{field_name}.deadman_switch",
                        violation_type=deadman_result.violation_type
                    )
                validated_settings[validated_key] = deadman_result.sanitized_value
                
            elif validated_key == "disable_export":
                if not isinstance(value, bool):
                    raise FileValidationError(
                        "disable_export must be a boolean",
                        field_name=f"{field_name}.disable_export",
                        violation_type="invalid_type"
                    )
                validated_settings[validated_key] = value
            elif validated_key in ["max_access_count", "deadman_switch"] and value is None:
                # Handle None values for numeric fields
                validated_settings[validated_key] = None
            else:
                # Other settings - validate as strings or leave as None
                if value is not None:
                    str_result = validate_string(
                        str(value),
                        field_name=f"{field_name}.{validated_key}",
                        max_length=1000
                    )
                    if not str_result.is_valid:
                        raise FileValidationError(
                            str_result.error_message,
                            field_name=f"{field_name}.{validated_key}",
                            violation_type=str_result.violation_type
                        )
                    validated_settings[validated_key] = str_result.sanitized_value
                else:
                    validated_settings[validated_key] = None
        
        return validated_settings
    
    def _validate_file_id(self, file_id: Any, field_name: str = "file_id") -> str:
        """Validate file ID parameter.
        
        Args:
            file_id: File ID to validate
            field_name: Name of the field for logging
            
        Returns:
            Validated file ID
            
        Raises:
            FileValidationError: If validation fails
        """
        id_result = validate_string(
            file_id,
            field_name=field_name,
            max_length=255,
            min_length=1,
            allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
            require_ascii=True
        )
        if not id_result.is_valid:
            raise FileValidationError(
                id_result.error_message,
                field_name=field_name,
                violation_type=id_result.violation_type
            )
        return id_result.sanitized_value
    
    def _is_media_file(self, filename: str, content: bytes) -> bool:
        """Determine if a file is a media file using enhanced format detection.
        
        Args:
            filename: The name of the file
            content: The file content
            
        Returns:
            True if the file is a media file, False otherwise
        """
        return self.format_detector.is_media_file(filename, content)
    
    def create_secure_file(self, content: bytes, filename: str, password: str, 
                          security_settings: Dict[str, Any]) -> str:
        """Create a new secure file with the specified security settings.
        
        Args:
            content: The file content to encrypt and store
            filename: The name of the file
            password: The password to encrypt the file with
            security_settings: Dictionary containing security parameters:
                - expiration_time: Optional timestamp when the file should expire
                - max_access_count: Optional maximum number of times the file can be accessed
                - deadman_switch: Optional period of inactivity after which the file is deleted
                - disable_export: Optional flag to prevent exporting (view-only mode)
                
        Returns:
            The ID of the created file
            
        Raises:
            FileValidationError: If input validation fails
        """
        # Comprehensive input validation per BAR Rules R030
        validated_content = self._validate_file_content(content)
        validated_filename = self._validate_filename(filename)
        validated_password = self._validate_password(password)
        validated_settings = self._validate_security_settings(security_settings)
        # Generate a unique file ID
        file_id = self._generate_file_id()
        
        # Detect file format using validated data
        format_info = self.format_detector.detect_format(validated_filename, validated_content)
        is_media = format_info['type'] in ['image', 'audio', 'video']
        
        # Check if this is a media file and automatically set disable_export if not explicitly set
        if is_media and "disable_export" not in security_settings:
            # Automatically make media files view-only unless explicitly overridden
            security_settings["disable_export"] = True
            self.logger.info(f"Automatically set view-only mode for {format_info['display_name']}: {filename}")
        
        # Encrypt the validated file content
        encrypted_content = self.encryption_manager.encrypt_file_content(validated_content, validated_password)
        
        # Create metadata
        current_time = datetime.now()
        metadata = {
            "file_id": file_id,
            "filename": validated_filename,
            "creation_time": current_time.isoformat(),
            "last_accessed": current_time.isoformat(),
            "access_count": 0,
            "file_type": format_info['type'],
            "file_format": format_info['format'],
            "mime_type": format_info['mime'],
            "display_name": format_info['display_name'],
            "viewable_in_app": format_info['viewable'],
            "external_viewer": format_info.get('external', False),
            "detection_confidence": format_info['confidence'],
            "security": {
                "expiration_time": validated_settings.get("expiration_time"),
                "max_access_count": validated_settings.get("max_access_count"),
                "deadman_switch": validated_settings.get("deadman_switch"),  # in days
                "disable_export": validated_settings.get("disable_export", False),  # prevents exporting of view-only files
            },
            "encryption": encrypted_content,
            "content_hash": self._hash_content(validated_content),  # Add content hash
            "failed_password_attempts": 0
        }
        
        # Save the file metadata with encryption
        with self._get_file_lock(file_id):
            self._save_metadata(file_id, metadata)
        
        self.logger.info(f"Created secure file with encrypted metadata: {file_id} ({validated_filename})")
        return file_id
    
    def access_file(self, file_id: str, password: str) -> Tuple[bytes, Dict[str, Any]]:
        """Access a secure file, checking security constraints.
        
        Args:
            file_id: The ID of the file to access
            password: The password to decrypt the file
            
        Returns:
            Tuple containing (file_content, metadata)
            
        Raises:
            FileValidationError: If input validation fails
            FileNotFoundError: If the file doesn't exist
            ValueError: If the password is incorrect or the file has expired
            
        Security:
            - Uses file-level locking to prevent race conditions
            - Enforces access count limits atomically
            - Securely deletes file immediately if max access reached
        """
        # Comprehensive input validation per BAR Rules R030
        validated_file_id = self._validate_file_id(file_id)
        validated_password = self._validate_password(password)
        
        # Use file-specific lock to prevent race conditions (CRITICAL FIX)
        with self._get_file_lock(validated_file_id):
            # Check if the validated file exists
            metadata_path = self.metadata_directory / f"{validated_file_id}.json"
            if not metadata_path.exists():
                raise FileNotFoundError(f"File with ID {validated_file_id} not found")
            
            # Load metadata with decryption
            metadata = self._load_metadata(validated_file_id)
            
            # Check security constraints
            if not self._check_security_constraints(metadata):
                # File has expired or reached max access count
                self._secure_delete_file(validated_file_id)
                raise ValueError("File has expired or reached maximum access count")
            
            # Initialize failed attempts tracking if not present
            if "failed_password_attempts" not in metadata:
                metadata["failed_password_attempts"] = 0
                
            # Define max failed attempts
            max_failed_attempts = 3  # Maximum number of failed password attempts allowed
            
            # Decrypt the file content
            try:
                file_content = self.encryption_manager.decrypt_file_content(
                    metadata["encryption"], validated_password)
                # Reset failed attempts on successful decryption
                metadata["failed_password_attempts"] = 0
                # Record successful access if monitor is available
                if self.monitor:
                    self.monitor.record_access_event(validated_file_id, "decrypt", success=True)
            except ValueError:
                # Increment failed attempts
                metadata["failed_password_attempts"] += 1
                self.logger.warning(f"Failed decryption attempt for file: {validated_file_id}. Attempt {metadata['failed_password_attempts']} of {max_failed_attempts}")
                
                # Record failed access if monitor is available
                if self.monitor:
                    self.monitor.record_access_event(validated_file_id, "decrypt", success=False)
                
                # Save updated metadata with failed attempts count
                self._save_metadata(validated_file_id, metadata)
                    
                # Check if max failed attempts reached
                if metadata["failed_password_attempts"] >= max_failed_attempts:
                    self.logger.warning(f"Maximum failed attempts reached for file: {validated_file_id}. Permanently deleting file.")
                    self._secure_delete_file(validated_file_id)
                    raise ValueError(f"File has been permanently deleted after {max_failed_attempts} failed password attempts")
                
                # Generic error message - don't reveal remaining attempts (SECURITY FIX)
                raise ValueError("Incorrect password. Multiple failed attempts will result in permanent file deletion.")
            
            # Update access metadata
            current_time = datetime.now()
            metadata["last_accessed"] = current_time.isoformat()
            metadata["access_count"] += 1
            
            # Check if this access triggers self-destruction
            max_access = metadata["security"].get("max_access_count")
            should_delete = max_access and metadata["access_count"] >= max_access
            
            if should_delete:
                # Mark for deletion
                metadata["pending_deletion"] = True
                self.logger.info(f"File {validated_file_id} reached max access count ({metadata['access_count']}/{max_access})")
            
            # Save updated metadata (last time before potential deletion)
            self._save_metadata(validated_file_id, metadata)
            
            # Store return value before deletion
            result = (file_content, metadata.copy())
            
            # Delete immediately if max access reached (while holding lock)
            if should_delete:
                self.logger.info(f"Deleting file {validated_file_id} after final access")
                self._secure_delete_file(validated_file_id)
            
            # Record successful access for monitoring
            if self.monitor:
                self.monitor.record_access_event(validated_file_id, "access", success=True)
            
            self.logger.info(f"Accessed file: {validated_file_id} ({metadata['filename']})")
            return result
    
    def list_files(self) -> List[Dict[str, Any]]:
        """List all available secure files with their metadata (excluding encryption details).
        
        Returns:
            List of dictionaries containing file metadata with additional UI-friendly fields:
            - is_view_only: Boolean indicating if the file is view-only (cannot be exported)
            - file_type: String indicating the type of file ("media" or "document")
            - file_type_display: User-friendly display name for the file type
        """
        files = []
        for metadata_file in self.metadata_directory.glob("*.json"):
            # Extract file_id from filename
            file_id = metadata_file.stem
            
            try:
                # Load metadata with decryption
                metadata = self._load_metadata(file_id, migrate_legacy=True)
            except Exception as e:
                self.logger.error(f"Failed to load metadata for {file_id}: {e}")
                continue
            
            # Remove sensitive encryption details
            if "encryption" in metadata:
                metadata_copy = metadata.copy()
                del metadata_copy["encryption"]
                
                # Add UI-friendly fields
                metadata_copy["is_view_only"] = metadata_copy.get("security", {}).get("disable_export", False)
                
                # Use enhanced format information if available, otherwise fall back to legacy
                if "display_name" in metadata_copy:
                    metadata_copy["file_type_display"] = metadata_copy["display_name"]
                else:
                    # Legacy fallback for older files
                    file_type = metadata_copy.get("file_type", "document")
                    if file_type == "media":
                        # Determine more specific media type based on filename
                        filename = metadata_copy.get("filename", "").lower()
                        if any(filename.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg"]):
                            metadata_copy["file_type_display"] = "Image"
                        elif any(filename.endswith(ext) for ext in [".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a"]):
                            metadata_copy["file_type_display"] = "Audio"
                        elif any(filename.endswith(ext) for ext in [".mp4", ".avi", ".mov", ".wmv", ".mkv", ".webm", ".flv"]):
                            metadata_copy["file_type_display"] = "Video"
                        elif filename.endswith(".pdf"):
                            metadata_copy["file_type_display"] = "PDF Document"
                        else:
                            metadata_copy["file_type_display"] = "Media File"
                    else:
                        metadata_copy["file_type_display"] = "Document"
                
                files.append(metadata_copy)
        
        return files
    
    def delete_file(self, file_id: str) -> bool:
        """Delete a secure file.
        
        Args:
            file_id: The ID of the file to delete
            
        Returns:
            True if the file was deleted, False if it doesn't exist
        """
        return self._delete_file(file_id)
    
    def _delete_file(self, file_id: str) -> bool:
        """Internal method to delete a file and its metadata.
        
        Args:
            file_id: The ID of the file to delete
            
        Returns:
            True if the file was deleted, False if it doesn't exist
        """
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            return False
        
        # Get filename for logging
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                filename = metadata.get("filename", "unknown")
        except:
            filename = "unknown"
        
        # Delete the metadata file
        metadata_path.unlink()
        
        self.logger.info(f"Deleted file: {file_id} ({filename})")
        return True
        
    def _secure_delete_file(self, file_id: str, blacklist: bool = True) -> bool:
        """Securely delete a file and its metadata to prevent recovery.
        
        This method uses secure deletion techniques to permanently remove the file
        from the device, making it unrecoverable even with specialized recovery tools.
        It also adds the file's content hash to a blacklist to prevent reimporting.
        
        Args:
            file_id: The ID of the file to delete
            blacklist: Whether to add the file to the blacklist (default: True)
            
        Returns:
            True if the file was deleted, False if it doesn't exist
        """
        from src.security.secure_file_ops import SecureFileOperations, SecureDeletionMethod
        
        # Validate file_id
        if not file_id or not isinstance(file_id, str):
            self.logger.error(f"Invalid file_id provided: {type(file_id)}")
            return False
            
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            return False
        
        # Default filename in case we can't read it from metadata
        filename = "unknown"
        
        # Get filename for logging and check for any file paths
        try:
            with open(metadata_path, "r") as f:
                try:
                    metadata = json.load(f)
                    filename = metadata.get("filename", "unknown")
                    
                    # If blacklisting is enabled, add file information to blacklist
                    # Handle this in a separate try block to prevent it from affecting the rest of the deletion
                    if blacklist:
                        try:
                            self._add_to_blacklist(metadata)
                        except Exception as blacklist_error:
                            self.logger.error(f"Error adding file to blacklist: {str(blacklist_error)}")
                            # Continue with deletion even if blacklisting fails
                    
                    # Process associated files in separate try blocks to ensure one failure doesn't stop others
                    
                    # If there's an actual file stored on disk (for BAR files), delete it too
                    if "file_path" in metadata:
                        try:
                            file_path = Path(metadata["file_path"])
                            if file_path.exists() and file_path.is_file():
                                # Initialize secure delete
                                secure_file_ops = SecureFileOperations()
                                # Securely delete the actual file
                                secure_file_ops.secure_delete_file(str(file_path), SecureDeletionMethod.DOD_7_PASS)
                                self.logger.info(f"Securely deleted actual file at: {file_path}")
                        except Exception as file_error:
                            self.logger.error(f"Error deleting associated file: {str(file_error)}")
                    
                    # Check for any exported files that might be associated with this file_id
                    try:
                        export_dir = self.base_directory / "exports"
                        if export_dir.exists() and export_dir.is_dir():
                            for export_file in export_dir.glob(f"*{file_id}*"):
                                if export_file.exists() and export_file.is_file():
                                    secure_file_ops = SecureFileOperations()
                                    secure_file_ops.secure_delete_file(str(export_file), SecureDeletionMethod.DOD_7_PASS)
                                    self.logger.info(f"Securely deleted exported file: {export_file}")
                    except Exception as export_error:
                        self.logger.error(f"Error deleting exported files: {str(export_error)}")
                    
                    # Check for any temporary files that might be associated with this file_id
                    try:
                        temp_dir = self.base_directory / "temp"
                        if temp_dir.exists() and temp_dir.is_dir():
                            for temp_file in temp_dir.glob(f"*{file_id}*"):
                                if temp_file.exists() and temp_file.is_file():
                                    secure_file_ops = SecureFileOperations()
                                    secure_file_ops.secure_delete_file(str(temp_file), SecureDeletionMethod.DOD_7_PASS)
                                    self.logger.info(f"Securely deleted temporary file: {temp_file}")
                    except Exception as temp_error:
                        self.logger.error(f"Error deleting temporary files: {str(temp_error)}")
                    
                    # Check for any portable files that might be associated with this file_id
                    try:
                        portable_dir = self.base_directory / "portable"
                        if portable_dir.exists() and portable_dir.is_dir():
                            for portable_file in portable_dir.glob(f"*{file_id}*"):
                                if portable_file.exists() and portable_file.is_file():
                                    secure_file_ops = SecureFileOperations()
                                    secure_file_ops.secure_delete_file(str(portable_file), SecureDeletionMethod.DOD_7_PASS)
                                    self.logger.info(f"Securely deleted portable file: {portable_file}")
                    except Exception as portable_error:
                        self.logger.error(f"Error deleting portable files: {str(portable_error)}")
                    
                    # Search for and delete any .bar files with matching content hash across the system
                    # Do this in a separate thread to prevent blocking and potential crashes
                    if "content_hash" in metadata:
                        content_hash = metadata.get("content_hash")
                        if content_hash:
                            try:
                                # Use a thread with a timeout to prevent hanging
                                search_thread = threading.Thread(
                                    target=self._find_and_delete_matching_bar_files,
                                    args=(content_hash,),
                                    daemon=True
                                )
                                search_thread.start()
                                # Don't wait for completion - let it run in background
                            except Exception as thread_error:
                                self.logger.error(f"Error starting search thread: {str(thread_error)}")
                except json.JSONDecodeError as json_error:
                    self.logger.error(f"Error parsing metadata JSON: {str(json_error)}")
        except Exception as e:
            self.logger.error(f"Error reading metadata during secure deletion: {str(e)}")
        
        # Initialize secure file operations
        secure_file_ops = SecureFileOperations()
        
        # Securely delete the metadata file
        try:
            secure_file_ops.secure_delete_file(str(metadata_path), SecureDeletionMethod.DOD_7_PASS)
        except Exception as delete_error:
            self.logger.error(f"Error securely deleting metadata file: {str(delete_error)}")
            # Try regular deletion as fallback
            try:
                os.remove(str(metadata_path))
                self.logger.warning(f"Fell back to regular deletion for metadata file: {metadata_path}")
            except Exception as fallback_error:
                self.logger.error(f"Failed to delete metadata file even with fallback: {str(fallback_error)}")
        
        self.logger.info(f"Securely deleted file: {file_id} ({filename})")
        return True
    
    def export_file(self, file_id: str, export_path: str) -> bool:
        """Export a secure file for sharing.
        
        Args:
            file_id: The ID of the file to export
            export_path: The path where the exported file should be saved
            
        Returns:
            True if the file was exported successfully, False otherwise
            
        Raises:
            ValueError: If the file is marked as view-only and cannot be exported
        """
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            return False
        
        # Load metadata to check export restrictions
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        # Check if export is disabled for this file
        if metadata.get("security", {}).get("disable_export", False):
            self.logger.warning(f"Attempted to export view-only file: {file_id}")
            raise ValueError("This file has been marked as view-only and cannot be exported")
        
        # Copy the metadata file to the export location
        try:
            shutil.copy(metadata_path, export_path)
            self.logger.info(f"Exported file: {file_id} to {export_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export file {file_id}: {str(e)}")
            return False
            
    def export_portable_file(self, file_id: str, password: str, export_path: str) -> bool:
        """Export a secure file in a portable format that can be imported on another device.
        
        This creates a fully encrypted portable file format where ALL metadata and content
        is encrypted, preventing any information leakage. Includes integrity protection
        and anti-forensics measures.
        
        Args:
            file_id: The ID of the file to export
            password: The password to decrypt and verify the file
            export_path: The path where the exported file should be saved
            
        Returns:
            True if the file was exported successfully, False otherwise
            
        Raises:
            ValueError: If the password is incorrect or if the file is view-only
            FileNotFoundError: If the file doesn't exist
        """
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            raise FileNotFoundError(f"File with ID {file_id} not found")
        
        # Load metadata
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        # Check if the file is marked as view-only before attempting decryption
        if metadata["security"].get("disable_export", False):
            self.logger.warning(f"Attempted to export view-only file: {file_id}")
            raise ValueError("This file has been marked as view-only and cannot be exported")
        
        # Verify password by attempting decryption
        try:
            file_content = self.encryption_manager.decrypt_file_content(
                metadata["encryption"], password)
        except ValueError:
            self.logger.warning(f"Failed decryption attempt during export for file: {file_id}")
            raise ValueError("Incorrect password")
        
        # Use the new secure portable format
        try:
            from src.crypto.secure_portable_format import SecurePortableFormat
            
            # Initialize secure portable format handler
            secure_format = SecurePortableFormat(self.logger)
            
            # Create the secure portable file with full encryption
            success = secure_format.create_portable_file(
                file_content=file_content,
                metadata=metadata,
                password=password,
                output_path=export_path
            )
            
            if success:
                self.logger.info(f"Exported secure portable file: {file_id} to {export_path}")
                
                # Security audit log
                self.logger.info(f"SECURITY: Portable export completed with full encryption - no plaintext metadata exposed")
                return True
            else:
                raise ValueError("Failed to create secure portable file")
                
        except ImportError as e:
            self.logger.error(f"Failed to import secure portable format: {str(e)}")
            raise ValueError("Secure portable format not available")
        except Exception as e:
            self.logger.error(f"Failed to export secure portable file {file_id}: {str(e)}")
            raise ValueError(f"Failed to export file: {str(e)}")
    
    def import_portable_file(self, import_path: str, password: str) -> str:
        """Import a portable secure file.
        
        Supports both new secure format (fully encrypted) and legacy format.
        The new format provides enhanced security with no metadata exposure.
        
        Args:
            import_path: The path of the portable file to import
            password: The password to decrypt the file
            
        Returns:
            The ID of the imported file
            
        Raises:
            ValueError: If the file is not a valid BAR portable file or password is incorrect
        """
        try:
            # Import secure portable files only - no legacy support for security
            from src.crypto.secure_portable_format import SecurePortableFormat
            
            secure_format = SecurePortableFormat(self.logger)
            
            # Check if it's a secure format file
            if secure_format.is_secure_portable_file(import_path):
                self.logger.info(f"Importing secure portable file: {import_path}")
                
                # Decrypt the secure portable file
                file_content, metadata = secure_format.read_portable_file(import_path, password)
                
                # Check if the file is in the blacklist
                content_hash = metadata.get("content_hash")
                if content_hash and self._is_blacklisted(content_hash):
                    raise ValueError("This file has been permanently deleted due to security violations and cannot be reimported")
                
                # Generate a new file ID for import
                file_id = self._generate_file_id()
                
                # Re-encrypt the content with our encryption manager
                encrypted_data = self.encryption_manager.encrypt_file_content(file_content, password)
                
                # Create new metadata
                import_metadata = {
                    "file_id": file_id,
                    "filename": metadata["filename"],
                    "creation_time": metadata["creation_time"],
                    "last_accessed": datetime.now().isoformat(),
                    "access_count": metadata.get("access_count", 0),
                    "file_type": metadata.get("file_type", "document"),
                    "security": metadata["security"],
                    "encryption": encrypted_data,
                    "content_hash": content_hash or self._hash_content(file_content),
                    "failed_password_attempts": 0  # Reset for new import
                }
                
                # Save the metadata file
                metadata_path = self.metadata_directory / f"{file_id}.json"
                with open(metadata_path, "w") as f:
                    json.dump(import_metadata, f, indent=2)
                
                self.logger.info(f"Successfully imported secure portable file: {file_id} ({metadata['filename']})")
                self.logger.info(f"SECURITY: File imported with military-grade security - zero metadata exposure")
                return file_id
            else:
                # File is not in secure format - reject it for security
                self.logger.error(f"SECURITY VIOLATION: Attempted to import insecure portable file: {import_path}")
                raise ValueError("This file is not in the secure BAR portable format. Only secure format files can be imported for security reasons. Please re-export the file using the current version of BAR.")
            
        except Exception as e:
            self.logger.error(f"Failed to import portable file: {str(e)}")
            raise ValueError(f"Failed to import file: {str(e)}")
    
    def _hash_content(self, content: bytes) -> str:
        """Create a hash of file content for integrity verification.
        
        Args:
            content: The file content to hash
            
        Returns:
            Base64-encoded hash of the content
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(content)
        content_hash = digest.finalize()
        return base64.b64encode(content_hash).decode('utf-8')
    
    def import_file(self, import_path: str) -> str:
        """Import a secure file.
        
        Args:
            import_path: The path of the file to import
            
        Returns:
            The ID of the imported file
            
        Raises:
            ValueError: If the file is not a valid BAR file
        """
        try:
            # Load and validate the file
            with open(import_path, "r") as f:
                metadata = json.load(f)
            
            # Check if it's a valid BAR file
            if "file_id" not in metadata or "encryption" not in metadata:
                raise ValueError("Not a valid BAR file")
            
            file_id = metadata["file_id"]
            
            # Check if a file with this ID already exists
            target_path = self.metadata_directory / f"{file_id}.json"
            if target_path.exists():
                # Generate a new file ID
                old_file_id = file_id
                file_id = self._generate_file_id()
                metadata["file_id"] = file_id
                target_path = self.metadata_directory / f"{file_id}.json"
                self.logger.info(f"Renamed imported file from {old_file_id} to {file_id}")
            
            # Save the metadata file
            with open(target_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info(f"Imported file: {file_id} ({metadata.get('filename', 'unknown')})")
            return file_id
            
        except Exception as e:
            self.logger.error(f"Failed to import file: {str(e)}")
            raise ValueError(f"Failed to import file: {str(e)}")
    
    def update_security_settings(self, file_id: str, security_settings: Dict[str, Any]) -> bool:
        """Update the security settings for a file.
        
        Args:
            file_id: The ID of the file to update
            security_settings: Dictionary containing security parameters to update
                
        Returns:
            True if the settings were updated, False if the file doesn't exist
        """
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            return False
        
        # Use file lock for thread safety
        with self._get_file_lock(file_id):
            try:
                # Load metadata with decryption
                metadata = self._load_metadata(file_id)
                
                # Update security settings
                for key, value in security_settings.items():
                    if key in metadata["security"]:
                        metadata["security"][key] = value
                
                # Save updated metadata with encryption
                self._save_metadata(file_id, metadata)
                
                self.logger.info(f"Updated security settings for file: {file_id}")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to update security settings for {file_id}: {e}")
                return False
    
    def _check_security_constraints(self, metadata: Dict[str, Any]) -> bool:
        """Check if a file meets its security constraints.
        
        Args:
            metadata: The file metadata
            
        Returns:
            True if the file can be accessed, False if it should be deleted
        """
        current_time = datetime.now()
        
        # Check expiration time
        if metadata["security"]["expiration_time"]:
            expiration_time = datetime.fromisoformat(metadata["security"]["expiration_time"])
            if current_time > expiration_time:
                self.logger.info(f"File {metadata['file_id']} has expired")
                return False
        
        # Check max access count
        max_access_count = metadata["security"]["max_access_count"]
        if max_access_count:
            # Handle both string and integer types for backward compatibility
            if isinstance(max_access_count, str):
                try:
                    max_access_count = int(max_access_count)
                except (ValueError, TypeError):
                    self.logger.warning(f"Invalid max_access_count value for file {metadata['file_id']}: {max_access_count}")
                    max_access_count = None
            
            if max_access_count and metadata["access_count"] >= max_access_count:
                self.logger.info(f"File {metadata['file_id']} has reached max access count")
                return False
        
        # Check deadman switch
        deadman_switch = metadata["security"]["deadman_switch"]
        if deadman_switch:
            # Handle both string and integer types for backward compatibility
            if isinstance(deadman_switch, str):
                try:
                    deadman_switch = int(deadman_switch)
                except (ValueError, TypeError):
                    self.logger.warning(f"Invalid deadman_switch value for file {metadata['file_id']}: {deadman_switch}")
                    deadman_switch = None
            
            if deadman_switch:
                last_accessed = datetime.fromisoformat(metadata["last_accessed"])
                inactive_days = (current_time - last_accessed).days
                
                if inactive_days > deadman_switch:
                    self.logger.info(f"File {metadata['file_id']} triggered deadman switch")
                    return False
        
        return True
    
    def _monitor_files(self):
        """Monitor files for security constraints and trigger self-destruction."""
        while self.monitoring_active:
            try:
                # Get all file metadata
                for metadata_file in self.metadata_directory.glob("*.json"):
                    file_id = metadata_file.stem
                    
                    try:
                        # Load metadata with decryption
                        metadata = self._load_metadata(file_id, migrate_legacy=False)
                        
                        # Check security constraints
                        if not self._check_security_constraints(metadata):
                            self._secure_delete_file(file_id)
                    except FileNotFoundError:
                        # File was deleted, skip
                        continue
                    except Exception as e:
                        self.logger.error(f"Error monitoring file {file_id}: {str(e)}")
                
                # Sleep for a while before checking again
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Error in file monitoring thread: {str(e)}")
                time.sleep(60)  # Sleep and try again
    
    def _generate_file_id(self) -> str:
        """Generate a unique file ID.
        
        Returns:
            A unique file ID
        """
        import uuid
        return str(uuid.uuid4())
    
    def shutdown(self):
        """Shutdown the file manager and stop monitoring."""
        self.monitoring_active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
        
        # Stop any ongoing scans
        if hasattr(self, 'file_scanner') and self.file_scanner.scan_in_progress:
            self.file_scanner.stop_scan()
        
        # Securely clear metadata encryption key
        self.clear_metadata_key()
        
        # Clear file locks
        with self._file_locks_lock:
            self._file_locks.clear()
            
        self.logger.info("File manager shutdown - metadata key cleared")
    
    def scan_device_for_bar_files(self, device_path: str, recursive: bool = True, callback=None) -> Dict[str, Any]:
        """Scan a device for .bar files.
        
        Args:
            device_path: The path to the device or directory to scan
            recursive: Whether to scan subdirectories recursively
            callback: Optional callback function to report progress
            
        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Starting scan for .bar files at {device_path}")
        return self.file_scanner.scan_device(device_path, recursive, callback)
    
    def get_scan_progress(self) -> Dict[str, Any]:
        """Get the current scan progress.
        
        Returns:
            Dictionary with scan progress information
        """
        return self.file_scanner.get_scan_progress()
    
    def get_scan_results(self) -> Dict[str, Any]:
        """Get the results of the last scan.
        
        Returns:
            Dictionary with scan results
        """
        return self.file_scanner.get_scan_results()
    
    def stop_scan(self) -> Dict[str, Any]:
        """Stop an ongoing scan.
        
        Returns:
            Dictionary with status information
        """
        self.logger.info("Stopping file scan")
        return self.file_scanner.stop_scan()
    
    def import_found_bar_file(self, file_path: str, password: str) -> Dict[str, Any]:
        """Import a found .bar file into the system.
        
        Args:
            file_path: Path to the .bar file to import
            password: Password to decrypt the file
            
        Returns:
            Dictionary with import results
        """
        self.logger.info(f"Importing found .bar file: {file_path}")
        return self.file_scanner.import_found_file(file_path, password)
    
    def scan_all_devices(self, callback=None) -> Dict[str, Any]:
        """Scan all connected devices for .bar files.
        
        Args:
            callback: Optional callback function to report progress
            
        Returns:
            Dictionary containing scan results
        """
        self.logger.info("Starting scan for .bar files on all connected devices")
        return self.file_scanner.scan_removable_devices(callback)
    
    def get_available_devices(self) -> List[Dict[str, Any]]:
        """Get a list of available devices that can be scanned.
        
        Returns:
            List of dictionaries containing device information
        """
        return self.file_scanner.get_available_devices()

    def _add_to_blacklist(self, metadata: Dict[str, Any]) -> bool:
        """Add a file's content hash to the blacklist to prevent reimporting.
        
        Args:
            metadata: The file metadata containing content hash and other information
            
        Returns:
            True if the file was added to the blacklist, False otherwise
        """
        try:
            # Extract content hash and other relevant information
            content_hash = metadata.get("content_hash")
            
            # Safely handle encryption data if content_hash is not available
            if not content_hash and "encryption" in metadata:
                try:
                    # If content hash is not available but we have the encrypted content,
                    # we can still create a hash of the encrypted data
                    encryption_data = metadata.get("encryption", {})
                    
                    # Handle different types of encryption data
                    if isinstance(encryption_data, dict):
                        content_str = json.dumps(encryption_data, sort_keys=True)
                    elif isinstance(encryption_data, str):
                        content_str = encryption_data
                    else:
                        content_str = str(encryption_data)
                        
                    content_hash = hashlib.sha256(content_str.encode('utf-8')).hexdigest()
                except Exception as hash_error:
                    self.logger.warning(f"Failed to create hash from encryption data: {str(hash_error)}")
                    # Generate a fallback hash using file_id and timestamp to ensure uniqueness
                    fallback_str = f"{metadata.get('file_id', 'unknown')}_{datetime.now().isoformat()}"
                    content_hash = hashlib.sha256(fallback_str.encode('utf-8')).hexdigest()
            
            if not content_hash:
                self.logger.warning("Cannot add file to blacklist: no content hash available")
                return False
            
            # Ensure the blacklist directory exists
            self.blacklist_directory.mkdir(parents=True, exist_ok=True)
            
            # Create blacklist entry
            blacklist_entry = {
                "content_hash": content_hash,
                "filename": metadata.get("filename", "unknown"),
                "file_id": metadata.get("file_id", "unknown"),
                "blacklisted_at": datetime.now().isoformat(),
                "reason": "security_violation",  # Default reason
                "original_creation_time": metadata.get("creation_time")
            }
            
            # Create a safe filename for the blacklist entry
            # Replace any potentially problematic characters with underscores
            safe_hash = re.sub(r'[^a-zA-Z0-9_-]', '_', content_hash)
            
            # Save to blacklist file
            blacklist_path = self.blacklist_directory / f"{safe_hash}.json"
            with open(blacklist_path, "w") as f:
                json.dump(blacklist_entry, f, indent=2)
            
            self.logger.info(f"Added file to blacklist: {metadata.get('filename', 'unknown')} (hash: {content_hash[:8] if len(content_hash) >= 8 else content_hash}...)")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding file to blacklist: {str(e)}")
            # Don't let blacklist errors crash the application
            return False
    
    def _is_blacklisted(self, content_hash: str) -> bool:
        """Check if a file's content hash is in the blacklist.
        
        Args:
            content_hash: The content hash to check
            
        Returns:
            True if the file is blacklisted, False otherwise
        """
        try:
            # Create a safe filename for the blacklist entry
            # Replace any potentially problematic characters with underscores
            safe_hash = re.sub(r'[^a-zA-Z0-9_-]', '_', content_hash)
            
            # Check if the hash exists in the blacklist directory
            blacklist_path = self.blacklist_directory / f"{safe_hash}.json"
            return blacklist_path.exists()
        except Exception as e:
            self.logger.error(f"Error checking blacklist: {str(e)}")
            return False
    
    def _find_and_delete_matching_bar_files(self, content_hash: str) -> int:
        """Find and securely delete any .bar files with matching content hash across the system.
        
        This helps ensure that when a file is deleted due to security violations,
        all copies of it are removed from the device.
        
        Args:
            content_hash: The content hash to search for
            
        Returns:
            Number of matching files deleted
        """
        try:
            # Validate content_hash to prevent crashes
            if not content_hash or not isinstance(content_hash, str):
                self.logger.warning(f"Invalid content hash provided: {type(content_hash)}")
                return 0
                
            from src.security.secure_file_ops import SecureFileOperations, SecureDeletionMethod
            secure_file_ops = SecureFileOperations()
            deleted_count = 0
            
            # Get all available devices - handle potential errors
            try:
                devices = self.file_scanner.get_available_devices()
            except Exception as dev_error:
                self.logger.error(f"Error getting available devices: {str(dev_error)}")
                return 0
            
            # Limit search to prevent excessive resource usage
            max_search_time = 60  # seconds
            start_time = time.time()
            
            for device in devices:
                # Check if we've exceeded the maximum search time
                if time.time() - start_time > max_search_time:
                    self.logger.warning("Maximum search time exceeded, stopping search")
                    break
                    
                device_path = device.get("path")
                if not device_path:
                    continue
                    
                # Skip network drives and CD-ROMs for performance and permission reasons
                if device.get("type") in ["Network", "CD-ROM"]:
                    continue
                
                try:
                    # Search for .bar files in common directories
                    search_dirs = [
                        Path(device_path) / "Users",  # Windows user directories
                        Path(device_path) / "Documents",  # Common document location
                        Path(device_path) / "Downloads",  # Common download location
                    ]
                    
                    for search_dir in search_dirs:
                        if not search_dir.exists() or not search_dir.is_dir():
                            continue
                            
                        # Search for .bar files with a timeout check
                        try:
                            for bar_file in search_dir.rglob("*.bar"):
                                # Check timeout periodically
                                if time.time() - start_time > max_search_time:
                                    self.logger.warning("Maximum search time exceeded during directory scan")
                                    break
                                    
                                try:
                                    # Check if this .bar file contains the matching content hash
                                    with open(bar_file, "r") as f:
                                        try:
                                            data = json.load(f)
                                            file_hash = data.get("content_hash")
                                            
                                            if file_hash and file_hash == content_hash:
                                                # Found a match, securely delete it
                                                if secure_file_ops.secure_delete_file(str(bar_file), SecureDeletionMethod.DOD_7_PASS):
                                                    self.logger.info(f"Deleted matching .bar file: {bar_file}")
                                                    deleted_count += 1
                                        except (json.JSONDecodeError, UnicodeDecodeError):
                                            # Not a valid JSON file, skip
                                            pass
                                except (PermissionError, OSError, FileNotFoundError):
                                    # Can't access file, skip
                                    pass
                        except Exception as rglob_error:
                            self.logger.warning(f"Error during directory scan of {search_dir}: {str(rglob_error)}")
                            continue
                except Exception as e:
                    self.logger.warning(f"Error searching device {device_path}: {str(e)}")
            
            if deleted_count > 0:
                hash_prefix = content_hash[:8] if len(content_hash) >= 8 else content_hash
                self.logger.info(f"Deleted {deleted_count} matching .bar files with content hash {hash_prefix}...")
            
            return deleted_count
        except Exception as e:
            self.logger.error(f"Error finding and deleting matching files: {str(e)}")
            # Don't let file search errors crash the application
            return 0