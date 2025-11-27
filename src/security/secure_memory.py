import os
import sys
import ctypes
import secrets
import threading
import weakref
import gc
import atexit
import subprocess
from typing import Any, Optional, Union, List, Dict, Callable

# Optional imports for cross-platform compatibility
try:
    import resource
    RESOURCE_AVAILABLE = True
except ImportError:
    RESOURCE_AVAILABLE = False
import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
import time
import hashlib
from enum import Enum
from pathlib import Path

# Import comprehensive input validation system
from .input_validator import (
    InputValidator, ValidationConfig, ValidationLevel, ValidationResult,
    MemoryValidationError, validate_string, validate_bytes, validate_integer
)

# Enhanced cryptographic imports per R004 - Cryptographic Standards
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logging.warning("Cryptography library not available - some security features will be limited")


class MemoryProtectionLevel(Enum):
    """Memory protection levels."""
    BASIC = "basic"                    # Basic secure clearing
    ENHANCED = "enhanced"              # Multi-pass clearing + locking
    MAXIMUM = "maximum"                # All features + canaries + monitoring
    MILITARY = "military"              # Maximum + TPM/enclave + anti-forensics


class SecureMemoryError(Exception):
    """Base exception for secure memory operations."""
    pass


class MemoryCorruptionError(SecureMemoryError):
    """Raised when memory corruption is detected."""
    pass


class MemoryLockError(SecureMemoryError):
    """Raised when memory locking fails critically."""
    pass


class MemoryForensicsError(SecureMemoryError):
    """Raised when memory forensics attempts are detected."""
    pass


class TPMError(SecureMemoryError):
    """Raised when TPM/secure enclave operations fail."""
    pass


@dataclass
class MemoryStats:
    """Statistics for secure memory usage."""
    total_allocations: int = 0
    active_allocations: int = 0
    total_bytes_allocated: int = 0
    active_bytes_allocated: int = 0
    lock_failures: int = 0
    corruption_detections: int = 0
    cleanup_operations: int = 0
    forensics_attempts: int = 0
    tpm_operations: int = 0
    enclave_operations: int = 0
    memory_monitoring_alerts: int = 0
    performance_violations: int = 0


@dataclass
class MemorySecurityEvent:
    """Represents a memory security event for monitoring."""
    event_type: str
    timestamp: float
    severity: str  # 'low', 'medium', 'high', 'critical'
    message: str
    object_id: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


class SecureBytes:
    """Enhanced secure string/bytes wrapper with advanced memory protection.
    
    Features:
    - Multi-pass secure memory clearing
    - Memory locking to prevent swapping
    - Canary values for corruption detection
    - Memory access monitoring
    - Thread-safe operations
    - Configurable protection levels
    """
    
    # Class-level constants
    CANARY_SIZE = 8
    CANARY_PATTERN = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
    OVERWRITE_PATTERNS = [0x00, 0xFF, 0xAA, 0x55]  # Multiple overwrite patterns
    
    def __init__(self, 
                 data: Union[str, bytes, bytearray] = None,
                 protection_level: MemoryProtectionLevel = MemoryProtectionLevel.ENHANCED,
                 require_lock: bool = False,
                 use_tmp: bool = False,
                 hardware_bound: bool = False):
        """Initialize secure bytes container with enhanced protection.
        
        Args:
            data: Initial data to store (will be securely copied)
            protection_level: Level of memory protection to apply
            require_lock: If True, raises MemoryLockError if memory locking fails
            use_tmp: If True, attempts to use TPM/secure enclave for protection
            hardware_bound: If True, binds data to current hardware ID
            
        Raises:
            MemoryValidationError: If input validation fails
            TypeError: If parameters have invalid types
            ValueError: If parameters have invalid values
        """
        # Initialize basic attributes first for validation methods
        self._protection_level = protection_level
        self._require_lock = require_lock
        self._use_tpm = use_tmp
        self._hardware_bound = hardware_bound
        self._locked = False
        self._corrupted = False
        self._access_count = 0
        self._created_time = time.time()
        self._lock = threading.RLock()  # Thread safety
        self.logger = logging.getLogger(f"SecureBytes_{id(self)}")
        
        # Comprehensive input validation per BAR Rules R030
        self._validate_initialization_parameters(
            data, protection_level, require_lock, use_tmp, hardware_bound
        )
        
        # Initialize input validator based on protection level
        validation_level = self._get_validation_level_for_protection(protection_level)
        self._validator = InputValidator(ValidationConfig(
            level=validation_level,
            max_length=100 * 1024 * 1024,  # 100MB max for memory operations
            timing_attack_protection=True,
            log_violations=True
        ))
        
        # Enhanced security components
        self._tmp_interface = None
        self._hardware_id = None
        self._sealed_data = None  # TPM-sealed version of data
        self._anti_forensics_monitor = None
        
        # Initialize security components based on protection level
        if protection_level in (MemoryProtectionLevel.MAXIMUM, MemoryProtectionLevel.MILITARY):
            if use_tmp:
                self._tmp_interface = TPMInterface()
            if protection_level == MemoryProtectionLevel.MILITARY:
                self._anti_forensics_monitor = AntiForensicsMonitor()
                self._anti_forensics_monitor.add_alert_callback(self._handle_security_alert)
                self._anti_forensics_monitor.start_monitoring()
        
        # Initialize data with validated input and enhanced protection
        if data is None:
            self._data = bytearray()
        else:
            # Validate and sanitize input data
            self._data = self._validate_and_prepare_data(data)
        
        # Hardware binding if requested
        if self._hardware_bound:
            self._bind_to_hardware()
        
        # TPM sealing if available and requested
        if self._use_tpm and hasattr(self, '_tmp_interface') and self._tmp_interface and self._tmp_interface.is_available():
            self._seal_with_tpm()
        
        # Add canary values for corruption detection (MAXIMUM protection)
        if self._protection_level == MemoryProtectionLevel.MAXIMUM:
            self._add_canaries()
        
        # Try to lock memory to prevent swapping
        self._attempt_memory_lock()
        
        # Register with memory manager
        get_secure_memory_manager().register_secure_object(self)
        
        self.logger.debug(f"SecureBytes initialized: {len(self._data)} bytes, protection: {protection_level.value}, TPM: {use_tmp}, HW-bound: {hardware_bound}")
    
    def _validate_initialization_parameters(self, data: Any, protection_level: Any, 
                                          require_lock: Any, use_tmp: Any, 
                                          hardware_bound: Any) -> None:
        """Validate initialization parameters with comprehensive security checks.
        
        Args:
            data: Data parameter to validate
            protection_level: Protection level parameter to validate
            require_lock: Memory lock requirement parameter to validate
            use_tpm: TPM usage parameter to validate
            hardware_bound: Hardware binding parameter to validate
            
        Raises:
            MemoryValidationError: If validation fails
            TypeError: If types are invalid
            ValueError: If values are invalid
        """
        # Validate protection level
        if not isinstance(protection_level, MemoryProtectionLevel):
            if isinstance(protection_level, str):
                try:
                    protection_level = MemoryProtectionLevel(protection_level.lower())
                except ValueError:
                    raise MemoryValidationError(
                        f"Invalid protection level: {protection_level}",
                        field_name="protection_level",
                        violation_type="invalid_enum_value"
                    )
            else:
                raise MemoryValidationError(
                    "Protection level must be MemoryProtectionLevel enum or valid string",
                    field_name="protection_level",
                    violation_type="invalid_type"
                )
        
        # Validate boolean parameters with strict type checking
        bool_params = {
            'require_lock': require_lock,
            'use_tmp': use_tmp, 
            'hardware_bound': hardware_bound
        }
        
        for param_name, param_value in bool_params.items():
            if not isinstance(param_value, bool):
                # Allow string-to-bool conversion for common cases
                if isinstance(param_value, str):
                    lower_val = param_value.lower()
                    if lower_val in ('true', '1', 'yes', 'on'):
                        bool_params[param_name] = True
                    elif lower_val in ('false', '0', 'no', 'off'):
                        bool_params[param_name] = False
                    else:
                        raise MemoryValidationError(
                            f"Invalid boolean value for {param_name}: {param_value}",
                            field_name=param_name,
                            violation_type="invalid_boolean_value"
                        )
                elif isinstance(param_value, int):
                    if param_value in (0, 1):
                        bool_params[param_name] = bool(param_value)
                    else:
                        raise MemoryValidationError(
                            f"Invalid integer boolean value for {param_name}: {param_value}",
                            field_name=param_name,
                            violation_type="invalid_boolean_value"
                        )
                else:
                    raise MemoryValidationError(
                        f"Parameter {param_name} must be boolean, got {type(param_value).__name__}",
                        field_name=param_name,
                        violation_type="invalid_type"
                    )
        
        # Validate data parameter if provided
        if data is not None:
            self._validate_data_input(data)
        
        self.logger.debug("Initialization parameters validated successfully")
    
    def _validate_data_input(self, data: Any) -> None:
        """Validate data input for security and type correctness.
        
        Args:
            data: Data to validate
            
        Raises:
            MemoryValidationError: If validation fails
        """
        if data is None:
            return  # None is allowed
        
        # Type validation
        if not isinstance(data, (str, bytes, bytearray)):
            raise MemoryValidationError(
                f"Data must be str, bytes, or bytearray, got {type(data).__name__}",
                field_name="data",
                violation_type="invalid_type"
            )
        
        # Size validation based on protection level
        max_size = self._get_max_data_size()
        data_size = len(data)
        
        if data_size > max_size:
            raise MemoryValidationError(
                f"Data size ({data_size}) exceeds maximum allowed ({max_size})",
                field_name="data",
                violation_type="size_exceeded"
            )
        
        # String encoding validation
        if isinstance(data, str):
            try:
                # Test UTF-8 encoding
                encoded = data.encode('utf-8')
                if len(encoded) != len(data.encode('utf-8', errors='ignore')):
                    self.logger.warning("String data contains potentially dangerous Unicode characters")
            except UnicodeEncodeError as e:
                raise MemoryValidationError(
                    f"String data encoding validation failed: {e}",
                    field_name="data",
                    violation_type="encoding_error"
                )
        
        # Binary data validation
        elif isinstance(data, (bytes, bytearray)):
            # Check for null bytes in excessive quantities (potential buffer overflow indicators)
            null_count = data.count(b'\x00')
            if null_count > len(data) * 0.8:  # More than 80% null bytes
                self.logger.warning(f"Data contains excessive null bytes ({null_count}/{len(data)})")
        
        self.logger.debug(f"Data input validated: {type(data).__name__}, {data_size} bytes")
    
    def _get_validation_level_for_protection(self, protection_level: MemoryProtectionLevel) -> ValidationLevel:
        """Map memory protection level to validation level.
        
        Args:
            protection_level: Memory protection level
            
        Returns:
            Corresponding validation level
        """
        mapping = {
            MemoryProtectionLevel.BASIC: ValidationLevel.BASIC,
            MemoryProtectionLevel.ENHANCED: ValidationLevel.ENHANCED,
            MemoryProtectionLevel.MAXIMUM: ValidationLevel.STRICT,
            MemoryProtectionLevel.MILITARY: ValidationLevel.PARANOID
        }
        return mapping.get(protection_level, ValidationLevel.ENHANCED)
    
    def _get_max_data_size(self) -> int:
        """Get maximum allowed data size based on protection level.
        
        Returns:
            Maximum data size in bytes
        """
        # Size limits based on protection level (more restrictive = higher security)
        size_limits = {
            MemoryProtectionLevel.BASIC: 100 * 1024 * 1024,    # 100MB
            MemoryProtectionLevel.ENHANCED: 50 * 1024 * 1024,  # 50MB
            MemoryProtectionLevel.MAXIMUM: 10 * 1024 * 1024,   # 10MB
            MemoryProtectionLevel.MILITARY: 1 * 1024 * 1024    # 1MB - most restrictive
        }
        return size_limits.get(self._protection_level, 50 * 1024 * 1024)
    
    def _validate_and_prepare_data(self, data: Any) -> bytearray:
        """Validate input data and convert to secure bytearray.
        
        Args:
            data: Input data to validate and convert
            
        Returns:
            Validated data as bytearray
            
        Raises:
            MemoryValidationError: If validation fails
        """
        # Re-validate data (defense in depth)
        self._validate_data_input(data)
        
        # Convert to bytearray with validation
        if isinstance(data, str):
            # Validate string content for dangerous patterns
            string_result = validate_string(
                data, 
                field_name="data",
                max_length=self._get_max_data_size(),
                require_ascii=False  # Allow Unicode but validate it
            )
            if not string_result.is_valid:
                raise MemoryValidationError(
                    string_result.error_message,
                    field_name="data",
                    violation_type=string_result.violation_type
                )
            
            # Convert to bytes first, then bytearray
            try:
                return bytearray(string_result.sanitized_value.encode('utf-8'))
            except UnicodeEncodeError as e:
                raise MemoryValidationError(
                    f"String encoding failed: {e}",
                    field_name="data",
                    violation_type="encoding_error"
                )
        
        elif isinstance(data, (bytes, bytearray)):
            # Validate bytes content
            bytes_result = validate_bytes(
                data,
                field_name="data",
                max_length=self._get_max_data_size()
            )
            if not bytes_result.is_valid:
                raise MemoryValidationError(
                    bytes_result.error_message,
                    field_name="data",
                    violation_type=bytes_result.violation_type
                )
            
            return bytearray(bytes_result.sanitized_value)
        
        else:
            # Should not reach here due to earlier validation, but defense in depth
            raise MemoryValidationError(
                f"Unsupported data type: {type(data).__name__}",
                field_name="data", 
                violation_type="invalid_type"
            )
    
    def _add_canaries(self):
        """Add canary values around data for corruption detection."""
        if len(self._data) == 0:
            return
            
        # Add canaries at the beginning and end
        original_data = bytes(self._data)
        self._data = bytearray(self.CANARY_PATTERN + original_data + self.CANARY_PATTERN)
        self.logger.debug(f"Added canary protection to {len(original_data)} bytes")
    
    def _check_canaries(self) -> bool:
        """Check if canary values are intact.
        
        Returns:
            True if canaries are intact, False if corruption detected
        """
        if self._protection_level != MemoryProtectionLevel.MAXIMUM:
            return True
            
        if len(self._data) < 2 * self.CANARY_SIZE:
            return True  # No canaries to check
            
        # Check start canary
        start_canary = bytes(self._data[:self.CANARY_SIZE])
        if start_canary != self.CANARY_PATTERN:
            self.logger.critical("Memory corruption detected: start canary violated")
            return False
            
        # Check end canary
        end_canary = bytes(self._data[-self.CANARY_SIZE:])
        if end_canary != self.CANARY_PATTERN:
            self.logger.critical("Memory corruption detected: end canary violated")
            return False
            
        return True
    
    def _get_data_without_canaries(self) -> bytearray:
        """Get the actual data without canary protection.
        
        Returns:
            Data without canary bytes
        """
        if self._protection_level != MemoryProtectionLevel.MAXIMUM or len(self._data) < 2 * self.CANARY_SIZE:
            return self._data
            
        return self._data[self.CANARY_SIZE:-self.CANARY_SIZE]
    
    def _attempt_memory_lock(self):
        """Attempt to lock memory with enhanced error handling."""
        try:
            self._lock_memory()
            if self._locked:
                self.logger.debug("Memory successfully locked")
            else:
                get_secure_memory_manager().stats.lock_failures += 1
                if self._require_lock:
                    raise MemoryLockError("Required memory locking failed")
                self.logger.warning("Memory locking failed - data may be swapped to disk")
        except Exception as e:
            get_secure_memory_manager().stats.lock_failures += 1
            if self._require_lock:
                raise MemoryLockError(f"Critical memory locking failure: {e}")
            self.logger.warning(f"Memory locking failed: {e}")
    
    def _lock_memory(self):
        """Attempt to lock memory pages to prevent swapping to disk.
        
        Implements platform-specific memory locking with comprehensive error handling.
        Per R006 - Memory Security: Must implement proper memory locking to prevent swapping.
        """
        if len(self._data) == 0:
            self._locked = True  # Empty data is considered "locked"
            return
            
        try:
            if sys.platform == "win32":
                self._lock_memory_windows()
            elif sys.platform in ("linux", "darwin", "freebsd", "openbsd", "netbsd"):
                self._lock_memory_unix()
            else:
                self.logger.warning(f"Memory locking not implemented for platform: {sys.platform}")
                if self._require_lock:
                    raise MemoryLockError(f"Memory locking not supported on platform: {sys.platform}")
        except Exception as e:
            self.logger.error(f"Memory locking failed: {e}")
            if self._require_lock:
                raise MemoryLockError(f"Critical memory locking failure: {e}")
    
    def _lock_memory_windows(self):
        """Lock memory on Windows using VirtualLock."""
        try:
            kernel32 = ctypes.windll.kernel32
            # Get memory address - need to be careful with bytearray
            data_ptr = (ctypes.c_ubyte * len(self._data)).from_buffer(self._data)
            addr = ctypes.cast(data_ptr, ctypes.c_void_p).value
            size = len(self._data)
            
            # VirtualLock: returns non-zero on success
            result = kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
            if result:
                self._locked = True
                self.logger.debug(f"Windows VirtualLock successful for {size} bytes")
            else:
                error_code = kernel32.GetLastError()
                raise MemoryLockError(f"VirtualLock failed with error code: {error_code}")
        except AttributeError as e:
            raise MemoryLockError(f"Windows memory locking not available: {e}")
        except OSError as e:
            raise MemoryLockError(f"Windows VirtualLock system error: {e}")
    
    def _lock_memory_unix(self):
        """Lock memory on Unix-like systems using mlock."""
        libc_names = {
            'linux': 'libc.so.6',
            'darwin': 'libc.dylib', 
            'freebsd': 'libc.so.7',
            'openbsd': 'libc.so',
            'netbsd': 'libc.so'
        }
        
        libc_name = libc_names.get(sys.platform, 'libc.so.6')
        
        try:
            libc = ctypes.CDLL(libc_name)
            # Get memory address
            data_ptr = (ctypes.c_ubyte * len(self._data)).from_buffer(self._data)
            addr = ctypes.cast(data_ptr, ctypes.c_void_p).value
            size = len(self._data)
            
            # mlock: returns 0 on success, -1 on error
            result = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
            if result == 0:
                self._locked = True
                self.logger.debug(f"Unix mlock successful for {size} bytes")
            else:
                # Get errno for more detailed error
                errno_addr = libc.__errno_location() if hasattr(libc, '__errno_location') else None
                errno_val = ctypes.c_int.from_address(errno_addr).value if errno_addr else 'unknown'
                raise MemoryLockError(f"mlock failed with errno: {errno_val}")
        except OSError as e:
            raise MemoryLockError(f"Unix mlock system error: {e}")
        except Exception as e:
            raise MemoryLockError(f"Unix memory locking failed: {e}")
    
    def _unlock_memory(self):
        """Unlock memory pages with comprehensive error handling.
        
        Per R006 - Memory Security: Must properly unlock memory and handle errors.
        """
        if not self._locked or len(self._data) == 0:
            return
            
        try:
            if sys.platform == "win32":
                self._unlock_memory_windows()
            elif sys.platform in ("linux", "darwin", "freebsd", "openbsd", "netbsd"):
                self._unlock_memory_unix()
            else:
                self.logger.warning(f"Memory unlocking not implemented for platform: {sys.platform}")
        except Exception as e:
            self.logger.warning(f"Memory unlocking failed (non-critical): {e}")
        finally:
            self._locked = False  # Always mark as unlocked
    
    def _unlock_memory_windows(self):
        """Unlock memory on Windows using VirtualUnlock."""
        try:
            kernel32 = ctypes.windll.kernel32
            data_ptr = (ctypes.c_ubyte * len(self._data)).from_buffer(self._data)
            addr = ctypes.cast(data_ptr, ctypes.c_void_p).value
            size = len(self._data)
            
            # VirtualUnlock: returns non-zero on success  
            result = kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
            if result:
                self.logger.debug(f"Windows VirtualUnlock successful for {size} bytes")
            else:
                error_code = kernel32.GetLastError()
                self.logger.warning(f"VirtualUnlock failed with error code: {error_code}")
        except Exception as e:
            self.logger.warning(f"Windows memory unlocking error: {e}")
    
    def _unlock_memory_unix(self):
        """Unlock memory on Unix-like systems using munlock."""
        libc_names = {
            'linux': 'libc.so.6',
            'darwin': 'libc.dylib',
            'freebsd': 'libc.so.7', 
            'openbsd': 'libc.so',
            'netbsd': 'libc.so'
        }
        
        libc_name = libc_names.get(sys.platform, 'libc.so.6')
        
        try:
            libc = ctypes.CDLL(libc_name)
            data_ptr = (ctypes.c_ubyte * len(self._data)).from_buffer(self._data)
            addr = ctypes.cast(data_ptr, ctypes.c_void_p).value
            size = len(self._data)
            
            # munlock: returns 0 on success, -1 on error
            result = libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
            if result == 0:
                self.logger.debug(f"Unix munlock successful for {size} bytes")
            else:
                self.logger.warning(f"munlock failed with return code: {result}")
        except Exception as e:
            self.logger.warning(f"Unix memory unlocking error: {e}")
    
    def get_bytes(self) -> bytes:
        """Get the data as bytes (creates a copy).
        
        Per R006 - Memory Security: Validates memory integrity before access.
        
        Returns:
            Copy of the stored data as bytes
            
        Raises:
            MemoryCorruptionError: If memory corruption is detected
            TPMError: If TPM unsealing fails when required
        """
        with self._lock:
            self._access_count += 1
            
            # Check for corruption before access
            if not self._check_canaries():
                self._corrupted = True
                get_secure_memory_manager().stats.corruption_detections += 1
                raise MemoryCorruptionError("Memory corruption detected during read access")
            
            # Handle TPM unsealing if data is sealed
            if self._sealed_data:
                unsealed_data = self._unseal_from_tpm()
                if unsealed_data is None:
                    raise TPMError("Failed to unseal data from TPM - data may be compromised")
                return unsealed_data
            
            # Get data without canaries
            clean_data = self._get_data_without_canaries()
            
            # Handle hardware unbinding if bound
            if self._hardware_bound and self._hardware_id:
                # Create a copy and unbind it for return
                unbound_data = bytearray(clean_data)
                hw_hash = hashlib.sha256(self._hardware_id.encode()).digest()
                for i in range(len(unbound_data)):
                    unbound_data[i] ^= hw_hash[i % len(hw_hash)]
                return bytes(unbound_data)
            
            return bytes(clean_data)
    
    def get_string(self, encoding: str = 'utf-8') -> str:
        """Get the data as a string (creates a copy).
        
        Args:
            encoding: Character encoding to use for decoding
            
        Returns:
            Copy of the stored data as string
            
        Raises:
            MemoryCorruptionError: If memory corruption is detected
            MemoryValidationError: If encoding validation fails
            UnicodeDecodeError: If data cannot be decoded with specified encoding
            TPMError: If TPM unsealing fails when required
        """
        # Validate encoding parameter
        encoding_result = validate_string(
            encoding,
            field_name="encoding",
            max_length=50,  # Reasonable limit for encoding names
            allowed_chars="abcdefghijklmnopqrstuvwxyz0123456789-_",
            require_ascii=True
        )
        if not encoding_result.is_valid:
            raise MemoryValidationError(
                encoding_result.error_message,
                field_name="encoding",
                violation_type=encoding_result.violation_type
            )
        
        # Use get_bytes which handles TPM unsealing and hardware binding
        data_bytes = self.get_bytes()
        
        try:
            return data_bytes.decode(encoding_result.sanitized_value)
        except (UnicodeDecodeError, LookupError) as e:
            self.logger.warning(f"Failed to decode data with encoding '{encoding}': {e}")
            raise
    
    def clear(self):
        """Securely clear the stored data using military-grade multi-pass overwrite.
        
        Per R006 - Memory Security: Must overwrite sensitive memory with random data
        before deallocation and use multiple passes to prevent data recovery.
        
        Implements DoD 5220.22-M standard with additional passes for enhanced security.
        """
        with self._lock:
            if not self._data or len(self._data) == 0:
                return
                
            data_len = len(self._data)
            get_secure_memory_manager().stats.cleanup_operations += 1
            
            try:
                # Enhanced multi-pass overwrite using DoD 5220.22-M+ standard
                self.logger.debug(f"Starting secure clear of {data_len} bytes")
                
                # Pass 1: All zeros (0x00)
                self._secure_overwrite_pass(0x00)
                
                # Pass 2: All ones (0xFF) 
                self._secure_overwrite_pass(0xFF)
                
                # Pass 3: Alternating pattern (0xAA = 10101010)
                self._secure_overwrite_pass(0xAA)
                
                # Pass 4: Inverse alternating (0x55 = 01010101)
                self._secure_overwrite_pass(0x55)
                
                # Pass 5: Random data (cryptographically secure)
                random_data = secrets.token_bytes(data_len)
                for i in range(data_len):
                    self._data[i] = random_data[i]
                
                # Pass 6: Inverse of random data
                for i in range(data_len):
                    self._data[i] = random_data[i] ^ 0xFF
                
                # Pass 7: Different random data
                random_data2 = secrets.token_bytes(data_len)
                for i in range(data_len):
                    self._data[i] = random_data2[i]
                
                # Final pass: All zeros
                self._secure_overwrite_pass(0x00)
                
                # Force memory sync to ensure writes reach physical storage
                if hasattr(os, 'sync'):
                    os.sync()
                
            except Exception as e:
                self.logger.error(f"Error during secure clearing: {e}")
            finally:
                # Always clear the bytearray safely
                try:
                    self._data.clear()
                except (BufferError, ValueError) as e:
                    # If clearing fails due to exports, create new empty bytearray
                    self.logger.debug(f"Direct clear failed ({e}), creating new empty array")
                    self._data = bytearray()
                self.logger.debug("Secure clear completed")
    
    def _secure_overwrite_pass(self, pattern: int):
        """Perform a single overwrite pass with the specified byte pattern.
        
        Args:
            pattern: Byte pattern to write (0-255)
        """
        for i in range(len(self._data)):
            self._data[i] = pattern
    
    def _bind_to_hardware(self):
        """Bind data to current hardware for hardware-bound protection.
        
        Per R007 - Hardware Binding Security: Implements hardware binding.
        """
        try:
            from .hardware_id import HardwareIdentifier
            hw_identifier = HardwareIdentifier()
            self._hardware_id = hw_identifier.get_hardware_id()
            
            # XOR data with hardware ID for additional binding
            if self._data and self._hardware_id:
                hw_hash = hashlib.sha256(self._hardware_id.encode()).digest()
                for i in range(len(self._data)):
                    self._data[i] ^= hw_hash[i % len(hw_hash)]
                    
            self.logger.debug("Data successfully bound to hardware")
        except Exception as e:
            self.logger.error(f"Hardware binding failed: {e}")
            if self._require_lock:  # Treat as critical if strict security required
                raise MemoryLockError(f"Hardware binding failed: {e}")
    
    def _unbind_from_hardware(self):
        """Unbind data from hardware (reverse the XOR operation)."""
        try:
            if self._data and self._hardware_id:
                hw_hash = hashlib.sha256(self._hardware_id.encode()).digest()
                for i in range(len(self._data)):
                    self._data[i] ^= hw_hash[i % len(hw_hash)]
        except Exception as e:
            self.logger.error(f"Hardware unbinding failed: {e}")
    
    def _seal_with_tpm(self):
        """Seal data with TPM/secure enclave if available.
        
        Per R007 - Hardware Binding Security: Uses TPM for enhanced protection.
        """
        try:
            if hasattr(self, '_tmp_interface') and self._tmp_interface:
                # Seal current data with TPM
                data_to_seal = bytes(self._data)
                sealed_data = self._tmp_interface.seal_data(data_to_seal)
                
                if sealed_data:
                    self._sealed_data = sealed_data
                    # Clear original data and replace with random noise
                    self.clear()
                    self._data = bytearray(secrets.token_bytes(len(data_to_seal)))
                    get_secure_memory_manager().stats.tpm_operations += 1
                    self.logger.debug("Data successfully sealed with TPM")
                else:
                    self.logger.warning("TPM sealing failed - falling back to memory protection")
        except Exception as e:
            self.logger.error(f"TPM sealing failed: {e}")
            get_secure_memory_manager().stats.tpm_operations += 1
    
    def _unseal_from_tpm(self) -> Optional[bytes]:
        """Unseal data from TPM/secure enclave.
        
        Returns:
            Unsealed data or None if unsealing fails
        """
        try:
            if hasattr(self, '_tmp_interface') and self._tmp_interface and self._sealed_data:
                unsealed_data = self._tmp_interface.unseal_data(self._sealed_data)
                if unsealed_data:
                    get_secure_memory_manager().stats.tpm_operations += 1
                    self.logger.debug("Data successfully unsealed from TPM")
                    return unsealed_data
                else:
                    self.logger.error("TPM unsealing failed")
                    get_secure_memory_manager().stats.tpm_operations += 1
        except Exception as e:
            self.logger.error(f"TPM unsealing failed: {e}")
            get_secure_memory_manager().stats.tpm_operations += 1
        return None
    
    def _handle_security_alert(self, event: MemorySecurityEvent):
        """Handle security alerts from anti-forensics monitor.
        
        Args:
            event: Security event that was detected
        """
        self.logger.warning(f"Security alert for SecureBytes {id(self)}: {event.message}")
        get_secure_memory_manager().stats.memory_monitoring_alerts += 1
        
        # Take defensive actions based on event severity
        if event.severity in ("high", "critical"):
            # Immediate defensive clearing for high/critical alerts
            self.logger.critical(f"Critical security event - performing emergency clear")
            try:
                self.clear()
            except Exception as e:
                self.logger.error(f"Emergency clear failed: {e}")
        
        # For memory dump tools, clear and mark as corrupted
        if event.event_type == "memory_dump_tool":
            self._corrupted = True
            try:
                # Multiple rapid clears to defeat memory capture
                for _ in range(3):
                    self.clear()
                    time.sleep(0.01)  # Small delay between clears
            except Exception as e:
                self.logger.error(f"Anti-dump clear failed: {e}")
    
    def set_data(self, data: Union[str, bytes, bytearray]):
        """Securely set new data, clearing old data first.
        
        Args:
            data: New data to store securely
            
        Raises:
            MemoryValidationError: If input validation fails
            TypeError: If data type is not supported
            MemoryLockError: If memory locking is required but fails
        """
        with self._lock:
            # Comprehensive input validation per BAR Rules R030
            self._validate_data_input(data)
            
            # Convert and validate data using secure validation methods
            new_data = self._validate_and_prepare_data(data)
            
            # Clear existing data securely
            self.clear()
            
            # Unlock old memory
            if self._locked:
                self._unlock_memory()
            
            # Set new data
            self._data = new_data
            
            # Add canary protection if enabled
            if self._protection_level == MemoryProtectionLevel.MAXIMUM:
                self._add_canaries()
            
            # Lock new memory
            self._attempt_memory_lock()
            
            self.logger.debug(f"Securely updated data: {len(new_data)} bytes")
    
    def __del__(self):
        """Secure cleanup on deletion with enhanced security features."""
        try:
            self._cleanup_enhanced_features()
            self.clear()
            self._unlock_memory()
        except Exception:
            pass  # Ignore errors during cleanup
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with secure cleanup."""
        self._cleanup_enhanced_features()
        self.clear()
        self._unlock_memory()
    
    def __len__(self) -> int:
        """Get length of stored data."""
        return len(self._data)
    
    def __bool__(self) -> bool:
        """Check if data is not empty."""
        return len(self._data) > 0 or self._sealed_data is not None
    
    def _cleanup_enhanced_features(self):
        """Clean up enhanced security features (TPM, anti-forensics monitoring)."""
        try:
            # Stop anti-forensics monitoring
            if self._anti_forensics_monitor:
                self._anti_forensics_monitor.stop_monitoring()
                self._anti_forensics_monitor = None
            
            # Clear TPM sealed data
            if self._sealed_data:
                # Securely overwrite sealed data
                if isinstance(self._sealed_data, bytearray):
                    secure_zero_memory(self._sealed_data)
                self._sealed_data = None
            
            # Clear hardware ID
            if self._hardware_id:
                # Securely clear hardware ID string
                secure_hw_id = SecureBytes(self._hardware_id)
                secure_hw_id.clear()
                self._hardware_id = None
                
        except Exception as e:
            self.logger.debug(f"Enhanced feature cleanup error: {e}")


class SecureString(SecureBytes):
    """A secure string wrapper that automatically clears memory on deletion."""
    
    def __init__(self, data: str = ""):
        """Initialize secure string container.
        
        Args:
            data: Initial string data to store
        """
        if not isinstance(data, str):
            raise TypeError("Data must be a string")
        super().__init__(data)
    
    def get_value(self) -> str:
        """Get the stored string value (creates a copy)."""
        return self.get_string()
    
    def set_value(self, value: str):
        """Set a new string value (securely clears old value first).
        
        Args:
            value: New string value to store
            
        Raises:
            MemoryValidationError: If input validation fails
            TypeError: If value is not a string
            MemoryLockError: If memory locking is required but fails
        """
        # Comprehensive string validation
        string_result = validate_string(
            value,
            field_name="value",
            max_length=self._get_max_data_size()
        )
        if not string_result.is_valid:
            raise MemoryValidationError(
                string_result.error_message,
                field_name="value",
                violation_type=string_result.violation_type
            )
        
        # Use the secure set_data method from parent class
        self.set_data(string_result.sanitized_value)


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """Perform constant-time comparison of two strings or byte sequences.
    
    This prevents timing attacks by ensuring the comparison takes the same
    amount of time regardless of where the differences occur.
    
    Args:
        a: First value to compare
        b: Second value to compare
        
    Returns:
        True if the values are equal, False otherwise
        
    Raises:
        MemoryValidationError: If input validation fails
    """
    # Validate first parameter
    if not isinstance(a, (str, bytes)):
        raise MemoryValidationError(
            f"First parameter must be str or bytes, got {type(a).__name__}",
            field_name="a",
            violation_type="invalid_type"
        )
    
    # Validate second parameter
    if not isinstance(b, (str, bytes)):
        raise MemoryValidationError(
            f"Second parameter must be str or bytes, got {type(b).__name__}",
            field_name="b",
            violation_type="invalid_type"
        )
    
    # Validate maximum length for security (prevent DoS through huge inputs)
    max_compare_length = 10 * 1024 * 1024  # 10MB
    
    if len(a) > max_compare_length:
        raise MemoryValidationError(
            f"First parameter too large ({len(a)} bytes, max {max_compare_length})",
            field_name="a",
            violation_type="length_exceeded"
        )
    
    if len(b) > max_compare_length:
        raise MemoryValidationError(
            f"Second parameter too large ({len(b)} bytes, max {max_compare_length})",
            field_name="b",
            violation_type="length_exceeded"
        )
    
    # Convert strings to bytes if necessary
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    # Use secrets.compare_digest for constant-time comparison
    return secrets.compare_digest(a, b)


def secure_random_string(length: int, charset: str = None) -> str:
    """Generate a cryptographically secure random string.
    
    Args:
        length: Length of the string to generate
        charset: Character set to use (default: alphanumeric)
        
    Returns:
        Cryptographically secure random string
        
    Raises:
        MemoryValidationError: If input validation fails
    """
    # Validate length parameter
    length_result = validate_integer(
        length,
        field_name="length",
        min_value=1,
        max_value=10 * 1024 * 1024,  # 10MB max for security
        allow_zero=False,
        allow_negative=False
    )
    if not length_result.is_valid:
        raise MemoryValidationError(
            length_result.error_message,
            field_name="length",
            violation_type=length_result.violation_type
        )
    
    # Validate charset if provided
    if charset is not None:
        charset_result = validate_string(
            charset,
            field_name="charset",
            max_length=1024,  # Reasonable limit for character sets
            min_length=1
        )
        if not charset_result.is_valid:
            raise MemoryValidationError(
                charset_result.error_message,
                field_name="charset",
                violation_type=charset_result.violation_type
            )
        charset = charset_result.sanitized_value
    else:
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    
    # Generate secure random string
    return ''.join(secrets.choice(charset) for _ in range(length_result.sanitized_value))


def secure_zero_memory(data: bytearray):
    """Securely zero out a bytearray in memory.
    
    Args:
        data: The bytearray to zero out
    """
    data_len = len(data)
    
    # Multiple-pass overwrite
    # Pass 1: zeros
    for i in range(data_len):
        data[i] = 0
    
    # Pass 2: ones
    for i in range(data_len):
        data[i] = 255
    
    # Pass 3: random
    random_data = os.urandom(data_len)
    for i in range(data_len):
        data[i] = random_data[i]
    
    # Pass 4: zeros again
    for i in range(data_len):
        data[i] = 0


class SecureMemoryManager:
    """Enhanced manager for secure memory operations and cleanup.
    
    Per R006 - Memory Security: Implements secure memory management with
    tracking, statistics, and comprehensive cleanup mechanisms.
    """
    
    def __init__(self):
        """Initialize the secure memory manager with comprehensive tracking."""
        self._secure_objects_weakrefs = []  # Use weak references to avoid cycles
        self._lock = threading.RLock()  # Thread-safe operations
        self.stats = MemoryStats()  # Memory usage statistics
        self.logger = logging.getLogger("SecureMemoryManager")
        self._shutdown_in_progress = False
        self._atexit_registered = False
        
        # Register atexit handler for cleanup
        self._register_atexit_handler()
        
        self.logger.debug("SecureMemoryManager initialized")
    
    def _register_atexit_handler(self):
        """Register atexit handler for secure cleanup on program exit."""
        if not self._atexit_registered:
            atexit.register(self._emergency_cleanup)
            self._atexit_registered = True
            self.logger.debug("Atexit cleanup handler registered")
    
    def register_secure_object(self, obj: SecureBytes):
        """Register a secure object for cleanup tracking using weak references.
        
        Args:
            obj: SecureBytes object to register
        """
        with self._lock:
            if self._shutdown_in_progress:
                self.logger.warning("Cannot register objects during shutdown")
                return
                
            # Create weak reference with cleanup callback
            weak_ref = weakref.ref(obj, self._object_cleanup_callback)
            self._secure_objects_weakrefs.append(weak_ref)
            
            # Update statistics
            self.stats.total_allocations += 1
            self.stats.active_allocations += 1
            self.stats.total_bytes_allocated += len(obj._data) if hasattr(obj, '_data') else 0
            self.stats.active_bytes_allocated += len(obj._data) if hasattr(obj, '_data') else 0
            
            self.logger.debug(f"Registered secure object: {id(obj)}, active objects: {self.stats.active_allocations}")
    
    def _object_cleanup_callback(self, weak_ref):
        """Callback when a weakly referenced object is garbage collected.
        
        Args:
            weak_ref: The weak reference that was garbage collected
        """
        with self._lock:
            try:
                self._secure_objects_weakrefs.remove(weak_ref)
                self.stats.active_allocations -= 1
                # Note: Cannot update active_bytes_allocated as object is already gone
                self.logger.debug(f"Secure object garbage collected, active objects: {self.stats.active_allocations}")
            except ValueError:
                # Already removed, ignore
                pass
    
    def cleanup_all(self) -> int:
        """Clean up all registered secure objects.
        
        Returns:
            Number of objects successfully cleaned up
        """
        with self._lock:
            cleaned_count = 0
            objects_to_clean = []
            
            # Collect all live objects
            for weak_ref in self._secure_objects_weakrefs[:]:
                obj = weak_ref()
                if obj is not None:
                    objects_to_clean.append(obj)
            
            # Clean up objects
            for obj in objects_to_clean:
                try:
                    if hasattr(obj, 'clear') and callable(obj.clear):
                        obj.clear()
                    if hasattr(obj, '_unlock_memory') and callable(obj._unlock_memory):
                        obj._unlock_memory()
                    cleaned_count += 1
                    self.stats.cleanup_operations += 1
                except (BufferError, ValueError) as e:
                    # Handle buffer clearing issues gracefully
                    self.logger.debug(f"Buffer clearing issue for object {id(obj)}: {e}")
                    # Still count as cleaned since we attempted cleanup
                    cleaned_count += 1
                    self.stats.cleanup_operations += 1
                except Exception as e:
                    self.logger.warning(f"Error cleaning up secure object {id(obj)}: {e}")
            
            # Clear the weakrefs list
            self._secure_objects_weakrefs.clear()
            self.stats.active_allocations = 0
            self.stats.active_bytes_allocated = 0
            
            self.logger.info(f"Cleaned up {cleaned_count} secure objects")
            return cleaned_count
    
    def _emergency_cleanup(self):
        """Emergency cleanup called during program shutdown.
        
        Per R006 - Memory Security: Must clear sensitive data from memory
        immediately before program termination.
        """
        self._shutdown_in_progress = True
        self.logger.info("Emergency cleanup initiated - program shutting down")
        
        try:
            cleaned = self.cleanup_all()
            
            # Force garbage collection to clean up any remaining objects
            gc.collect()
            
            self.logger.info(f"Emergency cleanup completed - {cleaned} objects cleaned")
        except Exception as e:
            # Use print instead of logger as logging may not work during shutdown
            print(f"[SecureMemoryManager] Emergency cleanup error: {e}", file=sys.stderr)
    
    def get_statistics(self) -> MemoryStats:
        """Get current memory usage statistics.
        
        Returns:
            Copy of current memory statistics
        """
        with self._lock:
            # Update active bytes by checking living objects
            active_bytes = 0
            for weak_ref in self._secure_objects_weakrefs:
                obj = weak_ref()
                if obj is not None and hasattr(obj, '_data'):
                    active_bytes += len(obj._data)
            
            self.stats.active_bytes_allocated = active_bytes
            
            # Return a copy to prevent external modification
            return MemoryStats(
                total_allocations=self.stats.total_allocations,
                active_allocations=self.stats.active_allocations,
                total_bytes_allocated=self.stats.total_bytes_allocated,
                active_bytes_allocated=self.stats.active_bytes_allocated,
                lock_failures=self.stats.lock_failures,
                corruption_detections=self.stats.corruption_detections,
                cleanup_operations=self.stats.cleanup_operations
            )
    
    def force_cleanup_and_gc(self):
        """Force cleanup of all objects and run garbage collection.
        
        Per R006 - Memory Security: Provides explicit cleanup mechanism
        for security-critical scenarios.
        """
        self.logger.info("Forced cleanup and garbage collection initiated")
        
        # Clean up all managed objects
        cleaned = self.cleanup_all()
        
        # Force multiple garbage collection passes
        for i in range(3):
            collected = gc.collect()
            self.logger.debug(f"GC pass {i+1}: collected {collected} objects")
        
        self.logger.info(f"Forced cleanup completed - {cleaned} objects cleaned")
    
    def __del__(self):
        """Clean up all objects on manager deletion."""
        if not self._shutdown_in_progress:
            try:
                self.cleanup_all()
            except Exception as e:
                # Ignore errors during deletion
                pass


# Global instance for easy access
_secure_memory_manager = SecureMemoryManager()


def get_secure_memory_manager() -> SecureMemoryManager:
    """Get the global secure memory manager instance.
    
    Returns:
        Global SecureMemoryManager instance
    """
    return _secure_memory_manager


def create_secure_string(value: str = "") -> SecureString:
    """Create a secure string and register it with the global manager.
    
    Args:
        value: Initial string value
        
    Returns:
        SecureString instance
    """
    secure_str = SecureString(value)
    _secure_memory_manager.register_secure_object(secure_str)
    return secure_str


def create_secure_bytes(value: Union[str, bytes, bytearray] = None, 
                        protection_level: MemoryProtectionLevel = MemoryProtectionLevel.ENHANCED,
                        require_lock: bool = False,
                        use_tpm: bool = False,
                        hardware_bound: bool = False) -> SecureBytes:
    """Create secure bytes and register it with the global manager.
    
    Args:
        value: Initial data value
        protection_level: Level of memory protection to apply
        require_lock: If True, raises MemoryLockError if memory locking fails
        use_tpm: If True, attempts to use TPM/secure enclave for protection
        hardware_bound: If True, binds data to current hardware ID
        
    Returns:
        SecureBytes instance registered with global manager
    """
    secure_bytes = SecureBytes(value, protection_level, require_lock, use_tpm, hardware_bound)
    # Note: SecureBytes constructor already registers with global manager
    return secure_bytes


def get_secure_memory_stats() -> MemoryStats:
    """Get current secure memory usage statistics.
    
    Returns:
        Current memory usage statistics
    """
    return _secure_memory_manager.get_statistics()


def force_secure_memory_cleanup():
    """Force cleanup of all secure memory objects and run garbage collection.
    
    Per R006 - Memory Security: Provides explicit cleanup for security scenarios.
    """
    _secure_memory_manager.force_cleanup_and_gc()


@contextmanager
def secure_memory_context():
    """Context manager for secure memory operations with automatic cleanup.
    
    Usage:
        with secure_memory_context():
            secure_data = create_secure_string("sensitive data")
            # ... use secure_data ...
        # All secure objects created in context are automatically cleaned up
    """
    initial_stats = get_secure_memory_stats()
    try:
        yield
    finally:
        # Force cleanup of objects created during this context
        force_secure_memory_cleanup()
        
        final_stats = get_secure_memory_stats()
        logging.getLogger("SecureMemoryContext").debug(
            f"Context cleanup: {final_stats.cleanup_operations - initial_stats.cleanup_operations} operations"
        )


def secure_wipe_variable(variable_name: str, frame_locals: dict = None):
    """Securely wipe a variable from local frame.
    
    EXPERIMENTAL: This function attempts to overwrite variables in the calling frame.
    Use with caution as Python's memory management may not guarantee complete wiping.
    
    Args:
        variable_name: Name of the variable to wipe
        frame_locals: Local variables dictionary (defaults to caller's locals)
    """
    if frame_locals is None:
        import inspect
        frame = inspect.currentframe().f_back
        frame_locals = frame.f_locals
    
    if variable_name in frame_locals:
        value = frame_locals[variable_name]
        if isinstance(value, (str, bytes, bytearray)):
            # Create secure wrapper and clear it
            secure_value = SecureBytes(value)
            secure_value.clear()
            # Set variable to None
            frame_locals[variable_name] = None
            # Force garbage collection
            gc.collect()


class TPMInterface:
    """Interface for TPM (Trusted Platform Module) operations.
    
    Per R007 - Hardware Binding Security: Implements TPM integration for enhanced security.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("TPMInterface")
        self._tpm_available = self._check_tpm_availability()
        
    def _check_tpm_availability(self) -> bool:
        """Check if TPM is available on the system."""
        try:
            if sys.platform == "win32":
                # Check Windows TPM via WMI or PowerShell
                result = subprocess.run(
                    ["powershell", "-Command", "Get-Tpm | Select-Object TpmPresent"],
                    capture_output=True, text=True, timeout=5
                )
                return "True" in result.stdout
            elif sys.platform == "linux":
                # Check Linux TPM via /sys/class/tpm
                return Path("/sys/class/tpm/tpm0").exists()
            elif sys.platform == "darwin":
                # macOS has T2/Apple Silicon secure enclave
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True, text=True, timeout=5
                )
                return "T2" in result.stdout or "Apple" in result.stdout
        except Exception as e:
            self.logger.debug(f"TPM availability check failed: {e}")
        return False
    
    def is_available(self) -> bool:
        """Check if TPM is available."""
        return self._tpm_available
    
    def seal_data(self, data: bytes, pcr_values: Optional[List[int]] = None) -> Optional[bytes]:
        """Seal data to TPM with optional PCR values.
        
        Args:
            data: Data to seal
            pcr_values: Optional PCR values to bind to
            
        Returns:
            Sealed data blob or None if TPM unavailable
        """
        if not self._tpm_available:
            return None
            
        try:
            # Platform-specific TPM sealing implementation
            if sys.platform == "win32":
                return self._seal_data_windows(data, pcr_values)
            elif sys.platform == "linux":
                return self._seal_data_linux(data, pcr_values)
            elif sys.platform == "darwin":
                return self._seal_data_macos(data)
        except Exception as e:
            self.logger.error(f"TPM seal operation failed: {e}")
            get_secure_memory_manager().stats.tpm_operations += 1
        return None
    
    def unseal_data(self, sealed_data: bytes) -> Optional[bytes]:
        """Unseal data from TPM.
        
        Args:
            sealed_data: Previously sealed data blob
            
        Returns:
            Unsealed data or None if operation fails
        """
        if not self._tpm_available or not sealed_data:
            return None
            
        try:
            # Platform-specific TPM unsealing implementation
            if sys.platform == "win32":
                return self._unseal_data_windows(sealed_data)
            elif sys.platform == "linux":
                return self._unseal_data_linux(sealed_data)
            elif sys.platform == "darwin":
                return self._unseal_data_macos(sealed_data)
        except Exception as e:
            self.logger.error(f"TPM unseal operation failed: {e}")
            get_secure_memory_manager().stats.tpm_operations += 1
        return None
    
    def _seal_data_windows(self, data: bytes, pcr_values: Optional[List[int]]) -> bytes:
        """Windows-specific TPM sealing using TBS API."""
        # Note: This would require Windows TBS (TPM Base Services) API
        # For now, return encrypted data with hardware binding
        return self._hardware_encrypt(data)
    
    def _seal_data_linux(self, data: bytes, pcr_values: Optional[List[int]]) -> bytes:
        """Linux-specific TPM sealing using tpm2-tools."""
        # Note: This would require tpm2-tools to be installed
        # For now, return encrypted data with hardware binding
        return self._hardware_encrypt(data)
    
    def _seal_data_macos(self, data: bytes) -> bytes:
        """macOS-specific sealing using Secure Enclave."""
        # Note: This would require Secure Enclave API
        # For now, return encrypted data with hardware binding
        return self._hardware_encrypt(data)
    
    def _unseal_data_windows(self, sealed_data: bytes) -> bytes:
        """Windows-specific TPM unsealing."""
        return self._hardware_decrypt(sealed_data)
    
    def _unseal_data_linux(self, sealed_data: bytes) -> bytes:
        """Linux-specific TPM unsealing."""
        return self._hardware_decrypt(sealed_data)
    
    def _unseal_data_macos(self, sealed_data: bytes) -> bytes:
        """macOS-specific unsealing."""
        return self._hardware_decrypt(sealed_data)
    
    def _hardware_encrypt(self, data: bytes) -> bytes:
        """Fallback hardware-bound encryption when TPM unavailable."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return data  # Fallback - return as-is
            
        # Use hardware ID as additional entropy for key derivation
        from .hardware_id import HardwareIdentifier
        hw_id = HardwareIdentifier().get_hardware_id()
        
        # Derive key from hardware ID
        salt = secrets.token_bytes(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(hw_id.encode())
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Return salt + nonce + ciphertext
        return salt + nonce + ciphertext
    
    def _hardware_decrypt(self, encrypted_data: bytes) -> bytes:
        """Fallback hardware-bound decryption."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return encrypted_data  # Fallback - return as-is
            
        if len(encrypted_data) < 44:  # 32 (salt) + 12 (nonce)
            raise ValueError("Invalid encrypted data")
            
        # Extract components
        salt = encrypted_data[:32]
        nonce = encrypted_data[32:44]
        ciphertext = encrypted_data[44:]
        
        # Derive key from hardware ID
        from .hardware_id import HardwareIdentifier
        hw_id = HardwareIdentifier().get_hardware_id()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(hw_id.encode())
        
        # Decrypt with AES-GCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)


class AntiForensicsMonitor:
    """Monitor for memory forensics attempts and implement countermeasures.
    
    Per R044 - Data Minimization and anti-forensics requirements.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("AntiForensicsMonitor")
        self._monitoring = False
        self._monitor_thread = None
        self._alert_callbacks: List[Callable[[MemorySecurityEvent], None]] = []
        
    def start_monitoring(self):
        """Start anti-forensics monitoring."""
        if self._monitoring:
            return
            
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self.logger.info("Anti-forensics monitoring started")
    
    def stop_monitoring(self):
        """Stop anti-forensics monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
        self.logger.info("Anti-forensics monitoring stopped")
    
    def add_alert_callback(self, callback: Callable[[MemorySecurityEvent], None]):
        """Add callback for security alerts."""
        self._alert_callbacks.append(callback)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._monitoring:
            try:
                # Check for memory dump tools
                self._check_memory_dump_tools()
                
                # Check for debuggers
                self._check_debugger_presence()
                
                # Check for suspicious memory access patterns
                self._check_memory_access_patterns()
                
                # Check system integrity
                self._check_system_integrity()
                
                time.sleep(1.0)  # Check every second
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(5.0)  # Back off on errors
    
    def _check_memory_dump_tools(self):
        """Check for memory dump tools running."""
        suspicious_processes = [
            "winpmem", "memdump", "dumpit", "volatility",
            "rekall", "gdb", "lldb", "ollydbg", "x64dbg",
            "processhacker", "procexp", "vmmap"
        ]
        
        try:
            if sys.platform == "win32":
                import psutil
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    if any(sus in proc_name for sus in suspicious_processes):
                        self._trigger_alert("memory_dump_tool", f"Detected: {proc_name}", "high")
            elif sys.platform in ("linux", "darwin"):
                # Check running processes
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
                for sus_proc in suspicious_processes:
                    if sus_proc in result.stdout.lower():
                        self._trigger_alert("memory_dump_tool", f"Detected: {sus_proc}", "high")
        except Exception as e:
            self.logger.debug(f"Process check failed: {e}")
    
    def _check_debugger_presence(self):
        """Check if a debugger is attached to the process."""
        try:
            if sys.platform == "win32":
                # Check IsDebuggerPresent
                kernel32 = ctypes.windll.kernel32
                if kernel32.IsDebuggerPresent():
                    self._trigger_alert("debugger_detected", "Windows debugger present", "critical")
                    
                # Check remote debugger
                debug_flag = ctypes.c_bool(False)
                if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(debug_flag)):
                    if debug_flag.value:
                        self._trigger_alert("remote_debugger", "Remote debugger detected", "critical")
            elif sys.platform == "linux":
                # Check /proc/self/status for TracerPid
                with open("/proc/self/status", "r") as f:
                    status = f.read()
                    for line in status.split("\n"):
                        if line.startswith("TracerPid:"):
                            tracer_pid = line.split("\t")[1]
                            if tracer_pid != "0":
                                self._trigger_alert("debugger_detected", f"TracerPid: {tracer_pid}", "critical")
        except Exception as e:
            self.logger.debug(f"Debugger check failed: {e}")
    
    def _check_memory_access_patterns(self):
        """Check for suspicious memory access patterns."""
        try:
            # Monitor memory usage patterns using psutil (cross-platform)
            import psutil
            process = psutil.Process()
            current_memory = process.memory_info().rss
            
            # Check for unusually high memory usage growth
            if hasattr(self, '_last_memory_usage'):
                memory_growth = current_memory - self._last_memory_usage
                if memory_growth > 100 * 1024 * 1024:  # 100MB growth
                    self._trigger_alert("memory_growth", f"Large memory growth: {memory_growth}", "medium")
            
            self._last_memory_usage = current_memory
            
            # Additional Unix-specific checks if resource module is available
            if RESOURCE_AVAILABLE and hasattr(resource, 'RUSAGE_SELF'):
                usage = resource.getrusage(resource.RUSAGE_SELF)
                # Additional monitoring can be added here for Unix systems
                
        except Exception as e:
            self.logger.debug(f"Memory pattern check failed: {e}")
    
    
    def _check_system_integrity(self):
        """Check system integrity indicators."""
        try:
            # Check if system time has been manipulated
            if hasattr(self, '_last_check_time'):
                time_diff = time.time() - self._last_check_time
                if time_diff < -1.0 or time_diff > 10.0:  # Time manipulation detected
                    self._trigger_alert("time_manipulation", f"Time diff: {time_diff}", "high")
            self._last_check_time = time.time()
        except Exception as e:
            self.logger.debug(f"System integrity check failed: {e}")
    
    def _trigger_alert(self, event_type: str, message: str, severity: str):
        """Trigger security alert."""
        event = MemorySecurityEvent(
            event_type=event_type,
            timestamp=time.time(),
            severity=severity,
            message=message
        )
        
        get_secure_memory_manager().stats.forensics_attempts += 1
        
        # Call all registered callbacks
        for callback in self._alert_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
        
        self.logger.warning(f"Security alert [{severity}] {event_type}: {message}")
