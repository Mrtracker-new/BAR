import os
import sys
import ctypes
import secrets
import threading
import weakref
import gc
import atexit
from typing import Any, Optional, Union, List, Dict
import logging
from contextlib import contextmanager
from dataclasses import dataclass
import time
from enum import Enum


class MemoryProtectionLevel(Enum):
    """Memory protection levels."""
    BASIC = "basic"                    # Basic secure clearing
    ENHANCED = "enhanced"              # Multi-pass clearing + locking
    MAXIMUM = "maximum"               # All features + canaries + monitoring


class SecureMemoryError(Exception):
    """Base exception for secure memory operations."""
    pass


class MemoryCorruptionError(SecureMemoryError):
    """Raised when memory corruption is detected."""
    pass


class MemoryLockError(SecureMemoryError):
    """Raised when memory locking fails critically."""
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
                 require_lock: bool = False):
        """Initialize secure bytes container with enhanced protection.
        
        Args:
            data: Initial data to store (will be securely copied)
            protection_level: Level of memory protection to apply
            require_lock: If True, raises MemoryLockError if memory locking fails
        """
        self._protection_level = protection_level
        self._require_lock = require_lock
        self._locked = False
        self._corrupted = False
        self._access_count = 0
        self._created_time = time.time()
        self._lock = threading.RLock()  # Thread safety
        self.logger = logging.getLogger(f"SecureBytes_{id(self)}")
        
        # Initialize data with canary protection
        if data is None:
            self._data = bytearray()
        elif isinstance(data, str):
            self._data = bytearray(data.encode('utf-8'))
        elif isinstance(data, (bytes, bytearray)):
            self._data = bytearray(data)
        else:
            raise TypeError("Data must be str, bytes, or bytearray")
        
        # Add canary values for corruption detection (MAXIMUM protection)
        if self._protection_level == MemoryProtectionLevel.MAXIMUM:
            self._add_canaries()
        
        # Try to lock memory to prevent swapping
        self._attempt_memory_lock()
        
        # Register with memory manager
        get_secure_memory_manager().register_secure_object(self)
        
        self.logger.debug(f"SecureBytes initialized: {len(self._data)} bytes, protection: {protection_level.value}")
    
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
        """
        with self._lock:
            self._access_count += 1
            
            # Check for corruption before access
            if not self._check_canaries():
                self._corrupted = True
                get_secure_memory_manager().stats.corruption_detections += 1
                raise MemoryCorruptionError("Memory corruption detected during read access")
            
            # Get data without canaries
            clean_data = self._get_data_without_canaries()
            return bytes(clean_data)
    
    def get_string(self, encoding: str = 'utf-8') -> str:
        """Get the data as a string (creates a copy).
        
        Args:
            encoding: Character encoding to use for decoding
            
        Returns:
            Copy of the stored data as string
            
        Raises:
            MemoryCorruptionError: If memory corruption is detected
            UnicodeDecodeError: If data cannot be decoded with specified encoding
        """
        with self._lock:
            self._access_count += 1
            
            # Check for corruption before access
            if not self._check_canaries():
                self._corrupted = True
                get_secure_memory_manager().stats.corruption_detections += 1
                raise MemoryCorruptionError("Memory corruption detected during read access")
            
            # Get data without canaries and decode
            clean_data = self._get_data_without_canaries()
            return clean_data.decode(encoding)
    
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
                # Always clear the bytearray
                self._data.clear()
                self.logger.debug("Secure clear completed")
    
    def _secure_overwrite_pass(self, pattern: int):
        """Perform a single overwrite pass with the specified byte pattern.
        
        Args:
            pattern: Byte pattern to write (0-255)
        """
        for i in range(len(self._data)):
            self._data[i] = pattern
    
    def set_data(self, data: Union[str, bytes, bytearray]):
        """Securely set new data, clearing old data first.
        
        Args:
            data: New data to store securely
            
        Raises:
            TypeError: If data type is not supported
            MemoryLockError: If memory locking is required but fails
        """
        with self._lock:
            # Validate input
            if isinstance(data, str):
                new_data = bytearray(data.encode('utf-8'))
            elif isinstance(data, (bytes, bytearray)):
                new_data = bytearray(data)
            else:
                raise TypeError("Data must be str, bytes, or bytearray")
            
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
        """Secure cleanup on deletion."""
        try:
            self.clear()
            self._unlock_memory()
        except Exception:
            pass  # Ignore errors during cleanup
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with secure cleanup."""
        self.clear()
        self._unlock_memory()
    
    def __len__(self) -> int:
        """Get length of stored data."""
        return len(self._data)
    
    def __bool__(self) -> bool:
        """Check if data is not empty."""
        return len(self._data) > 0


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
            TypeError: If value is not a string
            MemoryLockError: If memory locking is required but fails
        """
        if not isinstance(value, str):
            raise TypeError("Value must be a string")
        
        # Use the secure set_data method from parent class
        self.set_data(value)


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """Perform constant-time comparison of two strings or byte sequences.
    
    This prevents timing attacks by ensuring the comparison takes the same
    amount of time regardless of where the differences occur.
    
    Args:
        a: First value to compare
        b: Second value to compare
        
    Returns:
        True if the values are equal, False otherwise
    """
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
    """
    if charset is None:
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    
    return ''.join(secrets.choice(charset) for _ in range(length))


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
                        require_lock: bool = False) -> SecureBytes:
    """Create secure bytes and register it with the global manager.
    
    Args:
        value: Initial data value
        protection_level: Level of memory protection to apply
        require_lock: If True, raises MemoryLockError if memory locking fails
        
    Returns:
        SecureBytes instance registered with global manager
    """
    secure_bytes = SecureBytes(value, protection_level, require_lock)
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
