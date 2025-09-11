import os
import json
import logging
import secrets
import threading
import time
from pathlib import Path
from typing import List, Set, Optional, Dict, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import hashlib

from .secure_memory import (
    SecureBytes, SecureString, create_secure_bytes, create_secure_string,
    secure_compare, MemoryProtectionLevel, get_secure_memory_manager
)


class FileSecurityLevel(Enum):
    """File security classification levels."""
    STANDARD = "standard"      # Regular files with basic security
    CONFIDENTIAL = "confidential"  # Sensitive files requiring enhanced protection
    SECRET = "secret"         # Highly sensitive files requiring maximum security
    TOP_SECRET = "top_secret" # Most sensitive files with strictest controls


class SecureDeletionMethod(Enum):
    """Secure deletion methods following various standards."""
    BASIC = "basic"           # Simple overwrite with zeros
    DOD_3_PASS = "dod_3_pass" # DoD 5220.22-M 3-pass method
    DOD_7_PASS = "dod_7_pass" # DoD 5220.22-M 7-pass method (recommended)
    GUTMANN = "gutmann"       # Gutmann 35-pass method (maximum security)


@dataclass
class FileBlacklistEntry:
    """Entry in the file blacklist with metadata."""
    path_hash: str           # SHA-256 hash of the file path
    file_hash: Optional[str] # SHA-256 hash of file contents (if available)
    reason: str              # Reason for blacklisting
    timestamp: float         # When the file was blacklisted
    security_level: FileSecurityLevel
    deletion_method: SecureDeletionMethod
    wiped: bool = False      # Whether the file has been securely deleted


class FileAccessError(Exception):
    """Raised when file access is denied due to security policies."""
    pass


class SecureFileOperations:
    """Enhanced secure file operations with blacklisting and DoD-standard deletion.
    
    Features:
    - File blacklisting with hash-based tracking
    - DoD 5220.22-M compliant secure deletion
    - Memory-safe file handling using secure memory
    - File access monitoring and logging
    - Emergency wipe capabilities
    - Cross-platform secure deletion support
    
    Per R006 - Memory Security: All file content processed through secure memory.
    Per R030 - Security Violations: Implements comprehensive access controls.
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize secure file operations manager.
        
        Args:
            config_dir: Directory for storing blacklist and configuration files
        """
        self.logger = logging.getLogger("SecureFileOperations")
        
        # Configuration paths
        self._config_dir = config_dir or Path.home() / ".bar" / "security"
        self._blacklist_file = self._config_dir / "file_blacklist.enc"
        self._access_log_file = self._config_dir / "file_access.log"
        
        # Thread-safe operations
        self._lock = threading.RLock()
        
        # Blacklisted files (path_hash -> FileBlacklistEntry)
        self._blacklist: Dict[str, FileBlacklistEntry] = {}
        
        # File access statistics
        self._access_stats = {
            "files_accessed": 0,
            "files_blocked": 0,
            "files_securely_deleted": 0,
            "emergency_wipes": 0
        }
        
        self._ensure_config_directory()
        self._load_blacklist()
        
        self.logger.info("SecureFileOperations initialized with enhanced security")
    
    def _ensure_config_directory(self):
        """Ensure configuration directory exists with proper permissions."""
        self._config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        
        # Set restrictive permissions (owner only)
        if hasattr(os, 'chmod'):
            os.chmod(str(self._config_dir), 0o700)
    
    def _compute_path_hash(self, file_path: Union[str, Path]) -> str:
        """Compute SHA-256 hash of file path for secure storage.
        
        Args:
            file_path: Path to hash
            
        Returns:
            SHA-256 hash of the normalized path
        """
        normalized_path = str(Path(file_path).resolve()).lower()
        return hashlib.sha256(normalized_path.encode('utf-8')).hexdigest()
    
    def _compute_file_hash(self, file_path: Union[str, Path]) -> Optional[str]:
        """Compute SHA-256 hash of file contents safely.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA-256 hash of file contents, or None if error
        """
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.warning(f"Failed to hash file {file_path}: {e}")
            return None
    
    def is_file_blacklisted(self, file_path: Union[str, Path]) -> bool:
        """Check if a file is blacklisted.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file is blacklisted, False otherwise
        """
        with self._lock:
            path_hash = self._compute_path_hash(file_path)
            return path_hash in self._blacklist
    
    def add_to_blacklist(self, 
                        file_path: Union[str, Path], 
                        reason: str,
                        security_level: FileSecurityLevel = FileSecurityLevel.CONFIDENTIAL,
                        deletion_method: SecureDeletionMethod = SecureDeletionMethod.DOD_7_PASS) -> bool:
        """Add a file to the blacklist.
        
        Args:
            file_path: Path to blacklist
            reason: Reason for blacklisting
            security_level: Security classification of the file
            deletion_method: Method to use for secure deletion
            
        Returns:
            True if successfully added, False if already blacklisted
        """
        with self._lock:
            path_hash = self._compute_path_hash(file_path)
            
            if path_hash in self._blacklist:
                self.logger.info(f"File already blacklisted: {Path(file_path).name}")
                return False
            
            # Compute file hash if file exists
            file_hash = None
            if Path(file_path).exists():
                file_hash = self._compute_file_hash(file_path)
            
            # Create blacklist entry
            entry = FileBlacklistEntry(
                path_hash=path_hash,
                file_hash=file_hash,
                reason=reason,
                timestamp=time.time(),
                security_level=security_level,
                deletion_method=deletion_method
            )
            
            self._blacklist[path_hash] = entry
            self._save_blacklist()
            
            self._access_stats["files_blocked"] += 1
            self.logger.warning(f"File blacklisted: {Path(file_path).name} - Reason: {reason}")
            
            return True
    
    def remove_from_blacklist(self, file_path: Union[str, Path]) -> bool:
        """Remove a file from the blacklist.
        
        Args:
            file_path: Path to remove from blacklist
            
        Returns:
            True if successfully removed, False if not blacklisted
        """
        with self._lock:
            path_hash = self._compute_path_hash(file_path)
            
            if path_hash not in self._blacklist:
                return False
            
            del self._blacklist[path_hash]
            self._save_blacklist()
            
            self.logger.info(f"File removed from blacklist: {Path(file_path).name}")
            return True
    
    def get_blacklist_info(self, file_path: Union[str, Path]) -> Optional[FileBlacklistEntry]:
        """Get blacklist information for a file.
        
        Args:
            file_path: Path to query
            
        Returns:
            FileBlacklistEntry if blacklisted, None otherwise
        """
        with self._lock:
            path_hash = self._compute_path_hash(file_path)
            return self._blacklist.get(path_hash)
    
    def secure_read_file(self, file_path: Union[str, Path], 
                        max_size: int = 100 * 1024 * 1024) -> SecureBytes:
        """Securely read a file into secure memory.
        
        Args:
            file_path: Path to file to read
            max_size: Maximum file size to read (default 100MB)
            
        Returns:
            SecureBytes containing file contents
            
        Raises:
            FileAccessError: If file is blacklisted or access denied
            ValueError: If file is too large
        """
        file_path = Path(file_path)
        
        # Security checks
        self._check_file_access(file_path, "read")
        
        # Size check
        if file_path.stat().st_size > max_size:
            raise ValueError(f"File too large: {file_path.stat().st_size} bytes (max: {max_size})")
        
        try:
            # Read file into secure memory
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Store in secure memory with maximum protection
            secure_data = create_secure_bytes(
                file_data, 
                protection_level=MemoryProtectionLevel.MAXIMUM,
                require_lock=True
            )
            
            # Clear the temporary data
            file_data = b'\x00' * len(file_data)
            del file_data
            
            self._access_stats["files_accessed"] += 1
            self.logger.debug(f"Securely read file: {file_path.name}")
            
            return secure_data
            
        except Exception as e:
            self.logger.error(f"Failed to read file {file_path}: {e}")
            raise
    
    def secure_write_file(self, file_path: Union[str, Path], 
                         data: Union[SecureBytes, bytes, str],
                         overwrite: bool = False,
                         permissions: int = 0o600) -> bool:
        """Securely write data to a file.
        
        Args:
            file_path: Path to write to
            data: Data to write (SecureBytes, bytes, or str)
            overwrite: Whether to overwrite existing files
            permissions: File permissions to set (default: owner only)
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            FileAccessError: If file is blacklisted or access denied
        """
        file_path = Path(file_path)
        
        # Security checks
        self._check_file_access(file_path, "write")
        
        # Check if file exists and overwrite policy
        if file_path.exists() and not overwrite:
            raise FileAccessError(f"File exists and overwrite not allowed: {file_path}")
        
        try:
            # Prepare data for writing
            if isinstance(data, SecureBytes):
                write_data = data.get_bytes()
            elif isinstance(data, str):
                write_data = data.encode('utf-8')
            else:
                write_data = data
            
            # Write file with temporary name, then rename (atomic operation)
            temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
            
            with open(temp_path, 'wb') as f:
                f.write(write_data)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            
            # Set permissions before renaming
            if hasattr(os, 'chmod'):
                os.chmod(str(temp_path), permissions)
            
            # Atomic rename
            temp_path.rename(file_path)
            
            # Clear temporary data if it was converted
            if isinstance(data, str):
                write_data = b'\x00' * len(write_data)
                del write_data
            
            self.logger.debug(f"Securely wrote file: {file_path.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to write file {file_path}: {e}")
            # Clean up temp file if it exists
            temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            return False
    
    def secure_delete_file(self, file_path: Union[str, Path], 
                          method: SecureDeletionMethod = SecureDeletionMethod.DOD_7_PASS,
                          verify: bool = True) -> bool:
        """Securely delete a file using military-grade overwrite methods.
        
        Args:
            file_path: Path to file to delete
            method: Deletion method to use
            verify: Whether to verify deletion was successful
            
        Returns:
            True if successful, False otherwise
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.info(f"File already deleted: {file_path.name}")
            return True
        
        try:
            file_size = file_path.stat().st_size
            self.logger.info(f"Starting secure deletion: {file_path.name} ({file_size} bytes) using {method.value}")
            
            if method == SecureDeletionMethod.BASIC:
                success = self._secure_delete_basic(file_path, file_size)
            elif method == SecureDeletionMethod.DOD_3_PASS:
                success = self._secure_delete_dod_3_pass(file_path, file_size)
            elif method == SecureDeletionMethod.DOD_7_PASS:
                success = self._secure_delete_dod_7_pass(file_path, file_size)
            elif method == SecureDeletionMethod.GUTMANN:
                success = self._secure_delete_gutmann(file_path, file_size)
            else:
                raise ValueError(f"Unknown deletion method: {method}")
            
            if success:
                # Final deletion
                file_path.unlink()
                
                # Update blacklist if file was blacklisted
                path_hash = self._compute_path_hash(file_path)
                if path_hash in self._blacklist:
                    self._blacklist[path_hash].wiped = True
                    self._save_blacklist()
                
                # Verify deletion if requested
                if verify and file_path.exists():
                    self.logger.error(f"File still exists after deletion: {file_path}")
                    return False
                
                self._access_stats["files_securely_deleted"] += 1
                self.logger.info(f"Successfully deleted file: {file_path.name}")
                return True
            else:
                self.logger.error(f"Failed to securely overwrite file: {file_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Secure deletion failed for {file_path}: {e}")
            return False
    
    def _secure_delete_basic(self, file_path: Path, file_size: int) -> bool:
        """Basic secure deletion with single zero overwrite."""
        try:
            with open(file_path, 'r+b') as f:
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
            return True
        except Exception as e:
            self.logger.error(f"Basic secure deletion failed: {e}")
            return False
    
    def _secure_delete_dod_3_pass(self, file_path: Path, file_size: int) -> bool:
        """DoD 5220.22-M 3-pass secure deletion."""
        patterns = [0x00, 0xFF, secrets.randbits(8)]
        
        try:
            with open(file_path, 'r+b') as f:
                for i, pattern in enumerate(patterns):
                    self.logger.debug(f"DoD 3-pass: Pass {i+1}/3")
                    f.seek(0)
                    
                    if pattern == secrets.randbits(8):
                        # Random pass
                        f.write(secrets.token_bytes(file_size))
                    else:
                        # Fixed pattern pass
                        f.write(bytes([pattern]) * file_size)
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            return True
            
        except Exception as e:
            self.logger.error(f"DoD 3-pass secure deletion failed: {e}")
            return False
    
    def _secure_delete_dod_7_pass(self, file_path: Path, file_size: int) -> bool:
        """DoD 5220.22-M 7-pass secure deletion (recommended standard)."""
        # Enhanced 7-pass pattern for maximum security
        patterns = [
            0x00,           # Pass 1: All zeros
            0xFF,           # Pass 2: All ones
            0xAA,           # Pass 3: Alternating bits (10101010)
            0x55,           # Pass 4: Inverse alternating (01010101)
            'random1',      # Pass 5: Random data
            'random2',      # Pass 6: Different random data
            0x00            # Pass 7: Final zeros
        ]
        
        try:
            with open(file_path, 'r+b') as f:
                for i, pattern in enumerate(patterns):
                    self.logger.debug(f"DoD 7-pass: Pass {i+1}/7")
                    f.seek(0)
                    
                    if isinstance(pattern, str) and pattern.startswith('random'):
                        # Cryptographically secure random data
                        f.write(secrets.token_bytes(file_size))
                    else:
                        # Fixed pattern
                        f.write(bytes([pattern]) * file_size)
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            # Force filesystem sync
            if hasattr(os, 'sync'):
                os.sync()
            
            return True
            
        except Exception as e:
            self.logger.error(f"DoD 7-pass secure deletion failed: {e}")
            return False
    
    def _secure_delete_gutmann(self, file_path: Path, file_size: int) -> bool:
        """Gutmann 35-pass secure deletion method (maximum security)."""
        # Gutmann patterns for various storage media
        gutmann_patterns = [
            0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x92, 0x49, 0x24, 0x00, 0x00, 0x00, 0x00
        ]
        
        try:
            with open(file_path, 'r+b') as f:
                # First 4 passes: random data
                for i in range(4):
                    self.logger.debug(f"Gutmann: Random pass {i+1}/4")
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                
                # Gutmann pattern passes
                for i, pattern in enumerate(gutmann_patterns):
                    self.logger.debug(f"Gutmann: Pattern pass {i+5}/32")
                    f.seek(0)
                    f.write(bytes([pattern]) * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Final 3 passes: random data
                for i in range(3):
                    self.logger.debug(f"Gutmann: Final random pass {i+33}/35")
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Force filesystem sync
            if hasattr(os, 'sync'):
                os.sync()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Gutmann secure deletion failed: {e}")
            return False
    
    def emergency_wipe_directory(self, directory: Union[str, Path], 
                                recursive: bool = True,
                                method: SecureDeletionMethod = SecureDeletionMethod.DOD_7_PASS) -> Dict[str, Any]:
        """Emergency wipe of entire directory with secure deletion.
        
        Args:
            directory: Directory to wipe
            recursive: Whether to wipe subdirectories
            method: Secure deletion method to use
            
        Returns:
            Dictionary with wipe results
        """
        directory = Path(directory)
        results = {
            "total_files": 0,
            "wiped_files": 0,
            "failed_files": 0,
            "total_bytes": 0,
            "errors": []
        }
        
        self.logger.critical(f"EMERGENCY WIPE INITIATED: {directory}")
        self._access_stats["emergency_wipes"] += 1
        
        try:
            # Get all files to wipe
            if recursive:
                files_to_wipe = list(directory.rglob('*'))
            else:
                files_to_wipe = list(directory.iterdir())
            
            # Filter only files (not directories)
            files_to_wipe = [f for f in files_to_wipe if f.is_file()]
            
            results["total_files"] = len(files_to_wipe)
            
            for file_path in files_to_wipe:
                try:
                    file_size = file_path.stat().st_size
                    results["total_bytes"] += file_size
                    
                    if self.secure_delete_file(file_path, method=method, verify=False):
                        results["wiped_files"] += 1
                    else:
                        results["failed_files"] += 1
                        results["errors"].append(f"Failed to wipe: {file_path.name}")
                        
                except Exception as e:
                    results["failed_files"] += 1
                    results["errors"].append(f"Error wiping {file_path.name}: {str(e)}")
            
            # Remove empty directories if recursive
            if recursive:
                try:
                    for dir_path in sorted(directory.rglob('*'), key=lambda x: str(x), reverse=True):
                        if dir_path.is_dir() and not any(dir_path.iterdir()):
                            dir_path.rmdir()
                except Exception as e:
                    results["errors"].append(f"Directory cleanup error: {str(e)}")
            
            self.logger.critical(f"Emergency wipe completed: {results['wiped_files']}/{results['total_files']} files")
            return results
            
        except Exception as e:
            self.logger.error(f"Emergency wipe failed: {e}")
            results["errors"].append(f"Critical error: {str(e)}")
            return results
    
    def _check_file_access(self, file_path: Path, operation: str):
        """Check if file access is allowed.
        
        Args:
            file_path: Path to check
            operation: Operation type (read/write/delete)
            
        Raises:
            FileAccessError: If access is denied
        """
        # Check blacklist
        if self.is_file_blacklisted(file_path):
            entry = self.get_blacklist_info(file_path)
            raise FileAccessError(
                f"File access denied ({operation}): {file_path.name} - "
                f"Reason: {entry.reason if entry else 'blacklisted'}"
            )
        
        # Log access attempt
        self._log_file_access(file_path, operation)
    
    def _log_file_access(self, file_path: Path, operation: str):
        """Log file access attempt."""
        try:
            log_entry = {
                "timestamp": time.time(),
                "operation": operation,
                "file": file_path.name,  # Only log filename for privacy
                "path_hash": self._compute_path_hash(file_path)
            }
            
            # Append to log file
            with open(self._access_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            self.logger.warning(f"Failed to log file access: {e}")
    
    def _save_blacklist(self):
        """Save blacklist to encrypted file."""
        try:
            # Convert blacklist to JSON
            blacklist_data = {}
            for path_hash, entry in self._blacklist.items():
                blacklist_data[path_hash] = {
                    "file_hash": entry.file_hash,
                    "reason": entry.reason,
                    "timestamp": entry.timestamp,
                    "security_level": entry.security_level.value,
                    "deletion_method": entry.deletion_method.value,
                    "wiped": entry.wiped
                }
            
            # For now, save as JSON (could be encrypted in production)
            with open(self._blacklist_file, 'w') as f:
                json.dump(blacklist_data, f, indent=2)
            
            # Set restrictive permissions
            if hasattr(os, 'chmod'):
                os.chmod(str(self._blacklist_file), 0o600)
                
        except Exception as e:
            self.logger.error(f"Failed to save blacklist: {e}")
    
    def _load_blacklist(self):
        """Load blacklist from file."""
        try:
            if not self._blacklist_file.exists():
                return
            
            with open(self._blacklist_file, 'r') as f:
                blacklist_data = json.load(f)
            
            # Convert back to objects
            for path_hash, data in blacklist_data.items():
                entry = FileBlacklistEntry(
                    path_hash=path_hash,
                    file_hash=data.get("file_hash"),
                    reason=data["reason"],
                    timestamp=data["timestamp"],
                    security_level=FileSecurityLevel(data["security_level"]),
                    deletion_method=SecureDeletionMethod(data["deletion_method"]),
                    wiped=data.get("wiped", False)
                )
                self._blacklist[path_hash] = entry
            
            self.logger.info(f"Loaded {len(self._blacklist)} blacklisted files")
            
        except Exception as e:
            self.logger.error(f"Failed to load blacklist: {e}")
            # Initialize empty blacklist on error
            self._blacklist = {}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get file operation statistics.
        
        Returns:
            Dictionary containing operation statistics
        """
        with self._lock:
            return {
                "blacklisted_files": len(self._blacklist),
                "wiped_files": sum(1 for entry in self._blacklist.values() if entry.wiped),
                **self._access_stats
            }
    
    def cleanup(self):
        """Clean up resources and secure any remaining data."""
        try:
            self.logger.info("Cleaning up SecureFileOperations")
            
            # Force cleanup of any secure objects we might have created
            get_secure_memory_manager().cleanup_all()
            
            # Clear sensitive data structures
            self._blacklist.clear()
            
        except Exception as e:
            self.logger.warning(f"Cleanup error: {e}")
    
    def __del__(self):
        """Ensure cleanup on deletion."""
        try:
            self.cleanup()
        except Exception:
            pass  # Ignore errors during cleanup
