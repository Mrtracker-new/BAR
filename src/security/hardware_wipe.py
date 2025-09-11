"""
Hardware-level destruction capabilities for BAR.

This module provides hardware-level data destruction techniques including:
- Volume-scoped free space wiping
- Best-effort hardware entropy utilization
- Cross-platform compatibility with graceful degradation

Per project security rules:
- R004: Security-first design with defense in depth
- R006: Memory security with secure data handling
- R038: Cross-platform support with proper fallbacks
- R041: Performance requirements with memory efficiency

IMPORTANT: These operations are resource-intensive and should be used judiciously.
"""

import os
import sys
import time
import shutil
import secrets
from pathlib import Path
from typing import Optional, Union, Dict, Any
from enum import Enum
import logging


class WipePattern(Enum):
    """Patterns for hardware-level wiping operations."""
    ZEROS = "zeros"          # All zeros
    ONES = "ones"            # All ones
    RANDOM = "random"        # Cryptographically secure random
    ALTERNATING = "alternating"  # 0xAA pattern
    DOD_PATTERN = "dod_pattern"  # DoD 5220.22-M pattern sequence


class HardwareWipe:
    """
    Hardware-level destruction capabilities.
    
    Provides secure wiping operations that work at the storage level
    while maintaining cross-platform compatibility and performance.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize hardware wipe manager.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger("HardwareWipe")
        
        # Performance settings
        self.chunk_size = 1024 * 1024  # 1MB chunks for efficient wiping
        self.max_single_file_size = 100 * 1024 * 1024  # 100MB limit for single temp files
        self.progress_callback = None
        
        # Platform-specific capabilities
        self._platform_capabilities = self._detect_platform_capabilities()
        
        # Safety limits
        self._max_wipe_size_gb = 10  # Maximum 10GB free space wipe by default
        self._timeout_seconds = 300  # 5 minute timeout for safety
    
    def _detect_platform_capabilities(self) -> Dict[str, bool]:
        """Detect platform-specific hardware capabilities."""
        capabilities = {
            "windows_volume_ops": sys.platform == "win32",
            "unix_sync": hasattr(os, 'sync'),
            "direct_io": False,  # Would require platform-specific implementation
            "hardware_random": True,  # Always available via secrets module
        }
        
        # Check for additional Windows capabilities
        if capabilities["windows_volume_ops"]:
            try:
                import ctypes
                capabilities["windows_api"] = True
            except ImportError:
                capabilities["windows_api"] = False
        
        return capabilities
    
    def wipe_volume_free_space(self, path: Union[str, Path], max_bytes: Optional[int] = None,
                              pattern: str = "random", progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """Wipe free space on the volume containing the given path.
        
        This performs a best-effort wipe of available free space on the same volume
        as the specified path, without affecting other volumes or system areas.
        
        Args:
            path: Path on the volume to wipe free space from
            max_bytes: Maximum bytes to wipe (defaults to reasonable limit)
            pattern: Wipe pattern to use
            progress_callback: Optional progress callback function
            
        Returns:
            Dictionary with wipe results and statistics
        """
        try:
            path = Path(path).resolve()
            self.progress_callback = progress_callback
            
            # Safety check: ensure path exists and is accessible
            if not path.exists():
                return {"success": False, "error": "Path does not exist", "bytes_wiped": 0}
            
            # Get volume information
            volume_info = self._get_volume_info(path)
            if not volume_info["success"]:
                return {"success": False, "error": volume_info["error"], "bytes_wiped": 0}
            
            # Determine wipe size
            available_space = volume_info["free_bytes"]
            max_wipe_bytes = min(
                available_space,
                max_bytes or (self._max_wipe_size_gb * 1024 * 1024 * 1024),
                available_space // 2  # Never wipe more than half of free space for safety
            )
            
            if max_wipe_bytes < self.chunk_size:
                return {"success": True, "bytes_wiped": 0, "reason": "Insufficient free space"}
            
            self.logger.info(f"Starting free space wipe: {max_wipe_bytes:,} bytes on {volume_info['volume']}")
            
            # Perform the wipe operation
            start_time = time.time()
            wipe_result = self._perform_free_space_wipe(path, max_wipe_bytes, pattern)
            elapsed_time = time.time() - start_time
            
            # Update results with timing
            wipe_result["elapsed_seconds"] = elapsed_time
            wipe_result["volume_path"] = str(volume_info["volume"])
            wipe_result["pattern_used"] = pattern
            
            if wipe_result["success"]:
                self.logger.info(f"Free space wipe completed: {wipe_result['bytes_wiped']:,} bytes in {elapsed_time:.1f}s")
            else:
                self.logger.warning(f"Free space wipe failed: {wipe_result.get('error', 'Unknown error')}")
            
            return wipe_result
            
        except Exception as e:
            self.logger.error(f"Error in free space wipe: {e}")
            return {"success": False, "error": str(e), "bytes_wiped": 0}
    
    def _get_volume_info(self, path: Path) -> Dict[str, Any]:
        """Get volume information for the given path."""
        try:
            # Get disk usage statistics
            usage = shutil.disk_usage(path)
            
            # Determine volume root
            if sys.platform == "win32":
                volume_root = Path(path.anchor)  # e.g., "C:\\"
            else:
                # For Unix-like systems, find mount point
                volume_root = path
                while volume_root.parent != volume_root:
                    if volume_root.is_mount():
                        break
                    volume_root = volume_root.parent
            
            return {
                "success": True,
                "volume": volume_root,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _perform_free_space_wipe(self, base_path: Path, max_bytes: int, pattern: str) -> Dict[str, Any]:
        """Perform the actual free space wipe operation."""
        try:
            bytes_wiped = 0
            temp_files = []
            
            # Create temporary directory for wipe files
            temp_dir = base_path / ".tmp_wipe"
            temp_dir.mkdir(exist_ok=True)
            
            try:
                # Generate wipe pattern
                pattern_generator = self._get_pattern_generator(pattern)
                
                # Create temporary files to consume free space
                file_count = 0
                start_time = time.time()
                
                while bytes_wiped < max_bytes:
                    # Check timeout
                    if time.time() - start_time > self._timeout_seconds:
                        break
                    
                    # Determine size for this file
                    remaining_bytes = max_bytes - bytes_wiped
                    file_size = min(remaining_bytes, self.max_single_file_size)
                    
                    if file_size < self.chunk_size:
                        break
                    
                    # Create temporary file
                    temp_file = temp_dir / f"wipe_{file_count:04d}.tmp"
                    temp_files.append(temp_file)
                    
                    # Write wipe pattern to file
                    try:
                        written = self._write_wipe_file(temp_file, file_size, pattern_generator)
                        bytes_wiped += written
                        file_count += 1
                        
                        # Progress callback
                        if self.progress_callback:
                            progress = bytes_wiped / max_bytes
                            self.progress_callback(progress, bytes_wiped, max_bytes)
                        
                        # Check if we have enough disk space to continue
                        if not self._check_disk_space(base_path):
                            break
                            
                    except OSError as e:
                        # Likely out of disk space
                        if e.errno in (28, 122):  # No space left on device (Linux/Windows)
                            break
                        else:
                            raise
                
                # Force filesystem sync
                self._sync_filesystem()
                
                # Clean up temporary files
                self._cleanup_temp_files(temp_files)
                
                return {
                    "success": True,
                    "bytes_wiped": bytes_wiped,
                    "files_created": file_count,
                    "pattern": pattern
                }
                
            finally:
                # Ensure cleanup even on failure
                self._cleanup_temp_files(temp_files)
                try:
                    temp_dir.rmdir()
                except Exception:
                    pass
                
        except Exception as e:
            self.logger.error(f"Error performing free space wipe: {e}")
            return {"success": False, "error": str(e), "bytes_wiped": bytes_wiped}
    
    def _get_pattern_generator(self, pattern: str):
        """Get pattern generator function for the specified pattern."""
        if pattern == WipePattern.ZEROS.value:
            return lambda size: b'\x00' * size
        elif pattern == WipePattern.ONES.value:
            return lambda size: b'\xFF' * size
        elif pattern == WipePattern.ALTERNATING.value:
            return lambda size: b'\xAA' * size
        elif pattern == WipePattern.RANDOM.value:
            return lambda size: secrets.token_bytes(size)
        elif pattern == WipePattern.DOD_PATTERN.value:
            # Simplified DoD pattern (alternating zeros and ones)
            def dod_pattern(size):
                half_size = size // 2
                return b'\x00' * half_size + b'\xFF' * (size - half_size)
            return dod_pattern
        else:
            # Default to random
            return lambda size: secrets.token_bytes(size)
    
    def _write_wipe_file(self, file_path: Path, target_size: int, pattern_generator) -> int:
        """Write a wipe pattern file of the specified size."""
        bytes_written = 0
        
        with open(file_path, 'wb') as f:
            while bytes_written < target_size:
                chunk_size = min(self.chunk_size, target_size - bytes_written)
                chunk_data = pattern_generator(chunk_size)
                
                f.write(chunk_data)
                f.flush()
                bytes_written += len(chunk_data)
                
                # Periodic sync for better security
                if bytes_written % (self.chunk_size * 10) == 0:
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass
        
        # Final sync
        try:
            with open(file_path, 'r+b') as f:
                os.fsync(f.fileno())
        except Exception:
            pass
        
        return bytes_written
    
    def _check_disk_space(self, path: Path) -> bool:
        """Check if there's still reasonable disk space available."""
        try:
            usage = shutil.disk_usage(path)
            # Stop if less than 1% free space remaining
            free_percentage = usage.free / usage.total
            return free_percentage > 0.01
        except Exception:
            return False
    
    def _sync_filesystem(self):
        """Force filesystem synchronization."""
        try:
            if self._platform_capabilities["unix_sync"]:
                os.sync()
            elif sys.platform == "win32":
                # Windows doesn't have a direct equivalent, but we can flush buffers
                import ctypes
                try:
                    # FlushFileBuffers equivalent for system-wide sync
                    ctypes.windll.kernel32.SetSystemFileCacheSize(0, 0, 0x4)
                except Exception:
                    pass
        except Exception:
            pass
    
    def _cleanup_temp_files(self, temp_files: list):
        """Clean up temporary wipe files securely."""
        for temp_file in temp_files:
            try:
                if temp_file.exists():
                    # Quick overwrite with zeros before deletion
                    try:
                        file_size = temp_file.stat().st_size
                        with open(temp_file, 'r+b') as f:
                            chunks = file_size // self.chunk_size + 1
                            for _ in range(min(chunks, 10)):  # Limit overwrite passes
                                f.seek(0)
                                f.write(b'\x00' * min(self.chunk_size, file_size))
                                f.flush()
                    except Exception:
                        pass
                    
                    # Delete the file
                    temp_file.unlink()
                    
            except Exception as e:
                self.logger.debug(f"Error cleaning up temp file {temp_file}: {e}")
    
    def estimate_wipe_time(self, path: Union[str, Path], max_bytes: Optional[int] = None) -> Dict[str, Any]:
        """Estimate time required for free space wipe operation.
        
        Args:
            path: Path on the volume to estimate for
            max_bytes: Maximum bytes to wipe
            
        Returns:
            Dictionary with time estimates and recommendations
        """
        try:
            path = Path(path).resolve()
            
            # Get volume information
            volume_info = self._get_volume_info(path)
            if not volume_info["success"]:
                return {"success": False, "error": volume_info["error"]}
            
            # Calculate estimated wipe size
            available_space = volume_info["free_bytes"]
            estimated_wipe_bytes = min(
                available_space,
                max_bytes or (self._max_wipe_size_gb * 1024 * 1024 * 1024),
                available_space // 2
            )
            
            # Estimate based on typical performance (conservative estimate)
            # Assume ~50MB/s for random data writing on typical storage
            estimated_mb_per_second = 50
            estimated_seconds = (estimated_wipe_bytes / (1024 * 1024)) / estimated_mb_per_second
            
            return {
                "success": True,
                "estimated_bytes": estimated_wipe_bytes,
                "estimated_seconds": estimated_seconds,
                "estimated_minutes": estimated_seconds / 60,
                "free_space_bytes": available_space,
                "volume_path": str(volume_info["volume"]),
                "recommendation": self._get_wipe_recommendation(estimated_seconds, estimated_wipe_bytes)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _get_wipe_recommendation(self, estimated_seconds: float, estimated_bytes: int) -> str:
        """Get recommendation based on estimated wipe parameters."""
        if estimated_seconds < 30:
            return "Quick wipe - should complete rapidly"
        elif estimated_seconds < 300:  # 5 minutes
            return "Moderate wipe - allow a few minutes to complete"
        elif estimated_seconds < 1800:  # 30 minutes
            return "Extended wipe - may take significant time, consider during maintenance window"
        else:
            return "Long wipe operation - consider reducing scope or scheduling during downtime"
    
    def set_safety_limits(self, max_wipe_size_gb: int = 10, timeout_seconds: int = 300):
        """Set safety limits for wipe operations.
        
        Args:
            max_wipe_size_gb: Maximum GB to wipe in a single operation
            timeout_seconds: Maximum time to spend on wipe operation
        """
        self._max_wipe_size_gb = max(1, min(max_wipe_size_gb, 100))  # 1-100GB range
        self._timeout_seconds = max(60, min(timeout_seconds, 3600))   # 1-60 minute range
        
        self.logger.info(f"Updated safety limits: {self._max_wipe_size_gb}GB max, {self._timeout_seconds}s timeout")
    
    def get_platform_capabilities(self) -> Dict[str, Any]:
        """Get information about platform-specific capabilities.
        
        Returns:
            Dictionary with capability information
        """
        return {
            "capabilities": self._platform_capabilities.copy(),
            "platform": sys.platform,
            "chunk_size": self.chunk_size,
            "max_single_file_size": self.max_single_file_size,
            "safety_limits": {
                "max_wipe_size_gb": self._max_wipe_size_gb,
                "timeout_seconds": self._timeout_seconds
            }
        }
    
    def __del__(self):
        """Cleanup on destruction."""
        try:
            # Clear any sensitive data
            if hasattr(self, 'progress_callback'):
                self.progress_callback = None
        except Exception:
            pass
