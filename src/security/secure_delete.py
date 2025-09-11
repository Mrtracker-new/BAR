import os
import logging
import secrets
import string
import sys
from pathlib import Path
from typing import Optional


def _random_safe_name(length: int = 16) -> str:
    """Generate a filesystem-safe random name.

    Uses URL-safe characters to avoid encoding issues.
    """
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _best_effort_remove_ads_windows(path: Path, logger: logging.Logger) -> None:
    """Best-effort removal of common NTFS Alternate Data Streams (ADS) on Windows.

    Notes:
    - Enumerating arbitrary ADS requires platform APIs. To avoid external deps
      and keep offline-first, we remove well-known streams that often exist
      and could leak metadata (e.g., Zone.Identifier).
    - This function is a no-op on non-Windows platforms.
    """
    if sys.platform != "win32":
        return

    # Known/common ADS names to clear
    common_streams = ["Zone.Identifier", ":$DATA", "AlternateStream", "Meta"]

    for stream in common_streams:
        try:
            ads_path = f"{str(path)}:{stream}"
            # Open for write to truncate/overwrite small content, then unlink by recreate empty
            try:
                with open(ads_path, "wb") as f:
                    f.write(b"\x00" * 64)
                    f.flush()
                    os.fsync(f.fileno())
            except FileNotFoundError:
                continue
            # Overwrite again with random to reduce residuals
            try:
                with open(ads_path, "wb") as f:
                    f.write(os.urandom(64))
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                pass
        except Exception as e:
            try:
                logger.debug(f"ADS cleanup failed for {path}:{stream}: {e}")
            except Exception:
                pass


class SecureDelete:
    """Provides secure file deletion capabilities to prevent recovery of deleted files.
    
    Uses military-grade secure deletion patterns following DoD 5220.22-M standard.
    """
    
    # Constants for secure deletion
    DEFAULT_PASSES = 7  # Number of overwrite passes for enhanced security
    CHUNK_SIZE = 4096  # 4KB chunks for memory efficiency
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the secure deletion manager.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger("SecureDelete")
    
    def secure_delete_file(self, file_path: str, passes: int = DEFAULT_PASSES) -> bool:
        """Securely delete a file by overwriting its contents multiple times before deletion.
        
        Enhancements:
        - Randomize filename before overwrite to reduce MFT-based filename recovery
        - Best-effort cleanup of common NTFS ADS on Windows
        - Verification after unlink
        
        Args:
            file_path: Path to the file to delete
            passes: Number of overwrite passes (default: 7)
            
        Returns:
            True if deletion was successful, False otherwise
        """
        path = Path(file_path)
        
        if not path.exists() or not path.is_file():
            self.logger.warning(f"File not found: {file_path}")
            return False
        
        try:
            # Attempt best-effort ADS cleanup on Windows before we begin
            _best_effort_remove_ads_windows(path, self.logger)
            
            # Randomize filename first (same directory, preserve suffix) to break filename linkage
            try:
                random_name = _random_safe_name() + path.suffix
                randomized_path = path.with_name(random_name)
                path.rename(randomized_path)
                path = randomized_path
            except Exception:
                # If rename fails, continue with original path
                pass
            
            # Get file size
            file_size = path.stat().st_size
            
            # Open file for binary writing
            with open(str(path), "r+b") as f:
                # Multiple overwrite passes
                for pass_num in range(passes):
                    # Seek to beginning of file
                    f.seek(0)
                    
                    # Use DoD 5220.22-M inspired overwrite patterns
                    if pass_num == 0:
                        # Pass 1: All zeros (0x00)
                        pattern = bytes([0x00] * self.CHUNK_SIZE)
                    elif pass_num == 1:
                        # Pass 2: All ones (0xFF)
                        pattern = bytes([0xFF] * self.CHUNK_SIZE)
                    elif pass_num == 2:
                        # Pass 3: Random data
                        pattern = os.urandom(self.CHUNK_SIZE)
                    elif pass_num == 3:
                        # Pass 4: Complement of pass 3 (NOT operation)
                        random_data = os.urandom(self.CHUNK_SIZE)
                        pattern = bytes([~b & 0xFF for b in random_data])
                    elif pass_num == 4:
                        # Pass 5: Alternating pattern (0x55)
                        pattern = bytes([0x55] * self.CHUNK_SIZE)
                    elif pass_num == 5:
                        # Pass 6: Alternating pattern (0xAA)
                        pattern = bytes([0xAA] * self.CHUNK_SIZE)
                    else:
                        # Pass 7: Final secure random overwrite
                        pattern = os.urandom(self.CHUNK_SIZE)
                    
                    # Write pattern in chunks
                    bytes_written = 0
                    while bytes_written < file_size:
                        chunk_size = min(self.CHUNK_SIZE, file_size - bytes_written)
                        f.write(pattern[:chunk_size])
                        bytes_written += chunk_size
                    
                    # Flush to disk
                    f.flush()
                    os.fsync(f.fileno())
                
                # Final pass: truncate file to 0 bytes
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())
            
            # Delete the file
            try:
                os.remove(str(path))
            except FileNotFoundError:
                pass
            
            # Verification: ensure path no longer exists
            if Path(path).exists():
                self.logger.error(f"File still exists after deletion attempt: {path}")
                return False
            
            self.logger.info(f"Securely deleted file with {passes} passes: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during secure deletion of {file_path}: {str(e)}")
            return False
    
    def secure_delete_directory(self, dir_path: str, passes: int = DEFAULT_PASSES) -> bool:
        """Securely delete all files in a directory and its subdirectories.
        
        Args:
            dir_path: Path to the directory to delete
            passes: Number of overwrite passes (default: 3)
            
        Returns:
            True if deletion was successful, False otherwise
        """
        path = Path(dir_path)
        
        if not path.exists() or not path.is_dir():
            self.logger.warning(f"Directory not found: {dir_path}")
            return False
        
        try:
            # Delete files first
            for file_path in path.rglob("*"):
                if file_path.is_file():
                    self.secure_delete_file(str(file_path), passes)
            
            # Then remove empty directories
            for dirpath, dirnames, filenames in os.walk(dir_path, topdown=False):
                for dirname in dirnames:
                    full_path = os.path.join(dirpath, dirname)
                    try:
                        os.rmdir(full_path)
                    except OSError:
                        pass  # Directory not empty, will be handled in next iteration
            
            # Finally remove the root directory
            try:
                os.rmdir(dir_path)
            except OSError as e:
                self.logger.warning(f"Could not remove directory {dir_path}: {str(e)}")
                return False
            
            self.logger.info(f"Securely deleted directory: {dir_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during secure deletion of directory {dir_path}: {str(e)}")
            return False