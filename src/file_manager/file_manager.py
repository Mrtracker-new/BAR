
import os
import json
import time
import shutil
import threading
import logging
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from cryptography.hazmat.primitives import hashes

from ..crypto.encryption import EncryptionManager
from .file_scanner import FileScanner


class FileManager:
    """Manages secure file operations for the BAR application."""
    
    def __init__(self, base_directory: str):
        """Initialize the file manager.
        
        Args:
            base_directory: The base directory for storing all files and metadata
        """
        self.base_directory = Path(base_directory)
        self.files_directory = self.base_directory / "files"
        self.metadata_directory = self.base_directory / "metadata"
        
        # Create directories if they don't exist
        self.files_directory.mkdir(parents=True, exist_ok=True)
        self.metadata_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize the encryption manager
        self.encryption_manager = EncryptionManager()
        
        # Start the file monitoring thread
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_files, daemon=True)
        self.monitor_thread.start()
        
        # Setup logging
        self._setup_logging()
        
        # Initialize the file scanner
        self.file_scanner = FileScanner(self)
    
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
                
        Returns:
            The ID of the created file
        """
        # Generate a unique file ID
        file_id = self._generate_file_id()
        
        # Encrypt the file content
        encrypted_content = self.encryption_manager.encrypt_file_content(content, password)
        
        # Create metadata
        current_time = datetime.now()
        metadata = {
            "file_id": file_id,
            "filename": filename,
            "creation_time": current_time.isoformat(),
            "last_accessed": current_time.isoformat(),
            "access_count": 0,
            "security": {
                "expiration_time": security_settings.get("expiration_time"),
                "max_access_count": security_settings.get("max_access_count"),
                "deadman_switch": security_settings.get("deadman_switch"),  # in days
            },
            "encryption": encrypted_content
        }
        
        # Save the file metadata
        metadata_path = self.metadata_directory / f"{file_id}.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Created secure file: {file_id} ({filename})")
        return file_id
    
    def access_file(self, file_id: str, password: str) -> Tuple[bytes, Dict[str, Any]]:
        """Access a secure file, checking security constraints.
        
        Args:
            file_id: The ID of the file to access
            password: The password to decrypt the file
            
        Returns:
            Tuple containing (file_content, metadata)
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the password is incorrect or the file has expired
        """
        # Check if the file exists
        metadata_path = self.metadata_directory / f"{file_id}.json"
        if not metadata_path.exists():
            raise FileNotFoundError(f"File with ID {file_id} not found")
        
        # Load metadata
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        # Check security constraints
        if not self._check_security_constraints(metadata):
            # File has expired or reached max access count
            self._delete_file(file_id)
            raise ValueError("File has expired or reached maximum access count")
        
        # Decrypt the file content
        try:
            file_content = self.encryption_manager.decrypt_file_content(
                metadata["encryption"], password)
        except ValueError:
            self.logger.warning(f"Failed decryption attempt for file: {file_id}")
            raise ValueError("Incorrect password")
        
        # Update access metadata
        current_time = datetime.now()
        metadata["last_accessed"] = current_time.isoformat()
        metadata["access_count"] += 1
        
        # Save updated metadata
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        # Check if this access has triggered self-destruction
        if metadata["security"]["max_access_count"] and \
           metadata["access_count"] >= metadata["security"]["max_access_count"]:
            # Schedule deletion after returning the content
            threading.Thread(target=self._delete_file, args=(file_id,), daemon=True).start()
        
        self.logger.info(f"Accessed file: {file_id} ({metadata['filename']})")
        return file_content, metadata
    
    def list_files(self) -> List[Dict[str, Any]]:
        """List all available secure files with their metadata (excluding encryption details).
        
        Returns:
            List of dictionaries containing file metadata
        """
        files = []
        for metadata_file in self.metadata_directory.glob("*.json"):
            with open(metadata_file, "r") as f:
                metadata = json.load(f)
            
            # Remove sensitive encryption details
            if "encryption" in metadata:
                metadata_copy = metadata.copy()
                del metadata_copy["encryption"]
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
    
    def export_file(self, file_id: str, export_path: str) -> bool:
        """Export a secure file for sharing.
        
        Args:
            file_id: The ID of the file to export
            export_path: The path where the exported file should be saved
            
        Returns:
            True if the file was exported successfully, False otherwise
        """
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            return False
        
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
        
        This creates a special file format that contains both the encrypted content and
        all necessary metadata to maintain security settings when transferred to another device.
        
        Args:
            file_id: The ID of the file to export
            password: The password to decrypt and verify the file
            export_path: The path where the exported file should be saved
            
        Returns:
            True if the file was exported successfully, False otherwise
            
        Raises:
            ValueError: If the password is incorrect
            FileNotFoundError: If the file doesn't exist
        """
        metadata_path = self.metadata_directory / f"{file_id}.json"
        
        if not metadata_path.exists():
            raise FileNotFoundError(f"File with ID {file_id} not found")
        
        # Load metadata
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        # Verify password by attempting decryption
        try:
            file_content = self.encryption_manager.decrypt_file_content(
                metadata["encryption"], password)
        except ValueError:
            self.logger.warning(f"Failed decryption attempt during export for file: {file_id}")
            raise ValueError("Incorrect password")
        
        # Create portable file format
        portable_data = {
            "bar_portable_file": True,
            "version": "1.0",
            "filename": metadata["filename"],
            "creation_time": metadata["creation_time"],
            "security": metadata["security"],
            "encryption": metadata["encryption"],
            "content_hash": self._hash_content(file_content)
        }
        
        # Save the portable file
        try:
            with open(export_path, "w") as f:
                json.dump(portable_data, f, indent=2)
            
            self.logger.info(f"Exported portable file: {file_id} to {export_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export portable file {file_id}: {str(e)}")
            raise ValueError(f"Failed to export file: {str(e)}")
    
    def import_portable_file(self, import_path: str, password: str) -> str:
        """Import a portable secure file.
        
        Args:
            import_path: The path of the portable file to import
            password: The password to decrypt the file
            
        Returns:
            The ID of the imported file
            
        Raises:
            ValueError: If the file is not a valid BAR portable file or password is incorrect
        """
        try:
            # Load and validate the file
            with open(import_path, "r") as f:
                portable_data = json.load(f)
            
            # Check if it's a valid BAR portable file
            if not portable_data.get("bar_portable_file"):
                raise ValueError("Not a valid BAR portable file")
            
            # Verify the password by attempting decryption
            try:
                file_content = self.encryption_manager.decrypt_file_content(
                    portable_data["encryption"], password)
            except ValueError:
                raise ValueError("Incorrect password")
            
            # Generate a new file ID
            file_id = self._generate_file_id()
            
            # Create metadata
            metadata = {
                "file_id": file_id,
                "filename": portable_data["filename"],
                "creation_time": portable_data["creation_time"],
                "last_accessed": datetime.now().isoformat(),
                "access_count": 0,
                "security": portable_data["security"],
                "encryption": portable_data["encryption"]
            }
            
            # Save the metadata file
            metadata_path = self.metadata_directory / f"{file_id}.json"
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info(f"Imported portable file: {file_id} ({metadata['filename']})")
            return file_id
            
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
        
        # Load metadata
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        # Update security settings
        for key, value in security_settings.items():
            if key in metadata["security"]:
                metadata["security"][key] = value
        
        # Save updated metadata
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Updated security settings for file: {file_id}")
        return True
    
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
        if metadata["security"]["max_access_count"] and \
           metadata["access_count"] >= metadata["security"]["max_access_count"]:
            self.logger.info(f"File {metadata['file_id']} has reached max access count")
            return False
        
        # Check deadman switch
        if metadata["security"]["deadman_switch"]:
            last_accessed = datetime.fromisoformat(metadata["last_accessed"])
            inactive_days = (current_time - last_accessed).days
            
            if inactive_days > metadata["security"]["deadman_switch"]:
                self.logger.info(f"File {metadata['file_id']} triggered deadman switch")
                return False
        
        return True
    
    def _monitor_files(self):
        """Monitor files for security constraints and trigger self-destruction."""
        while self.monitoring_active:
            try:
                # Get all file metadata
                for metadata_file in self.metadata_directory.glob("*.json"):
                    try:
                        with open(metadata_file, "r") as f:
                            metadata = json.load(f)
                        
                        # Check security constraints
                        if not self._check_security_constraints(metadata):
                            file_id = metadata["file_id"]
                            self._delete_file(file_id)
                    except Exception as e:
                        self.logger.error(f"Error monitoring file {metadata_file}: {str(e)}")
                
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
            
        self.logger.info("File manager shutdown")
    
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