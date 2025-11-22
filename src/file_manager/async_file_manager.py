import asyncio
import os
import json
import time
import logging
import gc
try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except ImportError:  # Optional dependency
    psutil = None  # type: ignore
    _HAS_PSUTIL = False
import uuid
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, AsyncIterator, Union
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from src.crypto.async_encryption import AsyncEncryptionManager, StreamingConfig, PerformanceMetrics
from src.crypto.encryption import EncryptionManager
from src.file_manager.file_scanner import FileScanner
from src.file_manager.format_detector import FileFormatDetector

# Import comprehensive input validation system
from src.security.input_validator import (
    get_file_validator, get_global_validator, get_crypto_validator,
    FileValidationError, validate_string, validate_bytes, validate_integer
)


@dataclass
class FileOperationProgress:
    """Progress tracking for file operations."""
    operation_id: str
    operation_type: str  # 'encrypt', 'decrypt', 'scan', 'analyze'
    file_path: str
    total_bytes: int
    processed_bytes: int
    start_time: datetime
    estimated_completion: Optional[datetime] = None
    throughput: float = 0.0  # bytes per second
    status: str = "in_progress"  # in_progress, completed, failed, cancelled
    error_message: Optional[str] = None


class MemoryMonitor:
    """Monitor memory usage and trigger cleanup when needed."""
    
    def __init__(self, max_memory_mb: int = 512):
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        # Create process handle if psutil is available; else use fallback
        if _HAS_PSUTIL:
            self.process = psutil.Process()
        else:
            self.process = None  # Fallback: unavailable
        self.cleanup_callbacks = []
        self.peak_memory = 0  # Track peak memory usage
    
    def add_cleanup_callback(self, callback):
        """Add a callback to be called when memory cleanup is needed."""
        self.cleanup_callbacks.append(callback)
    
    async def check_memory_usage(self):
        """Check current memory usage and trigger cleanup if needed."""
        try:
            if self.process is not None:
                memory_info = self.process.memory_info()
                current_memory = memory_info.rss  # Resident Set Size (physical memory)
            else:
                # Fallback: no psutil, approximate as 0
                current_memory = 0
            
            # Update peak memory
            if current_memory > self.peak_memory:
                self.peak_memory = current_memory
            
            if current_memory > self.max_memory_bytes and self.process is not None:
                # Trigger cleanup callbacks
                for callback in self.cleanup_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback()
                        else:
                            callback()
                    except Exception as e:
                        logging.warning(f"Memory cleanup callback failed: {e}")
                
                # Force garbage collection
                gc.collect()
                
                return True  # Cleanup was triggered
            return False  # No cleanup needed
        except Exception as e:
            logging.warning(f"Memory monitoring failed: {e}")
            return False
    
    def get_memory_usage(self) -> Dict[str, int]:
        """Get current memory usage statistics."""
        try:
            if self.process is not None:
                memory_info = self.process.memory_info()
                percent = self.process.memory_percent()
                rss = memory_info.rss
                vms = memory_info.vms
            else:
                rss = 0
                vms = 0
                percent = 0.0
            return {
                'rss': rss,  # Physical memory
                'vms': vms,  # Virtual memory
                'percent': percent,
                'max_allowed': self.max_memory_bytes,
                'peak': self.peak_memory  # Peak memory usage
            }
        except Exception as e:
            logging.warning(f"Failed to get memory usage: {e}")
            return {'error': str(e)}
    
    def reset_peak_memory(self):
        """Reset peak memory tracking."""
        self.peak_memory = 0


class AsyncFileManager:
    """Async version of FileManager with performance optimizations and streaming support.
    
    This class implements Rules R041 (Performance Requirements) and R042 (Memory Management)
    providing:
    - Async file operations with thread pool execution
    - Streaming support for large files (1GB+)
    - Memory-efficient processing with automatic cleanup
    - Real-time progress tracking and cancellation support
    - Performance monitoring and optimization
    """
    
    def __init__(self, base_directory: str, max_workers: int = None, 
                 max_memory_mb: int = 512, monitor=None):
        """Initialize the async file manager.
        
        Args:
            base_directory: The base directory for storing all files and metadata
            max_workers: Maximum number of worker threads
            max_memory_mb: Maximum memory usage in MB
            monitor: Optional intelligent monitor for access tracking
        """
        # Validate base directory
        self._validate_base_directory(base_directory)
        
        # Directory setup
        self.base_directory = Path(base_directory)
        self.files_directory = self.base_directory / "files"
        self.metadata_directory = self.base_directory / "metadata"
        self.temp_directory = self.base_directory / "temp"
        self.monitor = monitor
        
        # Create directories
        for directory in [self.files_directory, self.metadata_directory, self.temp_directory]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Performance and resource management
        self.max_workers = max_workers or min(os.cpu_count() or 4, 8)
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.memory_monitor = MemoryMonitor(max_memory_mb)
        
        # Progress tracking
        self.active_operations = {}
        self.operation_lock = asyncio.Lock()
        
        # Initialize components
        self.async_encryption = AsyncEncryptionManager(max_workers=self.max_workers)
        self.format_detector = FileFormatDetector()
        self.file_scanner = FileScanner(self)  # Pass self for compatibility
        
        # Setup logging
        self._setup_logging()
        
        # Initialize validators
        self.file_validator = get_file_validator()
        
        # Performance metrics
        self.operation_metrics = []
        
        # Setup memory cleanup
        self.memory_monitor.add_cleanup_callback(self._cleanup_temporary_files)
        
        # Start memory monitoring
        self._start_memory_monitoring()
    
    def _validate_base_directory(self, base_directory: Any) -> None:
        """Validate base directory parameter per Rule R030."""
        validator = get_file_validator()
        
        try:
            path_result = validator.validate_file_path(
                base_directory,
                field_name="base_directory",
                allow_absolute=True,
                allow_parent_traversal=False
            )
            if not path_result.is_valid:
                raise FileValidationError(
                    path_result.error_message,
                    field_name="base_directory",
                    violation_type=path_result.violation_type
                )
        except (AttributeError, TypeError) as e:
            # Handle cases where validation may not be fully configured (e.g., testing)
            # Only allow this for development/testing - in production this should fail
            if os.getenv('BAR_ENV') == 'production':
                raise FileValidationError(
                    f"Base directory validation failed: {e}",
                    field_name="base_directory",
                    violation_type="validation_error"
                )
            # For dev/test, do basic validation
            if not base_directory or not isinstance(base_directory, (str, Path)):
                raise FileValidationError(
                    "Base directory must be a valid path string",
                    field_name="base_directory",
                    violation_type="invalid_type"
                )

    def _setup_logging(self):
        """Set up logging for the async file manager."""
        log_dir = self.base_directory / "logs"
        log_dir.mkdir(exist_ok=True)

        log_file = log_dir / "async_file_operations.log"

        # Configure dedicated logger
        self.logger = logging.getLogger("AsyncFileManager")

        if not self.logger.handlers:  # Avoid duplicate handlers
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _start_memory_monitoring(self):
        """Start background memory monitoring."""
        async def monitor_memory():
            while True:
                try:
                    await asyncio.sleep(30)  # Check every 30 seconds
                    cleanup_triggered = await self.memory_monitor.check_memory_usage()
                    if cleanup_triggered:
                        self.logger.info("Memory cleanup triggered")
                except Exception as e:
                    self.logger.warning(f"Memory monitoring error: {e}")

        # Start monitoring task
        asyncio.create_task(monitor_memory())

    async def _cleanup_temporary_files(self):
        """Clean up temporary files to free memory."""
        try:
            temp_files = list(self.temp_directory.glob("*"))
            for temp_file in temp_files:
                try:
                    # Check if file is older than 1 hour
                    if temp_file.stat().st_mtime < time.time() - 3600:
                        temp_file.unlink()
                        self.logger.info(f"Cleaned up temporary file: {temp_file.name}")
                except Exception as e:
                    self.logger.warning(f"Failed to clean up {temp_file}: {e}")
        except Exception as e:
            self.logger.warning(f"Temporary file cleanup failed: {e}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.async_encryption.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with cleanup."""
        await self.cleanup()

    async def cleanup(self):
        """Clean up resources."""
        # Cancel all active operations
        for operation_id in list(self.active_operations.keys()):
            await self.cancel_operation(operation_id)

        # Cleanup encryption manager
        await self.async_encryption.cleanup()

        # Shutdown thread pool
        self.executor.shutdown(wait=True)

        # Clean up temporary files
        await self._cleanup_temporary_files()

    def _generate_operation_id(self) -> str:
        """Generate a unique operation ID."""
        return str(uuid.uuid4())
    
    async def _start_operation(self, operation_type: str, file_path: str, 
                              total_bytes: int = 0) -> str:
        """Start tracking a new operation."""
        operation_id = self._generate_operation_id()
        
        # Reset peak memory for this operation
        self.memory_monitor.reset_peak_memory()
        
        async with self.operation_lock:
            progress = FileOperationProgress(
                operation_id=operation_id,
                operation_type=operation_type,
                file_path=file_path,
                total_bytes=total_bytes,
                processed_bytes=0,
                start_time=datetime.now()
            )
            self.active_operations[operation_id] = progress
        
        return operation_id
    
    async def _update_operation_progress(self, operation_id: str, 
                                       processed_bytes: int,
                                       status: str = "in_progress",
                                       error_message: str = None):
        """Update operation progress."""
        async with self.operation_lock:
            if operation_id in self.active_operations:
                progress = self.active_operations[operation_id]
                progress.processed_bytes = processed_bytes
                progress.status = status
                progress.error_message = error_message
                
                # Calculate throughput and ETA
                elapsed_time = (datetime.now() - progress.start_time).total_seconds()
                if elapsed_time > 0:
                    progress.throughput = processed_bytes / elapsed_time
                    
                    if progress.total_bytes > 0 and processed_bytes > 0:
                        remaining_bytes = progress.total_bytes - processed_bytes
                        if progress.throughput > 0:
                            eta_seconds = remaining_bytes / progress.throughput
                            progress.estimated_completion = datetime.now() + timedelta(seconds=eta_seconds)
    
    async def _finish_operation(self, operation_id: str, status: str = "completed",
                               error_message: str = None):
        """Mark operation as finished."""
        async with self.operation_lock:
            if operation_id in self.active_operations:
                progress = self.active_operations[operation_id]
                progress.status = status
                progress.error_message = error_message
                
                # Record metrics
                duration = (datetime.now() - progress.start_time).total_seconds()
                metric = PerformanceMetrics(
                    operation=f"{progress.operation_type}_async",
                    data_size=progress.processed_bytes,
                    duration=duration,
                    throughput=progress.throughput,
                    memory_peak=self.memory_monitor.peak_memory,  # now tracked
                    timestamp=datetime.now()
                )
                self.operation_metrics.append(metric)
                
                # Keep only recent metrics
                if len(self.operation_metrics) > 1000:
                    self.operation_metrics = self.operation_metrics[-1000:]
    
    async def get_operation_progress(self, operation_id: str) -> Optional[FileOperationProgress]:
        """Get progress information for an operation."""
        async with self.operation_lock:
            return self.active_operations.get(operation_id)
    
    async def cancel_operation(self, operation_id: str) -> bool:
        """Cancel an active operation."""
        async with self.operation_lock:
            if operation_id in self.active_operations:
                progress = self.active_operations[operation_id]
                progress.status = "cancelled"
                self.logger.info(f"Operation cancelled: {operation_id}")
                return True
            return False
    
    def _serialize_encrypted_data(self, encrypted_data: Dict[str, bytes], salt: bytes) -> bytes:
        """Safely serialize encrypted data using JSON + base64 instead of pickle.
        
        Args:
            encrypted_data: Dictionary containing ciphertext and nonce
            salt: The salt used for key derivation
            
        Returns:
            JSON-serialized bytes
        """
        safe_data = {
            'version': 2,  # Format version
            'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('ascii'),
            'nonce': base64.b64encode(encrypted_data['nonce']).decode('ascii'),
            'salt': base64.b64encode(salt).decode('ascii')
        }
        return json.dumps(safe_data).encode('utf-8')
    
    def _deserialize_encrypted_data(self, data: bytes) -> Tuple[Dict[str, bytes], bytes]:
        """Safely deserialize encrypted data from JSON + base64.
        
        Args:
            data: JSON-serialized bytes
            
        Returns:
            Tuple of (encrypted_data dict, salt)
        """
        try:
            safe_data = json.loads(data.decode('utf-8'))
            
            # Check version
            if safe_data.get('version') != 2:
                raise ValueError(f"Unsupported format version: {safe_data.get('version')}")
            
            encrypted_data = {
                'ciphertext': base64.b64decode(safe_data['ciphertext']),
                'nonce': base64.b64decode(safe_data['nonce'])
            }
            salt = base64.b64decode(safe_data['salt'])
            
            return encrypted_data, salt
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Failed to deserialize encrypted data: {e}")
    
    async def create_secure_file_async(self, content: bytes, filename: str, 
                                     password: str, security_settings: Dict[str, Any],
                                     progress_callback=None) -> Tuple[str, str]:
        """Create a new secure file asynchronously.
        
        Args:
            content: The file content to encrypt and store
            filename: The name of the file
            password: The password to encrypt the file with
            security_settings: Dictionary containing security parameters
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (file_id, operation_id)
        """
        # Input validation
        validated_content = self._validate_file_content(content)
        validated_filename = self._validate_filename(filename)
        validated_password = self._validate_password(password)
        validated_settings = self._validate_security_settings(security_settings)
        
        # Generate file ID
        file_id = self._generate_file_id()
        
        # Start operation tracking
        operation_id = await self._start_operation("encrypt", filename, len(validated_content))
        
        temp_file = self.temp_directory / f"{file_id}_temp"
        
        try:
            async def progress_handler(progress_data):
                await self._update_operation_progress(
                    operation_id, 
                    progress_data.get('bytes_processed', 0)
                )
                if progress_callback:
                    await progress_callback(progress_data)
            
            # For large files, use streaming encryption
            if len(validated_content) > StreamingConfig.MEDIUM_FILE_CHUNK_SIZE:
                self.logger.info(f"Using streaming encryption for large file: {filename} ({len(validated_content)} bytes)")
                
                # Create async iterator for content
                async def content_stream():
                    chunk_size = StreamingConfig.get_optimal_chunk_size(
                        len(validated_content), 
                        StreamingConfig.MAX_MEMORY_USAGE
                    )
                    for i in range(0, len(validated_content), chunk_size):
                        chunk = validated_content[i:i+chunk_size]
                        yield chunk
                
                # Stream encrypt to temporary file - using JSON serialization
                chunks = []
                salt_b64 = None
                total_size = 0
                async for item in self.async_encryption.encrypt_stream_async(
                    content_stream(), validated_password, progress_callback=progress_handler
                ):
                    itype = item.get('type')
                    if itype == 'metadata':
                        salt_b64 = base64.b64encode(item['salt']).decode('ascii')
                        continue
                    if itype == 'chunk':
                        total_size += item.get('size', 0)
                        chunks.append({
                            'index': item['index'],
                            'ciphertext': base64.b64encode(item['ciphertext']).decode('ascii'),
                            'nonce': base64.b64encode(item['nonce']).decode('ascii')
                        })
                    # final_metadata is ignored for storage; we compute totals ourselves
                
                if salt_b64 is None:
                    raise ValueError('Streaming encryption missing salt metadata')
                
                # Write JSON structure
                with open(temp_file, 'w') as f:
                    json.dump({
                        'version': 2,
                        'streaming': True,
                        'salt': salt_b64,
                        'total_size': total_size,
                        'chunks': chunks
                    }, f)
            
            else:
                # Use regular encryption for smaller files
                def encrypt_small_file():
                    salt = EncryptionManager.generate_salt()
                    key = EncryptionManager.derive_key(validated_password, salt)
                    encrypted_data = EncryptionManager.encrypt_data(validated_content, key)
                    return encrypted_data, salt
                
                loop = asyncio.get_event_loop()
                encrypted_data, salt = await loop.run_in_executor(self.executor, encrypt_small_file)
                
                # Save encrypted data with JSON serialization (safer than pickle)
                with open(temp_file, 'wb') as f:
                    f.write(self._serialize_encrypted_data(encrypted_data, salt))
            
            # Detect file format
            format_info = self.format_detector.detect_format(validated_filename, validated_content)
            
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
                "original_size": len(validated_content),
                "encrypted_size": temp_file.stat().st_size,
                "streaming_encrypted": len(validated_content) > StreamingConfig.MEDIUM_FILE_CHUNK_SIZE,
                "serialization_format": "json_base64_v2",  # New safer format
                "security": {
                    "expiration_time": validated_settings.get("expiration_time"),
                    "max_access_count": validated_settings.get("max_access_count"),
                    "deadman_switch": validated_settings.get("deadman_switch"),
                    "disable_export": validated_settings.get("disable_export", False),
                },
                "performance": {
                    "encryption_method": "streaming" if len(validated_content) > StreamingConfig.MEDIUM_FILE_CHUNK_SIZE else "standard",
                    "created_with_async": True
                }
            }
            
            # Move temporary file to final location
            final_file_path = self.files_directory / f"{file_id}.bar"
            temp_file.rename(final_file_path)
            
            # Save metadata
            metadata_path = self.metadata_directory / f"{file_id}.json"
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            await self._finish_operation(operation_id, "completed")
            self.logger.info(f"Created secure file asynchronously: {file_id} ({filename})")
            
            return file_id, operation_id
        
        except Exception as e:
            await self._finish_operation(operation_id, "failed", str(e))
            # Clean up temporary file
            if temp_file.exists():
                temp_file.unlink()
            raise
    
    def _validate_file_content(self, content: Any, field_name: str = "content") -> bytes:
        """Validate file content parameter per Rule R030."""
        content_result = validate_bytes(
            content,
            field_name=field_name,
            min_length=1,
            max_length=1024 * 1024 * 1024  # 1GB max
        )
        if not content_result.is_valid:
            raise FileValidationError(
                content_result.error_message,
                field_name=field_name,
                violation_type=content_result.violation_type
            )
        return content_result.sanitized_value
    
    def _validate_filename(self, filename: Any, field_name: str = "filename") -> str:
        """Validate filename parameter per Rule R030."""
        filename_result = self.file_validator.validate_filename(
            filename,
            field_name=field_name,
            max_length=255,
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
        """Validate password parameter per Rule R030."""
        from ..security.input_validator import get_crypto_validator
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
        """Validate security settings parameter per Rule R030."""
        if not isinstance(security_settings, dict):
            raise FileValidationError(
                "Security settings must be a dictionary",
                field_name=field_name,
                violation_type="invalid_type"
            )
        
        # Basic validation of security settings
        validated_settings = {}
        for key, value in security_settings.items():
            if key in ["expiration_time", "deadman_switch"] and value is not None:
                # Validate datetime or numeric values
                validated_settings[key] = value
            elif key == "max_access_count" and value is not None:
                count_result = validate_integer(
                    value,
                    field_name=f"{field_name}.max_access_count",
                    min_value=1,
                    max_value=1000000
                )
                if not count_result.is_valid:
                    raise FileValidationError(
                        count_result.error_message,
                        field_name=f"{field_name}.max_access_count"
                    )
                validated_settings[key] = count_result.sanitized_value
            elif key == "disable_export":
                if not isinstance(value, bool):
                    raise FileValidationError(
                        "disable_export must be a boolean",
                        field_name=f"{field_name}.disable_export"
                    )
                validated_settings[key] = value
            else:
                validated_settings[key] = value
        
        return validated_settings
    
    def _generate_file_id(self) -> str:
        """Generate a unique file ID."""
        import uuid
        return str(uuid.uuid4())
    
    async def access_file_async(self, file_id: str, password: str,
                              progress_callback=None) -> Tuple[bytes, Dict[str, Any], str]:
        """Access a secure file asynchronously.
        
        Args:
            file_id: The ID of the file to access
            password: The password to decrypt the file
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (file_content, metadata, operation_id)
        """
        # Input validation
        validated_file_id = self._validate_file_id(file_id)
        # SECURITY: When accessing files, we don't re-validate password strength
        # because we're just checking if it decrypts. The password was already
        # validated when the file was created. This allows backward compatibility
        # with files created before stronger password requirements.
        from src.security.input_validator import get_crypto_validator
        crypto_validator = get_crypto_validator()
        password_result = crypto_validator.validate_password(
            password,
            field_name="password",
            min_length=1,  # Accept any password length for decryption
            max_length=1024,
            require_complexity=False  # Skip complexity checks for decryption
        )
        if not password_result.is_valid:
            raise FileValidationError(
                password_result.error_message,
                field_name="password",
                violation_type=password_result.violation_type
            )
        validated_password = password_result.sanitized_value
        
        # Check if file exists
        file_path = self.files_directory / f"{validated_file_id}.bar"
        metadata_path = self.metadata_directory / f"{validated_file_id}.json"
        
        if not file_path.exists() or not metadata_path.exists():
            raise FileNotFoundError(f"File not found: {validated_file_id}")
        
        # Load metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Start operation tracking
        file_size = metadata.get('encrypted_size', file_path.stat().st_size)
        operation_id = await self._start_operation("decrypt", metadata['filename'], file_size)
        
        try:
            async def progress_handler(progress_data):
                await self._update_operation_progress(
                    operation_id,
                    progress_data.get('bytes_processed', 0)
                )
                if progress_callback:
                    await progress_callback(progress_data)
            
            # Check if file was encrypted using streaming
            if metadata.get('streaming_encrypted', False):
                self.logger.info(f"Using streaming decryption for file: {validated_file_id}")
                
                # Read streaming chunks
                with open(file_path, 'r') as f:
                    stream_obj = json.load(f)
                
                if stream_obj.get('version') != 2 or not stream_obj.get('streaming'):
                    raise ValueError("Invalid streaming file format")
                
                # Create async iterator matching AsyncEncryptionManager's expected input
                async def encrypted_chunk_reader():
                    # initial metadata with salt
                    yield {
                        'type': 'metadata',
                        'salt': base64.b64decode(stream_obj['salt']),
                        'chunk_count': 0,
                        'total_size': stream_obj.get('total_size', 0)
                    }
                    total = 0
                    for chunk in stream_obj['chunks']:
                        ct = base64.b64decode(chunk['ciphertext'])
                        nonce = base64.b64decode(chunk['nonce'])
                        idx = chunk['index']
                        total += len(ct)
                        yield {
                            'type': 'chunk',
                            'index': idx,
                            'ciphertext': ct,
                            'nonce': nonce,
                            'size': len(ct)
                        }
                    # final metadata
                    yield {
                        'type': 'final_metadata',
                        'total_chunks': len(stream_obj['chunks']),
                        'total_size': total
                    }
                
                # Decrypt using streaming
                content_chunks = []
                async for decrypted_chunk in self.async_encryption.decrypt_stream_async(
                    encrypted_chunk_reader(), validated_password, progress_handler
                ):
                    content_chunks.append(decrypted_chunk)
                
                content = b''.join(content_chunks)
            
            else:
                # Use regular decryption for files encrypted with standard method
                def decrypt_standard_file():
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    # Deserialize safely
                    encrypted_data, salt = self._deserialize_encrypted_data(data)
                    
                    key = EncryptionManager.derive_key(validated_password, salt)
                    return EncryptionManager.decrypt_data(encrypted_data, key)
                
                loop = asyncio.get_event_loop()
                content = await loop.run_in_executor(self.executor, decrypt_standard_file)
            
            # Update metadata
            metadata['last_accessed'] = datetime.now().isoformat()
            metadata['access_count'] = metadata.get('access_count', 0) + 1
            
            # Save updated metadata
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            await self._finish_operation(operation_id, "completed")
            self.logger.info(f"Accessed file asynchronously: {validated_file_id}")
            
            return content, metadata, operation_id
        
        except Exception as e:
            await self._finish_operation(operation_id, "failed", str(e))
            raise
    
    def _validate_file_id(self, file_id: Any, field_name: str = "file_id") -> str:
        """Validate file ID parameter per Rule R030."""
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
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for async operations."""
        metrics = {
            'async_file_operations': len(self.operation_metrics),
            'memory_usage': self.memory_monitor.get_memory_usage(),
            'active_operations': len(self.active_operations),
            'max_workers': self.max_workers
        }
        
        # Add encryption metrics
        encryption_metrics = self.async_encryption.get_performance_metrics()
        metrics['encryption_performance'] = encryption_metrics
        
        # Calculate operation statistics
        if self.operation_metrics:
            total_bytes = sum(m.data_size for m in self.operation_metrics)
            total_time = sum(m.duration for m in self.operation_metrics)
            avg_throughput = sum(m.throughput for m in self.operation_metrics) / len(self.operation_metrics)
            avg_memory_peak = sum(m.memory_peak for m in self.operation_metrics) / len(self.operation_metrics)
            
            metrics['file_operations'] = {
                'total_bytes_processed': total_bytes,
                'total_time': total_time,
                'average_throughput': avg_throughput,
                'average_memory_peak': avg_memory_peak,
                'operations_count': len(self.operation_metrics)
            }
        
        return metrics
    
    async def list_active_operations(self) -> List[FileOperationProgress]:
        """Get list of all active operations."""
        async with self.operation_lock:
            return list(self.active_operations.values())