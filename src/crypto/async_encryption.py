import asyncio
import os
import time
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, AsyncIterator, Union
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

from src.security.secure_memory import SecureBytes, secure_compare, secure_zero_memory
from src.security.input_validator import (
    get_crypto_validator, CryptographicValidationError, validate_bytes
)
from .encryption import EncryptionManager


@dataclass
class PerformanceMetrics:
    """Performance metrics for encryption operations."""
    operation: str
    data_size: int
    duration: float
    throughput: float  # bytes per second
    memory_peak: int
    timestamp: datetime


class StreamingConfig:
    """Configuration for streaming operations."""
    
    # Buffer sizes optimized for different scenarios
    SMALL_FILE_CHUNK_SIZE = 64 * 1024      # 64KB for files < 1MB
    MEDIUM_FILE_CHUNK_SIZE = 1024 * 1024   # 1MB for files 1MB-100MB
    LARGE_FILE_CHUNK_SIZE = 8 * 1024 * 1024 # 8MB for files > 100MB
    
    # Memory management thresholds
    MAX_MEMORY_USAGE = 512 * 1024 * 1024   # 512MB max memory usage
    GC_THRESHOLD = 256 * 1024 * 1024       # Trigger GC at 256MB
    
    # Performance thresholds
    MIN_THROUGHPUT_MBPS = 10               # Minimum 10MB/s throughput
    ADAPTIVE_CHUNK_SIZE = True             # Enable adaptive chunk sizing
    
    @staticmethod
    def get_optimal_chunk_size(file_size: int, available_memory: int) -> int:
        """Calculate optimal chunk size based on file size and available memory."""
        if file_size < 1024 * 1024:  # < 1MB
            return min(StreamingConfig.SMALL_FILE_CHUNK_SIZE, available_memory // 4)
        elif file_size < 100 * 1024 * 1024:  # < 100MB
            return min(StreamingConfig.MEDIUM_FILE_CHUNK_SIZE, available_memory // 4)
        else:
            return min(StreamingConfig.LARGE_FILE_CHUNK_SIZE, available_memory // 4)


class AsyncEncryptionManager:
    """Async version of EncryptionManager with streaming support and performance optimizations.
    
    This class implements Rule R041 (Performance Requirements) and R042 (Memory Management)
    from the BAR project rules, providing:
    - Async operations for non-blocking UI
    - Streaming support for files up to 1GB
    - Memory-efficient processing
    - Hardware-accelerated crypto where available
    """
    
    def __init__(self, max_workers: int = None, enable_metrics: bool = True):
        """Initialize the async encryption manager.
        
        Args:
            max_workers: Maximum number of worker threads for CPU-intensive operations
            enable_metrics: Whether to collect performance metrics
        """
        # Use CPU count for optimal threading, but limit to reasonable maximum
        self.max_workers = max_workers or min(os.cpu_count() or 4, 8)
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.enable_metrics = enable_metrics
        self.metrics_history = []
        
        # Performance monitoring
        self.current_operations = {}
        self.total_bytes_processed = 0
        self.operation_count = 0
        
        # Crypto validator for input validation (Rule R030)
        self.crypto_validator = get_crypto_validator()
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt for key derivation."""
        return EncryptionManager.generate_salt()
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a random nonce for AES-GCM."""
        return EncryptionManager.generate_nonce()
    
    @staticmethod
    def encrypt_data(data: bytes, key: bytes, aad: bytes = None) -> Dict[str, bytes]:
        """Encrypt data using AES-256-GCM."""
        return EncryptionManager.encrypt_data(data, key, aad)
    
    @staticmethod
    def decrypt_data(encrypted_data: Dict[str, bytes], key: bytes, aad: bytes = None) -> bytes:
        """Decrypt data using AES-256-GCM."""
        return EncryptionManager.decrypt_data(encrypted_data, key, aad)
        
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with cleanup."""
        await self.cleanup()
    
    async def cleanup(self):
        """Clean up resources and shutdown executor."""
        self.executor.shutdown(wait=True)
        
        # Secure cleanup of any remaining sensitive data
        for operation_id in list(self.current_operations.keys()):
            operation = self.current_operations.pop(operation_id)
            if hasattr(operation, 'secure_cleanup'):
                operation.secure_cleanup()
    
    def _record_metric(self, operation: str, data_size: int, duration: float, memory_peak: int = 0):
        """Record performance metric."""
        if not self.enable_metrics:
            return
            
        throughput = data_size / duration if duration > 0 else 0
        metric = PerformanceMetrics(
            operation=operation,
            data_size=data_size,
            duration=duration,
            throughput=throughput,
            memory_peak=memory_peak,
            timestamp=datetime.now()
        )
        
        self.metrics_history.append(metric)
        
        # Keep only recent metrics (last 1000 operations)
        if len(self.metrics_history) > 1000:
            self.metrics_history = self.metrics_history[-1000:]
    
    async def derive_key_async(self, password: str, salt: bytes, 
                              iterations: Optional[int] = None) -> bytes:
        """Async version of key derivation with adaptive iteration count.
        
        Args:
            password: Password string to derive key from
            salt: Random salt bytes for key derivation
            iterations: Optional custom iteration count (auto-calculated if None)
            
        Returns:
            Derived key bytes
            
        Raises:
            CryptographicValidationError: If input validation fails
        """
        start_time = time.time()
        
        # Input validation (Rule R030)
        # SECURITY: Enforce strong password requirements to prevent brute force
        password_result = self.crypto_validator.validate_password(
            password, 
            field_name="password", 
            min_length=12,  # Minimum 12 characters for security
            max_length=1024,
            require_complexity=True  # Enforce complexity and entropy requirements
        )
        if not password_result.is_valid:
            raise CryptographicValidationError(
                password_result.error_message, field_name="password",
                violation_type=password_result.violation_type
            )
        
        salt_result = self.crypto_validator.validate_salt(
            salt, min_size=16, field_name="salt"
        )
        if not salt_result.is_valid:
            raise CryptographicValidationError(
                salt_result.error_message, field_name="salt",
                violation_type=salt_result.violation_type
            )
        
        # Auto-calculate iterations based on hardware capability
        if iterations is None:
            iterations = await self._calculate_optimal_iterations()
        
        # Run key derivation in thread pool to avoid blocking
        def _derive_key():
            with SecureBytes(password_result.sanitized_value) as secure_password:
                password_bytes = secure_password.get_bytes()
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=EncryptionManager.KEY_SIZE,
                    salt=salt_result.sanitized_value,
                    iterations=iterations,
                )
                
                derived_key = kdf.derive(password_bytes)
                
                # Secure cleanup
                if isinstance(password_bytes, bytearray):
                    secure_zero_memory(password_bytes)
                
                return derived_key
        
        loop = asyncio.get_event_loop()
        derived_key = await loop.run_in_executor(self.executor, _derive_key)
        
        # Record performance metrics
        duration = time.time() - start_time
        self._record_metric("key_derivation", len(password), duration)
        
        return derived_key
    
    async def _calculate_optimal_iterations(self) -> int:
        """Calculate optimal PBKDF2 iterations based on hardware performance."""
        def _benchmark_iterations():
            # Quick benchmark to determine optimal iteration count
            # Target: ~100ms for key derivation
            test_password = b"test_password_for_benchmarking"
            test_salt = os.urandom(32)
            
            # Start with base iterations and increase until we hit time target
            target_time = 0.1  # 100ms
            iterations = 100000
            
            while iterations <= 1000000:  # Cap at 1M iterations
                start_time = time.time()
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=test_salt,
                    iterations=iterations,
                )
                kdf.derive(test_password)
                
                duration = time.time() - start_time
                
                if duration >= target_time:
                    return iterations
                
                # Estimate iterations needed for target time
                target_iterations = int(iterations * (target_time / duration))
                iterations = min(target_iterations, iterations * 2)  # Don't jump too much
            
            return min(iterations, 1000000)  # Return capped value
        
        loop = asyncio.get_event_loop()
        optimal_iterations = await loop.run_in_executor(self.executor, _benchmark_iterations)
        
        # Ensure minimum security (Rule R004)
        return max(optimal_iterations, EncryptionManager.PBKDF2_ITERATIONS)
    
    async def encrypt_stream_async(self, data_stream: AsyncIterator[bytes], 
                                  password: str,
                                  chunk_size: Optional[int] = None,
                                  progress_callback=None) -> AsyncIterator[Dict[str, bytes]]:
        """Encrypt data stream asynchronously with memory-efficient processing.
        
        Args:
            data_stream: Async iterator yielding data chunks
            password: Password for encryption
            chunk_size: Optional chunk size (auto-calculated if None)
            progress_callback: Optional callback for progress reporting
            
        Yields:
            Dictionary containing encrypted chunk and metadata
            
        Raises:
            CryptographicValidationError: If input validation fails
        """
        # Generate salt and derive key
        salt = self.generate_salt()
        key = await self.derive_key_async(password, salt)
        
        # Initialize streaming state
        total_processed = 0
        chunk_count = 0
        
        # Yield initial metadata
        yield {
            'type': 'metadata',
            'salt': salt,
            'chunk_count': 0,  # Will be updated at the end
            'total_size': 0    # Will be updated at the end
        }
        
        try:
            async for data_chunk in data_stream:
                # Validate chunk
                chunk_result = validate_bytes(
                    data_chunk, field_name="data_chunk",
                    min_length=0, max_length=StreamingConfig.LARGE_FILE_CHUNK_SIZE
                )
                if not chunk_result.is_valid:
                    raise CryptographicValidationError(
                        chunk_result.error_message, field_name="data_chunk"
                    )
                
                # Encrypt chunk in thread pool
                def _encrypt_chunk():
                    nonce = EncryptionManager.generate_nonce()
                    aesgcm = AESGCM(key)
                    
                    # Include chunk index as AAD for integrity
                    aad = f"chunk_{chunk_count}".encode()
                    ciphertext = aesgcm.encrypt(nonce, chunk_result.sanitized_value, aad)
                    
                    return {
                        'type': 'chunk',
                        'index': chunk_count,
                        'ciphertext': ciphertext,
                        'nonce': nonce,
                        'size': len(chunk_result.sanitized_value)
                    }
                
                loop = asyncio.get_event_loop()
                encrypted_chunk = await loop.run_in_executor(self.executor, _encrypt_chunk)
                
                # Update progress
                total_processed += len(data_chunk)
                chunk_count += 1
                
                if progress_callback:
                    await progress_callback({
                        'bytes_processed': total_processed,
                        'chunks_processed': chunk_count,
                        'current_chunk_size': len(data_chunk)
                    })
                
                yield encrypted_chunk
                
                # Memory management - trigger GC if needed
                if total_processed % StreamingConfig.GC_THRESHOLD == 0:
                    import gc
                    gc.collect()
        
        finally:
            # Secure cleanup of key material
            if isinstance(key, (bytes, bytearray)):
                secure_zero_memory(key)
        
        # Yield final metadata
        yield {
            'type': 'final_metadata',
            'total_chunks': chunk_count,
            'total_size': total_processed
        }
    
    async def decrypt_stream_async(self, encrypted_stream: AsyncIterator[Dict[str, bytes]], 
                                  password: str,
                                  progress_callback=None) -> AsyncIterator[bytes]:
        """Decrypt data stream asynchronously.
        
        Args:
            encrypted_stream: Async iterator yielding encrypted chunks
            password: Password for decryption
            progress_callback: Optional callback for progress reporting
            
        Yields:
            Decrypted data chunks
            
        Raises:
            CryptographicValidationError: If input validation fails
            ValueError: If decryption fails
        """
        # Get initial metadata
        metadata = await encrypted_stream.__anext__()
        if metadata.get('type') != 'metadata':
            raise ValueError("Invalid stream format: missing metadata")
        
        salt = metadata.get('salt')
        if not salt:
            raise ValueError("Invalid stream format: missing salt")
        
        # Derive key
        key = await self.derive_key_async(password, salt)
        
        total_processed = 0
        chunks_processed = 0
        
        try:
            async for encrypted_chunk in encrypted_stream:
                chunk_type = encrypted_chunk.get('type')
                
                if chunk_type == 'chunk':
                    # Decrypt chunk in thread pool
                    def _decrypt_chunk():
                        ciphertext = encrypted_chunk['ciphertext']
                        nonce = encrypted_chunk['nonce']
                        index = encrypted_chunk['index']
                        
                        aesgcm = AESGCM(key)
                        
                        # Reconstruct AAD
                        aad = f"chunk_{index}".encode()
                        
                        try:
                            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
                            return plaintext
                        except Exception as e:
                            raise ValueError(f"Decryption failed for chunk {index}: {e}")
                    
                    loop = asyncio.get_event_loop()
                    decrypted_chunk = await loop.run_in_executor(self.executor, _decrypt_chunk)
                    
                    # Update progress
                    total_processed += len(decrypted_chunk)
                    chunks_processed += 1
                    
                    if progress_callback:
                        await progress_callback({
                            'bytes_processed': total_processed,
                            'chunks_processed': chunks_processed,
                            'current_chunk_size': len(decrypted_chunk)
                        })
                    
                    yield decrypted_chunk
                    
                    # Memory management
                    if total_processed % StreamingConfig.GC_THRESHOLD == 0:
                        import gc
                        gc.collect()
                
                elif chunk_type == 'final_metadata':
                    # Final validation
                    expected_chunks = encrypted_chunk.get('total_chunks', 0)
                    if chunks_processed != expected_chunks:
                        raise ValueError(f"Chunk count mismatch: expected {expected_chunks}, got {chunks_processed}")
                    break
        
        finally:
            # Secure cleanup
            if isinstance(key, (bytes, bytearray)):
                secure_zero_memory(key)
    
    async def encrypt_large_file_async(self, file_path: str, password: str,
                                      output_path: str, 
                                      progress_callback=None) -> Dict[str, Any]:
        """Encrypt a large file asynchronously with streaming.
        
        Args:
            file_path: Path to input file
            password: Encryption password
            output_path: Path for encrypted output file
            progress_callback: Optional progress callback
            
        Returns:
            Dictionary with encryption metadata and performance stats
        """
        start_time = time.time()
        
        # Validate file paths
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        
        # Determine optimal chunk size
        available_memory = StreamingConfig.MAX_MEMORY_USAGE
        chunk_size = StreamingConfig.get_optimal_chunk_size(file_size, available_memory)
        
        async def file_reader():
            """Async generator for reading file chunks."""
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        
        # Encrypt file using streaming
        with open(output_path, 'wb') as output_file:
            async for encrypted_chunk in self.encrypt_stream_async(
                file_reader(), password, chunk_size, progress_callback
            ):
                # Write encrypted chunk to file
                import pickle
                chunk_data = pickle.dumps(encrypted_chunk)
                chunk_size_bytes = len(chunk_data).to_bytes(4, 'big')
                output_file.write(chunk_size_bytes + chunk_data)
        
        # Calculate performance metrics
        duration = time.time() - start_time
        throughput = file_size / duration if duration > 0 else 0
        
        self._record_metric("file_encryption", file_size, duration)
        
        return {
            'input_size': file_size,
            'output_size': os.path.getsize(output_path),
            'duration': duration,
            'throughput': throughput,
            'chunk_size': chunk_size,
            'chunks_processed': file_size // chunk_size + (1 if file_size % chunk_size else 0)
        }
    
    async def decrypt_large_file_async(self, encrypted_file_path: str, password: str,
                                      output_path: str,
                                      progress_callback=None) -> Dict[str, Any]:
        """Decrypt a large file asynchronously with streaming.
        
        Args:
            encrypted_file_path: Path to encrypted file
            password: Decryption password
            output_path: Path for decrypted output file
            progress_callback: Optional progress callback
            
        Returns:
            Dictionary with decryption metadata and performance stats
        """
        start_time = time.time()
        
        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")
        
        encrypted_file_size = os.path.getsize(encrypted_file_path)
        
        async def encrypted_file_reader():
            """Async generator for reading encrypted file chunks."""
            with open(encrypted_file_path, 'rb') as f:
                while True:
                    # Read chunk size
                    size_bytes = f.read(4)
                    if not size_bytes:
                        break
                    
                    chunk_size = int.from_bytes(size_bytes, 'big')
                    chunk_data = f.read(chunk_size)
                    
                    if len(chunk_data) != chunk_size:
                        raise ValueError("Corrupted encrypted file: chunk size mismatch")
                    
                    import pickle
                    yield pickle.loads(chunk_data)
        
        # Decrypt file using streaming
        total_decrypted = 0
        with open(output_path, 'wb') as output_file:
            async for decrypted_chunk in self.decrypt_stream_async(
                encrypted_file_reader(), password, progress_callback
            ):
                output_file.write(decrypted_chunk)
                total_decrypted += len(decrypted_chunk)
        
        # Calculate performance metrics
        duration = time.time() - start_time
        throughput = total_decrypted / duration if duration > 0 else 0
        
        self._record_metric("file_decryption", total_decrypted, duration)
        
        return {
            'input_size': encrypted_file_size,
            'output_size': total_decrypted,
            'duration': duration,
            'throughput': throughput
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics summary."""
        if not self.metrics_history:
            return {'total_operations': 0}
        
        # Calculate aggregate statistics
        total_ops = len(self.metrics_history)
        total_bytes = sum(m.data_size for m in self.metrics_history)
        total_time = sum(m.duration for m in self.metrics_history)
        avg_throughput = sum(m.throughput for m in self.metrics_history) / total_ops
        
        # Get metrics by operation type
        by_operation = {}
        for metric in self.metrics_history:
            op = metric.operation
            if op not in by_operation:
                by_operation[op] = []
            by_operation[op].append(metric)
        
        operation_stats = {}
        for op, metrics in by_operation.items():
            operation_stats[op] = {
                'count': len(metrics),
                'total_bytes': sum(m.data_size for m in metrics),
                'total_time': sum(m.duration for m in metrics),
                'avg_throughput': sum(m.throughput for m in metrics) / len(metrics),
                'max_throughput': max(m.throughput for m in metrics),
                'min_throughput': min(m.throughput for m in metrics)
            }
        
        return {
            'total_operations': total_ops,
            'total_bytes_processed': total_bytes,
            'total_time': total_time,
            'overall_avg_throughput': avg_throughput,
            'by_operation': operation_stats,
            'max_workers': self.max_workers
        }