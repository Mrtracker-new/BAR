#!/usr/bin/env python3
"""
Secure Memory Performance Benchmark Module

This module provides comprehensive performance benchmarking for secure memory operations
in the BAR project, ensuring compliance with R041-R043 performance requirements.

Per BAR Project Rules:
- R041: Handle files up to 1GB without excessive memory usage
- R042: Memory-efficient file processing with proper resource management
- R043: Thread-safe operations with proper synchronization

Author: Rolan Lobo (RNR)
Version: 1.0.0
"""

import os
import sys
import time
import threading
import multiprocessing
import statistics
import gc
from typing import Dict, List, Tuple, Any, Callable

# Optional imports for cross-platform compatibility
try:
    import resource
    RESOURCE_AVAILABLE = True
except ImportError:
    RESOURCE_AVAILABLE = False
from dataclasses import dataclass, field
from pathlib import Path
import logging
import secrets
import psutil

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security.secure_memory import (
    SecureBytes, SecureString, MemoryProtectionLevel,
    create_secure_bytes, create_secure_string,
    get_secure_memory_manager, force_secure_memory_cleanup,
    secure_memory_context, TPMInterface, AntiForensicsMonitor
)


@dataclass
class BenchmarkResult:
    """Results from a performance benchmark test."""
    test_name: str
    data_size: int
    iterations: int
    total_time: float
    avg_time: float
    min_time: float
    max_time: float
    memory_usage_mb: float
    memory_peak_mb: float
    throughput_mbps: float
    success_rate: float
    additional_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemBenchmark:
    """System-level performance metrics."""
    cpu_count: int
    memory_total_gb: float
    memory_available_gb: float
    platform: str
    python_version: str
    tpm_available: bool
    timestamp: float


class SecureMemoryBenchmark:
    """Comprehensive performance benchmark suite for secure memory operations.
    
    Per R041-R043: Ensures memory operations meet performance requirements
    while maintaining security standards.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("SecureMemoryBenchmark")
        self.results: List[BenchmarkResult] = []
        self.system_info = self._gather_system_info()
        
        # Performance targets per BAR project rules
        self.performance_targets = {
            'max_allocation_time_ms': 100,    # Max 100ms to allocate secure memory
            'max_clear_time_ms': 50,          # Max 50ms to clear sensitive data
            'min_throughput_mbps': 50,        # Min 50 MB/s throughput
            'max_memory_overhead_percent': 25, # Max 25% memory overhead
            'max_lock_time_ms': 10,           # Max 10ms to lock memory
        }
        
        self.logger.info(f"Benchmark initialized on {self.system_info.platform}")
        self.logger.info(f"System: {self.system_info.cpu_count} CPUs, {self.system_info.memory_total_gb:.1f}GB RAM")
    
    def _gather_system_info(self) -> SystemBenchmark:
        """Gather system information for benchmark context."""
        memory = psutil.virtual_memory()
        tpm_interface = TPMInterface()
        
        return SystemBenchmark(
            cpu_count=multiprocessing.cpu_count(),
            memory_total_gb=memory.total / (1024**3),
            memory_available_gb=memory.available / (1024**3),
            platform=f"{sys.platform}-{os.name}",
            python_version=sys.version.split()[0],
            tpm_available=tpm_interface.is_available(),
            timestamp=time.time()
        )
    
    def benchmark_allocation_performance(self) -> BenchmarkResult:
        """Benchmark secure memory allocation performance.
        
        Tests allocation times for different data sizes and protection levels.
        """
        self.logger.info("Starting allocation performance benchmark")
        
        data_sizes = [1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024]  # 1KB to 10MB
        protection_levels = [
            MemoryProtectionLevel.BASIC,
            MemoryProtectionLevel.ENHANCED,
            MemoryProtectionLevel.MAXIMUM
        ]
        
        all_times = []
        total_data_size = 0
        successful_allocations = 0
        total_allocations = 0
        max_memory = 0
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        for size in data_sizes:
            for protection_level in protection_levels:
                test_data = secrets.token_bytes(size)
                iterations = max(1, 1000000 // size)  # Scale iterations by size
                
                times = []
                for i in range(iterations):
                    gc.collect()  # Clean slate for each test
                    
                    start_time = time.perf_counter()
                    try:
                        secure_obj = SecureBytes(
                            test_data, 
                            protection_level=protection_level,
                            require_lock=False
                        )
                        end_time = time.perf_counter()
                        
                        allocation_time = (end_time - start_time) * 1000  # Convert to ms
                        times.append(allocation_time)
                        successful_allocations += 1
                        
                        # Track memory usage
                        current_memory = process.memory_info().rss
                        max_memory = max(max_memory, current_memory)
                        
                        # Clean up
                        secure_obj.clear()
                        del secure_obj
                        
                    except Exception as e:
                        self.logger.warning(f"Allocation failed for {size} bytes: {e}")
                    
                    total_allocations += 1
                
                if times:
                    all_times.extend(times)
                    total_data_size += size * len(times)
                    
                    avg_time = statistics.mean(times)
                    if avg_time > self.performance_targets['max_allocation_time_ms']:
                        self.logger.warning(
                            f"Allocation time {avg_time:.2f}ms exceeds target "
                            f"{self.performance_targets['max_allocation_time_ms']}ms for {size} bytes"
                        )
        
        # Calculate final metrics
        total_time = sum(all_times) / 1000  # Convert to seconds
        memory_overhead = (max_memory - initial_memory) / (1024**2)  # MB
        throughput = (total_data_size / (1024**2)) / total_time if total_time > 0 else 0  # MB/s
        success_rate = successful_allocations / total_allocations if total_allocations > 0 else 0
        
        result = BenchmarkResult(
            test_name="allocation_performance",
            data_size=total_data_size,
            iterations=len(all_times),
            total_time=total_time,
            avg_time=statistics.mean(all_times) if all_times else 0,
            min_time=min(all_times) if all_times else 0,
            max_time=max(all_times) if all_times else 0,
            memory_usage_mb=memory_overhead,
            memory_peak_mb=max_memory / (1024**2),
            throughput_mbps=throughput,
            success_rate=success_rate,
            additional_metrics={
                'total_allocations': total_allocations,
                'successful_allocations': successful_allocations,
                'target_allocation_time_ms': self.performance_targets['max_allocation_time_ms'],
                'target_throughput_mbps': self.performance_targets['min_throughput_mbps']
            }
        )
        
        self.results.append(result)
        self.logger.info(f"Allocation benchmark completed: {throughput:.1f} MB/s, {success_rate:.1%} success rate")
        return result
    
    def benchmark_clearing_performance(self) -> BenchmarkResult:
        """Benchmark secure memory clearing performance."""
        self.logger.info("Starting clearing performance benchmark")
        
        data_sizes = [1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024]
        protection_levels = [MemoryProtectionLevel.BASIC, MemoryProtectionLevel.ENHANCED, MemoryProtectionLevel.MAXIMUM]
        
        all_times = []
        total_data_size = 0
        successful_clears = 0
        total_clears = 0
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        max_memory = initial_memory
        
        for size in data_sizes:
            for protection_level in protection_levels:
                test_data = secrets.token_bytes(size)
                iterations = max(1, 500000 // size)
                
                for i in range(iterations):
                    try:
                        # Create secure object
                        secure_obj = SecureBytes(test_data, protection_level=protection_level)
                        
                        # Measure clearing time
                        start_time = time.perf_counter()
                        secure_obj.clear()
                        end_time = time.perf_counter()
                        
                        clear_time = (end_time - start_time) * 1000  # Convert to ms
                        all_times.append(clear_time)
                        successful_clears += 1
                        total_data_size += size
                        
                        # Track memory
                        current_memory = process.memory_info().rss
                        max_memory = max(max_memory, current_memory)
                        
                        del secure_obj
                        
                    except Exception as e:
                        self.logger.warning(f"Clear failed for {size} bytes: {e}")
                    
                    total_clears += 1
                    
                    if i % 100 == 0:  # Periodic cleanup
                        gc.collect()
        
        # Calculate metrics
        total_time = sum(all_times) / 1000
        memory_overhead = (max_memory - initial_memory) / (1024**2)
        throughput = (total_data_size / (1024**2)) / total_time if total_time > 0 else 0
        success_rate = successful_clears / total_clears if total_clears > 0 else 0
        
        result = BenchmarkResult(
            test_name="clearing_performance",
            data_size=total_data_size,
            iterations=len(all_times),
            total_time=total_time,
            avg_time=statistics.mean(all_times) if all_times else 0,
            min_time=min(all_times) if all_times else 0,
            max_time=max(all_times) if all_times else 0,
            memory_usage_mb=memory_overhead,
            memory_peak_mb=max_memory / (1024**2),
            throughput_mbps=throughput,
            success_rate=success_rate,
            additional_metrics={
                'target_clear_time_ms': self.performance_targets['max_clear_time_ms'],
                'violations': sum(1 for t in all_times if t > self.performance_targets['max_clear_time_ms'])
            }
        )
        
        self.results.append(result)
        self.logger.info(f"Clearing benchmark completed: {throughput:.1f} MB/s, {success_rate:.1%} success rate")
        return result
    
    def benchmark_concurrent_access(self) -> BenchmarkResult:
        """Benchmark concurrent access performance and thread safety."""
        self.logger.info("Starting concurrent access benchmark")
        
        num_threads = min(16, multiprocessing.cpu_count() * 2)
        iterations_per_thread = 1000
        test_data = secrets.token_bytes(64 * 1024)  # 64KB test data
        
        # Create shared secure object
        shared_secure_obj = SecureBytes(test_data, MemoryProtectionLevel.ENHANCED)
        
        results_lock = threading.Lock()
        thread_results = []
        errors = []
        
        def worker_thread(thread_id: int):
            """Worker thread for concurrent access testing."""
            thread_times = []
            thread_errors = []
            
            for i in range(iterations_per_thread):
                start_time = time.perf_counter()
                try:
                    # Test concurrent read access
                    data = shared_secure_obj.get_bytes()
                    
                    # Verify data integrity
                    if data != test_data:
                        thread_errors.append(f"Thread {thread_id}: Data integrity violation at iteration {i}")
                    
                    # Test string conversion
                    if len(data) < 1000:  # Only for smaller data to avoid encoding issues
                        try:
                            data_str = data.decode('utf-8', errors='ignore')
                        except Exception:
                            pass  # Ignore encoding errors for random data
                    
                    end_time = time.perf_counter()
                    access_time = (end_time - start_time) * 1000
                    thread_times.append(access_time)
                    
                except Exception as e:
                    thread_errors.append(f"Thread {thread_id}: {str(e)}")
                    end_time = time.perf_counter()
                    access_time = (end_time - start_time) * 1000
                    thread_times.append(access_time)
            
            with results_lock:
                thread_results.extend(thread_times)
                errors.extend(thread_errors)
        
        # Start threads
        threads = []
        start_time = time.perf_counter()
        
        for i in range(num_threads):
            thread = threading.Thread(target=worker_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        # Calculate metrics
        total_operations = len(thread_results)
        successful_operations = total_operations - len(errors)
        success_rate = successful_operations / total_operations if total_operations > 0 else 0
        
        avg_time = statistics.mean(thread_results) if thread_results else 0
        throughput = (total_operations * len(test_data) / (1024**2)) / total_time if total_time > 0 else 0
        
        result = BenchmarkResult(
            test_name="concurrent_access",
            data_size=len(test_data) * total_operations,
            iterations=total_operations,
            total_time=total_time,
            avg_time=avg_time,
            min_time=min(thread_results) if thread_results else 0,
            max_time=max(thread_results) if thread_results else 0,
            memory_usage_mb=0,  # Not measured for this test
            memory_peak_mb=0,
            throughput_mbps=throughput,
            success_rate=success_rate,
            additional_metrics={
                'num_threads': num_threads,
                'iterations_per_thread': iterations_per_thread,
                'errors': len(errors),
                'error_rate': len(errors) / total_operations if total_operations > 0 else 0
            }
        )
        
        # Cleanup
        shared_secure_obj.clear()
        
        self.results.append(result)
        self.logger.info(f"Concurrent access benchmark completed: {num_threads} threads, {success_rate:.1%} success rate")
        
        if errors:
            self.logger.warning(f"Concurrent access errors: {len(errors)}")
            for error in errors[:5]:  # Log first 5 errors
                self.logger.warning(f"  {error}")
        
        return result
    
    def benchmark_memory_locking(self) -> BenchmarkResult:
        """Benchmark memory locking performance across different platforms."""
        self.logger.info("Starting memory locking benchmark")
        
        data_sizes = [4096, 65536, 1024*1024, 10*1024*1024]  # 4KB to 10MB
        lock_times = []
        unlock_times = []
        successful_locks = 0
        total_attempts = 0
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        max_memory = initial_memory
        
        for size in data_sizes:
            iterations = max(1, 100000 // size)
            test_data = secrets.token_bytes(size)
            
            for i in range(iterations):
                try:
                    # Measure lock time
                    secure_obj = SecureBytes(test_data, require_lock=False)
                    
                    start_time = time.perf_counter()
                    secure_obj._attempt_memory_lock()
                    lock_end_time = time.perf_counter()
                    
                    lock_time = (lock_end_time - start_time) * 1000
                    lock_times.append(lock_time)
                    
                    if secure_obj._locked:
                        successful_locks += 1
                    
                    # Measure unlock time
                    unlock_start_time = time.perf_counter()
                    secure_obj._unlock_memory()
                    unlock_end_time = time.perf_counter()
                    
                    unlock_time = (unlock_end_time - unlock_start_time) * 1000
                    unlock_times.append(unlock_time)
                    
                    # Track memory
                    current_memory = process.memory_info().rss
                    max_memory = max(max_memory, current_memory)
                    
                    secure_obj.clear()
                    del secure_obj
                    
                except Exception as e:
                    self.logger.debug(f"Memory locking test failed for {size} bytes: {e}")
                
                total_attempts += 1
                
                if i % 100 == 0:
                    gc.collect()
        
        # Calculate metrics
        all_times = lock_times + unlock_times
        total_time = sum(all_times) / 1000
        lock_success_rate = successful_locks / total_attempts if total_attempts > 0 else 0
        memory_overhead = (max_memory - initial_memory) / (1024**2)
        
        avg_lock_time = statistics.mean(lock_times) if lock_times else 0
        avg_unlock_time = statistics.mean(unlock_times) if unlock_times else 0
        
        result = BenchmarkResult(
            test_name="memory_locking",
            data_size=sum(data_sizes) * total_attempts,
            iterations=len(all_times),
            total_time=total_time,
            avg_time=statistics.mean(all_times) if all_times else 0,
            min_time=min(all_times) if all_times else 0,
            max_time=max(all_times) if all_times else 0,
            memory_usage_mb=memory_overhead,
            memory_peak_mb=max_memory / (1024**2),
            throughput_mbps=0,  # Not applicable for this test
            success_rate=lock_success_rate,
            additional_metrics={
                'avg_lock_time_ms': avg_lock_time,
                'avg_unlock_time_ms': avg_unlock_time,
                'max_lock_time_ms': max(lock_times) if lock_times else 0,
                'lock_target_ms': self.performance_targets['max_lock_time_ms'],
                'lock_violations': sum(1 for t in lock_times if t > self.performance_targets['max_lock_time_ms']),
                'platform': sys.platform
            }
        )
        
        self.results.append(result)
        self.logger.info(f"Memory locking benchmark completed: {lock_success_rate:.1%} lock success rate")
        return result
    
    def benchmark_large_data_handling(self) -> BenchmarkResult:
        """Benchmark handling of large data blocks up to 1GB per R041."""
        self.logger.info("Starting large data handling benchmark")
        
        # Test sizes up to 1GB (but scaled down for practical testing)
        if self.system_info.memory_available_gb < 4:
            # Scale down for systems with limited memory
            max_size = min(100 * 1024 * 1024, int(self.system_info.memory_available_gb * 1024**3 // 10))
            self.logger.info(f"Scaling down max size to {max_size // (1024**2)}MB due to limited system memory")
        else:
            max_size = 500 * 1024 * 1024  # 500MB max for testing
        
        data_sizes = [
            50 * 1024 * 1024,   # 50MB
            100 * 1024 * 1024,  # 100MB
            max_size            # Maximum size
        ]
        
        results_list = []
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        for size in data_sizes:
            if size > self.system_info.memory_available_gb * 1024**3 * 0.8:
                self.logger.info(f"Skipping {size // (1024**2)}MB test - insufficient memory")
                continue
            
            self.logger.info(f"Testing large data handling: {size // (1024**2)}MB")
            
            try:
                # Generate test data
                self.logger.debug("Generating test data...")
                test_data = secrets.token_bytes(size)
                
                # Test allocation
                start_time = time.perf_counter()
                secure_obj = SecureBytes(test_data, MemoryProtectionLevel.ENHANCED)
                allocation_time = time.perf_counter() - start_time
                
                current_memory = process.memory_info().rss
                memory_usage = (current_memory - initial_memory) / (1024**2)
                
                # Test access
                access_start = time.perf_counter()
                retrieved_data = secure_obj.get_bytes()
                access_time = time.perf_counter() - access_start
                
                # Verify data integrity
                data_integrity = retrieved_data == test_data
                
                # Test clearing
                clear_start = time.perf_counter()
                secure_obj.clear()
                clear_time = time.perf_counter() - clear_start
                
                # Calculate throughput
                total_time = allocation_time + access_time + clear_time
                throughput = (size / (1024**2)) / total_time if total_time > 0 else 0
                
                results_list.append({
                    'size_mb': size // (1024**2),
                    'allocation_time': allocation_time,
                    'access_time': access_time,
                    'clear_time': clear_time,
                    'total_time': total_time,
                    'memory_usage_mb': memory_usage,
                    'throughput_mbps': throughput,
                    'data_integrity': data_integrity
                })
                
                del secure_obj, test_data, retrieved_data
                gc.collect()
                
                self.logger.info(f"  {size // (1024**2)}MB: {throughput:.1f} MB/s, {memory_usage:.1f}MB overhead")
                
            except Exception as e:
                self.logger.error(f"Large data test failed for {size // (1024**2)}MB: {e}")
                results_list.append({
                    'size_mb': size // (1024**2),
                    'error': str(e)
                })
        
        # Calculate aggregate metrics
        successful_tests = [r for r in results_list if 'error' not in r]
        if successful_tests:
            avg_throughput = statistics.mean([r['throughput_mbps'] for r in successful_tests])
            max_memory = max([r['memory_usage_mb'] for r in successful_tests])
            total_data = sum([r['size_mb'] for r in successful_tests])
            total_time = sum([r['total_time'] for r in successful_tests])
            success_rate = len(successful_tests) / len(results_list)
        else:
            avg_throughput = 0
            max_memory = 0
            total_data = 0
            total_time = 0
            success_rate = 0
        
        result = BenchmarkResult(
            test_name="large_data_handling",
            data_size=total_data * 1024**2,  # Convert back to bytes
            iterations=len(results_list),
            total_time=total_time,
            avg_time=total_time / len(results_list) if results_list else 0,
            min_time=min([r.get('total_time', 0) for r in successful_tests]) if successful_tests else 0,
            max_time=max([r.get('total_time', 0) for r in successful_tests]) if successful_tests else 0,
            memory_usage_mb=max_memory,
            memory_peak_mb=max_memory,
            throughput_mbps=avg_throughput,
            success_rate=success_rate,
            additional_metrics={
                'detailed_results': results_list,
                'target_max_size_gb': 1.0,
                'target_min_throughput_mbps': self.performance_targets['min_throughput_mbps'],
                'meets_1gb_requirement': max([r.get('size_mb', 0) for r in results_list]) >= 1000
            }
        )
        
        self.results.append(result)
        self.logger.info(f"Large data benchmark completed: {avg_throughput:.1f} MB/s average throughput")
        return result
    
    def run_full_benchmark_suite(self) -> Dict[str, BenchmarkResult]:
        """Run the complete benchmark suite."""
        self.logger.info("Starting full benchmark suite")
        self.logger.info(f"System: {self.system_info.platform}, {self.system_info.cpu_count} CPUs, {self.system_info.memory_total_gb:.1f}GB RAM")
        
        suite_start = time.time()
        
        # Clear any existing results
        self.results.clear()
        force_secure_memory_cleanup()
        
        benchmarks = [
            ("Allocation Performance", self.benchmark_allocation_performance),
            ("Clearing Performance", self.benchmark_clearing_performance),
            ("Concurrent Access", self.benchmark_concurrent_access),
            ("Memory Locking", self.benchmark_memory_locking),
            ("Large Data Handling", self.benchmark_large_data_handling),
        ]
        
        results_dict = {}
        
        for name, benchmark_func in benchmarks:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Running: {name}")
            self.logger.info(f"{'='*60}")
            
            try:
                result = benchmark_func()
                results_dict[result.test_name] = result
                
                # Check against performance targets
                self._check_performance_targets(result)
                
            except Exception as e:
                self.logger.error(f"Benchmark {name} failed: {e}")
                
            # Cleanup between tests
            force_secure_memory_cleanup()
            gc.collect()
            
            # Brief pause between tests
            time.sleep(1)
        
        suite_end = time.time()
        suite_duration = suite_end - suite_start
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"BENCHMARK SUITE COMPLETED")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Total duration: {suite_duration:.1f} seconds")
        self.logger.info(f"Tests completed: {len(results_dict)}")
        
        # Generate summary report
        self._generate_summary_report(results_dict)
        
        return results_dict
    
    def _check_performance_targets(self, result: BenchmarkResult):
        """Check benchmark results against performance targets."""
        violations = []
        
        if result.test_name == "allocation_performance":
            if result.avg_time > self.performance_targets['max_allocation_time_ms']:
                violations.append(f"Average allocation time {result.avg_time:.1f}ms exceeds target {self.performance_targets['max_allocation_time_ms']}ms")
            
            if result.throughput_mbps < self.performance_targets['min_throughput_mbps']:
                violations.append(f"Throughput {result.throughput_mbps:.1f} MB/s below target {self.performance_targets['min_throughput_mbps']} MB/s")
        
        elif result.test_name == "clearing_performance":
            if result.avg_time > self.performance_targets['max_clear_time_ms']:
                violations.append(f"Average clear time {result.avg_time:.1f}ms exceeds target {self.performance_targets['max_clear_time_ms']}ms")
        
        elif result.test_name == "memory_locking":
            avg_lock_time = result.additional_metrics.get('avg_lock_time_ms', 0)
            if avg_lock_time > self.performance_targets['max_lock_time_ms']:
                violations.append(f"Average lock time {avg_lock_time:.1f}ms exceeds target {self.performance_targets['max_lock_time_ms']}ms")
        
        # Log violations
        for violation in violations:
            self.logger.warning(f"PERFORMANCE TARGET VIOLATION: {violation}")
    
    def _generate_summary_report(self, results_dict: Dict[str, BenchmarkResult]):
        """Generate a comprehensive summary report."""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("PERFORMANCE SUMMARY REPORT")
        self.logger.info(f"{'='*60}")
        
        for test_name, result in results_dict.items():
            self.logger.info(f"\n{test_name.upper()}:")
            self.logger.info(f"  Data processed: {result.data_size / (1024**2):.1f} MB")
            self.logger.info(f"  Iterations: {result.iterations}")
            self.logger.info(f"  Average time: {result.avg_time:.2f} ms")
            self.logger.info(f"  Throughput: {result.throughput_mbps:.1f} MB/s")
            self.logger.info(f"  Success rate: {result.success_rate:.1%}")
            self.logger.info(f"  Memory usage: {result.memory_usage_mb:.1f} MB")
        
        # Overall assessment
        avg_throughput = statistics.mean([r.throughput_mbps for r in results_dict.values() if r.throughput_mbps > 0])
        avg_success_rate = statistics.mean([r.success_rate for r in results_dict.values()])
        
        self.logger.info(f"\nOVERALL ASSESSMENT:")
        self.logger.info(f"  Average throughput: {avg_throughput:.1f} MB/s")
        self.logger.info(f"  Average success rate: {avg_success_rate:.1%}")
        self.logger.info(f"  Platform: {self.system_info.platform}")
        self.logger.info(f"  TPM available: {self.system_info.tpm_available}")
        
        # Performance grade
        if avg_throughput >= self.performance_targets['min_throughput_mbps'] and avg_success_rate >= 0.95:
            grade = "EXCELLENT"
        elif avg_throughput >= self.performance_targets['min_throughput_mbps'] * 0.8 and avg_success_rate >= 0.90:
            grade = "GOOD"
        elif avg_throughput >= self.performance_targets['min_throughput_mbps'] * 0.6 and avg_success_rate >= 0.80:
            grade = "ACCEPTABLE"
        else:
            grade = "NEEDS IMPROVEMENT"
        
        self.logger.info(f"  Performance Grade: {grade}")


def main():
    """Main benchmark execution function."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    benchmark = SecureMemoryBenchmark()
    
    try:
        results = benchmark.run_full_benchmark_suite()
        
        # Optional: Save results to file
        import json
        results_json = {}
        for name, result in results.items():
            results_json[name] = {
                'test_name': result.test_name,
                'data_size': result.data_size,
                'iterations': result.iterations,
                'total_time': result.total_time,
                'avg_time': result.avg_time,
                'min_time': result.min_time,
                'max_time': result.max_time,
                'memory_usage_mb': result.memory_usage_mb,
                'memory_peak_mb': result.memory_peak_mb,
                'throughput_mbps': result.throughput_mbps,
                'success_rate': result.success_rate,
                'additional_metrics': result.additional_metrics
            }
        
        output_file = Path(__file__).parent / "benchmark_results.json"
        with open(output_file, 'w') as f:
            json.dump({
                'system_info': {
                    'cpu_count': benchmark.system_info.cpu_count,
                    'memory_total_gb': benchmark.system_info.memory_total_gb,
                    'platform': benchmark.system_info.platform,
                    'python_version': benchmark.system_info.python_version,
                    'timestamp': benchmark.system_info.timestamp
                },
                'results': results_json
            }, f, indent=2)
        
        print(f"\nBenchmark results saved to: {output_file}")
        
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
    except Exception as e:
        logging.error(f"Benchmark failed: {e}")
        raise


if __name__ == "__main__":
    main()
