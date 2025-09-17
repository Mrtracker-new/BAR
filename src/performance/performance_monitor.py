import asyncio
import time
import psutil
import logging
import threading
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from pathlib import Path
import platform
import gc

# Performance-related imports
try:
    import cProfile
    import pstats
    import io
    PROFILING_AVAILABLE = True
except ImportError:
    PROFILING_AVAILABLE = False

try:
    import tracemalloc
    MEMORY_PROFILING_AVAILABLE = True
except ImportError:
    MEMORY_PROFILING_AVAILABLE = False


@dataclass
class SystemMetrics:
    """System-level performance metrics."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_rss: int  # Resident Set Size in bytes
    memory_vms: int  # Virtual Memory Size in bytes
    disk_io_read: int  # Bytes read from disk
    disk_io_write: int  # Bytes written to disk
    network_io_sent: int  # Bytes sent over network
    network_io_recv: int  # Bytes received over network
    open_file_descriptors: int
    thread_count: int
    process_count: int


@dataclass
class OperationMetrics:
    """Metrics for a specific operation."""
    operation_id: str
    operation_type: str  # 'encryption', 'decryption', 'file_scan', 'file_access'
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    data_size_bytes: int = 0
    throughput_bytes_per_second: float = 0.0
    memory_peak_bytes: int = 0
    cpu_time_seconds: float = 0.0
    success: bool = True
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ComponentMetrics:
    """Performance metrics for a system component."""
    component_name: str
    timestamp: datetime
    operations_per_second: float
    average_response_time: float
    error_rate: float
    active_connections: int
    queue_size: int
    memory_usage_bytes: int
    cpu_usage_percent: float


@dataclass
class PerformanceThreshold:
    """Performance threshold for monitoring."""
    metric_name: str
    warning_value: float
    critical_value: float
    comparison: str  # 'greater_than', 'less_than'
    enabled: bool = True
    callback: Optional[Callable] = None


class PerformanceOptimizer:
    """Automatic performance optimization based on system metrics."""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.optimization_history = []
        self.optimization_lock = asyncio.Lock()
        
        # Optimization parameters
        self.min_optimization_interval = 30  # seconds
        self.last_optimization = {}
        
        self.logger = logging.getLogger("PerformanceOptimizer")
    
    async def analyze_and_optimize(self) -> Dict[str, Any]:
        """Analyze current performance and apply optimizations."""
        async with self.optimization_lock:
            current_time = datetime.now()
            
            # Get recent metrics
            recent_metrics = self.monitor.get_recent_system_metrics(300)  # Last 5 minutes
            if len(recent_metrics) < 10:  # Need sufficient data
                return {'status': 'insufficient_data'}
            
            optimizations_applied = []
            
            # CPU optimization
            cpu_optimization = await self._optimize_cpu_usage(recent_metrics)
            if cpu_optimization:
                optimizations_applied.append(cpu_optimization)
            
            # Memory optimization
            memory_optimization = await self._optimize_memory_usage(recent_metrics)
            if memory_optimization:
                optimizations_applied.append(memory_optimization)
            
            # I/O optimization
            io_optimization = await self._optimize_io_performance(recent_metrics)
            if io_optimization:
                optimizations_applied.append(io_optimization)
            
            # Threading optimization
            threading_optimization = await self._optimize_threading()
            if threading_optimization:
                optimizations_applied.append(threading_optimization)
            
            # Record optimization event
            optimization_event = {
                'timestamp': current_time.isoformat(),
                'optimizations_applied': optimizations_applied,
                'system_state': {
                    'avg_cpu': sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics),
                    'avg_memory': sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
                }
            }
            
            self.optimization_history.append(optimization_event)
            
            # Keep only recent optimization history
            if len(self.optimization_history) > 100:
                self.optimization_history = self.optimization_history[-100:]
            
            return {
                'status': 'completed',
                'optimizations_count': len(optimizations_applied),
                'optimizations': optimizations_applied
            }
    
    async def _optimize_cpu_usage(self, metrics: List[SystemMetrics]) -> Optional[Dict[str, Any]]:
        """Optimize CPU usage based on metrics."""
        avg_cpu = sum(m.cpu_percent for m in metrics) / len(metrics)
        
        if avg_cpu > 80:  # High CPU usage
            # Reduce thread pool sizes
            if hasattr(self.monitor, 'async_file_manager'):
                current_workers = getattr(self.monitor.async_file_manager, 'max_workers', 8)
                if current_workers > 2:
                    new_workers = max(2, current_workers - 2)
                    # Note: In practice, you'd need to implement thread pool resizing
                    return {
                        'type': 'cpu_optimization',
                        'action': 'reduce_thread_pool',
                        'old_workers': current_workers,
                        'new_workers': new_workers,
                        'reason': f'High CPU usage: {avg_cpu:.1f}%'
                    }
        
        elif avg_cpu < 30:  # Low CPU usage, can increase performance
            if hasattr(self.monitor, 'async_file_manager'):
                current_workers = getattr(self.monitor.async_file_manager, 'max_workers', 8)
                max_possible = min(os.cpu_count() or 4, 16)
                if current_workers < max_possible:
                    new_workers = min(max_possible, current_workers + 1)
                    return {
                        'type': 'cpu_optimization',
                        'action': 'increase_thread_pool',
                        'old_workers': current_workers,
                        'new_workers': new_workers,
                        'reason': f'Low CPU usage: {avg_cpu:.1f}%'
                    }
        
        return None
    
    async def _optimize_memory_usage(self, metrics: List[SystemMetrics]) -> Optional[Dict[str, Any]]:
        """Optimize memory usage based on metrics."""
        avg_memory = sum(m.memory_percent for m in metrics) / len(metrics)
        
        if avg_memory > 85:  # High memory usage
            # Force garbage collection
            gc.collect()
            
            # Reduce buffer sizes
            from src.crypto.async_encryption import StreamingConfig
            if StreamingConfig.LARGE_FILE_CHUNK_SIZE > 1024 * 1024:  # > 1MB
                old_size = StreamingConfig.LARGE_FILE_CHUNK_SIZE
                StreamingConfig.LARGE_FILE_CHUNK_SIZE = max(
                    1024 * 1024,  # Minimum 1MB
                    StreamingConfig.LARGE_FILE_CHUNK_SIZE // 2
                )
                return {
                    'type': 'memory_optimization',
                    'action': 'reduce_buffer_sizes',
                    'old_chunk_size': old_size,
                    'new_chunk_size': StreamingConfig.LARGE_FILE_CHUNK_SIZE,
                    'reason': f'High memory usage: {avg_memory:.1f}%'
                }
        
        elif avg_memory < 50:  # Low memory usage, can increase performance
            from src.crypto.async_encryption import StreamingConfig
            max_size = 16 * 1024 * 1024  # 16MB max
            if StreamingConfig.LARGE_FILE_CHUNK_SIZE < max_size:
                old_size = StreamingConfig.LARGE_FILE_CHUNK_SIZE
                StreamingConfig.LARGE_FILE_CHUNK_SIZE = min(
                    max_size,
                    StreamingConfig.LARGE_FILE_CHUNK_SIZE * 2
                )
                return {
                    'type': 'memory_optimization',
                    'action': 'increase_buffer_sizes',
                    'old_chunk_size': old_size,
                    'new_chunk_size': StreamingConfig.LARGE_FILE_CHUNK_SIZE,
                    'reason': f'Low memory usage: {avg_memory:.1f}%'
                }
        
        return None
    
    async def _optimize_io_performance(self, metrics: List[SystemMetrics]) -> Optional[Dict[str, Any]]:
        """Optimize I/O performance based on metrics."""
        # Check for high I/O wait times (implementation would need system-specific monitoring)
        return None
    
    async def _optimize_threading(self) -> Optional[Dict[str, Any]]:
        """Optimize threading configuration."""
        current_threads = threading.active_count()
        
        if current_threads > 50:  # Too many threads
            return {
                'type': 'threading_optimization',
                'action': 'thread_pool_consolidation',
                'current_threads': current_threads,
                'reason': 'High thread count detected'
            }
        
        return None


class PerformanceMonitor:
    """Comprehensive performance monitoring system for BAR application.
    
    This class implements Rule R059 (Performance Monitoring) providing:
    - Real-time system metrics collection
    - Operation-level performance tracking
    - Automatic performance optimization
    - Alerting and threshold monitoring
    - Historical performance analysis
    """
    
    def __init__(self, monitoring_interval: int = 5, history_retention_hours: int = 24):
        """Initialize the performance monitor.
        
        Args:
            monitoring_interval: Interval between metric collections (seconds)
            history_retention_hours: How long to retain performance history
        """
        self.monitoring_interval = monitoring_interval
        self.history_retention = timedelta(hours=history_retention_hours)
        
        # Metrics storage
        self.system_metrics: deque = deque(maxlen=10000)  # Ring buffer for system metrics
        self.operation_metrics: Dict[str, OperationMetrics] = {}
        self.component_metrics: Dict[str, List[ComponentMetrics]] = defaultdict(list)
        
        # Thresholds and alerts
        self.thresholds: List[PerformanceThreshold] = []
        self.alert_callbacks: List[Callable] = []
        
        # Monitoring control
        self.monitoring_active = False
        self.monitoring_task = None
        self.monitoring_lock = asyncio.Lock()
        
        # Performance profiling
        self.profiling_enabled = False
        self.profiler = None
        self.memory_profiler_enabled = False
        
        # System process handle
        try:
            self.process = psutil.Process()
            self.process_available = True
        except:
            self.process_available = False
            
        # Performance optimizer
        self.optimizer = PerformanceOptimizer(self)
        self.auto_optimization_enabled = True
        
        # Baseline metrics
        self.baseline_metrics = None
        self.baseline_recorded = False
        
        # Setup logging
        self.logger = logging.getLogger("PerformanceMonitor")
        
        # Component references (to be set by integrating code)
        self.async_file_manager = None
        self.async_encryption = None
        self.async_file_scanner = None
    
    async def start_monitoring(self):
        """Start performance monitoring."""
        async with self.monitoring_lock:
            if self.monitoring_active:
                return
            
            self.monitoring_active = True
            
            # Set up default thresholds
            self._setup_default_thresholds()
            
            # Enable memory profiling if available
            if MEMORY_PROFILING_AVAILABLE and self.memory_profiler_enabled:
                tracemalloc.start()
            
            # Start monitoring task
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            
            self.logger.info("Performance monitoring started")
    
    async def stop_monitoring(self):
        """Stop performance monitoring."""
        async with self.monitoring_lock:
            if not self.monitoring_active:
                return
            
            self.monitoring_active = False
            
            if self.monitoring_task:
                self.monitoring_task.cancel()
                try:
                    await self.monitoring_task
                except asyncio.CancelledError:
                    pass
            
            # Stop memory profiling
            if MEMORY_PROFILING_AVAILABLE and tracemalloc.is_tracing():
                tracemalloc.stop()
            
            self.logger.info("Performance monitoring stopped")
    
    def _setup_default_thresholds(self):
        """Set up default performance thresholds."""
        self.thresholds = [
            PerformanceThreshold(
                metric_name="cpu_percent",
                warning_value=70.0,
                critical_value=90.0,
                comparison="greater_than"
            ),
            PerformanceThreshold(
                metric_name="memory_percent",
                warning_value=80.0,
                critical_value=95.0,
                comparison="greater_than"
            ),
            PerformanceThreshold(
                metric_name="throughput_bytes_per_second",
                warning_value=1024 * 1024,  # 1 MB/s
                critical_value=512 * 1024,  # 512 KB/s
                comparison="less_than"
            ),
            PerformanceThreshold(
                metric_name="response_time_seconds",
                warning_value=5.0,
                critical_value=10.0,
                comparison="greater_than"
            )
        ]
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        try:
            while self.monitoring_active:
                # Collect system metrics
                system_metrics = await self._collect_system_metrics()
                if system_metrics:
                    self.system_metrics.append(system_metrics)
                    
                    # Check thresholds
                    await self._check_thresholds(system_metrics)
                    
                    # Record baseline if not done
                    if not self.baseline_recorded:
                        self.baseline_metrics = system_metrics
                        self.baseline_recorded = True
                
                # Collect component metrics
                await self._collect_component_metrics()
                
                # Clean up old metrics
                await self._cleanup_old_metrics()
                
                # Auto-optimization (every 5 minutes)
                if (len(self.system_metrics) % (300 // self.monitoring_interval)) == 0:
                    if self.auto_optimization_enabled:
                        try:
                            await self.optimizer.analyze_and_optimize()
                        except Exception as e:
                            self.logger.warning(f"Auto-optimization failed: {e}")
                
                # Wait for next interval
                await asyncio.sleep(self.monitoring_interval)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Monitoring loop error: {e}")
    
    async def _collect_system_metrics(self) -> Optional[SystemMetrics]:
        """Collect system-level metrics."""
        if not self.process_available:
            return None
        
        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent()
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            # I/O statistics
            try:
                io_counters = self.process.io_counters()
                disk_read = io_counters.read_bytes
                disk_write = io_counters.write_bytes
            except (AttributeError, AccessDenied):
                disk_read = disk_write = 0
            
            # Network statistics (system-wide)
            try:
                net_io = psutil.net_io_counters()
                net_sent = net_io.bytes_sent
                net_recv = net_io.bytes_recv
            except:
                net_sent = net_recv = 0
            
            # Process information
            try:
                num_fds = self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
            except:
                num_fds = 0
            
            thread_count = self.process.num_threads()
            process_count = len(psutil.pids())
            
            return SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_rss=memory_info.rss,
                memory_vms=memory_info.vms,
                disk_io_read=disk_read,
                disk_io_write=disk_write,
                network_io_sent=net_sent,
                network_io_recv=net_recv,
                open_file_descriptors=num_fds,
                thread_count=thread_count,
                process_count=process_count
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to collect system metrics: {e}")
            return None
    
    async def _collect_component_metrics(self):
        """Collect metrics from system components."""
        timestamp = datetime.now()
        
        # File manager metrics
        if self.async_file_manager:
            try:
                fm_metrics = self.async_file_manager.get_performance_metrics()
                
                component_metric = ComponentMetrics(
                    component_name="async_file_manager",
                    timestamp=timestamp,
                    operations_per_second=0,  # TODO: Calculate from recent operations
                    average_response_time=0,  # TODO: Calculate from recent operations
                    error_rate=0,  # TODO: Track error rates
                    active_connections=fm_metrics.get('active_operations', 0),
                    queue_size=0,  # TODO: Track operation queue size
                    memory_usage_bytes=fm_metrics.get('memory_usage', {}).get('rss', 0),
                    cpu_usage_percent=0  # TODO: Track component-specific CPU usage
                )
                
                self.component_metrics['async_file_manager'].append(component_metric)
                
            except Exception as e:
                self.logger.debug(f"Failed to collect file manager metrics: {e}")
        
        # Encryption metrics
        if self.async_encryption:
            try:
                enc_metrics = self.async_encryption.get_performance_metrics()
                
                component_metric = ComponentMetrics(
                    component_name="async_encryption",
                    timestamp=timestamp,
                    operations_per_second=0,  # TODO: Calculate
                    average_response_time=0,  # TODO: Calculate
                    error_rate=0,
                    active_connections=0,
                    queue_size=0,
                    memory_usage_bytes=0,
                    cpu_usage_percent=0
                )
                
                self.component_metrics['async_encryption'].append(component_metric)
                
            except Exception as e:
                self.logger.debug(f"Failed to collect encryption metrics: {e}")
    
    async def _check_thresholds(self, metrics: SystemMetrics):
        """Check performance thresholds and trigger alerts."""
        for threshold in self.thresholds:
            if not threshold.enabled:
                continue
            
            metric_value = getattr(metrics, threshold.metric_name, None)
            if metric_value is None:
                continue
            
            alert_triggered = False
            alert_level = None
            
            if threshold.comparison == "greater_than":
                if metric_value >= threshold.critical_value:
                    alert_triggered = True
                    alert_level = "critical"
                elif metric_value >= threshold.warning_value:
                    alert_triggered = True
                    alert_level = "warning"
            elif threshold.comparison == "less_than":
                if metric_value <= threshold.critical_value:
                    alert_triggered = True
                    alert_level = "critical"
                elif metric_value <= threshold.warning_value:
                    alert_triggered = True
                    alert_level = "warning"
            
            if alert_triggered:
                alert_data = {
                    'timestamp': metrics.timestamp,
                    'metric_name': threshold.metric_name,
                    'metric_value': metric_value,
                    'threshold_value': threshold.critical_value if alert_level == "critical" else threshold.warning_value,
                    'alert_level': alert_level,
                    'comparison': threshold.comparison
                }
                
                await self._trigger_alert(alert_data)
                
                if threshold.callback:
                    try:
                        if asyncio.iscoroutinefunction(threshold.callback):
                            await threshold.callback(alert_data)
                        else:
                            threshold.callback(alert_data)
                    except Exception as e:
                        self.logger.error(f"Threshold callback failed: {e}")
    
    async def _trigger_alert(self, alert_data: Dict[str, Any]):
        """Trigger performance alert."""
        self.logger.warning(
            f"Performance alert: {alert_data['metric_name']} = {alert_data['metric_value']:.2f} "
            f"({alert_data['alert_level']} threshold: {alert_data['threshold_value']:.2f})"
        )
        
        # Call registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_data)
                else:
                    callback(alert_data)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
    
    async def _cleanup_old_metrics(self):
        """Clean up old metrics based on retention policy."""
        cutoff_time = datetime.now() - self.history_retention
        
        # Clean up operation metrics
        to_remove = []
        for op_id, metrics in self.operation_metrics.items():
            if metrics.start_time < cutoff_time:
                to_remove.append(op_id)
        
        for op_id in to_remove:
            del self.operation_metrics[op_id]
        
        # Clean up component metrics
        for component_name in self.component_metrics:
            self.component_metrics[component_name] = [
                m for m in self.component_metrics[component_name]
                if m.timestamp >= cutoff_time
            ]
    
    def start_operation_tracking(self, operation_id: str, operation_type: str,
                               data_size_bytes: int = 0, metadata: Dict[str, Any] = None) -> str:
        """Start tracking a specific operation."""
        operation_metrics = OperationMetrics(
            operation_id=operation_id,
            operation_type=operation_type,
            start_time=datetime.now(),
            data_size_bytes=data_size_bytes,
            metadata=metadata or {}
        )
        
        self.operation_metrics[operation_id] = operation_metrics
        return operation_id
    
    def finish_operation_tracking(self, operation_id: str, success: bool = True,
                                error_message: str = None, memory_peak_bytes: int = 0):
        """Finish tracking an operation."""
        if operation_id not in self.operation_metrics:
            return
        
        operation = self.operation_metrics[operation_id]
        operation.end_time = datetime.now()
        operation.duration_seconds = (operation.end_time - operation.start_time).total_seconds()
        operation.success = success
        operation.error_message = error_message
        operation.memory_peak_bytes = memory_peak_bytes
        
        # Calculate throughput
        if operation.duration_seconds > 0 and operation.data_size_bytes > 0:
            operation.throughput_bytes_per_second = operation.data_size_bytes / operation.duration_seconds
    
    def get_recent_system_metrics(self, seconds: int = 300) -> List[SystemMetrics]:
        """Get system metrics from the last N seconds."""
        cutoff_time = datetime.now() - timedelta(seconds=seconds)
        return [
            m for m in self.system_metrics
            if m.timestamp >= cutoff_time
        ]
    
    def get_operation_statistics(self, operation_type: str = None) -> Dict[str, Any]:
        """Get statistics for operations."""
        operations = list(self.operation_metrics.values())
        
        if operation_type:
            operations = [op for op in operations if op.operation_type == operation_type]
        
        if not operations:
            return {'operation_count': 0}
        
        completed_operations = [op for op in operations if op.end_time is not None]
        successful_operations = [op for op in completed_operations if op.success]
        
        if completed_operations:
            avg_duration = sum(op.duration_seconds for op in completed_operations) / len(completed_operations)
            avg_throughput = sum(op.throughput_bytes_per_second for op in completed_operations if op.throughput_bytes_per_second > 0) / max(1, len([op for op in completed_operations if op.throughput_bytes_per_second > 0]))
            success_rate = len(successful_operations) / len(completed_operations)
        else:
            avg_duration = avg_throughput = success_rate = 0
        
        return {
            'operation_count': len(operations),
            'completed_operations': len(completed_operations),
            'successful_operations': len(successful_operations),
            'success_rate': success_rate,
            'average_duration_seconds': avg_duration,
            'average_throughput_bytes_per_second': avg_throughput,
            'total_data_processed_bytes': sum(op.data_size_bytes for op in completed_operations)
        }
    
    def get_system_health_score(self) -> Dict[str, Any]:
        """Calculate overall system health score."""
        if not self.system_metrics:
            return {'score': 0, 'status': 'no_data'}
        
        recent_metrics = self.get_recent_system_metrics(300)  # Last 5 minutes
        if len(recent_metrics) < 5:
            return {'score': 0, 'status': 'insufficient_data'}
        
        # Calculate average metrics
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        
        # Calculate health score (0-100)
        score = 100
        
        # CPU penalty
        if avg_cpu > 90:
            score -= 40
        elif avg_cpu > 70:
            score -= 20
        elif avg_cpu > 50:
            score -= 10
        
        # Memory penalty
        if avg_memory > 95:
            score -= 40
        elif avg_memory > 80:
            score -= 20
        elif avg_memory > 60:
            score -= 10
        
        # Operation success rate bonus/penalty
        op_stats = self.get_operation_statistics()
        if op_stats['operation_count'] > 0:
            success_rate = op_stats['success_rate']
            if success_rate < 0.8:
                score -= 20
            elif success_rate < 0.9:
                score -= 10
            elif success_rate > 0.99:
                score += 5
        
        score = max(0, min(100, score))
        
        # Determine status
        if score >= 90:
            status = 'excellent'
        elif score >= 75:
            status = 'good'
        elif score >= 60:
            status = 'fair'
        elif score >= 40:
            status = 'poor'
        else:
            status = 'critical'
        
        return {
            'score': score,
            'status': status,
            'avg_cpu_percent': avg_cpu,
            'avg_memory_percent': avg_memory,
            'operation_success_rate': op_stats.get('success_rate', 0),
            'factors': {
                'cpu_usage': avg_cpu,
                'memory_usage': avg_memory,
                'operation_reliability': op_stats.get('success_rate', 0)
            }
        }
    
    def get_comprehensive_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        return {
            'system_health': self.get_system_health_score(),
            'system_metrics': {
                'current': asdict(self.system_metrics[-1]) if self.system_metrics else None,
                'average_last_hour': self._calculate_average_metrics(3600),
                'baseline': asdict(self.baseline_metrics) if self.baseline_metrics else None
            },
            'operation_statistics': {
                'overall': self.get_operation_statistics(),
                'encryption': self.get_operation_statistics('encryption'),
                'decryption': self.get_operation_statistics('decryption'),
                'file_scan': self.get_operation_statistics('file_scan')
            },
            'component_metrics': {
                name: len(metrics) for name, metrics in self.component_metrics.items()
            },
            'optimization_history': self.optimizer.optimization_history[-10:],  # Last 10 optimizations
            'monitoring_status': {
                'active': self.monitoring_active,
                'interval_seconds': self.monitoring_interval,
                'metrics_collected': len(self.system_metrics),
                'operations_tracked': len(self.operation_metrics)
            }
        }
    
    def _calculate_average_metrics(self, seconds: int) -> Dict[str, float]:
        """Calculate average metrics over specified time period."""
        metrics = self.get_recent_system_metrics(seconds)
        if not metrics:
            return {}
        
        return {
            'cpu_percent': sum(m.cpu_percent for m in metrics) / len(metrics),
            'memory_percent': sum(m.memory_percent for m in metrics) / len(metrics),
            'memory_rss_mb': sum(m.memory_rss for m in metrics) / len(metrics) / (1024 * 1024),
            'thread_count': sum(m.thread_count for m in metrics) / len(metrics)
        }
    
    def add_alert_callback(self, callback: Callable):
        """Add a callback to be called when alerts are triggered."""
        self.alert_callbacks.append(callback)
    
    def add_threshold(self, threshold: PerformanceThreshold):
        """Add a custom performance threshold."""
        self.thresholds.append(threshold)
    
    def enable_profiling(self, enable: bool = True):
        """Enable or disable CPU profiling."""
        if not PROFILING_AVAILABLE:
            self.logger.warning("CPU profiling not available (cProfile not installed)")
            return
        
        self.profiling_enabled = enable
        
        if enable and not self.profiler:
            self.profiler = cProfile.Profile()
            self.profiler.enable()
        elif not enable and self.profiler:
            self.profiler.disable()
    
    def get_profiling_stats(self) -> Optional[str]:
        """Get CPU profiling statistics."""
        if not self.profiler or not PROFILING_AVAILABLE:
            return None
        
        stats_stream = io.StringIO()
        stats = pstats.Stats(self.profiler, stream=stats_stream)
        stats.sort_stats('cumulative').print_stats(20)  # Top 20 functions
        
        return stats_stream.getvalue()
    
    def export_metrics(self, file_path: str):
        """Export performance metrics to a file."""
        metrics_data = {
            'export_timestamp': datetime.now().isoformat(),
            'comprehensive_metrics': self.get_comprehensive_metrics(),
            'recent_system_metrics': [
                asdict(m) for m in self.get_recent_system_metrics(3600)
            ],
            'operation_metrics': [
                asdict(op) for op in self.operation_metrics.values()
            ]
        }
        
        with open(file_path, 'w') as f:
            json.dump(metrics_data, f, indent=2, default=str)
        
        self.logger.info(f"Performance metrics exported to {file_path}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start_monitoring()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop_monitoring()