#!/usr/bin/env python3
"""
System Health Monitor for BAR Security Suite

This module provides real-time monitoring of system health metrics
that could impact security operations, including memory usage,
CPU temperature, and potential security threats.

Author: Rolan Lobo (RNR)
Version: 1.0.0
Last Updated: January 2025
"""

import time
import psutil
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat level indicators for system health"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SystemMetrics:
    """System health metrics data structure"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    temperature: Optional[float]
    threat_level: ThreatLevel
    active_threats: List[str]


class SystemHealthMonitor:
    """
    Real-time system health monitoring for security operations
    
    Monitors critical system metrics that could impact the security
    and performance of BAR operations, providing early warning
    of potential issues.
    """
    
    def __init__(self, 
                 check_interval: float = 5.0,
                 memory_threshold: float = 85.0,
                 cpu_threshold: float = 90.0,
                 temperature_threshold: float = 80.0):
        """
        Initialize the system health monitor
        
        Args:
            check_interval: Time between health checks (seconds)
            memory_threshold: Memory usage threshold for warnings (%)
            cpu_threshold: CPU usage threshold for warnings (%)
            temperature_threshold: Temperature threshold for warnings (°C)
        """
        self.check_interval = check_interval
        self.memory_threshold = memory_threshold
        self.cpu_threshold = cpu_threshold
        self.temperature_threshold = temperature_threshold
        
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[SystemMetrics], None]] = []
        self._last_metrics: Optional[SystemMetrics] = None
        
        logger.info("SystemHealthMonitor initialized")
    
    def add_callback(self, callback: Callable[[SystemMetrics], None]) -> None:
        """
        Add a callback function to be called when metrics are updated
        
        Args:
            callback: Function to call with SystemMetrics data
        """
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[SystemMetrics], None]) -> None:
        """
        Remove a callback function
        
        Args:
            callback: Function to remove from callbacks
        """
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    def get_current_metrics(self) -> SystemMetrics:
        """
        Get current system health metrics
        
        Returns:
            SystemMetrics object with current system state
        """
        # Get CPU usage (1 second average)
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Get memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Get disk usage for system drive
        disk = psutil.disk_usage('/')
        disk_usage = (disk.used / disk.total) * 100
        
        # Try to get temperature (may not be available on all systems)
        temperature = self._get_cpu_temperature()
        
        # Analyze threats
        threats, threat_level = self._analyze_threats(
            cpu_percent, memory_percent, temperature
        )
        
        metrics = SystemMetrics(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_usage=disk_usage,
            temperature=temperature,
            threat_level=threat_level,
            active_threats=threats
        )
        
        self._last_metrics = metrics
        return metrics
    
    def _get_cpu_temperature(self) -> Optional[float]:
        """
        Attempt to get CPU temperature
        
        Returns:
            Temperature in Celsius or None if unavailable
        """
        try:
            # Try to get temperature sensors
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps:
                    # Get first available temperature sensor
                    for name, entries in temps.items():
                        if entries:
                            return entries[0].current
            return None
        except (AttributeError, OSError):
            return None
    
    def _analyze_threats(self, cpu_percent: float, memory_percent: float, 
                        temperature: Optional[float]) -> tuple[List[str], ThreatLevel]:
        """
        Analyze system metrics for potential security threats
        
        Args:
            cpu_percent: Current CPU usage percentage
            memory_percent: Current memory usage percentage 
            temperature: Current temperature (if available)
        
        Returns:
            Tuple of (threat_list, threat_level)
        """
        threats = []
        threat_level = ThreatLevel.LOW
        
        # Check memory usage
        if memory_percent > self.memory_threshold:
            threats.append(f"High memory usage: {memory_percent:.1f}%")
            threat_level = ThreatLevel.MEDIUM
        
        if memory_percent > 95:
            threats.append("Critical memory usage - potential memory exhaustion attack")
            threat_level = ThreatLevel.CRITICAL
        
        # Check CPU usage
        if cpu_percent > self.cpu_threshold:
            threats.append(f"High CPU usage: {cpu_percent:.1f}%")
            if threat_level == ThreatLevel.LOW:
                threat_level = ThreatLevel.MEDIUM
        
        if cpu_percent > 98:
            threats.append("Critical CPU usage - potential DoS attack or crypto mining")
            threat_level = ThreatLevel.CRITICAL
        
        # Check temperature
        if temperature and temperature > self.temperature_threshold:
            threats.append(f"High CPU temperature: {temperature:.1f}°C")
            if threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM]:
                threat_level = ThreatLevel.HIGH
        
        if temperature and temperature > 90:
            threats.append("Critical CPU temperature - thermal throttling likely")
            threat_level = ThreatLevel.CRITICAL
        
        # Check for suspicious processes (basic heuristic)
        try:
            suspicious_processes = self._check_suspicious_processes()
            if suspicious_processes:
                threats.extend([f"Suspicious process: {proc}" for proc in suspicious_processes])
                if threat_level == ThreatLevel.LOW:
                    threat_level = ThreatLevel.MEDIUM
        except Exception as e:
            logger.warning(f"Failed to check processes: {e}")
        
        return threats, threat_level
    
    def _check_suspicious_processes(self) -> List[str]:
        """
        Basic check for potentially suspicious processes
        
        Returns:
            List of suspicious process names
        """
        suspicious_names = [
            'keylogger', 'backdoor', 'trojan', 'rootkit',
            'miner', 'coinminer', 'xmrig', 'cryptonight'
        ]
        
        suspicious = []
        try:
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                for sus_name in suspicious_names:
                    if sus_name in proc_name:
                        suspicious.append(proc.info['name'])
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return suspicious
    
    def start_monitoring(self) -> None:
        """Start continuous system health monitoring"""
        if self._monitoring:
            logger.warning("Monitoring already started")
            return
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("System health monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop continuous system health monitoring"""
        if not self._monitoring:
            return
        
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        logger.info("System health monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop (runs in separate thread)"""
        while self._monitoring:
            try:
                metrics = self.get_current_metrics()
                
                # Log significant threats
                if metrics.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    logger.warning(f"System health threat level: {metrics.threat_level.value}")
                    for threat in metrics.active_threats:
                        logger.warning(f"Active threat: {threat}")
                
                # Call registered callbacks
                for callback in self._callbacks:
                    try:
                        callback(metrics)
                    except Exception as e:
                        logger.error(f"Error in health monitor callback: {e}")
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.check_interval)
    
    def get_health_report(self) -> Dict:
        """
        Get a comprehensive health report
        
        Returns:
            Dictionary with current system health status
        """
        metrics = self.get_current_metrics()
        
        return {
            'timestamp': metrics.timestamp,
            'overall_status': metrics.threat_level.value,
            'metrics': {
                'cpu_usage': f"{metrics.cpu_percent:.1f}%",
                'memory_usage': f"{metrics.memory_percent:.1f}%", 
                'disk_usage': f"{metrics.disk_usage:.1f}%",
                'temperature': f"{metrics.temperature:.1f}°C" if metrics.temperature else "N/A"
            },
            'threats': {
                'count': len(metrics.active_threats),
                'level': metrics.threat_level.value,
                'details': metrics.active_threats
            },
            'recommendations': self._get_recommendations(metrics)
        }
    
    def _get_recommendations(self, metrics: SystemMetrics) -> List[str]:
        """
        Get security recommendations based on current metrics
        
        Args:
            metrics: Current system metrics
        
        Returns:
            List of recommended actions
        """
        recommendations = []
        
        if metrics.memory_percent > self.memory_threshold:
            recommendations.append("Consider closing unnecessary applications to free memory")
            recommendations.append("Monitor for potential memory-based attacks")
        
        if metrics.cpu_percent > self.cpu_threshold:
            recommendations.append("Check for malicious processes consuming CPU")
            recommendations.append("Consider pausing non-critical operations")
        
        if metrics.temperature and metrics.temperature > self.temperature_threshold:
            recommendations.append("Check system cooling and ventilation")
            recommendations.append("Consider reducing system load temporarily")
        
        if metrics.threat_level == ThreatLevel.CRITICAL:
            recommendations.append("IMMEDIATE ACTION REQUIRED - System may be compromised")
            recommendations.append("Consider emergency shutdown of BAR operations")
        
        return recommendations


def create_health_monitor() -> SystemHealthMonitor:
    """
    Factory function to create a preconfigured health monitor
    
    Returns:
        Configured SystemHealthMonitor instance
    """
    return SystemHealthMonitor(
        check_interval=5.0,
        memory_threshold=85.0,
        cpu_threshold=90.0,
        temperature_threshold=80.0
    )


# Example usage callback for BAR integration
def bar_security_callback(metrics: SystemMetrics) -> None:
    """
    Example callback for BAR security integration
    
    Args:
        metrics: Current system metrics
    """
    if metrics.threat_level == ThreatLevel.CRITICAL:
        logger.critical("SECURITY ALERT: Critical system threat detected!")
        # In a real BAR implementation, this might trigger:
        # - Emergency data wipe
        # - Application shutdown
        # - Security protocol activation
    
    elif metrics.threat_level == ThreatLevel.HIGH:
        logger.warning("Security warning: High threat level detected")
        # Might trigger enhanced monitoring or user notification


if __name__ == "__main__":
    # Demo usage
    import sys
    
    # Configure logging for demo
    logging.basicConfig(level=logging.INFO)
    
    # Create monitor
    monitor = create_health_monitor()
    monitor.add_callback(bar_security_callback)
    
    print("BAR System Health Monitor Demo")
    print("=" * 40)
    
    try:
        # Get initial report
        report = monitor.get_health_report()
        print(f"System Status: {report['overall_status'].upper()}")
        print(f"CPU Usage: {report['metrics']['cpu_usage']}")
        print(f"Memory Usage: {report['metrics']['memory_usage']}")
        print(f"Disk Usage: {report['metrics']['disk_usage']}")
        print(f"Temperature: {report['metrics']['temperature']}")
        
        if report['threats']['count'] > 0:
            print(f"\nActive Threats ({report['threats']['count']}):")
            for threat in report['threats']['details']:
                print(f"  - {threat}")
        
        if report['recommendations']:
            print(f"\nRecommendations:")
            for rec in report['recommendations']:
                print(f"  - {rec}")
        
        # Start monitoring for 30 seconds
        print("\nStarting continuous monitoring (30 seconds)...")
        monitor.start_monitoring()
        time.sleep(30)
        monitor.stop_monitoring()
        print("Monitoring stopped.")
        
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
        monitor.stop_monitoring()
        sys.exit(0)