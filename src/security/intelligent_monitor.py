"""
Intelligent File Monitor - Advanced monitoring with behavioral analysis and tamper detection.

This module provides enhanced monitoring capabilities beyond basic file watching,
including behavioral analysis, access pattern detection, and proactive threat response.

Per project security rules:
- R004: Security-first design with defense in depth
- R006: Memory security with secure data handling
- R019: Logging standards with sanitized messages
"""

import os
import time
import threading
import hashlib
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import logging


class ThreatLevel(Enum):
    """Threat levels for monitoring events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccessPattern(Enum):
    """Known access patterns."""
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    BULK_ACCESS = "bulk_access"
    RAPID_FAILURE = "rapid_failure"
    UNUSUAL_TIMING = "unusual_timing"
    EXTERNAL_PROCESS = "external_process"


@dataclass
class AccessEvent:
    """Represents a file access event."""
    timestamp: datetime
    file_id: str
    event_type: str  # access, failure, deletion, etc.
    process_name: Optional[str] = None
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitoringProfile:
    """User behavioral profile for anomaly detection."""
    typical_access_hours: Set[int] = field(default_factory=set)
    average_session_duration: float = 0.0
    typical_access_intervals: List[float] = field(default_factory=list)
    failure_rate_baseline: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)


class IntelligentFileMonitor:
    """
    Advanced file monitoring with behavioral analysis and threat detection.
    
    Features:
    - Behavioral baseline learning
    - Access pattern anomaly detection
    - Process monitoring and analysis
    - Automated threat response
    - Tamper detection
    """
    
    def __init__(self, base_directory: Path, logger: Optional[logging.Logger] = None):
        """Initialize the intelligent monitor.
        
        Args:
            base_directory: Base directory for BAR application
            logger: Optional logger instance
        """
        self.base_directory = Path(base_directory)
        self.logger = logger or logging.getLogger("IntelligentMonitor")
        
        # Monitoring state
        self._monitoring_active = False
        self._monitor_thread = None
        
        # Event tracking
        self._access_events: List[AccessEvent] = []
        self._max_events = 1000  # Keep last 1000 events for analysis
        self._event_lock = threading.RLock()
        
        # Behavioral profiling
        self._user_profile = MonitoringProfile()
        self._profile_lock = threading.RLock()
        
        # Threat response callbacks
        self._threat_callbacks: Dict[ThreatLevel, List[Callable]] = {
            ThreatLevel.LOW: [],
            ThreatLevel.MEDIUM: [],
            ThreatLevel.HIGH: [],
            ThreatLevel.CRITICAL: []
        }
        
        # Configuration
        self._learning_period_days = 7  # Days to learn baseline behavior
        self._analysis_window_hours = 24  # Hours to analyze for patterns
        self._failure_threshold = 5  # Failed attempts before alert
        
        # Process monitoring (Windows-specific, graceful fallback)
        self._monitored_processes: Set[str] = set()
        self._suspicious_processes: Set[str] = {
            "forensics", "recovery", "undelete", "disk", "hex", "binary",
            "wireshark", "tcpdump", "volatility", "binwalk", "strings"
        }
    
    def start_monitoring(self):
        """Start the intelligent monitoring system."""
        if self._monitoring_active:
            return
        
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        self.logger.info("Intelligent file monitoring started")
    
    def stop_monitoring(self):
        """Stop the monitoring system."""
        self._monitoring_active = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        
        self.logger.info("Intelligent file monitoring stopped")
    
    def register_threat_callback(self, threat_level: ThreatLevel, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback for specific threat levels.
        
        Args:
            threat_level: Level of threat to trigger callback
            callback: Function to call when threat is detected
        """
        self._threat_callbacks[threat_level].append(callback)
    
    def record_access_event(self, file_id: str, event_type: str, success: bool = True, 
                           metadata: Optional[Dict[str, Any]] = None):
        """Record a file access event for analysis.
        
        Args:
            file_id: ID of the file accessed
            event_type: Type of access (read, write, delete, etc.)
            success: Whether the access was successful
            metadata: Additional event metadata
        """
        try:
            # Get current process info (best effort)
            process_name = self._get_current_process_name()
            
            event = AccessEvent(
                timestamp=datetime.now(),
                file_id=file_id,
                event_type=event_type,
                process_name=process_name,
                success=success,
                metadata=metadata or {}
            )
            
            with self._event_lock:
                self._access_events.append(event)
                
                # Maintain event history limit
                if len(self._access_events) > self._max_events:
                    self._access_events = self._access_events[-self._max_events:]
            
            # Immediate analysis for critical events
            if not success and event_type in ("access", "decrypt"):
                self._analyze_failure_pattern(event)
            
        except Exception as e:
            self.logger.debug(f"Error recording access event: {e}")
    
    def analyze_current_behavior(self) -> Dict[str, Any]:
        """Analyze current behavior patterns and return assessment.
        
        Returns:
            Dictionary with behavior analysis results
        """
        try:
            with self._event_lock:
                recent_events = self._get_recent_events(hours=1)
                
            if not recent_events:
                return {"status": "no_activity", "threat_level": ThreatLevel.LOW.value}
            
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "event_count": len(recent_events),
                "patterns": [],
                "threat_level": ThreatLevel.LOW.value,
                "recommendations": []
            }
            
            # Analyze various patterns
            analysis.update(self._analyze_access_frequency(recent_events))
            analysis.update(self._analyze_failure_patterns(recent_events))
            analysis.update(self._analyze_timing_patterns(recent_events))
            analysis.update(self._analyze_process_patterns(recent_events))
            
            # Determine overall threat level
            threat_level = self._calculate_threat_level(analysis)
            analysis["threat_level"] = threat_level.value
            
            # Trigger callbacks if needed
            if threat_level != ThreatLevel.LOW:
                self._trigger_threat_callbacks(threat_level, analysis)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing behavior: {e}")
            return {"status": "error", "threat_level": ThreatLevel.LOW.value}
    
    def update_user_profile(self):
        """Update the user behavioral profile based on recent activity."""
        try:
            with self._event_lock:
                # Get events from learning period
                cutoff_date = datetime.now() - timedelta(days=self._learning_period_days)
                learning_events = [e for e in self._access_events if e.timestamp > cutoff_date and e.success]
            
            if len(learning_events) < 10:  # Need minimum data for profiling
                return
            
            with self._profile_lock:
                # Update typical access hours
                access_hours = {e.timestamp.hour for e in learning_events}
                self._user_profile.typical_access_hours = access_hours
                
                # Calculate session patterns (simplified)
                if len(learning_events) > 1:
                    intervals = []
                    for i in range(1, len(learning_events)):
                        interval = (learning_events[i].timestamp - learning_events[i-1].timestamp).total_seconds()
                        if interval < 3600:  # Within same session (1 hour)
                            intervals.append(interval)
                    
                    if intervals:
                        self._user_profile.average_session_duration = statistics.mean(intervals)
                        self._user_profile.typical_access_intervals = intervals[-20:]  # Keep recent intervals
                
                # Calculate failure rate baseline
                total_events = len(self._access_events)
                failed_events = len([e for e in self._access_events if not e.success])
                self._user_profile.failure_rate_baseline = failed_events / max(total_events, 1)
                
                self._user_profile.last_updated = datetime.now()
                
            self.logger.debug("User behavioral profile updated")
            
        except Exception as e:
            self.logger.error(f"Error updating user profile: {e}")
    
    def detect_tampering(self) -> Optional[Dict[str, Any]]:
        """Detect potential tampering with BAR files or directories.
        
        Returns:
            Tampering detection results or None if no tampering detected
        """
        try:
            tampering_indicators = []
            
            # Check for unauthorized file access
            suspicious_processes = self._detect_suspicious_processes()
            if suspicious_processes:
                tampering_indicators.append({
                    "type": "suspicious_processes",
                    "details": list(suspicious_processes),
                    "severity": "high"
                })
            
            # Check for unusual file system activity
            unusual_activity = self._detect_unusual_fs_activity()
            if unusual_activity:
                tampering_indicators.append({
                    "type": "unusual_filesystem_activity", 
                    "details": unusual_activity,
                    "severity": "medium"
                })
            
            # Check for rapid multiple access attempts
            rapid_access = self._detect_rapid_access_attempts()
            if rapid_access:
                tampering_indicators.append({
                    "type": "rapid_access_attempts",
                    "details": rapid_access,
                    "severity": "high" 
                })
            
            if tampering_indicators:
                return {
                    "detected": True,
                    "timestamp": datetime.now().isoformat(),
                    "indicators": tampering_indicators,
                    "recommended_action": self._get_recommended_action(tampering_indicators)
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in tamper detection: {e}")
            return None
    
    def _monitor_loop(self):
        """Main monitoring loop (runs in separate thread)."""
        while self._monitoring_active:
            try:
                # Periodic analysis
                analysis = self.analyze_current_behavior()
                
                # Update user profile periodically
                if datetime.now().minute % 30 == 0:  # Every 30 minutes
                    self.update_user_profile()
                
                # Check for tampering
                tampering = self.detect_tampering()
                if tampering:
                    self.logger.warning(f"Tampering detected: {tampering}")
                    self._trigger_threat_callbacks(ThreatLevel.HIGH, tampering)
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                time.sleep(60)
    
    def _get_recent_events(self, hours: int = 24) -> List[AccessEvent]:
        """Get events from the last N hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [e for e in self._access_events if e.timestamp > cutoff_time]
    
    def _analyze_failure_pattern(self, event: AccessEvent):
        """Analyze failure patterns for immediate threat detection."""
        try:
            # Check for rapid failures (possible brute force)
            recent_failures = []
            cutoff_time = datetime.now() - timedelta(minutes=10)
            
            with self._event_lock:
                for e in reversed(self._access_events):
                    if e.timestamp < cutoff_time:
                        break
                    if not e.success and e.event_type == event.event_type:
                        recent_failures.append(e)
            
            if len(recent_failures) >= self._failure_threshold:
                threat_data = {
                    "type": "rapid_failures",
                    "count": len(recent_failures),
                    "event_type": event.event_type,
                    "file_id": event.file_id
                }
                self._trigger_threat_callbacks(ThreatLevel.HIGH, threat_data)
                
        except Exception as e:
            self.logger.debug(f"Error analyzing failure pattern: {e}")
    
    def _analyze_access_frequency(self, events: List[AccessEvent]) -> Dict[str, Any]:
        """Analyze access frequency patterns."""
        if not events:
            return {}
        
        # Calculate events per hour
        time_span = (events[-1].timestamp - events[0].timestamp).total_seconds() / 3600
        if time_span == 0:
            return {"access_frequency": "instantaneous"}
        
        frequency = len(events) / time_span
        
        # Classify frequency
        if frequency > 10:
            return {"access_frequency": "very_high", "pattern": AccessPattern.BULK_ACCESS.value}
        elif frequency > 5:
            return {"access_frequency": "high", "pattern": AccessPattern.SUSPICIOUS.value}
        else:
            return {"access_frequency": "normal", "pattern": AccessPattern.NORMAL.value}
    
    def _analyze_failure_patterns(self, events: List[AccessEvent]) -> Dict[str, Any]:
        """Analyze failure rate patterns."""
        if not events:
            return {}
        
        failures = [e for e in events if not e.success]
        failure_rate = len(failures) / len(events)
        
        # Compare to baseline
        with self._profile_lock:
            baseline = self._user_profile.failure_rate_baseline
        
        if failure_rate > baseline * 3:  # 3x normal failure rate
            return {"failure_pattern": "elevated", "failure_rate": failure_rate}
        
        return {"failure_pattern": "normal", "failure_rate": failure_rate}
    
    def _analyze_timing_patterns(self, events: List[AccessEvent]) -> Dict[str, Any]:
        """Analyze timing patterns against user profile."""
        if not events:
            return {}
        
        current_hour = datetime.now().hour
        with self._profile_lock:
            typical_hours = self._user_profile.typical_access_hours
        
        if typical_hours and current_hour not in typical_hours:
            return {"timing_pattern": AccessPattern.UNUSUAL_TIMING.value}
        
        return {"timing_pattern": AccessPattern.NORMAL.value}
    
    def _analyze_process_patterns(self, events: List[AccessEvent]) -> Dict[str, Any]:
        """Analyze process patterns for suspicious activity."""
        processes = {e.process_name for e in events if e.process_name}
        
        suspicious = processes & self._suspicious_processes
        if suspicious:
            return {"process_pattern": AccessPattern.EXTERNAL_PROCESS.value, "suspicious_processes": list(suspicious)}
        
        return {"process_pattern": AccessPattern.NORMAL.value}
    
    def _calculate_threat_level(self, analysis: Dict[str, Any]) -> ThreatLevel:
        """Calculate overall threat level from analysis."""
        threat_indicators = 0
        
        # Check various threat indicators
        if analysis.get("access_frequency") in ("high", "very_high"):
            threat_indicators += 1
        
        if analysis.get("failure_pattern") == "elevated":
            threat_indicators += 2
        
        if analysis.get("timing_pattern") == AccessPattern.UNUSUAL_TIMING.value:
            threat_indicators += 1
        
        if analysis.get("process_pattern") == AccessPattern.EXTERNAL_PROCESS.value:
            threat_indicators += 2
        
        # Map indicators to threat levels
        if threat_indicators >= 4:
            return ThreatLevel.CRITICAL
        elif threat_indicators >= 2:
            return ThreatLevel.HIGH
        elif threat_indicators >= 1:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _trigger_threat_callbacks(self, threat_level: ThreatLevel, threat_data: Dict[str, Any]):
        """Trigger registered callbacks for threat level."""
        try:
            callbacks = self._threat_callbacks.get(threat_level, [])
            for callback in callbacks:
                try:
                    callback(threat_data)
                except Exception as e:
                    self.logger.error(f"Error in threat callback: {e}")
        except Exception as e:
            self.logger.error(f"Error triggering threat callbacks: {e}")
    
    def _get_current_process_name(self) -> Optional[str]:
        """Get current process name (best effort, platform dependent)."""
        try:
            if os.name == 'nt':
                # Windows - use basic approach to avoid external dependencies
                return "python.exe"  # Simplified for now
            else:
                # Unix-like systems
                return os.path.basename(os.environ.get('_', 'unknown'))
        except Exception:
            return None
    
    def _detect_suspicious_processes(self) -> Set[str]:
        """Detect suspicious processes that might indicate tampering."""
        # This is a simplified implementation
        # In a full implementation, this would check running processes
        # For now, return empty set to avoid false positives
        return set()
    
    def _detect_unusual_fs_activity(self) -> Optional[Dict[str, Any]]:
        """Detect unusual filesystem activity."""
        # Simplified implementation - check for unexpected files
        try:
            base_files = set(self.base_directory.iterdir())
            # This would compare against known good state
            # For now, return None to avoid false positives
            return None
        except Exception:
            return None
    
    def _detect_rapid_access_attempts(self) -> Optional[Dict[str, Any]]:
        """Detect rapid access attempts that might indicate automated tools."""
        try:
            recent_events = self._get_recent_events(hours=1)
            if len(recent_events) > 50:  # More than 50 events in an hour
                return {
                    "event_count": len(recent_events),
                    "time_window": "1_hour",
                    "likely_automated": True
                }
            return None
        except Exception:
            return None
    
    def _get_recommended_action(self, indicators: List[Dict[str, Any]]) -> str:
        """Get recommended action based on tampering indicators."""
        high_severity = any(i.get("severity") == "high" for i in indicators)
        
        if high_severity:
            return "immediate_emergency_wipe"
        else:
            return "enhanced_monitoring"
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics."""
        try:
            with self._event_lock:
                total_events = len(self._access_events)
                recent_events = self._get_recent_events(hours=24)
                
            with self._profile_lock:
                profile_age = (datetime.now() - self._user_profile.last_updated).total_seconds() / 86400
            
            return {
                "monitoring_active": self._monitoring_active,
                "total_events_tracked": total_events,
                "events_last_24h": len(recent_events),
                "profile_age_days": round(profile_age, 2),
                "typical_access_hours": list(self._user_profile.typical_access_hours),
                "baseline_failure_rate": self._user_profile.failure_rate_baseline
            }
            
        except Exception as e:
            self.logger.error(f"Error getting monitoring stats: {e}")
            return {"error": str(e)}
    
    def __del__(self):
        """Cleanup on destruction."""
        try:
            self.stop_monitoring()
        except Exception:
            pass
