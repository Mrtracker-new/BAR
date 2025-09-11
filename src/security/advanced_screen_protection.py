"""
Advanced Screen Protection System for BAR Application

This module provides comprehensive security features for view-only files including:
- Screenshot prevention and detection
- Screen recording detection
- Window focus monitoring
- Clipboard protection
- OCR prevention measures
- Dynamic content scrambling
- Security event logging

Author: Rolan Lobo (RNR)
Project: BAR - Burn After Reading Security Suite
"""

import os
import sys
import time
import threading
import platform
import random
import hashlib
import json
import subprocess
from datetime import datetime, timedelta
from typing import Callable, Optional, Dict, List, Any
from dataclasses import dataclass

# Import security configuration
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from config.security_config import get_security_config, SecurityLevel

from PyQt5.QtWidgets import (
    QWidget, QTextEdit, QLabel, QApplication, QVBoxLayout, QHBoxLayout,
    QFrame, QGraphicsEffect, QGraphicsBlurEffect, QGraphicsOpacityEffect
)
from PyQt5.QtGui import (
    QPixmap, QPainter, QColor, QFont, QPen, QBrush, QImage, QPalette,
    QLinearGradient, QRadialGradient, QConicalGradient
)
from PyQt5.QtCore import (
    Qt, QTimer, QSize, QPoint, QRect, QObject, pyqtSignal, QPointF,
    QThread, QMutex, QPropertyAnimation, QEasingCurve
)

# Import platform-specific modules
if platform.system().lower() == 'windows':
    try:
        import win32gui
        import win32api
        import win32con
        import win32process
        import psutil
        from .win_screenshot_prevention import KeyboardHook, ScreenCaptureBlocker
        from .ultra_fast_screenshot_prevention import ComprehensiveScreenshotPrevention
    except ImportError:
        print("Windows-specific modules not available - some features may be limited")


@dataclass
class SecurityEvent:
    """Represents a security-related event."""
    timestamp: datetime
    event_type: str  # 'screenshot_attempt', 'focus_lost', 'suspicious_process', etc.
    severity: str    # 'low', 'medium', 'high', 'critical'
    details: Dict[str, Any]
    user_agent: str
    window_title: str = ""
    process_name: str = ""


class ProcessMonitor(QThread):
    """Monitors running processes for suspicious screenshot/recording software."""
    
    suspicious_process_detected = pyqtSignal(str, str)  # process_name, reason
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitoring = False
        self.check_interval = 5.0  # Increased interval to be less aggressive
        
        # Keep track of already reported processes to avoid spam
        self.reported_processes = set()
        
        # Known screenshot and screen recording software
        self.suspicious_processes = {
            # Screenshot tools
            'snagit32.exe': 'Screenshot tool (Snagit)',
            'lightshot.exe': 'Screenshot tool (Lightshot)',
            'greenshot.exe': 'Screenshot tool (Greenshot)',
            'puush.exe': 'Screenshot sharing tool',
            'sharex.exe': 'Screenshot tool (ShareX)',
            'gyazo.exe': 'Screenshot sharing tool',
            'flameshot.exe': 'Screenshot tool (Flameshot)',
            'shutter.exe': 'Screenshot tool (Shutter)',
            
            # Screen recording tools
            'obs64.exe': 'Screen recording (OBS Studio)',
            'obs32.exe': 'Screen recording (OBS Studio)',
            'camtasia.exe': 'Screen recording (Camtasia)',
            'bandicam.exe': 'Screen recording (Bandicam)',
            'fraps.exe': 'Screen recording (Fraps)',
            'xsplit.core.exe': 'Screen recording (XSplit)',
            'ffmpeg.exe': 'Media processing tool (potential recording)',
            'screencastify.exe': 'Screen recording extension',
            'loom.exe': 'Screen recording (Loom)',
            'nvidia-share.exe': 'NVIDIA screen recording',
            
            # Remote desktop tools
            'teamviewer.exe': 'Remote desktop tool',
            'anydesk.exe': 'Remote desktop tool',
            'chrome_remote_desktop_host.exe': 'Remote desktop',
            'mstsc.exe': 'Windows Remote Desktop',
            'vnc.exe': 'VNC remote access',
            
            # Network analysis tools (actual security threats)
            'fiddler.exe': 'Network debugging tool',
            'wireshark.exe': 'Network analysis tool'
            # Note: Removed development tools as they're now whitelisted
        }
    
    def start_monitoring(self):
        """Start process monitoring."""
        self.monitoring = True
        self.start()
    
    def stop_monitoring(self):
        """Stop process monitoring."""
        self.monitoring = False
        self.wait(3000)  # Wait up to 3 seconds for thread to finish
    
    def run(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                self._check_processes()
                time.sleep(self.check_interval)
            except Exception as e:
                print(f"Error in process monitoring: {e}")
                time.sleep(self.check_interval)
    
    def _check_processes(self):
        """Check running processes for suspicious software."""
        try:
            current_processes = set()
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    current_processes.add(proc_name)
                    
                    # Only report processes we haven't already reported
                    if proc_name in self.suspicious_processes and proc_name not in self.reported_processes:
                        reason = self.suspicious_processes[proc_name]
                        self.suspicious_process_detected.emit(proc_name, reason)
                        self.reported_processes.add(proc_name)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Remove processes that are no longer running from reported set
            self.reported_processes &= current_processes
            
        except Exception as e:
            print(f"Error checking processes: {e}")


class WindowFocusMonitor(QObject):
    """Monitors window focus changes and implements security measures."""
    
    focus_lost = pyqtSignal()
    focus_gained = pyqtSignal()
    window_minimized = pyqtSignal()
    alt_tab_detected = pyqtSignal()
    
    def __init__(self, protected_widget: QWidget, parent=None):
        super().__init__(parent)
        self.protected_widget = protected_widget
        self.monitoring = False
        self.timer = QTimer()
        self.timer.timeout.connect(self._check_focus)
        self.last_focus_state = True
        self.blur_effect = None
        
        # Install event filter on the protected widget
        if self.protected_widget:
            self.protected_widget.installEventFilter(self)
    
    def start_monitoring(self):
        """Start focus monitoring."""
        self.monitoring = True
        self.timer.start(100)  # Check every 100ms
    
    def stop_monitoring(self):
        """Stop focus monitoring."""
        self.monitoring = False
        self.timer.stop()
        self._remove_blur_effect()
    
    def _check_focus(self):
        """Check if the protected widget has focus."""
        if not self.protected_widget:
            return
        
        has_focus = self.protected_widget.hasFocus() or self.protected_widget.isActiveWindow()
        
        if has_focus != self.last_focus_state:
            if has_focus:
                self.focus_gained.emit()
                self._remove_blur_effect()
            else:
                self.focus_lost.emit()
                self._apply_blur_effect()
            
            self.last_focus_state = has_focus
    
    def _apply_blur_effect(self):
        """Apply blur effect when focus is lost."""
        try:
            if not self.blur_effect and self.protected_widget:
                self.blur_effect = QGraphicsBlurEffect()
                self.blur_effect.setBlurRadius(15)
                self.protected_widget.setGraphicsEffect(self.blur_effect)
        except Exception as e:
            print(f"Error applying blur effect: {e}")
    
    def _remove_blur_effect(self):
        """Remove blur effect when focus is gained."""
        try:
            if self.blur_effect and self.protected_widget:
                self.protected_widget.setGraphicsEffect(None)
                self.blur_effect = None
        except Exception as e:
            print(f"Error removing blur effect: {e}")
    
    def eventFilter(self, obj, event):
        """Event filter to detect focus changes and key combinations."""
        # Detect Alt+Tab attempts
        if hasattr(event, 'key') and event.key() == Qt.Key_Tab:
            if hasattr(event, 'modifiers') and event.modifiers() & Qt.AltModifier:
                self.alt_tab_detected.emit()
                return True  # Block Alt+Tab
        
        return False


class DynamicWatermark(QObject):
    """Creates dynamic, moving watermarks that are difficult to remove."""
    
    def __init__(self, username: str, parent=None):
        super().__init__(parent)
        self.username = username
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self._update_position)
        self.current_position = 0
        self.watermark_widgets = []
    
    def create_dynamic_watermark_overlay(self, parent_widget: QWidget) -> QWidget:
        """Create a dynamic watermark overlay."""
        overlay = QFrame(parent_widget)
        overlay.setFrameStyle(QFrame.NoFrame)
        overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        overlay.setStyleSheet("background: transparent;")
        
        # Create watermark text
        watermark_text = f"CONFIDENTIAL - {self.username} - {self.timestamp}"
        
        # Create multiple watermark labels at different positions
        for i in range(5):
            label = QLabel(watermark_text, overlay)
            label.setStyleSheet("""
                QLabel {
                    color: rgba(255, 0, 0, 180);
                    font-weight: bold;
                    font-size: 14px;
                    background: transparent;
                }
            """)
            label.setAttribute(Qt.WA_TransparentForMouseEvents)
            self.watermark_widgets.append(label)
        
        # Start animation
        self.animation_timer.start(1000)  # Update every second
        
        return overlay
    
    def _update_position(self):
        """Update watermark positions for dynamic effect."""
        self.current_position = (self.current_position + 1) % 360
        
        for i, widget in enumerate(self.watermark_widgets):
            if widget and widget.parent():
                parent = widget.parent()
                angle = self.current_position + (i * 72)  # 72 degrees apart
                
                # Calculate new position
                radius = min(parent.width(), parent.height()) // 4
                center_x = parent.width() // 2
                center_y = parent.height() // 2
                
                import math
                x = center_x + int(radius * math.cos(math.radians(angle)))
                y = center_y + int(radius * math.sin(math.radians(angle)))
                
                widget.move(x - widget.width() // 2, y - widget.height() // 2)


class ClipboardMonitor(QObject):
    """Monitors and protects clipboard content."""
    
    clipboard_access_detected = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitoring = False
        self.timer = QTimer()
        self.timer.timeout.connect(self._check_clipboard)
        self.last_clipboard_content = None
        self.protected_content_active = False
    
    def start_monitoring(self):
        """Start clipboard monitoring."""
        self.monitoring = True
        self._store_current_clipboard()
        self.timer.start(200)  # Check every 200ms
    
    def stop_monitoring(self):
        """Stop clipboard monitoring."""
        self.monitoring = False
        self.timer.stop()
    
    def set_protection_active(self, active: bool):
        """Set whether clipboard protection is active."""
        self.protected_content_active = active
    
    def _check_clipboard(self):
        """Check for clipboard changes."""
        if not self.protected_content_active:
            return
        
        clipboard = QApplication.clipboard()
        current_content = clipboard.text()
        
        if current_content != self.last_clipboard_content:
            if self.last_clipboard_content is not None:
                # Clear clipboard if content was copied
                clipboard.clear()
                self.clipboard_access_detected.emit()
        
        self.last_clipboard_content = current_content
    
    def _store_current_clipboard(self):
        """Store current clipboard state."""
        clipboard = QApplication.clipboard()
        self.last_clipboard_content = clipboard.text()


class SecurityEventLogger:
    """Logs security events for analysis and audit."""
    
    def __init__(self, log_directory: str):
        self.log_directory = log_directory
        os.makedirs(log_directory, exist_ok=True)
        self.events = []
        self.max_events_in_memory = 1000
    
    def log_event(self, event: SecurityEvent):
        """Log a security event."""
        self.events.append(event)
        
        # Write to file immediately for critical events
        if event.severity == 'critical':
            self._write_event_to_file(event)
        
        # Flush events if we have too many in memory
        if len(self.events) >= self.max_events_in_memory:
            self._flush_events()
    
    def _write_event_to_file(self, event: SecurityEvent):
        """Write a single event to file."""
        log_file = os.path.join(
            self.log_directory, 
            f"security_events_{event.timestamp.strftime('%Y%m%d')}.json"
        )
        
        event_data = {
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type,
            'severity': event.severity,
            'details': event.details,
            'user_agent': event.user_agent,
            'window_title': event.window_title,
            'process_name': event.process_name
        }
        
        try:
            # Append to daily log file
            mode = 'a' if os.path.exists(log_file) else 'w'
            with open(log_file, mode) as f:
                json.dump(event_data, f)
                f.write('\n')
        except Exception as e:
            print(f"Failed to write security event to log: {e}")
    
    def _flush_events(self):
        """Flush all events to file and clear memory."""
        for event in self.events:
            self._write_event_to_file(event)
        self.events.clear()
    
    def get_recent_events(self, hours: int = 24) -> List[SecurityEvent]:
        """Get recent security events."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [event for event in self.events if event.timestamp > cutoff_time]


class AdvancedScreenProtectionManager:
    """Comprehensive screen protection system for view-only files."""
    
    def __init__(self, username: str, protected_widget: QWidget, log_directory: str, security_level: SecurityLevel = None):
        self.username = username
        self.protected_widget = protected_widget
        self.active = False
        
        # Load security configuration
        self.security_config = get_security_config(security_level)
        
        # Initialize components
        self.process_monitor = ProcessMonitor()
        self.focus_monitor = WindowFocusMonitor(protected_widget)
        self.clipboard_monitor = ClipboardMonitor()
        self.dynamic_watermark = DynamicWatermark(username)
        self.security_logger = SecurityEventLogger(log_directory)
        
        # Import existing screen protection
        try:
            from .screen_protection import ScreenProtectionManager
            self.basic_protection = ScreenProtectionManager(username, protected_widget)
        except ImportError:
            print("Basic screen protection not available")
            self.basic_protection = None
            
        # Initialize ultra-fast screenshot prevention (Windows only)
        self.ultra_fast_protection = None
        if platform.system().lower() == 'windows':
            try:
                self.ultra_fast_protection = ComprehensiveScreenshotPrevention()
                self.ultra_fast_protection.screenshot_attempt_detected.connect(
                    self._on_ultra_fast_screenshot_attempt
                )
            except Exception as e:
                print(f"Ultra-fast screenshot prevention not available: {e}")
        
        # Connect signals
        self._connect_signals()
        
        # Security settings from configuration
        self.max_focus_loss_count = self.security_config['max_focus_loss_count']
        self.focus_loss_count = 0
        self.suspicious_activity_score = 0
        self.max_suspicious_score = self.security_config['max_suspicious_score']
        
        # Update process monitor check interval
        self.process_monitor.check_interval = self.security_config['check_interval']
        
        # Overlay widgets
        self.security_overlay = None
        
        # Whitelisted processes (development and common applications)
        self.whitelisted_processes = {
            'code.exe': 'Visual Studio Code (Development Environment)',
            'devenv.exe': 'Visual Studio (Development Environment)',
            'pycharm64.exe': 'PyCharm (Development Environment)',
            'pycharm.exe': 'PyCharm (Development Environment)',
            'sublime_text.exe': 'Sublime Text (Development Environment)',
            'notepad++.exe': 'Notepad++ (Development Environment)',
            'atom.exe': 'Atom Editor (Development Environment)',
            'chrome.exe': 'Google Chrome (Browser)',
            'firefox.exe': 'Mozilla Firefox (Browser)',
            'msedge.exe': 'Microsoft Edge (Browser)',
            'explorer.exe': 'Windows Explorer (System)',
            'dwm.exe': 'Desktop Window Manager (System)',
            'winlogon.exe': 'Windows Logon (System)',
            'csrss.exe': 'Client Server Runtime (System)',
            'svchost.exe': 'Service Host (System)',
            'python.exe': 'Python Interpreter (Development)',
            'pythonw.exe': 'Python Interpreter (Development)',
            'node.exe': 'Node.js (Development)',
            'npm.exe': 'Node Package Manager (Development)',
            'git.exe': 'Git Version Control (Development)',
            'powershell.exe': 'PowerShell (System/Development)',
            'pwsh.exe': 'PowerShell Core (System/Development)',
            'cmd.exe': 'Command Prompt (System)',
            'conhost.exe': 'Console Host (System)',
            'wininit.exe': 'Windows Initialization (System)',
            'services.exe': 'Service Control Manager (System)',
            'lsass.exe': 'Local Security Authority (System)',
            'spoolsv.exe': 'Print Spooler (System)',
            'taskeng.exe': 'Task Scheduler Engine (System)',
            'taskhost.exe': 'Task Host (System)',
            'taskhostw.exe': 'Task Host Window (System)',
            'audiodg.exe': 'Windows Audio Device Graph (System)',
            'registry.exe': 'Registry Editor (System)',
            'mmc.exe': 'Microsoft Management Console (System)'
        }
        
        # Check if we're in a development environment
        self.is_development_env = self._detect_development_environment()
        
    def _connect_signals(self):
        """Connect all monitoring signals."""
        # Process monitoring
        self.process_monitor.suspicious_process_detected.connect(self._on_suspicious_process)
        
        # Focus monitoring
        self.focus_monitor.focus_lost.connect(self._on_focus_lost)
        self.focus_monitor.focus_gained.connect(self._on_focus_gained)
        self.focus_monitor.alt_tab_detected.connect(self._on_alt_tab_detected)
        
        # Clipboard monitoring
        self.clipboard_monitor.clipboard_access_detected.connect(self._on_clipboard_access)
        
    def _on_ultra_fast_screenshot_attempt(self, detection_type: str, details: str):
        """Handle ultra-fast screenshot attempt detection."""
        self.suspicious_activity_score += 15  # High penalty for screenshot attempts
        
        self._log_security_event("ultra_fast_screenshot_attempt", "high", {
            "detection_type": detection_type,
            "details": details,
            "suspicious_score": self.suspicious_activity_score
        })
        
        print(f"Ultra-fast screenshot attempt detected: {detection_type} - {details}")
        
        if self.suspicious_activity_score >= self.max_suspicious_score:
            self._handle_security_breach(f"Multiple ultra-fast screenshot attempts: {detection_type}")
    
    def start_protection(self):
        """Start comprehensive screen protection."""
        if self.active:
            return
        
        self.active = True
        
        # Log protection start
        self._log_security_event("protection_started", "info", {
            "protected_widget": str(type(self.protected_widget)),
            "username": self.username,
            "security_config": str(self.security_config),
            "max_suspicious_score": self.max_suspicious_score
        })
        
        # Start monitors based on security configuration
        try:
            # Process monitoring
            if self.security_config['process_monitoring_enabled']:
                self.process_monitor.start_monitoring()
            else:
                print("Process monitoring disabled by security configuration")
            
            # Focus monitoring
            if self.security_config['focus_monitoring_enabled']:
                self.focus_monitor.start_monitoring()
            
            # Clipboard protection
            if self.security_config['clipboard_protection_enabled']:
                self.clipboard_monitor.start_monitoring()
                self.clipboard_monitor.set_protection_active(True)
            
            # Screenshot blocking
            if self.security_config['screenshot_blocking_enabled'] and self.basic_protection:
                self.basic_protection.start_monitoring()
            
            # Ultra-fast screenshot prevention
            if self.security_config['screenshot_blocking_enabled'] and self.ultra_fast_protection:
                self.ultra_fast_protection.start_all_monitoring()
            
            # Security overlay
            if self.security_config['overlay_protection_enabled']:
                self._create_security_overlay()
            
            print(f"Advanced screen protection started successfully with security level configuration")
            
        except Exception as e:
            self._log_security_event("protection_start_failed", "high", {
                "error": str(e)
            })
            print(f"Failed to start some protection components: {e}")
    
    def stop_protection(self):
        """Stop all screen protection."""
        if not self.active:
            return
        
        self.active = False
        
        # Log protection stop
        self._log_security_event("protection_stopped", "info", {
            "focus_loss_count": self.focus_loss_count,
            "suspicious_activity_score": self.suspicious_activity_score
        })
        
        try:
            # Stop all monitors (conditionally stop process monitor)
            if not self.is_development_env:
                self.process_monitor.stop_monitoring()
            self.focus_monitor.stop_monitoring()
            self.clipboard_monitor.stop_monitoring()
            
            # Stop basic protection
            if self.basic_protection:
                self.basic_protection.stop_monitoring()
                
            # Stop ultra-fast protection
            if self.ultra_fast_protection:
                self.ultra_fast_protection.stop_all_monitoring()
            
            # Remove security overlay
            self._remove_security_overlay()
            
            # Flush security logs
            self.security_logger._flush_events()
            
            print("Screen protection stopped")
            
        except Exception as e:
            print(f"Error stopping protection components: {e}")
    
    def _create_security_overlay(self):
        """Create security overlay with watermarks."""
        if not self.protected_widget:
            return
        
        try:
            self.security_overlay = self.dynamic_watermark.create_dynamic_watermark_overlay(
                self.protected_widget
            )
            
            # Position overlay to cover the entire widget
            if self.security_overlay:
                self.security_overlay.resize(self.protected_widget.size())
                self.security_overlay.show()
                
        except Exception as e:
            print(f"Failed to create security overlay: {e}")
    
    def _remove_security_overlay(self):
        """Remove security overlay."""
        if self.security_overlay:
            try:
                self.security_overlay.hide()
                self.security_overlay.deleteLater()
                self.security_overlay = None
            except Exception as e:
                print(f"Error removing security overlay: {e}")
    
    def _on_suspicious_process(self, process_name: str, reason: str):
        """Handle detection of suspicious processes."""
        # Check if process is whitelisted
        if process_name.lower() in [p.lower() for p in self.whitelisted_processes.keys()]:
            # Log but don't treat as suspicious
            self._log_security_event("whitelisted_process", "info", {
                "process_name": process_name,
                "reason": f"Whitelisted: {self.whitelisted_processes.get(process_name.lower(), 'Unknown')}"
            })
            return
        
        # In development environment, be less aggressive
        score_increase = 1 if self.is_development_env else 2
        self.suspicious_activity_score += score_increase
        
        severity = "low" if self.is_development_env else "medium"
        
        self._log_security_event("suspicious_process", severity, {
            "process_name": process_name,
            "reason": reason,
            "suspicious_score": self.suspicious_activity_score,
            "development_env": self.is_development_env
        })
        
        if self.is_development_env:
            print(f"Note: Process detected in dev environment: {process_name} - {reason} (Score: {self.suspicious_activity_score})")
        else:
            print(f"Suspicious process detected: {process_name} - {reason}")
        
        # Take action if score is too high
        if self.suspicious_activity_score >= self.max_suspicious_score:
            breach_reason = "Too many suspicious processes detected"
            if self.is_development_env:
                breach_reason += " (Development environment - consider using production mode)"
            self._handle_critical_security_breach(breach_reason)
    
    def _on_focus_lost(self):
        """Handle window focus loss."""
        self.focus_loss_count += 1
        
        self._log_security_event("focus_lost", "low", {
            "focus_loss_count": self.focus_loss_count
        })
        
        # Increase suspicious activity score for frequent focus changes
        if self.focus_loss_count > self.max_focus_loss_count:
            self.suspicious_activity_score += 1
            
            if self.suspicious_activity_score >= self.max_suspicious_score:
                self._handle_critical_security_breach("Excessive window focus changes")
    
    def _on_focus_gained(self):
        """Handle window focus gained."""
        self._log_security_event("focus_gained", "info", {})
    
    def _on_alt_tab_detected(self):
        """Handle Alt+Tab detection."""
        self.suspicious_activity_score += 1
        
        self._log_security_event("alt_tab_blocked", "medium", {
            "suspicious_score": self.suspicious_activity_score
        })
        
        print("Alt+Tab blocked - potential task switching attempt")
    
    def _on_clipboard_access(self):
        """Handle clipboard access attempt."""
        self.suspicious_activity_score += 3
        
        self._log_security_event("clipboard_access_blocked", "high", {
            "suspicious_score": self.suspicious_activity_score
        })
        
        print("Clipboard access blocked - potential copy attempt")
        
        if self.suspicious_activity_score >= self.max_suspicious_score:
            self._handle_critical_security_breach("Clipboard access detected")
    
    def _handle_critical_security_breach(self, reason: str):
        """Handle critical security breach."""
        self._log_security_event("critical_security_breach", "critical", {
            "reason": reason,
            "focus_loss_count": self.focus_loss_count,
            "suspicious_activity_score": self.suspicious_activity_score,
            "action": "force_close_viewer"
        })
        
        print(f"CRITICAL SECURITY BREACH: {reason}")
        
        # Force close the protected widget
        if self.protected_widget:
            self.protected_widget.close()
    
    def _log_security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log a security event."""
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            details=details,
            user_agent=self.username,
            window_title=self.protected_widget.windowTitle() if self.protected_widget else "",
            process_name=os.path.basename(sys.argv[0]) if sys.argv else ""
        )
        
        self.security_logger.log_event(event)
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status."""
        return {
            "active": self.active,
            "focus_loss_count": self.focus_loss_count,
            "suspicious_activity_score": self.suspicious_activity_score,
            "max_suspicious_score": self.max_suspicious_score,
            "recent_events": len(self.security_logger.get_recent_events(1))
        }
    
    def reset_security_scores(self):
        """Reset security scores (for testing or after manual review)."""
        self.focus_loss_count = 0
        self.suspicious_activity_score = 0
        
        self._log_security_event("security_scores_reset", "info", {
            "reset_by": self.username
        })
    
    def _detect_development_environment(self) -> bool:
        """Detect if we're running in a development environment."""
        try:
            # Check common development indicators
            dev_indicators = [
                # Check if we're running from a development directory
                'Desktop' in os.getcwd(),
                'dev' in os.getcwd().lower(),
                'development' in os.getcwd().lower(),
                'src' in os.getcwd().lower(),
                'project' in os.getcwd().lower(),
                # Check if Python is running in development mode
                hasattr(sys, 'ps1'),  # Interactive Python session
                # Check for common development environment variables
                os.environ.get('DEVELOPMENT') is not None,
                os.environ.get('DEBUG') is not None,
                # Check if running from IDE
                'PYCHARM' in os.environ,
                'VSCODE' in os.environ,
            ]
            
            return any(dev_indicators)
        except Exception as e:
            print(f"Error detecting development environment: {e}")
            return False
