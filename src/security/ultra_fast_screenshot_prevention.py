"""
Ultra-Fast Screenshot Prevention System

This module provides an additional layer of screenshot prevention that runs
at high frequency to catch extremely fast key combinations that might bypass
the standard Windows hook system.

Author: Rolan Lobo (RNR)  
Project: BAR - Burn After Reading Security Suite
"""

import time
import threading
import win32api
import win32con
import ctypes
from ctypes import wintypes
from PyQt5.QtCore import QObject, pyqtSignal, QTimer


class UltraFastScreenshotPrevention(QObject):
    """High-frequency polling system to catch ultra-fast screenshot attempts."""
    
    screenshot_attempt_detected = pyqtSignal(str, str)  # type, details
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitoring = False
        self.poll_thread = None
        self.poll_interval = 0.01  # 10ms polling (100Hz)
        
        # Key state tracking
        self.previous_states = {}
        self.combo_detection_window = 0.05  # 50ms window for combo detection
        
        # Screenshot key combinations to monitor
        self.screenshot_keys = [
            win32con.VK_SNAPSHOT,  # Print Screen
            (win32con.VK_LWIN, win32con.VK_SHIFT, 0x53),  # Win+Shift+S
            (win32con.VK_RWIN, win32con.VK_SHIFT, 0x53),  # Win+Shift+S (right win)
            (win32con.VK_MENU, win32con.VK_SNAPSHOT),     # Alt+Print Screen
        ]
        
        # Rapid-fire prevention
        self.last_detection = 0
        self.detection_cooldown = 0.1  # 100ms between detections
        
        # Statistics
        self.detections_count = 0
        self.false_positives_filtered = 0
        
    def start_monitoring(self):
        """Start ultra-fast screenshot monitoring."""
        if self.monitoring:
            return
            
        self.monitoring = True
        self.poll_thread = threading.Thread(target=self._polling_loop, daemon=True)
        self.poll_thread.start()
        print("Ultra-fast screenshot prevention started (100Hz polling)")
        
    def stop_monitoring(self):
        """Stop ultra-fast screenshot monitoring."""
        self.monitoring = False
        if self.poll_thread:
            self.poll_thread.join(timeout=1.0)
        print("Ultra-fast screenshot prevention stopped")
        
    def _polling_loop(self):
        """High-frequency polling loop to detect key combinations."""
        while self.monitoring:
            try:
                current_time = time.time()
                
                # Check for rapid key state changes
                self._check_rapid_key_changes(current_time)
                
                # Check for screenshot key combinations
                self._check_screenshot_combinations(current_time)
                
                # Sleep for polling interval
                time.sleep(self.poll_interval)
                
            except Exception as e:
                print(f"Error in ultra-fast polling loop: {e}")
                time.sleep(0.05)  # Longer sleep on error
                
    def _check_rapid_key_changes(self, current_time):
        """Check for suspiciously rapid key state changes."""
        try:
            # Sample key states for critical keys
            critical_keys = [
                win32con.VK_SNAPSHOT,
                win32con.VK_LWIN, win32con.VK_RWIN,
                win32con.VK_SHIFT, win32con.VK_CONTROL,
                0x53  # S key
            ]
            
            rapid_changes = 0
            for vk_code in critical_keys:
                try:
                    current_state = win32api.GetAsyncKeyState(vk_code) & 0x8000
                    previous_state = self.previous_states.get(vk_code, False)
                    
                    # Detect state change
                    if current_state != previous_state:
                        self.previous_states[vk_code] = current_state
                        rapid_changes += 1
                        
                except Exception:
                    continue
            
            # If too many keys changed state simultaneously, it might be suspicious
            if rapid_changes >= 3:
                if current_time - self.last_detection > self.detection_cooldown:
                    self.last_detection = current_time
                    self.detections_count += 1
                    self.screenshot_attempt_detected.emit(
                        "rapid_key_change", 
                        f"Detected {rapid_changes} simultaneous key changes"
                    )
                    
        except Exception as e:
            print(f"Error checking rapid key changes: {e}")
            
    def _check_screenshot_combinations(self, current_time):
        """Check for specific screenshot key combinations."""
        try:
            # Check Print Screen
            if self._is_key_pressed(win32con.VK_SNAPSHOT):
                if current_time - self.last_detection > self.detection_cooldown:
                    self.last_detection = current_time
                    self.detections_count += 1
                    self.screenshot_attempt_detected.emit("printscreen", "Print Screen key detected")
            
            # Check Win+Shift+S combinations
            for win_key in [win32con.VK_LWIN, win32con.VK_RWIN]:
                if (self._is_key_pressed(win_key) and 
                    self._is_key_pressed(win32con.VK_SHIFT) and 
                    self._is_key_pressed(0x53)):  # S key
                    
                    if current_time - self.last_detection > self.detection_cooldown:
                        self.last_detection = current_time
                        self.detections_count += 1
                        self.screenshot_attempt_detected.emit(
                            "win_shift_s", 
                            f"Win+Shift+S combination detected ({'L' if win_key == win32con.VK_LWIN else 'R'}Win)"
                        )
            
            # Check Alt+Print Screen
            if (self._is_key_pressed(win32con.VK_MENU) and 
                self._is_key_pressed(win32con.VK_SNAPSHOT)):
                
                if current_time - self.last_detection > self.detection_cooldown:
                    self.last_detection = current_time
                    self.detections_count += 1
                    self.screenshot_attempt_detected.emit("alt_printscreen", "Alt+Print Screen detected")
                    
        except Exception as e:
            print(f"Error checking screenshot combinations: {e}")
            
    def _is_key_pressed(self, vk_code):
        """Check if a virtual key is currently pressed."""
        try:
            return (win32api.GetAsyncKeyState(vk_code) & 0x8000) != 0
        except Exception:
            return False
            
    def get_statistics(self):
        """Get monitoring statistics."""
        return {
            "detections_count": self.detections_count,
            "false_positives_filtered": self.false_positives_filtered,
            "monitoring": self.monitoring,
            "poll_interval_ms": self.poll_interval * 1000
        }


class ClipboardWatcher(QObject):
    """Monitor clipboard for screenshot-related changes."""
    
    clipboard_screenshot_detected = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitoring = False
        self.last_clipboard_hash = None
        self.timer = QTimer()
        self.timer.timeout.connect(self._check_clipboard)
        
    def start_monitoring(self):
        """Start clipboard monitoring."""
        if not self.monitoring:
            self.monitoring = True
            self.timer.start(50)  # Check every 50ms
            
    def stop_monitoring(self):
        """Stop clipboard monitoring."""
        if self.monitoring:
            self.monitoring = False
            self.timer.stop()
            
    def _check_clipboard(self):
        """Check clipboard for new screenshot content."""
        try:
            # Try to open clipboard
            if not win32api.OpenClipboard(0):
                return
                
            try:
                # Check if clipboard contains bitmap data (screenshots)
                if win32api.IsClipboardFormatAvailable(win32con.CF_BITMAP):
                    # Get current clipboard data hash
                    try:
                        data = win32api.GetClipboardData(win32con.CF_BITMAP)
                        if data:
                            data_hash = hash(str(data))
                            if self.last_clipboard_hash != data_hash:
                                self.last_clipboard_hash = data_hash
                                self.clipboard_screenshot_detected.emit()
                    except Exception:
                        pass
                        
            finally:
                win32api.CloseClipboard()
                
        except Exception as e:
            # Clipboard access can fail for various reasons, don't spam errors
            pass


class ComprehensiveScreenshotPrevention(QObject):
    """Comprehensive screenshot prevention combining multiple detection methods."""
    
    screenshot_attempt_detected = pyqtSignal(str, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Initialize all prevention systems
        self.ultra_fast = UltraFastScreenshotPrevention(self)
        self.clipboard_watcher = ClipboardWatcher(self)
        
        # Connect signals
        self.ultra_fast.screenshot_attempt_detected.connect(
            self.screenshot_attempt_detected
        )
        self.clipboard_watcher.clipboard_screenshot_detected.connect(
            lambda: self.screenshot_attempt_detected.emit("clipboard", "Screenshot detected in clipboard")
        )
        
        # Statistics
        self.total_detections = 0
        
    def start_all_monitoring(self):
        """Start all screenshot prevention systems."""
        self.ultra_fast.start_monitoring()
        self.clipboard_watcher.start_monitoring()
        print("Comprehensive screenshot prevention activated")
        
    def stop_all_monitoring(self):
        """Stop all screenshot prevention systems."""
        self.ultra_fast.stop_monitoring()
        self.clipboard_watcher.stop_monitoring()
        print("Comprehensive screenshot prevention deactivated")
        
    def get_comprehensive_statistics(self):
        """Get statistics from all monitoring systems."""
        ultra_fast_stats = self.ultra_fast.get_statistics()
        
        return {
            "total_detections": self.total_detections,
            "ultra_fast_detections": ultra_fast_stats["detections_count"],
            "systems_active": {
                "ultra_fast": ultra_fast_stats["monitoring"],
                "clipboard_watcher": self.clipboard_watcher.monitoring,
            },
            "performance": {
                "ultra_fast_poll_ms": ultra_fast_stats["poll_interval_ms"],
                "clipboard_check_ms": 50
            }
        }
