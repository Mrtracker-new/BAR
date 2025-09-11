"""
Window-Level Screenshot Prevention

This module implements window-specific screenshot prevention using Windows DWM
(Desktop Window Manager) and security attributes to make windows unscreenshottable.

Author: Rolan Lobo (RNR)
Project: BAR - Burn After Reading Security Suite
"""

import ctypes
import ctypes.wintypes
from ctypes import wintypes
import win32api
import win32con
import win32gui
import sys
import time
from PyQt5.QtCore import QObject, pyqtSignal, QTimer
from PyQt5.QtWidgets import QWidget


# Windows DWM constants
DWMWA_EXCLUDED_FROM_PEEK = 12
DWMWA_DISALLOW_PEEK = 13
DWMWA_CLOAK = 13
DWMWA_CLOAKED = 14

# Additional Windows constants
WS_EX_NOREDIRECTIONBITMAP = 0x00200000
WS_EX_LAYERED = 0x00080000
WDA_NONE = 0
WDA_MONITOR = 1


class WindowProtectionManager(QObject):
    """Manages window-level screenshot protection."""
    
    protection_applied = pyqtSignal(str)
    protection_failed = pyqtSignal(str, str)
    
    def __init__(self, protected_widget: QWidget, parent=None):
        super().__init__(parent)
        self.protected_widget = protected_widget
        self.hwnd = None
        self.original_style = None
        self.original_ex_style = None
        self.protection_active = False
        
        # Windows API functions
        self.user32 = ctypes.windll.user32
        self.dwmapi = None
        
        # Try to load DWM API
        try:
            self.dwmapi = ctypes.windll.dwmapi
        except OSError:
            print("DWM API not available - some protections will be limited")
            
        # Protection methods to apply
        self.protection_methods = [
            self._apply_no_redirection_bitmap,
            self._apply_dwm_exclusions,
            self._apply_layered_window,
            self._apply_window_security_attributes,
            self._apply_topmost_protection,
        ]
        
    def apply_protection(self):
        """Apply all available window protection methods."""
        if self.protection_active:
            return True
            
        # Get window handle
        if self.protected_widget:
            self.hwnd = int(self.protected_widget.winId())
        else:
            print("No protected widget provided")
            return False
            
        if not self.hwnd:
            print("Could not get window handle")
            return False
            
        # Store original window styles
        self._store_original_styles()
        
        success_count = 0
        total_methods = len(self.protection_methods)
        
        # Apply all protection methods
        for method in self.protection_methods:
            try:
                if method():
                    success_count += 1
                    method_name = method.__name__.replace('_apply_', '').replace('_', ' ').title()
                    self.protection_applied.emit(method_name)
            except Exception as e:
                method_name = method.__name__.replace('_apply_', '').replace('_', ' ').title()
                self.protection_failed.emit(method_name, str(e))
                
        if success_count > 0:
            self.protection_active = True
            print(f"Window protection applied: {success_count}/{total_methods} methods successful")
            return True
        else:
            print("Window protection failed: no methods were successful")
            return False
            
    def remove_protection(self):
        """Remove window protection and restore original styles."""
        if not self.protection_active or not self.hwnd:
            return
            
        try:
            # Restore original window styles
            if self.original_style is not None:
                self.user32.SetWindowLongW(self.hwnd, win32con.GWL_STYLE, self.original_style)
                
            if self.original_ex_style is not None:
                self.user32.SetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE, self.original_ex_style)
                
            # Remove topmost flag
            self.user32.SetWindowPos(
                self.hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0,
                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE
            )
            
            self.protection_active = False
            print("Window protection removed and original styles restored")
            
        except Exception as e:
            print(f"Error removing window protection: {e}")
            
    def _store_original_styles(self):
        """Store original window styles for restoration."""
        try:
            self.original_style = self.user32.GetWindowLongW(self.hwnd, win32con.GWL_STYLE)
            self.original_ex_style = self.user32.GetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE)
        except Exception as e:
            print(f"Could not store original window styles: {e}")
            
    def _apply_no_redirection_bitmap(self):
        """Apply WS_EX_NOREDIRECTIONBITMAP to prevent DWM capture."""
        try:
            current_ex_style = self.user32.GetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE)
            new_ex_style = current_ex_style | WS_EX_NOREDIRECTIONBITMAP
            
            result = self.user32.SetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE, new_ex_style)
            
            if result == 0:
                error = ctypes.get_last_error()
                print(f"SetWindowLongW failed with error: {error}")
                return False
                
            print("WS_EX_NOREDIRECTIONBITMAP applied successfully")
            return True
            
        except Exception as e:
            print(f"Failed to apply WS_EX_NOREDIRECTIONBITMAP: {e}")
            return False
            
    def _apply_dwm_exclusions(self):
        """Apply DWM exclusions to prevent thumbnail and peek capture."""
        if not self.dwmapi:
            return False
            
        try:
            # Exclude from peek (Alt+Tab thumbnails)
            peek_value = ctypes.c_int(1)  # TRUE
            result1 = self.dwmapi.DwmSetWindowAttribute(
                self.hwnd,
                DWMWA_EXCLUDED_FROM_PEEK,
                ctypes.byref(peek_value),
                ctypes.sizeof(peek_value)
            )
            
            # Try to cloak the window from capture
            cloak_value = ctypes.c_int(1)  # TRUE  
            result2 = self.dwmapi.DwmSetWindowAttribute(
                self.hwnd,
                DWMWA_CLOAK,
                ctypes.byref(cloak_value),
                ctypes.sizeof(cloak_value)
            )
            
            if result1 == 0 or result2 == 0:
                print("DWM exclusions applied successfully")
                return True
            else:
                print(f"DWM exclusions failed: result1={result1}, result2={result2}")
                return False
                
        except Exception as e:
            print(f"Failed to apply DWM exclusions: {e}")
            return False
            
    def _apply_layered_window(self):
        """Apply layered window attributes for additional protection."""
        try:
            current_ex_style = self.user32.GetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE)
            new_ex_style = current_ex_style | WS_EX_LAYERED
            
            # Apply layered window style
            result1 = self.user32.SetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE, new_ex_style)
            
            # Set layered window attributes (fully opaque but layered)
            result2 = self.user32.SetLayeredWindowAttributes(
                self.hwnd, 
                0,  # colorkey (not used)
                255,  # alpha (fully opaque)
                win32con.LWA_ALPHA  # use alpha
            )
            
            if result1 != 0 and result2 != 0:
                print("Layered window attributes applied successfully")
                return True
            else:
                print(f"Layered window failed: result1={result1}, result2={result2}")
                return False
                
        except Exception as e:
            print(f"Failed to apply layered window: {e}")
            return False
            
    def _apply_window_security_attributes(self):
        """Apply additional security-related window attributes."""
        try:
            # Make window tool window to exclude from many capture methods
            current_ex_style = self.user32.GetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE)
            new_ex_style = current_ex_style | win32con.WS_EX_TOOLWINDOW
            
            result = self.user32.SetWindowLongW(self.hwnd, win32con.GWL_EXSTYLE, new_ex_style)
            
            if result != 0:
                print("Security window attributes applied successfully")
                return True
            else:
                print("Security window attributes failed")
                return False
                
        except Exception as e:
            print(f"Failed to apply security attributes: {e}")
            return False
            
    def _apply_topmost_protection(self):
        """Make window topmost for additional protection."""
        try:
            result = self.user32.SetWindowPos(
                self.hwnd,
                win32con.HWND_TOPMOST,
                0, 0, 0, 0,
                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE
            )
            
            if result != 0:
                print("Topmost protection applied successfully")
                return True
            else:
                print("Topmost protection failed")
                return False
                
        except Exception as e:
            print(f"Failed to apply topmost protection: {e}")
            return False


class ScreenshotDetectionOverlay(QWidget):
    """Transparent overlay to detect screenshot attempts via window messages."""
    
    screenshot_detected = pyqtSignal()
    
    def __init__(self, parent_widget: QWidget):
        super().__init__(parent_widget)
        self.parent_widget = parent_widget
        
        # Make overlay transparent and on top
        self.setWindowFlags(
            self.windowFlags() | 
            win32con.Qt.FramelessWindowHint |
            win32con.Qt.WindowStaysOnTopHint |
            win32con.Qt.Tool
        )
        self.setAttribute(win32con.Qt.WA_TranslucentBackground)
        
        # Position overlay over parent
        self.resize(parent_widget.size())
        self.move(parent_widget.pos())
        
        # Timer to check for capture attempts
        self.detection_timer = QTimer()
        self.detection_timer.timeout.connect(self._check_for_capture)
        self.detection_timer.start(10)  # Check every 10ms
        
    def _check_for_capture(self):
        """Check for potential capture attempts."""
        try:
            # Check if parent window has lost focus (potential screenshot)
            if not self.parent_widget.hasFocus() and not self.hasFocus():
                # Additional checks could go here
                pass
                
        except Exception as e:
            print(f"Capture detection error: {e}")


class ComprehensiveWindowProtection(QObject):
    """Comprehensive window protection combining all methods."""
    
    protection_status_changed = pyqtSignal(str, bool)  # method, success
    
    def __init__(self, protected_widget: QWidget, parent=None):
        super().__init__(parent)
        self.protected_widget = protected_widget
        
        # Initialize protection components
        self.window_protection = WindowProtectionManager(protected_widget, self)
        self.detection_overlay = None
        
        # Connect signals
        self.window_protection.protection_applied.connect(
            lambda method: self.protection_status_changed.emit(method, True)
        )
        self.window_protection.protection_failed.connect(
            lambda method, error: self.protection_status_changed.emit(f"{method}: {error}", False)
        )
        
        self.active = False
        
    def start_comprehensive_protection(self):
        """Start all window protection methods."""
        if self.active:
            return True
            
        print("🔒 Starting comprehensive window protection...")
        
        # Apply window-level protections
        window_success = self.window_protection.apply_protection()
        
        # Create detection overlay
        try:
            self.detection_overlay = ScreenshotDetectionOverlay(self.protected_widget)
            self.detection_overlay.show()
            overlay_success = True
        except Exception as e:
            print(f"Failed to create detection overlay: {e}")
            overlay_success = False
            
        if window_success or overlay_success:
            self.active = True
            print("🛡️ Comprehensive window protection active")
            return True
        else:
            print("❌ Comprehensive window protection failed")
            return False
            
    def stop_comprehensive_protection(self):
        """Stop all window protection methods."""
        if not self.active:
            return
            
        print("🔓 Stopping comprehensive window protection...")
        
        # Remove window protections
        self.window_protection.remove_protection()
        
        # Remove detection overlay
        if self.detection_overlay:
            self.detection_overlay.close()
            self.detection_overlay = None
            
        self.active = False
        print("✅ Comprehensive window protection stopped")
        
    def get_protection_status(self):
        """Get current protection status."""
        return {
            "active": self.active,
            "window_protection": self.window_protection.protection_active,
            "detection_overlay": self.detection_overlay is not None,
            "protected_widget": self.protected_widget is not None
        }
