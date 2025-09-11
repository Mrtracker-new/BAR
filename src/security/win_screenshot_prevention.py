import ctypes
import threading
import time
import subprocess
from ctypes import wintypes
import win32con
import win32gui
import win32api
import win32process
from PyQt5.QtCore import QObject, pyqtSignal, QTimer, QThread
import psutil
import os

# Windows API constants
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104

# Key codes
VK_SNAPSHOT = 0x2C  # Print Screen key
VK_LWIN = 0x5B      # Left Windows key
VK_RWIN = 0x5C      # Right Windows key
VK_SHIFT = 0x10     # Shift key
VK_S = 0x53         # S key
VK_ESCAPE = 0x1B    # Escape key
VK_F1 = 0x70        # F1 key
VK_F12 = 0x7B       # F12 key

# Windows API constants for DWM
DWMWA_EXCLUDED_FROM_PEEK = 12
DWM_EC_DISABLECOMPOSITION = 0
DWM_EC_ENABLECOMPOSITION = 1

class KeyboardHook(QObject):
    """Windows keyboard hook to detect screenshot hotkeys."""
    
    # Signal emitted when a screenshot hotkey is detected
    screenshot_hotkey_detected = pyqtSignal()
    
    def __init__(self, parent=None):
        """Initialize the keyboard hook.
        
        Args:
            parent: The parent QObject
        """
        super().__init__(parent)
        self.hooked = False
        self.hook_thread = None
        self.hook_id = None
        self.key_state = {}
        self.timer = None
        try:
            self.user32 = ctypes.WinDLL('user32', use_last_error=True)
        except Exception as e:
            print(f"Failed to load user32.dll: {e}")
            self.user32 = None
        
        # Track key states
        self.win_pressed = False
        self.shift_pressed = False
        self.s_pressed = False

        # Short-term suppression window to defeat ultra-fast combos
        self.suppression_active = False
        self.suppression_until = 0  # epoch seconds
        self.suppression_window_ms = 600  # block S/PrintScreen for 600ms after Win/Shift press
        
        # Additional proactive protections
        self.last_blocked_time = 0
        self.consecutive_blocks = 0
        self.max_blocks_per_second = 10  # Limit blocks to prevent resource exhaustion
        
        # Process termination list for aggressive screenshot apps
        self.aggressive_screenshot_processes = [
            'SnippingTool.exe', 'ScreenSketch.exe', 'Snagit32.exe', 'Lightshot.exe',
            'Greenshot.exe', 'ShareX.exe', 'Gyazo.exe', 'Flameshot.exe'
        ]
        
        # Define callback function type
        self.LowLevelKeyboardProc = ctypes.CFUNCTYPE(
            wintypes.LPARAM, 
            ctypes.c_int, 
            wintypes.WPARAM, 
            wintypes.LPARAM
        )
        
        # Create callback function
        # Use ctypes.CFUNCTYPE to ensure correct function pointer type
        self._keyboard_proc_callback = self._keyboard_proc  # Store reference to prevent garbage collection
        self.keyboard_callback = self.LowLevelKeyboardProc(self._keyboard_proc_callback)
    
    def start(self):
        """Start the keyboard hook in a separate thread."""
        if not self.hooked:
            self.hooked = True
            self.hook_thread = threading.Thread(target=self._hook_thread_func, name="BAR_KeyboardHook")
            self.hook_thread.daemon = True
            self.hook_thread.start()

            # Try to boost thread priority to reduce race windows
            try:
                # Obtain handle to current thread and raise priority
                handle = win32api.OpenThread(win32con.THREAD_SET_INFORMATION | win32con.THREAD_QUERY_INFORMATION, False, int(ctypes.windll.kernel32.GetCurrentThreadId()))
                if handle:
                    try:
                        win32process.SetThreadPriority(handle, win32process.THREAD_PRIORITY_TIME_CRITICAL)
                    except Exception:
                        # Fall back to highest priority if time critical not allowed
                        win32process.SetThreadPriority(handle, win32process.THREAD_PRIORITY_HIGHEST)
            except Exception as e:
                print(f"Failed to boost keyboard hook thread priority: {e}")
            
            # Start a timer to periodically check for screenshot apps
            self.timer = QTimer()
            self.timer.timeout.connect(self._check_screenshot_apps)
            self.timer.start(1000)  # Check every second
            
            # Start additional timer for process monitoring
            self.process_timer = QTimer()
            self.process_timer.timeout.connect(self._monitor_screenshot_processes)
            self.process_timer.start(2000)  # Check every 2 seconds
    
    def stop(self):
        """Stop the keyboard hook."""
        if self.timer:
            self.timer.stop()
            self.timer = None
            
        if hasattr(self, 'process_timer') and self.process_timer:
            self.process_timer.stop()
            self.process_timer = None
            
        if self.hooked:
            self.hooked = False
            if self.hook_id:
                self.user32.UnhookWindowsHookEx(self.hook_id)
                self.hook_id = None
    
    def _hook_thread_func(self):
        """Thread function for the keyboard hook."""
        if not self.user32:
            print("Cannot set keyboard hook: user32.dll not loaded")
            return
            
        try:
            # Make sure we have the correct function prototype and handle
            # Error 126 typically means "The specified module could not be found"
            # Ensure module handle is valid
            module_handle = ctypes.windll.kernel32.GetModuleHandleW(None)
            if not module_handle:
                print("Failed to get module handle")
                return
                
            # Set the hook with proper error handling
            self.hook_id = self.user32.SetWindowsHookExA(
                WH_KEYBOARD_LL,
                self.keyboard_callback,
                module_handle,
                0
            )
        except Exception as e:
            print(f"Failed to set keyboard hook: {e}")
            return
        
        if not self.hook_id:
            error_code = ctypes.get_last_error()
            print(f"Failed to set keyboard hook: {error_code}")
            # Continue without the hook - don't crash the application
            return
        
        # Message loop - with error handling
        try:
            msg = wintypes.MSG()
            while self.hooked and self.user32.GetMessageA(ctypes.byref(msg), 0, 0, 0) != 0:
                self.user32.TranslateMessage(ctypes.byref(msg))
                self.user32.DispatchMessageA(ctypes.byref(msg))
        except Exception as e:
            print(f"Error in keyboard hook message loop: {e}")
            # Don't crash the application, just exit the thread
    
    def _keyboard_proc(self, n_code, w_param, l_param):
        """Keyboard hook callback function.
        
        Args:
            n_code: The hook code
            w_param: The key state (pressed/released)
            l_param: Pointer to a KBDLLHOOKSTRUCT structure
            
        Returns:
            The result of CallNextHookEx
        """
        try:
            if n_code >= 0:
                try:
                    kb = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                    key_code = kb.vkCode
                    
                    # Track key state for complex combinations
                    key_down = (w_param == WM_KEYDOWN or w_param == WM_SYSKEYDOWN)
                    key_up = (w_param == WM_KEYUP or w_param == 0x0105)  # WM_KEYUP or WM_SYSKEYUP
                    
                    if key_down:
                        self.key_state[key_code] = True
                    elif key_up:
                        self.key_state[key_code] = False
                    
                    # Key down events
                    if w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
                        # Track PrintScreen key directly
                        # Suppression window check (defense against ultra-fast key chords)
                        now = time.time()
                        if self.suppression_active and now < self.suppression_until:
                            if key_code in (VK_SNAPSHOT, VK_S):
                                return 1
                        else:
                            # Expire suppression when window passes
                            if self.suppression_active and now >= self.suppression_until:
                                self.suppression_active = False

                        if key_code == VK_SNAPSHOT:
                            # Rate limiting check
                            now = time.time()
                            if now - self.last_blocked_time < 1.0:
                                self.consecutive_blocks += 1
                                if self.consecutive_blocks > self.max_blocks_per_second:
                                    return 1  # Block but don't process to avoid resource exhaustion
                            else:
                                self.consecutive_blocks = 0
                            self.last_blocked_time = now
                            
                            print("PrintScreen detected and blocked")
                            try:
                                self.screenshot_hotkey_detected.emit()
                            except Exception as e:
                                print(f"Error emitting screenshot signal: {e}")
                            return 1  # Block the key
                        
                        # Track Win+Shift+S combination
                        if key_code == VK_LWIN or key_code == VK_RWIN:
                            self.win_pressed = True
                            # Activate suppression window
                            self.suppression_active = True
                            self.suppression_until = time.time() + (self.suppression_window_ms / 1000.0)
                        elif key_code == VK_SHIFT:
                            self.shift_pressed = True
                            # Activate suppression window
                            self.suppression_active = True
                            self.suppression_until = time.time() + (self.suppression_window_ms / 1000.0)
                        elif key_code == VK_S:
                            self.s_pressed = True
                        
                        # Check for Win+Shift+S combination (robust using async state)
                        try:
                            win_down = (win32api.GetAsyncKeyState(VK_LWIN) & 0x8000) or (win32api.GetAsyncKeyState(VK_RWIN) & 0x8000)
                            shift_down = (win32api.GetAsyncKeyState(VK_SHIFT) & 0x8000)
                            s_down = (win32api.GetAsyncKeyState(VK_S) & 0x8000)
                        except Exception:
                            win_down = self.win_pressed
                            shift_down = self.shift_pressed
                            s_down = self.s_pressed

                        if (self.win_pressed and self.shift_pressed and self.s_pressed) or (win_down and shift_down and s_down):
                            print("Win+Shift+S detected and blocked")
                            try:
                                self.screenshot_hotkey_detected.emit()
                            except Exception as e:
                                print(f"Error emitting screenshot signal: {e}")
                            return 1  # Block the key
                        
                        # Check for Alt+PrintScreen (window screenshot)
                        try:
                            if key_code == VK_S and win32api.GetAsyncKeyState(0x12) & 0x8000:  # Alt key
                                if self.win_pressed and self.shift_pressed:
                                    print("Alt+Win+Shift+S detected and blocked")
                                    try:
                                        self.screenshot_hotkey_detected.emit()
                                    except Exception as e:
                                        print(f"Error emitting screenshot signal: {e}")
                                    return 1  # Block the key
                        except Exception as e:
                            print(f"Error checking Alt key state: {e}")
                    
                    # Key up events
                    elif w_param in (WM_KEYUP, 0x0105):  # WM_KEYUP or WM_SYSKEYUP
                        if key_code == VK_LWIN or key_code == VK_RWIN:
                            self.win_pressed = False
                        elif key_code == VK_SHIFT:
                            self.shift_pressed = False
                        elif key_code == VK_S:
                            self.s_pressed = False

                        # If all keys are up, end suppression quickly
                        if not (self.win_pressed or self.shift_pressed):
                            self.suppression_active = False
                except Exception as e:
                    print(f"Error processing keyboard event: {e}")
            
            # Call the next hook with robust error handling
            try:
                if self.user32 and self.hook_id:
                    return self.user32.CallNextHookEx(self.hook_id, n_code, w_param, l_param)
                return 0
            except Exception as e:
                print(f"Error calling next hook: {e}")
                return 0
        except Exception as e:
            print(f"Critical error in keyboard hook: {e}")
            # Don't crash the application, just pass the event through
            return 0
    
    def _check_screenshot_apps(self):
        """Check if any known screenshot applications are running and block them."""
        try:
            # List of known screenshot application window titles (partial matches)
            screenshot_apps = [
                "Snipping Tool", 
                "Snip & Sketch",
                "Screenshot",
                "Greenshot",
                "Lightshot",
                "Screenpresso",
                "Snagit"
            ]
            
            # Function to be called for each window
            def enum_window_callback(hwnd, _):
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                
                window_text = win32gui.GetWindowText(hwnd)
                for app in screenshot_apps:
                    if app.lower() in window_text.lower():
                        print(f"Screenshot app detected: {window_text}")
                        # Try to close or minimize the window
                        try:
                            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                        except:
                            pass
                        self.screenshot_hotkey_detected.emit()
                return True
            
            # Enumerate all windows
            win32gui.EnumWindows(enum_window_callback, None)
        except Exception as e:
            print(f"Error checking screenshot apps: {e}")
    
    def _monitor_screenshot_processes(self):
        """Monitor and terminate known screenshot processes proactively."""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name']
                    if proc_name in self.aggressive_screenshot_processes:
                        print(f"Terminating aggressive screenshot process: {proc_name}")
                        try:
                            proc.terminate()
                            # Give it a moment to terminate gracefully
                            try:
                                proc.wait(timeout=2)
                            except psutil.TimeoutExpired:
                                # Force kill if it doesn't terminate
                                proc.kill()
                            
                            # Emit signal for detected screenshot attempt
                            self.screenshot_hotkey_detected.emit()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                            # Process might have already terminated or we lack permissions
                            pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error monitoring screenshot processes: {e}")

# KBDLLHOOKSTRUCT structure for keyboard hook
class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]

# Window overlay to prevent screen capture
class ScreenCaptureBlocker:
    """Windows-specific screen capture blocker.
    
    Creates multiple transparent overlay windows that prevent screen capture.
    """
    
    def __init__(self):
        self.overlay_hwnds = []
        self.timer = None
        self.gdi32 = None
        
        # Try to load user32.dll and gdi32.dll
        try:
            self.user32 = ctypes.WinDLL('user32', use_last_error=True)
            self.gdi32 = ctypes.WinDLL('gdi32', use_last_error=True)
        except Exception as e:
            print(f"Failed to load required DLLs: {e}")
            self.user32 = None
    
    def start(self, parent_hwnd=None):
        """Start the screen capture blocker.
        
        Args:
            parent_hwnd: Handle to the parent window
            
        Returns:
            True if at least one overlay was created, False otherwise
        """
        if not self.user32:
            print("Cannot start screen capture blocker: required DLLs not loaded")
            return False
            
        try:
            # Clear any existing overlays
            self.stop()
            
            # Get screen dimensions
            try:
                screen_width = self.user32.GetSystemMetrics(0)  # SM_CXSCREEN
                screen_height = self.user32.GetSystemMetrics(1)  # SM_CYSCREEN
            except Exception as e:
                print(f"Error getting screen dimensions: {e}")
                # Use fallback dimensions
                screen_width = 1920
                screen_height = 1080
            
            # Create main full-screen overlay
            try:
                main_overlay = self._create_overlay(0, 0, screen_width, screen_height)
                if main_overlay:
                    self.overlay_hwnds.append(main_overlay)
            except Exception as e:
                print(f"Error creating main overlay: {e}")
            
            # Try to create additional overlays for multi-monitor setups
            # but don't fail if this doesn't work
            try:
                # Get information about all monitors
                def monitor_enum_proc(hMonitor, hdcMonitor, lprcMonitor, dwData):
                    try:
                        # lprcMonitor points to a RECT structure with monitor coordinates
                        rect = ctypes.cast(lprcMonitor, ctypes.POINTER(wintypes.RECT)).contents
                        # Create an overlay for this monitor
                        monitor_overlay = self._create_overlay(
                            rect.left, rect.top, 
                            rect.right - rect.left, 
                            rect.bottom - rect.top
                        )
                        if monitor_overlay:
                            self.overlay_hwnds.append(monitor_overlay)
                    except Exception as e:
                        print(f"Error creating overlay for monitor: {e}")
                    return True
                
                # Define callback function type
                MonitorEnumProc = ctypes.WINFUNCTYPE(
                    ctypes.c_bool,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.POINTER(wintypes.RECT),
                    ctypes.c_void_p
                )
                
                # Enumerate all monitors
                callback = MonitorEnumProc(monitor_enum_proc)
                self.user32.EnumDisplayMonitors(None, None, callback, 0)
            except Exception as e:
                print(f"Error creating multi-monitor overlays: {e}")
            
            # Create a timer to periodically refresh the overlays
            try:
                if self.timer is None:
                    self.timer = QTimer()
                    self.timer.timeout.connect(self._refresh_overlays)
                self.timer.start(500)  # Refresh every 500ms
            except Exception as e:
                print(f"Error starting overlay refresh timer: {e}")
            
            # Check if we created at least one overlay
            if not self.overlay_hwnds:
                print("Failed to create any overlay windows")
                return False
                
            return True
        except Exception as e:
            print(f"Error starting screen capture blocker: {e}")
            # Make sure to clean up any resources
            self.stop()
            return False
    
    def _refresh_overlays(self):
        """Periodically refresh the overlays to ensure they stay on top."""
        if not self.user32:
            return
            
        if not self.overlay_hwnds:
            return
            
        try:
            # Define constants if not available in win32con
            HWND_TOPMOST = getattr(win32con, 'HWND_TOPMOST', -1)
            SWP_NOMOVE = getattr(win32con, 'SWP_NOMOVE', 0x0002)
            SWP_NOSIZE = getattr(win32con, 'SWP_NOSIZE', 0x0001)
            
            # Keep overlays on top
            for hwnd in self.overlay_hwnds[:]:
                try:
                    # Check if window still exists
                    if not self.user32.IsWindow(hwnd):
                        self.overlay_hwnds.remove(hwnd)
                        continue
                    
                    # Bring to top
                    self.user32.SetWindowPos(
                        hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE
                    )
                except Exception as e:
                    print(f"Error refreshing overlay window: {e}")
                    # Remove from list if window is invalid
                    try:
                        self.overlay_hwnds.remove(hwnd)
                    except ValueError:
                        pass
        except Exception as e:
            print(f"Error in overlay refresh: {e}")
    
    def _create_overlay(self, x, y, width, height):
        """Create a transparent overlay window.
        
        Args:
            x, y: Position of the window
            width, height: Size of the window
            
        Returns:
            Window handle if successful, None otherwise
        """
        if not self.user32:
            return None
            
        try:
            # Register window class if not already done
            class_name = "BAR_ScreenProtectionOverlay"
            
            # Create window class structure
            class WNDCLASSEX(ctypes.Structure):
                _fields_ = [
                    ('cbSize', wintypes.UINT),
                    ('style', wintypes.UINT),
                    ('lpfnWndProc', ctypes.c_void_p),
                    ('cbClsExtra', ctypes.c_int),
                    ('cbWndExtra', ctypes.c_int),
                    ('hInstance', wintypes.HINSTANCE),
                    ('hIcon', wintypes.HICON),
                    ('hCursor', wintypes.HCURSOR),
                    ('hbrBackground', wintypes.HBRUSH),
                    ('lpszMenuName', wintypes.LPCWSTR),
                    ('lpszClassName', wintypes.LPCWSTR),
                    ('hIconSm', wintypes.HICON)
                ]
            
            # Default window procedure
            def_window_proc = self.user32.DefWindowProcW
            def_window_proc.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            def_window_proc.restype = wintypes.LRESULT
            
            # Window class
            wndclass = WNDCLASSEX()
            wndclass.cbSize = ctypes.sizeof(WNDCLASSEX)
            wndclass.style = 0
            wndclass.lpfnWndProc = ctypes.cast(def_window_proc, ctypes.c_void_p)
            wndclass.cbClsExtra = 0
            wndclass.cbWndExtra = 0
            wndclass.hInstance = ctypes.windll.kernel32.GetModuleHandleW(None)
            wndclass.hIcon = None
            wndclass.hCursor = None
            wndclass.hbrBackground = None
            wndclass.lpszMenuName = None
            wndclass.lpszClassName = class_name
            wndclass.hIconSm = None
            
            # Register class (ignore if already registered)
            try:
                self.user32.RegisterClassExW(ctypes.byref(wndclass))
            except Exception:
                pass  # Class might already be registered
            
            # Window styles for transparent, always-on-top overlay
            WS_EX_TRANSPARENT = 0x00000020
            WS_EX_LAYERED = 0x00080000
            WS_EX_TOPMOST = 0x00000008
            WS_EX_TOOLWINDOW = 0x00000080  # Hide from taskbar
            WS_POPUP = 0x80000000
            
            # Create the overlay window
            hwnd = self.user32.CreateWindowExW(
                WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                class_name,
                "BAR Screen Protection",
                WS_POPUP,
                x, y, width, height,
                None,  # parent
                None,  # menu
                wndclass.hInstance,
                None   # param
            )
            
            if not hwnd:
                error_code = ctypes.get_last_error()
                print(f"Failed to create overlay window: {error_code}")
                return None
            
            # Set the window to be 99% transparent but still intercept capture
            try:
                self.user32.SetLayeredWindowAttributes(
                    hwnd, 0, 3, 2  # LWA_ALPHA = 2, almost transparent
                )
            except Exception as e:
                print(f"Failed to set window transparency: {e}")
                # Continue anyway, window will still block captures
            
            # Show the window
            try:
                SW_SHOWNOACTIVATE = 4
                self.user32.ShowWindow(hwnd, SW_SHOWNOACTIVATE)
            except Exception as e:
                print(f"Failed to show overlay window: {e}")
                # Clean up
                try:
                    self.user32.DestroyWindow(hwnd)
                except Exception:
                    pass
                return None
            
            return hwnd
            
        except Exception as e:
            print(f"Error creating overlay window: {e}")
            return None
    
    def stop(self):
        """Stop the screen capture blocker and clean up resources.
        
        Returns:
            True if cleanup was successful, False otherwise
        """
        success = True
        
        # Stop the refresh timer
        if self.timer:
            try:
                self.timer.stop()
                self.timer = None
            except Exception as e:
                print(f"Error stopping timer: {e}")
                success = False
        
        # Destroy all overlay windows
        if self.user32:
            for hwnd in self.overlay_hwnds[:]:
                try:
                    if self.user32.IsWindow(hwnd):
                        self.user32.DestroyWindow(hwnd)
                except Exception as e:
                    print(f"Error destroying overlay window: {e}")
                    success = False
        
        # Clear the list
        self.overlay_hwnds.clear()
        
        return success


class EnhancedScreenProtection(QThread):
    """Enhanced screen protection with multiple blocking mechanisms."""
    
    security_threat_detected = pyqtSignal(str, str)  # threat_type, description
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitoring = False
        self.keyboard_hook = None
        self.capture_blocker = None
        
        # Initialize components
        try:
            self.keyboard_hook = KeyboardHook(self)
            self.capture_blocker = ScreenCaptureBlocker()
        except Exception as e:
            print(f"Failed to initialize enhanced protection: {e}")
        
        # Connect signals
        if self.keyboard_hook:
            self.keyboard_hook.screenshot_hotkey_detected.connect(
                lambda: self.security_threat_detected.emit("screenshot_hotkey", "Screenshot hotkey blocked")
            )
    
    def start_protection(self, window_handle=None):
        """Start enhanced screen protection."""
        if self.monitoring:
            return True
        
        success = True
        
        # Start keyboard hook
        if self.keyboard_hook:
            try:
                self.keyboard_hook.start()
            except Exception as e:
                print(f"Failed to start keyboard hook: {e}")
                success = False
        
        # Start screen capture blocker
        if self.capture_blocker:
            try:
                if not self.capture_blocker.start(window_handle):
                    print("Screen capture blocker failed to start")
                    success = False
            except Exception as e:
                print(f"Failed to start screen capture blocker: {e}")
                success = False
        
        # Start process monitoring thread
        if success:
            self.monitoring = True
            self.start()
        
        return success
    
    def stop_protection(self):
        """Stop enhanced screen protection."""
        self.monitoring = False
        
        # Stop keyboard hook
        if self.keyboard_hook:
            try:
                self.keyboard_hook.stop()
            except Exception as e:
                print(f"Error stopping keyboard hook: {e}")
        
        # Stop screen capture blocker
        if self.capture_blocker:
            try:
                self.capture_blocker.stop()
            except Exception as e:
                print(f"Error stopping screen capture blocker: {e}")
        
        # Wait for thread to finish
        self.wait(3000)
    
    def run(self):
        """Monitor for security threats."""
        while self.monitoring:
            try:
                self._check_security_threats()
                time.sleep(1)
            except Exception as e:
                print(f"Error in security monitoring: {e}")
                time.sleep(1)
    
    def _check_security_threats(self):
        """Check for various security threats."""
        try:
            # Check for screen recording software
            self._check_screen_recording_software()
            
            # Check for debugging tools
            self._check_debugging_tools()
            
            # Check for remote desktop connections
            self._check_remote_desktop()
            
        except Exception as e:
            print(f"Error checking security threats: {e}")
    
    def _check_screen_recording_software(self):
        """Check for running screen recording software."""
        recording_processes = [
            'obs64.exe', 'obs32.exe', 'bandicam.exe', 'camtasia.exe',
            'fraps.exe', 'xsplit.core.exe', 'nvidia-share.exe'
        ]
        
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() in [p.lower() for p in recording_processes]:
                    self.security_threat_detected.emit(
                        "screen_recording", 
                        f"Screen recording software detected: {proc.info['name']}"
                    )
        except Exception as e:
            print(f"Error checking screen recording software: {e}")
    
    def _check_debugging_tools(self):
        """Check for debugging and analysis tools."""
        debug_processes = [
            'windbg.exe', 'x64dbg.exe', 'ollydbg.exe', 'ida.exe', 'ida64.exe',
            'cheatengine-x86_64.exe', 'processhacker.exe', 'procexp.exe'
        ]
        
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() in [p.lower() for p in debug_processes]:
                    self.security_threat_detected.emit(
                        "debugging_tool", 
                        f"Debugging tool detected: {proc.info['name']}"
                    )
        except Exception as e:
            print(f"Error checking debugging tools: {e}")
    
    def _check_remote_desktop(self):
        """Check for remote desktop connections."""
        try:
            # Check if Terminal Services (Remote Desktop) is active
            result = subprocess.run(
                ['query', 'session'], 
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                # Look for active RDP sessions
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'rdp-tcp' in line.lower() and 'active' in line.lower():
                        self.security_threat_detected.emit(
                            "remote_desktop", 
                            "Remote Desktop connection detected"
                        )
                        break
        except Exception as e:
            print(f"Error checking remote desktop: {e}")
            
            # Refresh each overlay
            invalid_hwnds = []
            for hwnd in self.overlay_hwnds:
                if not hwnd:
                    invalid_hwnds.append(hwnd)
                    continue
                    
                try:
                    # Check if window still exists
                    if not self.user32.IsWindow(hwnd):
                        invalid_hwnds.append(hwnd)
                        continue
                        
                    # Ensure window is still on top
                    result = self.user32.SetWindowPos(
                        hwnd, HWND_TOPMOST,
                        0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE
                    )
                    
                    if not result:
                        # Window might be invalid
                        invalid_hwnds.append(hwnd)
                except Exception as e:
                    print(f"Error refreshing overlay {hwnd}: {e}")
                    invalid_hwnds.append(hwnd)
            
            # Remove invalid window handles
            if invalid_hwnds:
                for hwnd in invalid_hwnds:
                    if hwnd in self.overlay_hwnds:
                        self.overlay_hwnds.remove(hwnd)
                
                # If all overlays are gone, try to recreate them
                if not self.overlay_hwnds:
                    print("All overlay windows are invalid, attempting to recreate")
                    self.start()
        except Exception as e:
            print(f"Error refreshing overlays: {e}")
    
    def stop(self):
        """Stop the screen capture blocker.
        
        Returns:
            True if successfully stopped, False if errors occurred
        """
        success = True
        
        # Stop the refresh timer
        if self.timer:
            try:
                self.timer.stop()
                self.timer = None
            except Exception as e:
                print(f"Error stopping timer: {e}")
                success = False
        
        # Destroy all overlay windows
        if self.overlay_hwnds and self.user32:
            for hwnd in list(self.overlay_hwnds):  # Create a copy of the list to safely modify during iteration
                try:
                    if hwnd and self.user32.IsWindow(hwnd):
                        self.user32.DestroyWindow(hwnd)
                except Exception as e:
                    print(f"Error destroying window {hwnd}: {e}")
                    success = False
            
            # Clear the list regardless of errors
            self.overlay_hwnds = []
        
        return success
    
    def _create_overlay(self, x, y, width, height):
        """Create a transparent overlay window.
        
        Args:
            x: X position
            y: Y position
            width: Window width
            height: Window height
            
        Returns:
            Window handle or None if creation fails
        """
        if not self.user32:
            print("Cannot create overlay: user32.dll not loaded")
            return None
            
        try:
            # Window class name
            class_name = "ScreenCaptureBlockerClass"
            
            # Define WNDCLASS structure
            class WNDCLASS(ctypes.Structure):
                _fields_ = [
                    ("style", ctypes.c_uint),
                    ("lpfnWndProc", ctypes.c_void_p),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.c_void_p),
                    ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_char_p),
                    ("lpszClassName", ctypes.c_char_p)
                ]
            
            # Define constants if not available in win32con
            WS_EX_LAYERED = getattr(win32con, 'WS_EX_LAYERED', 0x00080000)
            WS_EX_TRANSPARENT = getattr(win32con, 'WS_EX_TRANSPARENT', 0x00000020)
            WS_EX_TOPMOST = getattr(win32con, 'WS_EX_TOPMOST', 0x00000008)
            WS_POPUP = getattr(win32con, 'WS_POPUP', 0x80000000)
            LWA_ALPHA = getattr(win32con, 'LWA_ALPHA', 0x00000002)
            LWA_COLORKEY = getattr(win32con, 'LWA_COLORKEY', 0x00000001)
            SW_SHOW = getattr(win32con, 'SW_SHOW', 5)
            HWND_TOPMOST = getattr(win32con, 'HWND_TOPMOST', -1)
            SWP_NOMOVE = getattr(win32con, 'SWP_NOMOVE', 0x0002)
            SWP_NOSIZE = getattr(win32con, 'SWP_NOSIZE', 0x0001)
            
            # Register window class
            wnd_class = WNDCLASS()
            # Convert DefWindowProcA to the correct function pointer type
            try:
                # Correct function signature for WNDPROC
                WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)
                wnd_proc_func = WNDPROC(self.user32.DefWindowProcA)
                wnd_class.lpfnWndProc = ctypes.cast(wnd_proc_func, ctypes.c_void_p)
                wnd_class.hInstance = ctypes.windll.kernel32.GetModuleHandleW(None)
                wnd_class.lpszClassName = class_name.encode('utf-8')
                # Initialize other fields to prevent memory issues
                wnd_class.style = 0
                wnd_class.cbClsExtra = 0
                wnd_class.cbWndExtra = 0
                wnd_class.hIcon = 0
                wnd_class.hCursor = 0
                wnd_class.hbrBackground = 0
                wnd_class.lpszMenuName = None
            except Exception as e:
                print(f"Error setting up window class: {e}")
                return None
            
            # Register the window class - don't fail if already registered
            result = self.user32.RegisterClassA(ctypes.byref(wnd_class))
            if not result:
                error_code = ctypes.get_last_error()
                # Error 1410 means class already registered, which is fine
                if error_code != 1410:  # ERROR_CLASS_ALREADY_EXISTS
                    print(f"Failed to register window class: {error_code}")
                    return None
            
            # Create the window with more aggressive anti-screenshot properties
            try:
                # Ensure all parameters have the correct types to prevent overflow errors
                overlay_hwnd = self.user32.CreateWindowExA(
                    ctypes.c_int(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST),
                    class_name.encode('utf-8'),
                    b"Screen Capture Blocker",
                    ctypes.c_int(WS_POPUP),
                    ctypes.c_int(x), ctypes.c_int(y), 
                    ctypes.c_int(width), ctypes.c_int(height),
                    None, None, wnd_class.hInstance, None
                )
                
                if not overlay_hwnd:
                    error_code = ctypes.get_last_error()
                    print(f"Failed to create overlay window: {error_code}")
                    return None
            except Exception as e:
                print(f"Exception creating overlay window: {e}")
                return None
            
            # Create a solid black background that will appear in screenshots
            # but be transparent to the user
            try:
                # Import GDI32 for advanced drawing
                if self.gdi32 is None:
                    self.gdi32 = ctypes.WinDLL('gdi32', use_last_error=True)
                
                # Create a device context
                hdc = self.user32.GetDC(overlay_hwnd)
                if hdc:
                    # Create a compatible DC for drawing
                    memDC = self.gdi32.CreateCompatibleDC(hdc)
                    if memDC:
                        # Create a bitmap
                        bitmap = self.gdi32.CreateCompatibleBitmap(hdc, width, height)
                        if bitmap:
                            # Select bitmap into DC
                            self.gdi32.SelectObject(memDC, bitmap)
                            
                            # Fill with black
                            brush = self.gdi32.CreateSolidBrush(0x00000000)  # Black
                            rect = wintypes.RECT(0, 0, width, height)
                            self.user32.FillRect(memDC, ctypes.byref(rect), brush)
                            self.gdi32.DeleteObject(brush)
                            
                            # Apply to window
                            SRCCOPY = 0x00CC0020
                            self.user32.BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY)
                            
                            # Clean up
                            self.gdi32.DeleteObject(bitmap)
                        self.gdi32.DeleteDC(memDC)
                    self.user32.ReleaseDC(overlay_hwnd, hdc)
            except Exception as e:
                print(f"Failed to create black background: {e}")
                # Continue even if background creation fails
            
            try:
                # Make the window semi-transparent to the user but opaque to screenshots
                self.user32.SetLayeredWindowAttributes(
                    overlay_hwnd, 0, 10, LWA_ALPHA  # Very low alpha (10) makes it nearly invisible to user
                )
                
                # Show the window
                self.user32.ShowWindow(overlay_hwnd, SW_SHOW)
                self.user32.UpdateWindow(overlay_hwnd)
                
                # Set window to always be on top with highest priority
                self.user32.SetWindowPos(
                    overlay_hwnd, HWND_TOPMOST,
                    0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE
                )
                
                # Ensure window stays on top by setting a timer to periodically bring it to front
                try:
                    # Create a timer to keep window on top
                    WM_TIMER = 0x0113
                    TIMER_ID = 1
                    self.user32.SetTimer(overlay_hwnd, TIMER_ID, 100, None)  # 100ms interval
                except Exception as e:
                    print(f"Failed to set timer: {e}")
                    # Continue even if timer creation fails
            except Exception as e:
                print(f"Error configuring overlay window: {e}")
                # Try to destroy the window if configuration fails
                try:
                    self.user32.DestroyWindow(overlay_hwnd)
                except:
                    pass
                return None
                
            # Return the successfully created window handle
            return overlay_hwnd
        except Exception as e:
            print(f"Error creating overlay window: {e}")
            return None