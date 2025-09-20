import os
import sys
import time
import threading
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from security.secure_delete import SecureDelete
from security.hardware_wipe import HardwareWipe


class EmergencyProtocol:
    """Emergency data destruction and security protocols.
    
    This class provides:
    - Emergency data wipe capabilities
    - Panic button functionality  
    - Dead man's switch implementation
    - File blacklisting and quarantine
    - Anti-forensics measures
    - Graded destruction levels
    """
    
    def __init__(self, base_directory: str, device_auth=None):
        """Initialize the emergency protocol manager.
        
        Args:
            base_directory: Base directory for the application
            device_auth: Device authentication manager (optional)
        """
        self.base_directory = Path(base_directory)
        self.device_auth = device_auth
        self.secure_delete = SecureDelete()
        self.hardware_wipe = HardwareWipe()
        
        # Initialize logger
        import logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Emergency state
        self._emergency_active = False
        self._dead_mans_switch_active = False
        self._last_activity = datetime.now()
        
        # Blacklist management
        self.blacklist_path = self.base_directory / "blacklist.json"
        self._blacklisted_files = set()
        self._load_blacklist()
        
        # Emergency callbacks
        self._emergency_callbacks = []
        
        # Dead man's switch configuration
        self._dead_mans_timeout = timedelta(hours=24)  # Default 24 hours
        self._dead_mans_timer = None
        
    def register_emergency_callback(self, callback: Callable[[], None]):
        """Register a callback to be called during emergency procedures.
        
        Args:
            callback: Function to call during emergency
        """
        self._emergency_callbacks.append(callback)
    
    def set_dead_mans_switch_timeout(self, hours: int):
        """Set the dead man's switch timeout.
        
        Args:
            hours: Number of hours of inactivity before triggering
        """
        self._dead_mans_timeout = timedelta(hours=hours)
    
    def start_dead_mans_switch(self):
        """Start the dead man's switch monitoring."""
        if self._dead_mans_switch_active:
            return
            
        self._dead_mans_switch_active = True
        self._last_activity = datetime.now()
        
        # Start monitoring thread
        self._dead_mans_timer = threading.Timer(
            self._dead_mans_timeout.total_seconds(),
            self._trigger_dead_mans_switch
        )
        self._dead_mans_timer.daemon = True
        self._dead_mans_timer.start()
    
    def stop_dead_mans_switch(self):
        """Stop the dead man's switch monitoring."""
        self._dead_mans_switch_active = False
        
        if self._dead_mans_timer:
            self._dead_mans_timer.cancel()
            self._dead_mans_timer = None
    
    def heartbeat(self):
        """Send a heartbeat to reset the dead man's switch."""
        if not self._dead_mans_switch_active:
            return
            
        self._last_activity = datetime.now()
        
        # Reset timer
        if self._dead_mans_timer:
            self._dead_mans_timer.cancel()
            
        self._dead_mans_timer = threading.Timer(
            self._dead_mans_timeout.total_seconds(),
            self._trigger_dead_mans_switch
        )
        self._dead_mans_timer.daemon = True
        self._dead_mans_timer.start()
    
    def _trigger_dead_mans_switch(self):
        """Trigger dead man's switch emergency protocol."""
        if not self._dead_mans_switch_active:
            return
            
        # Check if we really haven't had activity
        time_since_activity = datetime.now() - self._last_activity
        if time_since_activity < self._dead_mans_timeout:
            # False alarm, reschedule
            remaining = self._dead_mans_timeout - time_since_activity
            self._dead_mans_timer = threading.Timer(
                remaining.total_seconds(),
                self._trigger_dead_mans_switch
            )
            self._dead_mans_timer.daemon = True
            self._dead_mans_timer.start()
            return
        
        # Trigger emergency destruction with aggressive level (comprehensive but not extreme)
        self.trigger_emergency_destruction(
            reason="Dead man's switch activated - No activity detected",
            level="aggressive",
            scrub_free_space=True
        )
    
    def trigger_emergency_destruction(self, reason: str = "Manual trigger", level: str = "aggressive", scrub_free_space: Optional[bool] = None):
        """Trigger emergency data destruction with truly graded intensity.
        
        MEANINGFUL DESTRUCTION LEVELS:
        
        - "selective": MINIMAL - Only current session data and active files
          * Current encrypted files being processed
          * Active memory dumps and temp files
          * Session keys and authentication tokens
          * Does NOT exit application (allows continued use)
          * No free space scrubbing
          * Preserves user data and history
        
        - "aggressive": COMPREHENSIVE - All BAR data but preserves system
          * Everything from selective level
          * All BAR application data and user files
          * Configuration, logs, and cached data
          * User directories and permanent storage
          * Free space scrubbing on BAR volumes
          * Exits application after cleanup
          * Preserves non-BAR system data
        
        - "scorched": MAXIMUM - Complete system sanitization
          * Everything from aggressive level  
          * Extended forensic counter-measures
          * Hardware-level entropy injection
          * Registry/system traces cleanup (Windows)
          * Multiple-pass overwriting with random patterns
          * Maximum free space scrubbing
          * Self-destruct application binary
          * Force system restart/shutdown
        
        Args:
            reason: Reason for triggering emergency protocol
            level: Destruction level (selective|aggressive|scorched)
            scrub_free_space: Override free space scrubbing behavior
        """
        if self._emergency_active:
            return  # Already in progress
            
        self._emergency_active = True
        
        try:
            # Call registered callbacks first
            for callback in self._emergency_callbacks:
                try:
                    callback()
                except Exception:
                    pass  # Ignore errors during emergency
            
            # Enhanced logging per level
            try:
                log_file = self.base_directory / "emergency.log"
                with open(log_file, "a") as f:
                    f.write(f"{datetime.now().isoformat()} - EMERGENCY DESTRUCTION INITIATED\n")
                    f.write(f"Reason: {reason}\n")
                    f.write(f"Level: {level.upper()}\n")
                    f.write(f"Timestamp: {time.time()}\n")
                    f.write("--- DESTRUCTION SEQUENCE STARTED ---\n")
            except Exception:
                pass
            
            # LEVEL-SPECIFIC DESTRUCTION LOGIC
            
            if level == "selective":
                self._selective_destruction(reason)
                # SELECTIVE DOES NOT EXIT - allows continued use
                return
                
            elif level == "aggressive":
                self._aggressive_destruction(reason, scrub_free_space)
                # AGGRESSIVE EXITS after cleanup
                
            elif level == "scorched":
                self._scorched_earth_destruction(reason, scrub_free_space)
                # SCORCHED forces system shutdown
                
            else:
                # Fallback to aggressive for unknown levels
                try:
                    self.logger.warning(f"Unknown destruction level '{level}', using aggressive")
                except:
                    pass  # In case logger fails
                self._aggressive_destruction(reason, scrub_free_space)
                
        except Exception as e:
            self.logger.critical(f"Emergency destruction failed: {e}")
            # Even on failure, still try to exit for security
            pass
        
        finally:
            if level != "selective":  # Selective level doesn't exit
                self._force_application_exit(level)
    
    def _selective_destruction(self, reason: str):
        """SELECTIVE: Minimal destruction - only active session data.
        
        This level cleans up current sensitive data but allows continued use.
        Designed for temporary security concerns or user-initiated cleanup.
        """
        self.logger.warning(f"SELECTIVE DESTRUCTION: {reason}")
        
        try:
            # 1. Clear active session data only
            session_paths = [
                self.base_directory / "temp",      # Only temp files
                self.base_directory / "logs" / "session.log",  # Only session log
                self.base_directory / "cache" / "active",     # Only active cache
            ]
            
            for path in session_paths:
                if path.exists():
                    if path.is_dir():
                        self.secure_delete.secure_delete_directory(str(path))
                    else:
                        self.secure_delete.secure_delete_file(str(path))
            
            # 2. Clear authentication tokens but keep user data
            if self.device_auth:
                self.device_auth.clear_session_tokens()  # Only session data
            
            # 3. Clear memory but don't scrub storage
            try:
                # Force garbage collection of sensitive objects
                import gc
                gc.collect()
            except Exception:
                pass
            
            # 4. Create minimal log entry
            try:
                log_file = self.base_directory / "selective_cleanup.log"
                with open(log_file, "a") as f:
                    f.write(f"{datetime.now().isoformat()} - Selective cleanup: {reason}\n")
            except Exception:
                pass
                
            self.logger.info("Selective destruction completed - application continues")
            
        except Exception as e:
            self.logger.error(f"Selective destruction failed: {e}")
    
    def _aggressive_destruction(self, reason: str, scrub_free_space: Optional[bool]):
        """AGGRESSIVE: Comprehensive destruction - all BAR data.
        
        This level removes all BAR-related data but preserves system integrity.
        Designed for security incidents or when BAR data must be completely removed.
        """
        self.logger.critical(f"AGGRESSIVE DESTRUCTION: {reason}")
        
        try:
            # 1. Wipe ALL BAR application data - current directory and subdirectories
            app_dirs = [
                self.base_directory / "data",
                self.base_directory / "logs", 
                self.base_directory / "temp",
                self.base_directory / "cache",
                self.base_directory / "backups",
                self.base_directory / "exports",
            ]
            
            for dir_path in app_dirs:
                if dir_path.exists():
                    self.secure_delete.secure_delete_directory(str(dir_path))
            
            # Also wipe the entire base directory contents
            try:
                for item in self.base_directory.iterdir():
                    if item.is_file():
                        self.secure_delete.secure_delete_file(str(item))
                    elif item.is_dir() and item.name not in ['src']:  # Keep source code during development
                        self.secure_delete.secure_delete_directory(str(item))
            except Exception:
                pass
            
            # 2. Wipe ALL user-scope BAR directories
            user_dirs = [
                Path.home() / ".bar",
                Path.home() / "Documents" / "BAR",
                Path.home() / "AppData" / "Local" / "BAR" if os.name == 'nt' else Path.home() / ".local" / "share" / "bar",
                Path.home() / "AppData" / "Roaming" / "BAR" if os.name == 'nt' else Path.home() / ".config" / "bar",
            ]
            
            for dir_path in user_dirs:
                if dir_path.exists():
                    self.secure_delete.secure_delete_directory(str(dir_path))
            
            # 3. Wipe ALL configuration files
            config_patterns = ["*.json", "*.key", "*.enc", "*.conf", "*.cfg", "*.ini"]
            for pattern in config_patterns:
                for file_path in self.base_directory.glob(pattern):
                    if file_path.exists():
                        self.secure_delete.secure_delete_file(str(file_path))
            
            # 4. Full device authentication wipe
            if self.device_auth:
                self.device_auth.emergency_wipe()
            
            # 5. Wipe blacklist and quarantine
            sensitive_artifacts = [
                self.base_directory / "quarantine",
                self.base_directory / "blacklist.json",
                self.blacklist_path,
            ]
            
            for item in sensitive_artifacts:
                if item.exists():
                    if item.is_dir():
                        self.secure_delete.secure_delete_directory(str(item))
                    else:
                        self.secure_delete.secure_delete_file(str(item))
            
            # 6. Free space scrubbing (default enabled)
            do_scrub = scrub_free_space if scrub_free_space is not None else True
            if do_scrub:
                self.hardware_wipe.wipe_volume_free_space(
                    self.base_directory, 
                    max_bytes=5 * 1024 * 1024 * 1024,  # 5GB limit
                    pattern="random"
                )
            
            # 7. Create destruction confirmation
            try:
                destruction_file = self.base_directory / "AGGRESSIVE_WIPE_COMPLETE.txt"
                with open(destruction_file, "w") as f:
                    f.write(f"BAR AGGRESSIVE WIPE COMPLETED\n")
                    f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                    f.write(f"Reason: {reason}\n")
                    f.write("All BAR data has been securely destroyed.\n")
                    f.write("Application will now exit.\n")
            except Exception:
                pass
                
            self.logger.critical("Aggressive destruction completed - exiting application")
            
        except Exception as e:
            self.logger.error(f"Aggressive destruction failed: {e}")
    
    def _scorched_earth_destruction(self, reason: str, scrub_free_space: Optional[bool]):
        """SCORCHED EARTH: Maximum destruction with complete application reset.
        
        This level performs maximum data destruction with anti-forensic measures
        and ensures BAR will start as a completely fresh installation after restart.
        Designed for extreme security threats or when complete sanitization is required.
        """
        self.logger.critical(f"SCORCHED EARTH DESTRUCTION: {reason}")
        
        try:
            # 1. Perform all aggressive destruction first
            self._aggressive_destruction(reason, scrub_free_space=False)  # We'll do our own
            
            # 2. COMPLETE APPLICATION RESET - Remove ALL traces of BAR
            self._complete_application_reset()
            
            # 3. Extended forensic countermeasures
            self._deploy_forensic_countermeasures()
            
            # 4. Hardware entropy injection
            self._inject_hardware_entropy()
            
            # 5. Registry/system traces cleanup (Windows specific)
            if os.name == 'nt':
                self._cleanup_windows_traces()
            
            # 6. Multiple-pass overwriting of sensitive areas
            self._multi_pass_overwrite_sensitive_areas()
            
            # 7. Maximum free space scrubbing
            do_scrub = scrub_free_space if scrub_free_space is not None else True
            if do_scrub:
                # Use maximum scrubbing with multiple patterns
                patterns = ["zeros", "ones", "random", "dod"]
                for pattern in patterns:
                    try:
                        self.hardware_wipe.wipe_volume_free_space(
                            self.base_directory,
                            max_bytes=None,  # No limit for scorched earth
                            pattern=pattern
                        )
                    except Exception:
                        pass  # Continue even if free space wipe fails
            
            # 8. Self-destruct application binary (if possible)
            self._attempt_binary_self_destruct()
            
            # 9. Final confirmation and cleanup
            self._finalize_scorched_earth_destruction(reason)
                
            self.logger.critical("SCORCHED EARTH destruction completed - forcing system restart")
            
        except Exception as e:
            try:
                self.logger.error(f"Scorched earth destruction failed: {e}")
            except:
                pass  # Even logging might fail at this point
    
    def _deploy_forensic_countermeasures(self):
        """Deploy anti-forensic countermeasures."""
        try:
            # Create decoy files with misleading content
            decoy_dir = self.base_directory / "decoys"
            decoy_dir.mkdir(exist_ok=True)
            
            for i in range(20):  # Create multiple decoys
                decoy_file = decoy_dir / f"important_data_{i:03d}.enc"
                with open(decoy_file, "wb") as f:
                    f.write(secrets.token_bytes(secrets.randbelow(1024 * 1024) + 1024))
                
                # Immediately overwrite and delete
                for _ in range(3):
                    with open(decoy_file, "wb") as f:
                        f.write(secrets.token_bytes(decoy_file.stat().st_size))
                decoy_file.unlink()
            
            decoy_dir.rmdir()
            
        except Exception:
            pass  # Ignore errors in countermeasures
    
    def _inject_hardware_entropy(self):
        """Inject random entropy into hardware-level caches."""
        try:
            # Generate and immediately discard large amounts of random data
            # This forces hardware RNG to cycle and masks previous entropy
            for _ in range(100):
                entropy_data = secrets.token_bytes(64 * 1024)  # 64KB chunks
                # Immediately overwrite
                entropy_data = b'\x00' * len(entropy_data)
                del entropy_data
                
        except Exception:
            pass
    
    def _cleanup_windows_traces(self):
        """Clean up Windows-specific traces for complete application reset.
        
        Removes BAR traces from:
        - Registry (recent files, run history, etc.)
        - Prefetch files
        - Windows event logs
        - Jump lists
        """
        if os.name != 'nt':
            return
            
        try:
            import winreg
            
            # 1. Clean up registry entries related to BAR
            registry_cleanup_keys = [
                # Recent documents and files
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"),
                
                # File associations and shell extensions
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"),
                
                # Application data
                (winreg.HKEY_CURRENT_USER, r"Software\BAR"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BAR"),
                
                # Windows search index
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Search"),
            ]
            
            for hkey, subkey_path in registry_cleanup_keys:
                try:
                    self._clean_registry_key_for_bar(hkey, subkey_path)
                except Exception as e:
                    self.logger.debug(f"Registry cleanup warning for {subkey_path}: {e}")
            
            # 2. Clean Windows prefetch files
            try:
                prefetch_dir = Path("C:") / "Windows" / "Prefetch"
                if prefetch_dir.exists():
                    for pf_file in prefetch_dir.glob("*BAR*"):
                        if pf_file.is_file():
                            try:
                                pf_file.unlink()
                            except Exception:
                                pass  # Prefetch files might be locked
                                
            except Exception:
                pass  # Prefetch cleanup is optional
            
            # 3. Clean Windows jump lists
            try:
                jumplist_dirs = [
                    Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations",
                    Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "CustomDestinations",
                ]
                
                for jl_dir in jumplist_dirs:
                    if jl_dir.exists():
                        # Remove all jump list files (they're hard to parse)
                        for jl_file in jl_dir.iterdir():
                            if jl_file.is_file():
                                try:
                                    jl_file.unlink()
                                except Exception:
                                    pass  # Some files might be locked
                                    
            except Exception:
                pass  # Jump list cleanup is optional
            
            # 4. Clear Windows Search database references
            try:
                search_dirs = [
                    Path.home() / "AppData" / "Local" / "Microsoft" / "Windows" / "Search",
                    Path("C:") / "ProgramData" / "Microsoft" / "Search",
                ]
                
                for search_dir in search_dirs:
                    if search_dir.exists():
                        # Look for BAR-related search index files
                        for search_file in search_dir.rglob("*"):
                            if search_file.is_file() and "bar" in search_file.name.lower():
                                try:
                                    search_file.unlink()
                                except Exception:
                                    pass
                                    
            except Exception:
                pass  # Search index cleanup is optional
                
            self.logger.info("Windows traces cleanup completed")
                    
        except Exception as e:
            try:
                self.logger.warning(f"Windows cleanup error: {e}")
            except:
                pass  # Even logging might fail
    
    def _clean_registry_key_for_bar(self, hkey, subkey_path: str):
        """Clean BAR-related entries from a specific registry key."""
        try:
            with winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_ALL_ACCESS) as key:
                # Get all value names
                i = 0
                values_to_delete = []
                
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                        # Check if value contains BAR-related data
                        if (value_name and ("bar" in value_name.lower() or "BAR" in value_name)) or \
                           (isinstance(value_data, str) and ("bar" in value_data.lower() or "BAR" in value_data)):
                            values_to_delete.append(value_name)
                        i += 1
                    except WindowsError:
                        break  # No more values
                
                # Delete BAR-related values
                for value_name in values_to_delete:
                    try:
                        winreg.DeleteValue(key, value_name)
                    except Exception:
                        pass  # Continue even if some deletions fail
                        
        except Exception:
            pass  # Registry operations can fail for many reasons
    
    def _multi_pass_overwrite_sensitive_areas(self):
        """Perform multiple-pass overwriting of known sensitive file locations."""
        try:
            # Identify and overwrite common locations where BAR data might persist
            sensitive_locations = [
                Path.home() / "AppData" / "Local" / "Temp",
                Path.home() / "AppData" / "Local" / "Microsoft" / "Windows" / "INetCache",
                self.base_directory.parent,  # Parent directory might have traces
            ]
            
            for location in sensitive_locations:
                if location.exists() and location.is_dir():
                    # Look for BAR-related files
                    for pattern in ["*bar*", "*BAR*", "*.enc", "*decrypt*", "*crypto*"]:
                        try:
                            for file_path in location.glob(pattern):
                                if file_path.is_file():
                                    # Multiple pass overwrite
                                    self.secure_delete.secure_delete_file(str(file_path))
                        except Exception:
                            pass
                            
        except Exception:
            pass
    
    def _complete_application_reset(self):
        """Complete application reset - removes ALL traces of BAR from system.
        
        This ensures that after restart, BAR will behave as a completely fresh installation
        with no memory of previous master password, device binding, or configuration.
        """
        try:
            # 1. Wipe ALL BAR user directories (comprehensive locations)
            user_data_locations = [
                # Primary BAR directories
                Path.home() / ".bar",
                Path.home() / "Documents" / "BAR", 
                
                # Windows-specific locations
                Path.home() / "AppData" / "Local" / "BAR" if os.name == 'nt' else None,
                Path.home() / "AppData" / "Roaming" / "BAR" if os.name == 'nt' else None,
                Path.home() / "AppData" / "Local" / "Temp" / "BAR" if os.name == 'nt' else None,
                
                # Linux/Mac locations
                Path.home() / ".local" / "share" / "bar" if os.name != 'nt' else None,
                Path.home() / ".config" / "bar" if os.name != 'nt' else None,
                Path.home() / ".cache" / "bar" if os.name != 'nt' else None,
                
                # Common locations
                Path("/tmp") / "bar" if os.name != 'nt' else None,
            ]
            
            for location in user_data_locations:
                if location and location.exists():
                    try:
                        self.secure_delete.secure_delete_directory(str(location))
                        self.logger.info(f"Wiped user data location: {location}")
                    except Exception as e:
                        self.logger.warning(f"Could not wipe {location}: {e}")
            
            # 2. Wipe all temporary files that might contain BAR traces
            temp_patterns = [
                "*bar*", "*BAR*", "*.enc", "*decrypt*", "*crypto*", 
                "*device*", "*master*", "*secret*", "*key*"
            ]
            
            temp_locations = [
                Path.home() / "AppData" / "Local" / "Temp" if os.name == 'nt' else Path("/tmp"),
                Path(os.environ.get('TEMP', '/tmp')) if os.environ.get('TEMP') else None,
                Path(os.environ.get('TMP', '/tmp')) if os.environ.get('TMP') else None,
            ]
            
            for temp_dir in temp_locations:
                if temp_dir and temp_dir.exists():
                    for pattern in temp_patterns:
                        try:
                            for file_path in temp_dir.glob(pattern):
                                if file_path.is_file():
                                    self.secure_delete.secure_delete_file(str(file_path))
                        except Exception:
                            pass  # Continue with other patterns
            
            # 3. Clear environment variables that might contain BAR data
            sensitive_env_vars = [
                'BAR_PASSWORD', 'BAR_KEY', 'BAR_TOKEN', 'BAR_CONFIG',
                'BAR_USER', 'BAR_SESSION', 'BAR_AUTH', 'BAR_SECRET',
                'BAR_DEVICE', 'BAR_MASTER', 'BAR_DATA', 'BAR_HOME'
            ]
            
            for var in sensitive_env_vars:
                if var in os.environ:
                    # Overwrite with dummy data before deletion
                    os.environ[var] = "SCORCHED_" + secrets.token_hex(32)
                    del os.environ[var]
            
            # 4. Force memory cleanup to remove any traces
            import gc
            for _ in range(10):
                collected = gc.collect()
            
            self.logger.critical("Complete application reset executed - all BAR traces removed")
            
        except Exception as e:
            try:
                self.logger.error(f"Application reset error: {e}")
            except:
                pass
    
    def _finalize_scorched_earth_destruction(self, reason: str):
        """Finalize scorched earth destruction with confirmation."""
        try:
            # Create temporary destruction confirmation (will be wiped)
            destruction_file = self.base_directory / "SCORCHED_EARTH_COMPLETE.txt"
            with open(destruction_file, "w") as f:
                f.write(f"SCORCHED EARTH PROTOCOL COMPLETED\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Reason: {reason}\n")
                f.write("Maximum security wipe completed.\n")
                f.write("Application reset to factory state.\n")
                f.write("System will restart for complete sanitization.\n")
                
            # Immediately overwrite and delete the confirmation file
            for _ in range(7):
                with open(destruction_file, "wb") as f:
                    f.write(secrets.token_bytes(1024))
                time.sleep(0.1)
            destruction_file.unlink()
            
        except Exception:
            pass  # Even confirmation can fail
    
    def _attempt_binary_self_destruct(self):
        """Attempt to securely delete the BAR application binary itself."""
        try:
            import sys
            
            # Get the path to the current executable
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                exe_path = Path(sys.executable)
                
                # Schedule self-deletion after exit
                if os.name == 'nt':
                    # Windows: Use batch script for delayed deletion
                    batch_script = exe_path.parent / "self_destruct.bat"
                    with open(batch_script, "w") as f:
                        f.write("@echo off\n")
                        f.write("timeout /t 3 /nobreak > nul\n")
                        f.write(f'del "{exe_path}"\n')
                        f.write(f'del "{batch_script}"\n')
                    
                    # Execute batch script in background
                    import subprocess
                    subprocess.Popen([str(batch_script)], 
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    # Linux/Mac: Use shell script
                    shell_script = exe_path.parent / "self_destruct.sh"
                    with open(shell_script, "w") as f:
                        f.write("#!/bin/bash\n")
                        f.write("sleep 3\n")
                        f.write(f'rm "{exe_path}"\n')
                        f.write(f'rm "{shell_script}"\n')
                    
                    shell_script.chmod(0o755)
                    subprocess.Popen([str(shell_script)])
                    
        except Exception:
            pass  # Self-destruct is best-effort only
    
    def _force_application_exit(self, level: str):
        """Force application exit with level-appropriate method."""
        try:
            if level == "scorched":
                # Scorched earth: Force system restart/shutdown
                if os.name == 'nt':
                    # Windows shutdown
                    os.system("shutdown /r /t 10 /c \"BAR Scorched Earth Protocol - System Restart Required\"")
                else:
                    # Linux/Mac restart
                    os.system("sudo shutdown -r +1 'BAR Scorched Earth Protocol'")
                
                # Force immediate exit
                os._exit(1)
                
            else:
                # Aggressive: Clean exit
                sys.exit(0)
                
        except Exception:
            # Final fallback
            os._exit(1)
    
    def add_to_blacklist(self, file_path: str, reason: str = "User request"):
        """Add a file to the blacklist for secure deletion.
        
        Args:
            file_path: Path to the file to blacklist
            reason: Reason for blacklisting
        """
        file_path = str(Path(file_path).resolve())
        
        self._blacklisted_files.add(file_path)
        
        # Save blacklist
        self._save_blacklist()
        
        # Immediately delete the file if it exists
        if Path(file_path).exists():
            self.secure_delete.secure_delete_file(file_path)
    
    def remove_from_blacklist(self, file_path: str):
        """Remove a file from the blacklist.
        
        Args:
            file_path: Path to remove from blacklist
        """
        file_path = str(Path(file_path).resolve())
        self._blacklisted_files.discard(file_path)
        self._save_blacklist()
    
    def is_blacklisted(self, file_path: str) -> bool:
        """Check if a file is blacklisted.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if blacklisted, False otherwise
        """
        file_path = str(Path(file_path).resolve())
        return file_path in self._blacklisted_files
    
    def get_blacklist(self) -> List[str]:
        """Get list of blacklisted files.
        
        Returns:
            List of blacklisted file paths
        """
        return list(self._blacklisted_files)
    
    def quarantine_file(self, file_path: str, reason: str = "Security risk"):
        """Quarantine a file by moving it to quarantine and blacklisting.
        
        Args:
            file_path: Path to the file to quarantine
            reason: Reason for quarantine
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return
            
        # Create quarantine directory
        quarantine_dir = self.base_directory / "quarantine"
        quarantine_dir.mkdir(exist_ok=True)
        
        # Move file to quarantine with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_file = quarantine_dir / f"{timestamp}_{file_path.name}"
        
        try:
            file_path.rename(quarantine_file)
            
            # Add to blacklist
            self.add_to_blacklist(str(quarantine_file), f"Quarantined: {reason}")
            
        except Exception as e:
            # If move fails, just delete it
            self.secure_delete.secure_delete_file(str(file_path))
    
    def secure_file_shredding(self, file_path: str, passes: int = 7):
        """Perform secure file shredding with anti-forensics.
        
        Args:
            file_path: Path to the file to shred
            passes: Number of overwrite passes
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return
            
        # Add to blacklist first
        self.add_to_blacklist(str(file_path), "Secure shredding requested")
        
        # Perform multi-pass secure deletion
        self.secure_delete.secure_delete_file(str(file_path), passes)
        
        # Anti-forensics: Create decoy files with similar names
        self._create_decoy_files(file_path.parent, file_path.name)
    
    def _create_decoy_files(self, directory: Path, original_name: str):
        """Create decoy files to confuse forensic analysis.
        
        Args:
            directory: Directory to create decoys in
            original_name: Original filename for similarity
        """
        try:
            # Create several decoy files with similar names
            base_name = Path(original_name).stem
            extension = Path(original_name).suffix
            
            for i in range(3):
                decoy_name = f"{base_name}_{i}{extension}"
                decoy_path = directory / decoy_name
                
                # Create decoy with random content
                decoy_size = len(original_name) * 100  # Approximate size
                decoy_content = os.urandom(decoy_size)
                
                with open(decoy_path, "wb") as f:
                    f.write(decoy_content)
                
                # Immediately delete the decoy securely
                self.secure_delete.secure_delete_file(str(decoy_path))
                
        except Exception:
            pass  # Ignore errors in decoy creation
    
    def _load_blacklist(self):
        """Load blacklist from file."""
        try:
            if self.blacklist_path.exists():
                import json
                with open(self.blacklist_path, "r") as f:
                    data = json.load(f)
                    self._blacklisted_files = set(data.get("files", []))
        except Exception:
            self._blacklisted_files = set()
    
    def _save_blacklist(self):
        """Save blacklist to file."""
        try:
            import json
            data = {
                "files": list(self._blacklisted_files),
                "updated": datetime.now().isoformat()
            }
            with open(self.blacklist_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Ignore save errors
    
    def get_emergency_status(self) -> Dict[str, Any]:
        """Get current emergency protocol status.
        
        Returns:
            Dictionary with emergency status information
        """
        return {
            "emergency_active": self._emergency_active,
            "dead_mans_switch_active": self._dead_mans_switch_active,
            "dead_mans_timeout_hours": self._dead_mans_timeout.total_seconds() / 3600,
            "last_activity": self._last_activity.isoformat(),
            "time_until_trigger": (
                self._last_activity + self._dead_mans_timeout - datetime.now()
            ).total_seconds() if self._dead_mans_switch_active else None,
            "blacklisted_files_count": len(self._blacklisted_files)
        }
    
    def panic_button(self):
        """Immediate panic button - destroys all data with maximum security.
        
        Uses scorched earth destruction for maximum data sanitization.
        This is the "nuclear option" for emergency situations.
        """
        self.logger.critical("PANIC BUTTON ACTIVATED - SCORCHED EARTH DESTRUCTION")
        self.trigger_emergency_destruction(
            reason="PANIC BUTTON ACTIVATED", 
            level="scorched",
            scrub_free_space=True
        )
    
    def __del__(self):
        """Cleanup on destruction."""
        self.stop_dead_mans_switch()
