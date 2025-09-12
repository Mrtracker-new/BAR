import os
import sys
import time
import threading
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
        
        # Trigger emergency destruction
        self.trigger_emergency_destruction("Dead man's switch activated")
    
    def trigger_emergency_destruction(self, reason: str = "Manual trigger", level: str = "aggressive", scrub_free_space: Optional[bool] = None):
        """Trigger emergency data destruction with graded intensity.
        
        Levels:
        - "selective": Only BAR app directories and configs
        - "aggressive": Selective + user-level BAR caches and temp traces
        - "scorched": Aggressive + best-effort wipe of additional BAR artifacts (still scoped)
        
        Args:
            reason: Reason for triggering emergency protocol
            level: Destruction level (selective|aggressive|scorched)
            scrub_free_space: If True, perform best-effort free-space scrub on the same volume.
                Defaults: False for selective, True for aggressive/scorched.
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
            
            # Minimal logging per security rules
            try:
                log_file = self.base_directory / "emergency.log"
                with open(log_file, "a") as f:
                    f.write(f"{datetime.now().isoformat()} - Emergency protocol triggered: {reason} level={level}\n")
            except Exception:
                pass
            
            # Define sensitive paths per level
            sensitive_dirs = [
                self.base_directory / "data",
                self.base_directory / "logs",
                self.base_directory / "temp",
                self.base_directory / "cache",
            ]

            user_scope_extra = []
            if level in ("aggressive", "scorched"):
                # Wipe known user-scope BAR dirs
                user_scope_extra.extend([
                    Path.home() / ".bar",
                    Path.home() / "Documents" / "BAR",
                    Path.home() / "AppData" / "Local" / "BAR" if os.name == 'nt' else Path.home() / ".local" / "share" / "bar",
                ])
            
            extended_traces = []
            if level == "scorched":
                # Include quarantine and blacklist artifacts
                extended_traces.extend([
                    self.base_directory / "quarantine",
                    self.base_directory / "blacklist.json",
                ])
            
            # Perform directory wipes
            for dir_path in sensitive_dirs + user_scope_extra:
                try:
                    if dir_path.exists():
                        self.secure_delete.secure_delete_directory(str(dir_path))
                except Exception:
                    pass
            
            # Wipe authentication and device data via device auth manager (already graded internally)
            try:
                if self.device_auth:
                    self.device_auth.emergency_wipe(
                        wipe_user_data=(level in ("aggressive", "scorched")),
                        wipe_temp_files=(level in ("aggressive", "scorched")),
                    )
            except Exception:
                pass
            
            # Wipe configuration files in base dir
            try:
                config_files = list(self.base_directory.glob("*.json"))
                config_files.extend(list(self.base_directory.glob("*.key")))
                config_files.extend(list(self.base_directory.glob("*.enc")))
                for file_path in config_files:
                    if file_path.exists():
                        self.secure_delete.secure_delete_file(str(file_path))
            except Exception:
                pass

            # Scorched level extras
            if level == "scorched":
                for item in extended_traces:
                    try:
                        if item.is_file() and item.exists():
                            self.secure_delete.secure_delete_file(str(item))
                        elif item.is_dir() and item.exists():
                            self.secure_delete.secure_delete_directory(str(item))
                    except Exception:
                        pass

            # Optional hardware-level best-effort free-space scrub (scoped to volume)
            try:
                do_scrub = scrub_free_space if scrub_free_space is not None else (level in ("aggressive", "scorched"))
                if do_scrub:
                    self.hardware_wipe.wipe_volume_free_space(self.base_directory, max_bytes=None, pattern="random")
            except Exception:
                pass
            
            # Create destruction confirmation file (non-sensitive)
            try:
                destruction_file = self.base_directory / "DESTROYED.txt"
                with open(destruction_file, "w") as f:
                    f.write(f"BAR data destroyed on {datetime.now().isoformat()}\n")
                    f.write(f"Reason: {reason}\n")
                    f.write(f"Level: {level}\n")
                    f.write("All sensitive data has been securely wiped.\n")
            except Exception:
                pass
                
        except Exception:
            pass  # Ignore all errors during emergency
        
        finally:
            # Exit the application
            try:
                sys.exit(0)
            except Exception:
                os._exit(0)
    
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
        """Immediate panic button - destroys all data instantly."""
        self.trigger_emergency_destruction("Panic button activated")
    
    def __del__(self):
        """Cleanup on destruction."""
        self.stop_dead_mans_switch()
