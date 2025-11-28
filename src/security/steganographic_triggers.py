"""
Steganographic Self-Destruct Triggers - Hidden destruction triggers in normal operations.

This module implements covert self-destruct mechanisms that can be embedded within
normal application operations to avoid detection by attackers while providing
emergency destruction capabilities.

Security principles:
- R004: Security-first design with multiple layers
- R006: Memory security with secure handling
- R008: Plausible deniability through hidden mechanisms

WARNING: This is a security-critical component. Use only for legitimate protection purposes.
"""

import os
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any, Tuple
from enum import Enum
import logging


class TriggerType(Enum):
    """Types of steganographic triggers."""
    PASSWORD_PATTERN = "password_pattern"    # Specific password sequences
    ACCESS_SEQUENCE = "access_sequence"      # File access patterns
    TIMING_PATTERN = "timing_pattern"        # Time-based patterns
    CONTENT_SIGNATURE = "content_signature"  # Hidden signatures in file content
    BEHAVIOR_ANOMALY = "behavior_anomaly"    # Unusual behavior patterns


class TriggerAction(Enum):
    """Actions to take when trigger is activated."""
    SELECTIVE_WIPE = "selective_wipe"
    AGGRESSIVE_WIPE = "aggressive_wipe"
    SCORCHED_EARTH = "scorched_earth"
    SILENT_CORRUPTION = "silent_corruption"  # Gradually corrupt data
    DECOY_ACTIVATION = "decoy_activation"    # Show decoy data


class StegTrigger:
    """Represents a steganographic trigger."""
    
    def __init__(self, trigger_type: TriggerType, pattern: str, action: TriggerAction,
                 sensitivity: float = 1.0, description: str = ""):
        self.trigger_type = trigger_type
        self.pattern = pattern  # Encoded pattern
        self.action = action
        self.sensitivity = sensitivity  # 0.0-1.0, lower = more sensitive
        self.description = description
        self.created_at = datetime.now()
        self.activated_count = 0
        self.last_activated = None
        self.active = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert trigger to dictionary for storage."""
        return {
            "trigger_type": self.trigger_type.value,
            "pattern": self.pattern,
            "action": self.action.value,
            "sensitivity": self.sensitivity,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "activated_count": self.activated_count,
            "last_activated": self.last_activated.isoformat() if self.last_activated else None,
            "active": self.active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StegTrigger':
        """Create trigger from dictionary."""
        trigger = cls(
            TriggerType(data["trigger_type"]),
            data["pattern"],
            TriggerAction(data["action"]),
            data.get("sensitivity", 1.0),
            data.get("description", "")
        )
        trigger.created_at = datetime.fromisoformat(data["created_at"])
        trigger.activated_count = data.get("activated_count", 0)
        if data.get("last_activated"):
            trigger.last_activated = datetime.fromisoformat(data["last_activated"])
        trigger.active = data.get("active", True)
        return trigger


class SteganographicTriggerSystem:
    """
    Steganographic trigger system for covert self-destruct mechanisms.
    
    This system embeds hidden triggers within normal application operations
    that can activate emergency protocols when specific patterns are detected.
    """
    
    def __init__(self, base_directory: Path, logger: Optional[logging.Logger] = None):
        """Initialize the steganographic trigger system.
        
        Args:
            base_directory: Base directory for BAR application
            logger: Optional logger instance
        """
        self.base_directory = Path(base_directory)
        self.logger = logger or logging.getLogger("StegTriggers")
        
        # Trigger storage (encrypted)
        self.trigger_file = self.base_directory / ".system" / "integrity.dat"
        self.trigger_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Active triggers
        self._triggers: List[StegTrigger] = []
        self._trigger_callbacks: Dict[TriggerAction, List[Callable]] = {
            action: [] for action in TriggerAction
        }
        
        # Pattern tracking for detection
        self._password_history: List[str] = []
        self._access_sequence: List[Tuple[str, datetime]] = []
        
        # Security settings
        self._max_history_size = 100
        self._pattern_window_hours = 24
        
        # Steganographic encoding key (derived from system properties)
        self._encoding_key = self._derive_encoding_key()
        
        # Load existing triggers
        self._load_triggers()
        
        # Install default protective triggers
        self._install_default_triggers()
    
    def _derive_encoding_key(self) -> bytes:
        """Derive encoding key from system properties for steganographic storage."""
        try:
            # Use system-specific properties for key derivation
            system_info = [
                str(self.base_directory),
                str(os.path.getsize(__file__) if os.path.exists(__file__) else "0"),
                str(time.time())[:10]  # Day-level precision for stability
            ]
            
            key_material = "|".join(system_info).encode('utf-8')
            return hashlib.sha256(key_material).digest()[:32]
            
        except Exception:
            # Fallback to static key (less secure but functional)
            return hashlib.sha256(b"BAR_STEG_FALLBACK_KEY").digest()[:32]
    
    def _encode_pattern(self, pattern: str) -> str:
        """Encode a pattern using simple XOR steganography."""
        try:
            pattern_bytes = pattern.encode('utf-8')
            key_bytes = self._encoding_key
            
            # XOR with repeating key
            encoded = bytearray()
            for i, b in enumerate(pattern_bytes):
                encoded.append(b ^ key_bytes[i % len(key_bytes)])
            
            # Return as hex string
            return encoded.hex()
            
        except Exception:
            return pattern  # Fallback to plaintext
    
    def _decode_pattern(self, encoded_pattern: str) -> str:
        """Decode a steganographically encoded pattern."""
        try:
            if len(encoded_pattern) % 2 != 0:
                return encoded_pattern  # Not encoded
            
            encoded_bytes = bytes.fromhex(encoded_pattern)
            key_bytes = self._encoding_key
            
            # XOR with repeating key
            decoded = bytearray()
            for i, b in enumerate(encoded_bytes):
                decoded.append(b ^ key_bytes[i % len(key_bytes)])
            
            return decoded.decode('utf-8')
            
        except Exception:
            return encoded_pattern  # Fallback
    
    def install_trigger(self, trigger_type: TriggerType, pattern: str, 
                       action: TriggerAction, sensitivity: float = 1.0,
                       description: str = "") -> str:
        """Install a new steganographic trigger.
        
        Args:
            trigger_type: Type of trigger to install
            pattern: Pattern to match (will be encoded)
            action: Action to take when triggered
            sensitivity: Sensitivity level (0.0-1.0)
            description: Optional description
            
        Returns:
            Trigger ID for reference
        """
        try:
            # Encode the pattern steganographically
            encoded_pattern = self._encode_pattern(pattern)
            
            trigger = StegTrigger(
                trigger_type=trigger_type,
                pattern=encoded_pattern,
                action=action,
                sensitivity=sensitivity,
                description=description
            )
            
            self._triggers.append(trigger)
            self._save_triggers()
            
            # Generate a trigger ID for reference (hash-based)
            trigger_id = hashlib.sha256(f"{trigger_type.value}:{pattern}".encode()).hexdigest()[:8]
            
            self.logger.debug(f"Installed steganographic trigger: {trigger_id}")
            return trigger_id
            
        except Exception as e:
            self.logger.error(f"Failed to install trigger: {e}")
            return ""
    
    def register_trigger_callback(self, action: TriggerAction, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback for trigger actions.
        
        Args:
            action: Trigger action type
            callback: Function to call when action is triggered
        """
        self._trigger_callbacks[action].append(callback)
    
    def check_password_trigger(self, password: str, context: Dict[str, Any] = None) -> bool:
        """Check if a password matches any steganographic triggers.
        
        Args:
            password: Password to check
            context: Additional context for trigger evaluation
            
        Returns:
            True if a trigger was activated, False otherwise
        """
        try:
            # Add to password history (hashed for privacy)
            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            self._password_history.append(password_hash)
            
            # Maintain history size
            if len(self._password_history) > self._max_history_size:
                self._password_history = self._password_history[-self._max_history_size:]
            
            # Check password pattern triggers
            for trigger in self._triggers:
                if not trigger.active or trigger.trigger_type != TriggerType.PASSWORD_PATTERN:
                    continue
                
                # Decode pattern and check
                pattern = self._decode_pattern(trigger.pattern)
                if self._match_password_pattern(password, pattern, trigger.sensitivity):
                    return self._activate_trigger(trigger, {"password_context": context or {}})
            
            # Check sequence patterns in password history
            if len(self._password_history) >= 3:
                sequence = '|'.join(self._password_history[-3:])
                for trigger in self._triggers:
                    if not trigger.active or trigger.trigger_type != TriggerType.ACCESS_SEQUENCE:
                        continue
                    
                    pattern = self._decode_pattern(trigger.pattern)
                    if pattern in sequence:
                        return self._activate_trigger(trigger, {"sequence_context": True})
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking password trigger: {e}")
            return False
    
    def check_access_pattern_trigger(self, file_id: str, access_type: str) -> bool:
        """Check if file access patterns match any triggers.
        
        Args:
            file_id: ID of accessed file
            access_type: Type of access
            
        Returns:
            True if trigger activated, False otherwise
        """
        try:
            # Record access event
            self._access_sequence.append((f"{file_id}:{access_type}", datetime.now()))
            
            # Maintain sequence size and time window
            cutoff_time = datetime.now() - timedelta(hours=self._pattern_window_hours)
            self._access_sequence = [
                (event, timestamp) for event, timestamp in self._access_sequence 
                if timestamp > cutoff_time
            ][-self._max_history_size:]
            
            # Check access pattern triggers
            for trigger in self._triggers:
                if not trigger.active or trigger.trigger_type != TriggerType.ACCESS_SEQUENCE:
                    continue
                
                pattern = self._decode_pattern(trigger.pattern)
                if self._match_access_pattern(pattern, trigger.sensitivity):
                    return self._activate_trigger(trigger, {"access_context": {"file_id": file_id, "type": access_type}})
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking access pattern trigger: {e}")
            return False
    
    def check_timing_trigger(self, current_time: datetime = None) -> bool:
        """Check if current timing matches any timing-based triggers.
        
        Args:
            current_time: Current time (defaults to now)
            
        Returns:
            True if trigger activated, False otherwise
        """
        try:
            if current_time is None:
                current_time = datetime.now()
            
            # Check timing pattern triggers
            for trigger in self._triggers:
                if not trigger.active or trigger.trigger_type != TriggerType.TIMING_PATTERN:
                    continue
                
                pattern = self._decode_pattern(trigger.pattern)
                if self._match_timing_pattern(current_time, pattern, trigger.sensitivity):
                    return self._activate_trigger(trigger, {"timing_context": current_time.isoformat()})
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking timing trigger: {e}")
            return False
    
    def check_content_signature_trigger(self, content: bytes, file_id: str = "") -> bool:
        """Check if file content contains steganographic trigger signatures.
        
        Args:
            content: File content to check
            file_id: Optional file identifier
            
        Returns:
            True if trigger activated, False otherwise
        """
        try:
            # Generate content signature
            content_hash = hashlib.sha256(content).hexdigest()
            
            # Check for embedded signatures
            for trigger in self._triggers:
                if not trigger.active or trigger.trigger_type != TriggerType.CONTENT_SIGNATURE:
                    continue
                
                pattern = self._decode_pattern(trigger.pattern)
                if self._match_content_signature(content, content_hash, pattern, trigger.sensitivity):
                    return self._activate_trigger(trigger, {"content_context": {"file_id": file_id, "hash": content_hash}})
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking content signature trigger: {e}")
            return False
    
    def _match_password_pattern(self, password: str, pattern: str, sensitivity: float) -> bool:
        """Check if password matches a trigger pattern."""
        try:
            # Support various pattern types
            if pattern.startswith("exact:"):
                return password == pattern[6:]
            elif pattern.startswith("contains:"):
                return pattern[9:] in password
            elif pattern.startswith("length:"):
                target_length = int(pattern[7:])
                threshold = int(target_length * sensitivity)
                return abs(len(password) - target_length) <= threshold
            elif pattern.startswith("regex:"):
                import re
                return bool(re.search(pattern[6:], password))
            else:
                # Default exact match
                return password == pattern
                
        except Exception:
            return False
    
    def _match_access_pattern(self, pattern: str, sensitivity: float) -> bool:
        """Check if access sequence matches pattern."""
        try:
            # Convert access sequence to string
            recent_events = [event for event, _ in self._access_sequence[-10:]]  # Last 10 events
            sequence_str = '|'.join(recent_events)
            
            # Check pattern match
            if pattern.startswith("sequence:"):
                target_sequence = pattern[9:]
                return target_sequence in sequence_str
            elif pattern.startswith("count:"):
                # Count-based trigger (e.g., "count:access:5" for 5 access events)
                parts = pattern.split(":")
                if len(parts) == 3:
                    event_type = parts[1]
                    target_count = int(parts[2])
                    actual_count = sum(1 for event in recent_events if event_type in event)
                    threshold = int(target_count * sensitivity)
                    return actual_count >= threshold
            
            return False
            
        except Exception:
            return False
    
    def _match_timing_pattern(self, current_time: datetime, pattern: str, sensitivity: float) -> bool:
        """Check if timing matches trigger pattern."""
        try:
            if pattern.startswith("hour:"):
                target_hour = int(pattern[5:])
                return current_time.hour == target_hour
            elif pattern.startswith("date:"):
                # Format: date:MM-DD
                target_date = pattern[5:]
                current_date = current_time.strftime("%m-%d")
                return current_date == target_date
            elif pattern.startswith("interval:"):
                # Check intervals between events
                # TODO: Implement interval-based timing trigger
                # Requires tracking event timestamps and calculating intervals
                pass
            
            return False
            
        except Exception:
            return False
    
    def _match_content_signature(self, content: bytes, content_hash: str, pattern: str, sensitivity: float) -> bool:
        """Check if content contains trigger signature."""
        try:
            if pattern.startswith("hash:"):
                target_hash = pattern[5:]
                return content_hash == target_hash
            elif pattern.startswith("bytes:"):
                target_bytes = bytes.fromhex(pattern[6:])
                return target_bytes in content
            elif pattern.startswith("entropy:"):
                # Check entropy level (simplified Shannon entropy)
                target_entropy = float(pattern[8:])
                # Shannon entropy calculation
                if len(content) > 0:
                    import math
                    byte_counts = [0] * 256
                    for byte in content:
                        byte_counts[byte] += 1
                    
                    entropy = 0.0
                    for count in byte_counts:
                        if count > 0:
                            p = count / len(content)
                            entropy -= p * math.log2(p)
                    
                    threshold = target_entropy * sensitivity
                    return entropy >= threshold
            
            return False
            
        except Exception:
            return False
    
    def _activate_trigger(self, trigger: StegTrigger, context: Dict[str, Any]) -> bool:
        """Activate a steganographic trigger."""
        try:
            trigger.activated_count += 1
            trigger.last_activated = datetime.now()
            
            # Log trigger activation (minimal for stealth)
            self.logger.info(f"Security protocol activated: {trigger.action.value}")
            
            # Execute callbacks for this action
            callbacks = self._trigger_callbacks.get(trigger.action, [])
            activation_data = {
                "trigger_type": trigger.trigger_type.value,
                "action": trigger.action.value,
                "timestamp": datetime.now().isoformat(),
                "context": context
            }
            
            for callback in callbacks:
                try:
                    callback(activation_data)
                except Exception as e:
                    self.logger.error(f"Error in trigger callback: {e}")
            
            # Save updated trigger state
            self._save_triggers()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error activating trigger: {e}")
            return False
    
    def _install_default_triggers(self):
        """Install default protective triggers."""
        try:
            # Don't reinstall if triggers already exist
            if self._triggers:
                return
            
            # Emergency password trigger (example - customize as needed)
            # Uses pattern that looks like normal password but triggers emergency wipe
            emergency_pattern = "burnaftereading123!"
            self.install_trigger(
                TriggerType.PASSWORD_PATTERN,
                f"exact:{emergency_pattern}",
                TriggerAction.SCORCHED_EARTH,
                sensitivity=1.0,
                description="Emergency destruction password"
            )
            
            # Rapid access trigger (possible brute force or forensic tool)
            self.install_trigger(
                TriggerType.ACCESS_SEQUENCE,
                "count:access:20",  # 20 access attempts
                TriggerAction.AGGRESSIVE_WIPE,
                sensitivity=0.8,
                description="Rapid access detection"
            )
            
            # Unusual timing trigger (access during non-typical hours)
            self.install_trigger(
                TriggerType.TIMING_PATTERN,
                "hour:3",  # 3 AM access
                TriggerAction.SELECTIVE_WIPE,
                sensitivity=1.0,
                description="Unusual hour access"
            )
            
        except Exception as e:
            self.logger.error(f"Error installing default triggers: {e}")
    
    def _load_triggers(self):
        """Load triggers from steganographic storage."""
        trigger_file_to_use = None
        
        try:
            # Check primary location first
            if self.trigger_file.exists():
                trigger_file_to_use = self.trigger_file
            else:
                # Check fallback location
                import tempfile
                fallback_file = Path(tempfile.gettempdir()) / '.bar_integrity.dat'
                if fallback_file.exists():
                    trigger_file_to_use = fallback_file
                    self.logger.debug(f"Using fallback trigger file: {fallback_file}")
            
            if not trigger_file_to_use:
                return
            
            # Read and decode trigger file
            with open(trigger_file_to_use, 'rb') as f:
                encrypted_data = f.read()
            
            # Simple XOR decryption
            key_bytes = self._encoding_key
            decrypted_data = bytearray()
            for i, b in enumerate(encrypted_data):
                decrypted_data.append(b ^ key_bytes[i % len(key_bytes)])
            
            # Parse JSON
            import json
            trigger_data = json.loads(decrypted_data.decode('utf-8'))
            
            self._triggers = [StegTrigger.from_dict(data) for data in trigger_data.get("triggers", [])]
            
        except Exception as e:
            self.logger.debug(f"Could not load triggers: {e}")
            self._triggers = []
    
    def _save_triggers(self):
        """Save triggers to steganographic storage."""
        try:
            # Convert triggers to dictionary format
            import json
            trigger_data = {
                "version": "1.0",
                "triggers": [trigger.to_dict() for trigger in self._triggers],
                "updated": datetime.now().isoformat()
            }
            
            # Serialize to JSON
            json_data = json.dumps(trigger_data).encode('utf-8')
            
            # Simple XOR encryption
            key_bytes = self._encoding_key
            encrypted_data = bytearray()
            for i, b in enumerate(json_data):
                encrypted_data.append(b ^ key_bytes[i % len(key_bytes)])
            
            # Ensure directory exists and is writable
            self.trigger_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Try to remove existing file if it exists and is problematic
            if self.trigger_file.exists():
                try:
                    # Try to make it writable first
                    if os.name == 'nt':
                        import subprocess
                        subprocess.run(['attrib', '-H', '-R', str(self.trigger_file)], 
                                     capture_output=True, check=False)
                    else:
                        os.chmod(self.trigger_file, 0o644)
                except Exception:
                    pass
            
            # Write to file (hidden as system integrity data)
            # Use a temporary file first to avoid corruption
            temp_file = self.trigger_file.with_suffix('.tmp')
            try:
                with open(temp_file, 'wb') as f:
                    f.write(encrypted_data)
                
                # Move temporary file to final location
                if self.trigger_file.exists():
                    self.trigger_file.unlink()
                temp_file.replace(self.trigger_file)
                
            except Exception:
                # If temp file approach fails, try direct write
                with open(self.trigger_file, 'wb') as f:
                    f.write(encrypted_data)
            
            # Set appropriate permissions (hidden/system file on Windows)
            if os.name == 'nt':
                try:
                    import subprocess
                    # Use attrib command to set hidden attribute
                    subprocess.run(['attrib', '+H', str(self.trigger_file)], 
                                 capture_output=True, check=False)
                except Exception:
                    pass
            
        except Exception as e:
            self.logger.error(f"Error saving triggers: {e}")
            # Try fallback location in user's temp directory
            try:
                import tempfile
                fallback_file = Path(tempfile.gettempdir()) / '.bar_integrity.dat'
                with open(fallback_file, 'wb') as f:
                    f.write(encrypted_data)
                self.logger.debug(f"Saved triggers to fallback location: {fallback_file}")
            except Exception as fallback_error:
                self.logger.error(f"Fallback save also failed: {fallback_error}")
    
    def get_trigger_stats(self) -> Dict[str, Any]:
        """Get statistics about active triggers (sanitized for security)."""
        try:
            active_triggers = [t for t in self._triggers if t.active]
            
            stats = {
                "total_triggers": len(self._triggers),
                "active_triggers": len(active_triggers),
                "trigger_types": {},
                "total_activations": sum(t.activated_count for t in self._triggers),
                "last_activation": None
            }
            
            # Count by type
            for trigger in active_triggers:
                trigger_type = trigger.trigger_type.value
                stats["trigger_types"][trigger_type] = stats["trigger_types"].get(trigger_type, 0) + 1
            
            # Find last activation
            last_activated_triggers = [t for t in self._triggers if t.last_activated]
            if last_activated_triggers:
                last_activation = max(t.last_activated for t in last_activated_triggers)
                stats["last_activation"] = last_activation.isoformat()
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting trigger stats: {e}")
            return {"error": "unavailable"}
    
    def cleanup(self):
        """Clean up steganographic trigger system."""
        try:
            # Clear sensitive data from memory
            self._password_history.clear()
            self._access_sequence.clear()
            
            # Clear encoding key
            if hasattr(self, '_encoding_key'):
                self._encoding_key = b'\x00' * len(self._encoding_key)
                del self._encoding_key
            
        except Exception as e:
            self.logger.debug(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Cleanup on destruction."""
        try:
            self.cleanup()
        except Exception:
            pass
