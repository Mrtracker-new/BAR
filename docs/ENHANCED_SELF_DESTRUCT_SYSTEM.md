# Enhanced Self-Destruct System Documentation

**Version**: 2.0.0  
**Last Updated**: January 2025  
**Author**: BAR Development Team  

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)  
- [Components](#components)
- [Destruction Levels](#destruction-levels)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

---

## Overview

The Enhanced Self-Destruct System provides comprehensive data destruction capabilities for the BAR (Burn After Reading) application. This system implements multiple layers of security-focused data destruction, from selective file removal to complete system sanitization.

### Key Features

- **Graded Destruction Levels**: Selective, Aggressive, and Scorched Earth modes
- **Intelligent Monitoring**: Behavioral analysis and threat detection  
- **Steganographic Triggers**: Hidden destruction triggers embedded in normal operations
- **Hardware-Level Wiping**: Volume-scoped free space sanitization
- **Cross-Platform Support**: Windows, Linux, and macOS compatibility
- **Offline Operation**: No external dependencies or network requirements

### Security Principles

The enhanced system follows these core security principles:

- **Defense in Depth**: Multiple overlapping security layers
- **Fail-Safe Defaults**: Secure defaults with explicit override required for reduced security
- **Minimal Attack Surface**: Offline-first design with no external dependencies
- **Plausible Deniability**: Hidden triggers that appear as normal operations
- **Performance Efficiency**: Resource-conscious operations with safety limits

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Enhanced Self-Destruct System            │
├─────────────────┬─────────────────┬─────────────────────────┤
│ Emergency       │ Intelligent     │ Steganographic          │
│ Protocol        │ Monitor         │ Triggers                │
│                 │                 │                         │
│ • Graded levels │ • Behavioral    │ • Hidden patterns       │
│ • Dead man's    │   analysis      │ • Multiple trigger      │
│   switch        │ • Threat        │   types                 │
│ • Blacklisting  │   detection     │ • Covert activation     │
└─────────────────┼─────────────────┼─────────────────────────┤
┌─────────────────┼─────────────────┼─────────────────────────┐
│ Secure Delete   │ Hardware Wipe   │ File Manager            │
│                 │                 │ Integration             │
│ • DoD patterns  │ • Free space    │                         │
│ • ADS cleanup   │   scrubbing     │ • Automatic             │
│ • Verification  │ • Safe limits   │   monitoring            │
│ • Filename      │ • Cross-platform│ • Trigger integration   │
│   randomization │                 │                         │
└─────────────────┴─────────────────┴─────────────────────────┘
```

---

## Components

### 1. Emergency Protocol (`emergency_protocol.py`)

The central orchestrator for emergency data destruction.

**Key Features:**
- Graded destruction levels (selective, aggressive, scorched)
- Dead man's switch with configurable timeout
- File blacklisting and quarantine
- Hardware-level free space scrubbing integration
- Anti-forensics measures

**Usage:**
```python
from src.security.emergency_protocol import EmergencyProtocol

# Initialize with device auth manager
emergency = EmergencyProtocol(base_directory, device_auth_manager)

# Trigger emergency destruction
emergency.trigger_emergency_destruction(
    reason="Manual activation",
    level="aggressive",  # selective | aggressive | scorched  
    scrub_free_space=True
)
```

### 2. Secure Delete (`secure_delete.py`)

Enhanced secure deletion with advanced anti-forensics.

**Enhancements:**
- Filename randomization before overwrite
- NTFS Alternate Data Stream (ADS) cleanup on Windows  
- Post-deletion verification
- DoD 5220.22-M compliant patterns

**Usage:**
```python
from src.security.secure_delete import SecureDelete

secure_delete = SecureDelete()

# Secure file deletion
result = secure_delete.secure_delete_file("/path/to/file.txt", passes=7)

# Secure directory deletion
result = secure_delete.secure_delete_directory("/path/to/directory")
```

### 3. Intelligent Monitor (`intelligent_monitor.py`)

Behavioral analysis and threat detection system.

**Features:**
- User behavior profiling
- Access pattern anomaly detection
- Threat level assessment with callbacks
- Tamper detection capabilities
- Real-time monitoring with background thread

**Usage:**
```python
from src.security.intelligent_monitor import IntelligentFileMonitor, ThreatLevel

monitor = IntelligentFileMonitor(base_directory)

# Register threat response
def handle_high_threat(threat_data):
    # Trigger appropriate response
    emergency.trigger_emergency_destruction("Threat detected", level="aggressive")

monitor.register_threat_callback(ThreatLevel.HIGH, handle_high_threat)

# Start monitoring
monitor.start_monitoring()

# Record access events
monitor.record_access_event("file_id", "access", success=True)
```

### 4. Steganographic Triggers (`steganographic_triggers.py`)

Hidden destruction triggers embedded in normal operations.

**Trigger Types:**
- **Password Patterns**: Specific password sequences
- **Access Sequences**: File access patterns  
- **Timing Patterns**: Time-based activation
- **Content Signatures**: Hidden signatures in file content
- **Behavior Anomalies**: Unusual activity detection

**Usage:**
```python
from src.security.steganographic_triggers import SteganographicTriggerSystem, TriggerType, TriggerAction

steg_system = SteganographicTriggerSystem(base_directory)

# Install emergency password trigger
steg_system.install_trigger(
    TriggerType.PASSWORD_PATTERN,
    "exact:emergency_destroy_now",
    TriggerAction.SCORCHED_EARTH,
    sensitivity=1.0,
    description="Emergency password trigger"
)

# Check for trigger activation
result = steg_system.check_password_trigger(user_password)
if result:
    # Trigger was activated - emergency protocol engaged
    pass
```

### 5. Hardware Wipe (`hardware_wipe.py`)

Volume-scoped hardware-level data destruction.

**Features:**
- Free space wiping on same volume only
- Multiple wipe patterns (zeros, ones, random, DoD)
- Safety limits and timeouts
- Cross-platform compatibility
- Performance estimation

**Usage:**
```python
from src.security.hardware_wipe import HardwareWipe, WipePattern

hardware_wipe = HardwareWipe()

# Estimate wipe time
estimate = hardware_wipe.estimate_wipe_time(
    path="/path/to/volume",
    max_bytes=1024*1024*1024  # 1GB limit
)

# Perform free space wipe
result = hardware_wipe.wipe_volume_free_space(
    path="/path/to/volume",
    max_bytes=None,  # Use default limits
    pattern="random"
)
```

---

## Destruction Levels

The enhanced system provides three graded destruction levels:

### Selective (Level 1)
**Scope:** BAR application directories and configuration files only
**Use Case:** Targeted cleanup while preserving system functionality
**Includes:**
- `base_directory/data/`
- `base_directory/logs/`
- `base_directory/temp/` 
- `base_directory/cache/`
- Configuration files (*.json, *.key, *.enc)

### Aggressive (Level 2)  
**Scope:** Selective + user-scope BAR directories and temp traces
**Use Case:** Comprehensive BAR removal with system-wide cleanup
**Includes:**
- All Selective level targets
- `~/.bar/` (user home BAR directory)
- `~/Documents/BAR/` 
- Platform-specific app data directories
- BAR-related temporary files
- **Free space scrubbing** (default enabled)

### Scorched Earth (Level 3)
**Scope:** Aggressive + additional artifacts and traces  
**Use Case:** Maximum security when complete data destruction is required
**Includes:**
- All Aggressive level targets
- Quarantine directories
- Blacklist artifacts
- Extended trace cleanup
- **Free space scrubbing** (default enabled)
- Additional anti-forensics measures

### Activation Examples

```python
# Selective destruction (minimal impact)
emergency.trigger_emergency_destruction(
    reason="Routine cleanup",
    level="selective",
    scrub_free_space=False  # Override default
)

# Aggressive destruction (comprehensive)  
emergency.trigger_emergency_destruction(
    reason="Security incident",
    level="aggressive"
    # scrub_free_space=True (default for aggressive)
)

# Scorched earth (maximum security)
emergency.trigger_emergency_destruction(
    reason="Emergency wipe",
    level="scorched"
    # scrub_free_space=True (default for scorched)
)
```

---

## Configuration

### Emergency Protocol Configuration

```python
# Dead man's switch timeout
emergency.set_dead_mans_switch_timeout(hours=24)

# Start dead man's switch
emergency.start_dead_mans_switch()

# Register callbacks
emergency.register_emergency_callback(lambda: print("Emergency activated"))
```

### Intelligent Monitor Configuration

```python
# Configure monitoring parameters
monitor._learning_period_days = 7      # Behavioral learning period
monitor._failure_threshold = 5         # Failed attempts before alert
monitor._analysis_window_hours = 24    # Analysis time window

# Update user profile periodically
monitor.update_user_profile()
```

### Hardware Wipe Safety Limits

```python
# Set conservative safety limits
hardware_wipe.set_safety_limits(
    max_wipe_size_gb=5,    # Maximum 5GB per operation
    timeout_seconds=300    # 5 minute timeout
)

# Check platform capabilities
capabilities = hardware_wipe.get_platform_capabilities()
```

### Steganographic Trigger Configuration

```python
# Install various trigger types

# Password-based trigger
steg_system.install_trigger(
    TriggerType.PASSWORD_PATTERN,
    "contains:panic",  # Any password containing "panic"
    TriggerAction.AGGRESSIVE_WIPE
)

# Access count trigger  
steg_system.install_trigger(
    TriggerType.ACCESS_SEQUENCE,
    "count:decrypt:10",  # 10 decryption attempts
    TriggerAction.SELECTIVE_WIPE,
    sensitivity=0.8
)

# Timing trigger
steg_system.install_trigger(
    TriggerType.TIMING_PATTERN, 
    "hour:3",  # Access at 3 AM
    TriggerAction.AGGRESSIVE_WIPE
)
```

---

## Usage Examples

### Complete Integration Example

```python
import os
from pathlib import Path
from src.security.emergency_protocol import EmergencyProtocol
from src.security.intelligent_monitor import IntelligentFileMonitor, ThreatLevel
from src.security.steganographic_triggers import SteganographicTriggerSystem, TriggerType, TriggerAction

# Initialize components
base_dir = Path(os.getcwd())
device_auth = DeviceAuthManager()  # Your device auth implementation

# Set up emergency protocol
emergency = EmergencyProtocol(base_dir, device_auth)

# Set up intelligent monitoring
monitor = IntelligentFileMonitor(base_dir)

# Set up steganographic triggers
steg_system = SteganographicTriggerSystem(base_dir)

# Configure threat responses
def handle_critical_threat(threat_data):
    emergency.trigger_emergency_destruction(
        reason=f"Critical threat: {threat_data.get('type', 'unknown')}",
        level="scorched"
    )

def handle_high_threat(threat_data):
    emergency.trigger_emergency_destruction(
        reason=f"High threat: {threat_data.get('type', 'unknown')}", 
        level="aggressive"
    )

# Register callbacks
monitor.register_threat_callback(ThreatLevel.CRITICAL, handle_critical_threat)
monitor.register_threat_callback(ThreatLevel.HIGH, handle_high_threat)

# Install steganographic triggers
steg_system.install_trigger(
    TriggerType.PASSWORD_PATTERN,
    "exact:burn_everything_now",
    TriggerAction.SCORCHED_EARTH
)

steg_system.register_trigger_callback(
    TriggerAction.SCORCHED_EARTH,
    lambda data: emergency.trigger_emergency_destruction("Steg trigger", "scorched")
)

# Start monitoring
monitor.start_monitoring()
emergency.start_dead_mans_switch()

# In your application's file access code:
def access_file(file_id, password):
    # Check steganographic triggers
    trigger_activated = steg_system.check_password_trigger(password)
    if trigger_activated:
        # Emergency protocol already triggered by callback
        return None
        
    try:
        # Normal file access
        content = file_manager.access_file(file_id, password)
        
        # Record successful access for monitoring
        monitor.record_access_event(file_id, "access", success=True)
        
        return content
        
    except Exception as e:
        # Record failed access
        monitor.record_access_event(file_id, "access", success=False)
        raise e

# Cleanup on shutdown
def shutdown():
    monitor.stop_monitoring()
    emergency.stop_dead_mans_switch()
    steg_system.cleanup()
```

### Emergency Activation Scenarios

```python
# Manual panic button
def panic_button():
    emergency.trigger_emergency_destruction(
        reason="Manual panic activation",
        level="scorched"
    )

# Automated threat response
def automated_response(threat_level, threat_data):
    if threat_level >= ThreatLevel.CRITICAL:
        level = "scorched"
    elif threat_level >= ThreatLevel.HIGH:
        level = "aggressive" 
    else:
        level = "selective"
        
    emergency.trigger_emergency_destruction(
        reason=f"Automated response to {threat_data.get('type')}",
        level=level
    )

# Dead man's switch activation (automatic)
# Triggers automatically if no heartbeat received within timeout period
emergency.heartbeat()  # Call periodically during normal operation
```

---

## Security Considerations

### Threat Model

The enhanced self-destruct system is designed to protect against:

1. **Forensic Analysis**: Post-incident investigation attempts
2. **Unauthorized Access**: Brute force and social engineering attacks  
3. **Malware/Rootkits**: System compromise and data exfiltration
4. **Physical Seizure**: Device confiscation scenarios
5. **Insider Threats**: Privileged user abuse
6. **Legal Compulsion**: Court orders and government requests

### Security Assumptions

- **Physical Security**: Attacker cannot modify the application binary
- **OS Integrity**: Operating system is not completely compromised
- **User Cooperation**: Legitimate user follows security procedures
- **Time Constraints**: Attacker has limited time before activation
- **Storage Technology**: Standard filesystems without specialized recovery tools

### Limitations

1. **SSD Wear Leveling**: May prevent complete data destruction on SSDs
2. **Hardware Forensics**: Nation-state actors with specialized equipment
3. **Memory Dumps**: Live memory analysis during execution
4. **Timing Attacks**: Analysis of activation patterns  
5. **Social Engineering**: User manipulation to bypass security

### Best Practices

1. **Regular Testing**: Periodically test emergency procedures
2. **User Training**: Educate users on proper activation procedures
3. **Monitoring Review**: Regularly review monitoring alerts and patterns
4. **Trigger Management**: Periodically update steganographic triggers
5. **Hardware Considerations**: Use full-disk encryption as additional layer

---

## Testing

### Running Tests

The comprehensive test suite validates all enhanced self-destruct functionality:

```bash
# Run all enhanced self-destruct tests
python -m pytest tests/security/test_enhanced_self_destruct.py -v

# Run specific test categories
python -m pytest tests/security/test_enhanced_self_destruct.py::TestSecureDelete -v
python -m pytest tests/security/test_enhanced_self_destruct.py::TestEmergencyProtocol -v
python -m pytest tests/security/test_enhanced_self_destruct.py::TestIntelligentMonitor -v
python -m pytest tests/security/test_enhanced_self_destruct.py::TestSteganographicTriggers -v
python -m pytest tests/security/test_enhanced_self_destruct.py::TestHardwareWipe -v

# Run integration tests
python -m pytest tests/security/test_enhanced_self_destruct.py::TestIntegrationScenarios -v
```

### Test Coverage

The test suite provides comprehensive coverage of:

- **Unit Tests**: Individual component functionality
- **Integration Tests**: Component interaction and data flow  
- **Security Tests**: Threat scenarios and edge cases
- **Performance Tests**: Resource usage and timing
- **Error Handling**: Failure modes and recovery
- **Cross-Platform**: Platform-specific functionality

### Test Safety

All tests use:
- Temporary directories that are automatically cleaned up
- Mock sensitive operations to prevent actual data destruction
- Small data sizes to minimize resource usage
- Isolated test environments to prevent interference

---

## Troubleshooting

### Common Issues

#### Emergency Protocol Not Triggering

**Symptoms**: Emergency destruction not activated when expected
**Possible Causes**:
- Dead man's switch not started
- Callback registration issues
- System exit being prevented

**Solutions**:
```python
# Verify dead man's switch status
status = emergency.get_emergency_status()
print(f"Dead man's switch active: {status['dead_mans_switch_active']}")

# Check callback registration
emergency.register_emergency_callback(lambda: print("Emergency callback triggered"))

# Test trigger manually
emergency.trigger_emergency_destruction("Test", level="selective")
```

#### Intelligent Monitor False Positives

**Symptoms**: Too many threat alerts for normal usage
**Possible Causes**:
- Insufficient learning period
- Overly sensitive thresholds
- Atypical user behavior

**Solutions**:
```python
# Increase learning period
monitor._learning_period_days = 14

# Adjust failure threshold
monitor._failure_threshold = 10

# Update user profile manually
monitor.update_user_profile()
```

#### Steganographic Triggers Not Activating

**Symptoms**: Hidden triggers not responding to patterns
**Possible Causes**:
- Pattern encoding/decoding issues
- Incorrect pattern syntax
- Callback not registered

**Solutions**:
```python
# Test pattern matching manually
pattern = "exact:test_password"
result = steg_system._match_password_pattern("test_password", pattern, 1.0)
print(f"Pattern match result: {result}")

# Verify trigger installation
stats = steg_system.get_trigger_stats()
print(f"Active triggers: {stats['active_triggers']}")

# Check callback registration
steg_system.register_trigger_callback(
    TriggerAction.SELECTIVE_WIPE,
    lambda data: print(f"Trigger activated: {data}")
)
```

#### Hardware Wipe Performance Issues

**Symptoms**: Free space wipe takes too long or fails
**Possible Causes**:
- Insufficient free space
- Safety limits too restrictive
- Storage performance limitations

**Solutions**:
```python
# Check disk space and estimate time
estimate = hardware_wipe.estimate_wipe_time(path, max_bytes=1024*1024*1024)
print(f"Estimated time: {estimate['estimated_minutes']} minutes")

# Adjust safety limits
hardware_wipe.set_safety_limits(max_wipe_size_gb=1, timeout_seconds=600)

# Use faster wipe pattern
result = hardware_wipe.wipe_volume_free_space(path, pattern="zeros")
```

### Diagnostic Information

```python
# Emergency protocol status
emergency_status = emergency.get_emergency_status()

# Monitoring statistics  
monitor_stats = monitor.get_monitoring_stats()

# Steganographic trigger information
trigger_stats = steg_system.get_trigger_stats()

# Hardware capabilities
hw_capabilities = hardware_wipe.get_platform_capabilities()

# Print comprehensive diagnostic info
print("=== Enhanced Self-Destruct System Diagnostics ===")
print(f"Emergency Status: {emergency_status}")
print(f"Monitor Stats: {monitor_stats}")
print(f"Trigger Stats: {trigger_stats}")
print(f"Hardware Capabilities: {hw_capabilities}")
```

### Log Analysis

Monitor log files for diagnostic information:

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Component-specific loggers
emergency_logger = logging.getLogger("EmergencyProtocol")
monitor_logger = logging.getLogger("IntelligentMonitor")
steg_logger = logging.getLogger("StegTriggers")
hw_logger = logging.getLogger("HardwareWipe")
```

---

## API Reference

### EmergencyProtocol

#### Methods

**`__init__(base_directory, device_auth)`**
- Initialize emergency protocol with base directory and device auth manager

**`trigger_emergency_destruction(reason, level="aggressive", scrub_free_space=None)`**
- Trigger emergency data destruction
- `reason`: String describing activation reason
- `level`: Destruction level ("selective", "aggressive", "scorched")
- `scrub_free_space`: Override free space scrubbing (defaults per level)

**`start_dead_mans_switch()` / `stop_dead_mans_switch()`**
- Start/stop dead man's switch monitoring

**`heartbeat()`**
- Send heartbeat to reset dead man's switch timer

**`add_to_blacklist(file_path, reason)` / `remove_from_blacklist(file_path)`**
- Manage file blacklist for automatic secure deletion

**`quarantine_file(file_path, reason)`**
- Move file to quarantine and add to blacklist

**`get_emergency_status()`**
- Get current emergency protocol status and statistics

### IntelligentFileMonitor  

#### Methods

**`__init__(base_directory, logger=None)`**
- Initialize intelligent monitor for given directory

**`start_monitoring()` / `stop_monitoring()`**
- Start/stop background monitoring thread

**`record_access_event(file_id, event_type, success=True, metadata=None)`**
- Record file access event for behavioral analysis

**`register_threat_callback(threat_level, callback)`**
- Register callback for specific threat levels

**`analyze_current_behavior()`**
- Analyze recent behavior patterns and return threat assessment

**`detect_tampering()`**
- Check for system tampering indicators

**`get_monitoring_stats()`**
- Get monitoring statistics and configuration

### SteganographicTriggerSystem

#### Methods

**`__init__(base_directory, logger=None)`**
- Initialize steganographic trigger system

**`install_trigger(trigger_type, pattern, action, sensitivity=1.0, description="")`**
- Install new steganographic trigger

**`register_trigger_callback(action, callback)`**
- Register callback for trigger actions

**`check_password_trigger(password, context=None)`**
- Check password against installed triggers

**`check_access_pattern_trigger(file_id, access_type)`**
- Check access patterns against triggers

**`check_timing_trigger(current_time=None)`**
- Check timing-based triggers

**`get_trigger_stats()`**
- Get trigger statistics and status

### HardwareWipe

#### Methods

**`__init__(logger=None)`**
- Initialize hardware wipe manager

**`wipe_volume_free_space(path, max_bytes=None, pattern="random", progress_callback=None)`**
- Wipe free space on volume containing path

**`estimate_wipe_time(path, max_bytes=None)`** 
- Estimate time required for wipe operation

**`set_safety_limits(max_wipe_size_gb=10, timeout_seconds=300)`**
- Configure safety limits for wipe operations

**`get_platform_capabilities()`**
- Get platform-specific capabilities and limitations

---

## Conclusion

The Enhanced Self-Destruct System provides comprehensive, multi-layered data destruction capabilities designed for maximum security while maintaining usability and performance. The system's modular architecture allows for flexible deployment and customization based on specific security requirements.

For additional security, combine this system with full-disk encryption, secure boot, and proper operational security practices. Regular testing and user training are essential for maintaining the system's effectiveness in real-world scenarios.

---

**⚠️ IMPORTANT SECURITY NOTICE**

This documentation describes powerful data destruction capabilities. Use only for legitimate security purposes and ensure proper authorization before deployment. Test thoroughly in non-production environments before production use. The authors are not responsible for data loss resulting from improper use of these systems.

---

*This document is part of the BAR (Burn After Reading) security documentation suite. For additional information, see:*

- *SECURITY_IMPROVEMENTS.md - Core security enhancements*
- *STATISTICAL_MASKING_DOCUMENTATION.md - Anti-detection techniques*  
- *API_REFERENCE.md - Complete API documentation*
- *USER_GUIDE.md - End-user instructions*
