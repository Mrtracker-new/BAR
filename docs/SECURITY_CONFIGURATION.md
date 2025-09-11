# BAR Security Configuration System

## Overview

The BAR security configuration system provides flexible, environment-aware security settings for the advanced screen protection features. This system allows for easy adjustment of security parameters based on different use cases, from development to maximum security production deployments.

## Security Levels

### Development (`SecurityLevel.DEVELOPMENT`)
- **Purpose**: Development-friendly settings with minimal interference
- **Use Case**: Local development, testing, debugging
- **Key Settings**:
  - Process monitoring: **Disabled**
  - Max suspicious score: **50** (very high threshold)
  - Max focus loss count: **50** (very tolerant)
  - Check interval: **10 seconds** (less frequent)
  - Overlay protection: **Disabled**
  - Aggressive mode: **Disabled**

### Basic (`SecurityLevel.BASIC`)
- **Purpose**: Basic protection suitable for most users
- **Use Case**: General use, low-sensitivity content
- **Key Settings**:
  - Process monitoring: **Enabled**
  - Max suspicious score: **30**
  - Max focus loss count: **20**
  - Check interval: **5 seconds**
  - Overlay protection: **Disabled**
  - Aggressive mode: **Disabled**

### Standard (`SecurityLevel.STANDARD`) - Default
- **Purpose**: Standard protection with all features enabled
- **Use Case**: Business use, moderate sensitivity content
- **Key Settings**:
  - Process monitoring: **Enabled**
  - Max suspicious score: **20**
  - Max focus loss count: **10**
  - Check interval: **3 seconds**
  - Overlay protection: **Enabled**
  - Aggressive mode: **Disabled**

### High (`SecurityLevel.HIGH`)
- **Purpose**: High security for sensitive environments
- **Use Case**: Corporate environments, sensitive documents
- **Key Settings**:
  - Process monitoring: **Enabled**
  - Max suspicious score: **15**
  - Max focus loss count: **5**
  - Check interval: **2 seconds**
  - Overlay protection: **Enabled**
  - Aggressive mode: **Enabled**

### Maximum (`SecurityLevel.MAXIMUM`)
- **Purpose**: Maximum security for highly sensitive content
- **Use Case**: Classified documents, high-value intellectual property
- **Key Settings**:
  - Process monitoring: **Enabled**
  - Max suspicious score: **10** (very strict)
  - Max focus loss count: **3** (very strict)
  - Check interval: **1 second** (very frequent)
  - Overlay protection: **Enabled**
  - Aggressive mode: **Enabled**

## Configuration Parameters

### Core Security Settings

#### `max_suspicious_score` (int)
- **Description**: Maximum threshold for suspicious activity before triggering security breach handling
- **Range**: 10-50
- **Impact**: Lower values trigger security measures more aggressively

#### `max_focus_loss_count` (int)
- **Description**: Maximum number of focus losses before escalating security response
- **Range**: 3-50
- **Impact**: Lower values react more strictly to window focus changes

#### `check_interval` (float)
- **Description**: Interval in seconds between security checks
- **Range**: 1.0-10.0 seconds
- **Impact**: Lower values provide more responsive but resource-intensive monitoring

### Feature Toggles

#### `process_monitoring_enabled` (bool)
- **Description**: Enable monitoring of running processes for suspicious software
- **Default**: True (except Development level)
- **Impact**: Detects screen capture and recording software

#### `clipboard_protection_enabled` (bool)
- **Description**: Enable clipboard access monitoring and blocking
- **Default**: True
- **Impact**: Prevents unauthorized copying of protected content

#### `watermark_enabled` (bool)
- **Description**: Enable dynamic watermarking of protected content
- **Default**: True
- **Impact**: Adds forensic tracking to content

#### `focus_monitoring_enabled` (bool)
- **Description**: Enable window focus monitoring and blur effects
- **Default**: True
- **Impact**: Protects content when window loses focus

#### `overlay_protection_enabled` (bool)
- **Description**: Enable security overlay warnings and notifications
- **Default**: Varies by level
- **Impact**: Provides visual security feedback to users

#### `screenshot_blocking_enabled` (bool)
- **Description**: Enable keyboard hook blocking of screenshot keys
- **Default**: True
- **Impact**: Blocks Print Screen and other screenshot hotkeys

#### `aggressive_mode` (bool)
- **Description**: Enable aggressive security measures and rapid response
- **Default**: Enabled for High and Maximum levels
- **Impact**: Faster breach detection but potentially more false positives

## Usage Examples

### Basic Usage (Auto-Detection)

```python
from src.security.advanced_screen_protection import AdvancedScreenProtectionManager

# Auto-detects security level based on environment
protection = AdvancedScreenProtectionManager(
    username="user123",
    protected_widget=my_widget,
    log_directory="security_logs"
)
protection.start_protection()
```

### Explicit Security Level

```python
from src.security.advanced_screen_protection import AdvancedScreenProtectionManager
from src.config.security_config import SecurityLevel

# Explicitly set security level
protection = AdvancedScreenProtectionManager(
    username="user123",
    protected_widget=my_widget,
    log_directory="security_logs",
    security_level=SecurityLevel.HIGH
)
protection.start_protection()
```

### Custom Configuration

```python
from src.config.security_config import security_config, SecurityLevel

# Create custom configuration based on HIGH level with overrides
custom_config = security_config.create_custom_config(
    base_level=SecurityLevel.HIGH,
    overrides={
        'max_suspicious_score': 25,  # Slightly more lenient
        'process_monitoring_enabled': False  # Disable process monitoring
    }
)

# Use custom configuration (would require additional implementation)
```

### Configuration Queries

```python
from src.config.security_config import security_config, get_security_config

# Get available levels with descriptions
levels = security_config.get_available_levels()
for level, description in levels.items():
    print(f"{level.value}: {description}")

# Get development-friendly config
dev_config = get_security_config(SecurityLevel.DEVELOPMENT)
print(f"Development max suspicious score: {dev_config['max_suspicious_score']}")
```

## Environment Auto-Detection

The system automatically detects the appropriate security level based on environment indicators:

### Development Environment Detection
- Running from Desktop directory
- Paths containing 'dev', 'development', 'src', 'project'
- Environment variables: DEVELOPMENT, DEBUG, PYCHARM, VSCODE
- **Result**: Uses `SecurityLevel.DEVELOPMENT`

### Production Environment Detection
- Paths containing 'production', 'prod'
- Environment variable: PRODUCTION
- Installation in system directories (/usr/local, /opt, C:\\Program Files)
- **Result**: Uses `SecurityLevel.HIGH`

### Default Fallback
- Unknown environments default to `SecurityLevel.STANDARD`

## Integration with Protection Manager

The `AdvancedScreenProtectionManager` automatically applies the security configuration:

1. **Initialization**: Loads configuration based on specified or auto-detected security level
2. **Component Configuration**: Updates monitoring intervals and thresholds
3. **Feature Enablement**: Enables/disables features based on configuration
4. **Runtime Adjustment**: Applies settings when protection starts

## Security Considerations

### Configuration Validation
- All configurations are validated before application
- Invalid configurations are rejected with helpful error messages
- Missing required parameters fall back to secure defaults

### Tamper Resistance
- Configuration is applied at runtime, not stored in easily modified files
- Security level detection uses multiple indicators to prevent bypass
- Configuration changes require application restart

### Performance Impact
- Higher security levels have increased resource usage
- Development level optimized for minimal performance impact
- Production levels balance security and performance

## Best Practices

### Development
- Use `SecurityLevel.DEVELOPMENT` for active development
- Test with `SecurityLevel.STANDARD` before production deployment
- Consider creating custom test configurations for specific scenarios

### Production Deployment
- Use `SecurityLevel.HIGH` for most production environments
- Reserve `SecurityLevel.MAXIMUM` for highly sensitive content
- Monitor performance impact and adjust if necessary

### Configuration Management
- Document any custom configurations and their rationale
- Test configuration changes in non-production environments
- Consider security level requirements when deploying to different environments

## Troubleshooting

### Common Issues

#### Protection Too Aggressive
- **Symptom**: Frequent false alarms, content blocked inappropriately
- **Solution**: Lower security level or create custom configuration with higher thresholds

#### Protection Too Lenient  
- **Symptom**: Suspicious activity not detected
- **Solution**: Increase security level or enable additional protection features

#### Development Interference
- **Symptom**: Protection interfering with development tools
- **Solution**: Ensure `SecurityLevel.DEVELOPMENT` is being used or explicitly set it

### Debugging

Enable debug logging to troubleshoot configuration issues:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Configuration debug information will be logged
protection = AdvancedScreenProtectionManager(...)
```

## Future Enhancements

### Planned Features
- User interface for security level selection
- Runtime configuration updates without restart
- Advanced custom rule creation
- Integration with enterprise security policies
- Audit trail for configuration changes

### Extension Points
- Custom security level definitions
- Plugin system for additional security checks
- Integration with external security systems
- Centralized configuration management

---

**Note**: This configuration system is designed to be both powerful and easy to use. The auto-detection ensures appropriate security levels without user intervention, while the explicit configuration options provide flexibility for specific requirements.
