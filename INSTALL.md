# BAR - Burn After Reading: Installation Guide

**Author**: Rolan (RNR)  
**Version**: 2.0.0+  
**Last Updated**: January 2025

This document provides comprehensive instructions for installing and running the BAR secure file management application with enhanced screenshot protection and advanced security features.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11 (primary support), limited Linux/macOS support
- **Python**: 3.8 or higher (for source installation)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 100MB for application + space for secure files
- **Internet**: Not required for operation (fully offline)

### Additional Windows Requirements
- **Administrator privileges** may be required for enhanced screenshot protection features
- **Windows API access** for keyboard hook and clipboard monitoring
- **Hardware binding** capabilities for device-specific authentication

## Installation

### Option 1: Running from Source

1. Clone or download this repository

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python main.py
   ```

### Option 2: Building a Standalone Executable

1. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the build script:
   ```
   python build.py
   ```

3. The executable will be created in the `dist` directory

4. Run the executable by double-clicking `BAR.exe`

## First-Time Setup

### Device Initialization (v2.0.0+)

1. **Single-User Authentication**: BAR v2.0.0+ uses device-bound authentication
2. **First Launch**: Run the application and click "Initialize Device"
3. **Master Password**: Create a strong master password for device unlock
4. **Hardware Binding**: Your password will be bound to this specific device
5. **No User Accounts**: No separate user registration needed - one device, one master password

### Authentication Flow
1. **Device Unlock**: Enter your master password to unlock secure storage
2. **Direct Access**: After unlock, access all features without additional authentication
3. **Session Management**: Application remembers unlock status during session

## Security Considerations

### Core Security
- **Local Storage**: All data stored in `~/.bar` directory with strong encryption
- **AES-256-GCM**: Military-grade authenticated encryption for all sensitive data
- **Hardware Binding**: Device-specific encryption prevents unauthorized access
- **No Recovery**: If you forget your master password, data cannot be recovered
- **Self-Destruction**: Files with security constraints will be permanently deleted

### Enhanced Screenshot Protection (Windows)
- **Keyboard Hooks**: Real-time blocking of Print Screen, Win+Shift+S, Alt+Print Screen
- **Clipboard Monitoring**: Automatic detection and clearing of screenshot images
- **Process Detection**: Monitors and terminates screenshot applications
- **Statistical Analysis**: Tracks suspicious behavior and automatically responds to threats
- **Administrator Privileges**: May be required for full protection effectiveness

### View-Only File Protection
- **Multi-layer Defense**: Combines multiple anti-capture techniques
- **Real-time Monitoring**: Continuous surveillance for screenshot attempts
- **Event Logging**: Comprehensive logging of all security events
- **Breach Response**: Automatic file closure on detection of security violations

## Troubleshooting

### Common Issues

**Application Startup:**
- Verify all dependencies are installed: `pip install -r requirements.txt`
- Check Python version: `python --version` (requires 3.8+)
- On Windows, ensure Visual C++ Redistributable is installed

**Authentication Issues:**
- **Device Not Initialized**: Click "Initialize Device" on first run
- **Forgotten Master Password**: No recovery possible - data will be permanently inaccessible
- **Hardware Binding**: Password only works on the device where it was created

**Screenshot Protection Issues:**
- **Keyboard Hook Error 126**: Run as administrator or check Windows permissions
- **Protection Not Active**: Verify Windows security features are enabled
- **Process Detection**: Check if antivirus software is blocking system access

**File Access Problems:**
- **Decryption Failures**: Verify correct password and file integrity
- **Self-Destruct Triggered**: Check security logs for constraint violations
- **View-Only Restrictions**: Enhanced protection prevents certain file operations

### Log Files and Debugging
- **Application Logs**: `~/.bar/logs/` directory
- **Security Events**: `~/.bar/security_logs/` directory (if protection active)
- **Debug Mode**: Run with `python main.py --debug` for detailed output
- **System Events**: Check Windows Event Viewer for system-level issues

### Performance Optimization
- **Memory Usage**: Close other applications for better performance
- **File Scanning**: Limit scan scope to necessary drives only
- **Protection Overhead**: Disable unnecessary security features in development
- **Hardware Resources**: Ensure adequate RAM and CPU for encryption operations

### Getting Help
- **Documentation**: Check the `docs/` directory for detailed guides
- **Error Messages**: Note exact error text for troubleshooting
- **System Information**: Note OS version, Python version, and hardware details
- **Log Files**: Include relevant log entries when seeking assistance
