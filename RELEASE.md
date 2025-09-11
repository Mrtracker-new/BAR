![BAR_logo](https://github.com/user-attachments/assets/2424e744-755d-4de2-9ce1-4362f7729521)
# BAR - Burn After Reading v2.0.0+

**Author**: Rolan (RNR)  
**Release Date**: January 2025  
**Status**: Enhanced Security Release

## 🔥 Secure File Management with Advanced Anti-Capture Protection 🔥

### 🚀 Release Highlights

We're excited to announce the enhanced release of BAR (Burn After Reading) - a standalone desktop application featuring revolutionary screenshot protection, streamlined authentication, and military-grade security for sensitive file management.

### What is BAR?

BAR is a completely offline file management system designed for users who need the highest level of security and privacy. It allows you to store sensitive files with customizable security parameters including time-based expiration, access count limits, and deadman switch functionality.

### ✨ Key Features

**🛡️ Enhanced Security Architecture**
- **100% Offline Security**: Works without internet connection or server dependencies
- **Military-Grade Encryption**: AES-256-GCM authenticated encryption protects all content
- **Device-Bound Authentication**: Single-user device authentication with hardware binding
- **Advanced Screenshot Protection**: Revolutionary multi-layer anti-capture system

**🔥 Self-Destruction Mechanisms**
- **Time-based Expiration**: Files delete after specified time periods
- **Access Count Limits**: Files delete after being viewed a set number of times
- **Deadman Switch**: Files delete after periods of inactivity
- **Anti-Brute Force**: Files delete after multiple failed password attempts
- **DoD-Compliant Deletion**: Multi-pass overwrite for unrecoverable destruction

**📸 Revolutionary Screenshot Protection**
- **Real-time Keyboard Blocking**: Intercepts Print Screen, Win+Shift+S, Alt+Print Screen
- **Clipboard Monitoring**: Detects and clears screenshot images immediately
- **Process Detection**: Monitors and terminates screenshot applications automatically
- **Statistical Analysis**: Tracks suspicious behavior with automatic breach response
- **Focus Change Monitoring**: Detects window switching and Alt+Tab attempts
- **Multi-layer Defense**: Combines multiple protection methods for comprehensive coverage

**📁 Advanced File Management**
- **Multi-threaded Scanning**: Fast detection of .bar files across all connected devices
- **Secure File Sharing**: Export/import encrypted files with security constraints intact
- **View-Only Protection**: Enhanced security for files with export restrictions
- **Comprehensive Logging**: Detailed audit trails for all security events

### 🔧 Technical Specifications

**Core Technologies:**
- Built with Python 3.8+ and PyQt5 for cross-platform compatibility
- Packaged as standalone Windows executable with no dependencies
- AES-256-GCM mode for authenticated encryption with integrity verification
- PBKDF2-HMAC-SHA256 key derivation with configurable iterations

**Enhanced Security Implementation:**
- Low-level Windows API integration for system-level hooks
- Real-time keyboard hook interception using SetWindowsHookEx
- Clipboard monitoring with image detection capabilities
- Process enumeration and termination for screenshot applications
- Hardware fingerprinting for device-bound authentication
- Statistical behavior analysis with threat scoring

**Performance Features:**
- Multi-threaded scanning engine for improved performance
- Support for all Windows drive types (Fixed, Removable, Network)
- Memory-efficient handling of large files
- Optimized encryption/decryption pipeline
- Background monitoring with minimal system impact

### Installation

#### Option 1: Running the Executable
1. Download BAR.exe from the release page
2. No installation required - simply double-click to run

#### Option 2: Building from Source
1. Ensure Python 3.8+ is installed
2. Clone the repository
3. Install dependencies: pip install -r requirements.txt
4. Run the build script: python build.py
5. Find the executable in the dist directory

### 🚀 First-Time Setup (v2.0.0+)

**Device Initialization:**
1. **Launch Application**: Run BAR.exe (no installation required)
2. **Initialize Device**: Click "Initialize Device" on first startup
3. **Set Master Password**: Create strong master password for device unlock
4. **Hardware Binding**: Password automatically bound to current device
5. **Start Securing**: Begin adding files with custom security settings

**Simplified Authentication:**
- **No User Accounts**: Single device authentication replaces user system
- **One Password**: Master password unlocks all secure storage
- **Session Persistence**: Stays unlocked during application session
- **Device Portability**: Files remain locked to initialization device

### 🔒 Security Notice

**Critical Security Information:**
- **Unrecoverable Deletion**: Files that self-destruct CANNOT be recovered by any means
- **No Password Recovery**: Master password cannot be recovered - choose wisely
- **Hardware Binding**: Password only works on device where it was created
- **Complete Privacy**: All operations local - no data transmitted externally

**Screenshot Protection Limitations:**
- **Mobile Cameras**: Cannot block physical phone/camera screenshots
- **External Capture**: Hardware capture devices may bypass protection
- **Administrator Tools**: Some elevated screenshot tools may bypass protection
- **Windows Only**: Full protection features require Windows 10/11

**Recommended Security Practices:**
- **Run as Administrator**: For maximum screenshot protection effectiveness
- **Secure Environment**: Use in controlled physical environment
- **Strong Passwords**: Use complex master password with mixed characters
- **Regular Backups**: Backup non-sensitive data before applying security constraints

### Use Cases

- Secure sharing of confidential documents
- Temporary storage of sensitive credentials
- Compliance with data retention policies
- Protection of intellectual property
- Secure communication with built-in destruction capabilities

### System Requirements

- Windows 10/11 (64-bit)
- 100MB free disk space
- 4GB RAM recommended

### 📈 Latest Updates

#### Version 2.0.0+ (Current - January 2025)

**🛡️ Enhanced Security Architecture:**
- Revolutionary screenshot protection with real-time blocking
- Integrated Windows keyboard hook system for hotkey interception
- Advanced clipboard monitoring with image detection
- Process monitoring and automatic termination of screenshot apps
- Statistical behavior analysis with automatic breach response

**🔧 System Improvements:**
- Streamlined single-user device authentication
- Enhanced hardware binding for device-specific security
- Consolidated protection modules for better performance
- Improved error handling and user feedback
- Comprehensive security event logging

**📋 Project Organization:**
- Cleaned up redundant test files and development artifacts
- Reorganized documentation in proper docs/ structure
- Enhanced .gitignore for better security protection
- Professional project structure ready for production deployment

**🔍 Technical Enhancements:**
- Fixed keyboard hook integration for reliable screenshot blocking
- Enhanced clipboard monitoring frequency (50ms) for faster detection
- Added KBDLLHOOKSTRUCT definition for stable Windows operations
- Improved memory management and resource cleanup
- Better compatibility with Windows security features

---

*Remember*: Once a file is destroyed by BAR, it cannot be recovered. Use responsibly.