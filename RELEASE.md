![BAR_logo](https://github.com/user-attachments/assets/2424e744-755d-4de2-9ce1-4362f7729521)
# BAR - Burn After Reading v1.0.0

## 🔥 Secure File Management with Self-Destruction Capabilities 🔥

### Release Highlights

We're excited to announce the release of BAR (Burn After Reading) - a standalone desktop application that provides secure file management with advanced security features and self-destruction capabilities.

### What is BAR?

BAR is a completely offline file management system designed for users who need the highest level of security and privacy. It allows you to store sensitive files with customizable security parameters including time-based expiration, access count limits, and deadman switch functionality.

### Key Features

- *100% Offline Security*: Works without internet connection or server dependencies
- *Military-Grade Encryption*: AES-256 encryption protects all file content
- *Multiple Self-Destruction Options*:
  - Time-based expiration (files delete after a specified time)
  - Access count limits (files delete after being viewed a set number of times)
  - Deadman switch (files delete after period of inactivity)
- *Advanced File Scanning*: Detect and validate .bar files across all connected devices
- *Secure File Sharing*: Export/import encrypted files while maintaining security constraints
- *User-Friendly Interface*: Clean, intuitive UI showing file security status
- *Screenshot Prevention*: Blocks all Windows screenshot methods (Print Screen, Win+Shift+S, etc.)
- *Screen Capture Protection*: Uses transparent overlays to prevent screen recording

### Technical Specifications

- Built with Python 3.8+ and PyQt5
- Packaged as a standalone Windows executable
- AES-256 in GCM mode for authenticated encryption
- PBKDF2-HMAC-SHA256 for key derivation
- Multi-threaded scanning engine for improved performance
- Support for all Windows drive types (Fixed, Removable, Network)
- Low-level Windows API integration for security features
- Hardware ID binding for enhanced security

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

### First-Time Setup

1. Create a local user account with a strong password
2. Log in to access your secure file storage
3. Start adding files with custom security settings

### Security Notice

- BAR uses strong encryption and secure deletion techniques
- Files that self-destruct CANNOT be recovered
- Your password is used for encryption - if forgotten, data CANNOT be recovered
- All operations run locally on your machine - no data is sent to external servers

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

### Latest Updates

#### Version 1.0.0 (Current)
- Initial public release
- Enhanced screenshot prevention system
- Two-factor authentication support
- Hardware ID binding capability
- Comprehensive audit logging

---

*Remember*: Once a file is destroyed by BAR, it cannot be recovered. Use responsibly.