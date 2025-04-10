# BAR - Burn After Reading: Wiki

Welcome to the BAR (Burn After Reading) wiki. This document provides comprehensive information about the BAR secure file management system, including its architecture, security features, implementation details, and usage guidelines.

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [File Management](#file-management)
- [User Interface](#user-interface)
- [Installation and Setup](#installation-and-setup)
- [Usage Guide](#usage-guide)
- [Technical Implementation](#technical-implementation)
- [Development Guidelines](#development-guidelines)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

## Project Overview

BAR is a standalone desktop application designed for secure file management with self-destruction capabilities. It operates entirely offline, ensuring that sensitive data never leaves the user's machine. The application provides strong encryption, multiple self-destruction mechanisms, and advanced file scanning capabilities.

### Core Principles

1. **Security First**: All design decisions prioritize data security
2. **Offline Operation**: No internet connection or server dependencies required
3. **Self-Destruction**: Files can be configured to automatically delete under specific conditions
4. **User Control**: Full control over security parameters for each file
5. **Simplicity**: Intuitive interface despite complex security features

## Architecture

BAR follows a modular architecture with clear separation of concerns:

### Component Structure

```
src/
├── config/           # Configuration management
├── crypto/           # Encryption and key management
├── file_manager/     # File operations and scanning
├── gui/              # User interface components
├── security/         # Security features and audit logging
└── user_manager/     # User authentication and session management
```

### Core Components

1. **Encryption Manager**: Handles all cryptographic operations using AES-256 in GCM mode
2. **File Manager**: Manages file operations, metadata, and self-destruction mechanisms
3. **File Scanner**: Detects and validates .bar files across connected devices
4. **User Manager**: Handles user registration, authentication, and session management
5. **Security Manager**: Implements secure deletion and audit logging
6. **Configuration Manager**: Manages application settings and user preferences
7. **GUI Components**: Provides the user interface for all operations

## Security Features

### Encryption Implementation

BAR uses industry-standard encryption algorithms and techniques:

- **AES-256 in GCM mode**: Provides authenticated encryption with associated data (AEAD)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Unique Keys**: Each file has its own encryption key
- **Secure Random Generation**: Cryptographically secure random number generation for all keys, salts, and nonces
- **Memory Protection**: Sensitive data is cleared from memory when no longer needed

### Self-Destruction Mechanisms

BAR implements multiple self-destruction mechanisms that can be configured per file:

#### Time-Based Expiration

Files are automatically deleted after a specified time period. The implementation uses:

- Secure timestamp storage with the encrypted file
- Regular validation of expiration during file access
- Background monitoring for expired files

#### Access Count Limits

Files are deleted after being accessed a specified number of times:

- Secure counter that cannot be tampered with
- Counter incrementation on successful decryption
- Automatic deletion when the limit is reached

#### Deadman Switch

Files are deleted if not accessed within a specified period:

- Last access timestamp stored securely with the file
- Regular validation of inactivity period
- Automatic deletion when the inactivity threshold is exceeded

### Secure Deletion

BAR ensures that deleted files cannot be recovered using forensic tools:

- Multiple overwrite passes with different patterns
- File size randomization before deletion
- Metadata wiping
- Directory entry removal

### Two-Factor Authentication

BAR supports optional two-factor authentication for additional security:

- Time-based One-Time Password (TOTP) implementation
- Compatible with standard authenticator apps
- Backup recovery codes

## File Management

### .bar File Format

BAR uses a custom file format with the following structure:

```
[Signature][Version][Metadata][Encrypted Content][Authentication Tag]
```

- **Signature**: Identifies the file as a valid .bar file
- **Version**: Ensures compatibility with different BAR versions
- **Metadata**: Contains encrypted security parameters and file information
- **Encrypted Content**: The actual file content encrypted with AES-256-GCM
- **Authentication Tag**: Ensures the file has not been tampered with

### File Scanning

The file scanning engine can detect and validate .bar files across all connected devices:

- Multi-threaded scanning for performance
- Support for all Windows drive types (Fixed, Removable, Network)
- File signature validation
- Version compatibility checking
- Metadata integrity verification

## User Interface

BAR provides an intuitive user interface built with PyQt5:

### Main Window

The main window displays:

- List of available .bar files with security status
- File operations toolbar
- Security status indicators
- Device scanning controls

### Dialogs

- **Login Dialog**: User authentication
- **Register Dialog**: New user registration
- **File Dialog**: Create and configure new .bar files
- **Settings Dialog**: Application configuration
- **Two-Factor Dialog**: 2FA setup and verification

## Installation and Setup

### Prerequisites

- Windows operating system
- Python 3.8 or higher (for running from source)
- 50MB of disk space

### Installation Options

#### Option 1: Running the Executable

1. Download the latest release of BAR.exe
2. No installation required - simply double-click the executable to run

#### Option 2: Running from Source

1. Ensure you have Python 3.8 or higher installed
2. Clone or download the repository
3. Install dependencies: `pip install -r requirements.txt`
4. Run the application: `python main.py`

#### Option 3: Building Your Own Executable

1. Install dependencies: `pip install -r requirements.txt`
2. Run the build script: `python build.py`
3. Find the executable in the `dist` directory

### First-Time Setup

1. Launch the application
2. Click "Register" to create a new user account
3. Enter a username and strong password
4. Optionally set up two-factor authentication
5. Configure default security settings

## Usage Guide

### Creating Secure Files

1. Click the "New File" button in the main window
2. Select the file you want to secure
3. Configure security parameters:
   - Expiration time (if any)
   - Access count limit (if any)
   - Deadman switch period (if any)
4. Click "Create" to encrypt and secure the file

### Accessing Secure Files

1. Select the file from the main window
2. Click "Open" or double-click the file
3. Enter your password when prompted
4. The file will be decrypted and opened with the default application
5. The file will be securely deleted when the security conditions are met

### Sharing Secure Files

1. Select the file from the main window
2. Click "Export"
3. Choose a destination for the exported .bar file
4. Share the file and the password separately using secure channels

### Importing Shared Files

1. Click "Import" in the main window
2. Select the .bar file you received
3. Enter the password when prompted
4. The file will be added to your secure storage

### Scanning for .bar Files

1. Click "Scan Devices" in the main window
2. Select the drives you want to scan
3. Click "Start Scan"
4. Found .bar files will be displayed with their security status

## Technical Implementation

### Encryption Process

1. Generate a random salt (32 bytes)
2. Derive encryption key using PBKDF2 with the user's password and salt
3. Generate a random nonce (12 bytes) for AES-GCM
4. Encrypt the file content using AES-256-GCM
5. Encrypt the file metadata using the same key
6. Combine the encrypted components into the .bar file format

### Decryption Process

1. Extract the salt and nonce from the .bar file
2. Derive the encryption key using PBKDF2 with the user's password and salt
3. Decrypt the metadata using AES-256-GCM
4. Verify the security conditions (expiration, access count, deadman switch)
5. If conditions are met, decrypt the file content
6. Update the security metadata (access count, last access time)
7. Check if self-destruction conditions are triggered

### Self-Destruction Implementation

1. Time-based expiration:
   - Store creation timestamp and expiration period in metadata
   - Check current time against expiration time during access
   - Trigger secure deletion if expired

2. Access count limit:
   - Store maximum access count and current count in metadata
   - Increment count on each access
   - Trigger secure deletion when count reaches limit

3. Deadman switch:
   - Store last access timestamp and inactivity period in metadata
   - Check current time against last access time plus inactivity period
   - Trigger secure deletion if inactive for too long

### Secure Deletion Implementation

1. Open the file for binary writing
2. Perform multiple overwrite passes:
   - First pass: All zeros
   - Second pass: All ones
   - Third pass: Random data
3. Truncate the file to a random size
4. Close and delete the file
5. Remove directory entries

## Development Guidelines

### Code Structure

The BAR codebase follows these principles:

- **Modularity**: Each component has a single responsibility
- **Encapsulation**: Implementation details are hidden behind clear interfaces
- **Error Handling**: Comprehensive error handling and logging
- **Documentation**: All classes and methods are documented

### Adding New Features

When adding new features to BAR:

1. Ensure the feature aligns with the core principles
2. Design with security as the primary consideration
3. Implement comprehensive tests
4. Document the feature thoroughly
5. Update the user interface as needed

### Security Considerations

When modifying the codebase:

1. Never compromise on security for convenience
2. Use secure coding practices
3. Avoid storing sensitive data in memory longer than necessary
4. Ensure all cryptographic operations use secure parameters
5. Validate all user inputs

## Troubleshooting

### Common Issues

#### Application Won't Start

- Ensure Python 3.8+ is installed (if running from source)
- Verify all dependencies are installed
- Check the logs in `~/.bar/logs`

#### Can't Access Files

- Verify you're using the correct password
- Check if the file has expired or reached its access limit
- Ensure the file hasn't been corrupted

#### Scanning Issues

- Ensure you have permission to access the selected drives
- Try scanning with administrator privileges
- Check for antivirus interference

### Log Files

BAR maintains detailed logs in the `~/.bar/logs` directory:

- `application.log`: General application logs
- `security.log`: Security-related events
- `error.log`: Error messages and exceptions

## FAQ

### General Questions

**Q: Is BAR completely offline?**  
A: Yes, BAR operates entirely offline with no server dependencies or internet connection requirements.

**Q: What happens if I forget my password?**  
A: There is no password recovery mechanism. If you forget your password, your encrypted files cannot be recovered.

**Q: Can I recover a file after it self-destructs?**  
A: No, self-destructed files are securely deleted and cannot be recovered, even with forensic tools.

### Security Questions

**Q: How secure is the encryption?**  
A: BAR uses AES-256 in GCM mode, which is a military-grade encryption algorithm. The key derivation uses PBKDF2 with 100,000 iterations.

**Q: Can someone bypass the self-destruction mechanisms?**  
A: The self-destruction mechanisms are implemented securely and cannot be bypassed without the correct password.

**Q: Is two-factor authentication necessary?**  
A: Two-factor authentication adds an extra layer of security and is recommended but not required.

### Technical Questions

**Q: Can I use BAR on macOS or Linux?**  
A: Currently, BAR is only available for Windows. Support for other platforms may be added in the future.

**Q: How does the file scanning work?**  
A: The file scanner uses multi-threaded operations to search for files with the .bar extension and validates them by checking their signature and structure.

**Q: Can I integrate BAR with other applications?**  
A: BAR is designed as a standalone application, but the codebase is modular and could be adapted for integration with other systems.