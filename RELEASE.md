![BAR_logo](https://github.com/user-attachments/assets/2424e744-755d-4de2-9ce1-4362f7729521)

# BAR v2.0.0 - Release Notes

**Author**: [Rolan (RNR)](https://rolan-rnr.netlify.app/)  
**Release Date**: October 17, 2025  
**Status**: Stable Release

---

## 🔥 What's New in v2.0.0

This is a major release that makes BAR simpler, faster, and more secure!

---

## ✨ Key Features

### 🛡️ Security
- **100% Offline** - No internet needed, ever
- **Military-Grade Encryption** - AES-256-GCM
- **Device-Bound Authentication** - One device, one password
- **Screenshot Protection** - Advanced anti-capture system
- **Self-Destruct** - Files that really disappear

### 🔥 Self-Destruction
- **Time Bombs** - Delete after X hours/days
- **Read Limits** - Delete after X views
- **Deadman Switch** - Delete if you don't check in
- **Anti-Brute Force** - Delete after wrong passwords
- **Panic Wipe** - Nuclear option (98%+ destruction)

### 📸 Screenshot Protection
- Blocks Print Screen, Win+Shift+S, Alt+Print Screen
- Monitors and clears clipboard automatically
- Detects and terminates screenshot apps
- Tracks suspicious behavior
- Multi-layer defense system

### 📁 File Management
- Fast multi-threaded scanning
- Secure file sharing
- View-only mode
- DoD-compliant deletion
- Comprehensive logging

---

## 🚀 Installation

### Option 1: Ready to Run
1. Download BAR.exe
2. Double-click and go
3. No installation needed!

### Option 2: From Source
```bash
pip install -r requirements.txt
python main.py
```

### Option 3: Build It Yourself
```bash
pip install -r requirements.txt
python build.py
# Find BAR.exe in dist/
```

---

## 📋 System Requirements

- **OS**: Windows 10/11 (best), Limited Linux/macOS
- **RAM**: 4GB min, 8GB recommended
- **Storage**: 100MB + your files
- **Internet**: Not required!

---

## 🎯 What's Different from Before

### Simpler Authentication
- **Before**: Device Setup → Unlock → Login → App
- **Now**: Device Setup → Unlock → App ✅

### Better Security
- Enhanced screenshot protection
- Panic wipe system (3 levels)
- Improved hardware binding
- Better encryption

### Cleaner Code
- Removed 500+ lines of old code
- Fixed bugs and issues
- Better performance
- More stable

---

## ⚠️ Important Warnings

### Data Loss is Permanent
- Once deleted, files are **GONE FOREVER**
- No undo, no recovery
- DoD-compliant overwrite = unrecoverable

### No Password Recovery
- Forget your password = lose everything
- Hardware-bound to your device
- Choose wisely!

### Screenshot Protection Limits
- ✅ Blocks software screenshots
- ❌ Can't block phone cameras
- ❌ Can't block external capture devices
- ❌ Some admin tools may bypass

---

## 🎯 Use Cases

Perfect for:
- Sensitive document sharing
- Temporary credential storage
- Compliance with data retention
- Personal privacy protection
- Secure communication
- Corporate IP protection
- Healthcare information
- Financial documents

---

## 💡 Best Practices

### Do:
- ✅ Use strong passwords (12+ characters)
- ✅ Match security to importance
- ✅ Keep backups of important data
- ✅ Test with non-critical files first
- ✅ Read the documentation

### Don't:
- ❌ Forget your password
- ❌ Use Maximum security casually
- ❌ Skip the backups
- ❌ Use for illegal purposes
- ❌ Ignore the warnings

---

## 🔧 Technical Details

**Core Technologies:**
- Python 3.8+
- PySide6 for GUI
- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation
- DoD 5220.22-M deletion

**Enhanced Features:**
- Windows API integration
- Real-time keyboard hooks
- Clipboard monitoring
- Process detection
- Statistical analysis
- Hardware fingerprinting

**Performance:**
- Multi-threaded scanning
- Optimized encryption
- Low memory footprint
- Minimal CPU impact

---

## 📈 What Got Better

### v2.0.0 Improvements:
- ✅ Streamlined authentication
- ✅ Enhanced screenshot protection
- ✅ Panic wipe system added
- ✅ Better hardware binding
- ✅ Fixed security bugs
- ✅ Cleaner codebase
- ✅ Better performance
- ✅ More stable

---

## 🐛 Known Issues

### Limitations:
- Windows 10/11 works best
- Limited Linux/macOS support
- Can't block phone cameras
- Some admin tools may bypass protection
- Performance impact on old hardware

### Workarounds:
- Use in controlled environments
- Run as administrator for best protection
- Keep software updated
- Read the documentation

---

## 📞 Need Help?

- **Docs**: Check `docs/` folder
- **README**: Main overview
- **INSTALL**: Setup guide
- **DISCLAIMER**: Important warnings

---

## 📄 License

BAR is GPL-3.0 licensed:
- Free and open source
- Modify and share freely
- Keep it open source
- No warranties

See [LICENSE](LICENSE) for details.

---

## 👨‍💻 Who Made This?

I'm **[Rolan (RNR)](https://rolan-rnr.netlify.app/)**, and I built BAR because I wanted better tools for secure, temporary file handling. I'm passionate about cybersecurity and privacy, and I wanted to make something that's both seriously secure and actually usable.

Feel free to reach out with questions, feedback, or just to say hi!

---

<div align="center">

**BAR v2.0.0 - Because some things are meant to be temporary.**

*Stay safe out there.* 🔥

</div>

---

*Remember: Once a file is destroyed by BAR, it cannot be recovered. Use responsibly.*
