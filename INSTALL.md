# BAR - Installation Guide

**Author**: [Rolan (RNR)](https://rolan-rnr.netlify.app/)  
**Version**: 2.0.0  
**Last Updated**: October 17, 2025

---

## 🚀 Quick Start

Want to get BAR up and running? Here's how!

---

## 💻 What You'll Need

### Minimum Requirements
- **OS**: Windows 10/11 (best support), Limited Linux/macOS
- **Python**: 3.8+ (if running from source)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 100MB for BAR + your files
- **Internet**: Not needed! Works 100% offline

---

## 📥 Installation Options

### Option 1: Download & Run (Easiest!)

**Perfect for most people:**

1. Download `BAR.exe` from releases
2. Double-click to run
3. That's it! No installer needed

**First time running:**
- Create your master password
- BAR sets up everything automatically
- Start adding files!

---

### Option 2: Run from Source

**For developers and tinkerers:**

```bash
# 1. Clone or download the code
git clone <repository-url>
cd BAR

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run BAR
python main.py

# 4. Debug mode (optional)
python main.py --debug
```

**What gets installed:**
- PySide6 (GUI framework)
- Cryptography libraries
- All other dependencies

---

### Option 3: Build Your Own

**Don't trust pre-built files? Smart!**

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Build it
python build.py

# 3. Find your .exe
cd dist
# Your BAR.exe is here!

# Single-file version (optional)
python build.py --onefile
```

---

## 🔐 First-Time Setup

### Device Initialization

When you first run BAR:

1. **Welcome Screen** appears
2. **Click "Initialize Device"**
3. **Create Master Password**
   - Make it strong! (12+ characters)
   - Mix letters, numbers, symbols
   - You can't recover it if forgotten!
4. **Hardware Binding** (automatic)
   - Your password works only on this device
5. **You're Ready!**

### Important First-Time Notes

- ⚠️ **No password recovery** - Write it down somewhere safe!
- 🔐 **Hardware-bound** - Won't work on other computers
- 💾 **One device, one password** - Keep it simple
- 🚫 **No user accounts** - Just your master password

---

## 🛠️ Troubleshooting

### Common Issues

**Can't Start BAR:**
- Check Python version: `python --version` (need 3.8+)
- Install dependencies: `pip install -r requirements.txt`
- On Windows: Install Visual C++ Redistributable

**Forgot Password:**
- No recovery possible (by design)
- Only option: Emergency wipe and fresh start
- All data will be lost

**Screenshot Protection Not Working:**
- Try running as administrator
- Check Windows security settings
- Some antivirus might block it

**Files Won't Open:**
- Check password is correct
- Verify file isn't corrupted
- Check security logs in `~/.bar/logs/`

---

## 📁 Where BAR Stores Stuff

- **Main folder**: `~/.bar/`
- **Your files**: `~/.bar/data/`
- **Logs**: `~/.bar/logs/`
- **Config**: `~/.bar/config/`

---

## 🔧 Optional: Admin Mode

For best screenshot protection:

1. Right-click `BAR.exe`
2. Select "Run as administrator"
3. This enables full keyboard hooks
4. Better protection against screenshots

**Note**: Works fine without admin, just with fewer features.

---

## ⚙️ System Notes

### Windows-Specific
- Full feature support
- Keyboard hooks for screenshot blocking
- Registry cleanup on panic wipe
- Best overall experience

### Linux/macOS
- Basic features work
- Limited screenshot protection
- Some features may not work
- Still secure, just fewer extras

---

## 💡 Tips for First-Time Users

1. **Test First**: Try it with non-important files
2. **Learn Features**: Explore without critical data
3. **Understand Security Levels**: Start with Standard
4. **Keep Backups**: Important stuff should have copies
5. **Read Docs**: Check `docs/` folder for guides

---

## 🆘 Need Help?

**Check the docs:**
- `README.md` - Main overview
- `DISCLAIMER.md` - Important warnings
- `docs/SECURITY_FEATURES.md` - Security guide
- `docs/` - More detailed guides

**Common fixes:**
- Restart BAR
- Check logs in `~/.bar/logs/`
- Reinstall dependencies
- Run as administrator
- Check antivirus isn't blocking it

---

## 🎉 You're Ready!

That's it! BAR is installed and ready to keep your files secure.

**Remember:**
- Use a strong password
- No password recovery exists
- Test with non-critical files first
- Keep backups of important stuff

**Stay secure!** 🔥

---

*BAR - Because some things are meant to be temporary.*
