# BAR - Installation Guide

**Author**: [Rolan (RNR)](https://rolan-rnr.netlify.app/)  
**Version**: 2.0.0  
**Last Updated**: November 28, 2025

---

## 🚀 Quick Start

Want to get BAR up and running? You're in the right place! Let's get you secured.

---

## 💻 What You'll Need

### Minimum Requirements
- **OS**: Windows 10/11 (VIP treatment), Linux/macOS (works, but with fewer party tricks)
- **Python**: 3.8+ (if running from source)
- **RAM**: 4GB minimum (8GB if you want it to actually breathe)
- **Storage**: 100MB for BAR + whatever secrets you're hiding
- **Internet**: Not needed! Works 100% offline (we're old school like that)

---

## 📥 Installation Options

### Option 1: Download & Run (Easiest!)

**Perfect for most people who just want things to work:**

1. Download `BAR.exe` from releases
2. Double-click to run
3. That's it! No installer needed (we respect your disk space)

**First time running:**
- Create your master password (make it memorable but not guessable)
- BAR sets up everything automatically (we're not savages)
- Start adding files!

---

### Option 2: Run from Source

**For developers, tinkerers, and people who like to see how the sausage is made:**

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

**Don't trust pre-built files? Smart! We wouldn't either.**

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
   - Make it strong! (12+ characters, no "password123" please)
   - Mix letters, numbers, symbols like you're making a smoothie
   - You can't recover it if forgotten! (Seriously, write it down somewhere safe)
4. **Hardware Binding** (automatic, no action needed)
   - Your password works only on this device (it's commitment-based security)
5. **You're Ready!**

### Important First-Time Notes

- ⚠️ **No password recovery** - Write it down somewhere safe! (Seriously, we can't help you)
- 🔐 **Hardware-bound** - Won't work on other computers (your secrets stay on this machine)
- 💾 **One device, one password** - Keep it simple, stupid (KISS principle)
- 🚫 **No user accounts** - Just your master password (less is more)

---

## 🛠️ Troubleshooting

### Common Issues

**Can't Start BAR:**
- Check Python version: `python --version` (need 3.8+)
- Install dependencies: `pip install -r requirements.txt`
- On Windows: Install Visual C++ Redistributable

**Forgot Password:**
- No recovery possible (by design, not laziness)
- Only option: Emergency wipe and fresh start
- All data will be lost (we warned you!)

**Screenshot Protection Not Working:**
- Try running as administrator (more privileges = more power)
- Check Windows security settings
- Some antivirus might block it (they're overprotective like that)

**Files Won't Open:**
- Check password is correct
- Verify file isn't corrupted
- Check security logs in `~/.bar/logs/`

---

## 📁 Where BAR Stores Stuff

**Everything lives in one tidy place:**

- **Main folder**: `~/.bar/` (the mothership)
- **Your files**: `~/.bar/data/` (the vault)
- **Logs**: `~/.bar/logs/` (the receipts)
- **Config**: `~/.bar/config/` (the preferences)

---

## 🔧 Optional: Admin Mode

**For maximum screenshot protection (paranoia mode):**

1. Right-click `BAR.exe`
2. Select "Run as administrator"
3. This enables full keyboard hooks (the good stuff)
4. Better protection against screenshots

**Note**: Works fine without admin, just with fewer superpowers.

---

## ⚙️ System Notes

### Windows-Specific
- Full feature support (all the bells and whistles)
- Keyboard hooks for screenshot blocking
- Registry cleanup on panic wipe (scorched earth mode)
- Best overall experience

### Linux/macOS
- Basic features work (the essentials)
- Limited screenshot protection
- Some features may not work (it's complicated)
- Still secure, just fewer party tricks

---

## 💡 Tips for First-Time Users

**Learn before you burn:**

1. **Test First**: Try it with non-important files (don't be a hero)
2. **Learn Features**: Explore without critical data (training wheels are good)
3. **Understand Security Levels**: Start with Standard (work your way up)
4. **Keep Backups**: Important stuff should have copies (redundancy is wisdom)
5. **Read Docs**: Check `docs/` folder for guides (knowledge is power)

---

## 🆘 Need Help?

**Check the docs:**
- `README.md` - Main overview
- `DISCLAIMER.md` - Important warnings
- `docs/SECURITY_FEATURES.md` - Security guide
- `docs/` - More detailed guides

**Common fixes (the IT crowd special):**
- Restart BAR (have you tried turning it off and on again?)
- Check logs in `~/.bar/logs/` (the truth is in there)
- Reinstall dependencies (when in doubt, reinstall)
- Run as administrator (ask nicely for more privileges)
- Check antivirus isn't blocking it (sometimes the bodyguard is too eager)

---

## 🎉 You're Ready!

That's it! BAR is installed and ready to keep your files secure. Welcome to the club.

**Remember the golden rules:**
- Use a strong password (not your cat's name)
- No password recovery exists (we're not kidding)
- Test with non-critical files first (be smart)
- Keep backups of important stuff (two is one, one is none)

**Stay secure!** 🔥

---

*BAR - Because some things are meant to be temporary. Burn responsibly.*
