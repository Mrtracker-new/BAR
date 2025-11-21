![BAR_logo](https://github.com/user-attachments/assets/2424e744-755d-4de2-9ce1-4362f7729521)

# BAR v2.0.0 - The "Finally Fixed Everything" Release

**Author**: [Rolan (RNR)](https://rolan-rnr.netlify.app/)  
**Release Date**: October 17, 2025  
**Status**: Stable (and actually stable this time!)

---

## 🔥 What's New in v2.0.0

Alright folks, this is the big one! v2.0.0 is a MASSIVE upgrade that makes BAR simpler, faster, and way more secure. I basically ripped out 500+ lines of old code that was making things complicated and replaced it with stuff that actually makes sense.

---

## ✨ The Cool Stuff You'll Actually Use

### 🛡️ Security (The Peace-of-Mind Features)
- **100% Offline** - Literally zero internet required. Your files stay on YOUR machine
- **Military-Grade Encryption** - AES-256-GCM (same tech the CIA probably uses)
- **Device-Bound Authentication** - One device, one password. Simple as that
- **Screenshot Protection** - Advanced system to stop people screenshotting your secrets
- **Self-Destruct** - Files that actually VANISH when they're supposed to

### 🔥 Self-Destruction Options (The Fun Part)
- **Time Bombs** - "Delete this in 24 hours" — Snapchat vibes for any file
- **Read Limits** - "Self-destruct after 3 views" — James Bond would be jealous
- **Deadman Switch** - Don't check in for a week? Files auto-delete (great for... reasons)
- **Anti-Brute Force** - Too many wrong passwords = file goes BOOM 💥
- **Panic Wipe** - Nuclear option for emergencies (98%+ destruction in seconds)

### 📸 Screenshot Protection (The "Stop Snooping" System)
- Blocks Print Screen, Win+Shift+S, Alt+Print Screen, and more
- Automatically monitors and clears your clipboard
- Detects screenshot apps and shuts them down
- Tracks suspicious behavior patterns
- Multi-layer defense (though phone cameras still work, can't fix physics)

### 📁 File Management (The Practical Stuff)
- Fast multi-threaded scanning (finds your .bar files QUICK)
- Secure file sharing without actually sharing the file
- View-only mode (show but don't share)
- DoD-compliant deletion (government-grade file destruction)
- Comprehensive logging (so you can see what happened)

---

## 🚀 Installation (Super Easy)

### Option 1: The "I Just Want It To Work" Method
1. Download BAR.exe from releases
2. Double-click it
3. There is no step 3 🎉

### Option 2: The "I Like Python" Method
```bash
pip install -r requirements.txt
python main.py
```

### Option 3: The "I Don't Trust Your EXE" Method
```bash
pip install -r requirements.txt
python build.py
# Your freshly-built BAR.exe will be chilling in dist/
```

---

## 📋 What You'll Need

- **OS**: Windows 10/11 (works like a charm), Linux/macOS (limited features, sorry)
- **RAM**: 4GB minimum (but c'mon, it's 2025, get 8GB)
- **Storage**: ~100MB for BAR + whatever files you're hiding
- **Internet**: Nope! 100% offline baby 👍

---

## 🎯 What Changed (aka Why v2.0 is Way Better)

### Authentication Got WAY Simpler
- **Old way**: Device Setup → Unlock → Login → Finally the App (ugh)
- **New way**: Device Setup → Unlock → App ✅
- Translation: One less annoying screen to deal with!

### Security Got an Upgrade
- Screenshot protection actually works better now
- Added panic wipe system with 3 destruction levels (mild, spicy, nuclear)
- Hardware binding is more secure and reliable
- Encryption improvements under the hood

### Code Got a Serious Makeover
- Deleted 500+ lines of overcomplicated nonsense
- Squashed bugs like they owed me money
- Performance improvements (it's snappier, trust me)
- Way more stable (fewer "why did it crash" moments)

---

## ⚠️ Serious Talk Time (Actually Read This)

### When BAR Deletes Something, It's REALLY Gone
- Like, **CIA-level gone**. No "Oops" button, no recovery software, nada
- DoD-compliant overwrite = even forensics experts can't save you
- Translation: **BACKUP ANYTHING IMPORTANT** before putting it in BAR

### No Password Recovery (I Mean It)
- Forget your password = wave goodbye to your files 👋
- It's hardware-bound to your device, so even I can't help you
- Seriously, write it down somewhere safe or use a password manager
- "password123" is not a good choice (please don't)

### Screenshot Protection Isn't Magic
- ✅ Blocks software screenshots (Print Screen, Snipping Tool, etc.)
- ❌ Can't stop someone from taking a photo with their phone
- ❌ Can't block fancy external capture devices
- ❌ Some admin-level tools might sneak past
- Physics and hardware limitations are real, sorry!

---

## 🎯 When Should You Use This Thing?

BAR is perfect for:
- 💼 Sensitive work docs you need to share temporarily
- 🔑 Storing API keys, passwords, or credentials short-term
- 📄 Meeting data retention requirements (auto-delete old files)
- 🔒 Keeping your personal stuff actually private
- 💬 Secure temporary file exchanges
- 🏭 Corporate secrets and IP that shouldn't stick around
- 🏥 Healthcare records with expiration dates
- 💰 Financial docs you don't want hanging around forever

---

## 💡 Pro Tips (Learn from My Mistakes)

### ✅ Things You Should Do:
- Use STRONG passwords (12+ characters, mix it up)
- Match your security level to what you're protecting (don't use Maximum for your grocery list)
- Backup important stuff elsewhere first (seriously, DO THIS)
- Test with throwaway files before trusting it with important stuff
- Actually read the docs (I know, boring, but useful)

### ❌ Things That Will Bite You:
- Forgetting your password (no recovery = you're screwed)
- Casually using Maximum security (3 wrong attempts = everything's gone)
- Skipping backups (then crying when files self-destruct)
- Using this for sketchy/illegal stuff (don't be that person)
- Ignoring warnings (they're there for a reason!)

---

## 🔧 For the Tech Nerds

**What's Under the Hood:**
- Python 3.8+ (because it works and I like it)
- PySide6 for the GUI (Qt is pretty solid)
- AES-256-GCM encryption (military-grade, authenticated)
- PBKDF2-HMAC-SHA256 key derivation (fancy way to say "secure password handling")
- DoD 5220.22-M deletion standard (government-approved file destruction)

**Cool Advanced Stuff:**
- Windows API integration (for the screenshot blocking magic)
- Real-time keyboard hooks (catches Print Screen before it happens)
- Clipboard monitoring (no sneaky copy-paste shenanigans)
- Process detection (spots screenshot tools trying to be sneaky)
- Statistical analysis (detects suspicious patterns)
- Hardware fingerprinting (locks files to your specific machine)

**Performance Geekery:**
- Multi-threaded file scanning (fast AF)
- Optimized encryption (quick but secure)
- Low memory footprint (won't eat all your RAM)
- Minimal CPU impact (your fan won't sound like a jet engine)

---

## 📈 The Upgrade Highlights

### What I Fixed/Improved in v2.0.0:
- ✅ Authentication is way simpler now (one less annoying screen)
- ✅ Screenshot protection actually works better
- ✅ Added the panic wipe system (3 levels of NOPE)
- ✅ Hardware binding is more reliable
- ✅ Squashed a bunch of security bugs
- ✅ Code is cleaner and easier to maintain
- ✅ Performance improvements across the board
- ✅ Stability++ (way fewer random crashes)

---

## 🐛 Known Issues (aka Honesty Time)

### Stuff I Can't Fix (Physics/Reality Limitations):
- Windows 10/11 is where it shines brightest (Linux/macOS support is limited)
- Can't block phone cameras pointed at your screen (not magic, sorry)
- Some admin-level tools might bypass protections (they have special privileges)
- Older/slower hardware might feel a performance hit
- Cross-platform features are Windows-first (I develop on Windows)

### How to Work Around Limitations:
- Use BAR in a controlled environment when possible
- Run as administrator for maximum protection features
- Keep the software updated (I fix stuff regularly)
- Check the docs if something seems weird

---

## 📞 Stuck? Need Help?

If something's not working or you're confused:
- **Docs folder** (`docs/`) has detailed guides
- **README.md** has the main overview and quick start
- **INSTALL.md** walks through setup step-by-step
- **DISCLAIMER.md** has the legal/warning stuff (boring but important)

---

## 📄 License (The Legal Stuff)

BAR is GPL-3.0 licensed, which means:
- ✅ It's free and open source (always will be)
- ✅ You can modify and share it however you want
- ✅ Just keep it open source if you distribute it
- ❌ No warranties (if it breaks, that's on you)

Full boring legal text: [LICENSE](LICENSE)

---

## 👨‍💻 Who Built This Thing?

Hey! I'm **[Rolan (RNR)](https://rolan-rnr.netlify.app/)**, and I created BAR because honestly, the existing self-destructing file tools either sucked or were sketchy as hell.

I'm into cybersecurity and privacy, and I believe security software shouldn't require a PhD to use. BAR is my attempt at making something that's both properly secure AND doesn't make you want to throw your computer out the window.

Got questions? Feedback? Just wanna chat? Hit me up! I actually respond to people.

---

<div align="center">

**🔥 BAR v2.0.0 - Because Some Things Should Just... Disappear 🔥**

*Your files will self-destruct. Your privacy won't.*

---

**Stay safe, stay secure, and for the love of all that is holy, BACK UP YOUR IMPORTANT STUFF!**

👋

</div>

---

*P.S. - Seriously though: Once BAR deletes something, it's gone forever. No take-backs. Use your brain. 🧠*
