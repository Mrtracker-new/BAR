#!/usr/bin/env python3

import os
import sys
import logging
from pathlib import Path

# Time to tell Python where our cool stuff lives! 🗺️
src_dir = Path(__file__).resolve().parent / 'src'
sys.path.insert(0, str(src_dir))

# Grabbing all our fancy modules (like grocery shopping but for code) 🛒
from src.config.config_manager import ConfigManager
from src.security.device_auth_manager import DeviceAuthManager
from src.gui.main_window import MainWindow
from src.gui.device_setup_dialog import DeviceSetupDialog
from src.gui.styles import StyleManager
from src.security.secure_memory import force_secure_memory_cleanup
from src.security.emergency_protocol import EmergencyProtocol
from src.security.intelligent_monitor import IntelligentFileMonitor, ThreatLevel
from src.security.steganographic_triggers import SteganographicTriggerSystem, TriggerType, TriggerAction
from src.security.system_health_monitor import SystemHealthMonitor, ThreatLevel as HealthThreatLevel
from src.file_manager.file_manager import FileManager

# Qt time! Because everyone loves a good GUI framework 🎨
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox, QLineEdit, QInputDialog


def setup_logging():
    """Set up application logging with security considerations."""
    log_dir = Path.home() / '.bar' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Fort Knox mode: Nobody's reading these logs except us! 🔐
    if hasattr(os, 'chmod'):
        os.chmod(str(log_dir), 0o700)
    
    log_file = log_dir / 'bar_app.log'
    
    # Let's get chatty - setting up our diary to remember everything 📝
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(str(log_file), encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Double-locking the diary because we're paranoid like that 🔒🔒
    if hasattr(os, 'chmod') and log_file.exists():
        os.chmod(str(log_file), 0o600)
    
    return log_file


def setup_application_directory():
    """Set up the application directory structure."""
    app_dir = Path.home() / '.bar'
    app_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    
    # Building a secret clubhouse that only we have the key to! 🏠🔑
    if hasattr(os, 'chmod'):
        os.chmod(str(app_dir), 0o700)
    
    return app_dir


class SimpleAuthDialog(QDialog):
    """Simple authentication dialog for device password entry."""
    
    def __init__(self, device_auth, parent=None, steg_system=None):
        super().__init__(parent)
        self.device_auth = device_auth
        self.steg_system = steg_system  # The sneaky spy system that watches for secret codes 🕵️
        self.authenticated = False
        self.password = None  # Holding onto this password like a hot potato - won't be here long! 🥔🔥
        
        self.setWindowTitle("BAR - Device Authentication")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        # Because we're hackers and hackers only use dark mode 😎🌙
        StyleManager.apply_theme("dark")
        
    def exec(self):
        """Override exec to use input dialog for simplicity."""
        
        # Hold up! Before we let anyone in, let's make sure the door isn't already deadbolted 🚪🔒
        # Testing the waters with an empty password (shh, don't tell anyone)
        try:
            success, lockout_message = self.device_auth.authenticate("")
            if not success and ("🔒 DEVICE LOCKED" in lockout_message or "⏰ DEVICE LOCKED" in lockout_message):
                # Yep, door's locked tighter than a pickle jar! Time to bail 🏃💨
                QMessageBox.critical(
                    self.parent(),
                    "Device Locked",
                    f"{lockout_message}\n\nApplication will exit due to security lockout."
                )
                return QDialog.DialogCode.Rejected
        except Exception:
            pass  # If this breaks, meh, we'll find out later anyway 🤷
        
        max_attempts = 3  # Three strikes rule (but the real bouncer is DeviceAuthManager) ⚾
        attempts = 0
        
        while attempts < max_attempts:
            password, ok = QInputDialog.getText(
                self.parent(),
                "Device Authentication",
                f"Enter your master password (Attempt {attempts + 1}/{max_attempts}):",
                QLineEdit.EchoMode.Password
            )
            
            if not ok:
                # User got cold feet and pressed cancel 👣❄️
                return QDialog.DialogCode.Rejected
            
            if password:
                # Is this password actually a secret code? Let's check our decoder ring! 💍🔍
                if self.steg_system:
                    trigger_activated = self.steg_system.check_password_trigger(password)
                    if trigger_activated:
                        # ABORT ABORT! Secret code detected - self-destruct sequence initiated! 💥🚨
                        return QDialog.DialogCode.Rejected
                
                success, message = self.device_auth.authenticate(password)
                
                if success:
                    self.authenticated = True
                    # Keeping this password in our pocket just for a sec (promise we'll throw it away!) 🤞
                    # Don't worry - file_manager will shred it like junk mail after using it 📄✂️
                    self.password = password
                    QMessageBox.information(
                        self.parent(),
                        "Authentication Successful",
                        message
                    )
                    return QDialog.DialogCode.Accepted
                    
                else:
                    # Did we just trigger something bad? Let's scan this error message real quick 👀
                    if ("🔒 DEVICE LOCKED" in message or 
                        "⏰ DEVICE LOCKED" in message or
                        "🔒 HIGH SECURITY LOCKOUT" in message or
                        "⏰ STANDARD SECURITY" in message or
                        "🚨 SECURITY BREACH" in message):
                        # Houston, we have a problem! Lockdown initiated! 🚨🔴
                        QMessageBox.critical(
                            self.parent(),
                            "Security Action",
                            f"{message}\n\nApplication will exit."
                        )
                        return QDialog.DialogCode.Rejected
                    
                    # Nope, wrong password buddy! Try again 🙅
                    attempts += 1
                    if attempts < max_attempts:
                        QMessageBox.warning(
                            self.parent(),
                            "Authentication Failed",
                            f"{message}\n\nAttempts remaining: {max_attempts - attempts}"
                        )
                    else:
                        QMessageBox.critical(
                            self.parent(),
                            "Authentication Failed",
                            f"{message}\n\nMaximum attempts reached. Application will exit."
                        )
                        return QDialog.DialogCode.Rejected
            else:
                attempts += 1
        
        return QDialog.DialogCode.Rejected
    
    def is_authenticated(self):
        return self.authenticated


def main():
    """Main entry point for the BAR application with enhanced security."""
    # First things first: let's start taking notes on everything! 📒
    log_file = setup_logging()
    logger = logging.getLogger("BAR.Main")
    
    logger.info("🔥 BAR - Burn After Reading v2.0.0 Starting...")
    
    # Time to build our secret lair! 🦸🏰
    app_dir = setup_application_directory()
    
    # Summoning the mighty Qt framework with extra security spells! ⚡🛡️
    app = QApplication(sys.argv)
    app.setApplicationName("BAR - Burn After Reading")
    app.setApplicationVersion("2.0.0")
    app.setStyle('Fusion')
    
    # Everything's cooler in dark mode (literally, your eyes will thank me) 🕶️
    StyleManager.apply_theme("dark")
    
    try:
        logger.info("Initializing device authentication manager...")
        
        # Waking up our security guard (he's a bit grumpy in the morning) 💂‍♂️☕
        device_auth = DeviceAuthManager()
        
        # Starting all the Mission Impossible self-destruct gadgets 🎬💣
        logger.info("Initializing enhanced security systems...")
        config_manager = ConfigManager(base_directory=str(app_dir))
        emergency = EmergencyProtocol(str(app_dir), device_auth)
        monitor = IntelligentFileMonitor(Path(app_dir))
        steg = SteganographicTriggerSystem(Path(app_dir))
        health_monitor = SystemHealthMonitor(check_interval=5.0, memory_threshold=85.0, cpu_threshold=90.0, temperature_threshold=80.0)
        
        # Is this our first date? Let's check if you've been here before 💐
        if not device_auth.is_device_initialized():
            logger.info("Device not initialized - starting first-time setup")
            
            # Welcome newbie! Let's get you all set up (no spy stuff needed yet) 🎉👋
            setup_dialog = DeviceSetupDialog(device_auth)
            setup_result = setup_dialog.exec()
            
            if setup_result != QDialog.DialogCode.Accepted or not setup_dialog.was_setup_successful():
                logger.info("Device setup cancelled or failed - exiting")
                force_secure_memory_cleanup()
                sys.exit(0)
            
            logger.info("Device setup completed successfully")
        
        # You're registered! Now prove it's really you (with spy system on standby) 🎭
        logger.info("Device initialized - requesting authentication")
        auth_dialog = SimpleAuthDialog(device_auth, steg_system=steg)
        auth_result = auth_dialog.exec()
        
        if auth_result != QDialog.DialogCode.Accepted or not auth_dialog.is_authenticated():
            logger.info("Authentication failed or cancelled - exiting")
            force_secure_memory_cleanup()
            sys.exit(0)
        
        logger.info("Authentication successful - configuring security systems")
        
        # CRITICAL: FileManager goes first or everything breaks! (Don't ask me why, I don't make the rules) 🎯⚠️
        file_manager = FileManager(str(app_dir), monitor=monitor)
        
        # ⚠️ SUPER IMPORTANT: Time to encrypt all the secret metadata! 🔐🎩
        # Order matters here - do this backwards and everything explodes! 💥
        logger.info("Initializing encrypted metadata system...")
        try:
            # Borrowing your password for a hot minute to make encryption keys 🔑
            # Relax - we'll forget it the moment you log out! (Like a digital goldfish) 🐠
            device_password = auth_dialog.password
            
            if device_password:
                file_manager.set_metadata_key(device_password)
                logger.info("✓ Encrypted metadata system initialized successfully")
                
                # Annnnnd... the password's gone! *poof* 💨✨
                auth_dialog.password = None
            else:
                logger.warning("⚠️ Could not initialize metadata encryption - legacy mode")
        except Exception as e:
            logger.error(f"Failed to initialize metadata encryption: {e}")
            # Oops, encryption broke! Going old-school with plain text (it's vintage!) 📼

        # Hooking up our alarm system 🚨
        # HIGH threats = we're nervous but won't panic yet (false alarms are super annoying)
        def handle_high_threat(data):
            reason = f"High threat detected: {data.get('type', 'unknown')}"
            logger.warning(f"⚠️ HIGH THREAT DETECTED: {reason} - Enhanced monitoring active")
            # Just keeping an extra eye out - we're not burning the house down yet! 🏠👀
        
        # CRITICAL threats = DEFCON 1 - hit the big red button! 🔴🚀
        def handle_critical_threat(data):
            reason = f"Critical threat detected: {data.get('type', 'unknown')}"
            logger.critical(f"🚨 CRITICAL THREAT DETECTED: {reason} - Triggering emergency wipe")
            emergency.trigger_emergency_destruction(reason=reason, level="aggressive")
        
        monitor.register_threat_callback(ThreatLevel.HIGH, handle_high_threat)
        monitor.register_threat_callback(ThreatLevel.CRITICAL, handle_critical_threat)

        # Connecting our system health checkup doctor 👨‍⚕️💉
        def handle_health_threat(metrics):
            if metrics.threat_level == HealthThreatLevel.CRITICAL:
                threats_summary = ", ".join(metrics.active_threats[:3])  # Top 3 worst problems (nobody wants the full list) 📋
                reason = f"Critical system health threat: {threats_summary}"
                emergency.trigger_emergency_destruction(reason=reason, level="aggressive")
            elif metrics.threat_level == HealthThreatLevel.HIGH:
                threats_summary = ", ".join(metrics.active_threats[:2])  # Top 2 problems (keeping it brief) 📝
                reason = f"High system health threat: {threats_summary}"
                emergency.trigger_emergency_destruction(reason=reason, level="selective")
        
        health_monitor.add_callback(handle_health_threat)

        # Setting up a tripwire for suspicious activity (you can customize this later!) 🪤
        # Pro tip: Don't hardcode your actual panic passwords here, Einstein 🤓
        steg.install_trigger(TriggerType.ACCESS_SEQUENCE, "count:access:20", TriggerAction.AGGRESSIVE_WIPE, sensitivity=0.9, description="Rapid access default")

        # Teaching our spy system what to do when it spots secret codes 🕵️📡
        def steg_callback(data):
            action = data.get('action')
            if action == TriggerAction.SELECTIVE_WIPE.value:
                emergency.trigger_emergency_destruction(reason="Steganographic trigger", level="selective")
            elif action == TriggerAction.AGGRESSIVE_WIPE.value:
                emergency.trigger_emergency_destruction(reason="Steganographic trigger", level="aggressive")
            elif action == TriggerAction.SCORCHED_EARTH.value:
                emergency.trigger_emergency_destruction(reason="Steganographic trigger", level="scorched")
        
        for action in TriggerAction:
            steg.register_trigger_callback(action, steg_callback)

        # Remember that FileManager we made earlier? Yeah, it's still there chilling 😎
        # Time to boot everything up! 3... 2... 1... 🚀
        monitor.start_monitoring()
        health_monitor.start_monitoring()
        emergency.start_dead_mans_switch()
        
        # Showtime! Opening the curtains on our fancy GUI with ALL the security bells and whistles 🎭🔔
        main_window = MainWindow(config_manager, file_manager, device_auth, emergency=emergency, monitor=monitor, steg=steg, health_monitor=health_monitor)
        main_window.show()
        
        logger.info("BAR application started successfully")
        
        # And now we wait... (this is where the magic happens) ✨⏳
        exit_code = app.exec()
        
        logger.info(f"BAR application exiting with code: {exit_code}")
        
        # Time to clean up our mess before we leave (mom raised us right!) 🧹🧼
        try:
            try:
                file_manager.shutdown()
            except Exception:
                pass
            try:
                monitor.stop_monitoring()
            except Exception:
                pass
            try:
                health_monitor.stop_monitoring()
            except Exception:
                pass
            try:
                emergency.stop_dead_mans_switch()
            except Exception:
                pass
            try:
                steg.cleanup()
            except Exception:
                pass
            device_auth.logout()
            force_secure_memory_cleanup()
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")
        
        sys.exit(exit_code)
        
    except Exception as e:
        logger.critical(f"Critical error during startup: {e}", exc_info=True)
        
        # OH NO! Everything's on fire! 🔥 Quick, destroy all evidence! 🏃💨
        try:
            if 'device_auth' in locals():
                device_auth.emergency_wipe()
            force_secure_memory_cleanup()
        except Exception as cleanup_error:
            logger.critical(f"Emergency cleanup failed: {cleanup_error}")
        
        QMessageBox.critical(
            None,
            "BAR - Critical Error",
            f"A critical security error occurred during startup:\n\n{str(e)}\n\n"
            "Emergency cleanup has been performed.\n"
            "The application will now exit."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()