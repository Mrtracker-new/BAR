#!/usr/bin/env python3

import os
import sys
import logging
from pathlib import Path

# Add the src directory to the path so we can import our modules
src_dir = Path(__file__).resolve().parent / 'src'
sys.path.insert(0, str(src_dir))

# Import required modules
from src.config.config_manager import ConfigManager
from src.security.device_auth_manager import DeviceAuthManager
from src.gui.main_window import MainWindow
from src.gui.device_setup_dialog import DeviceSetupDialog
from src.gui.styles import StyleManager
from src.security.secure_memory import get_secure_memory_manager, force_secure_memory_cleanup
from src.security.emergency_protocol import EmergencyProtocol
from src.security.intelligent_monitor import IntelligentFileMonitor, ThreatLevel
from src.security.steganographic_triggers import SteganographicTriggerSystem, TriggerType, TriggerAction
from src.file_manager.file_manager import FileManager

# Import PyQt5 modules
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox, QLineEdit, QInputDialog
from PyQt5.QtCore import Qt


def setup_logging():
    """Set up application logging with security considerations."""
    log_dir = Path.home() / '.bar' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Set restrictive permissions on log directory
    if hasattr(os, 'chmod'):
        os.chmod(str(log_dir), 0o700)
    
    log_file = log_dir / 'bar_app.log'
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(str(log_file), encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set restrictive permissions on log file
    if hasattr(os, 'chmod') and log_file.exists():
        os.chmod(str(log_file), 0o600)
    
    return log_file


def setup_application_directory():
    """Set up the application directory structure."""
    app_dir = Path.home() / '.bar'
    app_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    
    # Set restrictive permissions on app directory
    if hasattr(os, 'chmod'):
        os.chmod(str(app_dir), 0o700)
    
    return app_dir


class SimpleAuthDialog(QDialog):
    """Simple authentication dialog for device password entry."""
    
    def __init__(self, device_auth, parent=None, steg_system=None):
        super().__init__(parent)
        self.device_auth = device_auth
        self.steg_system = steg_system  # Steganographic trigger system
        self.authenticated = False
        
        self.setWindowTitle("BAR - Device Authentication")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        # Apply dark theme
        StyleManager.apply_theme("dark")
        
    def exec_(self):
        """Override exec to use input dialog for simplicity."""
        
        # First, check for security lockout before attempting authentication
        # Do a quick lockout check by calling authenticate with empty password
        try:
            success, lockout_message = self.device_auth.authenticate("")
            if not success and ("🔒 DEVICE LOCKED" in lockout_message or "⏰ DEVICE LOCKED" in lockout_message):
                # Device is locked, show lockout message and exit
                QMessageBox.critical(
                    self.parent(),
                    "Device Locked",
                    f"{lockout_message}\n\nApplication will exit due to security lockout."
                )
                return QDialog.Rejected
        except:
            pass  # Ignore errors from lockout check
        
        max_attempts = 3  # This is just for the dialog loop, actual security is handled by DeviceAuthManager
        attempts = 0
        
        while attempts < max_attempts:
            password, ok = QInputDialog.getText(
                self.parent(),
                "Device Authentication",
                f"Enter your master password (Attempt {attempts + 1}/{max_attempts}):",
                QLineEdit.Password
            )
            
            if not ok:
                # User cancelled
                return QDialog.Rejected
            
            if password:
                # Check steganographic triggers before authentication
                if self.steg_system:
                    trigger_activated = self.steg_system.check_password_trigger(password)
                    if trigger_activated:
                        # Steganographic trigger activated - emergency protocol should be running
                        return QDialog.Rejected
                
                success, message = self.device_auth.authenticate(password)
                
                if success:
                    self.authenticated = True
                    QMessageBox.information(
                        self.parent(),
                        "Authentication Successful",
                        message
                    )
                    return QDialog.Accepted
                    
                else:
                    # Check if this is a lockout or emergency wipe message
                    if ("🔒 DEVICE LOCKED" in message or 
                        "⏰ DEVICE LOCKED" in message or
                        "🔒 HIGH SECURITY LOCKOUT" in message or
                        "⏰ STANDARD SECURITY" in message or
                        "🚨 SECURITY BREACH" in message):
                        # Security lockout or emergency action triggered
                        QMessageBox.critical(
                            self.parent(),
                            "Security Action",
                            f"{message}\n\nApplication will exit."
                        )
                        return QDialog.Rejected
                    
                    # Regular authentication failure
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
                        return QDialog.Rejected
            else:
                attempts += 1
        
        return QDialog.Rejected
    
    def is_authenticated(self):
        return self.authenticated


def main():
    """Main entry point for the BAR application with enhanced security."""
    # Set up logging first
    log_file = setup_logging()
    logger = logging.getLogger("BAR.Main")
    
    logger.info("🔥 BAR - Burn After Reading v2.0.0 Starting...")
    
    # Set up application directory
    app_dir = setup_application_directory()
    
    # Create Qt application with enhanced security settings
    app = QApplication(sys.argv)
    app.setApplicationName("BAR - Burn After Reading")
    app.setApplicationVersion("2.0.0")
    app.setStyle('Fusion')
    
    # Apply dark theme globally
    StyleManager.apply_theme("dark")
    
    try:
        logger.info("Initializing device authentication manager...")
        
        # Initialize device authentication manager
        device_auth = DeviceAuthManager()
        
        # Initialize enhanced self-destruct components early for security
        logger.info("Initializing enhanced security systems...")
        config_manager = ConfigManager(base_directory=str(app_dir))
        emergency = EmergencyProtocol(str(app_dir), device_auth)
        monitor = IntelligentFileMonitor(Path(app_dir))
        steg = SteganographicTriggerSystem(Path(app_dir))
        
        # Check if device is initialized
        if not device_auth.is_device_initialized():
            logger.info("Device not initialized - starting first-time setup")
            
            # First-time setup (steg system not needed for setup)
            setup_dialog = DeviceSetupDialog(device_auth)
            setup_result = setup_dialog.exec_()
            
            if setup_result != QDialog.Accepted or not setup_dialog.was_setup_successful():
                logger.info("Device setup cancelled or failed - exiting")
                force_secure_memory_cleanup()
                sys.exit(0)
            
            logger.info("Device setup completed successfully")
        
        # Device is initialized, now authenticate with steg system available
        logger.info("Device initialized - requesting authentication")
        auth_dialog = SimpleAuthDialog(device_auth, steg_system=steg)
        auth_result = auth_dialog.exec_()
        
        if auth_result != QDialog.Accepted or not auth_dialog.is_authenticated():
            logger.info("Authentication failed or cancelled - exiting")
            force_secure_memory_cleanup()
            sys.exit(0)
        
        logger.info("Authentication successful - configuring security systems")

        # Register monitor threat callbacks
        def handle_high_threat(data):
            reason = f"High threat detected: {data.get('type', 'unknown')}"
            emergency.trigger_emergency_destruction(reason=reason, level="aggressive")
        def handle_critical_threat(data):
            reason = f"Critical threat detected: {data.get('type', 'unknown')}"
            emergency.trigger_emergency_destruction(reason=reason, level="scorched")
        monitor.register_threat_callback(ThreatLevel.HIGH, handle_high_threat)
        monitor.register_threat_callback(ThreatLevel.CRITICAL, handle_critical_threat)

        # Install a safe default steganographic trigger (example can be customized)
        # Note: avoid using real sensitive patterns in code
        steg.install_trigger(TriggerType.ACCESS_SEQUENCE, "count:access:20", TriggerAction.AGGRESSIVE_WIPE, sensitivity=0.9, description="Rapid access default")

        # Set up steganographic trigger callbacks
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

        # Create FileManager with monitor
        file_manager = FileManager(str(app_dir), monitor=monitor)

        # Start systems
        monitor.start_monitoring()
        emergency.start_dead_mans_switch()
        
        # Create and show main window with device authentication and self-destruct systems
        main_window = MainWindow(config_manager, file_manager, device_auth, emergency=emergency, monitor=monitor, steg=steg)
        main_window.show()
        
        logger.info("BAR application started successfully")
        
        # Start the application event loop
        exit_code = app.exec_()
        
        logger.info(f"BAR application exiting with code: {exit_code}")
        
        # Ensure secure cleanup on exit
        try:
            try:
                monitor.stop_monitoring()
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
        
        # Emergency cleanup
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