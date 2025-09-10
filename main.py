#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Add the src directory to the path so we can import our modules
src_dir = Path(__file__).resolve().parent / 'src'
sys.path.insert(0, str(src_dir))

# Import required modules
from src.config.config_manager import ConfigManager
from src.crypto.encryption import EncryptionManager
from src.file_manager.file_manager import FileManager
from src.security.device_auth import DeviceAuthManager
from src.gui.main_window import MainWindow
from src.gui.device_setup_dialog import DeviceSetupDialog
from src.gui.device_auth_dialog import DeviceAuthDialog

# Import PyQt5 modules
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5.QtCore import Qt


def setup_application_directory():
    """Set up the application directory structure."""
    app_dir = Path.home() / '.bar'
    app_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    (app_dir / 'logs').mkdir(exist_ok=True)
    (app_dir / 'data').mkdir(exist_ok=True)
    
    return app_dir


def main():
    """Main entry point for the BAR application."""
    # Set up application directory
    app_dir = setup_application_directory()
    
    # Create Qt application first
    app = QApplication(sys.argv)
    app.setApplicationName("BAR - Burn After Reading")
    app.setApplicationVersion("2.0.0")
    app.setStyle('Fusion')
    
    try:
        # Initialize device authentication manager
        device_auth = DeviceAuthManager(str(app_dir))
        
        # Check if device is initialized
        if not device_auth.is_device_initialized():
            # First-time setup
            setup_dialog = DeviceSetupDialog(device_auth)
            setup_result = setup_dialog.exec_()
            
            if setup_result != QDialog.Accepted or not setup_dialog.was_setup_successful():
                # User cancelled setup or setup failed
                sys.exit(0)
        
        # Device is initialized, now authenticate
        auth_dialog = DeviceAuthDialog(device_auth)
        auth_result = auth_dialog.exec_()
        
        if auth_result != QDialog.Accepted:
            # User cancelled authentication or requested reset
            if auth_dialog.was_reset_requested():
                # Device was reset, exit application
                sys.exit(0)
            else:
                # User just cancelled
                sys.exit(0)
        
        # Authentication successful, initialize other components
        config_manager = ConfigManager(str(app_dir))
        file_manager = FileManager(str(app_dir / 'data'))
        
        # Create and show main window with device authentication
        main_window = MainWindow(config_manager, file_manager, device_auth)
        main_window.show()
        
        # Start the application event loop
        sys.exit(app.exec_())
        
    except Exception as e:
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.critical(
            None,
            "BAR - Critical Error",
            f"A critical error occurred during startup:\n\n{str(e)}\n\n"
            "The application will now exit."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()