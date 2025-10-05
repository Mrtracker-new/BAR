import sys
from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QFormLayout, QWidget, QCheckBox, QGroupBox, QTextEdit,
    QProgressBar, QFrame
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal as pyqtSignal
from PySide6.QtGui import QIcon, QPixmap, QFont, QPalette, QColor

from .styles import StyleManager
from src.security.device_auth_manager import SecurityLevel


class AuthWorker(QThread):
    """Worker thread for authentication to prevent UI blocking."""
    
    finished = pyqtSignal(bool, str)  # success, message
    progress = pyqtSignal(int)  # progress percentage
    
    def __init__(self, device_auth, password):
        super().__init__()
        self.device_auth = device_auth
        self.password = password
    
    def run(self):
        try:
            self.progress.emit(30)
            
            # Authenticate (this may take time due to PBKDF2 verification)
            success, message = self.device_auth.authenticate(self.password)
            
            self.progress.emit(100)
            self.finished.emit(success, message)
            
        except Exception as e:
            self.progress.emit(100)
            self.finished.emit(False, f"Authentication failed: {str(e)}")


class DeviceAuthDialog(QDialog):
    """Dialog for authenticating with master password."""
    
    def __init__(self, device_auth, parent=None):
        """Initialize the device authentication dialog.
        
        Args:
            device_auth: DeviceAuthManager instance
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.device_auth = device_auth
        self.authenticated = False
        self.reset_requested = False
        
        self.setWindowTitle("BAR - Unlock Device")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)
        self.setModal(True)
        
        # Apply dark theme
        self.setStyleSheet("""
            QDialog {
                background-color: #2c2c2c;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 4px;
                margin-top: 20px;
                padding-top: 24px;
                color: #ffffff;
            }
            QGroupBox::title {
                color: #ffffff;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #444;
                border-radius: 4px;
                color: #ffffff;
                padding: 8px;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: #ffffff !important;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px 16px;
                min-width: 80px;
                font-weight: bold;
                text-align: center;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border: 1px solid #666;
                color: #ffffff !important;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
                color: #ffffff !important;
            }
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #888888 !important;
                border: 1px solid #3a3a3a;
            }
        """)
        
        self._setup_ui()
        
        # Get device info for display and update security status
        try:
            device_info = device_auth.get_device_info()
            if device_info:
                self.device_name_label.setText(f"Device: {device_info['device_name']}")
        except:
            pass
            
        # Update security status display
        self._update_security_status()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Title section
        title_label = QLabel("🔓 Unlock BAR Device")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #3498db; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Device name (will be updated if available)
        self.device_name_label = QLabel("Secure Device")
        self.device_name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        self.device_name_label.setFont(subtitle_font)
        self.device_name_label.setStyleSheet("color: #95a5a6; margin-bottom: 20px;")
        layout.addWidget(self.device_name_label)
        
        # Authentication form
        auth_group = QGroupBox("Master Password Authentication")
        auth_layout = QVBoxLayout(auth_group)
        layout.addWidget(auth_group)
        
        # Form layout
        form_layout = QFormLayout()
        auth_layout.addLayout(form_layout)
        
        # Master password
        self.password_label = QLabel("Master Password:")
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter your master password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.returnPressed.connect(self._authenticate)
        form_layout.addRow(self.password_label, self.password_edit)
        
        # Show password checkbox
        self.show_password_check = QCheckBox("Show password")
        self.show_password_check.toggled.connect(self._toggle_password_visibility)
        auth_layout.addWidget(self.show_password_check)
        
        # Security notice
        notice_label = QLabel(
            "⚠️ This device uses hardware-bound authentication.\n"
            "Your password cannot be recovered if forgotten."
        )
        notice_label.setStyleSheet("color: #f39c12; font-size: 9pt; margin: 10px;")
        notice_label.setWordWrap(True)
        auth_layout.addWidget(notice_label)
        
        # Security status section
        self.security_status_group = QGroupBox("🛡️ Security Status")
        self.security_status_layout = QVBoxLayout(self.security_status_group)
        layout.addWidget(self.security_status_group)
        
        self.security_level_label = QLabel("Loading security information...")
        self.security_level_label.setStyleSheet("color: #3498db; font-weight: bold;")
        self.security_status_layout.addWidget(self.security_level_label)
        
        self.attempts_info_label = QLabel("")
        self.attempts_info_label.setStyleSheet("color: #95a5a6;")
        self.attempts_info_label.setWordWrap(True)
        self.security_status_layout.addWidget(self.attempts_info_label)
        
        self.security_warning_label = QLabel("")
        self.security_warning_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        self.security_warning_label.setWordWrap(True)
        self.security_warning_label.setVisible(False)
        self.security_status_layout.addWidget(self.security_warning_label)
        
        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)
        
        # Emergency reset button (dangerous)
        self.reset_button = QPushButton("🗑️ Emergency Reset")
        self.reset_button.clicked.connect(self._emergency_reset)
        self.reset_button.setStyleSheet(StyleManager.get_button_style("danger"))
        self.reset_button.setToolTip("WARNING: This will permanently destroy ALL data!")
        button_layout.addWidget(self.reset_button)
        
        button_layout.addStretch()
        
        # Exit button
        self.exit_button = QPushButton("Exit")
        self.exit_button.clicked.connect(self.reject)
        self.exit_button.setStyleSheet(StyleManager.get_button_style())
        button_layout.addWidget(self.exit_button)
        
        # Unlock button
        self.unlock_button = QPushButton("🔓 Unlock Device")
        self.unlock_button.clicked.connect(self._authenticate)
        self.unlock_button.setStyleSheet(StyleManager.get_button_style("primary"))
        self.unlock_button.setDefault(True)
        button_layout.addWidget(self.unlock_button)
        
        # Connect password field changes
        self.password_edit.textChanged.connect(self._check_password_entered)
        
        # Focus on password field
        self.password_edit.setFocus()
    
    def _toggle_password_visibility(self, checked):
        """Toggle password visibility."""
        if checked:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
    
    def _check_password_entered(self):
        """Check if password is entered and update button state."""
        has_password = len(self.password_edit.text()) > 0
        self.unlock_button.setEnabled(has_password)
        
        if has_password:
            self.unlock_button.setText("🔓 Unlock Device")
        else:
            self.unlock_button.setText("🔓 Enter Password")
    
    def _authenticate(self):
        """Attempt to authenticate with master password."""
        password = self.password_edit.text()
        
        if not password:
            QMessageBox.warning(self, "Authentication", "Please enter your master password.")
            return
        
        # Disable UI during authentication
        self.unlock_button.setEnabled(False)
        self.reset_button.setEnabled(False)
        self.exit_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        
        # Start authentication in worker thread
        self.auth_worker = AuthWorker(self.device_auth, password)
        self.auth_worker.progress.connect(self.progress_bar.setValue)
        self.auth_worker.finished.connect(self._on_auth_finished)
        self.auth_worker.start()
    
    
    def _emergency_reset(self):
        """Handle emergency device reset."""
        # First confirmation
        reply = QMessageBox.question(
            self,
            "⚠️ EMERGENCY DEVICE RESET",
            "This will PERMANENTLY DESTROY ALL DATA on this device!\n\n"
            "• All files will be securely deleted\n"
            "• All configuration will be wiped\n"
            "• Device will need to be re-initialized\n\n"
            "This action CANNOT BE UNDONE!\n\n"
            "Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Second confirmation with text input
        from PySide6.QtWidgets import QInputDialog
        confirm_text, ok = QInputDialog.getText(
            self,
            "Final Confirmation",
            "To confirm emergency reset, type exactly:\nDESTROY ALL DATA",
            QLineEdit.EchoMode.Normal,
            ""
        )
        
        if not ok or confirm_text != "DESTROY ALL DATA":
            QMessageBox.information(self, "Reset Cancelled", "Emergency reset was cancelled.")
            return
        
        # Perform the reset
        try:
            success, message = self.device_auth.reset_device("DESTROY ALL DATA")
            
            if success:
                self.reset_requested = True
                QMessageBox.information(
                    self,
                    "Device Reset Complete",
                    f"{message}\n\n"
                    "The application will now exit.\n"
                    "Restart the application to set up a new device."
                )
                self.reject()
            else:
                QMessageBox.critical(self, "Reset Failed", f"Device reset failed: {message}")
                
        except Exception as e:
            QMessageBox.critical(self, "Reset Error", f"An error occurred during reset: {str(e)}")
    
    def is_authenticated(self) -> bool:
        """Check if authentication was successful."""
        return self.authenticated
    
    def was_reset_requested(self) -> bool:
        """Check if emergency reset was requested."""
        return self.reset_requested
    
    def _update_security_status(self):
        """Update the security status display with current information."""
        try:
            # Try to load device configuration to get security level
            import json
            from pathlib import Path
            
            device_config_path = self.device_auth.device_config_path
            if device_config_path.exists():
                with open(device_config_path, 'r') as f:
                    device_config = json.load(f)
                    
                security_level = device_config.get("security_level", "standard")
                
                # Try to get persistent security data to show attempt counts
                security_data = self.device_auth._load_persistent_security_data()
                
                if security_data:
                    failed_attempts = security_data.get("total_failed_attempts", 0)
                    lockout_count = security_data.get("lockout_count", 0)
                    data_corrupted = security_data.get("data_corrupted", False)
                    
                    # Get security configuration
                    from src.security.device_auth_manager import SecurityLevel
                    security_config = self.device_auth.SECURITY_CONFIGS.get(
                        security_level, self.device_auth.SECURITY_CONFIGS[SecurityLevel.STANDARD]
                    )
                    
                    if data_corrupted:
                        self.security_level_label.setText("🚨 SECURITY BREACH DETECTED")
                        self.security_level_label.setStyleSheet("color: #e74c3c; font-weight: bold; font-size: 12pt;")
                        self.attempts_info_label.setText("All data has been destroyed for security.")
                        self.security_warning_label.setText("Device requires complete reset.")
                        self.security_warning_label.setVisible(True)
                        return
                    
                    # Display security level
                    level_icons = {
                        SecurityLevel.STANDARD: "🔒",
                        SecurityLevel.HIGH: "🔐", 
                        SecurityLevel.MAXIMUM: "🚨"
                    }
                    
                    icon = level_icons.get(security_level, "🔒")
                    self.security_level_label.setText(f"{icon} Security Level: {security_level.upper()}")
                    
                    # Display attempt information
                    max_attempts = security_config["max_attempts"]
                    attempts_left = max_attempts - failed_attempts
                    
                    if failed_attempts > 0:
                        self.attempts_info_label.setText(
                            f"Failed attempts: {failed_attempts}/{max_attempts} • "
                            f"Attempts remaining: {attempts_left}"
                        )
                        
                        if lockout_count > 0:
                            self.attempts_info_label.setText(
                                self.attempts_info_label.text() + f" • Lockouts: {lockout_count}"
                            )
                    else:
                        self.attempts_info_label.setText(f"Maximum attempts allowed: {max_attempts}")
                    
                    # Show warning for maximum security or low remaining attempts
                    if security_config["destroy_data_on_breach"]:
                        if attempts_left <= 1:
                            self.security_warning_label.setText(
                                f"⚠️ CRITICAL: Only {attempts_left} attempt(s) remaining before DATA DESTRUCTION!"
                            )
                            self.security_warning_label.setVisible(True)
                        else:
                            self.security_warning_label.setText(
                                f"⚠️ Maximum security active: Data will be destroyed after {max_attempts} failed attempts."
                            )
                            self.security_warning_label.setVisible(True)
                    elif attempts_left <= 1:
                        self.security_warning_label.setText(
                            f"⚠️ Warning: Only {attempts_left} attempt(s) remaining before device lockout!"
                        )
                        self.security_warning_label.setVisible(True)
                else:
                    # Fallback display
                    self.security_level_label.setText(f"🔒 Security Level: {security_level.upper()}")
                    self.attempts_info_label.setText("Security status unavailable")
            else:
                self.security_level_label.setText("🔒 Device not initialized")
                self.attempts_info_label.setText("Complete device setup first")
                
        except Exception as e:
            # Fallback error display
            self.security_level_label.setText("⚠️ Security status unavailable")
            self.attempts_info_label.setText("Unable to load security information")
    
    def _on_auth_finished(self, success: bool, message: str):
        """Handle authentication completion with security status update."""
        self.progress_bar.setVisible(False)
        
        if success:
            self.authenticated = True
            self.accept()
        else:
            QMessageBox.warning(self, "Authentication Failed", message)
            
            # Update security status after failed attempt
            self._update_security_status()
            
            # Clear password and re-enable UI
            self.password_edit.clear()
            self.password_edit.setFocus()
            self.unlock_button.setEnabled(True)
            self.reset_button.setEnabled(True)
            self.exit_button.setEnabled(True)


class DeviceResetDialog(QDialog):
    """Dialog for confirming device reset operations."""
    
    def __init__(self, parent=None):
        """Initialize the device reset confirmation dialog."""
        super().__init__(parent)
        
        self.confirmed = False
        
        self.setWindowTitle("⚠️ Device Reset Confirmation")
        self.setMinimumWidth(500)
        self.setMinimumHeight(300)
        self.setModal(True)
        
        # Apply dark theme with red accent for danger
        self.setStyleSheet("""
            QDialog {
                background-color: #2c2c2c;
                color: #ffffff;
                border: 2px solid #e74c3c;
            }
            QLabel {
                color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #e74c3c;
                border-radius: 4px;
                margin-top: 20px;
                padding-top: 24px;
                color: #ffffff;
            }
            QGroupBox::title {
                color: #e74c3c;
                font-weight: bold;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: #ffffff !important;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px 16px;
                min-width: 80px;
                font-weight: bold;
                text-align: center;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border: 1px solid #666;
                color: #ffffff !important;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
                color: #ffffff !important;
            }
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #888888 !important;
                border: 1px solid #3a3a3a;
            }
        """)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("🚨 EMERGENCY DEVICE RESET")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #e74c3c; margin-bottom: 15px;")
        layout.addWidget(title_label)
        
        # Warning group
        warning_group = QGroupBox("⚠️ FINAL WARNING")
        warning_layout = QVBoxLayout(warning_group)
        layout.addWidget(warning_group)
        
        # Warning text
        warning_text = QLabel(
            "This action will:\n\n"
            "• PERMANENTLY DELETE all encrypted files\n"
            "• DESTROY all device configuration\n"
            "• WIPE all authentication data\n"
            "• RESET the device to factory state\n\n"
            "THERE IS NO WAY TO RECOVER YOUR DATA!\n"
            "This operation cannot be undone!"
        )
        warning_text.setStyleSheet("color: #ffffff; font-size: 11pt; line-height: 1.4;")
        warning_text.setWordWrap(True)
        warning_layout.addWidget(warning_text)
        
        # Confirmation input
        confirm_group = QGroupBox("Confirmation Required")
        confirm_layout = QVBoxLayout(confirm_group)
        layout.addWidget(confirm_group)
        
        confirm_instruction = QLabel(
            "To proceed, type exactly (case sensitive):\nDESTROY ALL DATA"
        )
        confirm_instruction.setStyleSheet("color: #f39c12; font-weight: bold;")
        confirm_layout.addWidget(confirm_instruction)
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Type the confirmation phrase here...")
        self.confirm_input.textChanged.connect(self._check_confirmation)
        confirm_layout.addWidget(self.confirm_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setStyleSheet(StyleManager.get_button_style("primary"))
        button_layout.addWidget(self.cancel_button)
        
        button_layout.addStretch()
        
        self.confirm_button = QPushButton("🗑️ DESTROY ALL DATA")
        self.confirm_button.clicked.connect(self._confirm_reset)
        self.confirm_button.setStyleSheet(StyleManager.get_button_style("danger"))
        self.confirm_button.setEnabled(False)
        button_layout.addWidget(self.confirm_button)
        
        # Focus on input
        self.confirm_input.setFocus()
    
    def _check_confirmation(self):
        """Check if the confirmation phrase is correct."""
        text = self.confirm_input.text()
        correct = text == "DESTROY ALL DATA"
        
        self.confirm_button.setEnabled(correct)
        
        if correct:
            self.confirm_button.setText("🗑️ DESTROY ALL DATA")
        else:
            self.confirm_button.setText("🗑️ Enter Confirmation")
    
    def _confirm_reset(self):
        """Confirm the reset operation."""
        self.confirmed = True
        self.accept()
    
    def is_confirmed(self) -> bool:
        """Check if reset was confirmed."""
        return self.confirmed
