import sys
from typing import Optional

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QFormLayout, QWidget, QCheckBox, QGroupBox, QTextEdit,
    QProgressBar, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap, QFont, QPalette, QColor

from .styles import StyleManager


class SetupWorker(QThread):
    """Worker thread for device initialization to prevent UI blocking."""
    
    finished = pyqtSignal(bool, str)  # success, message
    progress = pyqtSignal(int)  # progress percentage
    
    def __init__(self, device_auth, password, device_name):
        super().__init__()
        self.device_auth = device_auth
        self.password = password
        self.device_name = device_name
    
    def run(self):
        try:
            self.progress.emit(20)
            
            # Initialize device (this may take a while due to high PBKDF2 iterations)
            success, message = self.device_auth.initialize_device(self.password, self.device_name)
            
            self.progress.emit(100)
            self.finished.emit(success, message)
            
        except Exception as e:
            self.progress.emit(100)
            self.finished.emit(False, f"Setup failed: {str(e)}")


class DeviceSetupDialog(QDialog):
    """Dialog for setting up the device on first run."""
    
    def __init__(self, device_auth, parent=None):
        """Initialize the device setup dialog.
        
        Args:
            device_auth: DeviceAuthManager instance
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.device_auth = device_auth
        self.setup_successful = False
        
        self.setWindowTitle("BAR - Device Setup")
        self.setMinimumWidth(600)
        self.setMinimumHeight(700)
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
        """)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Title section
        title_label = QLabel("🔒 BAR - Device Setup")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #e74c3c; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Secure Single-User Authentication")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_font = QFont()
        subtitle_font.setPointSize(12)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setStyleSheet("color: #eff0f1; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        # Security notice
        notice_group = QGroupBox("⚠️ IMPORTANT SECURITY NOTICE")
        notice_layout = QVBoxLayout(notice_group)
        layout.addWidget(notice_group)
        
        notice_text = QTextEdit()
        notice_text.setReadOnly(True)
        notice_text.setMaximumHeight(120)
        notice_text.setPlainText(
            "BAR uses SINGLE-USER DEVICE-BOUND authentication:\n\n"
            "• ONE user per device (no multi-user accounts)\n"
            "• Password is bound to THIS hardware (cannot be transferred)\n"
            "• NO PASSWORD RECOVERY - forgot password = complete data wipe\n"
            "• All data is encrypted with military-grade security\n"
            "• Device reset PERMANENTLY DESTROYS all files"
        )
        notice_text.setStyleSheet(
            "QTextEdit { background-color: #3c2e2e; border: 1px solid #e74c3c; color: #ffffff; }"
        )
        notice_layout.addWidget(notice_text)
        
        # Setup form
        setup_group = QGroupBox("Device Configuration")
        setup_layout = QVBoxLayout(setup_group)
        layout.addWidget(setup_group)
        
        # Form layout
        form_layout = QFormLayout()
        setup_layout.addLayout(form_layout)
        
        # Device name
        self.device_name_label = QLabel("Device Name (optional):")
        self.device_name_edit = QLineEdit()
        self.device_name_edit.setPlaceholderText("e.g., John-Laptop, Work-PC (leave empty for auto-generated)")
        form_layout.addRow(self.device_name_label, self.device_name_edit)
        
        # Master password
        self.password_label = QLabel("Master Password:")
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter a strong master password")
        self.password_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow(self.password_label, self.password_edit)
        
        # Password requirements
        requirements_label = QLabel(
            "Password Requirements:\n"
            "• Minimum 12 characters\n"
            "• At least one lowercase letter\n"
            "• At least one uppercase letter\n"
            "• At least one number\n"
            "• At least one special character (!@#$%^&*etc)"
        )
        requirements_label.setStyleSheet("color: #95a5a6; font-size: 10pt; margin: 5px;")
        setup_layout.addWidget(requirements_label)
        
        # Confirm password
        self.confirm_label = QLabel("Confirm Password:")
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setPlaceholderText("Confirm your master password")
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow(self.confirm_label, self.confirm_edit)
        
        # Show password checkbox
        self.show_password_check = QCheckBox("Show password")
        self.show_password_check.toggled.connect(self._toggle_password_visibility)
        setup_layout.addWidget(self.show_password_check)
        
        # Acknowledgment
        ack_group = QGroupBox("⚡ Acknowledgment")
        ack_layout = QVBoxLayout(ack_group)
        layout.addWidget(ack_group)
        
        self.acknowledge_check = QCheckBox(
            "I understand that forgetting my master password will result in \n"
            "PERMANENT DATA LOSS with no recovery option."
        )
        self.acknowledge_check.setStyleSheet("color: #e74c3c; font-weight: bold;")
        ack_layout.addWidget(self.acknowledge_check)
        
        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)
        
        self.cancel_button = QPushButton("Exit Application")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setStyleSheet(StyleManager.get_button_style())
        button_layout.addWidget(self.cancel_button)
        
        button_layout.addStretch()
        
        self.setup_button = QPushButton("🔐 Initialize Device")
        self.setup_button.clicked.connect(self._setup_device)
        self.setup_button.setStyleSheet(StyleManager.get_button_style("danger"))
        self.setup_button.setEnabled(False)
        button_layout.addWidget(self.setup_button)
        
        # Connect signals
        self.password_edit.textChanged.connect(self._check_form_valid)
        self.confirm_edit.textChanged.connect(self._check_form_valid)
        self.acknowledge_check.toggled.connect(self._check_form_valid)
        
        # Focus on password field
        self.password_edit.setFocus()
    
    def _toggle_password_visibility(self, checked):
        """Toggle password visibility."""
        if checked:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.confirm_edit.setEchoMode(QLineEdit.Normal)
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.confirm_edit.setEchoMode(QLineEdit.Password)
    
    def _check_form_valid(self, *args):
        """Check if the form is valid and enable/disable setup button.
        
        Args:
            *args: Signal arguments (ignored)
        """
        password = self.password_edit.text()
        confirm = self.confirm_edit.text()
        acknowledged = self.acknowledge_check.isChecked()
        
        # Check if passwords match and requirements are met
        passwords_match = password and password == confirm
        password_strong = self._validate_password_strength(password)
        
        valid = passwords_match and password_strong and acknowledged
        self.setup_button.setEnabled(bool(valid))
        
        # Update button text with validation feedback
        if not password:
            self.setup_button.setText("🔐 Enter Master Password")
        elif not password_strong:
            self.setup_button.setText("❌ Password Too Weak")
        elif not passwords_match:
            self.setup_button.setText("❌ Passwords Don't Match")
        elif not acknowledged:
            self.setup_button.setText("⚠️ Please Acknowledge")
        else:
            self.setup_button.setText("🔐 Initialize Device")
    
    def _validate_password_strength(self, password: str) -> bool:
        """Validate password meets security requirements."""
        if len(password) < 12:
            return False
        
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_lower and has_upper and has_digit and has_special
    
    def _setup_device(self):
        """Initialize device setup."""
        password = self.password_edit.text()
        device_name = self.device_name_edit.text().strip() or None
        
        # Final confirmation
        reply = QMessageBox.question(
            self,
            "Final Confirmation",
            "Are you absolutely sure you want to initialize this device?\n\n"
            "This will create a hardware-bound authentication system.\n"
            "There is NO WAY to recover your data if you forget the password.\n\n"
            "Do you want to proceed?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Disable UI during setup
        self.setup_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        
        # Start setup in worker thread
        self.setup_worker = SetupWorker(self.device_auth, password, device_name)
        self.setup_worker.progress.connect(self.progress_bar.setValue)
        self.setup_worker.finished.connect(self._on_setup_finished)
        self.setup_worker.start()
    
    def _on_setup_finished(self, success: bool, message: str):
        """Handle setup completion."""
        self.progress_bar.setVisible(False)
        
        if success:
            self.setup_successful = True
            QMessageBox.information(
                self,
                "Device Setup Complete",
                f"{message}\n\n"
                "Your device is now ready for secure operation.\n"
                "Remember: Your master password cannot be recovered!"
            )
            self.accept()
        else:
            QMessageBox.critical(self, "Setup Failed", message)
            # Re-enable UI
            self.setup_button.setEnabled(True)
            self.cancel_button.setEnabled(True)
    
    def was_setup_successful(self) -> bool:
        """Check if setup was completed successfully."""
        return self.setup_successful
