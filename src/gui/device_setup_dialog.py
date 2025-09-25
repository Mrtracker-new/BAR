import sys
from typing import Optional

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QFormLayout, QWidget, QCheckBox, QGroupBox, QTextEdit,
    QProgressBar, QFrame, QComboBox, QButtonGroup, QRadioButton, QScrollArea, QApplication
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap, QFont, QPalette, QColor

from .styles import StyleManager
from src.security.device_auth_manager import SecurityLevel
from src.security.secure_memory import (
    SecureString, create_secure_string, secure_compare,
    get_secure_memory_manager, MemoryProtectionLevel
)


class SecurePasswordLineEdit(QLineEdit):
    """Enhanced QLineEdit that uses secure memory for password storage.
    
    Per R006 - Memory Security: All password data is stored in SecureString
    and automatically cleared when the widget is destroyed.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._secure_password = create_secure_string()
        self.textChanged.connect(self._on_text_changed)
    
    def _on_text_changed(self, text: str):
        """Update secure storage when text changes."""
        try:
            # Store new password in secure memory
            self._secure_password.set_value(text)
        except Exception as e:
            # Log error but don't expose sensitive information
            import logging
            logging.getLogger("SecurePasswordLineEdit").warning(f"Password update error: {type(e).__name__}")
    
    def get_secure_password(self) -> SecureString:
        """Get the password as a SecureString.
        
        Returns:
            SecureString containing the current password
        """
        # Update secure storage with current text
        current_text = self.text()
        if current_text != self._secure_password.get_value():
            self._secure_password.set_value(current_text)
        return self._secure_password
    
    def clear_secure(self):
        """Securely clear the password from memory and UI."""
        # Clear UI
        self.clear()
        # Clear secure storage
        self._secure_password.clear()
    
    def __del__(self):
        """Ensure secure cleanup on deletion."""
        try:
            if hasattr(self, '_secure_password') and self._secure_password:
                self._secure_password.clear()
        except Exception:
            pass  # Ignore errors during cleanup


class SetupWorker(QThread):
    """Worker thread for device initialization to prevent UI blocking.
    
    Uses secure memory for password handling throughout the initialization process.
    """
    
    finished = pyqtSignal(bool, str)  # success, message
    progress = pyqtSignal(int)  # progress percentage
    
    def __init__(self, device_auth, secure_password: SecureString, device_name: Optional[str], security_level: str):
        super().__init__()
        self.device_auth = device_auth
        # Store secure password with maximum protection
        self._secure_password = create_secure_string()
        self._secure_password.set_value(secure_password.get_value())
        self.device_name = device_name
        self.security_level = security_level
    
    def run(self):
        try:
            self.progress.emit(20)
            
            # Get password from secure storage for initialization
            password_value = self._secure_password.get_value()
            
            # Initialize device (this may take a while due to high PBKDF2 iterations)
            success, message = self.device_auth.initialize_device(password_value, self.device_name, self.security_level)
            
            self.progress.emit(100)
            self.finished.emit(success, message)
            
        except Exception as e:
            self.progress.emit(100)
            self.finished.emit(False, f"Setup failed: {str(e)}")
        finally:
            # Always clear sensitive data
            self._cleanup_sensitive_data()
    
    def _cleanup_sensitive_data(self):
        """Securely clear all sensitive data from worker thread."""
        try:
            if hasattr(self, '_secure_password') and self._secure_password:
                self._secure_password.clear()
        except Exception:
            pass  # Ignore errors during cleanup
    
    def __del__(self):
        """Ensure cleanup on deletion."""
        self._cleanup_sensitive_data()


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
        self.setMinimumWidth(680)  # Increased from 580
        self.setMaximumWidth(750)  # Increased from 650
        # Remove fixed height to allow dialog to size itself
        self.setModal(True)
        self.setSizeGripEnabled(False)  # Disable resizing for consistent layout
        
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
        self._adjust_size_to_screen()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setSpacing(8)  # Reduce spacing between elements
        layout.setContentsMargins(20, 15, 20, 15)  # Increased side margins for better text spacing
        
        # Title section
        title_label = QLabel("🔒 BAR - Device Setup")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)  # Reduced from 18
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #e74c3c; margin-bottom: 5px;")
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Secure Single-User Authentication")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)  # Reduced from 12
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setStyleSheet("color: #eff0f1; margin-bottom: 10px;")  # Reduced margin
        layout.addWidget(subtitle_label)
        
        # Security notice
        notice_group = QGroupBox("⚠️ IMPORTANT SECURITY NOTICE")
        notice_layout = QVBoxLayout(notice_group)
        layout.addWidget(notice_group)
        
        notice_text = QTextEdit()
        notice_text.setReadOnly(True)
        notice_text.setMaximumHeight(90)  # Reduced height
        notice_text.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # Add scrollbar if needed
        notice_text.setPlainText(
            "BAR uses SINGLE-USER DEVICE-BOUND authentication:\n"
            "• ONE user per device (no multi-user accounts)\n"
            "• Password is bound to THIS hardware (cannot be transferred)\n"
            "• NO PASSWORD RECOVERY - forgot password = complete data wipe\n"
            "• All data is encrypted with military-grade security"
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
        
        # Master password - using secure password field
        self.password_label = QLabel("Master Password:")
        self.password_edit = SecurePasswordLineEdit()
        self.password_edit.setPlaceholderText("Enter a strong master password")
        self.password_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow(self.password_label, self.password_edit)
        
        # Password requirements
        requirements_label = QLabel(
            "Requirements: 12+ chars, upper+lower+number+special (!@#$%^&*etc)"
        )
        requirements_label.setStyleSheet("color: #95a5a6; font-size: 9pt; margin: 2px;")
        requirements_label.setWordWrap(True)
        setup_layout.addWidget(requirements_label)
        
        # Confirm password - using secure password field
        self.confirm_label = QLabel("Confirm Password:")
        self.confirm_edit = SecurePasswordLineEdit()
        self.confirm_edit.setPlaceholderText("Confirm your master password")
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow(self.confirm_label, self.confirm_edit)
        
        # Show password checkbox
        self.show_password_check = QCheckBox("Show password")
        self.show_password_check.toggled.connect(self._toggle_password_visibility)
        setup_layout.addWidget(self.show_password_check)
        
        # Security level selection
        security_group = QGroupBox("🛡️ Security Level Configuration")
        security_layout = QVBoxLayout(security_group)
        layout.addWidget(security_group)
        
        security_info_label = QLabel(
            "Choose your authentication security level. This setting cannot be changed after initialization."
        )
        security_info_label.setStyleSheet("color: #f39c12; font-style: italic; margin: 5px; font-size: 9pt;")
        security_info_label.setWordWrap(True)
        security_info_label.setMaximumWidth(700)  # Prevent text from extending beyond dialog
        security_layout.addWidget(security_info_label)
        
        # Security level radio buttons
        self.security_button_group = QButtonGroup()
        
        # Standard security
        self.standard_radio = QRadioButton("🔒 Standard Security")
        self.standard_radio.setChecked(True)  # Default selection
        self.security_button_group.addButton(self.standard_radio, 0)
        security_layout.addWidget(self.standard_radio)
        
        standard_desc = QLabel("Standard security with temporary lockouts after 5 failed attempts")
        standard_desc.setStyleSheet("color: #95a5a6; font-size: 8pt; margin-left: 20px; margin-bottom: 8px;")
        standard_desc.setWordWrap(True)
        security_layout.addWidget(standard_desc)
        
        # High security
        self.high_radio = QRadioButton("🔐 High Security")
        self.security_button_group.addButton(self.high_radio, 1)
        security_layout.addWidget(self.high_radio)
        
        high_desc = QLabel("High security with progressive lockouts and 24-hour maximum")
        high_desc.setStyleSheet("color: #95a5a6; font-size: 8pt; margin-left: 20px; margin-bottom: 8px;")
        high_desc.setWordWrap(True)
        security_layout.addWidget(high_desc)
        
        # Maximum security
        self.maximum_radio = QRadioButton("🚨 Maximum Security (DATA DESTRUCTION)")
        self.security_button_group.addButton(self.maximum_radio, 2)
        security_layout.addWidget(self.maximum_radio)
        
        maximum_desc = QLabel("Maximum security with data corruption after 3 failed attempts")
        maximum_desc.setStyleSheet("color: #e74c3c; font-size: 8pt; font-weight: bold; margin-left: 20px; margin-bottom: 8px;")
        maximum_desc.setWordWrap(True)
        security_layout.addWidget(maximum_desc)
        
        # Warning for maximum security
        max_warning = QLabel(
            "⚠️ WARNING: Maximum security will PERMANENTLY DESTROY all your data after 3 failed login attempts. "
            "This action cannot be undone and there is no recovery method!"
        )
        max_warning.setStyleSheet(
            "background-color: #3c2e2e; border: 2px solid #e74c3c; border-radius: 4px; "
            "color: #ffffff; font-weight: bold; padding: 8px; margin: 5px; font-size: 9pt;"
        )
        max_warning.setWordWrap(True)
        max_warning.setMaximumWidth(700)  # Ensure it doesn't exceed dialog width
        security_layout.addWidget(max_warning)
        
        # Connect security level change
        self.security_button_group.buttonToggled.connect(self._on_security_level_changed)
        
        # Acknowledgment
        ack_group = QGroupBox("⚡ Acknowledgment")
        ack_layout = QVBoxLayout(ack_group)
        layout.addWidget(ack_group)
        
        # Use a shorter acknowledgment text to avoid wrapping issues
        self.acknowledge_check = QCheckBox(
            "I understand that forgetting my master password will result in PERMANENT DATA LOSS."
        )
        self.acknowledge_check.setStyleSheet("color: #e74c3c; font-weight: bold; font-size: 9pt;")
        self.acknowledge_check.setMaximumWidth(700)  # Prevent text from extending beyond dialog
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
    
    def _adjust_size_to_screen(self):
        """Adjust dialog size to fit available screen space."""
        try:
            # Get available screen geometry
            screen = QApplication.primaryScreen()
            screen_geometry = screen.availableGeometry()
            
            # Calculate maximum dialog dimensions (leave some padding)
            max_height = screen_geometry.height() - 100  # 50px padding top and bottom
            max_width = screen_geometry.width() - 100   # 50px padding left and right
            
            # Ensure dialog doesn't exceed screen width
            if self.width() > max_width:
                self.setMaximumWidth(max_width)
            
            # Get the dialog's preferred size
            self.adjustSize()
            current_size = self.size()
            
            # If dialog is too tall, limit its height and make it scrollable
            if current_size.height() > max_height:
                self.setMaximumHeight(max_height)
                
                # Make the main layout scrollable by wrapping it
                self._make_scrollable()
            
            # Center the dialog on screen
            self.move(
                screen_geometry.center().x() - self.width() // 2,
                screen_geometry.center().y() - self.height() // 2
            )
            
        except Exception as e:
            # Fallback: just center on screen
            import logging
            logging.getLogger("DeviceSetupDialog").warning(f"Size adjustment error: {e}")
    
    def _make_scrollable(self):
        """Make the dialog content scrollable if it's too tall for the screen."""
        try:
            # Get the current layout and its contents
            current_layout = self.layout()
            
            # Create a widget to hold the current content
            content_widget = QWidget()
            content_widget.setLayout(current_layout)
            
            # Create a scroll area
            scroll_area = QScrollArea()
            scroll_area.setWidget(content_widget)
            scroll_area.setWidgetResizable(True)
            scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            
            # Apply styling to scroll area
            scroll_area.setStyleSheet("""
                QScrollArea {
                    border: none;
                    background-color: #2c2c2c;
                }
                QScrollBar:vertical {
                    background-color: #3c3c3c;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #555555;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #666666;
                }
            """)
            
            # Set the scroll area as the main content
            new_layout = QVBoxLayout(self)
            new_layout.setContentsMargins(0, 0, 0, 0)
            new_layout.addWidget(scroll_area)
            
        except Exception as e:
            # If making scrollable fails, just continue with original layout
            import logging
            logging.getLogger("DeviceSetupDialog").warning(f"Scrollable setup error: {e}")
    
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
        
        Uses secure comparison for password validation.
        
        Args:
            *args: Signal arguments (ignored)
        """
        try:
            # Get passwords from secure fields
            password = self.password_edit.text()
            confirm = self.confirm_edit.text()
            acknowledged = self.acknowledge_check.isChecked()
            
            # Check if passwords match using secure comparison
            passwords_match = password and secure_compare(password, confirm)
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
                
        except Exception as e:
            # Log error but don't expose sensitive information
            import logging
            logging.getLogger("DeviceSetupDialog").warning(f"Form validation error: {type(e).__name__}")
            self.setup_button.setEnabled(False)
            self.setup_button.setText("❌ Validation Error")
    
    def _validate_password_strength(self, password: str) -> bool:
        """Validate password meets security requirements."""
        if len(password) < 12:
            return False
        
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_lower and has_upper and has_digit and has_special
    
    def _get_selected_security_level(self) -> str:
        """Get the selected security level.
        
        Returns:
            Selected security level string
        """
        if self.standard_radio.isChecked():
            return SecurityLevel.STANDARD
        elif self.high_radio.isChecked():
            return SecurityLevel.HIGH
        elif self.maximum_radio.isChecked():
            return SecurityLevel.MAXIMUM
        else:
            return SecurityLevel.STANDARD  # Fallback
    
    def _on_security_level_changed(self, button, checked):
        """Handle security level selection change."""
        if not checked:
            return
            
        # Show additional confirmation for maximum security
        if button == self.maximum_radio:
            reply = QMessageBox.question(
                self,
                "⚠️ Maximum Security Confirmation",
                "You have selected MAXIMUM SECURITY level.\n\n"
                "This means:\n"
                "• After 3 failed login attempts, ALL DATA will be PERMANENTLY DESTROYED\n"
                "• There is NO recovery method\n"
                "• This action CANNOT be undone\n\n"
                "Are you absolutely sure you want this level of protection?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                # Revert to standard security
                self.standard_radio.setChecked(True)
                return
        
        # Update form validation
        self._check_form_valid()
    
    def _setup_device(self):
        """Initialize device setup using secure password handling."""
        try:
            # Get secure password from secure field
            secure_password = self.password_edit.get_secure_password()
            device_name = self.device_name_edit.text().strip() or None
            security_level = self._get_selected_security_level()
            
            # Create security-specific confirmation message
            security_warning = ""
            if security_level == SecurityLevel.MAXIMUM:
                security_warning = "\n\n⚠️ MAXIMUM SECURITY WARNING:\nAfter 3 failed login attempts, ALL DATA will be PERMANENTLY DESTROYED!"
            elif security_level == SecurityLevel.HIGH:
                security_warning = "\n\nHigh security mode: Progressive lockouts with extended durations."
            
            # Final confirmation
            reply = QMessageBox.question(
                self,
                "Final Confirmation",
                f"Are you absolutely sure you want to initialize this device?\n\n"
                f"Security Level: {security_level.upper()}\n"
                f"This will create a hardware-bound authentication system.\n"
                f"There is NO WAY to recover your data if you forget the password.{security_warning}\n\n"
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
            
            # Start setup in worker thread with secure password
            self.setup_worker = SetupWorker(self.device_auth, secure_password, device_name, security_level)
            self.setup_worker.progress.connect(self.progress_bar.setValue)
            self.setup_worker.finished.connect(self._on_setup_finished)
            self.setup_worker.start()
            
        except Exception as e:
            import logging
            logging.getLogger("DeviceSetupDialog").error(f"Setup initiation error: {type(e).__name__}")
            QMessageBox.critical(self, "Setup Error", "Failed to start device setup. Please try again.")
            self._re_enable_ui()
    
    def _on_setup_finished(self, success: bool, message: str):
        """Handle setup completion with secure cleanup."""
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
            # Clear sensitive data before closing
            self._cleanup_sensitive_data()
            self.accept()
        else:
            QMessageBox.critical(self, "Setup Failed", message)
            self._re_enable_ui()
    
    def _re_enable_ui(self):
        """Re-enable UI elements after failed setup."""
        self.setup_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        # Re-check form validity
        self._check_form_valid()
    
    def was_setup_successful(self) -> bool:
        """Check if setup was completed successfully."""
        return self.setup_successful
    
    def _cleanup_sensitive_data(self):
        """Securely clear all sensitive data from the dialog.
        
        Per R006 - Memory Security: Must clear sensitive data immediately after use.
        """
        try:
            # Clear secure password fields
            if hasattr(self, 'password_edit'):
                self.password_edit.clear_secure()
            
            if hasattr(self, 'confirm_edit'):
                self.confirm_edit.clear_secure()
            
            # Force cleanup of any secure objects created by this dialog
            get_secure_memory_manager().cleanup_all()
            
        except Exception as e:
            import logging
            logging.getLogger("DeviceSetupDialog").warning(f"Cleanup error: {type(e).__name__}")
    
    def closeEvent(self, event):
        """Handle dialog close with secure cleanup."""
        self._cleanup_sensitive_data()
        super().closeEvent(event)
    
    def reject(self):
        """Handle dialog rejection with secure cleanup."""
        self._cleanup_sensitive_data()
        super().reject()
    
    def accept(self):
        """Handle dialog acceptance with secure cleanup."""
        # Note: cleanup is handled in _on_setup_finished for successful setup
        if not self.setup_successful:
            self._cleanup_sensitive_data()
        super().accept()
    
    def __del__(self):
        """Ensure cleanup on deletion."""
        try:
            self._cleanup_sensitive_data()
        except Exception:
            pass  # Ignore errors during cleanup
