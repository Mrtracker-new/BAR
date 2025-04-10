import os
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QFormLayout, QWidget, QCheckBox, QSpinBox, QDateTimeEdit,
    QFileDialog, QTabWidget, QTextEdit, QGroupBox
)
from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtGui import QFont


class FileDialog(QDialog):
    """Dialog for adding or importing secure files."""
    
    def __init__(self, default_security: Dict[str, Any], parent=None, 
                 filename: str = None, file_content: bytes = None):
        """Initialize the file dialog.
        
        Args:
            default_security: Default security settings
            parent: The parent widget
            filename: Optional filename for imported files
            file_content: Optional file content for imported files
        """
        super().__init__(parent)
        
        self.default_security = default_security
        self.filename = filename
        self.file_content = file_content
        self.file_path = None
        
        self.setWindowTitle("Add Secure File")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)
        self.setModal(True)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("Add Secure File")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        # File information
        file_group = QGroupBox("File Information")
        file_layout = QFormLayout(file_group)
        layout.addWidget(file_group)
        
        # Filename field
        self.filename_label = QLabel("Filename:")
        self.filename_edit = QLineEdit()
        if self.filename:
            self.filename_edit.setText(self.filename)
        file_layout.addRow(self.filename_label, self.filename_edit)
        
        # File selection (only if not importing)
        if not self.file_content:
            file_select_layout = QHBoxLayout()
            self.file_path_edit = QLineEdit()
            self.file_path_edit.setReadOnly(True)
            self.file_path_edit.setPlaceholderText("Select a file...")
            file_select_layout.addWidget(self.file_path_edit)
            
            self.browse_button = QPushButton("Browse")
            self.browse_button.clicked.connect(self._browse_file)
            file_select_layout.addWidget(self.browse_button)
            
            file_layout.addRow("Select File:", file_select_layout)
        
        # Security settings
        security_group = QGroupBox("Security Settings")
        security_layout = QFormLayout(security_group)
        layout.addWidget(security_group)
        
        # Expiration time
        self.expiration_check = QCheckBox("Enable")
        self.expiration_datetime = QDateTimeEdit()
        self.expiration_datetime.setDateTime(QDateTime.currentDateTime().addDays(7))
        self.expiration_datetime.setCalendarPopup(True)
        self.expiration_datetime.setEnabled(False)
        self.expiration_check.toggled.connect(self.expiration_datetime.setEnabled)
        
        # Set default if provided
        if "expiration_time" in self.default_security and self.default_security["expiration_time"]:
            self.expiration_check.setChecked(True)
            self.expiration_datetime.setDateTime(
                QDateTime.fromString(self.default_security["expiration_time"], Qt.ISODate))
        
        expiration_layout = QHBoxLayout()
        expiration_layout.addWidget(self.expiration_check)
        expiration_layout.addWidget(self.expiration_datetime)
        security_layout.addRow("Expiration Time:", expiration_layout)
        
        # Max access count
        self.access_check = QCheckBox("Enable")
        self.access_spin = QSpinBox()
        self.access_spin.setRange(1, 100)
        self.access_spin.setValue(3)
        self.access_spin.setEnabled(False)
        self.access_check.toggled.connect(self.access_spin.setEnabled)
        
        # Set default if provided
        if "max_access_count" in self.default_security and self.default_security["max_access_count"]:
            self.access_check.setChecked(True)
            self.access_spin.setValue(self.default_security["max_access_count"])
        
        access_layout = QHBoxLayout()
        access_layout.addWidget(self.access_check)
        access_layout.addWidget(self.access_spin)
        security_layout.addRow("Max Access Count:", access_layout)
        
        # Deadman switch
        self.deadman_check = QCheckBox("Enable")
        self.deadman_spin = QSpinBox()
        self.deadman_spin.setRange(1, 365)
        self.deadman_spin.setValue(30)
        self.deadman_spin.setEnabled(False)
        self.deadman_check.toggled.connect(self.deadman_spin.setEnabled)
        
        # Set default if provided
        if "deadman_switch" in self.default_security and self.default_security["deadman_switch"]:
            self.deadman_check.setChecked(True)
            self.deadman_spin.setValue(self.default_security["deadman_switch"])
        
        deadman_layout = QHBoxLayout()
        deadman_layout.addWidget(self.deadman_check)
        deadman_layout.addWidget(self.deadman_spin)
        security_layout.addRow("Deadman Switch (days):", deadman_layout)
        
        # Password protection
        password_group = QGroupBox("Password Protection")
        password_layout = QFormLayout(password_group)
        layout.addWidget(password_group)
        
        # Password field
        self.password_label = QLabel("Password:")
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter a strong password")
        self.password_edit.setEchoMode(QLineEdit.Password)
        password_layout.addRow(self.password_label, self.password_edit)
        
        # Confirm password field
        self.confirm_password_label = QLabel("Confirm Password:")
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setPlaceholderText("Confirm your password")
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        password_layout.addRow(self.confirm_password_label, self.confirm_password_edit)
        
        # Security note
        security_note = QLabel("Note: This password is used to encrypt your file. "
                              "If you forget it, your data cannot be recovered.")
        security_note.setWordWrap(True)
        layout.addWidget(security_note)
        
        # Buttons
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        self.add_button = QPushButton("Add File")
        self.add_button.setDefault(True)
        self.add_button.clicked.connect(self._add_file)
        button_layout.addWidget(self.add_button)
    
    def _browse_file(self):
        """Open a file dialog to select a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)")
        
        if file_path:
            self.file_path = file_path
            self.file_path_edit.setText(file_path)
            
            # Set filename if not already set
            if not self.filename_edit.text():
                self.filename_edit.setText(os.path.basename(file_path))
    
    def _add_file(self):
        """Validate input and accept the dialog."""
        # Check filename
        filename = self.filename_edit.text().strip()
        if not filename:
            QMessageBox.warning(self, "Missing Information", "Please enter a filename.")
            return
        
        # Check file selection (if not importing)
        if not self.file_content and not self.file_path:
            QMessageBox.warning(self, "Missing Information", "Please select a file.")
            return
        
        # Check password
        password = self.password_edit.text()
        confirm_password = self.confirm_password_edit.text()
        
        if not password:
            QMessageBox.warning(self, "Missing Information", "Please enter a password.")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            self.confirm_password_edit.clear()
            return
        
        # Check password strength
        if len(password) < 8:
            result = QMessageBox.question(
                self, "Weak Password", 
                "Your password is weak. This may compromise the security of your file. "
                "Do you want to continue anyway?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if result == QMessageBox.No:
                return
        
        # If we're not importing, read the file content
        if not self.file_content and self.file_path:
            try:
                with open(self.file_path, "rb") as f:
                    self.file_content = f.read()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read file: {str(e)}")
                return
        
        # Accept the dialog
        self.accept()
    
    def get_filename(self) -> str:
        """Get the filename.
        
        Returns:
            The filename
        """
        return self.filename_edit.text().strip()
    
    def get_file_data(self) -> bytes:
        """Get the file data.
        
        Returns:
            The file data
        """
        return self.file_content
    
    def get_password(self) -> str:
        """Get the password.
        
        Returns:
            The password
        """
        return self.password_edit.text()
    
    def get_security_settings(self) -> Dict[str, Any]:
        """Get the security settings.
        
        Returns:
            Dictionary containing security settings
        """
        security_settings = {}
        
        # Expiration time
        if self.expiration_check.isChecked():
            security_settings["expiration_time"] = self.expiration_datetime.dateTime().toString(Qt.ISODate)
        else:
            security_settings["expiration_time"] = None
        
        # Max access count
        if self.access_check.isChecked():
            security_settings["max_access_count"] = self.access_spin.value()
        else:
            security_settings["max_access_count"] = None
        
        # Deadman switch
        if self.deadman_check.isChecked():
            security_settings["deadman_switch"] = self.deadman_spin.value()
        else:
            security_settings["deadman_switch"] = None
        
        return security_settings