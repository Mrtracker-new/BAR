import sys
from typing import Optional

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QFormLayout, QWidget, QCheckBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap, QFont

from ..user_manager.user_manager import UserManager


class LoginDialog(QDialog):
    """Dialog for user login."""
    
    def __init__(self, user_manager: UserManager, parent=None):
        """Initialize the login dialog.
        
        Args:
            user_manager: The user account manager
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.user_manager = user_manager
        self.username = ""
        self.register_requested = False
        
        self.setWindowTitle("BAR - Login")
        self.setMinimumWidth(350)
        self.setModal(True)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("BAR - Burn After Reading")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Secure File Management")
        subtitle_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle_label)
        
        layout.addSpacing(20)
        
        # Login form
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # Username field
        self.username_label = QLabel("Username:")
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter your username")
        form_layout.addRow(self.username_label, self.username_edit)
        
        # Password field
        self.password_label = QLabel("Password:")
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter your password")
        self.password_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow(self.password_label, self.password_edit)
        
        layout.addSpacing(10)
        
        # Buttons
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)
        
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self._request_register)
        button_layout.addWidget(self.register_button)
        
        self.login_button = QPushButton("Login")
        self.login_button.setDefault(True)
        self.login_button.clicked.connect(self._login)
        button_layout.addWidget(self.login_button)
        
        # Connect enter key to login
        self.username_edit.returnPressed.connect(self._focus_password)
        self.password_edit.returnPressed.connect(self._login)
    
    def _focus_password(self):
        """Focus the password field."""
        self.password_edit.setFocus()
    
    def _login(self):
        """Attempt to log in with the provided credentials."""
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Login Failed", "Please enter both username and password.")
            return
        
        if self.user_manager.authenticate_user(username, password):
            self.username = username
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")
            self.password_edit.clear()
            self.password_edit.setFocus()
    
    def _request_register(self):
        """Request to show the registration dialog."""
        self.register_requested = True
        self.reject()
    
    def get_username(self) -> str:
        """Get the authenticated username.
        
        Returns:
            The authenticated username
        """
        return self.username