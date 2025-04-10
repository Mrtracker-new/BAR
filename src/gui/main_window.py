import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QMessageBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QSpinBox, QDateTimeEdit, QCheckBox, QDialog,
    QFormLayout, QGroupBox, QStackedWidget, QSplitter, QFrame, QAction, QMenu,
    QToolBar, QStatusBar, QSystemTrayIcon, QApplication, QStyle, QInputDialog, QTextEdit
)
from PyQt5.QtCore import Qt, QTimer, QDateTime, pyqtSignal, QSize, QEvent
from PyQt5.QtGui import QIcon, QPixmap, QFont, QPalette, QColor

from ..config.config_manager import ConfigManager
from ..crypto.encryption import EncryptionManager
from ..file_manager.file_manager import FileManager
from ..user_manager.user_manager import UserManager
from .login_dialog import LoginDialog
from .register_dialog import RegisterDialog
from .file_dialog import FileDialog
from .settings_dialog import SettingsDialog


class MainWindow(QMainWindow):
    """Main window for the BAR application."""
    
    def __init__(self, config_manager: ConfigManager, file_manager: FileManager, 
                 user_manager: UserManager, parent=None):
        """Initialize the main window.
        
        Args:
            config_manager: The application configuration manager
            file_manager: The secure file manager
            user_manager: The user account manager
            parent: The parent widget
        """
        super().__init__(parent)
        
        # Store managers
        self.config_manager = config_manager
        self.file_manager = file_manager
        self.user_manager = user_manager
        
        # Set up window properties
        self.setWindowTitle("BAR - Burn After Reading")
        self.setMinimumSize(900, 600)
        
        # Initialize UI components
        self.current_user = None
        self.auto_lock_timer = QTimer(self)
        self.auto_lock_timer.timeout.connect(self.lock_application)
        
        # Set up the UI
        self._setup_ui()
        self._apply_theme()
        
        # Show login dialog
        self._show_login_dialog()
    
    def _setup_ui(self):
        """Set up the user interface."""
        # Create central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        self.main_layout.addWidget(self.stacked_widget)
        
        # Create login screen
        self.login_screen = QWidget()
        self.stacked_widget.addWidget(self.login_screen)
        
        # Create main application screen
        self.app_screen = QWidget()
        self.app_layout = QVBoxLayout(self.app_screen)
        self.stacked_widget.addWidget(self.app_screen)
        
        # Create tab widget for different sections
        self.tab_widget = QTabWidget()
        self.app_layout.addWidget(self.tab_widget)
        
        # Create file management tab
        self.files_tab = QWidget()
        self.files_layout = QVBoxLayout(self.files_tab)
        self.tab_widget.addTab(self.files_tab, "Files")
        
        # Create file table
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(6)
        self.file_table.setHorizontalHeaderLabels(["Filename", "Created", "Last Accessed", 
                                                 "Access Count", "Expiration", "Actions"])
        self.file_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.files_layout.addWidget(self.file_table)
        
        # Create file action buttons
        self.file_buttons_layout = QHBoxLayout()
        self.files_layout.addLayout(self.file_buttons_layout)
        
        self.add_file_button = QPushButton("Add File")
        self.add_file_button.clicked.connect(self._add_file)
        self.file_buttons_layout.addWidget(self.add_file_button)
        
        self.refresh_files_button = QPushButton("Refresh")
        self.refresh_files_button.clicked.connect(self._refresh_files)
        self.file_buttons_layout.addWidget(self.refresh_files_button)
        
        # Create settings tab
        self.settings_tab = QWidget()
        self.settings_layout = QVBoxLayout(self.settings_tab)
        self.tab_widget.addTab(self.settings_tab, "Settings")
        
        # Create settings form
        self.settings_form = QFormLayout()
        self.settings_layout.addLayout(self.settings_form)
        
        # Theme selection
        self.theme_label = QLabel("Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "System"])
        self.theme_combo.currentTextChanged.connect(self._change_theme)
        self.settings_form.addRow(self.theme_label, self.theme_combo)
        
        # Auto-lock timeout
        self.lock_label = QLabel("Auto-lock after (minutes):")
        self.lock_spin = QSpinBox()
        self.lock_spin.setRange(1, 60)
        self.lock_spin.setValue(self.config_manager.get_value("auto_lock_timeout", 5))
        self.lock_spin.valueChanged.connect(self._change_lock_timeout)
        self.settings_form.addRow(self.lock_label, self.lock_spin)
        
        # Default security settings group
        self.security_group = QGroupBox("Default Security Settings")
        self.security_layout = QFormLayout(self.security_group)
        self.settings_layout.addWidget(self.security_group)
        
        # Expiration time
        self.expiration_label = QLabel("Default expiration time:")
        self.expiration_check = QCheckBox("Enable")
        self.expiration_datetime = QDateTimeEdit()
        self.expiration_datetime.setDateTime(QDateTime.currentDateTime().addDays(7))
        self.expiration_datetime.setCalendarPopup(True)
        self.expiration_layout = QHBoxLayout()
        self.expiration_layout.addWidget(self.expiration_check)
        self.expiration_layout.addWidget(self.expiration_datetime)
        self.security_layout.addRow(self.expiration_label, self.expiration_layout)
        
        # Max access count
        self.access_label = QLabel("Default max access count:")
        self.access_check = QCheckBox("Enable")
        self.access_spin = QSpinBox()
        self.access_spin.setRange(1, 100)
        self.access_spin.setValue(3)
        self.access_layout = QHBoxLayout()
        self.access_layout.addWidget(self.access_check)
        self.access_layout.addWidget(self.access_spin)
        self.security_layout.addRow(self.access_label, self.access_layout)
        
        # Deadman switch
        self.deadman_label = QLabel("Default deadman switch (days):")
        self.deadman_check = QCheckBox("Enable")
        self.deadman_spin = QSpinBox()
        self.deadman_spin.setRange(1, 365)
        self.deadman_spin.setValue(30)
        self.deadman_layout = QHBoxLayout()
        self.deadman_layout.addWidget(self.deadman_check)
        self.deadman_layout.addWidget(self.deadman_spin)
        self.security_layout.addRow(self.deadman_label, self.deadman_layout)
        
        # Save settings button
        self.save_settings_button = QPushButton("Save Settings")
        self.save_settings_button.clicked.connect(self._save_settings)
        self.settings_layout.addWidget(self.save_settings_button)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create menu bar
        self.menu_bar = self.menuBar()
        
        # File menu
        self.file_menu = self.menu_bar.addMenu("&File")
        
        self.new_file_action = QAction("&New File", self)
        self.new_file_action.triggered.connect(self._add_file)
        self.file_menu.addAction(self.new_file_action)
        
        # Import submenu
        self.import_menu = QMenu("&Import", self)
        
        self.import_regular_action = QAction("Import &Regular File", self)
        self.import_regular_action.triggered.connect(self._import_regular_file)
        self.import_menu.addAction(self.import_regular_action)
        
        self.import_portable_action = QAction("Import &Portable Encrypted File", self)
        self.import_portable_action.triggered.connect(self._import_portable_file)
        self.import_menu.addAction(self.import_portable_action)
        
        self.file_menu.addMenu(self.import_menu)
        
        self.file_menu.addSeparator()
        
        self.lock_action = QAction("&Lock Application", self)
        self.lock_action.triggered.connect(self.lock_application)
        self.file_menu.addAction(self.lock_action)
        
        self.exit_action = QAction("E&xit", self)
        self.exit_action.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_action)
        
        # User menu
        self.user_menu = self.menu_bar.addMenu("&User")
        
        self.change_password_action = QAction("Change &Password", self)
        self.change_password_action.triggered.connect(self._change_password)
        self.user_menu.addAction(self.change_password_action)
        
        self.logout_action = QAction("&Logout", self)
        self.logout_action.triggered.connect(self._logout)
        self.user_menu.addAction(self.logout_action)
        
        # Help menu
        self.help_menu = self.menu_bar.addMenu("&Help")
        
        self.about_action = QAction("&About", self)
        self.about_action.triggered.connect(self._show_about)
        self.help_menu.addAction(self.about_action)
    
    def _apply_theme(self):
        """Apply the selected theme to the application."""
        theme = self.config_manager.get_value("theme", "dark").lower()
        
        if theme == "dark":
            # Dark theme
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, Qt.black)
            QApplication.setPalette(palette)
        elif theme == "light":
            # Light theme (default)
            QApplication.setPalette(QApplication.style().standardPalette())
        else:
            # System theme
            QApplication.setPalette(QApplication.style().standardPalette())
    
    def _show_login_dialog(self):
        """Show the login dialog."""
        login_dialog = LoginDialog(self.user_manager, self)
        result = login_dialog.exec_()
        
        if result == QDialog.Accepted:
            self.current_user = login_dialog.get_username()
            self._refresh_files()
            self.stacked_widget.setCurrentWidget(self.app_screen)
            self.status_bar.showMessage(f"Logged in as {self.current_user}")
            self._start_auto_lock_timer()
        else:
            # Check if we need to show registration dialog
            if login_dialog.register_requested:
                self._show_register_dialog()
            else:
                # Exit if login was cancelled
                QApplication.quit()
                sys.exit(0)  # Ensure application exits completely
    
    def _show_register_dialog(self):
        """Show the registration dialog."""
        register_dialog = RegisterDialog(self.user_manager, self)
        result = register_dialog.exec_()
        
        if result == QDialog.Accepted:
            self.current_user = register_dialog.get_username()
            self.stacked_widget.setCurrentWidget(self.app_screen)
            self.status_bar.showMessage(f"Registered and logged in as {self.current_user}")
            self._start_auto_lock_timer()
        else:
            # Show login dialog again
            self._show_login_dialog()
    
    def _start_auto_lock_timer(self):
        """Start the auto-lock timer."""
        timeout = self.config_manager.get_value("auto_lock_timeout", 5)
        self.auto_lock_timer.start(timeout * 60 * 1000)  # Convert minutes to milliseconds
    
    def _reset_auto_lock_timer(self):
        """Reset the auto-lock timer."""
        if self.auto_lock_timer.isActive():
            self.auto_lock_timer.stop()
            self._start_auto_lock_timer()
    
    def lock_application(self):
        """Lock the application and show the login dialog."""
        if self.current_user:
            self.auto_lock_timer.stop()
            self.current_user = None
            self.stacked_widget.setCurrentWidget(self.login_screen)
            self._show_login_dialog()
    
    def _logout(self):
        """Log out the current user."""
        self.lock_application()
    
    def _refresh_files(self):
        """Refresh the file list."""
        if not self.current_user:
            return
        
        # Clear the table
        self.file_table.setRowCount(0)
        
        # Get the list of files
        files = self.file_manager.list_files()
        
        # Populate the table
        for i, file_data in enumerate(files):
            self.file_table.insertRow(i)
            
            # Filename
            self.file_table.setItem(i, 0, QTableWidgetItem(file_data["filename"]))
            
            # Creation time
            creation_time = datetime.fromisoformat(file_data["creation_time"])
            self.file_table.setItem(i, 1, QTableWidgetItem(creation_time.strftime("%Y-%m-%d %H:%M")))
            
            # Last accessed
            last_accessed = datetime.fromisoformat(file_data["last_accessed"])
            self.file_table.setItem(i, 2, QTableWidgetItem(last_accessed.strftime("%Y-%m-%d %H:%M")))
            
            # Access count
            self.file_table.setItem(i, 3, QTableWidgetItem(str(file_data["access_count"])))
            
            # Expiration
            expiration = file_data["security"]["expiration_time"]
            if expiration:
                expiration_time = datetime.fromisoformat(expiration)
                expiration_text = expiration_time.strftime("%Y-%m-%d %H:%M")
            else:
                expiration_text = "Never"
            self.file_table.setItem(i, 4, QTableWidgetItem(expiration_text))
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(0, 0, 0, 0)
            
            open_button = QPushButton("Open")
            open_button.setProperty("file_id", file_data["file_id"])
            open_button.clicked.connect(self._open_file)
            actions_layout.addWidget(open_button)
            
            export_button = QPushButton("Export")
            export_button.setProperty("file_id", file_data["file_id"])
            export_button.clicked.connect(self._export_file)
            actions_layout.addWidget(export_button)
            
            delete_button = QPushButton("Delete")
            delete_button.setProperty("file_id", file_data["file_id"])
            delete_button.clicked.connect(self._delete_file)
            actions_layout.addWidget(delete_button)
            
            self.file_table.setCellWidget(i, 5, actions_widget)
    
    def _add_file(self):
        """Add a new secure file."""
        if not self.current_user:
            return
        
        # Get default security settings
        default_security = {}
        
        if self.expiration_check.isChecked():
            default_security["expiration_time"] = self.expiration_datetime.dateTime().toString(Qt.ISODate)
        
        if self.access_check.isChecked():
            default_security["max_access_count"] = self.access_spin.value()
        
        if self.deadman_check.isChecked():
            default_security["deadman_switch"] = self.deadman_spin.value()
        
        # Show file dialog
        file_dialog = FileDialog(default_security, self)
        if file_dialog.exec_() == QDialog.Accepted:
            file_data = file_dialog.get_file_data()
            security_settings = file_dialog.get_security_settings()
            password = file_dialog.get_password()
            
            try:
                file_id = self.file_manager.create_secure_file(
                    file_data, file_dialog.get_filename(), password, security_settings)
                
                QMessageBox.information(self, "File Added", 
                                      f"File '{file_dialog.get_filename()}' has been securely stored.")
                
                self._refresh_files()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add file: {str(e)}")
    
    def _open_file(self):
        """Open a secure file."""
        if not self.current_user:
            return
        
        # Get the file ID from the sender button
        sender = self.sender()
        file_id = sender.property("file_id")
        
        # Ask for password
        password, ok = QInputDialog.getText(
            self, "Enter Password", "Enter the file password:", QLineEdit.Password)
        
        if ok and password:
            try:
                # Access the file
                file_content, metadata = self.file_manager.access_file(file_id, password)
                
                # Show file content
                self._show_file_content(file_content, metadata)
                
                # Refresh the file list to update access count
                self._refresh_files()
            except ValueError as e:
                QMessageBox.critical(self, "Error", str(e))
            except FileNotFoundError:
                QMessageBox.critical(self, "Error", "File not found. It may have been deleted.")
                self._refresh_files()
    
    def _show_file_content(self, content: bytes, metadata: Dict[str, Any]):
        """Show the content of a file."""
        # Create a dialog to display the file content
        dialog = QDialog(self)
        dialog.setWindowTitle(f"File: {metadata['filename']}")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        # File info
        info_layout = QFormLayout()
        layout.addLayout(info_layout)
        
        info_layout.addRow("Filename:", QLabel(metadata["filename"]))
        
        creation_time = datetime.fromisoformat(metadata["creation_time"])
        info_layout.addRow("Created:", QLabel(creation_time.strftime("%Y-%m-%d %H:%M")))
        
        last_accessed = datetime.fromisoformat(metadata["last_accessed"])
        info_layout.addRow("Last Accessed:", QLabel(last_accessed.strftime("%Y-%m-%d %H:%M")))
        
        info_layout.addRow("Access Count:", QLabel(str(metadata["access_count"])))
        
        # Security info
        security_group = QGroupBox("Security Settings")
        security_layout = QFormLayout(security_group)
        layout.addWidget(security_group)
        
        expiration = metadata["security"]["expiration_time"]
        if expiration:
            expiration_time = datetime.fromisoformat(expiration)
            expiration_text = expiration_time.strftime("%Y-%m-%d %H:%M")
        else:
            expiration_text = "Never"
        security_layout.addRow("Expiration:", QLabel(expiration_text))
        
        max_access = metadata["security"]["max_access_count"]
        if max_access:
            max_access_text = f"{metadata['access_count']} of {max_access}"
        else:
            max_access_text = "Unlimited"
        security_layout.addRow("Access Count:", QLabel(max_access_text))
        
        deadman = metadata["security"]["deadman_switch"]
        if deadman:
            deadman_text = f"{deadman} days of inactivity"
        else:
            deadman_text = "Disabled"
        security_layout.addRow("Deadman Switch:", QLabel(deadman_text))
        
        # File content
        content_label = QLabel("Content:")
        layout.addWidget(content_label)
        
        # Display content based on file type
        try:
            # Try to decode as text
            text_content = content.decode('utf-8')
            content_edit = QTextEdit()
            content_edit.setPlainText(text_content)
            content_edit.setReadOnly(True)
            layout.addWidget(content_edit)
        except UnicodeDecodeError:
            # Binary content
            binary_label = QLabel("Binary content cannot be displayed")
            layout.addWidget(binary_label)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)
        
        dialog.exec_()
    
    def _export_file(self):
        """Export a secure file."""
        if not self.current_user:
            return
        
        # Get the file ID from the sender button
        sender = self.sender()
        file_id = sender.property("file_id")
        
        # Ask for export type
        export_options = ["Export Original File", "Export Portable Encrypted File"]
        export_type, ok = QInputDialog.getItem(
            self, "Export Type", "Select export type:", export_options, 0, False)
        
        if not ok:
            return
        
        # Ask for password
        password, ok = QInputDialog.getText(
            self, "Enter Password", "Enter the file password:", QLineEdit.Password)
        
        if ok and password:
            try:
                if export_type == "Export Original File":
                    self._export_original_file(file_id, password)
                else:  # Export Portable Encrypted File
                    self._export_portable_file(file_id, password)
                
                # Refresh the file list to update access count
                self._refresh_files()
            except ValueError as e:
                QMessageBox.critical(self, "Error", str(e))
            except FileNotFoundError:
                QMessageBox.critical(self, "Error", "File not found. It may have been deleted.")
                self._refresh_files()
    
    def _export_original_file(self, file_id: str, password: str):
        """Export the original decrypted file."""
        try:
            # Access the file
            file_content, metadata = self.file_manager.access_file(file_id, password)
            
            # Ask for export location
            export_path, _ = QFileDialog.getSaveFileName(
                self, "Export File", metadata["filename"], "All Files (*)")
            
            if export_path:
                # Write the file content
                with open(export_path, "wb") as f:
                    f.write(file_content)
                
                QMessageBox.information(self, "File Exported", 
                                      f"File '{metadata['filename']}' has been exported.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export file: {str(e)}")
    
    def _export_portable_file(self, file_id: str, password: str):
        """Export a portable encrypted file that can be imported on another device."""
        try:
            # Get file metadata for the filename
            metadata_list = self.file_manager.list_files()
            filename = ""
            for metadata in metadata_list:
                if metadata["file_id"] == file_id:
                    filename = metadata["filename"]
                    break
            
            # Ask for export location
            export_path, _ = QFileDialog.getSaveFileName(
                self, "Export Portable File", 
                f"{filename}.bar" if filename else "secure_file.bar", 
                "BAR Files (*.bar);;All Files (*)")
            
            if export_path:
                # Export the portable file
                self.file_manager.export_portable_file(file_id, password, export_path)
                
                QMessageBox.information(
                    self, 
                    "Portable File Exported", 
                    f"Portable encrypted file has been exported to '{export_path}'."
                    "\n\nYou can now transfer this file to another device and import it using the BAR application."
                )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export portable file: {str(e)}")
    
    def _import_file(self):
        """Import a file."""
        if not self.current_user:
            return
        
        # Ask for import type
        import_options = ["Import Regular File", "Import Portable Encrypted File"]
        import_type, ok = QInputDialog.getItem(
            self, "Import Type", "Select import type:", import_options, 0, False)
        
        if not ok:
            return
        
        if import_type == "Import Regular File":
            self._import_regular_file()
        else:  # Import Portable Encrypted File
            self._import_portable_file()
    
    def _import_regular_file(self):
        """Import a regular file and encrypt it."""
        # Ask for file to import
        import_path, _ = QFileDialog.getOpenFileName(
            self, "Import File", "", "All Files (*)")
        
        if import_path:
            # Get the file content
            with open(import_path, "rb") as f:
                file_content = f.read()
            
            # Get the filename
            filename = os.path.basename(import_path)
            
            # Show file dialog for security settings
            file_dialog = FileDialog({}, self, filename=filename, file_content=file_content)
            if file_dialog.exec_() == QDialog.Accepted:
                security_settings = file_dialog.get_security_settings()
                password = file_dialog.get_password()
                
                try:
                    file_id = self.file_manager.create_secure_file(
                        file_content, file_dialog.get_filename(), password, security_settings)
                    
                    QMessageBox.information(self, "File Imported", 
                                          f"File '{file_dialog.get_filename()}' has been securely imported.")
                    
                    self._refresh_files()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to import file: {str(e)}")
    
    def _import_portable_file(self):
        """Import a portable encrypted file from another device."""
        # Ask for file to import
        import_path, _ = QFileDialog.getOpenFileName(
            self, "Import Portable File", "", "BAR Files (*.bar);;All Files (*)")
        
        if import_path:
            # Ask for password
            password, ok = QInputDialog.getText(
                self, "Enter Password", "Enter the file password:", QLineEdit.Password)
            
            if ok and password:
                try:
                    # Import the portable file
                    file_id = self.file_manager.import_portable_file(import_path, password)
                    
                    QMessageBox.information(
                        self, 
                        "Portable File Imported", 
                        "The portable encrypted file has been successfully imported."
                    )
                    
                    self._refresh_files()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to import portable file: {str(e)}")
    
    def _delete_file(self):
        """Delete a secure file."""
        if not self.current_user:
            return
        
        # Get the file ID from the sender button
        sender = self.sender()
        file_id = sender.property("file_id")
        
        # Confirm deletion
        reply = QMessageBox.question(
            self, "Confirm Deletion", 
            "Are you sure you want to delete this file? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                self.file_manager.delete_file(file_id)
                QMessageBox.information(self, "File Deleted", "File has been permanently deleted.")
                self._refresh_files()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete file: {str(e)}")
    
    def _change_theme(self, theme_name):
        """Change the application theme."""
        theme = theme_name.lower()
        self.config_manager.set_value("theme", theme)
        self._apply_theme()
    
    def _change_lock_timeout(self, value):
        """Change the auto-lock timeout."""
        self.config_manager.set_value("auto_lock_timeout", value)
        if self.auto_lock_timer.isActive():
            self._reset_auto_lock_timer()
    
    def _save_settings(self):
        """Save the application settings."""
        # Get security settings
        security_settings = {}
        
        if self.expiration_check.isChecked():
            security_settings["expiration_time"] = self.expiration_datetime.dateTime().toString(Qt.ISODate)
        else:
            security_settings["expiration_time"] = None
        
        if self.access_check.isChecked():
            security_settings["max_access_count"] = self.access_spin.value()
        else:
            security_settings["max_access_count"] = None
        
        if self.deadman_check.isChecked():
            security_settings["deadman_switch"] = self.deadman_spin.value()
        else:
            security_settings["deadman_switch"] = None
        
        # Update config
        self.config_manager.update_config({
            "default_security": security_settings
        })
        
        # Update user settings
        if self.current_user:
            self.user_manager.update_user_settings(self.current_user, {
                "default_security": security_settings
            })
        
        QMessageBox.information(self, "Settings Saved", "Your settings have been saved.")
    
    def _change_password(self):
        """Change the current user's password."""
        if not self.current_user:
            return
        
        # Ask for current password
        current_password, ok = QInputDialog.getText(
            self, "Current Password", "Enter your current password:", QLineEdit.Password)

    def _show_about(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About BAR - Burn After Reading",
            "BAR - Burn After Reading v1.0.0\n\n"
            "A secure file management application with self-destructing files.\n\n"
            "© 2023 BAR Security Team"
        )