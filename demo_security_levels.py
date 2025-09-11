#!/usr/bin/env python3
"""
Security Levels Demo for BAR Application

This script demonstrates the different security levels available in the BAR
security configuration system and shows how to use them.

Author: Rolan Lobo (RNR)
Project: BAR - Burn After Reading Security Suite
"""

import sys
import os
import time
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent / "src"))

try:
    from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QComboBox, QTextEdit
    from PyQt5.QtCore import Qt, QTimer
    from PyQt5.QtGui import QFont, QPixmap, QPalette
except ImportError as e:
    print(f"PyQt5 not available: {e}")
    print("Please install PyQt5: pip install PyQt5")
    sys.exit(1)

from config.security_config import SecurityLevel, security_config, get_security_config


class SecurityLevelDemo(QMainWindow):
    """Demo window showing security level configurations."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BAR Security Levels Demo")
        self.setGeometry(100, 100, 800, 600)
        
        # Apply dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
                padding: 5px;
            }
            QTextEdit {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 10px;
                font-family: 'Courier New', monospace;
            }
            QComboBox {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 5px;
            }
            QPushButton {
                background-color: #4a4a4a;
                color: #ffffff;
                border: 1px solid #666666;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5a5a5a;
            }
        """)
        
        self.setup_ui()
        self.load_security_levels()
        
    def setup_ui(self):
        """Setup the user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Title
        title = QLabel("BAR Security Configuration Levels")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Select a security level to view its configuration:")
        desc.setFont(QFont("Arial", 10))
        layout.addWidget(desc)
        
        # Security level selector
        self.level_combo = QComboBox()
        layout.addWidget(self.level_combo)
        
        # Configuration display
        self.config_display = QTextEdit()
        self.config_display.setReadOnly(True)
        layout.addWidget(self.config_display)
        
        # Environment detection info
        self.env_info = QLabel()
        self.env_info.setFont(QFont("Arial", 9))
        self.env_info.setStyleSheet("color: #aaaaaa; font-style: italic;")
        layout.addWidget(self.env_info)
        
        # Connect signals
        self.level_combo.currentTextChanged.connect(self.on_level_changed)
        
    def load_security_levels(self):
        """Load available security levels into combo box."""
        levels = security_config.get_available_levels()
        
        for level, description in levels.items():
            display_text = f"{level.value.title()} - {description}"
            self.level_combo.addItem(display_text, level)
        
        # Show auto-detected level
        auto_level = security_config.detect_security_level()
        auto_config = get_security_config()
        
        env_text = f"Auto-detected security level: {auto_level.value.title()}"
        self.env_info.setText(env_text)
        
        # Set combo to auto-detected level
        for i in range(self.level_combo.count()):
            if self.level_combo.itemData(i) == auto_level:
                self.level_combo.setCurrentIndex(i)
                break
        
    def on_level_changed(self, text):
        """Handle security level selection change."""
        if not text:
            return
            
        current_level = self.level_combo.currentData()
        if not current_level:
            return
            
        config = get_security_config(current_level)
        self.display_configuration(current_level, config)
        
    def display_configuration(self, level: SecurityLevel, config: dict):
        """Display the configuration for a security level."""
        display_text = f"Security Level: {level.value.upper()}\n"
        display_text += "=" * 50 + "\n\n"
        
        display_text += f"Description: {config['description']}\n\n"
        
        display_text += "Core Settings:\n"
        display_text += f"  Max Suspicious Score: {config['max_suspicious_score']}\n"
        display_text += f"  Max Focus Loss Count: {config['max_focus_loss_count']}\n"
        display_text += f"  Check Interval: {config['check_interval']} seconds\n"
        display_text += f"  Aggressive Mode: {'Yes' if config['aggressive_mode'] else 'No'}\n\n"
        
        display_text += "Feature Toggles:\n"
        display_text += f"  Process Monitoring: {'Enabled' if config['process_monitoring_enabled'] else 'Disabled'}\n"
        display_text += f"  Clipboard Protection: {'Enabled' if config['clipboard_protection_enabled'] else 'Disabled'}\n"
        display_text += f"  Watermarking: {'Enabled' if config['watermark_enabled'] else 'Disabled'}\n"
        display_text += f"  Focus Monitoring: {'Enabled' if config['focus_monitoring_enabled'] else 'Disabled'}\n"
        display_text += f"  Overlay Protection: {'Enabled' if config['overlay_protection_enabled'] else 'Disabled'}\n"
        display_text += f"  Screenshot Blocking: {'Enabled' if config['screenshot_blocking_enabled'] else 'Disabled'}\n\n"
        
        # Add usage recommendations
        display_text += "Usage Recommendations:\n"
        if level == SecurityLevel.DEVELOPMENT:
            display_text += "  • Ideal for development and testing\n"
            display_text += "  • Minimal interference with development tools\n"
            display_text += "  • Process monitoring disabled to prevent false alarms\n"
        elif level == SecurityLevel.BASIC:
            display_text += "  • Suitable for general use and low-sensitivity content\n"
            display_text += "  • Balanced protection without being intrusive\n"
            display_text += "  • Good for casual document viewing\n"
        elif level == SecurityLevel.STANDARD:
            display_text += "  • Default level for business use\n"
            display_text += "  • All protection features enabled\n"
            display_text += "  • Suitable for most corporate environments\n"
        elif level == SecurityLevel.HIGH:
            display_text += "  • Enhanced security for sensitive content\n"
            display_text += "  • Strict monitoring and rapid response\n"
            display_text += "  • Recommended for corporate and government use\n"
        elif level == SecurityLevel.MAXIMUM:
            display_text += "  • Maximum security for highly classified content\n"
            display_text += "  • Very strict monitoring and immediate response\n"
            display_text += "  • Use only for the most sensitive documents\n"
        
        display_text += "\n" + "=" * 50 + "\n"
        display_text += "Full Configuration (JSON):\n\n"
        
        # Format config as JSON-like structure
        import json
        config_copy = config.copy()
        config_copy.pop('description', None)  # Remove description for cleaner JSON
        display_text += json.dumps(config_copy, indent=2)
        
        self.config_display.setPlainText(display_text)


def main():
    """Main function to run the security levels demo."""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for better dark theme support
    
    # Set application-wide dark palette
    palette = QPalette()
    palette.setColor(QPalette.Window, Qt.darkGray)
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, Qt.black)
    palette.setColor(QPalette.AlternateBase, Qt.darkGray)
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, Qt.darkGray)
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, Qt.blue)
    palette.setColor(QPalette.Highlight, Qt.blue)
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    
    # Create and show demo window
    demo = SecurityLevelDemo()
    demo.show()
    
    print("BAR Security Levels Demo")
    print("=" * 40)
    print("This demo shows the different security levels available")
    print("in the BAR security configuration system.")
    print("\nFeatures demonstrated:")
    print("• Automatic environment detection")
    print("• Security level configurations")
    print("• Feature toggle explanations")
    print("• Usage recommendations")
    print("\nClose the window to exit.")
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
