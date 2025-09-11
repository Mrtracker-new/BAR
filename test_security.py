#!/usr/bin/env python3
"""
Test script for the enhanced security system.
This helps verify that the security features work correctly without being overly aggressive.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
from PyQt5.QtCore import QTimer
from src.security.advanced_screen_protection import AdvancedScreenProtectionManager
from src.config.security_config import SecurityLevel


class TestWindow(QMainWindow):
    """Test window for security system."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BAR Security Test - View-Only Content")
        self.setGeometry(100, 100, 800, 600)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Add test content
        title_label = QLabel("🔒 CONFIDENTIAL DOCUMENT - VIEW ONLY")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: red; text-align: center; margin: 20px;")
        layout.addWidget(title_label)
        
        content_label = QLabel("""
        This is a test of the BAR security system.
        
        If you're in development mode, you should see:
        - "Development environment detected - using relaxed security settings"
        - "Process monitoring disabled in development environment"
        
        Try the following to test security:
        1. Press Print Screen (should be blocked)
        2. Try Win+Shift+S (should be blocked)
        3. Try to copy this text (should be blocked)
        4. Switch to another window (content should blur)
        
        The system should NOT complain about:
        - Visual Studio Code
        - Development tools
        - System processes
        
        This window will auto-close in 30 seconds for security testing.
        """)
        content_label.setStyleSheet("font-size: 14px; margin: 20px; line-height: 1.5;")
        content_label.setWordWrap(True)
        layout.addWidget(content_label)
        
        # Initialize security protection
        self.init_security()
        
        # Auto-close timer for testing
        self.close_timer = QTimer()
        self.close_timer.timeout.connect(self.close)
        self.close_timer.setSingleShot(True)
        self.close_timer.start(30000)  # 30 seconds
    
    def init_security(self):
        """Initialize the security system."""
        try:
            # Create log directory
            log_dir = os.path.join(os.path.expanduser("~"), ".bar", "security_logs")
            os.makedirs(log_dir, exist_ok=True)
            
            # Initialize security protection with development security level
            self.protection_manager = AdvancedScreenProtectionManager(
                username="TestUser",
                protected_widget=self,
                log_directory="test_logs",
                security_level=SecurityLevel.DEVELOPMENT  # Use development-friendly settings
            )
                
            # Start protection
            self.security_manager.start_protection()
            
            print("✅ Security system initialized successfully")
            print(f"🔧 Development mode: {self.security_manager.is_development_env}")
            print(f"📊 Max suspicious score: {self.security_manager.max_suspicious_score}")
            
        except Exception as e:
            print(f"❌ Failed to initialize security: {e}")
            import traceback
            traceback.print_exc()
    
    def closeEvent(self, event):
        """Clean up when closing."""
        try:
            if hasattr(self, 'security_manager'):
                print("🛑 Stopping security protection...")
                self.security_manager.stop_protection()
                print("✅ Security protection stopped")
        except Exception as e:
            print(f"⚠️ Error stopping security: {e}")
        
        event.accept()


def main():
    """Main function to run the security test."""
    print("🧪 BAR Security System Test")
    print("=" * 50)
    
    # Check if required modules are available
    try:
        import psutil
        print("✅ psutil module available")
    except ImportError:
        print("❌ psutil module not available - some features may not work")
        print("   Install with: pip install psutil")
    
    try:
        if sys.platform == 'win32':
            import win32gui
            import win32api
            print("✅ Windows API modules available")
    except ImportError:
        print("⚠️ Windows API modules not available - some features may not work")
        print("   Install with: pip install pywin32")
    
    # Create application
    app = QApplication(sys.argv)
    
    # Create and show test window
    window = TestWindow()
    window.show()
    
    print("\n🔍 Security Test Window Opened")
    print("⌨️ Try pressing Print Screen or Win+Shift+S to test blocking")
    print("📋 Try copying text to test clipboard protection")
    print("🖱️ Try switching windows to test focus monitoring")
    print("⏰ Window will auto-close in 30 seconds")
    
    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
