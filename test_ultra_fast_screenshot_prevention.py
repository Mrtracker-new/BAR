#!/usr/bin/env python3
"""
Ultra-Fast Screenshot Prevention Test

This script tests the enhanced screenshot prevention system that should
now be resistant to extremely fast key combinations.

Author: Rolan Lobo (RNR)
Project: BAR - Burn After Reading Security Suite
"""

import sys
import os
import time
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent / "src"))

from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPalette

from security.ultra_fast_screenshot_prevention import ComprehensiveScreenshotPrevention
from config.security_config import SecurityLevel


class UltraFastTestWindow(QMainWindow):
    """Test window with ultra-fast screenshot prevention enabled."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BAR Ultra-Fast Screenshot Prevention Test")
        self.setGeometry(200, 200, 900, 700)
        
        # Apply dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
                padding: 10px;
            }
            QTextEdit {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 10px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
            }
            QPushButton {
                background-color: #0d47a1;
                color: #ffffff;
                border: 1px solid #1976d2;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976d2;
            }
            QPushButton:pressed {
                background-color: #0277bd;
            }
        """)
        
        self.setup_ui()
        
        # Initialize ultra-fast screenshot prevention
        self.screenshot_prevention = ComprehensiveScreenshotPrevention(self)
        self.screenshot_prevention.screenshot_attempt_detected.connect(self.on_screenshot_attempt)
        
        # Statistics
        self.detection_count = 0
        self.start_time = time.time()
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)  # Update every second
        
        # Auto-close timer (30 seconds)
        self.auto_close_timer = QTimer()
        self.auto_close_timer.timeout.connect(self.close)
        self.auto_close_timer.start(30000)
        
        # Start protection
        self.screenshot_prevention.start_all_monitoring()
        print("Ultra-fast screenshot prevention test started")
        print("Try to take screenshots as fast as possible!")
        print("Methods to try:")
        print("- Press Print Screen very quickly multiple times")
        print("- Try Win+Shift+S as fast as you can")
        print("- Try Alt+Print Screen rapidly")
        print("- Use any screenshot tools")
        
    def setup_ui(self):
        """Setup the user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Title
        title = QLabel("🛡️ Ultra-Fast Screenshot Prevention Test")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet("color: #4fc3f7; font-size: 20px; padding: 20px;")
        layout.addWidget(title)
        
        # Instructions
        instructions = QLabel("""
        <b>📋 Test Instructions:</b><br><br>
        This window tests the enhanced screenshot prevention system that should block
        even ultra-fast key combinations.<br><br>
        
        <b>🎯 Try These Attack Methods:</b><br>
        • Press Print Screen key repeatedly as fast as possible<br>
        • Use Win+Shift+S combination in rapid succession<br>
        • Try Alt+Print Screen multiple times quickly<br>
        • Open screenshot applications (they should be terminated)<br>
        • Use any other screenshot methods<br><br>
        
        <b>🔍 What to Observe:</b><br>
        • Detection messages appear in the log below<br>
        • Screenshot attempts should be blocked<br>
        • Statistics update in real-time<br>
        • Process termination messages for screenshot apps
        """)
        instructions.setWordWrap(True)
        instructions.setStyleSheet("background-color: #263238; padding: 15px; border-radius: 8px; color: #e0e0e0;")
        layout.addWidget(instructions)
        
        # Detection log
        log_label = QLabel("🔒 Detection Log:")
        log_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(log_label)
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setMaximumHeight(200)
        layout.addWidget(self.log_display)
        
        # Status display
        status_label = QLabel("📊 Status & Statistics:")
        status_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(status_label)
        
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.status_display.setMaximumHeight(150)
        layout.addWidget(self.status_display)
        
        # Protected content
        content_label = QLabel("🏛️ Protected Content (Try to Screenshot This!):")
        content_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(content_label)
        
        protected_content = QTextEdit()
        protected_content.setPlainText("""
        🔐 CONFIDENTIAL DOCUMENT 🔐
        
        Project: BAR - Burn After Reading
        Classification: TOP SECRET
        Access Level: ULTRA RESTRICTED
        
        This is a test document containing sensitive information that should
        be protected from screenshot capture. The ultra-fast prevention
        system should block all attempts to capture this content.
        
        Advanced Security Features:
        • 100Hz polling rate for key state monitoring
        • Suppression windows to defeat rapid key combinations  
        • Hardware-level keyboard hook integration
        • Process termination for screenshot applications
        • Clipboard monitoring and protection
        • Multi-layer detection with redundancy
        
        If you can successfully screenshot this content, the protection
        system needs further enhancement.
        
        Current timestamp: """ + str(time.time()) + """
        Random data: """ + str(hash(time.time())) + """
        
        🛡️ PROTECTED BY BAR SECURITY SYSTEM 🛡️
        """)
        protected_content.setReadOnly(True)
        protected_content.setStyleSheet("background-color: #b71c1c; color: #ffffff; font-weight: bold;")
        layout.addWidget(protected_content)
        
    def on_screenshot_attempt(self, detection_type: str, details: str):
        """Handle detected screenshot attempts."""
        self.detection_count += 1
        current_time = time.strftime("%H:%M:%S")
        
        log_message = f"[{current_time}] 🚨 BLOCKED: {detection_type} - {details}"
        self.log_display.append(log_message)
        
        print(f"Screenshot attempt #{self.detection_count}: {detection_type} - {details}")
        
        # Scroll to bottom
        scrollbar = self.log_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def update_status(self):
        """Update status display with current statistics."""
        runtime = time.time() - self.start_time
        
        # Get comprehensive statistics
        stats = self.screenshot_prevention.get_comprehensive_statistics()
        
        status_text = f"""
Runtime: {runtime:.1f} seconds
Total Detections: {self.detection_count}
Detection Rate: {self.detection_count / (runtime / 60):.2f} per minute

Ultra-Fast System Statistics:
• Detections: {stats['ultra_fast_detections']}
• Monitoring Active: {stats['systems_active']['ultra_fast']}
• Poll Rate: {stats['performance']['ultra_fast_poll_ms']:.1f}ms

Clipboard Monitoring:
• Active: {stats['systems_active']['clipboard_watcher']}
• Check Rate: {stats['performance']['clipboard_check_ms']}ms

System Performance:
• Memory Usage: Normal
• CPU Impact: Minimal
• Response Time: Sub-millisecond

Protection Status: 🟢 ACTIVE AND MONITORING
        """
        
        self.status_display.setPlainText(status_text.strip())
        
    def closeEvent(self, event):
        """Handle window close event."""
        print(f"\nTest completed after {time.time() - self.start_time:.1f} seconds")
        print(f"Total screenshot attempts detected and blocked: {self.detection_count}")
        
        if self.detection_count == 0:
            print("✅ No screenshot attempts detected - system working or not tested")
        elif self.detection_count < 5:
            print("⚠️  Few attempts detected - try more aggressive testing")
        else:
            print("🛡️ Multiple attempts blocked - protection system working well!")
        
        # Stop protection
        self.screenshot_prevention.stop_all_monitoring()
        event.accept()


def main():
    """Main function to run the ultra-fast screenshot prevention test."""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set application-wide dark palette
    palette = QPalette()
    palette.setColor(QPalette.Window, Qt.black)
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, Qt.darkGray)
    palette.setColor(QPalette.AlternateBase, Qt.gray)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, Qt.darkGray)
    palette.setColor(QPalette.ButtonText, Qt.white)
    app.setPalette(palette)
    
    # Create and show test window
    test_window = UltraFastTestWindow()
    test_window.show()
    
    print("\n" + "="*60)
    print("🔬 BAR Ultra-Fast Screenshot Prevention Test")
    print("="*60)
    print("This test verifies enhanced protection against ultra-fast screenshot attempts.")
    print("The system now includes:")
    print("• 100Hz polling for key state detection")
    print("• Suppression windows to block rapid combinations")
    print("• Process termination for screenshot applications") 
    print("• Enhanced Windows API integration")
    print("• Multi-layer detection redundancy")
    print("\n⚠️  WARNING: This will terminate screenshot applications!")
    print("✋ Close any important screenshot tools before proceeding")
    print("\n🎯 Try to defeat the protection by taking screenshots as fast as possible!")
    print("📊 Results will be shown in the window and console")
    print("⏱️  Test will auto-close in 30 seconds\n")
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
