#!/usr/bin/env python3
"""
Ultimate Screenshot Prevention Test

This script tests the most comprehensive screenshot prevention system combining:
- Hardware-level keyboard hooks
- Ultra-fast polling detection  
- Window-level DWM protections
- Clipboard monitoring and clearing
- Process termination
- Screen obfuscation

Author: Rolan Lobo (RNR)
Project: BAR - Burn After Reading Security Suite
"""

import sys
import os
import time
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent / "src"))

from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QHBoxLayout
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QPalette

# Import all protection systems
from security.ultra_fast_screenshot_prevention import ComprehensiveScreenshotPrevention
from security.window_screenshot_prevention import ComprehensiveWindowProtection
from security.hardware_level_screenshot_prevention import UltimateScreenshotProtection
from security.advanced_screen_protection import AdvancedScreenProtectionManager
from config.security_config import SecurityLevel


class UltimateProtectionTestWindow(QMainWindow):
    """Test window with all protection systems enabled."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BAR Ultimate Screenshot Prevention Test - DEFEAT THIS!")
        self.setGeometry(100, 100, 1000, 800)
        
        # Apply dark theme with extra security styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0d1421;
                color: #ffffff;
                border: 3px solid #ff4444;
            }
            QLabel {
                color: #ffffff;
                padding: 10px;
            }
            QTextEdit {
                background-color: #1a1a2e;
                color: #ffffff;
                border: 2px solid #16213e;
                padding: 15px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton {
                background-color: #c62828;
                color: #ffffff;
                border: 2px solid #d32f2f;
                padding: 12px 25px;
                border-radius: 6px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
                border-color: #f44336;
            }
            QPushButton:pressed {
                background-color: #b71c1c;
            }
        """)
        
        self.setup_ui()
        
        # Initialize ALL protection systems
        self.protection_systems = {}
        self.init_all_protection_systems()
        
        # Statistics
        self.detection_count = 0
        self.start_time = time.time()
        self.protection_violations = []
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(500)  # Update every 500ms
        
        # Auto-close timer (60 seconds for thorough testing)
        self.auto_close_timer = QTimer()
        self.auto_close_timer.timeout.connect(self.close)
        self.auto_close_timer.start(60000)
        
        # Start all protections
        self.start_all_protections()
        
    def init_all_protection_systems(self):
        """Initialize all available protection systems."""
        try:
            # System 1: Ultra-fast screenshot prevention
            self.protection_systems['ultra_fast'] = ComprehensiveScreenshotPrevention(self)
            self.protection_systems['ultra_fast'].screenshot_attempt_detected.connect(
                lambda t, d: self.on_protection_violation("Ultra-Fast", f"{t}: {d}")
            )
            
            # System 2: Window-level protection
            self.protection_systems['window'] = ComprehensiveWindowProtection(self, self)
            self.protection_systems['window'].protection_status_changed.connect(
                lambda method, success: self.on_protection_status(f"Window-{method}", success)
            )
            
            # System 3: Hardware-level protection
            self.protection_systems['hardware'] = UltimateScreenshotProtection(self)
            self.protection_systems['hardware'].protection_breach.connect(
                lambda method, details: self.on_protection_violation("Hardware", f"{method}: {details}")
            )
            
            # System 4: Advanced screen protection (integrated system)
            self.protection_systems['advanced'] = AdvancedScreenProtectionManager(
                username="UltimateTestUser",
                protected_widget=self,
                log_directory="ultimate_test_logs",
                security_level=SecurityLevel.MAXIMUM
            )
            
            print(f"✅ Initialized {len(self.protection_systems)} protection systems")
            
        except Exception as e:
            print(f"❌ Error initializing protection systems: {e}")
            
    def start_all_protections(self):
        """Start all protection systems."""
        print("🚀 Starting ultimate screenshot prevention...")
        print("=" * 60)
        
        active_systems = 0
        
        # Start each protection system
        for name, system in self.protection_systems.items():
            try:
                if name == 'ultra_fast':
                    system.start_all_monitoring()
                    active_systems += 1
                    print(f"✅ {name.replace('_', ' ').title()} Protection: ACTIVE")
                    
                elif name == 'window':
                    if system.start_comprehensive_protection():
                        active_systems += 1
                        print(f"✅ {name.replace('_', ' ').title()} Protection: ACTIVE")
                    else:
                        print(f"⚠️ {name.replace('_', ' ').title()} Protection: PARTIAL")
                        
                elif name == 'hardware':
                    system.start_ultimate_protection()
                    active_systems += 1
                    print(f"✅ {name.replace('_', ' ').title()} Protection: ACTIVE")
                    
                elif name == 'advanced':
                    system.start_protection()
                    active_systems += 1
                    print(f"✅ {name.replace('_', ' ').title()} Protection: ACTIVE")
                    
            except Exception as e:
                print(f"❌ {name.replace('_', ' ').title()} Protection: FAILED - {e}")
                
        print("=" * 60)
        print(f"🛡️ ULTIMATE PROTECTION ACTIVE: {active_systems}/{len(self.protection_systems)} systems online")
        print("🎯 TRY TO DEFEAT THIS PROTECTION!")
        print("⚠️ WARNING: Screenshot apps will be terminated!")
        print("⏱️ Test will run for 60 seconds")
        print("=" * 60)
        
    def setup_ui(self):
        """Setup the user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Title with warning
        title = QLabel("🛡️ ULTIMATE SCREENSHOT PREVENTION TEST 🛡️")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #ff4444; font-size: 24px; padding: 20px; background-color: #330000; border-radius: 10px;")
        layout.addWidget(title)
        
        # Challenge text
        challenge = QLabel("""
        <center><b>🎯 CHALLENGE: TRY TO SCREENSHOT THIS WINDOW!</b></center><br>
        
        This window is protected by MULTIPLE advanced security systems:<br>
        • <b>Ultra-Fast Detection</b>: 1000Hz polling for key combinations<br>
        • <b>Window-Level Protection</b>: DWM exclusions and security attributes<br>  
        • <b>Hardware-Level Blocking</b>: System-level intervention<br>
        • <b>Advanced Screen Protection</b>: AI-powered threat detection<br>
        • <b>Process Termination</b>: Aggressive screenshot app killing<br>
        • <b>Clipboard Clearing</b>: Automatic screenshot removal<br><br>
        
        <b>🚨 METHODS TO TRY:</b><br>
        • Press Print Screen as fast as you can<br>
        • Use Win+Shift+S rapidly<br> 
        • Try Alt+Print Screen<br>
        • Open screenshot applications<br>
        • Use browser extensions<br>
        • Try mobile phone cameras (if you dare!)<br>
        """)
        challenge.setWordWrap(True)
        challenge.setStyleSheet("""
            background-color: #1a237e; 
            padding: 20px; 
            border-radius: 10px; 
            color: #ffffff;
            border: 2px solid #3949ab;
        """)
        layout.addWidget(challenge)
        
        # Status displays
        status_layout = QHBoxLayout()
        
        # Detection log
        log_layout = QVBoxLayout()
        log_label = QLabel("🔒 Security Violations:")
        log_label.setFont(QFont("Arial", 12, QFont.Bold))
        log_layout.addWidget(log_label)
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setMaximumHeight(180)
        log_layout.addWidget(self.log_display)
        
        # Statistics
        stats_layout = QVBoxLayout()
        stats_label = QLabel("📊 Protection Stats:")
        stats_label.setFont(QFont("Arial", 12, QFont.Bold))
        stats_layout.addWidget(stats_label)
        
        self.stats_display = QTextEdit()
        self.stats_display.setReadOnly(True)
        self.stats_display.setMaximumHeight(180)
        stats_layout.addWidget(self.stats_display)
        
        status_layout.addLayout(log_layout)
        status_layout.addLayout(stats_layout)
        layout.addLayout(status_layout)
        
        # Protected content (the prize!)
        content_label = QLabel("🏆 PROTECTED CONTENT - THE PRIZE:")
        content_label.setFont(QFont("Arial", 14, QFont.Bold))
        content_label.setStyleSheet("color: #ffd700;")
        layout.addWidget(content_label)
        
        protected_content = QTextEdit()
        protected_content.setPlainText(f"""
🔐🔐🔐 ULTRA-CLASSIFIED DOCUMENT 🔐🔐🔐

PROJECT: BAR - ULTIMATE SCREENSHOT RESISTANCE TEST
CLASSIFICATION: BEYOND TOP SECRET
SECURITY LEVEL: MAXIMUM PARANOID MODE
ACCESS: RESTRICTED TO AUTHORIZED PERSONNEL ONLY

If you can see this text in a screenshot, you have successfully
defeated the most advanced screenshot prevention system ever created!

🎯 ACHIEVEMENT UNLOCKED: Screenshot Ninja Master! 🎯

Current Test Session:
• Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
• Test ID: {hash(time.time()) % 1000000}
• Protection Level: ULTIMATE MAXIMUM SECURITY
• Systems Active: Ultra-Fast + Window + Hardware + Advanced
• Challenge Rating: IMPOSSIBLE

🏆 HALL OF FAME 🏆
If you successfully screenshot this, you deserve recognition:
• Screenshot Master 2025
• Security System Breaker
• Digital Ninja Level 100
• BAR Ultimate Challenge Champion

REMEMBER: With great power comes great responsibility.
Use your screenshot powers for good, not evil! 😉

🛡️ PROTECTED BY BAR ULTIMATE SECURITY SUITE 🛡️
        
Current Timestamp: {time.time()}
Random Challenge Code: {hash(str(time.time()) + "ultra_secret") % 1000000}
        """)
        protected_content.setReadOnly(True)
        protected_content.setStyleSheet("""
            background-color: #1b5e20; 
            color: #ffffff; 
            font-weight: bold;
            font-size: 12px;
            border: 3px solid #4caf50;
            border-radius: 10px;
        """)
        layout.addWidget(protected_content)
        
    def on_protection_violation(self, system: str, details: str):
        """Handle protection violation (screenshot attempt detected)."""
        self.detection_count += 1
        current_time = time.strftime("%H:%M:%S.%f")[:-3]
        
        violation = {
            'time': current_time,
            'system': system,
            'details': details,
            'count': self.detection_count
        }
        self.protection_violations.append(violation)
        
        log_message = f"[{current_time}] 🚨 VIOLATION #{self.detection_count}: {system} - {details}"
        self.log_display.append(log_message)
        
        print(f"🚨 SECURITY VIOLATION #{self.detection_count}: {system} detected {details}")
        
        # Scroll to bottom
        scrollbar = self.log_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def on_protection_status(self, method: str, success: bool):
        """Handle protection status updates."""
        status = "✅ ACTIVE" if success else "❌ FAILED"
        print(f"Protection Status: {method} - {status}")
        
    def update_status(self):
        """Update status display."""
        runtime = time.time() - self.start_time
        remaining = max(0, 60 - runtime)
        
        # Calculate detection rate
        rate_per_minute = (self.detection_count / (runtime / 60)) if runtime > 0 else 0
        
        # Count active protection systems
        active_count = len([s for s in self.protection_systems.values() if hasattr(s, 'active') and s.active])
        
        stats_text = f"""
🕒 Runtime: {runtime:.1f}s (Remaining: {remaining:.1f}s)
🚨 Total Violations: {self.detection_count}
📈 Detection Rate: {rate_per_minute:.1f} per minute
🛡️ Active Systems: {active_count}/{len(self.protection_systems)}
⚡ Protection Level: MAXIMUM PARANOID

Recent Violations:
"""
        
        # Add last 5 violations
        for violation in self.protection_violations[-5:]:
            stats_text += f"• [{violation['time']}] {violation['system']}\n"
            
        if self.detection_count == 0:
            stats_text += "\n🎯 No violations detected yet...\n🤔 Are you even trying?\n"
        elif self.detection_count < 3:
            stats_text += "\n⚠️ Few violations - system may be working!\n"
        else:
            stats_text += f"\n🛡️ {self.detection_count} violations blocked!\n💪 Protection systems working!\n"
            
        stats_text += f"""
            
🎮 Challenge Progress:
{'█' * min(20, self.detection_count)}{'░' * max(0, 20-self.detection_count)}
        """
        
        self.stats_display.setPlainText(stats_text.strip())
        
    def closeEvent(self, event):
        """Handle window close event."""
        runtime = time.time() - self.start_time
        
        print("\n" + "="*60)
        print("🏁 ULTIMATE SCREENSHOT PREVENTION TEST COMPLETE")
        print("="*60)
        print(f"⏱️ Test Duration: {runtime:.1f} seconds")
        print(f"🚨 Total Violations Detected: {self.detection_count}")
        print(f"📊 Detection Rate: {self.detection_count / (runtime / 60):.2f} per minute")
        
        if self.detection_count == 0:
            print("🤔 NO VIOLATIONS DETECTED")
            print("   Either the system is perfect or you didn't try hard enough!")
        elif self.detection_count < 5:
            print("⚠️ FEW VIOLATIONS DETECTED")
            print("   Protection seems to be working, but more testing needed")
        elif self.detection_count < 20:
            print("✅ MODERATE VIOLATIONS DETECTED") 
            print("   Protection system is actively working!")
        else:
            print("🛡️ MANY VIOLATIONS DETECTED")
            print("   Protection system is HIGHLY ACTIVE!")
            
        print(f"🏆 ACHIEVEMENT LEVEL: {'ROOKIE' if self.detection_count < 5 else 'INTERMEDIATE' if self.detection_count < 15 else 'EXPERT'}")
        
        # Stop all protections
        print("\n🔓 Stopping all protection systems...")
        for name, system in self.protection_systems.items():
            try:
                if name == 'ultra_fast':
                    system.stop_all_monitoring()
                elif name == 'window':
                    system.stop_comprehensive_protection()
                elif name == 'hardware':
                    system.stop_ultimate_protection()
                elif name == 'advanced':
                    system.stop_protection()
            except Exception as e:
                print(f"Error stopping {name}: {e}")
                
        print("✅ All protection systems stopped")
        print("="*60)
        
        event.accept()


def main():
    """Main function."""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set dark theme
    palette = QPalette()
    palette.setColor(QPalette.Window, Qt.black)
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, Qt.darkBlue)
    palette.setColor(QPalette.AlternateBase, Qt.darkGray)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, Qt.darkRed)
    palette.setColor(QPalette.ButtonText, Qt.white)
    app.setPalette(palette)
    
    # Create test window
    test_window = UltimateProtectionTestWindow()
    test_window.show()
    
    print("\n" + "🔥"*20 + " ULTIMATE CHALLENGE " + "🔥"*20)
    print("🎯 BAR ULTIMATE SCREENSHOT PREVENTION TEST")
    print("🛡️ MOST ADVANCED PROTECTION SYSTEM EVER CREATED")
    print("=" * 70)
    print("This is the ultimate test of screenshot prevention technology.")
    print("We've combined EVERY available protection method:")
    print("• Ultra-fast key detection (1000Hz polling)")
    print("• Hardware-level keyboard hooks")  
    print("• Windows DWM protection attributes")
    print("• Graphics driver interference")
    print("• Process termination and monitoring")
    print("• Clipboard clearing and protection")
    print("• Advanced AI-powered threat detection")
    print("• Multi-layer redundant security")
    print("\n🚨 WARNING: This will terminate screenshot applications!")
    print("📱 Mobile phone screenshots are NOT blocked (hardware limitation)")
    print("🎮 Your mission: Try to screenshot the protected content!")
    print("⏱️ You have 60 seconds to defeat the system!")
    print("🏆 Good luck - you'll need it! 😈")
    print("=" * 70)
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
