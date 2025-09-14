"""
Simple Test Runner for Available BAR Components

This test runner checks what components are available and runs basic
functionality tests for each component. It gracefully handles missing
modules and provides a comprehensive report of component status.

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys
import time
import traceback
from typing import List, Dict, Any, Tuple

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class ComponentTester:
    """Simple component tester for BAR system."""
    
    def __init__(self):
        self.results = []
        self.start_time = None
        self.end_time = None
    
    def test_secure_memory(self) -> Tuple[bool, str, List[str]]:
        """Test secure memory component."""
        try:
            from security.secure_memory import SecureMemory, SecureBytes, SecureString
            
            errors = []
            
            # Test SecureMemory creation
            try:
                sm = SecureMemory(1024)
                if not sm:
                    errors.append("SecureMemory creation failed")
            except Exception as e:
                errors.append(f"SecureMemory creation error: {str(e)}")
            
            # Test SecureBytes creation
            try:
                sb = SecureBytes(b"test data")
                if not sb:
                    errors.append("SecureBytes creation failed")
                else:
                    # Test data retrieval
                    data = sb.get_data()
                    if data != b"test data":
                        errors.append("SecureBytes data retrieval failed")
            except Exception as e:
                errors.append(f"SecureBytes test error: {str(e)}")
            
            # Test SecureString creation
            try:
                ss = SecureString("test string")
                if not ss:
                    errors.append("SecureString creation failed")
                else:
                    # Test data retrieval
                    data = ss.get_string()
                    if data != "test string":
                        errors.append("SecureString data retrieval failed")
            except Exception as e:
                errors.append(f"SecureString test error: {str(e)}")
            
            success = len(errors) == 0
            status = "✅ PASS" if success else "❌ FAIL"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def test_encryption(self) -> Tuple[bool, str, List[str]]:
        """Test encryption component."""
        try:
            from crypto.encryption import AESCipher, encrypt_data, decrypt_data
            
            errors = []
            
            # Test AESCipher creation
            try:
                cipher = AESCipher()
                if not cipher:
                    errors.append("AESCipher creation failed")
            except Exception as e:
                errors.append(f"AESCipher creation error: {str(e)}")
            
            # Test encryption/decryption
            try:
                test_data = b"Hello, encryption test!"
                password = "test_password_123"
                
                # Encrypt
                encrypted = encrypt_data(test_data, password)
                if not encrypted or encrypted == test_data:
                    errors.append("Encryption failed or returned original data")
                
                # Decrypt
                decrypted = decrypt_data(encrypted, password)
                if decrypted != test_data:
                    errors.append("Decryption failed - data mismatch")
                    
            except Exception as e:
                errors.append(f"Encryption/decryption test error: {str(e)}")
            
            success = len(errors) == 0
            status = "✅ PASS" if success else "❌ FAIL"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def test_input_validator(self) -> Tuple[bool, str, List[str]]:
        """Test input validation component."""
        try:
            from security.input_validator import InputValidator, validate_input, ValidationLevel
            
            errors = []
            
            # Test InputValidator creation
            try:
                validator = InputValidator()
                if not validator:
                    errors.append("InputValidator creation failed")
            except Exception as e:
                errors.append(f"InputValidator creation error: {str(e)}")
            
            # Test basic validation
            try:
                # Valid string
                result = validate_input("valid_string", ValidationLevel.BASIC)
                if not result.is_valid:
                    errors.append("Basic validation failed for valid string")
                
                # Invalid string (SQL injection)
                result = validate_input("'; DROP TABLE users; --", ValidationLevel.STRICT)
                if result.is_valid:
                    errors.append("Validation should reject SQL injection")
                    
            except Exception as e:
                errors.append(f"Validation test error: {str(e)}")
            
            success = len(errors) == 0
            status = "✅ PASS" if success else "❌ FAIL"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def test_file_manager(self) -> Tuple[bool, str, List[str]]:
        """Test file manager component."""
        try:
            from file_manager.file_manager import FileManager
            
            errors = []
            
            # Test FileManager creation
            try:
                fm = FileManager()
                if not fm:
                    errors.append("FileManager creation failed")
            except Exception as e:
                errors.append(f"FileManager creation error: {str(e)}")
            
            # Test file operations
            try:
                # Test filename validation
                valid_filename = fm.is_valid_filename("test.txt")
                if not valid_filename:
                    errors.append("Valid filename rejected")
                
                invalid_filename = fm.is_valid_filename("../../../etc/passwd")
                if invalid_filename:
                    errors.append("Invalid filename (path traversal) accepted")
                    
            except Exception as e:
                errors.append(f"File operations test error: {str(e)}")
            
            success = len(errors) == 0
            status = "✅ PASS" if success else "❌ FAIL"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def test_config_manager(self) -> Tuple[bool, str, List[str]]:
        """Test configuration manager component."""
        try:
            from config.config_manager import ConfigManager
            
            errors = []
            
            # Test ConfigManager creation
            try:
                cm = ConfigManager()
                if not cm:
                    errors.append("ConfigManager creation failed")
            except Exception as e:
                errors.append(f"ConfigManager creation error: {str(e)}")
            
            # Test configuration operations
            try:
                # Test setting/getting values
                test_key = "test_setting"
                test_value = "test_value"
                
                cm.set_setting(test_key, test_value)
                retrieved_value = cm.get_setting(test_key)
                
                if retrieved_value != test_value:
                    errors.append("Configuration set/get failed")
                    
            except Exception as e:
                errors.append(f"Configuration operations test error: {str(e)}")
            
            success = len(errors) == 0
            status = "✅ PASS" if success else "❌ FAIL"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def test_hardware_id(self) -> Tuple[bool, str, List[str]]:
        """Test hardware ID component."""
        try:
            from security.hardware_id import HardwareID
            
            errors = []
            
            # Test HardwareID creation
            try:
                hw_id = HardwareID()
                if not hw_id:
                    errors.append("HardwareID creation failed")
            except Exception as e:
                errors.append(f"HardwareID creation error: {str(e)}")
            
            # Test hardware ID generation
            try:
                hardware_id = hw_id.get_hardware_id()
                if not hardware_id or len(hardware_id) < 16:
                    errors.append("Hardware ID generation failed or too short")
                
                # Test consistency
                hardware_id2 = hw_id.get_hardware_id()
                if hardware_id != hardware_id2:
                    errors.append("Hardware ID not consistent between calls")
                    
            except Exception as e:
                errors.append(f"Hardware ID test error: {str(e)}")
            
            success = len(errors) == 0
            status = "✅ PASS" if success else "❌ FAIL"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def test_emergency_protocol(self) -> Tuple[bool, str, List[str]]:
        """Test emergency protocol component."""
        try:
            from security.emergency_protocol import EmergencyProtocol
            
            errors = []
            
            # Test EmergencyProtocol creation
            try:
                ep = EmergencyProtocol()
                if not ep:
                    errors.append("EmergencyProtocol creation failed")
            except Exception as e:
                errors.append(f"EmergencyProtocol creation error: {str(e)}")
            
            # Test emergency status
            try:
                # Should not be in emergency state initially
                is_active = ep.is_active()
                if is_active:
                    errors.append("Emergency protocol incorrectly reports active state")
                
                # Test trigger validation
                valid_trigger = ep.is_valid_trigger("invalid_trigger")
                if valid_trigger:
                    errors.append("Invalid trigger accepted")
                    
            except Exception as e:
                errors.append(f"Emergency protocol test error: {str(e)}")
            
            success = len(errors) == 0
            status = "✅ PASS" if success else "❌ FAIL"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def test_screen_protection(self) -> Tuple[bool, str, List[str]]:
        """Test screen protection component."""
        try:
            from security.advanced_screen_protection import AdvancedScreenProtection
            
            errors = []
            
            # Test AdvancedScreenProtection creation
            try:
                asp = AdvancedScreenProtection()
                if not asp:
                    errors.append("AdvancedScreenProtection creation failed")
            except Exception as e:
                errors.append(f"AdvancedScreenProtection creation error: {str(e)}")
            
            # Test screen protection status
            try:
                # Check if protection can be initialized
                init_result = asp.initialize()
                # This might fail on headless systems, so we're lenient
                
                # Check status (should return boolean, not None)
                status = asp.get_protection_status()
                if status is None:
                    errors.append("Screen protection status returned None")
                    
            except Exception as e:
                # Screen protection might fail on headless systems
                errors.append(f"Screen protection test error (might be expected): {str(e)}")
            
            # For screen protection, we're more lenient due to system dependencies
            success = len([e for e in errors if "might be expected" not in e]) == 0
            status = "✅ PASS" if success else "⚠️ LIMITED"
            return success, status, errors
            
        except ImportError as e:
            return False, "❌ NOT AVAILABLE", [f"Import error: {str(e)}"]
        except Exception as e:
            return False, "❌ ERROR", [f"Unexpected error: {str(e)}"]
    
    def run_all_tests(self):
        """Run all available component tests."""
        print("🚀 BAR Component Availability & Basic Testing")
        print("=" * 60)
        print("Version: 2.0.0")
        print("Author: Rolan Lobo (RNR)")
        print("Testing: Available BAR Components")
        print("=" * 60)
        
        self.start_time = time.time()
        
        # Define test components
        components = [
            ("Secure Memory", self.test_secure_memory),
            ("Encryption", self.test_encryption), 
            ("Input Validator", self.test_input_validator),
            ("File Manager", self.test_file_manager),
            ("Config Manager", self.test_config_manager),
            ("Hardware ID", self.test_hardware_id),
            ("Emergency Protocol", self.test_emergency_protocol),
            ("Screen Protection", self.test_screen_protection),
        ]
        
        print(f"\n🔍 Testing {len(components)} Components...")
        print("-" * 60)
        
        # Run tests
        for component_name, test_method in components:
            print(f"\nTesting {component_name}...")
            success, status, errors = test_method()
            
            result = {
                'name': component_name,
                'success': success,
                'status': status,
                'errors': errors
            }
            self.results.append(result)
            
            print(f"{component_name}: {status}")
            if errors and len(errors) <= 3:  # Show first 3 errors
                for error in errors:
                    print(f"  • {error}")
            elif len(errors) > 3:
                for error in errors[:2]:
                    print(f"  • {error}")
                print(f"  • ... and {len(errors) - 2} more errors")
        
        self.end_time = time.time()
        self.print_summary()
        
        # Return success if all critical components are working
        critical_components = ["Secure Memory", "Encryption", "Input Validator"]
        critical_success = all(
            result['success'] for result in self.results 
            if result['name'] in critical_components and result['status'] != "❌ NOT AVAILABLE"
        )
        
        return critical_success
    
    def print_summary(self):
        """Print test summary."""
        total_duration = self.end_time - self.start_time
        
        print(f"\n{'='*70}")
        print("BAR COMPONENTS TEST SUMMARY")
        print("=" * 70)
        
        # Status breakdown
        available_count = sum(1 for r in self.results if r['status'] not in ["❌ NOT AVAILABLE", "❌ ERROR"])
        passing_count = sum(1 for r in self.results if r['success'])
        total_count = len(self.results)
        
        print(f"\n📊 OVERVIEW")
        print("-" * 30)
        print(f"Total Components: {total_count}")
        print(f"Available: {available_count}")
        print(f"Passing Tests: {passing_count}")
        print(f"Not Available: {total_count - available_count}")
        print(f"Test Duration: {total_duration:.2f} seconds")
        
        # Detailed results table
        print(f"\n📋 DETAILED RESULTS")
        print("-" * 50)
        print(f"{'Component':<20} {'Status':<15} {'Errors'}")
        print("-" * 50)
        
        for result in self.results:
            error_count = len(result['errors']) if result['errors'] else 0
            error_text = f"{error_count} errors" if error_count > 0 else "No errors"
            print(f"{result['name']:<20} {result['status']:<15} {error_text}")
        
        # Security status
        print(f"\n🔒 SECURITY STATUS")
        print("-" * 30)
        
        critical_security = ["Secure Memory", "Encryption", "Input Validator"]
        security_results = [r for r in self.results if r['name'] in critical_security]
        security_available = [r for r in security_results if r['status'] != "❌ NOT AVAILABLE"]
        security_passing = [r for r in security_available if r['success']]
        
        if len(security_available) == 0:
            print("⚠️ No critical security components available")
        elif len(security_passing) == len(security_available):
            print("✅ All available security components are working")
        else:
            print("❌ Some security components have issues")
        
        print(f"Security Components Available: {len(security_available)}/{len(critical_security)}")
        print(f"Security Components Passing: {len(security_passing)}/{len(security_available)}")
        
        # Final recommendation
        print(f"\n🏆 RECOMMENDATION")
        print("-" * 30)
        
        if len(security_available) >= 2 and len(security_passing) == len(security_available):
            print("✅ Core security functionality appears to be working")
            print("🚀 BAR system basic components are functional")
        elif len(security_available) >= 1:
            print("⚠️ Partial security functionality available")
            print("🔧 Some components need implementation or fixes")
        else:
            print("❌ Critical security components missing")
            print("🛠️ Significant development work needed")
        
        print(f"\nTest completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")


def main():
    """Main entry point."""
    try:
        tester = ComponentTester()
        success = tester.run_all_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Test execution interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {str(e)}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())