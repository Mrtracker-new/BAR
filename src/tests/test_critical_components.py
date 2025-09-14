"""
Master Test Suite for BAR Critical Components

This comprehensive test suite runs all critical component tests for the BAR
(Burn After Reading) security application, ensuring system integrity and
compliance with BAR Rules and security standards.

Components Tested:
- Secure Memory System (R006 - Memory Security)
- Encryption System (R004 - Cryptographic Standards)
- Input Validation System (R030 - Input Validation)
- File Management System
- Configuration System
- Hardware Binding System
- Emergency Protocols
- Screen Protection System

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys
import unittest
import time
import traceback
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import individual test modules
test_modules = []

# Import secure memory tests
try:
    from test_secure_memory import (
        run_secure_memory_tests, create_secure_memory_test_suite,
        SECURE_MEMORY_AVAILABLE
    )
    test_modules.append(('Secure Memory', run_secure_memory_tests, SECURE_MEMORY_AVAILABLE))
except ImportError as e:
    print(f"⚠️ Could not import secure memory tests: {e}")

# Import encryption tests
try:
    from test_encryption import (
        run_encryption_tests, create_encryption_test_suite,
        ENCRYPTION_AVAILABLE
    )
    test_modules.append(('Encryption', run_encryption_tests, ENCRYPTION_AVAILABLE))
except ImportError as e:
    print(f"⚠️ Could not import encryption tests: {e}")

# Import input validator tests
try:
    from test_input_validator import (
        run_input_validator_tests, create_input_validator_test_suite,
        VALIDATOR_AVAILABLE
    )
    test_modules.append(('Input Validator', run_input_validator_tests, VALIDATOR_AVAILABLE))
except ImportError as e:
    print(f"⚠️ Could not import input validator tests: {e}")


@dataclass
class TestResult:
    """Test result data structure."""
    name: str
    success: bool
    tests_run: int
    failures: int
    errors: int
    duration: float
    error_details: List[str]


@dataclass
class ComponentStatus:
    """Component availability status."""
    name: str
    available: bool
    reason: Optional[str] = None


class CriticalComponentsTestRunner:
    """Master test runner for all critical components."""
    
    def __init__(self):
        """Initialize the test runner."""
        self.results: List[TestResult] = []
        self.component_status: List[ComponentStatus] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
    
    def check_component_availability(self) -> None:
        """Check availability of all components."""
        print("🔍 Checking Component Availability...")
        print("=" * 60)
        
        # Check secure memory
        secure_memory_available = 'SECURE_MEMORY_AVAILABLE' in globals() and SECURE_MEMORY_AVAILABLE
        self.component_status.append(ComponentStatus(
            "Secure Memory", 
            secure_memory_available,
            None if secure_memory_available else "Module not found"
        ))
        
        # Check encryption
        encryption_available = 'ENCRYPTION_AVAILABLE' in globals() and ENCRYPTION_AVAILABLE
        self.component_status.append(ComponentStatus(
            "Encryption",
            encryption_available,
            None if encryption_available else "Module not found"
        ))
        
        # Check input validator
        validator_available = 'VALIDATOR_AVAILABLE' in globals() and VALIDATOR_AVAILABLE
        self.component_status.append(ComponentStatus(
            "Input Validator",
            validator_available,
            None if validator_available else "Module not found"
        ))
        
        # Check file manager
        try:
            from file_manager.file_operations import FileManager
            self.component_status.append(ComponentStatus("File Manager", True))
        except ImportError as e:
            self.component_status.append(ComponentStatus("File Manager", False, str(e)))
        
        # Check config manager
        try:
            from config.config_manager import ConfigManager
            self.component_status.append(ComponentStatus("Config Manager", True))
        except ImportError as e:
            self.component_status.append(ComponentStatus("Config Manager", False, str(e)))
        
        # Check hardware binding
        try:
            from security.hardware_id import HardwareID
            self.component_status.append(ComponentStatus("Hardware Binding", True))
        except ImportError as e:
            self.component_status.append(ComponentStatus("Hardware Binding", False, str(e)))
        
        # Check emergency protocols
        try:
            from security.emergency_protocol import EmergencyProtocol
            self.component_status.append(ComponentStatus("Emergency Protocol", True))
        except ImportError as e:
            self.component_status.append(ComponentStatus("Emergency Protocol", False, str(e)))
        
        # Check screen protection
        try:
            from security.advanced_screen_protection import AdvancedScreenProtection
            self.component_status.append(ComponentStatus("Screen Protection", True))
        except ImportError as e:
            self.component_status.append(ComponentStatus("Screen Protection", False, str(e)))
        
        # Print status
        for status in self.component_status:
            icon = "✅" if status.available else "❌"
            reason = f" ({status.reason})" if status.reason else ""
            print(f"{icon} {status.name}{reason}")
        
        available_count = sum(1 for s in self.component_status if s.available)
        total_count = len(self.component_status)
        print(f"\n📊 {available_count}/{total_count} components available")
    
    def run_component_test(self, name: str, test_runner, available: bool) -> TestResult:
        """Run a single component test."""
        if not available:
            return TestResult(
                name=name,
                success=False,
                tests_run=0,
                failures=0,
                errors=1,
                duration=0.0,
                error_details=[f"Component {name} not available"]
            )
        
        print(f"\n🧪 Running {name} Tests...")
        print("-" * 40)
        
        start_time = time.time()
        
        try:
            # Capture original stdout to get detailed results
            import io
            import contextlib
            
            captured_output = io.StringIO()
            
            with contextlib.redirect_stdout(captured_output):
                success = test_runner()
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Parse output for test counts (this is a simplified approach)
            output_lines = captured_output.getvalue().split('\n')
            tests_run = 0
            failures = 0
            errors = 0
            error_details = []
            
            for line in output_lines:
                if 'Tests run:' in line:
                    try:
                        tests_run = int(line.split('Tests run:')[1].split()[0])
                    except:
                        pass
                elif 'Failures:' in line:
                    try:
                        failures = int(line.split('Failures:')[1].split()[0])
                    except:
                        pass
                elif 'Errors:' in line:
                    try:
                        errors = int(line.split('Errors:')[1].split()[0])
                    except:
                        pass
                elif 'FAILURES' in line or 'ERRORS' in line:
                    error_details.append(line.strip())
            
            return TestResult(
                name=name,
                success=success,
                tests_run=tests_run,
                failures=failures,
                errors=errors,
                duration=duration,
                error_details=error_details
            )
        
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            return TestResult(
                name=name,
                success=False,
                tests_run=0,
                failures=0,
                errors=1,
                duration=duration,
                error_details=[f"Exception during {name} tests: {str(e)}", traceback.format_exc()]
            )
    
    def run_file_manager_tests(self) -> TestResult:
        """Run file manager component tests."""
        print("\n📁 Running File Manager Tests...")
        print("-" * 40)
        
        start_time = time.time()
        tests_run = 0
        failures = 0
        errors = 0
        error_details = []
        
        try:
            from file_manager.file_operations import FileManager
            
            # Basic functionality tests
            fm = FileManager()
            
            # Test file validation
            tests_run += 1
            try:
                valid_result = fm.validate_file_path("test.txt")
                if not valid_result:
                    failures += 1
                    error_details.append("File path validation failed for valid path")
            except Exception as e:
                errors += 1
                error_details.append(f"File path validation error: {str(e)}")
            
            # Test invalid file validation
            tests_run += 1
            try:
                invalid_result = fm.validate_file_path("../../../etc/passwd")
                if invalid_result:
                    failures += 1
                    error_details.append("File path validation should reject path traversal")
            except Exception as e:
                errors += 1
                error_details.append(f"Invalid file path validation error: {str(e)}")
            
            # Test filename sanitization
            tests_run += 1
            try:
                sanitized = fm.sanitize_filename("file<>name.txt")
                if "<" in sanitized or ">" in sanitized:
                    failures += 1
                    error_details.append("Filename sanitization failed to remove invalid characters")
            except Exception as e:
                errors += 1
                error_details.append(f"Filename sanitization error: {str(e)}")
        
        except ImportError as e:
            errors += 1
            error_details.append(f"Could not import FileManager: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        success = failures == 0 and errors == 0
        
        print(f"File Manager Tests: {tests_run} run, {failures} failures, {errors} errors ({duration:.2f}s)")
        
        return TestResult(
            name="File Manager",
            success=success,
            tests_run=tests_run,
            failures=failures,
            errors=errors,
            duration=duration,
            error_details=error_details
        )
    
    def run_config_manager_tests(self) -> TestResult:
        """Run configuration manager tests."""
        print("\n⚙️ Running Config Manager Tests...")
        print("-" * 40)
        
        start_time = time.time()
        tests_run = 0
        failures = 0
        errors = 0
        error_details = []
        
        try:
            from config.config_manager import ConfigManager
            
            # Basic functionality tests
            cm = ConfigManager()
            
            # Test configuration loading
            tests_run += 1
            try:
                config_loaded = cm.load_config()
                if not config_loaded:
                    failures += 1
                    error_details.append("Config manager failed to load configuration")
            except Exception as e:
                errors += 1
                error_details.append(f"Config loading error: {str(e)}")
            
            # Test configuration validation
            tests_run += 1
            try:
                valid_config = {"test_key": "test_value"}
                validation_result = cm.validate_config(valid_config)
                if not validation_result:
                    failures += 1
                    error_details.append("Config validation failed for valid configuration")
            except Exception as e:
                errors += 1
                error_details.append(f"Config validation error: {str(e)}")
            
            # Test theme enforcement (BAR Rule R011)
            tests_run += 1
            try:
                # Theme should always be enforced as dark
                theme = cm.get_setting("theme", "light")  # Try to get light theme
                if theme != "dark":
                    failures += 1
                    error_details.append("Theme lock enforcement failed - non-dark theme allowed")
            except Exception as e:
                errors += 1
                error_details.append(f"Theme enforcement error: {str(e)}")
        
        except ImportError as e:
            errors += 1
            error_details.append(f"Could not import ConfigManager: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        success = failures == 0 and errors == 0
        
        print(f"Config Manager Tests: {tests_run} run, {failures} failures, {errors} errors ({duration:.2f}s)")
        
        return TestResult(
            name="Config Manager",
            success=success,
            tests_run=tests_run,
            failures=failures,
            errors=errors,
            duration=duration,
            error_details=error_details
        )
    
    def run_hardware_binding_tests(self) -> TestResult:
        """Run hardware binding tests."""
        print("\n🖥️ Running Hardware Binding Tests...")
        print("-" * 40)
        
        start_time = time.time()
        tests_run = 0
        failures = 0
        errors = 0
        error_details = []
        
        try:
            from security.hardware_id import HardwareID
            
            # Basic functionality tests
            hw_id = HardwareID()
            
            # Test hardware ID generation
            tests_run += 1
            try:
                hardware_id = hw_id.generate_hardware_id()
                if not hardware_id or len(hardware_id) < 16:
                    failures += 1
                    error_details.append("Hardware ID generation produced invalid result")
            except Exception as e:
                errors += 1
                error_details.append(f"Hardware ID generation error: {str(e)}")
            
            # Test hardware ID consistency
            tests_run += 1
            try:
                id1 = hw_id.generate_hardware_id()
                id2 = hw_id.generate_hardware_id()
                if id1 != id2:
                    failures += 1
                    error_details.append("Hardware ID generation not consistent")
            except Exception as e:
                errors += 1
                error_details.append(f"Hardware ID consistency error: {str(e)}")
            
            # Test hardware ID validation
            tests_run += 1
            try:
                valid_id = hw_id.generate_hardware_id()
                validation_result = hw_id.validate_hardware_id(valid_id)
                if not validation_result:
                    failures += 1
                    error_details.append("Hardware ID validation failed for valid ID")
            except Exception as e:
                errors += 1
                error_details.append(f"Hardware ID validation error: {str(e)}")
        
        except ImportError as e:
            errors += 1
            error_details.append(f"Could not import HardwareID: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        success = failures == 0 and errors == 0
        
        print(f"Hardware Binding Tests: {tests_run} run, {failures} failures, {errors} errors ({duration:.2f}s)")
        
        return TestResult(
            name="Hardware Binding",
            success=success,
            tests_run=tests_run,
            failures=failures,
            errors=errors,
            duration=duration,
            error_details=error_details
        )
    
    def run_emergency_protocol_tests(self) -> TestResult:
        """Run emergency protocol tests."""
        print("\n🚨 Running Emergency Protocol Tests...")
        print("-" * 40)
        
        start_time = time.time()
        tests_run = 0
        failures = 0
        errors = 0
        error_details = []
        
        try:
            from security.emergency_protocol import EmergencyProtocol
            
            # Basic functionality tests
            ep = EmergencyProtocol()
            
            # Test emergency detection
            tests_run += 1
            try:
                # Should not be in emergency state initially
                emergency_state = ep.is_emergency_active()
                if emergency_state:
                    failures += 1
                    error_details.append("Emergency protocol incorrectly reports active state initially")
            except Exception as e:
                errors += 1
                error_details.append(f"Emergency state check error: {str(e)}")
            
            # Test emergency trigger validation
            tests_run += 1
            try:
                # Test with invalid trigger conditions
                invalid_trigger = ep.validate_emergency_trigger("invalid_trigger")
                if invalid_trigger:
                    failures += 1
                    error_details.append("Emergency protocol accepted invalid trigger")
            except Exception as e:
                errors += 1
                error_details.append(f"Emergency trigger validation error: {str(e)}")
            
            # Test security cleanup preparation
            tests_run += 1
            try:
                cleanup_ready = ep.prepare_security_cleanup()
                if not cleanup_ready:
                    failures += 1
                    error_details.append("Emergency protocol failed to prepare security cleanup")
            except Exception as e:
                errors += 1
                error_details.append(f"Security cleanup preparation error: {str(e)}")
        
        except ImportError as e:
            errors += 1
            error_details.append(f"Could not import EmergencyProtocol: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        success = failures == 0 and errors == 0
        
        print(f"Emergency Protocol Tests: {tests_run} run, {failures} failures, {errors} errors ({duration:.2f}s)")
        
        return TestResult(
            name="Emergency Protocol",
            success=success,
            tests_run=tests_run,
            failures=failures,
            errors=errors,
            duration=duration,
            error_details=error_details
        )
    
    def run_screen_protection_tests(self) -> TestResult:
        """Run screen protection tests."""
        print("\n🛡️ Running Screen Protection Tests...")
        print("-" * 40)
        
        start_time = time.time()
        tests_run = 0
        failures = 0
        errors = 0
        error_details = []
        
        try:
            from security.advanced_screen_protection import AdvancedScreenProtection
            
            # Basic functionality tests
            sp = AdvancedScreenProtection()
            
            # Test screen protection initialization
            tests_run += 1
            try:
                init_result = sp.initialize()
                if not init_result:
                    failures += 1
                    error_details.append("Screen protection failed to initialize")
            except Exception as e:
                errors += 1
                error_details.append(f"Screen protection initialization error: {str(e)}")
            
            # Test protection status
            tests_run += 1
            try:
                protection_status = sp.is_protection_active()
                # Status should be deterministic (either True or False, not None)
                if protection_status is None:
                    failures += 1
                    error_details.append("Screen protection status returned None")
            except Exception as e:
                errors += 1
                error_details.append(f"Screen protection status error: {str(e)}")
            
            # Test protection activation
            tests_run += 1
            try:
                activation_result = sp.activate_protection()
                if not activation_result:
                    # This might fail on headless systems, so it's a warning
                    error_details.append("Screen protection activation failed (might be expected on headless system)")
            except Exception as e:
                errors += 1
                error_details.append(f"Screen protection activation error: {str(e)}")
        
        except ImportError as e:
            errors += 1
            error_details.append(f"Could not import AdvancedScreenProtection: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        success = failures == 0 and errors == 0
        
        print(f"Screen Protection Tests: {tests_run} run, {failures} failures, {errors} errors ({duration:.2f}s)")
        
        return TestResult(
            name="Screen Protection",
            success=success,
            tests_run=tests_run,
            failures=failures,
            errors=errors,
            duration=duration,
            error_details=error_details
        )
    
    def run_all_tests(self) -> bool:
        """Run all critical component tests."""
        print("🚀 BAR Critical Components Test Suite")
        print("=" * 60)
        print(f"Version: 2.0.0")
        print(f"Author: Rolan Lobo (RNR)")
        print(f"Compliance: BAR Security Rules")
        print("=" * 60)
        
        self.start_time = time.time()
        
        # Check component availability
        self.check_component_availability()
        
        print(f"\n🧪 Running Critical Component Tests...")
        print("=" * 60)
        
        # Run main test modules
        for name, test_runner, available in test_modules:
            result = self.run_component_test(name, test_runner, available)
            self.results.append(result)
        
        # Run additional component tests
        additional_tests = [
            ("File Manager", self.run_file_manager_tests),
            ("Config Manager", self.run_config_manager_tests),
            ("Hardware Binding", self.run_hardware_binding_tests),
            ("Emergency Protocol", self.run_emergency_protocol_tests),
            ("Screen Protection", self.run_screen_protection_tests)
        ]
        
        for name, test_method in additional_tests:
            result = test_method()
            self.results.append(result)
        
        self.end_time = time.time()
        
        # Print comprehensive results
        self.print_results()
        
        # Return overall success
        return all(result.success for result in self.results)
    
    def print_results(self) -> None:
        """Print comprehensive test results."""
        total_duration = self.end_time - self.start_time if self.end_time and self.start_time else 0
        
        print(f"\n{'='*80}")
        print(f"BAR CRITICAL COMPONENTS TEST RESULTS")
        print(f"{'='*80}")
        
        # Summary table
        print(f"{'Component':<20} {'Status':<10} {'Tests':<8} {'Failures':<10} {'Errors':<8} {'Duration':<10}")
        print("-" * 80)
        
        total_tests = 0
        total_failures = 0
        total_errors = 0
        successful_components = 0
        
        for result in self.results:
            status = "✅ PASS" if result.success else "❌ FAIL"
            print(f"{result.name:<20} {status:<10} {result.tests_run:<8} {result.failures:<10} "
                  f"{result.errors:<8} {result.duration:<10.2f}s")
            
            total_tests += result.tests_run
            total_failures += result.failures
            total_errors += result.errors
            if result.success:
                successful_components += 1
        
        print("-" * 80)
        print(f"{'TOTAL':<20} {'':<10} {total_tests:<8} {total_failures:<10} {total_errors:<8} {total_duration:<10.2f}s")
        
        # Overall summary
        print(f"\n📊 SUMMARY")
        print(f"{'='*40}")
        print(f"Components Tested: {len(self.results)}")
        print(f"Components Passed: {successful_components}")
        print(f"Components Failed: {len(self.results) - successful_components}")
        print(f"Total Tests Run: {total_tests}")
        print(f"Total Failures: {total_failures}")
        print(f"Total Errors: {total_errors}")
        print(f"Total Duration: {total_duration:.2f} seconds")
        print(f"Success Rate: {successful_components/len(self.results)*100:.1f}%")
        
        # Failure details
        if total_failures > 0 or total_errors > 0:
            print(f"\n❌ FAILURE DETAILS")
            print(f"{'='*40}")
            for result in self.results:
                if not result.success and result.error_details:
                    print(f"\n{result.name}:")
                    for detail in result.error_details[:5]:  # Limit to first 5 errors
                        print(f"  • {detail}")
                    if len(result.error_details) > 5:
                        print(f"  • ... and {len(result.error_details) - 5} more errors")
        
        # Security compliance status
        print(f"\n🔒 SECURITY COMPLIANCE STATUS")
        print(f"{'='*40}")
        
        critical_security_components = [
            "Secure Memory", "Encryption", "Input Validator", 
            "Hardware Binding", "Emergency Protocol"
        ]
        
        security_passed = sum(1 for result in self.results 
                            if result.name in critical_security_components and result.success)
        security_total = sum(1 for result in self.results 
                           if result.name in critical_security_components)
        
        security_status = "✅ COMPLIANT" if security_passed == security_total else "❌ NON-COMPLIANT"
        print(f"Security Components Status: {security_status}")
        print(f"Security Components Passed: {security_passed}/{security_total}")
        
        if security_passed == security_total:
            print("🛡️ All critical security components are functioning correctly.")
        else:
            print("⚠️ Critical security components have failures - immediate attention required!")
        
        # Final verdict
        print(f"\n🏆 FINAL VERDICT")
        print(f"{'='*40}")
        
        if all(result.success for result in self.results):
            print("✅ ALL TESTS PASSED - BAR system is ready for deployment")
        elif security_passed == security_total:
            print("⚠️ PARTIAL SUCCESS - Core security is intact but some components need attention")
        else:
            print("❌ CRITICAL FAILURES - BAR system requires immediate fixes before deployment")
        
        print(f"\nTest completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")


def run_critical_components_tests():
    """Run all critical component tests."""
    runner = CriticalComponentsTestRunner()
    return runner.run_all_tests()


def main():
    """Main entry point for the test suite."""
    try:
        success = run_critical_components_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Test execution interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n💥 Unexpected error during test execution: {str(e)}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())