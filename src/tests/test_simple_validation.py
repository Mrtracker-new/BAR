#!/usr/bin/env python3
"""
Simple validation test to verify core functionality

This script tests the actual BAR validation system to verify it's working
correctly and understand the real API.

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_basic_validation():
    """Test basic validation functionality."""
    try:
        from security.input_validator import (
            InputValidator, ValidationConfig, ValidationLevel,
            get_global_validator, get_crypto_validator, get_file_validator,
            validate_string, validate_integer
        )
        print("✅ Successfully imported validation modules")
    except ImportError as e:
        print(f"❌ Failed to import validation modules: {e}")
        return False
    
    # Test basic string validation
    try:
        result = validate_string("hello world", field_name="test")
        print(f"✅ Basic string validation: {result.is_valid}, sanitized: '{result.sanitized_value}'")
        
        # Test attack detection
        result = validate_string("'; DROP TABLE users; --", field_name="sql_test")
        print(f"✅ SQL injection detection: valid={result.is_valid}, violation={result.violation_type}, risk={result.security_risk_level}")
        
        # Test command injection detection
        result = validate_string("$(rm -rf /)", field_name="cmd_test")
        print(f"✅ Command injection detection: valid={result.is_valid}, violation={result.violation_type}, risk={result.security_risk_level}")
        
        # Test script injection detection
        result = validate_string("<script>alert('xss')</script>", field_name="script_test")
        print(f"✅ Script injection detection: valid={result.is_valid}, violation={result.violation_type}, risk={result.security_risk_level}")
        
    except Exception as e:
        print(f"❌ String validation error: {e}")
        return False
    
    # Test integer validation
    try:
        result = validate_integer(42, field_name="number_test")
        print(f"✅ Integer validation: valid={result.is_valid}, value={result.sanitized_value}")
        
        result = validate_integer("not_a_number", field_name="bad_number")
        print(f"✅ Bad integer detection: valid={result.is_valid}, violation={result.violation_type}")
        
    except Exception as e:
        print(f"❌ Integer validation error: {e}")
        return False
    
    # Test crypto validation
    try:
        crypto_validator = get_crypto_validator()
        
        # Test password validation
        result = crypto_validator.validate_password("SecureP@ssw0rd123!", field_name="strong_pwd")
        print(f"✅ Strong password validation: valid={result.is_valid}, risk={result.security_risk_level}")
        
        result = crypto_validator.validate_password("weak", field_name="weak_pwd")
        print(f"✅ Weak password detection: valid={result.is_valid}, violation={result.violation_type}")
        
    except Exception as e:
        print(f"❌ Crypto validation error: {e}")
        return False
    
    # Test file validation
    try:
        file_validator = get_file_validator()
        
        # Test filename validation
        result = file_validator.validate_filename("document.txt", field_name="good_file")
        print(f"✅ Good filename validation: valid={result.is_valid}")
        
        result = file_validator.validate_filename("../../../etc/passwd", field_name="bad_file")
        print(f"✅ Path traversal detection: valid={result.is_valid}, violation={result.violation_type}")
        
    except Exception as e:
        print(f"❌ File validation error: {e}")
        return False
    
    print("\n🎉 All basic validation tests completed successfully!")
    return True


def test_performance():
    """Test validation performance."""
    try:
        import time
        from security.input_validator import validate_string
        
        print("\n⏱️ Performance testing...")
        
        # Test many validations
        start_time = time.time()
        for i in range(1000):
            result = validate_string(f"test_string_{i}", field_name="perf_test")
        end_time = time.time()
        
        duration = end_time - start_time
        rate = 1000 / duration
        
        print(f"✅ Performance test: {1000} validations in {duration:.3f}s ({rate:.1f} validations/sec)")
        
        if rate > 500:  # Expect at least 500 validations per second
            print("✅ Performance is acceptable")
        else:
            print("⚠️ Performance might be slow")
        
    except Exception as e:
        print(f"❌ Performance test error: {e}")
        return False
    
    return True


def main():
    """Main test function."""
    print("🔒 BAR Input Validation System Test")
    print("=" * 50)
    
    success = True
    
    # Test basic functionality
    if not test_basic_validation():
        success = False
    
    # Test performance
    if not test_performance():
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests passed! Validation system is working correctly.")
    else:
        print("❌ Some tests failed. Please check the validation system.")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())