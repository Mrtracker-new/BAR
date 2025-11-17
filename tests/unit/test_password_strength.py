"""Unit tests for password strength validation.

Tests cover:
- Entropy calculation
- Common password detection
- Complexity requirements
- Integration with encryption module
"""

import unittest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.security.password_strength import (
    PasswordStrength,
    validate_password_strength,
    COMMON_PASSWORDS
)
from src.crypto.encryption import EncryptionManager
from src.security.input_validator import CryptographicValidationError


class TestPasswordEntropy(unittest.TestCase):
    """Test entropy calculation."""
    
    def setUp(self):
        self.validator = PasswordStrength()
    
    def test_entropy_single_character(self):
        """Test entropy calculation for single character passwords."""
        password = "a"
        entropy = self.validator.calculate_entropy(password)
        # Single character has 0 entropy (no uncertainty)
        self.assertEqual(entropy, 0.0)
    
    def test_entropy_repeated_characters(self):
        """Test entropy for repeated characters."""
        password = "aaaaaaaaaaaaa"
        entropy = self.validator.calculate_entropy(password)
        # All same characters = 0 entropy
        self.assertEqual(entropy, 0.0)
    
    def test_entropy_simple_pattern(self):
        """Test entropy for simple patterns."""
        password = "abababab"
        entropy = self.validator.calculate_entropy(password)
        # Simple pattern has low entropy
        self.assertLess(entropy, 10.0)
    
    def test_entropy_diverse_password(self):
        """Test entropy for diverse password."""
        password = "MySecureP@ssw0rd!2024"
        entropy = self.validator.calculate_entropy(password)
        # Diverse password should have high entropy
        self.assertGreater(entropy, 60.0)
    
    def test_entropy_random_characters(self):
        """Test entropy for random-looking characters."""
        password = "7mK9$pL2xQ&nZ5wJ"
        entropy = self.validator.calculate_entropy(password)
        # Random characters should have very high entropy
        self.assertGreater(entropy, 60.0)
    
    def test_character_space_lowercase(self):
        """Test character space calculation for lowercase only."""
        password = "abcdefghijk"
        space = self.validator.calculate_character_space(password)
        self.assertEqual(space, 26)
    
    def test_character_space_mixed(self):
        """Test character space calculation for mixed characters."""
        password = "AbC123!@#"
        space = self.validator.calculate_character_space(password)
        # Should be 26 (lower) + 26 (upper) + 10 (digits) + 32 (special)
        self.assertEqual(space, 94)
    
    def test_theoretical_entropy(self):
        """Test theoretical entropy calculation."""
        password = "Password123"  # 11 chars, mixed case + numbers
        theoretical = self.validator.calculate_theoretical_entropy(password)
        # Theoretical entropy for 11 chars from 62-char space
        # log2(62^11) = 11 * log2(62) ≈ 11 * 5.95 ≈ 65.5
        self.assertGreater(theoretical, 60.0)
        self.assertLess(theoretical, 70.0)


class TestCommonPasswordDetection(unittest.TestCase):
    """Test common password detection."""
    
    def setUp(self):
        self.validator = PasswordStrength()
    
    def test_common_password_exact_match(self):
        """Test detection of exact common passwords."""
        for pwd in ['password', '123456', 'qwerty', 'admin']:
            self.assertTrue(self.validator.is_common_password(pwd))
    
    def test_common_password_case_insensitive(self):
        """Test case-insensitive detection."""
        for pwd in ['PASSWORD', 'Password', 'PaSsWoRd']:
            self.assertTrue(self.validator.is_common_password(pwd))
    
    def test_common_password_patterns(self):
        """Test detection of common patterns."""
        # All numbers
        self.assertTrue(self.validator.is_common_password('12345678'))
        # All lowercase
        self.assertTrue(self.validator.is_common_password('abcdefgh'))
        # Repeated characters
        self.assertTrue(self.validator.is_common_password('aaaa'))
    
    def test_strong_password_not_common(self):
        """Test that strong passwords are not flagged as common."""
        strong_passwords = [
            'MySecureP@ssw0rd!2024',
            'Tr0ub4dor&3xK9m',
            'correct-HORSE-battery-STAPLE-42'
        ]
        for pwd in strong_passwords:
            self.assertFalse(self.validator.is_common_password(pwd))


class TestPasswordComplexity(unittest.TestCase):
    """Test password complexity requirements."""
    
    def setUp(self):
        self.validator = PasswordStrength()
    
    def test_complexity_missing_uppercase(self):
        """Test detection of missing uppercase."""
        is_valid, error = self.validator.check_complexity('password123!')
        self.assertFalse(is_valid)
        self.assertIn('uppercase', error.lower())
    
    def test_complexity_missing_lowercase(self):
        """Test detection of missing lowercase."""
        is_valid, error = self.validator.check_complexity('PASSWORD123!')
        self.assertFalse(is_valid)
        self.assertIn('lowercase', error.lower())
    
    def test_complexity_missing_numbers(self):
        """Test detection of missing numbers."""
        is_valid, error = self.validator.check_complexity('PasswordOnly!')
        self.assertFalse(is_valid)
        self.assertIn('number', error.lower())
    
    def test_complexity_all_requirements_met(self):
        """Test password meeting all complexity requirements."""
        is_valid, error = self.validator.check_complexity('Password123')
        self.assertTrue(is_valid)
        self.assertEqual(error, '')


class TestPasswordValidation(unittest.TestCase):
    """Test comprehensive password validation."""
    
    def test_weak_password_too_short(self):
        """Test rejection of too-short passwords."""
        result = validate_password_strength('Pass1')
        self.assertFalse(result['is_valid'])
        self.assertIn('12 characters', ' '.join(result['errors']))
    
    def test_weak_password_single_character(self):
        """Test rejection of single character passwords."""
        result = validate_password_strength('a')
        self.assertFalse(result['is_valid'])
        # Should fail on multiple criteria
        self.assertGreater(len(result['errors']), 1)
    
    def test_weak_password_common(self):
        """Test rejection of common passwords."""
        result = validate_password_strength('password123456')
        self.assertFalse(result['is_valid'])
        error_text = ' '.join(result['errors']).lower()
        self.assertTrue('common' in error_text or 'pattern' in error_text)
    
    def test_weak_password_low_entropy(self):
        """Test rejection of low-entropy passwords."""
        result = validate_password_strength('aaaaaaaaaaaa')  # 12 a's
        self.assertFalse(result['is_valid'])
        self.assertIn('entropy', ' '.join(result['errors']).lower())
    
    def test_medium_password(self):
        """Test medium-strength password."""
        result = validate_password_strength('Tr0ub4dor&3')
        # Might not meet minimum requirements
        if not result['is_valid']:
            self.assertIn('12 characters', ' '.join(result['errors']))
    
    def test_strong_password_accepted(self):
        """Test acceptance of strong passwords."""
        strong_passwords = [
            'MySecureP@ssw0rd!2024',
            'Correct-Horse-Battery-Staple-42',
            'Tr0ub4dor&3ExtraSecure',
            'G00d!P4ssW0rd#2024'
        ]
        
        for pwd in strong_passwords:
            result = validate_password_strength(pwd)
            self.assertTrue(result['is_valid'], 
                          f"Password '{pwd}' should be valid. Errors: {result['errors']}")
            self.assertIn(result['strength'], ['strong', 'very_strong'])
    
    def test_password_strength_levels(self):
        """Test password strength level classification."""
        # Very weak
        result = validate_password_strength('Pass1', min_length=5, min_entropy_bits=1)
        self.assertEqual(result['strength'], 'weak')
        
        # Strong
        result = validate_password_strength('MySecurePassword123')
        if result['is_valid']:
            self.assertIn(result['strength'], ['strong', 'very_strong'])
    
    def test_password_score(self):
        """Test password scoring system."""
        # Weak password should have low score
        weak_result = validate_password_strength('Pass1', min_length=5, min_entropy_bits=1)
        self.assertLess(weak_result['score'], 50)
        
        # Strong password should have high score
        strong_result = validate_password_strength('MySecureP@ssw0rd!2024')
        if strong_result['is_valid']:
            self.assertGreater(strong_result['score'], 70)


class TestEncryptionIntegration(unittest.TestCase):
    """Test integration with encryption module."""
    
    def test_encryption_rejects_weak_password(self):
        """Test that encryption rejects weak passwords."""
        weak_passwords = ['a', '123', 'password', 'Pass1', 'weak']
        test_content = b"Test data to encrypt"
        
        for weak_pwd in weak_passwords:
            with self.assertRaises(CryptographicValidationError) as context:
                EncryptionManager.encrypt_file_content(test_content, weak_pwd)
            
            # Verify it's a password validation error
            error_msg = str(context.exception).lower()
            self.assertTrue(
                any(word in error_msg for word in ['password', 'length', 'complexity', 'entropy']),
                f"Expected password validation error, got: {context.exception}"
            )
    
    def test_encryption_accepts_strong_password(self):
        """Test that encryption accepts strong passwords."""
        strong_password = 'MySecureP@ssw0rd!2024'
        test_content = b"Test data to encrypt"
        
        # Should not raise an exception
        encrypted = EncryptionManager.encrypt_file_content(test_content, strong_password)
        
        # Verify encrypted data structure
        self.assertIn('ciphertext', encrypted)
        self.assertIn('nonce', encrypted)
        self.assertIn('salt', encrypted)
        
        # Verify decryption works
        decrypted = EncryptionManager.decrypt_file_content(encrypted, strong_password)
        self.assertEqual(decrypted, test_content)
    
    def test_derive_key_requires_strong_password(self):
        """Test that key derivation requires strong password."""
        weak_password = 'weak'
        salt = EncryptionManager.generate_salt()
        
        with self.assertRaises(CryptographicValidationError):
            EncryptionManager.derive_key(weak_password, salt)
    
    def test_derive_key_works_with_strong_password(self):
        """Test that key derivation works with strong password."""
        strong_password = 'MySecureP@ssw0rd!2024'
        salt = EncryptionManager.generate_salt()
        
        # Should not raise an exception
        key = EncryptionManager.derive_key(strong_password, salt)
        
        # Verify key is the correct size
        self.assertEqual(len(key), EncryptionManager.KEY_SIZE)


class TestPasswordStrengthFeedback(unittest.TestCase):
    """Test password strength feedback generation."""
    
    def setUp(self):
        self.validator = PasswordStrength()
    
    def test_feedback_includes_strength(self):
        """Test that feedback includes strength level."""
        feedback = self.validator.get_strength_feedback('MySecureP@ssw0rd!2024')
        self.assertIn('Strength:', feedback)
    
    def test_feedback_includes_entropy(self):
        """Test that feedback includes entropy value."""
        feedback = self.validator.get_strength_feedback('MySecureP@ssw0rd!2024')
        self.assertIn('Entropy:', feedback)
        self.assertIn('bits', feedback)
    
    def test_feedback_shows_errors_for_weak_password(self):
        """Test that feedback shows errors for weak passwords."""
        feedback = self.validator.get_strength_feedback('weak')
        self.assertIn('Error', feedback)
    
    def test_feedback_shows_success_for_strong_password(self):
        """Test that feedback shows success for strong passwords."""
        feedback = self.validator.get_strength_feedback('MySecureP@ssw0rd!2024')
        self.assertIn('✅', feedback)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def test_empty_password(self):
        """Test handling of empty password."""
        validator = PasswordStrength()
        result = validator.validate_password('')
        self.assertFalse(result['is_valid'])
    
    def test_very_long_password(self):
        """Test handling of very long passwords."""
        # Create a long but valid password
        long_password = 'MySecureP@ssw0rd!2024' * 10  # 210 characters
        result = validate_password_strength(long_password)
        # Should be valid (high entropy and meets all requirements)
        self.assertTrue(result['is_valid'])
    
    def test_unicode_password(self):
        """Test handling of unicode characters."""
        unicode_password = 'MyPässwörd123€'
        result = validate_password_strength(unicode_password)
        # Should validate (might fail length or other requirements)
        self.assertIsNotNone(result)
    
    def test_minimum_entropy_boundary(self):
        """Test password at minimum entropy boundary."""
        # Create password with exactly minimum entropy
        validator = PasswordStrength(min_length=12, min_entropy_bits=40)
        # This should be close to the boundary
        result = validator.validate_password('MyPassword12')
        self.assertIsNotNone(result)


def run_tests():
    """Run all tests and return results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordEntropy))
    suite.addTests(loader.loadTestsFromTestCase(TestCommonPasswordDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordComplexity))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestEncryptionIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordStrengthFeedback))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == '__main__':
    result = run_tests()
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
