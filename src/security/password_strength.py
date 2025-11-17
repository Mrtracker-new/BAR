"""Password strength validation module.

This module provides comprehensive password strength validation including:
- Entropy calculation using Shannon entropy
- Common password detection
- Character complexity requirements
- Minimum length enforcement
"""

import math
import re
from typing import Dict, Optional, Tuple
from collections import Counter


# Extended list of common weak passwords
COMMON_PASSWORDS = {
    # Top weak passwords
    'password', '123456', '123456789', 'qwerty', 'abc123', '12345678',
    'password123', 'admin', 'root', 'user', 'guest', '1234567890',
    'letmein', 'welcome', 'monkey', 'dragon', 'master', 'sunshine',
    'princess', 'football', 'iloveyou', 'shadow', 'michael', 'jennifer',
    '111111', '000000', '123123', '654321', 'superman', 'qazwsx',
    'trustno1', 'passw0rd', 'password1', '1234', '12345', '123',
    # Keyboard patterns
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qwerty123',
    'qwerty12345', 'admin123', 'pass', 'login', 'welcome123',
    # Common variations
    'Password1', 'Password123', 'Admin123', 'Qwerty123',
    'password!', 'Password!', 'Password1!', 'Password@123',
}


# Common password patterns (regex)
COMMON_PATTERNS = [
    r'^password\d*$',  # password + optional numbers
    r'^\d{4,}$',  # All numbers (4+ digits)
    r'^[a-z]{4,}$',  # All lowercase letters
    r'^[A-Z]{4,}$',  # All uppercase letters
    r'^(.)\1{2,}$',  # Repeated character (aaa, 111, etc.)
    r'^(..)\1{1,}$',  # Repeated pairs (abab, 1212, etc.)
    r'^123+',  # Starts with 123
    r'abc',  # Contains abc
]


class PasswordStrength:
    """Password strength analyzer with entropy calculation."""
    
    # Minimum requirements
    MIN_LENGTH = 12
    MIN_ENTROPY_BITS = 50  # Recommended minimum for strong passwords
    RECOMMENDED_ENTROPY_BITS = 60  # Better security
    
    def __init__(self, 
                 min_length: int = MIN_LENGTH,
                 min_entropy_bits: float = MIN_ENTROPY_BITS,
                 require_uppercase: bool = True,
                 require_lowercase: bool = True,
                 require_numbers: bool = True,
                 require_special: bool = False):
        """Initialize password strength validator.
        
        Args:
            min_length: Minimum password length
            min_entropy_bits: Minimum entropy in bits
            require_uppercase: Whether uppercase letters are required
            require_lowercase: Whether lowercase letters are required
            require_numbers: Whether numbers are required
            require_special: Whether special characters are required
        """
        self.min_length = min_length
        self.min_entropy_bits = min_entropy_bits
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_numbers = require_numbers
        self.require_special = require_special
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of a password.
        
        Shannon entropy measures the unpredictability of information content.
        Higher entropy means more unpredictable and stronger password.
        
        Formula: H(X) = -Σ(P(xi) * log2(P(xi)))
        
        Args:
            password: Password to analyze
            
        Returns:
            Entropy in bits
        """
        if not password:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(password)
        password_length = len(password)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / password_length
            entropy -= probability * math.log2(probability)
        
        # Total entropy is per-character entropy * length
        total_entropy = entropy * password_length
        
        return total_entropy
    
    def calculate_character_space(self, password: str) -> int:
        """Calculate the character space (pool size) of a password.
        
        This determines how many possible characters could have been used.
        
        Args:
            password: Password to analyze
            
        Returns:
            Character space size
        """
        space = 0
        
        if re.search(r'[a-z]', password):
            space += 26  # lowercase letters
        if re.search(r'[A-Z]', password):
            space += 26  # uppercase letters
        if re.search(r'[0-9]', password):
            space += 10  # digits
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', password):
            space += 32  # special characters (approximate)
        
        return space
    
    def calculate_theoretical_entropy(self, password: str) -> float:
        """Calculate theoretical entropy based on character space.
        
        This is the maximum possible entropy for a password of given length
        and character space. It assumes each character is chosen randomly.
        
        Formula: E = log2(N^L) = L * log2(N)
        where N = character space, L = password length
        
        Args:
            password: Password to analyze
            
        Returns:
            Theoretical entropy in bits
        """
        if not password:
            return 0.0
        
        char_space = self.calculate_character_space(password)
        if char_space == 0:
            return 0.0
        
        return len(password) * math.log2(char_space)
    
    def is_common_password(self, password: str) -> bool:
        """Check if password is in the common password list.
        
        Args:
            password: Password to check
            
        Returns:
            True if password is common/weak
        """
        # Check exact match (case-insensitive)
        if password.lower() in COMMON_PASSWORDS:
            return True
        
        # Check against common patterns
        for pattern in COMMON_PATTERNS:
            if re.match(pattern, password, re.IGNORECASE):
                return True
        
        return False
    
    def check_complexity(self, password: str) -> Tuple[bool, str]:
        """Check if password meets complexity requirements.
        
        Args:
            password: Password to check
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if self.require_lowercase and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if self.require_numbers and not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"
        
        if self.require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', password):
            return False, "Password must contain at least one special character"
        
        return True, ""
    
    def validate_password(self, password: str) -> Dict[str, any]:
        """Perform comprehensive password validation.
        
        Args:
            password: Password to validate
            
        Returns:
            Dictionary with validation results:
            {
                'is_valid': bool,
                'strength': str (weak/medium/strong/very_strong),
                'entropy': float,
                'theoretical_entropy': float,
                'errors': list of error messages,
                'warnings': list of warning messages,
                'score': int (0-100)
            }
        """
        errors = []
        warnings = []
        
        # Check length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        # Check common passwords
        if self.is_common_password(password):
            errors.append("Password is too common or follows a predictable pattern")
        
        # Check complexity
        is_complex, complexity_error = self.check_complexity(password)
        if not is_complex:
            errors.append(complexity_error)
        
        # Calculate entropy
        actual_entropy = self.calculate_entropy(password)
        theoretical_entropy = self.calculate_theoretical_entropy(password)
        
        # Check entropy
        if actual_entropy < self.min_entropy_bits:
            errors.append(f"Password entropy too low ({actual_entropy:.1f} bits, minimum {self.min_entropy_bits} bits required)")
        
        # Add warnings for medium-strength passwords
        if self.min_entropy_bits <= actual_entropy < self.RECOMMENDED_ENTROPY_BITS:
            warnings.append(f"Password could be stronger (current: {actual_entropy:.1f} bits, recommended: {self.RECOMMENDED_ENTROPY_BITS} bits)")
        
        # Determine strength level
        is_valid = len(errors) == 0
        
        if actual_entropy < 40:
            strength = "weak"
            score = min(40, int(actual_entropy))
        elif actual_entropy < 50:
            strength = "medium"
            score = 40 + int((actual_entropy - 40) * 3)
        elif actual_entropy < 60:
            strength = "strong"
            score = 70 + int((actual_entropy - 50) * 2)
        else:
            strength = "very_strong"
            score = min(100, 90 + int((actual_entropy - 60) / 2))
        
        return {
            'is_valid': is_valid,
            'strength': strength,
            'entropy': actual_entropy,
            'theoretical_entropy': theoretical_entropy,
            'errors': errors,
            'warnings': warnings,
            'score': score
        }
    
    def get_strength_feedback(self, password: str) -> str:
        """Get human-readable feedback on password strength.
        
        Args:
            password: Password to analyze
            
        Returns:
            Feedback string
        """
        result = self.validate_password(password)
        
        feedback = f"Strength: {result['strength'].upper()} (Score: {result['score']}/100)\n"
        feedback += f"Entropy: {result['entropy']:.1f} bits\n"
        
        if result['errors']:
            feedback += "\nErrors:\n"
            for error in result['errors']:
                feedback += f"  ❌ {error}\n"
        
        if result['warnings']:
            feedback += "\nWarnings:\n"
            for warning in result['warnings']:
                feedback += f"  ⚠️  {warning}\n"
        
        if result['is_valid']:
            feedback += "\n✅ Password meets security requirements"
        
        return feedback


def validate_password_strength(password: str,
                               min_length: int = PasswordStrength.MIN_LENGTH,
                               min_entropy_bits: float = PasswordStrength.MIN_ENTROPY_BITS,
                               require_complexity: bool = True) -> Dict[str, any]:
    """Convenience function to validate password strength.
    
    Args:
        password: Password to validate
        min_length: Minimum password length
        min_entropy_bits: Minimum entropy in bits
        require_complexity: Whether to require character complexity
        
    Returns:
        Validation result dictionary
    """
    validator = PasswordStrength(
        min_length=min_length,
        min_entropy_bits=min_entropy_bits,
        require_uppercase=require_complexity,
        require_lowercase=require_complexity,
        require_numbers=require_complexity,
        require_special=False
    )
    
    return validator.validate_password(password)


if __name__ == "__main__":
    # Test the password strength validator
    test_passwords = [
        "a",  # Too short, very weak
        "password",  # Common password
        "Password123",  # Common pattern
        "short1A",  # Too short
        "MySecureP@ssw0rd!2024",  # Strong
        "correct-horse-battery-staple",  # Long but lower entropy
        "Tr0ub4dor&3",  # Medium strength
        "aaaaaaaaaaaa",  # Low entropy
    ]
    
    validator = PasswordStrength()
    
    print("Password Strength Validator Test\n" + "=" * 50)
    for pwd in test_passwords:
        print(f"\nPassword: {'*' * len(pwd)} (length: {len(pwd)})")
        print(validator.get_strength_feedback(pwd))
        print("-" * 50)
