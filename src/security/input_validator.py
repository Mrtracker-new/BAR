"""
BAR Input Validation System

This module provides comprehensive input validation for all components of the BAR project,
implementing security-first validation according to BAR project rules R030 - Input Validation.

Security Features:
- Prevents injection attacks (SQL, command, path traversal, etc.)
- Validates cryptographic parameters and data integrity
- Enforces secure data types and ranges
- Protects against buffer overflow and memory corruption
- Implements timing-attack resistant validation
- Provides detailed logging without information leakage

Per BAR Rules R030:
- NEVER trust any external input without validation
- NEVER use string concatenation for SQL-like operations
- NEVER allow arbitrary code execution through user input
- NEVER bypass security checks for "convenience"

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import os
import re
import sys
import hmac
import hashlib
import secrets
import logging
import unicodedata
from pathlib import Path, PurePath
from typing import Any, Optional, Union, List, Dict, Callable, Tuple, TypeVar, Generic
from enum import Enum
from dataclasses import dataclass
from contextlib import contextmanager
import time

# Enhanced type checking
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

T = TypeVar('T')

class ValidationLevel(Enum):
    """Validation security levels."""
    BASIC = "basic"           # Basic type and range checking
    ENHANCED = "enhanced"     # Enhanced security validation
    STRICT = "strict"         # Strict security validation with detailed checks
    PARANOID = "paranoid"     # Maximum security - assume all input is malicious


class ValidationError(Exception):
    """Base exception for input validation failures."""
    
    def __init__(self, message: str, field_name: Optional[str] = None, 
                 violation_type: Optional[str] = None, 
                 sanitized_value: Optional[Any] = None):
        super().__init__(message)
        self.field_name = field_name
        self.violation_type = violation_type
        self.sanitized_value = sanitized_value


class CryptographicValidationError(ValidationError):
    """Raised when cryptographic parameter validation fails."""
    pass


class FileValidationError(ValidationError):
    """Raised when file operation validation fails."""
    pass


class MemoryValidationError(ValidationError):
    """Raised when memory operation validation fails."""
    pass


class ConfigValidationError(ValidationError):
    """Raised when configuration validation fails."""
    pass


class NetworkValidationError(ValidationError):
    """Raised when network-related validation fails."""
    pass


@dataclass
class ValidationResult:
    """Result of input validation operation."""
    is_valid: bool
    sanitized_value: Optional[Any] = None
    error_message: Optional[str] = None
    violation_type: Optional[str] = None
    security_risk_level: str = "low"  # low, medium, high, critical


@dataclass  
class ValidationConfig:
    """Configuration for validation behavior."""
    level: ValidationLevel = ValidationLevel.ENHANCED
    max_length: int = 1024 * 1024  # 1MB default
    allow_unicode: bool = True
    normalize_unicode: bool = True
    strict_encoding: bool = True
    log_violations: bool = True
    timing_attack_protection: bool = True


class InputValidator:
    """
    Comprehensive input validation system for BAR project.
    
    This class provides secure validation for all types of inputs, implementing
    defense-in-depth validation according to BAR security requirements.
    """
    
    # Security constants
    MAX_SAFE_STRING_LENGTH = 1024 * 1024  # 1MB
    MAX_SAFE_BYTES_LENGTH = 100 * 1024 * 1024  # 100MB
    MAX_SAFE_INTEGER = 2**53 - 1  # JavaScript safe integer limit
    MIN_SAFE_INTEGER = -(2**53 - 1)
    
    # Dangerous patterns that should never appear in input
    DANGEROUS_PATTERNS = [
        # Command injection patterns
        r'[;&|`$(){}[\]<>]',
        r'\$\([^)]*\)',  # Command substitution
        r'`[^`]*`',      # Backtick execution
        r'&&|[\|\|]',    # Command chaining
        
        # Path traversal patterns
        r'\.\./+',       # Directory traversal
        r'\.\.\\+',      # Windows directory traversal
        r'/etc/',        # Unix system directories
        r'/proc/',       # Linux proc filesystem
        r'/sys/',        # Linux sys filesystem
        r'C:\\Windows',  # Windows system directory
        r'C:\\System32', # Windows system32
        
        # Script injection patterns
        r'<script[^>]*>',
        r'javascript:',
        r'vbscript:',
        r'on\w+\s*=',    # Event handlers
        
        # SQL injection patterns
        r"'(\s*(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+)",
        r'--\s',         # SQL comments
        r'/\*.*\*/',     # SQL block comments
        
        # Format string vulnerabilities
        r'%[0-9]*[dioxXeEfFgGaAcspn%]',
        r'\{[^}]*\}',    # Python format strings (context dependent)
    ]
    
    # Compiled patterns for performance
    _compiled_patterns = None
    _logger = None
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        """Initialize the input validator.
        
        Args:
            config: Validation configuration
        """
        self.config = config or ValidationConfig()
        self._logger = logging.getLogger(f"InputValidator_{id(self)}")
        
        # Compile dangerous patterns for performance
        if InputValidator._compiled_patterns is None:
            InputValidator._compiled_patterns = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in self.DANGEROUS_PATTERNS
            ]
        
        self._validation_stats = {
            'total_validations': 0,
            'failed_validations': 0,
            'security_violations': 0,
            'timing_attacks_detected': 0
        }
    
    @contextmanager
    def _timing_attack_protection(self, operation_name: str):
        """Context manager for timing attack protection.
        
        Ensures consistent timing for validation operations to prevent
        timing-based information leakage.
        
        Args:
            operation_name: Name of the operation for logging
        """
        start_time = time.time()
        
        try:
            yield
        finally:
            if self.config.timing_attack_protection:
                # Ensure minimum processing time to prevent timing attacks
                elapsed = time.time() - start_time
                min_time = 0.001  # 1ms minimum
                if elapsed < min_time:
                    time.sleep(min_time - elapsed)
    
    def _log_validation_result(self, result: ValidationResult, field_name: Optional[str] = None):
        """Log validation results securely without exposing sensitive data.
        
        Args:
            result: Validation result to log
            field_name: Name of the field being validated
        """
        if not self.config.log_violations:
            return
            
        if not result.is_valid:
            self._validation_stats['failed_validations'] += 1
            
            if result.security_risk_level in ('high', 'critical'):
                self._validation_stats['security_violations'] += 1
                self._logger.warning(
                    f"Security validation failure - field: {field_name or 'unknown'}, "
                    f"violation: {result.violation_type or 'unknown'}, "
                    f"risk: {result.security_risk_level}"
                )
            else:
                self._logger.debug(
                    f"Validation failure - field: {field_name or 'unknown'}, "
                    f"type: {result.violation_type or 'unknown'}"
                )
    
    def _detect_dangerous_patterns(self, value: str) -> List[str]:
        """Detect dangerous patterns in input strings.
        
        Args:
            value: String value to check
            
        Returns:
            List of detected dangerous pattern types
        """
        violations = []
        
        for i, pattern in enumerate(InputValidator._compiled_patterns):
            if pattern.search(value):
                pattern_type = [
                    'command_injection', 'command_injection', 'command_injection', 'command_chaining',
                    'path_traversal', 'path_traversal', 'system_access', 'system_access', 'system_access',
                    'system_access', 'system_access',
                    'script_injection', 'script_injection', 'script_injection', 'script_injection',
                    'sql_injection', 'sql_injection', 'sql_injection',
                    'format_string', 'format_string'
                ][i % 20]  # Map pattern index to type
                violations.append(pattern_type)
        
        return violations
    
    def validate_string(self, value: Any, field_name: Optional[str] = None,
                       max_length: Optional[int] = None, 
                       min_length: int = 0,
                       allowed_chars: Optional[str] = None,
                       forbidden_chars: Optional[str] = None,
                       require_ascii: bool = False) -> ValidationResult:
        """Validate string input with comprehensive security checks.
        
        Args:
            value: Value to validate
            field_name: Name of the field for logging
            max_length: Maximum allowed length
            min_length: Minimum required length
            allowed_chars: Regex pattern of allowed characters
            forbidden_chars: Regex pattern of forbidden characters
            require_ascii: If True, only ASCII characters are allowed
            
        Returns:
            ValidationResult with validation outcome
        """
        with self._timing_attack_protection("string_validation"):
            self._validation_stats['total_validations'] += 1
            
            # Type validation
            if not isinstance(value, str):
                if value is None:
                    result = ValidationResult(
                        is_valid=False,
                        error_message="String value cannot be None",
                        violation_type="null_value",
                        security_risk_level="medium"
                    )
                else:
                    # Try to convert safely
                    try:
                        value = str(value)
                    except Exception:
                        result = ValidationResult(
                            is_valid=False,
                            error_message="Cannot convert value to string",
                            violation_type="type_error",
                            security_risk_level="medium"
                        )
                        self._log_validation_result(result, field_name)
                        return result
            
            # Length validation
            max_len = max_length or self.config.max_length
            if len(value) > max_len:
                result = ValidationResult(
                    is_valid=False,
                    error_message=f"String length exceeds maximum ({max_len})",
                    violation_type="length_exceeded",
                    security_risk_level="high"
                )
                self._log_validation_result(result, field_name)
                return result
            
            if len(value) < min_length:
                result = ValidationResult(
                    is_valid=False,
                    error_message=f"String length below minimum ({min_length})",
                    violation_type="length_insufficient",
                    security_risk_level="low"
                )
                self._log_validation_result(result, field_name)
                return result
            
            # Unicode validation and normalization
            if self.config.allow_unicode:
                try:
                    # Check for dangerous Unicode categories
                    for char in value:
                        category = unicodedata.category(char)
                        # Block dangerous Unicode categories
                        if category in ['Cc', 'Cf', 'Cs', 'Co', 'Cn']:  # Control chars, etc.
                            if char not in '\t\n\r ':  # Allow basic whitespace
                                result = ValidationResult(
                                    is_valid=False,
                                    error_message="Dangerous Unicode character detected",
                                    violation_type="unicode_control_char",
                                    security_risk_level="high"
                                )
                                self._log_validation_result(result, field_name)
                                return result
                    
                    # Normalize Unicode if requested
                    if self.config.normalize_unicode:
                        value = unicodedata.normalize('NFKC', value)
                        
                except UnicodeError:
                    result = ValidationResult(
                        is_valid=False,
                        error_message="Invalid Unicode encoding",
                        violation_type="unicode_error",
                        security_risk_level="high"
                    )
                    self._log_validation_result(result, field_name)
                    return result
            
            # ASCII-only validation if required
            if require_ascii:
                try:
                    value.encode('ascii')
                except UnicodeEncodeError:
                    result = ValidationResult(
                        is_valid=False,
                        error_message="Non-ASCII characters not allowed",
                        violation_type="non_ascii_chars",
                        security_risk_level="medium"
                    )
                    self._log_validation_result(result, field_name)
                    return result
            
            # Character set validation
            if allowed_chars:
                allowed_pattern = re.compile(f'^[{re.escape(allowed_chars)}]*$')
                if not allowed_pattern.match(value):
                    result = ValidationResult(
                        is_valid=False,
                        error_message="String contains disallowed characters",
                        violation_type="disallowed_chars",
                        security_risk_level="medium"
                    )
                    self._log_validation_result(result, field_name)
                    return result
            
            if forbidden_chars:
                forbidden_pattern = re.compile(f'[{re.escape(forbidden_chars)}]')
                if forbidden_pattern.search(value):
                    result = ValidationResult(
                        is_valid=False,
                        error_message="String contains forbidden characters",
                        violation_type="forbidden_chars",
                        security_risk_level="high"
                    )
                    self._log_validation_result(result, field_name)
                    return result
            
            # Security pattern detection
            if self.config.level in (ValidationLevel.STRICT, ValidationLevel.PARANOID):
                dangerous_patterns = self._detect_dangerous_patterns(value)
                if dangerous_patterns:
                    result = ValidationResult(
                        is_valid=False,
                        error_message="Potentially dangerous patterns detected",
                        violation_type="dangerous_patterns",
                        security_risk_level="critical"
                    )
                    self._log_validation_result(result, field_name)
                    return result
            
            # Success
            result = ValidationResult(
                is_valid=True,
                sanitized_value=value,
                security_risk_level="low"
            )
            self._log_validation_result(result, field_name)
            return result
    
    def validate_bytes(self, value: Any, field_name: Optional[str] = None,
                      max_length: Optional[int] = None,
                      min_length: int = 0,
                      require_encoding: Optional[str] = None) -> ValidationResult:
        """Validate bytes input with security checks.
        
        Args:
            value: Value to validate
            field_name: Name of the field for logging
            max_length: Maximum allowed length
            min_length: Minimum required length
            require_encoding: Required character encoding (e.g., 'utf-8')
            
        Returns:
            ValidationResult with validation outcome
        """
        with self._timing_attack_protection("bytes_validation"):
            self._validation_stats['total_validations'] += 1
            
            # Type validation
            if not isinstance(value, (bytes, bytearray)):
                if value is None:
                    result = ValidationResult(
                        is_valid=False,
                        error_message="Bytes value cannot be None",
                        violation_type="null_value",
                        security_risk_level="medium"
                    )
                else:
                    # Try to convert safely
                    try:
                        if isinstance(value, str):
                            value = value.encode('utf-8')
                        else:
                            value = bytes(value)
                    except Exception:
                        result = ValidationResult(
                            is_valid=False,
                            error_message="Cannot convert value to bytes",
                            violation_type="type_error",
                            security_risk_level="medium"
                        )
                        self._log_validation_result(result, field_name)
                        return result
            
            # Length validation
            max_len = max_length or self.MAX_SAFE_BYTES_LENGTH
            if len(value) > max_len:
                result = ValidationResult(
                    is_valid=False,
                    error_message=f"Bytes length exceeds maximum ({max_len})",
                    violation_type="length_exceeded",
                    security_risk_level="high"
                )
                self._log_validation_result(result, field_name)
                return result
            
            if len(value) < min_length:
                result = ValidationResult(
                    is_valid=False,
                    error_message=f"Bytes length below minimum ({min_length})",
                    violation_type="length_insufficient",
                    security_risk_level="low"
                )
                self._log_validation_result(result, field_name)
                return result
            
            # Encoding validation if required
            if require_encoding:
                try:
                    decoded = value.decode(require_encoding)
                    # Re-encode to verify round-trip integrity
                    if decoded.encode(require_encoding) != value:
                        result = ValidationResult(
                            is_valid=False,
                            error_message="Encoding round-trip validation failed",
                            violation_type="encoding_corruption",
                            security_risk_level="high"
                        )
                        self._log_validation_result(result, field_name)
                        return result
                except UnicodeDecodeError:
                    result = ValidationResult(
                        is_valid=False,
                        error_message=f"Invalid {require_encoding} encoding",
                        violation_type="encoding_error",
                        security_risk_level="high"
                    )
                    self._log_validation_result(result, field_name)
                    return result
            
            # Convert to bytes if bytearray for consistency
            if isinstance(value, bytearray):
                value = bytes(value)
            
            # Success
            result = ValidationResult(
                is_valid=True,
                sanitized_value=value,
                security_risk_level="low"
            )
            self._log_validation_result(result, field_name)
            return result
    
    def validate_integer(self, value: Any, field_name: Optional[str] = None,
                        min_value: Optional[int] = None,
                        max_value: Optional[int] = None,
                        allow_zero: bool = True,
                        allow_negative: bool = True) -> ValidationResult:
        """Validate integer input with range checks.
        
        Args:
            value: Value to validate
            field_name: Name of the field for logging
            min_value: Minimum allowed value
            max_value: Maximum allowed value
            allow_zero: Whether zero is allowed
            allow_negative: Whether negative values are allowed
            
        Returns:
            ValidationResult with validation outcome
        """
        with self._timing_attack_protection("integer_validation"):
            self._validation_stats['total_validations'] += 1
            
            # Type validation and conversion
            if not isinstance(value, int):
                if value is None:
                    result = ValidationResult(
                        is_valid=False,
                        error_message="Integer value cannot be None",
                        violation_type="null_value",
                        security_risk_level="medium"
                    )
                    self._log_validation_result(result, field_name)
                    return result
                
                # Try to convert safely
                try:
                    if isinstance(value, str):
                        # Check for non-numeric characters first
                        if not re.match(r'^-?\d+$', value.strip()):
                            result = ValidationResult(
                                is_valid=False,
                                error_message="String contains non-numeric characters",
                                violation_type="non_numeric",
                                security_risk_level="medium"
                            )
                            self._log_validation_result(result, field_name)
                            return result
                        value = int(value)
                    elif isinstance(value, float):
                        if value != int(value):  # Has fractional part
                            result = ValidationResult(
                                is_valid=False,
                                error_message="Float value has fractional part",
                                violation_type="fractional_value",
                                security_risk_level="low"
                            )
                            self._log_validation_result(result, field_name)
                            return result
                        value = int(value)
                    else:
                        value = int(value)
                except (ValueError, OverflowError):
                    result = ValidationResult(
                        is_valid=False,
                        error_message="Cannot convert value to integer",
                        violation_type="conversion_error",
                        security_risk_level="medium"
                    )
                    self._log_validation_result(result, field_name)
                    return result
            
            # Safe range validation
            if value > self.MAX_SAFE_INTEGER or value < self.MIN_SAFE_INTEGER:
                result = ValidationResult(
                    is_valid=False,
                    error_message="Integer value outside safe range",
                    violation_type="unsafe_range",
                    security_risk_level="high"
                )
                self._log_validation_result(result, field_name)
                return result
            
            # Zero validation
            if not allow_zero and value == 0:
                result = ValidationResult(
                    is_valid=False,
                    error_message="Zero value not allowed",
                    violation_type="zero_not_allowed",
                    security_risk_level="low"
                )
                self._log_validation_result(result, field_name)
                return result
            
            # Negative validation
            if not allow_negative and value < 0:
                result = ValidationResult(
                    is_valid=False,
                    error_message="Negative value not allowed",
                    violation_type="negative_not_allowed",
                    security_risk_level="low"
                )
                self._log_validation_result(result, field_name)
                return result
            
            # Range validation
            if min_value is not None and value < min_value:
                result = ValidationResult(
                    is_valid=False,
                    error_message=f"Value below minimum ({min_value})",
                    violation_type="below_minimum",
                    security_risk_level="medium"
                )
                self._log_validation_result(result, field_name)
                return result
            
            if max_value is not None and value > max_value:
                result = ValidationResult(
                    is_valid=False,
                    error_message=f"Value above maximum ({max_value})",
                    violation_type="above_maximum",
                    security_risk_level="medium"
                )
                self._log_validation_result(result, field_name)
                return result
            
            # Success
            result = ValidationResult(
                is_valid=True,
                sanitized_value=value,
                security_risk_level="low"
            )
            self._log_validation_result(result, field_name)
            return result


class CryptographicValidator:
    """Specialized validator for cryptographic parameters."""
    
    # Standard cryptographic sizes
    AES_KEY_SIZES = [16, 24, 32]  # AES-128, AES-192, AES-256
    NONCE_SIZES = [12, 16]        # GCM nonce sizes
    SALT_SIZES = [16, 32, 64]     # Common salt sizes
    HASH_SIZES = [20, 32, 48, 64] # SHA-1, SHA-256, SHA-384, SHA-512
    
    def __init__(self, validator: InputValidator):
        """Initialize with base validator.
        
        Args:
            validator: Base input validator instance
        """
        self.validator = validator
        self._logger = logging.getLogger(f"CryptographicValidator_{id(self)}")
    
    def validate_encryption_key(self, key: Any, 
                               algorithm: str = "AES",
                               field_name: Optional[str] = None) -> ValidationResult:
        """Validate encryption key parameters.
        
        Args:
            key: Key data to validate
            algorithm: Encryption algorithm (AES, ChaCha20, etc.)
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        # First validate as bytes
        bytes_result = self.validator.validate_bytes(
            key, field_name=field_name, min_length=1
        )
        if not bytes_result.is_valid:
            return bytes_result
        
        key_bytes = bytes_result.sanitized_value
        
        # Algorithm-specific validation
        if algorithm.upper() == "AES":
            if len(key_bytes) not in self.AES_KEY_SIZES:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid AES key size: {len(key_bytes)}. Must be 16, 24, or 32 bytes",
                    violation_type="invalid_key_size",
                    security_risk_level="critical"
                )
        elif algorithm.upper() == "CHACHA20":
            if len(key_bytes) != 32:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid ChaCha20 key size: {len(key_bytes)}. Must be 32 bytes",
                    violation_type="invalid_key_size",
                    security_risk_level="critical"
                )
        
        # Check for weak keys (all zeros, all ones, etc.)
        if self.validator.config.level in (ValidationLevel.STRICT, ValidationLevel.PARANOID):
            if self._is_weak_key(key_bytes):
                return ValidationResult(
                    is_valid=False,
                    error_message="Weak encryption key detected",
                    violation_type="weak_key",
                    security_risk_level="critical"
                )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=key_bytes,
            security_risk_level="low"
        )
    
    def validate_nonce(self, nonce: Any, 
                      algorithm: str = "GCM",
                      field_name: Optional[str] = None) -> ValidationResult:
        """Validate cryptographic nonce/IV.
        
        Args:
            nonce: Nonce data to validate
            algorithm: Algorithm using the nonce (GCM, CTR, etc.)
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        # First validate as bytes
        bytes_result = self.validator.validate_bytes(
            nonce, field_name=field_name, min_length=1
        )
        if not bytes_result.is_valid:
            return bytes_result
        
        nonce_bytes = bytes_result.sanitized_value
        
        # Algorithm-specific validation
        if algorithm.upper() == "GCM":
            if len(nonce_bytes) not in self.NONCE_SIZES:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid GCM nonce size: {len(nonce_bytes)}. Should be 12 or 16 bytes",
                    violation_type="invalid_nonce_size",
                    security_risk_level="high"
                )
        
        # Check for weak nonces (all zeros, predictable patterns)
        if self.validator.config.level in (ValidationLevel.STRICT, ValidationLevel.PARANOID):
            if self._is_weak_nonce(nonce_bytes):
                return ValidationResult(
                    is_valid=False,
                    error_message="Weak nonce detected",
                    violation_type="weak_nonce",
                    security_risk_level="high"
                )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=nonce_bytes,
            security_risk_level="low"
        )
    
    def validate_salt(self, salt: Any, 
                     min_size: int = 16,
                     field_name: Optional[str] = None) -> ValidationResult:
        """Validate cryptographic salt.
        
        Args:
            salt: Salt data to validate
            min_size: Minimum salt size in bytes
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        # First validate as bytes
        bytes_result = self.validator.validate_bytes(
            salt, field_name=field_name, min_length=min_size
        )
        if not bytes_result.is_valid:
            return bytes_result
        
        salt_bytes = bytes_result.sanitized_value
        
        # Check salt entropy and quality
        if self.validator.config.level in (ValidationLevel.STRICT, ValidationLevel.PARANOID):
            if self._is_weak_salt(salt_bytes):
                return ValidationResult(
                    is_valid=False,
                    error_message="Weak salt detected",
                    violation_type="weak_salt",
                    security_risk_level="high"
                )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=salt_bytes,
            security_risk_level="low"
        )
    
    def validate_password(self, password: Any,
                         min_length: int = 8,
                         max_length: int = 1024,
                         require_complexity: bool = True,
                         min_entropy_bits: Optional[float] = None,
                         field_name: Optional[str] = None) -> ValidationResult:
        """Validate password with security requirements including entropy.
        
        Args:
            password: Password to validate
            min_length: Minimum password length
            max_length: Maximum password length
            require_complexity: Whether to require password complexity
            min_entropy_bits: Minimum entropy in bits (default: 50 for complexity=True, None otherwise)
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        # First validate as string
        string_result = self.validator.validate_string(
            password, field_name=field_name, 
            min_length=min_length, max_length=max_length
        )
        if not string_result.is_valid:
            return string_result
        
        password_str = string_result.sanitized_value
        
        # If require_complexity is True, use the enhanced password strength validation
        if require_complexity:
            from src.security.password_strength import PasswordStrength
            
            # Set default entropy requirement if not specified
            if min_entropy_bits is None:
                min_entropy_bits = PasswordStrength.MIN_ENTROPY_BITS
            
            # Create password strength validator
            strength_validator = PasswordStrength(
                min_length=min_length,
                min_entropy_bits=min_entropy_bits,
                require_uppercase=True,
                require_lowercase=True,
                require_numbers=True,
                require_special=False
            )
            
            # Validate password strength
            strength_result = strength_validator.validate_password(password_str)
            
            if not strength_result['is_valid']:
                # Combine all errors into a single message
                error_msg = "; ".join(strength_result['errors'])
                return ValidationResult(
                    is_valid=False,
                    error_message=error_msg,
                    violation_type="insufficient_password_strength",
                    security_risk_level="high"
                )
        else:
            # Legacy complexity validation for backward compatibility
            complexity_score = self._calculate_password_complexity(password_str)
            if complexity_score < 3:  # Require at least 3 complexity factors
                return ValidationResult(
                    is_valid=False,
                    error_message="Password does not meet complexity requirements",
                    violation_type="insufficient_complexity",
                    security_risk_level="high"
                )
        
        # Check for common weak passwords in strict mode
        if self.validator.config.level in (ValidationLevel.STRICT, ValidationLevel.PARANOID):
            if self._is_common_password(password_str):
                return ValidationResult(
                    is_valid=False,
                    error_message="Password is too common/weak",
                    violation_type="common_password",
                    security_risk_level="high"
                )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=password_str,
            security_risk_level="low"
        )
    
    def _is_weak_key(self, key: bytes) -> bool:
        """Check if encryption key is weak.
        
        Args:
            key: Key bytes to check
            
        Returns:
            True if key is considered weak
        """
        # Check for all zeros
        if key == b'\x00' * len(key):
            return True
        
        # Check for all ones
        if key == b'\xff' * len(key):
            return True
        
        # Check for repeating patterns
        if len(set(key)) < len(key) // 4:  # Too much repetition
            return True
        
        # Check entropy - very basic check
        entropy_score = len(set(key)) / len(key)
        if entropy_score < 0.5:  # Low entropy
            return True
        
        return False
    
    def _is_weak_nonce(self, nonce: bytes) -> bool:
        """Check if nonce is weak.
        
        Args:
            nonce: Nonce bytes to check
            
        Returns:
            True if nonce is considered weak
        """
        # Check for all zeros
        if nonce == b'\x00' * len(nonce):
            return True
        
        # Check for predictable patterns
        if len(set(nonce)) < max(2, len(nonce) // 4):
            return True
        
        return False
    
    def _is_weak_salt(self, salt: bytes) -> bool:
        """Check if salt is weak.
        
        Args:
            salt: Salt bytes to check
            
        Returns:
            True if salt is considered weak
        """
        # Check for all zeros
        if salt == b'\x00' * len(salt):
            return True
        
        # Check entropy
        entropy_score = len(set(salt)) / len(salt)
        if entropy_score < 0.6:  # Require higher entropy for salts
            return True
        
        return False
    
    def _calculate_password_complexity(self, password: str) -> int:
        """Calculate password complexity score.
        
        Args:
            password: Password to analyze
            
        Returns:
            Complexity score (0-6)
        """
        score = 0
        
        # Length bonus
        if len(password) >= 12:
            score += 1
        
        # Character class checks
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
            score += 1
        
        # Additional complexity
        if len(set(password)) >= len(password) // 2:  # Good character diversity
            score += 1
        
        return score
    
    def _is_common_password(self, password: str) -> bool:
        """Check if password is a common weak password.
        
        Args:
            password: Password to check
            
        Returns:
            True if password is common/weak
        """
        # Simple check for very common passwords
        common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'root', 'user', 'guest', 
            'letmein', 'welcome', 'monkey', 'dragon', 'master',
            '111111', '000000', '123123', '1234567890'
        }
        
        return password.lower() in common_passwords


class FileValidator:
    """Specialized validator for file operations."""
    
    # Dangerous file extensions that should never be processed
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.jar',
        '.msi', '.ps1', '.reg', '.pif', '.application', '.gadget',
        '.msp', '.hta', '.cpl', '.msc', '.wsf', '.wsh', '.scf'
    }
    
    # Maximum safe file sizes per type (in bytes)
    MAX_FILE_SIZES = {
        'text': 10 * 1024 * 1024,    # 10MB
        'image': 50 * 1024 * 1024,   # 50MB
        'document': 100 * 1024 * 1024, # 100MB
        'archive': 1024 * 1024 * 1024, # 1GB
        'default': 100 * 1024 * 1024   # 100MB
    }
    
    def __init__(self, validator: InputValidator):
        """Initialize with base validator.
        
        Args:
            validator: Base input validator instance
        """
        self.validator = validator
        self._logger = logging.getLogger(f"FileValidator_{id(self)}")
    
    def validate_file_path(self, path: Any, 
                          allow_absolute: bool = False,
                          allow_parent_traversal: bool = False,
                          base_path: Optional[Union[str, Path]] = None,
                          field_name: Optional[str] = None) -> ValidationResult:
        """Validate file path for security.
        
        Args:
            path: File path to validate
            allow_absolute: Whether absolute paths are allowed
            allow_parent_traversal: Whether parent directory traversal is allowed
            base_path: Base path that relative paths should be relative to
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        # First validate as string
        string_result = self.validator.validate_string(
            path, field_name=field_name, max_length=4096  # Reasonable path limit
        )
        if not string_result.is_valid:
            return string_result
        
        path_str = string_result.sanitized_value
        
        try:
            # Convert to Path object for safer manipulation
            path_obj = Path(path_str)
            
            # Check for dangerous path patterns
            if self._has_dangerous_path_patterns(path_str):
                return ValidationResult(
                    is_valid=False,
                    error_message="Dangerous path patterns detected",
                    violation_type="dangerous_path_pattern",
                    security_risk_level="critical"
                )
            
            # Absolute path validation
            if path_obj.is_absolute() and not allow_absolute:
                return ValidationResult(
                    is_valid=False,
                    error_message="Absolute paths not allowed",
                    violation_type="absolute_path_not_allowed",
                    security_risk_level="high"
                )
            
            # Parent traversal validation
            if not allow_parent_traversal:
                path_parts = path_obj.parts
                if '..' in path_parts:
                    return ValidationResult(
                        is_valid=False,
                        error_message="Parent directory traversal not allowed",
                        violation_type="parent_traversal",
                        security_risk_level="critical"
                    )
            
            # Base path validation
            if base_path and not path_obj.is_absolute():
                try:
                    resolved_path = (Path(base_path) / path_obj).resolve()
                    base_resolved = Path(base_path).resolve()
                    
                    # Check if resolved path is within base path
                    if not str(resolved_path).startswith(str(base_resolved)):
                        return ValidationResult(
                            is_valid=False,
                            error_message="Path escapes base directory",
                            violation_type="path_escape",
                            security_risk_level="critical"
                        )
                except Exception:
                    return ValidationResult(
                        is_valid=False,
                        error_message="Path resolution failed",
                        violation_type="path_resolution_error",
                        security_risk_level="high"
                    )
            
            # Extension validation
            if path_obj.suffix.lower() in self.DANGEROUS_EXTENSIONS:
                return ValidationResult(
                    is_valid=False,
                    error_message="Dangerous file extension not allowed",
                    violation_type="dangerous_extension",
                    security_risk_level="critical"
                )
            
            # Normalize path for consistent handling
            try:
                normalized_path = str(path_obj.as_posix())  # Use forward slashes
            except Exception:
                normalized_path = path_str
            
            return ValidationResult(
                is_valid=True,
                sanitized_value=normalized_path,
                security_risk_level="low"
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Path validation failed: {str(e)}",
                violation_type="path_validation_error",
                security_risk_level="high"
            )
    
    def validate_filename(self, filename: Any,
                         max_length: int = 255,
                         allow_unicode: bool = True,
                         field_name: Optional[str] = None) -> ValidationResult:
        """Validate filename for security and filesystem compatibility.
        
        Args:
            filename: Filename to validate
            max_length: Maximum filename length
            allow_unicode: Whether Unicode characters are allowed
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        # First validate as string
        string_result = self.validator.validate_string(
            filename, field_name=field_name, max_length=max_length
        )
        if not string_result.is_valid:
            return string_result
        
        filename_str = string_result.sanitized_value
        
        # Check for path separators (shouldn't be in filename)
        if '/' in filename_str or '\\' in filename_str:
            return ValidationResult(
                is_valid=False,
                error_message="Path separators not allowed in filename",
                violation_type="path_separator_in_filename",
                security_risk_level="high"
            )
        
        # Check for dangerous filename patterns
        dangerous_patterns = [
            r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)',  # Windows reserved names
            r'^\.+$',  # Only dots
            r'^\s*$',  # Only whitespace
        ]
        
        for pattern in dangerous_patterns:
            if re.match(pattern, filename_str, re.IGNORECASE):
                return ValidationResult(
                    is_valid=False,
                    error_message="Dangerous filename pattern detected",
                    violation_type="dangerous_filename_pattern",
                    security_risk_level="high"
                )
        
        # Check for dangerous characters
        dangerous_chars = '<>:"|?*\x00'
        if any(char in filename_str for char in dangerous_chars):
            return ValidationResult(
                is_valid=False,
                error_message="Dangerous characters in filename",
                violation_type="dangerous_filename_chars",
                security_risk_level="high"
            )
        
        # Extension validation
        try:
            path_obj = Path(filename_str)
            if path_obj.suffix.lower() in self.DANGEROUS_EXTENSIONS:
                return ValidationResult(
                    is_valid=False,
                    error_message="Dangerous file extension not allowed",
                    violation_type="dangerous_extension",
                    security_risk_level="critical"
                )
        except Exception:
            pass  # Continue with other validations
        
        # Unicode validation
        if not allow_unicode:
            try:
                filename_str.encode('ascii')
            except UnicodeEncodeError:
                return ValidationResult(
                    is_valid=False,
                    error_message="Unicode characters not allowed in filename",
                    violation_type="unicode_not_allowed",
                    security_risk_level="medium"
                )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=filename_str,
            security_risk_level="low"
        )
    
    def validate_file_size(self, size: Any,
                          file_type: str = 'default',
                          max_size: Optional[int] = None,
                          field_name: Optional[str] = None) -> ValidationResult:
        """Validate file size against limits.
        
        Args:
            size: File size to validate
            file_type: Type of file (text, image, document, archive)
            max_size: Custom maximum size override
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        # First validate as integer
        int_result = self.validator.validate_integer(
            size, field_name=field_name, min_value=0
        )
        if not int_result.is_valid:
            return int_result
        
        size_int = int_result.sanitized_value
        
        # Determine maximum allowed size
        if max_size is not None:
            max_allowed = max_size
        else:
            max_allowed = self.MAX_FILE_SIZES.get(file_type.lower(), 
                                                 self.MAX_FILE_SIZES['default'])
        
        if size_int > max_allowed:
            return ValidationResult(
                is_valid=False,
                error_message=f"File size ({size_int}) exceeds maximum allowed ({max_allowed})",
                violation_type="file_size_exceeded",
                security_risk_level="medium"
            )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=size_int,
            security_risk_level="low"
        )
    
    def _has_dangerous_path_patterns(self, path: str) -> bool:
        """Check for dangerous patterns in file paths.
        
        Args:
            path: Path string to check
            
        Returns:
            True if dangerous patterns found
        """
        dangerous_patterns = [
            r'\.\.[\\/]',           # Directory traversal
            r'[\\/]\.\.[\\/]',      # Directory traversal  
            r'[\\/]\.\.$',          # Directory traversal at end
            r'^\.\.[\\/]',          # Directory traversal at start
            r'[\\/](etc|proc|sys|root|boot)[\\/]',  # Unix system directories
            r'^[Cc]:\\\\[Ww]indows\\\\',   # Windows system directory (more specific)
            r'^[Cc]:\\\\[Ss]ystem32\\\\', # Windows system32 (more specific)
            r'^[Cc]:\\\\[Pp]rogram\s[Ff]iles\\\\', # Program Files (more specific)
            r'\\\\[^\\]+\\\\[^\\]+', # UNC paths
            r'^\\\\\?\\\\',         # Extended-length path
            r'[<>:"|?*\x00-\x1f]',  # Control characters and dangerous chars (but allow : in drive letters)
        ]
        
        # Special case: Allow C:\ at the beginning for legitimate Windows paths
        # but block access to specific dangerous system directories
        if re.match(r'^[A-Za-z]:\\', path):  # Valid drive letter path
            # Check for specific dangerous Windows directories only
            specific_dangerous_patterns = [
                r'^[Cc]:\\\\[Ww]indows\\\\',
                r'^[Cc]:\\\\[Ss]ystem32\\\\',
                r'^[Cc]:\\\\[Pp]rogram\s[Ff]iles\\\\',
                r'^[Cc]:\\\\[Pp]rogram\s[Ff]iles\s\(x86\)\\\\',
            ]
            for pattern in specific_dangerous_patterns:
                if re.search(pattern, path):
                    return True
            # Skip the general dangerous pattern check for valid drive paths
            # and only check non-Windows-specific patterns
            non_windows_patterns = [
                r'\.\.[\\/]',           # Directory traversal
                r'[\\/]\.\.[\\/]',      # Directory traversal  
                r'[\\/]\.\.$',          # Directory traversal at end
                r'^\.\.[\\/]',          # Directory traversal at start
                r'[\\/](etc|proc|sys|root|boot)[\\/]',  # Unix system directories
                r'\\\\[^\\]+\\\\[^\\]+', # UNC paths
                r'^\\\\\?\\\\',         # Extended-length path
            ]
            for pattern in non_windows_patterns:
                if re.search(pattern, path):
                    return True
            # Check for dangerous characters but allow colon after drive letter
            path_after_drive = path[3:] if len(path) > 3 else ""
            if re.search(r'[<>"|?*\x00-\x1f]', path_after_drive):
                return True
            return False
        else:
            # For non-Windows drive paths, use all patterns
            for pattern in dangerous_patterns:
                if re.search(pattern, path):
                    return True
        
        return False


# Global validator instances for convenient access
_global_validator = None
_global_crypto_validator = None
_global_file_validator = None


def get_global_validator(config: Optional[ValidationConfig] = None) -> InputValidator:
    """Get the global input validator instance.
    
    Args:
        config: Optional configuration to apply
        
    Returns:
        Global InputValidator instance
    """
    global _global_validator
    if _global_validator is None:
        _global_validator = InputValidator(config)
    elif config is not None:
        _global_validator.config = config
    return _global_validator


def get_crypto_validator() -> CryptographicValidator:
    """Get the global cryptographic validator instance.
    
    Returns:
        Global CryptographicValidator instance
    """
    global _global_crypto_validator
    if _global_crypto_validator is None:
        _global_crypto_validator = CryptographicValidator(get_global_validator())
    return _global_crypto_validator


def get_file_validator() -> FileValidator:
    """Get the global file validator instance.
    
    Returns:
        Global FileValidator instance
    """
    global _global_file_validator
    if _global_file_validator is None:
        _global_file_validator = FileValidator(get_global_validator())
    return _global_file_validator


# Convenience functions for common validations
def validate_string(value: Any, **kwargs) -> ValidationResult:
    """Convenience function for string validation."""
    return get_global_validator().validate_string(value, **kwargs)


def validate_bytes(value: Any, **kwargs) -> ValidationResult:
    """Convenience function for bytes validation."""
    return get_global_validator().validate_bytes(value, **kwargs)


def validate_integer(value: Any, **kwargs) -> ValidationResult:
    """Convenience function for integer validation."""
    return get_global_validator().validate_integer(value, **kwargs)


def validate_encryption_key(key: Any, **kwargs) -> ValidationResult:
    """Convenience function for encryption key validation."""
    return get_crypto_validator().validate_encryption_key(key, **kwargs)


def validate_password(password: Any, **kwargs) -> ValidationResult:
    """Convenience function for password validation."""
    return get_crypto_validator().validate_password(password, **kwargs)


def validate_file_path(path: Any, **kwargs) -> ValidationResult:
    """Convenience function for file path validation."""
    return get_file_validator().validate_file_path(path, **kwargs)


def validate_filename(filename: Any, **kwargs) -> ValidationResult:
    """Convenience function for filename validation."""
    return get_file_validator().validate_filename(filename, **kwargs)


# Security decorator for automatic input validation
def validate_inputs(**validation_rules):
    """Decorator for automatic input validation.
    
    Args:
        **validation_rules: Validation rules for function arguments
        
    Example:
        @validate_inputs(
            username={"type": "string", "max_length": 50},
            password={"type": "password", "min_length": 8},
            file_path={"type": "file_path", "allow_absolute": False}
        )
        def process_user_input(username, password, file_path):
            # Function implementation
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Get function signature for argument mapping
            import inspect
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            # Validate each specified argument
            for arg_name, rules in validation_rules.items():
                if arg_name in bound_args.arguments:
                    value = bound_args.arguments[arg_name]
                    
                    # Determine validation type
                    validation_type = rules.get("type", "string")
                    
                    # Perform validation
                    if validation_type == "string":
                        result = validate_string(value, field_name=arg_name, **rules)
                    elif validation_type == "bytes":
                        result = validate_bytes(value, field_name=arg_name, **rules)
                    elif validation_type == "integer":
                        result = validate_integer(value, field_name=arg_name, **rules)
                    elif validation_type == "password":
                        result = validate_password(value, field_name=arg_name, **rules)
                    elif validation_type == "encryption_key":
                        result = validate_encryption_key(value, field_name=arg_name, **rules)
                    elif validation_type == "file_path":
                        result = validate_file_path(value, field_name=arg_name, **rules)
                    elif validation_type == "filename":
                        result = validate_filename(value, field_name=arg_name, **rules)
                    else:
                        continue  # Unknown validation type
                    
                    if not result.is_valid:
                        raise ValidationError(
                            result.error_message,
                            field_name=arg_name,
                            violation_type=result.violation_type
                        )
                    
                    # Replace with sanitized value
                    bound_args.arguments[arg_name] = result.sanitized_value
            
            # Call function with validated arguments
            return func(**bound_args.arguments)
        
        return wrapper
    return decorator


if __name__ == "__main__":
    # Basic testing
    validator = InputValidator()
    
    # Test string validation
    print("Testing string validation:")
    result = validator.validate_string("Hello, World!", max_length=20)
    print(f"Valid string: {result.is_valid}")
    
    result = validator.validate_string("../../etc/passwd", field_name="path")
    print(f"Dangerous string: {result.is_valid}")
    
    # Test cryptographic validation
    crypto_validator = CryptographicValidator(validator)
    
    print("\nTesting cryptographic validation:")
    result = crypto_validator.validate_encryption_key(b"0123456789ABCDEF0123456789ABCDEF")
    print(f"Valid AES-256 key: {result.is_valid}")
    
    result = crypto_validator.validate_password("weak")
    print(f"Weak password: {result.is_valid}")
    
    # Test file validation
    file_validator = FileValidator(validator)
    
    print("\nTesting file validation:")
    result = file_validator.validate_file_path("documents/report.pdf")
    print(f"Safe file path: {result.is_valid}")
    
    result = file_validator.validate_file_path("../../etc/passwd")
    print(f"Dangerous file path: {result.is_valid}")
    
    print("\nInput validation system ready!")