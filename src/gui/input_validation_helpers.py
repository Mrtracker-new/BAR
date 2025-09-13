"""
GUI Input Validation Helpers for BAR Project

This module provides comprehensive input validation helpers specifically designed for
GUI components, implementing security-first validation according to BAR project 
rules R030 - Input Validation.

Features:
- Real-time validation feedback for UI components
- Visual indication of validation status
- Secure input sanitization
- Attack pattern detection in GUI inputs
- User-friendly error messages
- Integration with the comprehensive validation system

Per BAR Rules R030:
- NEVER trust any external input without validation
- NEVER use string concatenation for SQL-like operations
- NEVER allow arbitrary code execution through user input
- NEVER bypass security checks for "convenience"

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

import re
import logging
from typing import Any, Optional, Callable, Dict, Tuple
from PyQt5.QtWidgets import (
    QLineEdit, QTextEdit, QSpinBox, QDoubleSpinBox, 
    QComboBox, QLabel, QWidget, QToolTip
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QPalette, QColor

# Import comprehensive input validation system
from ..security.input_validator import (
    get_global_validator, get_crypto_validator, get_file_validator,
    ValidationResult, ValidationLevel, ValidationConfig, ValidationError,
    validate_string, validate_integer
)


class ValidationStyle:
    """Styling constants for validation feedback."""
    
    VALID_STYLE = """
        border: 2px solid #2ecc71;
        background-color: #d5f4e6;
        color: #1e8449;
    """
    
    INVALID_STYLE = """
        border: 2px solid #e74c3c;
        background-color: #fdf2f2;
        color: #c0392b;
    """
    
    WARNING_STYLE = """
        border: 2px solid #f39c12;
        background-color: #fef9e7;
        color: #d68910;
    """
    
    NEUTRAL_STYLE = """
        border: 1px solid #bdc3c7;
        background-color: #ffffff;
        color: #2c3e50;
    """


class ValidationState:
    """Validation state constants."""
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    NEUTRAL = "neutral"


class GUIValidator:
    """Comprehensive GUI input validator with real-time feedback."""
    
    def __init__(self, validation_level: ValidationLevel = ValidationLevel.STRICT):
        """Initialize GUI validator.
        
        Args:
            validation_level: Validation security level
        """
        self.config = ValidationConfig(
            level=validation_level,
            log_violations=True,
            timing_attack_protection=True
        )
        self.general_validator = get_global_validator(self.config)
        self.crypto_validator = get_crypto_validator()
        self.file_validator = get_file_validator()
        self.logger = logging.getLogger(f"GUIValidator_{id(self)}")
    
    def validate_text_input(self, text: Any, field_type: str = "general", 
                           field_name: str = "input") -> ValidationResult:
        """Validate text input from GUI components.
        
        Args:
            text: Text to validate
            field_type: Type of field (general, password, filename, etc.)
            field_name: Name of the field for logging
            
        Returns:
            ValidationResult with validation outcome
        """
        try:
            if field_type == "password":
                return self.crypto_validator.validate_password(
                    text, field_name=field_name, require_complexity=True
                )
            elif field_type == "filename":
                return self.file_validator.validate_filename(
                    text, field_name=field_name
                )
            elif field_type == "filepath":
                return self.file_validator.validate_file_path(
                    text, field_name=field_name, allow_absolute=True
                )
            elif field_type == "device_name":
                return validate_string(
                    text,
                    field_name=field_name,
                    max_length=50,
                    min_length=0,  # Allow empty for auto-generation
                    allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. ",
                    require_ascii=True
                )
            else:  # General text
                return self.general_validator.validate_string(
                    text, field_name=field_name, max_length=1000
                )
        except Exception as e:
            self.logger.error(f"Validation error for {field_name}: {e}")
            return ValidationResult(
                is_valid=False,
                error_message=f"Validation failed: {type(e).__name__}",
                violation_type="validation_error",
                security_risk_level="high"
            )
    
    def validate_integer_input(self, value: Any, field_name: str = "input",
                              min_value: Optional[int] = None,
                              max_value: Optional[int] = None) -> ValidationResult:
        """Validate integer input from GUI components.
        
        Args:
            value: Value to validate
            field_name: Name of the field for logging
            min_value: Minimum allowed value
            max_value: Maximum allowed value
            
        Returns:
            ValidationResult with validation outcome
        """
        try:
            return validate_integer(
                value,
                field_name=field_name,
                min_value=min_value,
                max_value=max_value,
                allow_zero=True,
                allow_negative=min_value is None or min_value < 0
            )
        except Exception as e:
            self.logger.error(f"Integer validation error for {field_name}: {e}")
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid number: {type(e).__name__}",
                violation_type="validation_error",
                security_risk_level="medium"
            )


class ValidatedLineEdit(QLineEdit):
    """Enhanced QLineEdit with real-time input validation.
    
    Features:
    - Real-time validation as user types
    - Visual feedback with color coding
    - Tooltip error messages
    - Attack pattern detection
    - Secure input sanitization
    """
    
    validationChanged = pyqtSignal(bool, str)  # is_valid, message
    
    def __init__(self, field_type: str = "general", field_name: str = "input",
                 validation_level: ValidationLevel = ValidationLevel.STRICT,
                 parent=None):
        """Initialize validated line edit.
        
        Args:
            field_type: Type of field for validation
            field_name: Field name for logging
            validation_level: Validation security level
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.field_type = field_type
        self.field_name = field_name
        self.validator = GUIValidator(validation_level)
        self.validation_state = ValidationState.NEUTRAL
        self.last_validation_result = None
        
        # Setup validation timer to avoid excessive validation
        self.validation_timer = QTimer()
        self.validation_timer.setSingleShot(True)
        self.validation_timer.timeout.connect(self._perform_validation)
        
        # Connect signals
        self.textChanged.connect(self._on_text_changed)
        
        # Apply initial styling
        self._apply_validation_style(ValidationState.NEUTRAL)
    
    def _on_text_changed(self, text: str):
        """Handle text change events."""
        # Restart the validation timer (debounce validation)
        self.validation_timer.stop()
        self.validation_timer.start(300)  # 300ms delay
    
    def _perform_validation(self):
        """Perform input validation."""
        try:
            text = self.text()
            
            # Skip validation for empty text unless required
            if not text and self.field_type != "password":
                self._apply_validation_style(ValidationState.NEUTRAL)
                self.validationChanged.emit(True, "")
                return
            
            # Perform validation
            result = self.validator.validate_text_input(
                text, self.field_type, self.field_name
            )
            
            self.last_validation_result = result
            
            # Apply appropriate styling and feedback
            if result.is_valid:
                self._apply_validation_style(ValidationState.VALID)
                self.setToolTip("")
                self.validationChanged.emit(True, "Input is valid")
            else:
                # Determine severity based on security risk level
                if result.security_risk_level in ("high", "critical"):
                    self._apply_validation_style(ValidationState.INVALID)
                else:
                    self._apply_validation_style(ValidationState.WARNING)
                
                # Show error message in tooltip (without exposing sensitive data)
                safe_message = self._sanitize_error_message(result.error_message)
                self.setToolTip(safe_message)
                self.validationChanged.emit(False, safe_message)
                
                # Log security violations
                if result.security_risk_level in ("high", "critical"):
                    self.validator.logger.warning(
                        f"Security violation in GUI input - field: {self.field_name}, "
                        f"violation: {result.violation_type}, "
                        f"risk: {result.security_risk_level}"
                    )
                    
        except Exception as e:
            self.validator.logger.error(f"Validation error in GUI component: {e}")
            self._apply_validation_style(ValidationState.INVALID)
            self.setToolTip("Validation error occurred")
            self.validationChanged.emit(False, "Validation error")
    
    def _sanitize_error_message(self, message: str) -> str:
        """Sanitize error message for safe display.
        
        Args:
            message: Raw error message
            
        Returns:
            Sanitized error message safe for display
        """
        if not message:
            return "Invalid input"
        
        # Remove potentially sensitive information
        safe_message = re.sub(r'[<>"\']', '', message)
        
        # Limit length
        if len(safe_message) > 100:
            safe_message = safe_message[:97] + "..."
        
        return safe_message
    
    def _apply_validation_style(self, state: str):
        """Apply validation styling based on state.
        
        Args:
            state: Validation state (valid, invalid, warning, neutral)
        """
        self.validation_state = state
        
        style_map = {
            ValidationState.VALID: ValidationStyle.VALID_STYLE,
            ValidationState.INVALID: ValidationStyle.INVALID_STYLE,
            ValidationState.WARNING: ValidationStyle.WARNING_STYLE,
            ValidationState.NEUTRAL: ValidationStyle.NEUTRAL_STYLE
        }
        
        self.setStyleSheet(style_map.get(state, ValidationStyle.NEUTRAL_STYLE))
    
    def is_valid(self) -> bool:
        """Check if current input is valid.
        
        Returns:
            True if input is valid, False otherwise
        """
        if self.last_validation_result is None:
            # Trigger validation if not done yet
            self._perform_validation()
        
        return (self.last_validation_result is not None and 
                self.last_validation_result.is_valid)
    
    def get_validation_result(self) -> Optional[ValidationResult]:
        """Get the last validation result.
        
        Returns:
            Last validation result or None if not validated
        """
        return self.last_validation_result
    
    def get_sanitized_value(self) -> Optional[str]:
        """Get sanitized input value.
        
        Returns:
            Sanitized value if valid, None if invalid
        """
        if not self.is_valid():
            return None
        
        return (self.last_validation_result.sanitized_value 
                if self.last_validation_result else None)


class ValidatedTextEdit(QTextEdit):
    """Enhanced QTextEdit with input validation for multi-line text."""
    
    validationChanged = pyqtSignal(bool, str)  # is_valid, message
    
    def __init__(self, field_type: str = "general", field_name: str = "input",
                 validation_level: ValidationLevel = ValidationLevel.ENHANCED,
                 parent=None):
        """Initialize validated text edit.
        
        Args:
            field_type: Type of field for validation
            field_name: Field name for logging
            validation_level: Validation security level
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.field_type = field_type
        self.field_name = field_name
        self.validator = GUIValidator(validation_level)
        self.validation_state = ValidationState.NEUTRAL
        self.last_validation_result = None
        
        # Setup validation timer
        self.validation_timer = QTimer()
        self.validation_timer.setSingleShot(True)
        self.validation_timer.timeout.connect(self._perform_validation)
        
        # Connect signals
        self.textChanged.connect(self._on_text_changed)
        
        # Apply initial styling
        self._apply_validation_style(ValidationState.NEUTRAL)
    
    def _on_text_changed(self):
        """Handle text change events."""
        self.validation_timer.stop()
        self.validation_timer.start(500)  # 500ms delay for text areas
    
    def _perform_validation(self):
        """Perform input validation."""
        try:
            text = self.toPlainText()
            
            # Allow empty text for text areas
            if not text:
                self._apply_validation_style(ValidationState.NEUTRAL)
                self.validationChanged.emit(True, "")
                return
            
            # Perform validation with larger text limits
            result = self.validator.validate_text_input(
                text, self.field_type, self.field_name
            )
            
            self.last_validation_result = result
            
            # Apply styling based on result
            if result.is_valid:
                self._apply_validation_style(ValidationState.VALID)
                self.setToolTip("")
                self.validationChanged.emit(True, "Input is valid")
            else:
                if result.security_risk_level in ("high", "critical"):
                    self._apply_validation_style(ValidationState.INVALID)
                else:
                    self._apply_validation_style(ValidationState.WARNING)
                
                safe_message = self._sanitize_error_message(result.error_message)
                self.setToolTip(safe_message)
                self.validationChanged.emit(False, safe_message)
                
        except Exception as e:
            self.validator.logger.error(f"Text edit validation error: {e}")
            self._apply_validation_style(ValidationState.INVALID)
            self.validationChanged.emit(False, "Validation error")
    
    def _sanitize_error_message(self, message: str) -> str:
        """Sanitize error message for safe display."""
        if not message:
            return "Invalid input"
        
        safe_message = re.sub(r'[<>"\']', '', message)
        if len(safe_message) > 150:
            safe_message = safe_message[:147] + "..."
        
        return safe_message
    
    def _apply_validation_style(self, state: str):
        """Apply validation styling."""
        self.validation_state = state
        
        # Apply border styling to text edit
        if state == ValidationState.VALID:
            border_color = "#2ecc71"
        elif state == ValidationState.INVALID:
            border_color = "#e74c3c"
        elif state == ValidationState.WARNING:
            border_color = "#f39c12"
        else:
            border_color = "#bdc3c7"
        
        self.setStyleSheet(f"""
            QTextEdit {{
                border: 2px solid {border_color};
                border-radius: 4px;
                padding: 4px;
            }}
        """)
    
    def is_valid(self) -> bool:
        """Check if current input is valid."""
        if self.last_validation_result is None:
            self._perform_validation()
        
        return (self.last_validation_result is not None and 
                self.last_validation_result.is_valid)
    
    def get_sanitized_value(self) -> Optional[str]:
        """Get sanitized input value."""
        if not self.is_valid():
            return None
        
        return (self.last_validation_result.sanitized_value 
                if self.last_validation_result else None)


class ValidatedSpinBox(QSpinBox):
    """Enhanced QSpinBox with input validation."""
    
    validationChanged = pyqtSignal(bool, str)  # is_valid, message
    
    def __init__(self, field_name: str = "number_input", 
                 validation_level: ValidationLevel = ValidationLevel.ENHANCED,
                 parent=None):
        """Initialize validated spin box.
        
        Args:
            field_name: Field name for logging
            validation_level: Validation security level
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.field_name = field_name
        self.validator = GUIValidator(validation_level)
        self.last_validation_result = None
        
        # Connect signals
        self.valueChanged.connect(self._on_value_changed)
        
        # Set reasonable default range
        self.setRange(-999999, 999999)
    
    def _on_value_changed(self, value: int):
        """Handle value change events."""
        try:
            result = self.validator.validate_integer_input(
                value, self.field_name, self.minimum(), self.maximum()
            )
            
            self.last_validation_result = result
            
            if result.is_valid:
                self.setStyleSheet("")  # Reset to default style
                self.validationChanged.emit(True, "Value is valid")
            else:
                self.setStyleSheet("border: 2px solid #e74c3c;")
                self.validationChanged.emit(False, result.error_message or "Invalid value")
                
        except Exception as e:
            self.validator.logger.error(f"SpinBox validation error: {e}")
            self.setStyleSheet("border: 2px solid #e74c3c;")
            self.validationChanged.emit(False, "Validation error")
    
    def is_valid(self) -> bool:
        """Check if current value is valid."""
        return (self.last_validation_result is not None and 
                self.last_validation_result.is_valid)


def create_validation_label(text: str, validation_state: str = ValidationState.NEUTRAL) -> QLabel:
    """Create a validation status label.
    
    Args:
        text: Label text
        validation_state: Validation state for styling
        
    Returns:
        Configured QLabel with validation styling
    """
    label = QLabel(text)
    
    color_map = {
        ValidationState.VALID: "#2ecc71",
        ValidationState.INVALID: "#e74c3c", 
        ValidationState.WARNING: "#f39c12",
        ValidationState.NEUTRAL: "#7f8c8d"
    }
    
    color = color_map.get(validation_state, "#7f8c8d")
    label.setStyleSheet(f"color: {color}; font-weight: bold;")
    
    return label


def setup_form_validation(form_fields: Dict[str, QWidget], 
                         submit_button: Optional[QWidget] = None) -> Callable[[], bool]:
    """Setup comprehensive form validation.
    
    Args:
        form_fields: Dictionary mapping field names to widgets
        submit_button: Optional submit button to enable/disable
        
    Returns:
        Function to check if entire form is valid
    """
    validation_states = {}
    
    def update_form_state(field_name: str, is_valid: bool, message: str):
        """Update form validation state."""
        validation_states[field_name] = is_valid
        
        # Update submit button state if provided
        if submit_button:
            all_valid = all(validation_states.values()) if validation_states else False
            submit_button.setEnabled(all_valid)
    
    def is_form_valid() -> bool:
        """Check if entire form is valid."""
        return all(validation_states.values()) if validation_states else False
    
    # Connect validation signals for supported widgets
    for field_name, widget in form_fields.items():
        validation_states[field_name] = False  # Start with invalid
        
        if isinstance(widget, (ValidatedLineEdit, ValidatedTextEdit, ValidatedSpinBox)):
            widget.validationChanged.connect(
                lambda valid, msg, fname=field_name: update_form_state(fname, valid, msg)
            )
    
    return is_form_valid


# Convenience functions for creating validated widgets
def create_validated_line_edit(field_type: str = "general", 
                              field_name: str = "input",
                              placeholder: str = "",
                              validation_level: ValidationLevel = ValidationLevel.STRICT) -> ValidatedLineEdit:
    """Create a validated line edit widget.
    
    Args:
        field_type: Type of field for validation
        field_name: Field name for logging
        placeholder: Placeholder text
        validation_level: Validation security level
        
    Returns:
        Configured ValidatedLineEdit widget
    """
    widget = ValidatedLineEdit(field_type, field_name, validation_level)
    if placeholder:
        widget.setPlaceholderText(placeholder)
    return widget


def create_password_field(field_name: str = "password",
                         placeholder: str = "Enter password",
                         show_strength: bool = True) -> Tuple[ValidatedLineEdit, Optional[QLabel]]:
    """Create a validated password field with optional strength indicator.
    
    Args:
        field_name: Field name for logging
        placeholder: Placeholder text
        show_strength: Whether to include strength indicator
        
    Returns:
        Tuple of (password field, strength label or None)
    """
    password_field = ValidatedLineEdit("password", field_name, ValidationLevel.STRICT)
    password_field.setPlaceholderText(placeholder)
    password_field.setEchoMode(QLineEdit.Password)
    
    strength_label = None
    if show_strength:
        strength_label = QLabel("Password strength will appear here")
        strength_label.setStyleSheet("color: #7f8c8d; font-size: 10pt;")
        
        def update_strength(is_valid: bool, message: str):
            if is_valid:
                strength_label.setText("✅ Strong password")
                strength_label.setStyleSheet("color: #2ecc71; font-size: 10pt;")
            elif message:
                strength_label.setText(f"❌ {message}")
                strength_label.setStyleSheet("color: #e74c3c; font-size: 10pt;")
            else:
                strength_label.setText("Password strength will appear here")
                strength_label.setStyleSheet("color: #7f8c8d; font-size: 10pt;")
        
        password_field.validationChanged.connect(update_strength)
    
    return password_field, strength_label


if __name__ == "__main__":
    # Basic testing
    from PyQt5.QtWidgets import QApplication, QVBoxLayout, QWidget
    import sys
    
    app = QApplication(sys.argv)
    
    # Test window
    window = QWidget()
    layout = QVBoxLayout()
    
    # Test validated line edit
    line_edit = create_validated_line_edit("general", "test_field", "Enter some text...")
    layout.addWidget(line_edit)
    
    # Test password field
    password_field, strength_label = create_password_field("test_password", "Enter password...")
    layout.addWidget(password_field)
    if strength_label:
        layout.addWidget(strength_label)
    
    window.setLayout(layout)
    window.show()
    
    print("GUI validation helpers ready for testing!")
    # app.exec_()  # Uncomment to run the test application