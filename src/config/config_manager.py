import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

# Import comprehensive input validation system
from src.security.input_validator import (
    get_file_validator, get_global_validator, ConfigValidationError,
    validate_string, validate_integer, ValidationLevel, ValidationConfig
)


class ConfigManager:
    """Manages application configuration for the BAR application."""
    
    # Default configuration
    DEFAULT_CONFIG = {
        "theme": "dark",  # dark, light, system
        "default_security": {
            "expiration_time": None,  # ISO format datetime string
            "max_access_count": None,  # Integer
            "deadman_switch": 30,  # Days
        },
        "file_storage_path": None,  # Will be set during initialization
        "auto_lock_timeout": 5,  # Minutes
        "check_updates": False,  # Disabled for offline app
        "logging_level": "INFO",
    }
    
    def __init__(self, base_directory: str):
        """Initialize the configuration manager.
        
        Args:
            base_directory: The base directory for storing configuration
            
        Raises:
            ConfigValidationError: If input validation fails
        """
        # Comprehensive input validation per BAR Rules R030
        self._validate_base_directory(base_directory)
        self.base_directory = Path(base_directory)
        self.config_file = self.base_directory / "config.json"
        
        # Create base directory if it doesn't exist
        self.base_directory.mkdir(parents=True, exist_ok=True)
        
        # Load or create configuration
        self.config = self._load_config()
        
        # Initialize validators
        self.file_validator = get_file_validator()
        self.general_validator = get_global_validator(ValidationConfig(level=ValidationLevel.STRICT))
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Set up logging for the configuration manager."""
        log_dir = self.base_directory / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / "config.log"
        
        logging.basicConfig(
            level=getattr(logging, self.config.get("logging_level", "INFO")),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("ConfigManager")
    
    def _validate_base_directory(self, base_directory: Any) -> None:
        """Validate base directory parameter.
        
        Args:
            base_directory: Directory path to validate
            
        Raises:
            ConfigValidationError: If validation fails
        """
        # First, create a temporary file validator for this validation
        temp_file_validator = get_file_validator()
        
        # Validate base directory path
        path_result = temp_file_validator.validate_file_path(
            base_directory,
            field_name="base_directory",
            allow_absolute=True,  # Allow absolute paths for configuration
            allow_parent_traversal=False
        )
        if not path_result.is_valid:
            raise ConfigValidationError(
                path_result.error_message,
                field_name="base_directory",
                violation_type=path_result.violation_type
            )
    
    def _validate_config_key(self, key: Any, field_name: str = "key") -> str:
        """Validate configuration key.
        
        Args:
            key: Configuration key to validate
            field_name: Name of the field for logging
            
        Returns:
            Validated key
            
        Raises:
            ConfigValidationError: If validation fails
        """
        key_result = validate_string(
            key,
            field_name=field_name,
            max_length=100,  # Reasonable key length limit
            min_length=1,
            allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
            require_ascii=True
        )
        if not key_result.is_valid:
            raise ConfigValidationError(
                key_result.error_message,
                field_name=field_name,
                violation_type=key_result.violation_type
            )
        return key_result.sanitized_value
    
    def _validate_config_value(self, key: str, value: Any) -> Any:
        """Validate configuration value based on key.
        
        Args:
            key: Configuration key
            value: Configuration value to validate
            
        Returns:
            Validated value
            
        Raises:
            ConfigValidationError: If validation fails
        """
        # Validate different types of configuration values
        if key == "theme":
            if not isinstance(value, str):
                raise ConfigValidationError(
                    "Theme must be a string",
                    field_name="theme",
                    violation_type="invalid_type"
                )
            
            allowed_themes = ["dark", "light", "system"]
            if value not in allowed_themes:
                raise ConfigValidationError(
                    f"Theme must be one of: {', '.join(allowed_themes)}",
                    field_name="theme",
                    violation_type="invalid_value"
                )
            return value
            
        elif key == "auto_lock_timeout":
            timeout_result = validate_integer(
                value,
                field_name="auto_lock_timeout",
                min_value=1,
                max_value=1440,  # Max 24 hours in minutes
                allow_zero=False,
                allow_negative=False
            )
            if not timeout_result.is_valid:
                raise ConfigValidationError(
                    timeout_result.error_message,
                    field_name="auto_lock_timeout",
                    violation_type=timeout_result.violation_type
                )
            return timeout_result.sanitized_value
            
        elif key == "logging_level":
            if not isinstance(value, str):
                raise ConfigValidationError(
                    "Logging level must be a string",
                    field_name="logging_level",
                    violation_type="invalid_type"
                )
            
            allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            if value.upper() not in allowed_levels:
                raise ConfigValidationError(
                    f"Logging level must be one of: {', '.join(allowed_levels)}",
                    field_name="logging_level",
                    violation_type="invalid_value"
                )
            return value.upper()
            
        elif key == "file_storage_path":
            if value is None:
                return None  # Allow None for auto-determination
            
            path_result = self.file_validator.validate_file_path(
                value,
                field_name="file_storage_path",
                allow_absolute=True,
                allow_parent_traversal=False
            )
            if not path_result.is_valid:
                raise ConfigValidationError(
                    path_result.error_message,
                    field_name="file_storage_path",
                    violation_type=path_result.violation_type
                )
            return path_result.sanitized_value
            
        elif key == "check_updates":
            if not isinstance(value, bool):
                raise ConfigValidationError(
                    "Check updates must be a boolean",
                    field_name="check_updates",
                    violation_type="invalid_type"
                )
            return value
            
        elif key == "default_security" and isinstance(value, dict):
            validated_security = {}
            for sec_key, sec_value in value.items():
                if sec_key == "max_access_count" and sec_value is not None:
                    count_result = validate_integer(
                        sec_value,
                        field_name=f"default_security.max_access_count",
                        min_value=1,
                        max_value=1000000,
                        allow_zero=False,
                        allow_negative=False
                    )
                    if not count_result.is_valid:
                        raise ConfigValidationError(
                            count_result.error_message,
                            field_name=f"default_security.max_access_count",
                            violation_type=count_result.violation_type
                        )
                    validated_security[sec_key] = count_result.sanitized_value
                    
                elif sec_key == "deadman_switch" and sec_value is not None:
                    days_result = validate_integer(
                        sec_value,
                        field_name=f"default_security.deadman_switch",
                        min_value=1,
                        max_value=365,  # Max 1 year
                        allow_zero=False,
                        allow_negative=False
                    )
                    if not days_result.is_valid:
                        raise ConfigValidationError(
                            days_result.error_message,
                            field_name=f"default_security.deadman_switch",
                            violation_type=days_result.violation_type
                        )
                    validated_security[sec_key] = days_result.sanitized_value
                    
                elif sec_key == "expiration_time":
                    # Validate expiration time as string or None
                    if sec_value is not None:
                        time_result = validate_string(
                            sec_value,
                            field_name=f"default_security.expiration_time",
                            max_length=50
                        )
                        if not time_result.is_valid:
                            raise ConfigValidationError(
                                time_result.error_message,
                                field_name=f"default_security.expiration_time",
                                violation_type=time_result.violation_type
                            )
                        validated_security[sec_key] = time_result.sanitized_value
                    else:
                        validated_security[sec_key] = None
                else:
                    # Unknown security setting - validate as string
                    if sec_value is not None:
                        str_result = validate_string(
                            str(sec_value),
                            field_name=f"default_security.{sec_key}",
                            max_length=1000
                        )
                        if not str_result.is_valid:
                            raise ConfigValidationError(
                                str_result.error_message,
                                field_name=f"default_security.{sec_key}",
                                violation_type=str_result.violation_type
                            )
                        validated_security[sec_key] = str_result.sanitized_value
                    else:
                        validated_security[sec_key] = None
                        
            return validated_security
        else:
            # Unknown configuration key - validate as string or preserve type for basic types
            if value is None or isinstance(value, (bool, int, float)):
                # Allow basic types as-is, but validate ranges for numbers
                if isinstance(value, int):
                    int_result = validate_integer(
                        value,
                        field_name=key,
                        min_value=-1000000,
                        max_value=1000000,
                        allow_negative=True
                    )
                    if not int_result.is_valid:
                        raise ConfigValidationError(
                            int_result.error_message,
                            field_name=key,
                            violation_type=int_result.violation_type
                        )
                    return int_result.sanitized_value
                return value
            else:
                # Validate as string
                str_result = validate_string(
                    str(value),
                    field_name=key,
                    max_length=10000  # Large limit for unknown config values
                )
                if not str_result.is_valid:
                    raise ConfigValidationError(
                        str_result.error_message,
                        field_name=key,
                        violation_type=str_result.violation_type
                    )
                return str_result.sanitized_value
    
    def _validate_config_dict(self, config: Any) -> Dict[str, Any]:
        """Validate entire configuration dictionary.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            Validated configuration dictionary
            
        Raises:
            ConfigValidationError: If validation fails
        """
        if not isinstance(config, dict):
            raise ConfigValidationError(
                "Configuration must be a dictionary",
                field_name="config",
                violation_type="invalid_type"
            )
        
        validated_config = {}
        for key, value in config.items():
            validated_key = self._validate_config_key(key)
            validated_value = self._validate_config_value(validated_key, value)
            validated_config[validated_key] = validated_value
        
        return validated_config
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default.
        
        Returns:
            Dictionary containing configuration
        """
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    config = json.load(f)
                
                # Update with any missing default values
                updated = False
                for key, value in self.DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                        updated = True
                
                # Set file storage path if not already set
                if not config["file_storage_path"]:
                    config["file_storage_path"] = str(self.base_directory / "data")
                    updated = True
                
                if updated:
                    self._save_config(config)
                
                return config
            except Exception as e:
                print(f"Error loading configuration: {str(e)}")
                return self._create_default_config()
        else:
            return self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create and save default configuration.
        
        Returns:
            Dictionary containing default configuration
        """
        config = self.DEFAULT_CONFIG.copy()
        config["file_storage_path"] = str(self.base_directory / "data")
        
        self._save_config(config)
        return config
    
    def _save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file.
        
        Args:
            config: The configuration to save
            
        Returns:
            True if configuration was saved successfully, False otherwise
        """
        try:
            with open(self.config_file, "w") as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving configuration: {str(e)}")
            return False
    
    def get_config(self) -> Dict[str, Any]:
        """Get the current configuration.
        
        Returns:
            Dictionary containing configuration
        """
        return self.config.copy()
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            key: The configuration key to get
            default: The default value to return if key doesn't exist
            
        Returns:
            The configuration value, or default if key doesn't exist
            
        Raises:
            ConfigValidationError: If input validation fails
        """
        # Validate the key
        validated_key = self._validate_config_key(key)
        return self.config.get(validated_key, default)
    
    def set_value(self, key: str, value: Any) -> bool:
        """Set a configuration value.
        
        Args:
            key: The configuration key to set
            value: The value to set
            
        Returns:
            True if value was set and saved successfully, False otherwise
            
        Raises:
            ConfigValidationError: If input validation fails
        """
        # Comprehensive input validation per BAR Rules R030
        validated_key = self._validate_config_key(key)
        validated_value = self._validate_config_value(validated_key, value)
        self.config[validated_key] = validated_value
        result = self._save_config(self.config)
        
        if result:
            self.logger.info(f"Configuration updated: {validated_key}")
        
        return result
    
    def update_config(self, config_updates: Dict[str, Any]) -> bool:
        """Update multiple configuration values.
        
        Args:
            config_updates: Dictionary containing configuration updates
            
        Returns:
            True if configuration was updated and saved successfully, False otherwise
            
        Raises:
            ConfigValidationError: If input validation fails
        """
        # Comprehensive input validation per BAR Rules R030
        validated_updates = self._validate_config_dict(config_updates)
        for key, value in validated_updates.items():
            if isinstance(value, dict) and isinstance(self.config.get(key), dict):
                # Merge nested dictionaries
                self.config[key].update(value)
            else:
                self.config[key] = value
        
        result = self._save_config(self.config)
        
        if result:
            self.logger.info(f"Configuration updated with multiple values")
        
        return result
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults.
        
        Returns:
            True if configuration was reset and saved successfully, False otherwise
        """
        self.config = self._create_default_config()
        self.logger.info("Configuration reset to defaults")
        return True
    
    def clear_all_cached_config(self) -> bool:
        """Clear all cached configuration data and reset to defaults.
        
        This method is used during device resets to ensure all configuration
        data is cleared from memory and storage.
        
        Returns:
            True if all configuration was cleared successfully, False otherwise
        """
        try:
            # Clear in-memory configuration
            self.config.clear()
            
            # Remove configuration file if it exists
            if self.config_file.exists():
                self.config_file.unlink()
            
            # Reset to defaults
            self.config = self._create_default_config()
            
            self.logger.info("All cached configuration cleared and reset to defaults")
            return True
        except Exception as e:
            self.logger.error(f"Error clearing cached configuration: {e}")
            return False
    
    def get_themes(self) -> Dict[str, Dict[str, Any]]:
        """Get available themes.
        
        Returns:
            Dictionary containing theme configurations
        """
        return {
            "dark": {
                "name": "Dark",
                "primary_color": "#2c3e50",
                "secondary_color": "#34495e",
                "accent_color": "#3498db",
                "text_color": "#ecf0f1",
                "background_color": "#1a1a1a",
                "danger_color": "#e74c3c",
                "success_color": "#2ecc71",
                "warning_color": "#f39c12",
            },
            "light": {
                "name": "Light",
                "primary_color": "#3498db",
                "secondary_color": "#2980b9",
                "accent_color": "#9b59b6",
                "text_color": "#2c3e50",
                "background_color": "#ecf0f1",
                "danger_color": "#e74c3c",
                "success_color": "#2ecc71",
                "warning_color": "#f39c12",
            },
            "system": {
                "name": "System",
                "description": "Follows system theme (dark/light)"
            }
        }
    
    def get_current_theme(self) -> Dict[str, Any]:
        """Get the current theme configuration.
        
        Returns:
            Dictionary containing theme configuration
        """
        theme_name = self.config.get("theme", "dark")
        themes = self.get_themes()
        
        if theme_name == "system":
            # For system theme, default to dark for now
            # In a real implementation, this would check the system theme
            theme_name = "dark"
        
        return themes.get(theme_name, themes["dark"])