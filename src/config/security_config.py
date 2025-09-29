"""
Security configuration module for BAR application.

This module provides easy configuration of security settings for different environments.

Author: Rolan Lobo (RNR)
Project: BAR - Burn After Reading Security Suite
"""

import os
from typing import Dict, Any
from enum import Enum


class SecurityLevel(Enum):
    """Security level options."""
    DEVELOPMENT = "development"
    BASIC = "basic"
    STANDARD = "standard"
    HIGH = "high"
    MAXIMUM = "maximum"


class SecurityConfig:
    """Configuration manager for security settings."""
    
    def __init__(self):
        """Initialize security configuration."""
        self.configs = {
            SecurityLevel.DEVELOPMENT: {
                "max_suspicious_score": 50,
                "max_focus_loss_count": 50,
                "process_monitoring_enabled": True,  # Enable to catch screenshot apps
                "clipboard_protection_enabled": True,
                "watermark_enabled": True,
                "focus_monitoring_enabled": True,
                "overlay_protection_enabled": True,  # Enable overlay protection
                "screenshot_blocking_enabled": True,
                "hardware_protection_enabled": True,  # Enable hardware protection
                "enhanced_protection_enabled": True,  # Enable enhanced protection
                "aggressive_mode": False,
                "check_interval": 2.0,  # Faster monitoring
                "safe_mode": True,  # Keep safe mode but with more features
                "description": "Enhanced protection with content visibility preserved"
            },
            SecurityLevel.BASIC: {
                "max_suspicious_score": 30,
                "max_focus_loss_count": 20,
                "process_monitoring_enabled": True,
                "clipboard_protection_enabled": True,
                "watermark_enabled": True,
                "focus_monitoring_enabled": True,
                "overlay_protection_enabled": False,
                "screenshot_blocking_enabled": True,
                "hardware_protection_enabled": False,
                "enhanced_protection_enabled": False,
                "aggressive_mode": False,
                "check_interval": 5.0,
                "description": "Basic protection suitable for most users"
            },
            SecurityLevel.STANDARD: {
                "max_suspicious_score": 20,
                "max_focus_loss_count": 10,
                "process_monitoring_enabled": True,
                "clipboard_protection_enabled": True,
                "watermark_enabled": True,
                "focus_monitoring_enabled": True,
                "overlay_protection_enabled": True,
                "screenshot_blocking_enabled": True,
                "hardware_protection_enabled": True,
                "enhanced_protection_enabled": True,
                "aggressive_mode": False,
                "check_interval": 3.0,
                "description": "Standard protection with all features enabled"
            },
            SecurityLevel.HIGH: {
                "max_suspicious_score": 15,
                "max_focus_loss_count": 5,
                "process_monitoring_enabled": True,
                "clipboard_protection_enabled": True,
                "watermark_enabled": True,
                "focus_monitoring_enabled": True,
                "overlay_protection_enabled": True,
                "screenshot_blocking_enabled": True,
                "hardware_protection_enabled": True,
                "enhanced_protection_enabled": True,
                "aggressive_mode": True,
                "check_interval": 2.0,
                "description": "High security for sensitive environments"
            },
            SecurityLevel.MAXIMUM: {
                "max_suspicious_score": 10,
                "max_focus_loss_count": 3,
                "process_monitoring_enabled": True,
                "clipboard_protection_enabled": True,
                "watermark_enabled": True,
                "focus_monitoring_enabled": True,
                "overlay_protection_enabled": True,
                "screenshot_blocking_enabled": True,
                "hardware_protection_enabled": True,
                "enhanced_protection_enabled": True,
                "aggressive_mode": True,
                "check_interval": 1.0,
                "description": "Maximum security for highly sensitive content"
            }
        }
    
    def get_config(self, level: SecurityLevel = None) -> Dict[str, Any]:
        """Get security configuration for specified level.
        
        Args:
            level: Security level to get config for. If None, auto-detects based on environment.
            
        Returns:
            Dictionary with security configuration
        """
        if level is None:
            level = self.detect_security_level()
        
        return self.configs.get(level, self.configs[SecurityLevel.STANDARD]).copy()
    
    def detect_security_level(self) -> SecurityLevel:
        """Auto-detect appropriate security level based on environment.
        
        Returns:
            Recommended security level
        """
        # Check for development environment indicators
        dev_indicators = [
            'Desktop' in os.getcwd(),
            'dev' in os.getcwd().lower(),
            'development' in os.getcwd().lower(),
            'src' in os.getcwd().lower(),
            'project' in os.getcwd().lower(),
            os.environ.get('DEVELOPMENT') is not None,
            os.environ.get('DEBUG') is not None,
            'PYCHARM' in os.environ,
            'VSCODE' in os.environ,
        ]
        
        if any(dev_indicators):
            return SecurityLevel.DEVELOPMENT
        
        # Check for production environment indicators
        prod_indicators = [
            'production' in os.getcwd().lower(),
            'prod' in os.getcwd().lower(),
            os.environ.get('PRODUCTION') is not None,
            'C:\\Program Files' in os.getcwd(),
            '/usr/local' in os.getcwd(),
            '/opt' in os.getcwd(),
        ]
        
        if any(prod_indicators):
            return SecurityLevel.HIGH
        
        # Default to standard for unknown environments
        return SecurityLevel.STANDARD
    
    def get_available_levels(self) -> Dict[SecurityLevel, str]:
        """Get all available security levels with descriptions.
        
        Returns:
            Dictionary mapping security levels to descriptions
        """
        return {level: config["description"] for level, config in self.configs.items()}
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate a security configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        required_keys = [
            "max_suspicious_score",
            "max_focus_loss_count",
            "process_monitoring_enabled",
            "clipboard_protection_enabled",
            "watermark_enabled",
            "focus_monitoring_enabled",
            "screenshot_blocking_enabled"
        ]
        
        return all(key in config for key in required_keys)
    
    def create_custom_config(self, base_level: SecurityLevel, overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Create custom configuration based on a security level with overrides.
        
        Args:
            base_level: Base security level to start from
            overrides: Configuration values to override
            
        Returns:
            Custom configuration dictionary
        """
        config = self.get_config(base_level)
        config.update(overrides)
        
        if not self.validate_config(config):
            raise ValueError("Invalid configuration after applying overrides")
        
        return config


# Global security configuration instance
security_config = SecurityConfig()


def get_security_config(level: SecurityLevel = None) -> Dict[str, Any]:
    """Convenience function to get security configuration.
    
    Args:
        level: Security level (auto-detected if None)
        
    Returns:
        Security configuration dictionary
    """
    return security_config.get_config(level)


def get_development_config() -> Dict[str, Any]:
    """Get development-friendly security configuration.
    
    Returns:
        Development security configuration
    """
    return security_config.get_config(SecurityLevel.DEVELOPMENT)


def get_production_config() -> Dict[str, Any]:
    """Get production security configuration.
    
    Returns:
        Production security configuration
    """
    return security_config.get_config(SecurityLevel.HIGH)
