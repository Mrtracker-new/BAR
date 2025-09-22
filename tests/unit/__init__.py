"""
Tests module for BAR project

This module contains comprehensive tests for all components of the BAR project,
including validation, security, cryptography, file operations, and more.

Author: Rolan Lobo (RNR)
Version: 2.0.0
Last Updated: January 2025
"""

# Test suite version
__version__ = "2.0.0"

# Import main test functions
try:
    from .test_validation_comprehensive import run_validation_tests
    from . import test_simple_validation
    __all__ = ['run_validation_tests', 'test_simple_validation']
except ImportError:
    __all__ = []
