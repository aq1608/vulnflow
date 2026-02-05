# scanner/exceptional_conditions/__init__.py
"""
Exceptional Conditions Scanners

OWASP A10:2025 - Mishandling of Exceptional Conditions

Detects vulnerabilities related to:
- Improper error handling
- Systems that "fail open"
- Resource exhaustion issues
- Unhandled exceptions exposing sensitive data
"""

from .error_handling import ErrorHandlingScanner
from .fail_open import FailOpenScanner
from .resource_limits import ResourceLimitsScanner

__all__ = [
    'ErrorHandlingScanner',
    'FailOpenScanner',
    'ResourceLimitsScanner',
]