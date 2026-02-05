# scanner/supply_chain/__init__.py
"""
Supply Chain Security Scanners

OWASP A03:2025 - Software Supply Chain Failures

Detects vulnerabilities related to:
- Vulnerable and outdated components
- Missing integrity verification
- Dependency confusion
- CI/CD security issues
"""

from .dependency_check import DependencyCheckScanner
from .integrity_check import IntegrityCheckScanner
from .outdated_components import OutdatedComponentsScanner

__all__ = [
    'DependencyCheckScanner',
    'IntegrityCheckScanner',
    'OutdatedComponentsScanner',
]