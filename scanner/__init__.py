# websec/scanner/__init__.py
"""
VulnFlow Scanner Module

Comprehensive vulnerability scanning covering OWASP Top 10
"""

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory
from .vuln_scanner import VulnerabilityScanner

# Import individual scanners for direct access
from .injection.sqli import SQLInjectionScanner
from .injection.nosqli import NoSQLInjectionScanner
from .injection.cmdi import CommandInjectionScanner
from .injection.ssti import SSTIScanner

from .access_control.idor import IDORScanner
from .access_control.path_traversal import PathTraversalScanner
from .access_control.forced_browsing import ForcedBrowsingScanner

from .misconfig.headers import SecurityHeadersScanner
from .misconfig.cors import CORSScanner
from .misconfig.debug import DebugModeScanner
from .misconfig.backup import BackupFileScanner

from .ssrf.ssrf import SSRFScanner

from .xss.xss import XSSScanner

__all__ = [
    # Main classes
    'VulnerabilityScanner',
    'FastVulnerabilityScanner',
    'BaseScanner',
    'Vulnerability',
    'Severity',
    'OWASPCategory',
    
    # Injection scanners
    'SQLInjectionScanner',
    'NoSQLInjectionScanner',
    'CommandInjectionScanner',
    'SSTIScanner',
    'XSSScanner',
    
    # Access control scanners
    'IDORScanner',
    'PathTraversalScanner',
    'ForcedBrowsingScanner',
    
    # Misconfiguration scanners
    'SecurityHeadersScanner',
    'CORSScanner',
    'DebugModeScanner',
    'BackupFileScanner',
    
    # SSRF scanner
    'SSRFScanner',
]