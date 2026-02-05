# scanner/deserialization/__init__.py
"""
Deserialization and Data Integrity Scanner Module

OWASP A08:2025 - Software or Data Integrity Failures

This module contains scanners for integrity and deserialization vulnerabilities:
- Insecure Deserialization (CWE-502)
- Subresource Integrity (CWE-829, CWE-830, CWE-494)
- Cookie Integrity (CWE-565, CWE-784)
- Code Integrity (CWE-345, CWE-353)
"""

from .insecure_deserialization import InsecureDeserializationScanner
from .subresource_integrity import SubresourceIntegrityScanner
from .cookie_integrity import CookieIntegrityScanner
from .code_integrity import CodeIntegrityScanner

__all__ = [
    'InsecureDeserializationScanner',
    'SubresourceIntegrityScanner',
    'CookieIntegrityScanner',
    'CodeIntegrityScanner',
]

# OWASP 2025 A08 Software or Data Integrity Failures - CWE Mapping
OWASP_A08_2025_CWES = {
    'CWE-345': 'Insufficient Verification of Data Authenticity',
    'CWE-353': 'Missing Support for Integrity Check',
    'CWE-426': 'Untrusted Search Path',
    'CWE-427': 'Uncontrolled Search Path Element',
    'CWE-494': 'Download of Code Without Integrity Check',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-506': 'Embedded Malicious Code',
    'CWE-509': 'Replicating Malicious Code',
    'CWE-565': 'Reliance on Cookies without Validation',
    'CWE-784': 'Reliance on Cookies in Security Decision',
    'CWE-829': 'Inclusion of Functionality from Untrusted Control Sphere',
    'CWE-830': 'Inclusion of Web Functionality from Untrusted Source',
    'CWE-915': 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
    'CWE-926': 'Improper Export of Android Application Components',
}

# Scanner to CWE mapping
SCANNER_CWE_MAP = {
    'InsecureDeserializationScanner': ['CWE-502'],
    'SubresourceIntegrityScanner': ['CWE-829', 'CWE-830', 'CWE-494'],
    'CookieIntegrityScanner': ['CWE-565', 'CWE-784'],
    'CodeIntegrityScanner': ['CWE-345', 'CWE-353', 'CWE-494'],
}


def get_all_integrity_scanners():
    """Return all integrity scanner classes"""
    return [
        InsecureDeserializationScanner,
        SubresourceIntegrityScanner,
        CookieIntegrityScanner,
        CodeIntegrityScanner,
    ]


def get_scanner_for_cwe(cwe_id: str):
    """Get appropriate scanner(s) for a given CWE ID"""
    scanners = []
    for scanner_name, cwes in SCANNER_CWE_MAP.items():
        if cwe_id in cwes:
            scanner_class = globals().get(scanner_name)
            if scanner_class:
                scanners.append(scanner_class)
    return scanners