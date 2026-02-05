# scanner/insecure_design/__init__.py
"""
Insecure Design Scanner Module

OWASP A06:2025 - Insecure Design

This module contains scanners for design and architectural flaws including:
- File Upload Vulnerabilities (CWE-434, CWE-646)
- HTTP Request Smuggling (CWE-444)
- Clickjacking/UI Redressing (CWE-1021, CWE-1022)
- Race Conditions (CWE-362)
- Business Logic Flaws (CWE-841, CWE-799)
- Trust Boundary Violations (CWE-501, CWE-602, CWE-472)
"""

from .file_upload import FileUploadScanner
from .http_smuggling import HTTPSmugglingScanner
from .clickjacking import ClickjackingScanner
from .race_condition import RaceConditionScanner
from .business_logic import BusinessLogicScanner
from .trust_boundary import TrustBoundaryScanner

__all__ = [
    'FileUploadScanner',
    'HTTPSmugglingScanner',
    'ClickjackingScanner',
    'RaceConditionScanner',
    'BusinessLogicScanner',
    'TrustBoundaryScanner',
]

# OWASP 2025 A06 Insecure Design - CWE Mapping
OWASP_A06_2025_CWES = {
    # File handling
    'CWE-73': 'External Control of File Name or Path',
    'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
    'CWE-646': 'Reliance on File Name or Extension',
    
    # HTTP issues
    'CWE-444': 'HTTP Request Smuggling',
    
    # UI/Clickjacking
    'CWE-451': 'UI Misrepresentation',
    'CWE-1021': 'Improper Restriction of Rendered UI Layers',
    'CWE-1022': 'window.opener Vulnerability',
    
    # Concurrency
    'CWE-362': 'Race Condition',
    
    # Business logic
    'CWE-799': 'Improper Control of Interaction Frequency',
    'CWE-841': 'Improper Enforcement of Behavioral Workflow',
    
    # Trust boundaries
    'CWE-472': 'External Control of Assumed-Immutable Parameter',
    'CWE-501': 'Trust Boundary Violation',
    'CWE-602': 'Client-Side Enforcement of Server-Side Security',
    'CWE-642': 'External Control of Critical State Data',
    
    # Credentials/secrets
    'CWE-256': 'Unprotected Storage of Credentials',
    'CWE-522': 'Insufficiently Protected Credentials',
    
    # Access control design
    'CWE-266': 'Incorrect Privilege Assignment',
    'CWE-269': 'Improper Privilege Management',
    'CWE-286': 'Incorrect User Management',
    
    # Data protection design
    'CWE-311': 'Missing Encryption of Sensitive Data',
    'CWE-312': 'Cleartext Storage of Sensitive Information',
    'CWE-313': 'Cleartext Storage in File',
    'CWE-316': 'Cleartext Storage in Memory',
    
    # Miscellaneous design flaws
    'CWE-419': 'Unprotected Primary Channel',
    'CWE-525': 'Browser Cache with Sensitive Info',
    'CWE-539': 'Persistent Cookies with Sensitive Info',
    'CWE-598': 'GET Request with Sensitive Query String',
    'CWE-653': 'Insufficient Compartmentalization',
    'CWE-656': 'Security Through Obscurity',
    'CWE-657': 'Violation of Secure Design Principles',
    'CWE-693': 'Protection Mechanism Failure',
    'CWE-807': 'Reliance on Untrusted Inputs',
    'CWE-1125': 'Excessive Attack Surface',
}

# Scanner to CWE mapping
SCANNER_CWE_MAP = {
    'FileUploadScanner': ['CWE-434', 'CWE-646', 'CWE-73'],
    'HTTPSmugglingScanner': ['CWE-444'],
    'ClickjackingScanner': ['CWE-1021', 'CWE-1022', 'CWE-451'],
    'RaceConditionScanner': ['CWE-362'],
    'BusinessLogicScanner': ['CWE-841', 'CWE-799'],
    'TrustBoundaryScanner': ['CWE-501', 'CWE-602', 'CWE-472', 'CWE-642'],
}


def get_all_insecure_design_scanners():
    """Return all insecure design scanner classes"""
    return [
        FileUploadScanner,
        HTTPSmugglingScanner,
        ClickjackingScanner,
        RaceConditionScanner,
        BusinessLogicScanner,
        TrustBoundaryScanner,
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