# scanner/authentication/__init__.py
"""
Authentication Scanner Module

OWASP A07:2025 - Authentication Failures

This module contains scanners for authentication vulnerabilities including:
- Brute Force / Credential Stuffing (CWE-307)
- Session Fixation (CWE-384)
- Weak Password Policy (CWE-521, CWE-598)
- Default/Hardcoded Credentials (CWE-798, CWE-259, CWE-1392, CWE-1393)
- Session Management Issues (CWE-613, CWE-539)
- Authentication Bypass (CWE-287, CWE-288, CWE-302, CWE-306)
- Missing/Weak MFA (CWE-308)
"""

from .brute_force import BruteForceScanner
from .session_fixation import SessionFixationScanner
from .weak_password import WeakPasswordPolicyScanner
from .default_credentials import DefaultCredentials07Scanner
from .session_management import SessionManagementScanner
from .auth_bypass import AuthBypassScanner
from .mfa_check import MFAScanner

__all__ = [
    'BruteForceScanner',
    'SessionFixationScanner',
    'WeakPasswordPolicyScanner',
    'DefaultCredentials07Scanner',
    'SessionManagementScanner',
    'AuthBypassScanner',
    'MFAScanner',
]

# OWASP 2025 A07 Authentication Failures - CWE Mapping
OWASP_A07_2025_CWES = {
    # Credentials
    'CWE-258': 'Empty Password in Configuration File',
    'CWE-259': 'Use of Hard-coded Password',
    'CWE-521': 'Weak Password Requirements',
    'CWE-798': 'Use of Hard-coded Credentials',
    'CWE-1391': 'Use of Weak Credentials',
    'CWE-1392': 'Use of Default Credentials',
    'CWE-1393': 'Use of Default Password',
    
    # Authentication
    'CWE-287': 'Improper Authentication',
    'CWE-288': 'Authentication Bypass Using Alternate Path',
    'CWE-289': 'Authentication Bypass by Alternate Name',
    'CWE-290': 'Authentication Bypass by Spoofing',
    'CWE-291': 'Reliance on IP Address for Authentication',
    'CWE-293': 'Using Referer Field for Authentication',
    'CWE-294': 'Authentication Bypass by Capture-replay',
    'CWE-302': 'Authentication Bypass by Assumed-Immutable Data',
    'CWE-303': 'Incorrect Implementation of Authentication Algorithm',
    'CWE-304': 'Missing Critical Step in Authentication',
    'CWE-305': 'Authentication Bypass by Primary Weakness',
    'CWE-306': 'Missing Authentication for Critical Function',
    'CWE-307': 'Improper Restriction of Excessive Authentication Attempts',
    'CWE-308': 'Use of Single-factor Authentication',
    'CWE-309': 'Use of Password System for Primary Authentication',
    'CWE-1390': 'Weak Authentication',
    
    # Session Management
    'CWE-384': 'Session Fixation',
    'CWE-613': 'Insufficient Session Expiration',
    'CWE-539': 'Persistent Cookies with Sensitive Info',
    
    # Password Recovery
    'CWE-620': 'Unverified Password Change',
    'CWE-640': 'Weak Password Recovery Mechanism',
    
    # Certificate/Channel
    'CWE-295': 'Improper Certificate Validation',
    'CWE-297': 'Improper Validation of Certificate with Host Mismatch',
    'CWE-300': 'Channel Accessible by Non-Endpoint',
    'CWE-346': 'Origin Validation Error',
    'CWE-350': 'Reliance on Reverse DNS Resolution',
    'CWE-940': 'Improper Verification of Source of Communication Channel',
    'CWE-941': 'Incorrectly Specified Destination in Communication Channel',
}

# Scanner to CWE mapping
SCANNER_CWE_MAP = {
    'BruteForceScanner': ['CWE-307'],
    'SessionFixationScanner': ['CWE-384'],
    'WeakPasswordPolicyScanner': ['CWE-521', 'CWE-598'],
    'DefaultCredentials07Scanner': ['CWE-798', 'CWE-259', 'CWE-1392', 'CWE-1393', 'CWE-258'],
    'SessionManagementScanner': ['CWE-613', 'CWE-384', 'CWE-539'],
    'AuthBypassScanner': ['CWE-287', 'CWE-288', 'CWE-289', 'CWE-290', 'CWE-302', 'CWE-306'],
    'MFAScanner': ['CWE-308', 'CWE-287'],
}


def get_all_authentication_scanners():
    """Return all authentication scanner classes"""
    return [
        BruteForceScanner,
        SessionFixationScanner,
        WeakPasswordPolicyScanner,
        DefaultCredentials07Scanner,
        SessionManagementScanner,
        AuthBypassScanner,
        MFAScanner,
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