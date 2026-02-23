"""
Injection Scanner Module

OWASP A05:2025 - Injection

This module contains scanners for various injection vulnerabilities including:
- SQL Injection (CWE-89, CWE-564)
- NoSQL Injection (CWE-943)
- OS Command Injection (CWE-77, CWE-78, CWE-88)
- LDAP Injection (CWE-90)
- XPath Injection (CWE-643, CWE-91)
- Server-Side Template Injection (CWE-1336)
- Expression Language Injection (CWE-917)
- Code Injection (CWE-94, CWE-95, CWE-96)
- CRLF Injection (CWE-93, CWE-113)
- Host Header Injection (CWE-644)

Note: XSS (CWE-79, CWE-80) is in the scanner/xss/ module but also falls under A05:2025
"""

from .sqli import SQLInjectionScanner
from .nosqli import NoSQLInjectionScanner
from .cmdi import CommandInjectionScanner
from .ldapi import LDAPInjectionScanner
from .xpath import XPathInjectionScanner
from .ssti import SSTIScanner
from .hhi import HostHeaderInjectionScanner
from .crlf import CRLFInjectionScanner
from .code_injection import CodeInjectionScanner
from .el_injection import ELInjectionScanner
from .xxe import XXEScanner

__all__ = [
    # SQL Injection - CWE-89, CWE-564
    'SQLInjectionScanner',
    
    # NoSQL Injection - CWE-943  
    'NoSQLInjectionScanner',
    
    # Command Injection - CWE-77, CWE-78, CWE-88
    'CommandInjectionScanner',
    
    # LDAP Injection - CWE-90
    'LDAPInjectionScanner',
    
    # XPath Injection - CWE-643, CWE-91
    'XPathInjectionScanner',
    
    # Server-Side Template Injection - CWE-1336
    'SSTIScanner',
    
    # Host Header Injection - CWE-644
    'HostHeaderInjectionScanner',
    
    # CRLF Injection / HTTP Response Splitting - CWE-93, CWE-113
    'CRLFInjectionScanner',
    
    # Code/Eval Injection - CWE-94, CWE-95, CWE-96
    'CodeInjectionScanner',
    
    # Expression Language Injection - CWE-917
    'ELInjectionScanner',

    # XML External Entity Injection - CWE-611, CWE-776, CWE-91
    'XXEScanner',
]

# OWASP 2025 A05 Injection - CWE Mapping
OWASP_A05_2025_CWES = {
    'CWE-20': 'Improper Input Validation',
    'CWE-74': 'Injection (General)',
    'CWE-77': 'Command Injection',
    'CWE-78': 'OS Command Injection',
    'CWE-79': 'Cross-site Scripting (XSS)',
    'CWE-80': 'Basic XSS',
    'CWE-83': 'XSS in Attributes',
    'CWE-86': 'Invalid Characters in Identifiers',
    'CWE-88': 'Argument Injection',
    'CWE-89': 'SQL Injection',
    'CWE-90': 'LDAP Injection',
    'CWE-91': 'XML/XPath Injection',
    'CWE-93': 'CRLF Injection',
    'CWE-94': 'Code Injection',
    'CWE-95': 'Eval Injection',
    'CWE-96': 'Static Code Injection',
    'CWE-97': 'Server-Side Includes Injection',
    'CWE-98': 'PHP Remote File Inclusion',
    'CWE-99': 'Resource Injection',
    'CWE-113': 'HTTP Response Splitting',
    'CWE-116': 'Improper Encoding/Escaping',
    'CWE-564': 'SQL Injection: Hibernate',
    'CWE-611': 'Improper Restriction of XML External Entity Reference',
    'CWE-643': 'XPath Injection',
    'CWE-776': 'Improper Restriction of Recursive Entity References (Billion Laughs)',
    'CWE-917': 'Expression Language Injection',
    'CWE-943': 'NoSQL Injection',
    'CWE-1336': 'Server-Side Template Injection',
}

# Scanner to CWE mapping
SCANNER_CWE_MAP = {
    'SQLInjectionScanner': ['CWE-89', 'CWE-564'],
    'NoSQLInjectionScanner': ['CWE-943'],
    'CommandInjectionScanner': ['CWE-77', 'CWE-78', 'CWE-88'],
    'LDAPInjectionScanner': ['CWE-90'],
    'XPathInjectionScanner': ['CWE-643', 'CWE-91'],
    'SSTIScanner': ['CWE-1336'],
    'HostHeaderInjectionScanner': ['CWE-644'],
    'CRLFInjectionScanner': ['CWE-93', 'CWE-113'],
    'CodeInjectionScanner': ['CWE-94', 'CWE-95', 'CWE-96'],
    'ELInjectionScanner': ['CWE-917'],
    'XXEScanner': ['CWE-611', 'CWE-776', 'CWE-91'],
}


def get_all_injection_scanners():
    """Return all injection scanner classes"""
    return [
        SQLInjectionScanner,
        NoSQLInjectionScanner,
        CommandInjectionScanner,
        LDAPInjectionScanner,
        XPathInjectionScanner,
        SSTIScanner,
        HostHeaderInjectionScanner,
        CRLFInjectionScanner,
        CodeInjectionScanner,
        ELInjectionScanner,
        XXEScanner,
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

# scanner/xss/__init__.py
"""
XSS Scanner Module

Part of OWASP A05:2025 - Injection

This module contains scanners for Cross-Site Scripting vulnerabilities:
- Reflected XSS (CWE-79)
- Stored XSS (CWE-79)
- DOM-based XSS (CWE-79)
- Basic XSS (CWE-80)
- XSS in Attributes (CWE-83)
- Invalid Characters in Identifiers (CWE-86)
"""

from .xss import XSSScanner
from .dom_xss import DOMXSSScanner

__all__ = [
    'XSSScanner',
    'DOMXSSScanner',
]

# CWE Mapping for XSS
XSS_CWES = {
    'CWE-79': 'Cross-site Scripting (XSS)',
    'CWE-80': 'Basic XSS',
    'CWE-83': 'XSS in Attributes',
    'CWE-86': 'Invalid Characters in Identifiers',
}

def get_all_xss_scanners():
    """Return all XSS scanner classes"""
    return [
        XSSScanner,
        DOMXSSScanner,
    ]