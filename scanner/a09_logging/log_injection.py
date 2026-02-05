"""Log Injection Scanner (CWE-117)"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
import re

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class LogInjectionScanner(BaseScanner):
    """
    Scanner for Log Injection / Log Forging vulnerabilities (CWE-117).
    
    Tests if user input can be injected into application logs by:
    1. Injecting CRLF sequences that could create fake log entries
    2. Testing for log format string injection
    3. Checking if injected content appears in error responses
    """
    
    name = "Log Injection Scanner"
    description = "Detects log injection and log forging vulnerabilities"
    owasp_category = OWASPCategory.A09_LOGGING_ALERTING_FAILURES
    
    # Log injection payloads - designed to create fake log entries
    LOG_INJECTION_PAYLOADS = [
        # CRLF injection for log forging
        "test%0d%0a[INFO] Fake log entry injected",
        "test%0d%0a%0d%0a[ADMIN] User authenticated successfully",
        "test\r\n[ERROR] System compromised\r\n",
        "test%0aINFO: Admin login successful",
        "test%0d%0aWARNING: Security bypass detected",
        
        # Unicode line separators
        "test\u2028[INFO] Unicode line separator injection",
        "test\u2029[INFO] Unicode paragraph separator injection",
        
        # Log format string injection (for format-string vulnerable loggers)
        "test %s %s %s %s %s",
        "test %n%n%n%n",
        "test %x%x%x%x",
        "${jndi:ldap://test.com/a}",  # Log4j style (also detects Log4Shell remnants)
        "{{constructor.constructor('return this')()}}",
        
        # Timestamp manipulation attempts
        "test\r\n2024-01-01 00:00:00 [CRITICAL] Injected timestamp",
        
        # Multi-line injection
        "test\nFake Entry 1\nFake Entry 2\nFake Entry 3",
        
        # Null byte injection (may truncate logs)
        "test%00teleported",
        "test\x00after_null",
    ]
    
    # Patterns indicating successful log injection in response
    INJECTION_SUCCESS_PATTERNS = [
        r'\[INFO\].*Fake',
        r'\[ADMIN\].*authenticated',
        r'\[ERROR\].*compromised',
        r'\[CRITICAL\].*Injected',
        r'INFO:.*Admin login',
        r'WARNING:.*bypass',
        r'Fake Entry \d',
        r'%s %s %s',  # Unprocessed format strings
        r'\$\{jndi:',  # Log4j pattern reflected
    ]
    
    # Headers to test for log injection
    INJECTABLE_HEADERS = [
        'User-Agent',
        'Referer', 
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Custom-Header',
        'Cookie',
    ]

    async def scan(self, session: aiohttp.ClientSession,
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for log injection vulnerabilities"""
        vulnerabilities = []
        
        # Test parameter-based log injection
        if params:
            param_vulns = await self._test_parameter_injection(session, url, params)
            vulnerabilities.extend(param_vulns)
        
        # Test header-based log injection
        header_vulns = await self._test_header_injection(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Test URL path-based log injection
        path_vulns = await self._test_path_injection(session, url)
        vulnerabilities.extend(path_vulns)
        
        return vulnerabilities
    
    async def _test_parameter_injection(self, session: aiohttp.ClientSession,
                                         url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test parameters for log injection"""
        vulnerabilities = []
        
        for param_name, original_value in params.items():
            for payload in self.LOG_INJECTION_PAYLOADS[:8]:  # Limit for speed
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                try:
                    body = await response.text()
                    
                    vuln = self._check_injection_success(
                        url, param_name, payload, body, response.status, "parameter"
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # Found vuln for this param, move to next
                        
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_header_injection(self, session: aiohttp.ClientSession,
                                      url: str) -> List[Vulnerability]:
        """Test headers for log injection (commonly logged)"""
        vulnerabilities = []
        
        for header_name in self.INJECTABLE_HEADERS:
            for payload in self.LOG_INJECTION_PAYLOADS[:5]:  # Limit payloads
                headers = {header_name: payload}
                
                response = await self.make_request(session, "GET", url, headers=headers)
                if not response:
                    continue
                
                try:
                    body = await response.text()
                    
                    vuln = self._check_injection_success(
                        url, header_name, payload, body, response.status, "header"
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
                        
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_path_injection(self, session: aiohttp.ClientSession,
                                    url: str) -> List[Vulnerability]:
        """Test URL path for log injection"""
        vulnerabilities = []
        parsed = urlparse(url)
        
        # Only test a few payloads in path
        path_payloads = [
            "%0d%0a[INJECTED]%20log%20entry",
            "../%00test",
            "..%2F%00injected",
        ]
        
        for payload in path_payloads:
            # Append payload to path
            test_path = parsed.path.rstrip('/') + '/' + payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, test_path,
                parsed.params, parsed.query, parsed.fragment
            ))
            
            response = await self.make_request(session, "GET", test_url)
            if not response:
                continue
            
            try:
                body = await response.text()
                
                vuln = self._check_injection_success(
                    url, "URL Path", payload, body, response.status, "path"
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break
                    
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_injection_success(self, url: str, location: str, payload: str,
                                  response_body: str, status_code: int,
                                  injection_type: str) -> Optional[Vulnerability]:
        """Check if log injection was successful"""
        
        # Check for injection patterns in response
        for pattern in self.INJECTION_SUCCESS_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE):
                return self.create_vulnerability(
                    vuln_type="Log Injection / Log Forging",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=location,
                    payload=payload,
                    evidence=f"Injected log pattern found in response. Pattern matched: {pattern}",
                    description=(
                        f"The application appears vulnerable to log injection via {injection_type}. "
                        f"An attacker can inject fake log entries by manipulating the '{location}' {injection_type}. "
                        "This can be used to:\n"
                        "- Forge log entries to cover malicious activity\n"
                        "- Inject misleading information for forensic analysis\n"
                        "- Potentially exploit log viewing tools (XSS in log viewers)\n"
                        "- Manipulate log-based monitoring and alerting systems"
                    ),
                    cwe_id="CWE-117",
                    cvss_score=5.3,
                    remediation=(
                        "1. Sanitize all user input before logging - encode or remove newlines (CR/LF)\n"
                        "2. Use structured logging formats (JSON) that properly escape special characters\n"
                        "3. Implement allowlists for expected log entry formats\n"
                        "4. Use logging frameworks that auto-encode output (e.g., SLF4J with Logback)\n"
                        "5. Never include raw user input in log messages without encoding"
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Log_Injection",
                        "https://cwe.mitre.org/data/definitions/117.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
                    ]
                )
        
        # Check if CRLF characters appear literally (improper handling)
        decoded_payload = payload.replace('%0d', '\r').replace('%0a', '\n').replace('%00', '\x00')
        if '\r' in decoded_payload or '\n' in decoded_payload:
            if decoded_payload in response_body or payload in response_body:
                return self.create_vulnerability(
                    vuln_type="Potential Log Injection Vector",
                    severity=Severity.LOW,
                    url=url,
                    parameter=location,
                    payload=payload,
                    evidence=f"CRLF/newline characters reflected in response from {location}",
                    description=(
                        f"The application reflects CRLF characters from {injection_type} input without encoding. "
                        "While this may not directly indicate log injection, it suggests insufficient input "
                        "sanitization that could affect logging systems."
                    ),
                    cwe_id="CWE-117",
                    cvss_score=3.7,
                    remediation=(
                        "Encode or strip newline characters (CR, LF) from all user input before processing. "
                        "Use output encoding appropriate for the context (logs, HTTP headers, etc.)."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Log_Injection",
                        "https://cwe.mitre.org/data/definitions/93.html"
                    ]
                )
        
        return None