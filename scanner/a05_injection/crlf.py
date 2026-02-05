# scanner/injection/crlf.py
"""
CRLF Injection / HTTP Response Splitting Scanner

Detects CRLF injection vulnerabilities that can lead to:
- HTTP Response Splitting
- Header Injection
- Cache Poisoning
- XSS via header injection
- Session Fixation

OWASP: A05:2025 - Injection
CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
"""

import re
import asyncio
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import quote, urlencode

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CRLFInjectionScanner(BaseScanner):
    """Scanner for CRLF Injection and HTTP Response Splitting vulnerabilities"""
    
    name = "CRLF Injection Scanner"
    description = "Detects CRLF injection and HTTP response splitting vulnerabilities"
    owasp_category = OWASPCategory.A05_INJECTION
    
    # CRLF sequences to test
    CRLF_SEQUENCES = [
        # Standard CRLF
        ("\r\n", "Standard CRLF"),
        ("\r", "CR only"),
        ("\n", "LF only"),
        
        # URL encoded
        ("%0d%0a", "URL encoded CRLF"),
        ("%0d", "URL encoded CR"),
        ("%0a", "URL encoded LF"),
        
        # Double URL encoded
        ("%250d%250a", "Double encoded CRLF"),
        
        # Unicode/UTF-8 encoded
        ("%c0%8d%c0%8a", "UTF-8 overlong CRLF"),
        
        # Mixed encodings
        ("%0d\n", "Mixed CR encoding"),
        ("\r%0a", "Mixed LF encoding"),
        
        # Null byte bypass
        ("%00%0d%0a", "Null + CRLF"),
        
        # Alternative representations
        ("%%0d%%0a", "Double percent CRLF"),
        ("%E5%98%8A%E5%98%8D", "UTF-8 CRLF"),
    ]
    
    # Payloads for header injection
    HEADER_INJECTION_PAYLOADS = [
        # Basic header injection
        ("X-Injected: true", "Basic header"),
        ("Set-Cookie: injected=true", "Cookie injection"),
        ("Set-Cookie: session=malicious; Path=/; HttpOnly", "Session fixation"),
        
        # XSS via headers
        ("Content-Type: text/html\r\n\r\n<script>alert('XSS')</script>", "XSS via content-type"),
        ("X-XSS: <script>alert(1)</script>", "XSS in custom header"),
        
        # Cache poisoning
        ("Cache-Control: public, max-age=31536000", "Cache poisoning"),
        ("X-Forwarded-Host: evil.com", "Host header injection"),
        
        # Response splitting (inject full response)
        ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Injected</html>", "Full response split"),
    ]
    
    # Headers commonly vulnerable to CRLF injection
    INJECTABLE_HEADERS = [
        "Location",
        "Set-Cookie",
        "X-Custom",
        "Content-Disposition",
        "X-Forwarded-For",
        "Referer",
        "User-Agent",
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for CRLF injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            params = {'test': 'value'}
        
        # Test URL parameters
        for param_name in params.keys():
            param_vulns = await self._test_parameter(session, url, params, param_name)
            vulnerabilities.extend(param_vulns)
        
        # Test headers
        header_vulns = await self._test_headers(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Test redirect endpoints
        redirect_vulns = await self._test_redirects(session, url, params)
        vulnerabilities.extend(redirect_vulns)
        
        return vulnerabilities
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str],
                               param_name: str) -> List[Vulnerability]:
        """Test a URL parameter for CRLF injection"""
        vulnerabilities = []
        
        for crlf_seq, crlf_desc in self.CRLF_SEQUENCES:
            for header_payload, header_desc in self.HEADER_INJECTION_PAYLOADS[:4]:  # Limit for speed
                full_payload = f"test{crlf_seq}{header_payload}"
                
                test_params = params.copy()
                test_params[param_name] = full_payload
                
                try:
                    async with session.get(
                        url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        # Check response headers for injection
                        vuln = self._check_header_injection(
                            response.headers, header_payload, url,
                            param_name, full_payload, crlf_desc
                        )
                        if vuln:
                            vulnerabilities.append(vuln)
                            return vulnerabilities  # Found, stop testing this param
                        
                        # Check response body for response splitting
                        body = await response.text()
                        if self._check_response_split(body, header_payload):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="HTTP Response Splitting",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=full_payload,
                                evidence=f"Injected content found in response body",
                                description=f"HTTP response splitting via {crlf_desc}. Attacker can inject arbitrary HTTP responses.",
                                cwe_id="CWE-113",
                                cvss_score=8.1,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                                    "https://cwe.mitre.org/data/definitions/113.html"
                                ]
                            ))
                            return vulnerabilities
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_headers(self, session: aiohttp.ClientSession,
                            url: str) -> List[Vulnerability]:
        """Test request headers for CRLF injection"""
        vulnerabilities = []
        
        for header_name in self.INJECTABLE_HEADERS:
            for crlf_seq, crlf_desc in self.CRLF_SEQUENCES[:4]:  # Limit
                payload = f"test{crlf_seq}X-Injected: true"
                
                try:
                    headers = {header_name: payload}
                    
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        # Check if injected header appears
                        if 'X-Injected' in response.headers or 'x-injected' in str(response.headers).lower():
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="CRLF Injection via Request Header",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter=f"Header: {header_name}",
                                payload=payload,
                                evidence=f"Injected header reflected in response",
                                description=f"CRLF injection via {header_name} header using {crlf_desc}",
                                cwe_id="CWE-93",
                                cvss_score=6.1,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://cwe.mitre.org/data/definitions/93.html"
                                ]
                            ))
                            return vulnerabilities
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_redirects(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test redirect functionality for CRLF injection"""
        vulnerabilities = []
        
        # Common redirect parameters
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 
                          'goto', 'destination', 'redir', 'redirect_uri']
        
        for redir_param in redirect_params:
            for crlf_seq, crlf_desc in self.CRLF_SEQUENCES[:5]:
                payload = f"http://example.com{crlf_seq}Set-Cookie: injected=true"
                
                test_params = params.copy()
                test_params[redir_param] = payload
                
                try:
                    async with session.get(
                        url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        # Check Location header and Set-Cookie
                        location = response.headers.get('Location', '')
                        cookies = response.headers.getall('Set-Cookie', [])
                        
                        # Check if our cookie was injected
                        if any('injected=true' in c for c in cookies):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="CRLF Injection in Redirect",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=redir_param,
                                payload=payload,
                                evidence=f"Cookie injection via redirect: {cookies}",
                                description=f"CRLF injection in redirect URL allows cookie/header injection",
                                cwe_id="CWE-113",
                                cvss_score=7.5,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"
                                ]
                            ))
                            return vulnerabilities
                        
                        # Check if CRLF is in Location header (partial vulnerability)
                        if crlf_seq.replace('%', '') in location or '\r' in location or '\n' in location:
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Potential CRLF Injection in Redirect",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter=redir_param,
                                payload=payload,
                                evidence=f"CRLF sequence in Location header",
                                description="CRLF characters accepted in redirect URL",
                                cwe_id="CWE-93",
                                cvss_score=5.4,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://cwe.mitre.org/data/definitions/93.html"
                                ]
                            ))
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _check_header_injection(self, headers, payload: str, url: str,
                                 param: str, full_payload: str,
                                 crlf_desc: str) -> Optional[Vulnerability]:
        """Check if header was successfully injected"""
        headers_str = str(headers).lower()
        
        # Extract the header name we tried to inject
        if ':' in payload:
            injected_header = payload.split(':')[0].strip().lower()
            
            if injected_header in headers_str:
                return self.create_vulnerability(
                    vuln_type="CRLF Header Injection",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=full_payload,
                    evidence=f"Injected header '{injected_header}' found in response",
                    description=f"CRLF injection allows arbitrary header injection via {crlf_desc}",
                    cwe_id="CWE-113",
                    cvss_score=7.5,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                        "https://cwe.mitre.org/data/definitions/113.html"
                    ]
                )
        
        return None
    
    def _check_response_split(self, body: str, payload: str) -> bool:
        """Check if response was successfully split"""
        # Look for signs of response splitting
        indicators = [
            '<script>alert',
            '<html>Injected',
            'HTTP/1.1 200 OK',
        ]
        
        return any(ind.lower() in body.lower() for ind in indicators if ind in payload)
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
CRLF Injection Prevention:

1. Input Validation: Reject or encode CR (\\r, %0d) and LF (\\n, %0a) characters
2. Output Encoding: Properly encode data before including in HTTP headers
3. Framework Protection: Use modern frameworks that auto-escape header values
4. Allowlist Validation: For redirect URLs, validate against an allowlist
5. URL Encoding: Properly URL-encode user input used in headers

Example (Python):
```python
import re

def sanitize_header_value(value):
    # Remove CRLF sequences
    return re.sub(r'[\\r\\n]', '', value)

def safe_redirect(url):
    # Validate URL and remove CRLF
    if not url.startswith(('http://', 'https://')):
        raise ValueError("Invalid URL scheme")
    return sanitize_header_value(url)
```
Example (Java):
```java
// Use ESAPI or similar library
String safeValue = ESAPI.encoder().encodeForHTTPHeader(userInput);
```
"""