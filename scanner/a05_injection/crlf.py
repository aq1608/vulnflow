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
                            print(f"[*] CRLF: Found potential vulnerability from A05")
                            # Highlight the payload in the response body
                            highlighted_evidence = self._highlight_payload_in_body(
                                body, header_payload, full_payload
                            )
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="HTTP Response Splitting",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=full_payload,
                                evidence=highlighted_evidence,
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


    def _highlight_payload_in_body(self, body: str, header_payload: str, 
                                    full_payload: str, 
                                    context_chars: int = 200,
                                    max_body_length: int = 2000) -> str:
        """
        Highlight the injected payload in the response body.
        
        Args:
            body: The full response body
            header_payload: The header injection payload to find
            full_payload: The complete payload including CRLF sequence
            context_chars: Number of characters to show around the payload
            max_body_length: Maximum length of body to include in evidence
        
        Returns:
            Formatted evidence string with highlighted payload
        """
        # Markers for highlighting
        HIGHLIGHT_START = ">>>>> INJECTED PAYLOAD START >>>>>"
        HIGHLIGHT_END = "<<<<< INJECTED PAYLOAD END <<<<<"
        
        # Try to find and highlight the payload in the body
        payloads_to_search = [header_payload, full_payload]
        
        for payload in payloads_to_search:
            if payload in body:
                # Find the position of the payload
                pos = body.find(payload)
                
                # Calculate context window
                start_pos = max(0, pos - context_chars)
                end_pos = min(len(body), pos + len(payload) + context_chars)
                
                # Extract the relevant portion
                prefix = body[start_pos:pos]
                found_payload = body[pos:pos + len(payload)]
                suffix = body[pos + len(payload):end_pos]
                
                # Build the highlighted evidence
                evidence_parts = []
                evidence_parts.append("=== RESPONSE BODY (with payload highlighted) ===\n")
                
                if start_pos > 0:
                    evidence_parts.append(f"[... {start_pos} chars truncated ...]\n")
                
                evidence_parts.append(prefix)
                evidence_parts.append(f"\n{HIGHLIGHT_START}\n")
                evidence_parts.append(found_payload)
                evidence_parts.append(f"\n{HIGHLIGHT_END}\n")
                evidence_parts.append(suffix)
                
                if end_pos < len(body):
                    evidence_parts.append(f"\n[... {len(body) - end_pos} chars truncated ...]")
                
                evidence_parts.append(f"\n\n=== PAYLOAD DETAILS ===")
                evidence_parts.append(f"\nPayload found at position: {pos}")
                evidence_parts.append(f"\nPayload length: {len(payload)}")
                evidence_parts.append(f"\nTotal response body length: {len(body)}")
                
                return ''.join(evidence_parts)
        
        # If payload not found directly, return truncated body with note
        truncated_body = body[:max_body_length]
        if len(body) > max_body_length:
            truncated_body += f"\n[... {len(body) - max_body_length} chars truncated ...]"
        
        return (
            f"=== RESPONSE BODY ===\n"
            f"{truncated_body}\n\n"
            f"=== NOTE ===\n"
            f"Payload detection triggered but exact payload not found in body.\n"
            f"Expected payload: {repr(header_payload)}"
        )


    def _highlight_payload_in_body_html(self, body: str, header_payload: str,
                                        full_payload: str,
                                        context_chars: int = 200) -> str:
        """
        Alternative version that produces HTML-formatted evidence.
        Useful if your reporting supports HTML rendering.
        """
        import html
        
        for payload in [header_payload, full_payload]:
            if payload in body:
                pos = body.find(payload)
                start_pos = max(0, pos - context_chars)
                end_pos = min(len(body), pos + len(payload) + context_chars)
                
                prefix = html.escape(body[start_pos:pos])
                found_payload = html.escape(body[pos:pos + len(payload)])
                suffix = html.escape(body[pos + len(payload):end_pos])
                
                return (
                    f'<div class="evidence">'
                    f'<h4>Response Body Evidence</h4>'
                    f'<pre>'
                    f'{"..." if start_pos > 0 else ""}'
                    f'{prefix}'
                    f'<mark style="background-color: #ff6b6b; padding: 2px 4px; font-weight: bold;">'
                    f'{found_payload}'
                    f'</mark>'
                    f'{suffix}'
                    f'{"..." if end_pos < len(body) else ""}'
                    f'</pre>'
                    f'<p><strong>Payload position:</strong> {pos}</p>'
                    f'<p><strong>Body length:</strong> {len(body)}</p>'
                    f'</div>'
                )
        
        return f'<pre>{html.escape(body[:2000])}</pre>'
    
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
                            # Build detailed evidence with headers
                            evidence = self._highlight_payload_in_headers(
                                response.headers,
                                payload,
                                'X-Injected',
                                header_name
                            )
                            print(f"[*] CRLF: Found potential vulnerability from A05")
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="CRLF Injection via Request Header",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter=f"Header: {header_name}",
                                payload=payload,
                                evidence=evidence,
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
                            evidence = self._highlight_redirect_injection(
                                response.headers,
                                payload,
                                location,
                                cookies,
                                redir_param,
                                injection_type="cookie"
                            )
                            print(f"[*] CRLF: Found potential vulnerability from A05")
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="CRLF Injection in Redirect",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=redir_param,
                                payload=payload,
                                evidence=evidence,
                                description=f"CRLF injection in redirect URL allows cookie/header injection via {crlf_desc}",
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
                            evidence = self._highlight_redirect_injection(
                                response.headers,
                                payload,
                                location,
                                cookies,
                                redir_param,
                                injection_type="location",
                                crlf_seq=crlf_seq
                            )
                            print(f"[*] CRLF: Found potential vulnerability from A05")
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Potential CRLF Injection in Redirect",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter=redir_param,
                                payload=payload,
                                evidence=evidence,
                                description=f"CRLF characters accepted in redirect URL via {crlf_desc}",
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
                # Build detailed evidence
                evidence = self._highlight_payload_in_headers(
                    headers,
                    full_payload,
                    injected_header,
                    param
                )
                print(f"[*] CRLF: Found potential vulnerability from A05")
                return self.create_vulnerability(
                    vuln_type="CRLF Header Injection",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=full_payload,
                    evidence=evidence,
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


    def _highlight_payload_in_headers(self, headers, payload: str,
                                    injected_header: str,
                                    source_param: str) -> str:
        """
        Create detailed evidence showing injected headers with highlighting.
        
        Args:
            headers: Response headers (aiohttp headers object)
            payload: The payload that was sent
            injected_header: The header name that was injected
            source_param: The parameter/header used for injection
        
        Returns:
            Formatted evidence string with highlighted injection
        """
        HIGHLIGHT_START = ">>>>> INJECTED HEADER START >>>>>"
        HIGHLIGHT_END = "<<<<< INJECTED HEADER END <<<<<"
        
        evidence_parts = []
        evidence_parts.append("=== RESPONSE HEADERS ===\n")
        
        # Format all headers, highlighting the injected one
        for header_name, header_value in headers.items():
            header_line = f"{header_name}: {header_value}"
            
            if injected_header.lower() in header_name.lower():
                evidence_parts.append(f"\n{HIGHLIGHT_START}\n")
                evidence_parts.append(header_line)
                evidence_parts.append(f"\n{HIGHLIGHT_END}\n")
            else:
                evidence_parts.append(f"{header_line}\n")
        
        # Add injection details
        evidence_parts.append(f"\n=== INJECTION DETAILS ===")
        evidence_parts.append(f"\nInjection Point: {source_param}")
        evidence_parts.append(f"\nPayload Sent: {repr(payload)}")
        evidence_parts.append(f"\nInjected Header: {injected_header}")
        evidence_parts.append(f"\nTotal Headers in Response: {len(headers)}")
        
        return ''.join(evidence_parts)


    def _highlight_redirect_injection(self, headers, payload: str,
                                    location: str, cookies: List[str],
                                    param: str, injection_type: str,
                                    crlf_seq: str = None) -> str:
        """
        Create detailed evidence for redirect-based CRLF injection.
        
        Args:
            headers: Response headers
            payload: The payload that was sent
            location: The Location header value
            cookies: List of Set-Cookie header values
            param: The redirect parameter used
            injection_type: Type of injection ("cookie" or "location")
            crlf_seq: The CRLF sequence used (for location injection)
        
        Returns:
            Formatted evidence string with highlighted injection
        """
        HIGHLIGHT_START = ">>>>> INJECTED CONTENT START >>>>>"
        HIGHLIGHT_END = "<<<<< INJECTED CONTENT END <<<<<"
        
        evidence_parts = []
        evidence_parts.append("=== RESPONSE HEADERS ===\n")
        
        # Format all headers
        for header_name, header_value in headers.items():
            header_line = f"{header_name}: {header_value}"
            
            # Highlight based on injection type
            if injection_type == "cookie" and header_name.lower() == "set-cookie":
                if "injected=true" in header_value:
                    evidence_parts.append(f"\n{HIGHLIGHT_START}\n")
                    evidence_parts.append(header_line)
                    evidence_parts.append(f"\n{HIGHLIGHT_END}\n")
                else:
                    evidence_parts.append(f"{header_line}\n")
            elif injection_type == "location" and header_name.lower() == "location":
                # Highlight the CRLF sequence in location
                highlighted_location = self._highlight_crlf_in_string(
                    header_value, crlf_seq
                )
                evidence_parts.append(f"\n{HIGHLIGHT_START}\n")
                evidence_parts.append(f"{header_name}: {highlighted_location}")
                evidence_parts.append(f"\n{HIGHLIGHT_END}\n")
            else:
                evidence_parts.append(f"{header_line}\n")
        
        # Add cookie details if relevant
        if cookies:
            evidence_parts.append(f"\n=== SET-COOKIE HEADERS ({len(cookies)}) ===\n")
            for i, cookie in enumerate(cookies, 1):
                if "injected=true" in cookie:
                    evidence_parts.append(f"\n{HIGHLIGHT_START}\n")
                    evidence_parts.append(f"[{i}] {cookie}")
                    evidence_parts.append(f"\n{HIGHLIGHT_END}\n")
                else:
                    evidence_parts.append(f"[{i}] {cookie}\n")
        
        # Add location header details
        if location:
            evidence_parts.append(f"\n=== LOCATION HEADER ===\n")
            evidence_parts.append(f"Raw Value: {repr(location)}\n")
            evidence_parts.append(f"Decoded Value: {location}\n")
        
        # Add injection details
        evidence_parts.append(f"\n=== INJECTION DETAILS ===")
        evidence_parts.append(f"\nInjection Type: {injection_type.upper()}")
        evidence_parts.append(f"\nRedirect Parameter: {param}")
        evidence_parts.append(f"\nPayload Sent: {repr(payload)}")
        
        if injection_type == "cookie":
            evidence_parts.append(f"\nInjected Cookie: injected=true")
            evidence_parts.append(f"\nImpact: Attacker can set arbitrary cookies in victim's browser")
        else:
            evidence_parts.append(f"\nCRLF Sequence: {repr(crlf_seq)}")
            evidence_parts.append(f"\nImpact: CRLF characters in redirect may allow header injection")
        
        return ''.join(evidence_parts)


    def _highlight_crlf_in_string(self, text: str, crlf_seq: str = None) -> str:
        """
        Highlight CRLF sequences in a string.
        
        Args:
            text: The string to search
            crlf_seq: Specific CRLF sequence to highlight (optional)
        
        Returns:
            String with CRLF sequences highlighted
        """
        result = text
        
        # Define replacements for visual highlighting
        crlf_markers = [
            ('\r\n', '[CRLF:0x0D0A]'),
            ('\r', '[CR:0x0D]'),
            ('\n', '[LF:0x0A]'),
            ('%0d%0a', '[CRLF:%0d%0a]'),
            ('%0D%0A', '[CRLF:%0D%0A]'),
            ('%0d', '[CR:%0d]'),
            ('%0D', '[CR:%0D]'),
            ('%0a', '[LF:%0a]'),
            ('%0A', '[LF:%0A]'),
        ]
        
        for seq, marker in crlf_markers:
            if seq in result:
                result = result.replace(seq, f" >>>{marker}<<< ")
        
        return result


    def _highlight_payload_in_body(self, body: str, header_payload: str, 
                                    full_payload: str, 
                                    context_chars: int = 200,
                                    max_body_length: int = 2000) -> str:
        """
        Highlight the injected payload in the response body.
        
        Args:
            body: The full response body
            header_payload: The header injection payload to find
            full_payload: The complete payload including CRLF sequence
            context_chars: Number of characters to show around the payload
            max_body_length: Maximum length of body to include in evidence
        
        Returns:
            Formatted evidence string with highlighted payload
        """
        HIGHLIGHT_START = ">>>>> INJECTED PAYLOAD START >>>>>"
        HIGHLIGHT_END = "<<<<< INJECTED PAYLOAD END <<<<<"
        
        # Try to find and highlight the payload in the body
        payloads_to_search = [header_payload, full_payload]
        
        for payload in payloads_to_search:
            if payload in body:
                pos = body.find(payload)
                
                # Calculate context window
                start_pos = max(0, pos - context_chars)
                end_pos = min(len(body), pos + len(payload) + context_chars)
                
                # Extract the relevant portion
                prefix = body[start_pos:pos]
                found_payload = body[pos:pos + len(payload)]
                suffix = body[pos + len(payload):end_pos]
                
                # Build the highlighted evidence
                evidence_parts = []
                evidence_parts.append("=== RESPONSE BODY (with payload highlighted) ===\n")
                
                if start_pos > 0:
                    evidence_parts.append(f"[... {start_pos} chars truncated ...]\n")
                
                evidence_parts.append(prefix)
                evidence_parts.append(f"\n{HIGHLIGHT_START}\n")
                evidence_parts.append(found_payload)
                evidence_parts.append(f"\n{HIGHLIGHT_END}\n")
                evidence_parts.append(suffix)
                
                if end_pos < len(body):
                    evidence_parts.append(f"\n[... {len(body) - end_pos} chars truncated ...]")
                
                evidence_parts.append(f"\n\n=== PAYLOAD DETAILS ===")
                evidence_parts.append(f"\nPayload found at position: {pos}")
                evidence_parts.append(f"\nPayload length: {len(payload)}")
                evidence_parts.append(f"\nTotal response body length: {len(body)}")
                
                return ''.join(evidence_parts)
        
        # If payload not found directly, return truncated body with note
        truncated_body = body[:max_body_length]
        if len(body) > max_body_length:
            truncated_body += f"\n[... {len(body) - max_body_length} chars truncated ...]"
        
        return (
            f"=== RESPONSE BODY ===\n"
            f"{truncated_body}\n\n"
            f"=== NOTE ===\n"
            f"Payload detection triggered but exact payload not found in body.\n"
            f"Expected payload: {repr(header_payload)}"
        )
    
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