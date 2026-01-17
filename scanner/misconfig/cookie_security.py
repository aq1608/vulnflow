# scanner/misconfig/cookie_security.py
"""
Cookie Security Scanner

Detects insecure cookie configurations:
- Missing Secure flag
- Missing HttpOnly flag
- Missing/weak SameSite attribute
- Sensitive data in cookies
- Cookie scope issues

OWASP: A05:2021 - Security Misconfiguration
CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse
from http.cookies import SimpleCookie

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CookieSecurityScanner(BaseScanner):
    """Scanner for cookie security issues"""

    name="Cookie Security Scanner",
    description="Detects insecure cookie configurations",
    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    def __init__(self):
        
        # Session cookie name patterns
        self.session_cookie_patterns = [
            r"session",
            r"sess",
            r"sid",
            r"ssid",
            r"phpsessid",
            r"jsessionid",
            r"asp\.net_sessionid",
            r"aspsessionid",
            r"cfid",
            r"cftoken",
            r"auth",
            r"token",
            r"jwt",
            r"access_token",
            r"refresh_token",
            r"remember",
            r"login",
            r"user",
            r"laravel_session",
            r"_session",
            r"connect\.sid",
        ]
        
        # Sensitive data patterns in cookie values
        self.sensitive_patterns = [
            (r"password", "password"),
            (r"passwd", "password"),
            (r"pwd", "password"),
            (r"secret", "secret"),
            (r"api_key", "API key"),
            (r"apikey", "API key"),
            (r"private", "private data"),
            (r"credit", "credit card"),
            (r"ssn", "SSN"),
            (r"email=", "email"),
            (r"@.*\.", "email address"),
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for cookie security issues.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"
        
        try:
            # Make request to get cookies
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False,
                allow_redirects=True
            ) as response:
                # Get Set-Cookie headers
                set_cookie_headers = response.headers.getall('Set-Cookie', [])
# scanner/misconfig/cookie_security.py (continued)

                for cookie_header in set_cookie_headers:
                    cookie_vulns = self._analyze_cookie(
                        cookie_header, url, is_https
                    )
                    vulnerabilities.extend(cookie_vulns)
                
                # Also check cookies from jar
                for cookie in session.cookie_jar:
                    jar_vulns = self._analyze_cookie_from_jar(
                        cookie, url, is_https
                    )
                    vulnerabilities.extend(jar_vulns)
        
        except Exception as e:
            pass
        
        # Deduplicate vulnerabilities
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln.vuln_type, vuln.parameter)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _analyze_cookie(
        self,
        cookie_header: str,
        url: str,
        is_https: bool
    ) -> List[Vulnerability]:
        """Analyze a Set-Cookie header for security issues"""
        vulnerabilities = []
        
        # Parse cookie
        parts = cookie_header.split(';')
        if not parts:
            return vulnerabilities
        
        # Get cookie name and value
        name_value = parts[0].strip()
        if '=' not in name_value:
            return vulnerabilities
        
        cookie_name, cookie_value = name_value.split('=', 1)
        cookie_name = cookie_name.strip()
        cookie_value = cookie_value.strip()
        
        # Parse attributes
        attributes = {}
        for part in parts[1:]:
            part = part.strip().lower()
            if '=' in part:
                attr_name, attr_value = part.split('=', 1)
                attributes[attr_name.strip()] = attr_value.strip()
            else:
                attributes[part] = True
        
        # Check if it's a session/auth cookie
        is_session_cookie = self._is_session_cookie(cookie_name)
        
        # Check Secure flag
        if is_https and 'secure' not in attributes:
            severity = Severity.HIGH if is_session_cookie else Severity.MEDIUM
            vulnerabilities.append(Vulnerability(
                vuln_type="Cookie Missing Secure Flag",
                severity=severity,
                url=url,
                parameter=cookie_name,
                payload="N/A",
                evidence=f"Set-Cookie: {cookie_header[:100]}...",
                description=f"Cookie '{cookie_name}' is missing the Secure flag on HTTPS",
                cwe_id="CWE-614",
                remediation="Add 'Secure' flag to prevent cookie transmission over HTTP."
            ))
        
        # Check HttpOnly flag
        if 'httponly' not in attributes:
            severity = Severity.HIGH if is_session_cookie else Severity.LOW
            vulnerabilities.append(Vulnerability(
                vuln_type="Cookie Missing HttpOnly Flag",
                severity=severity,
                url=url,
                parameter=cookie_name,
                payload="N/A",
                evidence=f"Set-Cookie: {cookie_header[:100]}...",
                description=f"Cookie '{cookie_name}' is missing HttpOnly flag",
                cwe_id="CWE-1004",
                remediation="Add 'HttpOnly' flag to prevent JavaScript access to cookie."
            ))
        
        # Check SameSite attribute
        samesite = attributes.get('samesite', None)
        if samesite is None:
            severity = Severity.MEDIUM if is_session_cookie else Severity.LOW
            vulnerabilities.append(Vulnerability(
                vuln_type="Cookie Missing SameSite Attribute",
                severity=severity,
                url=url,
                parameter=cookie_name,
                payload="N/A",
                evidence=f"Set-Cookie: {cookie_header[:100]}...",
                description=f"Cookie '{cookie_name}' is missing SameSite attribute",
                cwe_id="CWE-1275",
                remediation="Add 'SameSite=Strict' or 'SameSite=Lax' to prevent CSRF."
            ))
        elif samesite == 'none' and 'secure' not in attributes:
            vulnerabilities.append(Vulnerability(
                vuln_type="Cookie SameSite=None Without Secure",
                severity=Severity.MEDIUM,
                url=url,
                parameter=cookie_name,
                payload="N/A",
                evidence=f"SameSite=None without Secure flag",
                description="SameSite=None requires Secure flag in modern browsers",
                cwe_id="CWE-1275",
                remediation="Add 'Secure' flag when using 'SameSite=None'."
            ))
        
        # Check for sensitive data in cookie value
        sensitive_vuln = self._check_sensitive_data(
            cookie_name, cookie_value, url
        )
        if sensitive_vuln:
            vulnerabilities.append(sensitive_vuln)
        
        # Check cookie scope (overly broad domain/path)
        scope_vuln = self._check_cookie_scope(
            cookie_name, attributes, url
        )
        if scope_vuln:
            vulnerabilities.append(scope_vuln)
        
        # Check for weak/predictable session ID
        if is_session_cookie:
            weak_vuln = self._check_weak_session_id(
                cookie_name, cookie_value, url
            )
            if weak_vuln:
                vulnerabilities.append(weak_vuln)
        
        return vulnerabilities
    
    def _analyze_cookie_from_jar(
        self,
        cookie,
        url: str,
        is_https: bool
    ) -> List[Vulnerability]:
        """Analyze cookie from aiohttp cookie jar"""
        vulnerabilities = []
        
        cookie_name = cookie.key
        cookie_value = cookie.value
        
        is_session_cookie = self._is_session_cookie(cookie_name)
        
        # Check Secure flag (cookie['secure'] is the attribute)
        if is_https and not cookie.get('secure'):
            severity = Severity.HIGH if is_session_cookie else Severity.MEDIUM
            vulnerabilities.append(Vulnerability(
                vuln_type="Cookie Missing Secure Flag",
                severity=severity,
                url=url,
                parameter=cookie_name,
                payload="N/A",
                evidence=f"Cookie: {cookie_name}",
                description=f"Cookie '{cookie_name}' missing Secure flag",
                cwe_id="CWE-614",
                remediation="Add 'Secure' flag to cookie."
            ))
        
        return vulnerabilities
    
    def _is_session_cookie(self, cookie_name: str) -> bool:
        """Check if cookie appears to be a session cookie"""
        cookie_lower = cookie_name.lower()
        
        for pattern in self.session_cookie_patterns:
            if re.search(pattern, cookie_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _check_sensitive_data(
        self,
        cookie_name: str,
        cookie_value: str,
        url: str
    ) -> Optional[Vulnerability]:
        """Check for sensitive data in cookie"""
        combined = f"{cookie_name}={cookie_value}".lower()
        
        for pattern, data_type in self.sensitive_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return Vulnerability(
                    vuln_type="Sensitive Data in Cookie",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=cookie_name,
                    payload="N/A",
                    evidence=f"Cookie appears to contain {data_type}",
                    description=f"Cookie may contain sensitive data ({data_type})",
                    cwe_id="CWE-315",
                    remediation="Don't store sensitive data in cookies. Use server-side sessions."
                )
        
        return None
    
    def _check_cookie_scope(
        self,
        cookie_name: str,
        attributes: Dict,
        url: str
    ) -> Optional[Vulnerability]:
        """Check for overly broad cookie scope"""
        parsed = urlparse(url)
        
        # Check domain scope
        domain = attributes.get('domain', '')
        if domain:
            # Domain starting with dot is overly broad
            if domain.startswith('.') and domain.count('.') <= 1:
                return Vulnerability(
                    vuln_type="Cookie Domain Too Broad",
                    severity=Severity.LOW,
                    url=url,
                    parameter=cookie_name,
                    payload="N/A",
                    evidence=f"Domain: {domain}",
                    description=f"Cookie domain '{domain}' is overly permissive",
                    cwe_id="CWE-1004",
                    remediation="Restrict cookie domain to specific subdomain."
                )
        
        # Check path scope
        path = attributes.get('path', '')
        if path == '/':
            # Path=/ is very common but worth noting for session cookies
            pass  # Could add informational finding
        
        return None
    
    def _check_weak_session_id(
        self,
        cookie_name: str,
        cookie_value: str,
        url: str
    ) -> Optional[Vulnerability]:
        """Check for weak/predictable session IDs"""
        if not cookie_value:
            return None
        
        # Check length (should be at least 128 bits = 32 hex chars)
        if len(cookie_value) < 20:
            return Vulnerability(
                vuln_type="Weak Session ID",
                severity=Severity.MEDIUM,
                url=url,
                parameter=cookie_name,
                payload="N/A",
                evidence=f"Session ID length: {len(cookie_value)} chars",
                description="Session ID appears to be too short for security",
                cwe_id="CWE-330",
                remediation="Use cryptographically random session IDs of at least 128 bits."
            )
        
        # Check for sequential/predictable patterns
        if cookie_value.isdigit():
            return Vulnerability(
                vuln_type="Predictable Session ID",
                severity=Severity.HIGH,
                url=url,
                parameter=cookie_name,
                payload="N/A",
                evidence=f"Session ID is numeric only: {cookie_value[:20]}...",
                description="Session ID appears to be sequential/predictable",
                cwe_id="CWE-330",
                remediation="Use cryptographically random session IDs."
            )
        
        return None