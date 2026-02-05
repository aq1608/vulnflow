# scanner/deserialization/cookie_integrity.py
"""
Cookie Integrity Scanner

Detects cookie integrity and validation issues:
- Unsigned/unencrypted sensitive cookies
- JWT without signature verification
- Session cookies without integrity protection
- Cookie-based security decisions without validation

OWASP: A08:2025 - Software or Data Integrity Failures
CWE-565: Reliance on Cookies without Validation and Integrity Checking
CWE-784: Reliance on Cookies without Validation in a Security Decision
"""

import re
import base64
import json
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CookieIntegrityScanner(BaseScanner):
    """Scanner for cookie integrity vulnerabilities"""
    
    name = "Cookie Integrity Scanner"
    description = "Detects cookies lacking integrity protection"
    owasp_category = OWASPCategory.A08_DATA_INTEGRITY_FAILURES
    
    # Cookies that should have integrity protection
    SENSITIVE_COOKIE_PATTERNS = [
        r'session', r'auth', r'token', r'user', r'admin',
        r'role', r'privilege', r'permission', r'access',
        r'cart', r'order', r'payment', r'price', r'discount',
        r'prefs', r'settings', r'config', r'state',
    ]
    
    # Patterns indicating unprotected data
    PLAINTEXT_PATTERNS = [
        r'^(true|false)$',  # Boolean values
        r'^\d+$',  # Numeric IDs
        r'^[a-zA-Z0-9_]+=[^&]+(&[a-zA-Z0-9_]+=[^&]+)*$',  # Query string format
        r'^{"[^}]+}$',  # Simple JSON
        r'^admin|user|guest|moderator$',  # Role names
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for cookie integrity issues"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            # Get cookies from response
            cookies = response.headers.getall('Set-Cookie', [])
            
            for cookie_str in cookies:
                # Parse cookie
                cookie_parts = cookie_str.split(';')
                if not cookie_parts:
                    continue
                
                name_value = cookie_parts[0].strip()
                if '=' not in name_value:
                    continue
                
                name, value = name_value.split('=', 1)
                name = name.strip()
                value = value.strip()
                
                # Check if sensitive cookie
                is_sensitive = self._is_sensitive_cookie(name)
                
                if is_sensitive and value:
                    # Check for unprotected values
                    integrity_vulns = self._check_cookie_integrity(name, value, url)
                    vulnerabilities.extend(integrity_vulns)
                    
                    # Check for JWT issues
                    jwt_vulns = self._check_jwt_integrity(name, value, url)
                    vulnerabilities.extend(jwt_vulns)
            
            # Check for cookie manipulation opportunities
            manipulation_vulns = await self._test_cookie_manipulation(session, url, response)
            vulnerabilities.extend(manipulation_vulns)
            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_sensitive_cookie(self, name: str) -> bool:
        """Check if cookie name suggests sensitive data"""
        name_lower = name.lower()
        return any(re.search(pattern, name_lower) for pattern in self.SENSITIVE_COOKIE_PATTERNS)
    
    def _check_cookie_integrity(self, name: str, value: str, url: str) -> List[Vulnerability]:
        """Check if cookie value lacks integrity protection"""
        vulnerabilities = []
        
        # Check for plaintext patterns
        for pattern in self.PLAINTEXT_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Unprotected Cookie Value",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=name,
                    payload=value[:50] + ('...' if len(value) > 50 else ''),
                    evidence=f"Cookie '{name}' contains plaintext value matching pattern",
                    description=f"Cookie '{name}' contains unprotected data that could be tampered with.",
                    cwe_id="CWE-565",
                    cvss_score=5.5,
                    remediation=self._get_cookie_remediation(),
                    references=[
                        "https://cwe.mitre.org/data/definitions/565.html"
                    ]
                ))
                break
        
        # Check for base64-encoded but unsigned data
        try:
            decoded = base64.b64decode(value)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            
            # Check if it's just base64-encoded plaintext (no signature)
            if decoded_str and not self._appears_signed(value):
                # Check if it contains structured data
                if '{' in decoded_str or '=' in decoded_str:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Base64 Encoded Cookie Without Signature",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=name,
                        payload=f"Decoded: {decoded_str[:50]}...",
                        evidence=f"Cookie contains base64-encoded data without apparent signature",
                        description=f"Cookie '{name}' is base64-encoded but not signed, allowing tampering.",
                        cwe_id="CWE-565",
                        cvss_score=6.0,
                        remediation=self._get_cookie_remediation(),
                        references=[
                            "https://cwe.mitre.org/data/definitions/565.html"
                        ]
                    ))
        except:
            pass
        
        # Check for serialized data patterns
        if self._looks_like_serialized(value):
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Serialized Data in Cookie",
                severity=Severity.HIGH,
                url=url,
                parameter=name,
                payload=value[:50] + '...',
                evidence="Cookie appears to contain serialized data",
                description=f"Cookie '{name}' may contain serialized data vulnerable to tampering or deserialization attacks.",
                cwe_id="CWE-502",
                cvss_score=7.0,
                remediation="Don't store serialized objects in cookies. Use signed/encrypted server-side sessions.",
                references=[
                    "https://cwe.mitre.org/data/definitions/502.html"
                ]
            ))
        
        return vulnerabilities
    
    def _check_jwt_integrity(self, name: str, value: str, url: str) -> List[Vulnerability]:
        """Check JWT tokens for integrity issues"""
        vulnerabilities = []
        
        # Check if it looks like a JWT
        if not self._is_jwt(value):
            return vulnerabilities
        
        try:
            parts = value.split('.')
            if len(parts) != 3:
                return vulnerabilities
            
            # Decode header
            header_b64 = parts[0]
            # Add padding if needed
            header_b64 += '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ''
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            # Check algorithm
            alg = header.get('alg', '').upper()
            
            if alg == 'NONE':
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="JWT with 'none' Algorithm",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=name,
                    payload="alg: none",
                    evidence="JWT uses 'none' algorithm - no signature verification",
                    description="JWT token uses 'none' algorithm, meaning no signature is required. Anyone can forge tokens.",
                    cwe_id="CWE-347",
                    cvss_score=9.8,
                    remediation="Never accept 'none' algorithm. Always verify signatures with strong algorithms (RS256, ES256).",
                    references=[
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                    ]
                ))
            
            elif alg in ['HS256', 'HS384', 'HS512']:
                # Symmetric algorithm - check for weak key indicators
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="JWT Using Symmetric Algorithm",
                    severity=Severity.LOW,
                    url=url,
                    parameter=name,
                    payload=f"alg: {alg}",
                    evidence=f"JWT uses symmetric signing ({alg})",
                    description=f"JWT uses symmetric algorithm {alg}. Ensure the secret key is strong and securely stored.",
                    cwe_id="CWE-327",
                    cvss_score=3.0,
                    remediation="Consider using asymmetric algorithms (RS256, ES256) for better key management.",
                    references=[]
                ))
            
            # Decode payload to check for sensitive data
            payload_b64 = parts[1]
            payload_b64 += '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ''
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            # Check for sensitive data in payload
            sensitive_fields = ['password', 'secret', 'api_key', 'credit_card', 'ssn']
            for field in sensitive_fields:
                if field in str(payload).lower():
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Sensitive Data in JWT Payload",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=name,
                        payload=f"Contains: {field}",
                        evidence=f"JWT payload contains potentially sensitive field",
                        description="JWT payload contains sensitive data. JWTs are only signed, not encrypted.",
                        cwe_id="CWE-311",
                        cvss_score=5.5,
                        remediation="Don't store sensitive data in JWT payload. Use JWE for encryption if needed.",
                        references=[]
                    ))
                    break
            
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _test_cookie_manipulation(self, session: aiohttp.ClientSession,
                                         url: str, original_response) -> List[Vulnerability]:
        """Test if manipulated cookies are accepted"""
        vulnerabilities = []
        
        # Get original cookies
        original_cookies = {}
        for cookie_str in original_response.headers.getall('Set-Cookie', []):
            parts = cookie_str.split(';')[0].split('=', 1)
            if len(parts) == 2:
                original_cookies[parts[0].strip()] = parts[1].strip()
        
        # Test manipulation of sensitive cookies
        for name, value in original_cookies.items():
            if not self._is_sensitive_cookie(name):
                continue
            
            # Try simple manipulation
            manipulations = [
                (value + 'x', 'append'),
                ('admin', 'replace with admin'),
                ('true', 'replace with true'),
                ('1', 'replace with 1'),
            ]
            
            for manip_value, manip_type in manipulations:
                try:
                    test_cookies = original_cookies.copy()
                    test_cookies[name] = manip_value
                    
                    response = await self.make_request(
                        session, "GET", url,
                        headers={'Cookie': '; '.join(f'{k}={v}' for k, v in test_cookies.items())}
                    )
                    
                    if response and response.status == 200:
                        body = await response.text()
                        
                        # Check for signs that manipulation was accepted
                        if 'admin' in body.lower() and 'admin' not in (await original_response.text()).lower():
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Cookie Manipulation Accepted",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=name,
                                payload=f"Manipulation: {manip_type}",
                                evidence="Manipulated cookie value was accepted",
                                description=f"Cookie '{name}' can be manipulated without detection, potentially allowing privilege escalation.",
                                cwe_id="CWE-784",
                                cvss_score=8.0,
                                remediation="Implement cookie signing (HMAC) or use server-side sessions.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/784.html"
                                ]
                            ))
                            return vulnerabilities
                            
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _appears_signed(self, value: str) -> bool:
        """Check if value appears to have a signature"""
        # Check for common signature patterns
        # HMAC signatures are typically appended with a delimiter
        if '--' in value or '.' in value:
            parts = value.replace('--', '.').split('.')
            if len(parts) >= 2:
                # Last part might be signature (usually longer random string)
                last_part = parts[-1]
                if len(last_part) >= 20 and re.match(r'^[A-Za-z0-9+/=_-]+$', last_part):
                    return True
        return False
    
    def _looks_like_serialized(self, value: str) -> bool:
        """Check if value looks like serialized data"""
        # PHP serialization
        if re.match(r'^[OasidbN]:\d+:', value):
            return True
        
        # Java serialization (base64)
        if value.startswith('rO0AB') or value.startswith('H4sIA'):
            return True
        
        # .NET serialization
        if value.startswith('AAEAAAD'):
            return True
        
        # Python pickle
        if value.startswith('gASV') or value.startswith('KGxw'):
            return True
        
        return False
    
    def _is_jwt(self, value: str) -> bool:
        """Check if value is a JWT"""
        parts = value.split('.')
        if len(parts) != 3:
            return False
        
        try:
            # Try to decode header
            header_b64 = parts[0]
            header_b64 += '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ''
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            return 'alg' in header or 'typ' in header
        except:
            return False
    
    def _get_cookie_remediation(self) -> str:
        """Get cookie integrity remediation"""
        return """
Cookie Integrity Protection:

1. **Use Signed Cookies**
   - Sign cookies with HMAC-SHA256
   - Verify signature before trusting cookie data

   Example (Python Flask):
   ```python
   from itsdangerous import URLSafeSerializer
   
   serializer = URLSafeSerializer(SECRET_KEY)
   
   # Sign
   signed_value = serializer.dumps(data)
   
   # Verify
   try:
       data = serializer.loads(signed_cookie)
   except BadSignature:
       # Cookie was tampered with
    ```
2. Use Server-Side Sessions
    - Store sensitive data server-side
    - Only send session ID to client
3. Encrypt Sensitive Cookies
    - Use authenticated encryption (AES-GCM)
    - Include integrity protection
4. Avoid Storing Sensitive Data in Cookies
    - Minimize cookie data
    - Use opaque session identifiers
"""