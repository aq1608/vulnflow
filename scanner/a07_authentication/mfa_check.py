# scanner/authentication/mfa_check.py
"""
Multi-Factor Authentication Scanner

Detects MFA-related vulnerabilities:
- Missing MFA on critical endpoints
- MFA bypass possibilities
- Weak MFA implementation
- MFA enumeration

OWASP: A07:2025 - Authentication Failures
CWE-308: Use of Single-factor Authentication
CWE-287: Improper Authentication
"""

import re
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class MFAScanner(BaseScanner):
    """Scanner for Multi-Factor Authentication vulnerabilities"""
    
    name = "MFA Check Scanner"
    description = "Detects missing or weak multi-factor authentication"
    owasp_category = OWASPCategory.A07_AUTH_FAILURES
    
    # Endpoints that should have MFA
    CRITICAL_ENDPOINTS = [
        '/admin', '/admin/login', '/administrator',
        '/api/admin', '/management', '/settings/security',
        '/account/security', '/user/security',
        '/payment', '/billing', '/financial',
        '/api/payments', '/api/transfer', '/api/withdraw',
    ]
    
    # MFA-related endpoints
    MFA_ENDPOINTS = [
        '/mfa', '/2fa', '/two-factor', '/totp',
        '/api/mfa', '/api/2fa', '/verify', '/otp',
        '/auth/mfa', '/auth/2fa', '/security/2fa',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for MFA vulnerabilities"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test 1: Check for MFA presence indicators
        mfa_present = await self._check_mfa_presence(session, base_url)
        
        if not mfa_present:
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="No MFA Implementation Detected",
                severity=Severity.MEDIUM,
                url=base_url,
                parameter="Authentication",
                payload="N/A",
                evidence="No MFA endpoints or indicators found",
                description="The application does not appear to implement multi-factor authentication.",
                cwe_id="CWE-308",
                cvss_score=5.5,
                remediation=self._get_mfa_remediation(),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/308.html"
                ]
            ))
        else:
            # Test 2: Check for MFA bypass possibilities
            bypass_vulns = await self._test_mfa_bypass(session, base_url)
            vulnerabilities.extend(bypass_vulns)
            
            # Test 3: Check for weak MFA implementation
            weak_vulns = await self._check_weak_mfa(session, base_url)
            vulnerabilities.extend(weak_vulns)
        
        # Test 4: Check critical endpoints for MFA requirement
        critical_vulns = await self._check_critical_endpoints(session, base_url, mfa_present)
        vulnerabilities.extend(critical_vulns)
        
        return vulnerabilities
    
    async def _check_mfa_presence(self, session: aiohttp.ClientSession,
                                   base_url: str) -> bool:
        """Check if MFA is implemented in the application"""
        
        # Check for MFA endpoints
        for endpoint in self.MFA_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            try:
                response = await self.make_request(session, "GET", test_url)
                if response and response.status in [200, 401, 403]:
                    return True
            except Exception:
                continue
        
        # Check login page for MFA indicators
        login_endpoints = ['/login', '/signin', '/auth/login', '/api/auth/login']
        
        for endpoint in login_endpoints:
            test_url = urljoin(base_url, endpoint)
            try:
                response = await self.make_request(session, "GET", test_url)
                if response and response.status == 200:
                    body = await response.text()
                    body_lower = body.lower()
                    
                    mfa_indicators = [
                        'two-factor', 'two factor', '2fa', 'mfa',
                        'multi-factor', 'multi factor', 'authenticator',
                        'verification code', 'otp', 'one-time password',
                        'google authenticator', 'authy', 'totp',
                        'sms code', 'email code', 'security code',
                    ]
                    
                    if any(ind in body_lower for ind in mfa_indicators):
                        return True
                        
            except Exception:
                continue
        
        # Check settings/security page
        settings_endpoints = ['/settings', '/settings/security', '/account/security', '/profile/security']
        
        for endpoint in settings_endpoints:
            test_url = urljoin(base_url, endpoint)
            try:
                response = await self.make_request(session, "GET", test_url)
                if response and response.status == 200:
                    body = await response.text()
                    
                    if 'two-factor' in body.lower() or '2fa' in body.lower() or 'mfa' in body.lower():
                        return True
                        
            except Exception:
                continue
        
        return False
    
    async def _test_mfa_bypass(self, session: aiohttp.ClientSession,
                                base_url: str) -> List[Vulnerability]:
        """Test for MFA bypass vulnerabilities"""
        vulnerabilities = []
        
        # Find MFA verification endpoint
        mfa_endpoints = []
        for endpoint in self.MFA_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            try:
                response = await self.make_request(session, "GET", test_url)
                if response and response.status in [200, 401, 405]:
                    mfa_endpoints.append(test_url)
            except Exception:
                continue
        
        for mfa_url in mfa_endpoints:
            # Test 1: Empty/null OTP
            bypass_payloads = [
                {'otp': '', 'code': '', 'token': ''},
                {'otp': '000000', 'code': '000000'},
                {'otp': '123456', 'code': '123456'},
                {'otp': 'null', 'code': 'null'},
                {'bypass': 'true', 'skip_mfa': 'true'},
            ]
            
            for payload in bypass_payloads:
                try:
                    response = await self.make_request(session, "POST", mfa_url, data=payload)
                    
                    if response and response.status == 200:
                        body = await response.text()
                        
                        # Check for success indicators
                        success_indicators = ['success', 'verified', 'authenticated', 'dashboard', 'welcome']
                        failure_indicators = ['invalid', 'incorrect', 'wrong', 'failed', 'error']
                        
                        has_success = any(ind in body.lower() for ind in success_indicators)
                        has_failure = any(ind in body.lower() for ind in failure_indicators)
                        
                        if has_success and not has_failure:
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="MFA Bypass Vulnerability",
                                severity=Severity.CRITICAL,
                                url=mfa_url,
                                parameter="OTP/Code",
                                payload=str(payload),
                                evidence="MFA verification bypassed with test payload",
                                description="Multi-factor authentication can be bypassed.",
                                cwe_id="CWE-287",
                                cvss_score=9.8,
                                remediation="Implement proper MFA validation. Never accept empty or predictable codes.",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication"
                                ]
                            ))
                            return vulnerabilities
                            
                except Exception:
                    continue
            
            # Test 2: Direct access bypass (skip MFA page)
            protected_endpoints = ['/dashboard', '/home', '/account', '/admin']
            
            for protected in protected_endpoints:
                try:
                    test_url = urljoin(base_url, protected)
                    response = await self.make_request(session, "GET", test_url)
                    
                    if response and response.status == 200:
                        body = await response.text()
                        
                        # Check if we got to protected content without completing MFA
                        if 'dashboard' in body.lower() or 'welcome' in body.lower():
                            if 'mfa' not in body.lower() and '2fa' not in body.lower():
                                vulnerabilities.append(self.create_vulnerability(
                                    vuln_type="MFA Bypass via Direct Navigation",
                                    severity=Severity.HIGH,
                                    url=test_url,
                                    parameter="URL",
                                    payload=protected,
                                    evidence="Protected page accessible without MFA completion",
                                    description="MFA can be bypassed by directly navigating to protected pages.",
                                    cwe_id="CWE-288",
                                    cvss_score=8.5,
                                    remediation="Enforce MFA verification before allowing access to any protected resource.",
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/288.html"
                                    ]
                                ))
                                return vulnerabilities
                                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _check_weak_mfa(self, session: aiohttp.ClientSession,
                               base_url: str) -> List[Vulnerability]:
        """Check for weak MFA implementation"""
        vulnerabilities = []
        
        # Check settings page for MFA configuration
        settings_pages = ['/settings/security', '/account/security', '/profile/security', '/settings/2fa']
        
        for page in settings_pages:
            try:
                test_url = urljoin(base_url, page)
                response = await self.make_request(session, "GET", test_url)
                
                if response and response.status == 200:
                    body = await response.text()
                    body_lower = body.lower()
                    
                    # Check for SMS-only MFA (weaker than TOTP)
                    has_sms = 'sms' in body_lower and ('verification' in body_lower or '2fa' in body_lower)
                    has_totp = any(t in body_lower for t in ['authenticator', 'totp', 'google auth', 'authy'])
                    
                    if has_sms and not has_totp:
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="SMS-Only MFA",
                            severity=Severity.LOW,
                            url=test_url,
                            parameter="MFA Method",
                            payload="SMS",
                            evidence="Only SMS-based MFA available",
                            description="SMS-based MFA is vulnerable to SIM swapping and SS7 attacks. TOTP-based MFA is recommended.",
                            cwe_id="CWE-308",
                            cvss_score=4.0,
                            remediation="Offer TOTP-based MFA (Google Authenticator, Authy) as an option.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html"
                            ]
                        ))
                    
                    # Check for recovery code exposure
                    if 'recovery code' in body_lower or 'backup code' in body_lower:
                        # Check if codes are displayed in plaintext
                        code_pattern = r'[A-Z0-9]{4,8}[-\s]?[A-Z0-9]{4,8}'
                        if re.search(code_pattern, body):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="MFA Recovery Codes Exposed",
                                severity=Severity.MEDIUM,
                                url=test_url,
                                parameter="Recovery Codes",
                                payload="N/A",
                                evidence="Recovery codes visible on page",
                                description="MFA recovery codes are displayed and could be captured.",
                                cwe_id="CWE-522",
                                cvss_score=5.0,
                                remediation="Only show recovery codes once during setup. Require re-authentication to view.",
                                references=[]
                            ))
                    
                    break
                    
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _check_critical_endpoints(self, session: aiohttp.ClientSession,
                                         base_url: str, mfa_present: bool) -> List[Vulnerability]:
        """Check if critical endpoints enforce MFA"""
        vulnerabilities = []
        
        if not mfa_present:
            # Already reported no MFA
            return vulnerabilities
        
        # This would require authenticated testing, so we check for indicators
        for endpoint in self.CRITICAL_ENDPOINTS[:5]:
            try:
                test_url = urljoin(base_url, endpoint)
                response = await self.make_request(session, "GET", test_url)
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    # Check if this is a sensitive page without MFA requirement
                    is_sensitive = any(s in body.lower() for s in ['admin', 'payment', 'transfer', 'financial'])
                    has_mfa_prompt = any(m in body.lower() for m in ['verify', '2fa', 'mfa', 'authenticator'])
                    
                    if is_sensitive and not has_mfa_prompt:
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Critical Endpoint May Lack MFA",
                            severity=Severity.MEDIUM,
                            url=test_url,
                            parameter="Endpoint",
                            payload=endpoint,
                            evidence="Sensitive endpoint accessible without apparent MFA requirement",
                            description=f"Critical endpoint {endpoint} may not require MFA for access.",
                            cwe_id="CWE-308",
                            cvss_score=5.0,
                            remediation="Require MFA verification for all sensitive operations.",
                            references=[]
                        ))
                        break
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    def _get_mfa_remediation(self) -> str:
        """Get MFA implementation remediation advice"""
        return """
Multi-Factor Authentication Best Practices:

1. **Implement TOTP-Based MFA**
   - Support Google Authenticator, Authy, Microsoft Authenticator
   - Use standard TOTP algorithm (RFC 6238)
   - Generate secure secrets (minimum 160 bits)

2. **Avoid SMS-Only MFA**
   - SMS is vulnerable to SIM swapping
   - Offer SMS as backup only, not primary
   - Prefer app-based TOTP or hardware keys

3. **Support Hardware Security Keys**
   - Implement WebAuthn/FIDO2
   - Support YubiKey and similar devices
   - Most secure MFA option

4. **Secure Recovery Codes**
   - Generate cryptographically random codes
   - Hash stored recovery codes
   - Show codes only once during setup
   - Require re-authentication to regenerate

5. **Implementation Example (Python):**
```python
import pyotp
import secrets

def setup_totp(user):
    # Generate secure secret
    secret = pyotp.random_base32()
    
    # Store hashed secret
    user.totp_secret = hash_secret(secret)
    
    # Generate provisioning URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="YourApp"
    )
    
    return uri, secret

def verify_totp(user, code):
    secret = get_secret(user)
    totp = pyotp.TOTP(secret)
    
    # Allow 1 window tolerance
    return totp.verify(code, valid_window=1)
```
6. **Enforce MFA for:**
   - Admin accounts (mandatory)
   - Financial operations
   - Password changes
   - Security setting changes
   - API key management
"""