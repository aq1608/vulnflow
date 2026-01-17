# scanner/authentication/weak_password.py
"""
Weak Password Policy Scanner

Detects weak password policy configurations:
- Short minimum length
- No complexity requirements
- Common password acceptance
- Password in URL/GET parameters
- Password visible in forms

OWASP: A07:2021 - Identification and Authentication Failures
CWE-521: Weak Password Requirements
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class WeakPasswordPolicyScanner(BaseScanner):
    """Scanner for weak password policy detection"""
    
    name="Weak Password Policy Scanner",
    description="Detects weak password policy configurations",
    owasp_category=OWASPCategory.A07_AUTH_FAILURES

    def __init__(self):
        
        # Weak passwords to test
        self.weak_passwords = [
            "123456",
            "password",
            "12345678",
            "qwerty",
            "abc123",
            "111111",
            "123123",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "1234",
            "123",
            "a",
            "",
        ]
        
        # Password form field patterns
        self.password_field_patterns = [
            r'<input[^>]*type=["\']password["\'][^>]*>',
            r'<input[^>]*name=["\'](?:password|passwd|pwd|pass)["\'][^>]*>',
        ]
        
        # Registration/password change endpoints
        self.password_endpoints = [
            "/register",
            "/signup",
            "/create-account",
            "/api/register",
            "/api/signup",
            "/password/change",
            "/change-password",
            "/api/password",
            "/user/create",
            "/account/create",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for weak password policy issues.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check password field configuration
        field_vulns = await self._check_password_fields(session, url)
        vulnerabilities.extend(field_vulns)
        
        # Find registration/password endpoints
        for endpoint in self.password_endpoints:
            endpoint_url = urljoin(base_url, endpoint)
            
            # Check if endpoint exists
            exists = await self._check_endpoint_exists(session, endpoint_url)
            
            if exists:
                # Test weak passwords
                policy_vuln = await self._test_weak_passwords(session, endpoint_url)
                if policy_vuln:
                    vulnerabilities.append(policy_vuln)
                    break
                
                # Check form for password policy hints
                hint_vulns = await self._check_password_hints(session, endpoint_url)
                vulnerabilities.extend(hint_vulns)
        
        # Check for password in URL
        url_vuln = self._check_password_in_url(url, params)
        if url_vuln:
            vulnerabilities.append(url_vuln)
        
        return vulnerabilities
    
    async def _check_password_fields(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check password field configurations"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                html = await response.text()
                
                # Find password fields
                for pattern in self.password_field_patterns:
                    matches = re.finditer(pattern, html, re.IGNORECASE)
                    
                    for match in matches:
                        field_html = match.group()
                        
                        # Check for autocomplete="off" missing on password fields
                        if 'autocomplete=' not in field_html.lower() or \
                           'autocomplete="on"' in field_html.lower() or \
                           'autocomplete="current-password"' not in field_html.lower():
                            # This is actually less of an issue now, but worth noting
                            pass
                        
                        # Check for visible password (type != password)
                        if 'type="text"' in field_html.lower() and \
                           ('password' in field_html.lower() or 'passwd' in field_html.lower()):
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Password Field Not Masked",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter="Password Field",
                                payload="N/A",
                                evidence=field_html[:100],
                                description="Password field is not using type='password'",
                                cwe_id="CWE-549",
                                remediation="Use type='password' for password input fields."
                            ))
                        
                        # Check minlength attribute
                        minlength_match = re.search(r'minlength=["\']?(\d+)', field_html)
                        if minlength_match:
                            minlength = int(minlength_match.group(1))
                            if minlength < 8:
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Weak Password Length Requirement",
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    parameter="Password Field",
                                    payload="N/A",
                                    evidence=f"minlength={minlength}",
                                    description=f"Password minimum length is only {minlength} characters",
                                    cwe_id="CWE-521",
                                    remediation="Require minimum 8-12 character passwords."
                                ))
                        
                        # Check maxlength (too short is bad)
                        maxlength_match = re.search(r'maxlength=["\']?(\d+)', field_html)
                        if maxlength_match:
                            maxlength = int(maxlength_match.group(1))
                            if maxlength < 64:
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Password Length Limited",
                                    severity=Severity.LOW,
                                    url=url,
                                    parameter="Password Field",
                                    payload="N/A",
                                    evidence=f"maxlength={maxlength}",
                                    description=f"Password maximum length is limited to {maxlength} characters",
                                    cwe_id="CWE-521",
                                    remediation="Allow passwords up to at least 64-128 characters."
                                ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_endpoint_exists(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> bool:
        """Check if endpoint exists"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
                allow_redirects=True
            ) as response:
                return response.status != 404
        except:
            return False
    
    async def _test_weak_passwords(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test if weak passwords are accepted"""
        test_username = f"testuser{asyncio.get_event_loop().time()}"[:20]
        test_email = f"test{asyncio.get_event_loop().time()}@test.com"[:30]
        
        for weak_password in self.weak_passwords[:5]:  # Test first 5
            try:
                # Common registration form fields
                data_variants = [
                    {
                        "username": test_username,
                        "email": test_email,
                        "password": weak_password,
                        "password_confirmation": weak_password,
                    },
                    {
                        "user": test_username,
                        "mail": test_email,
                        "pass": weak_password,
                        "pass2": weak_password,
                    },
                    {
                        "name": test_username,
                        "email": test_email,
                        "pwd": weak_password,
                        "pwd_confirm": weak_password,
                    },
                ]
                
                for data in data_variants:
                    async with session.post(
                        url,
                        data=data,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        text = await response.text()
                        
                        # Check if password was accepted (look for success indicators)
                        success_patterns = [
                            r"success",
                            r"account\s+created",
                            r"registered",
                            r"welcome",
                            r"verify\s+your\s+email",
                            r"confirmation\s+sent",
                        ]
                        
                        rejection_patterns = [
                            r"password.*too\s+short",
                            r"password.*weak",
                            r"password.*must\s+contain",
                            r"password.*requirements",
                            r"password.*minimum",
                            r"password.*stronger",
                        ]
                        
                        # Check if weak password was rejected
                        was_rejected = any(
                            re.search(p, text, re.IGNORECASE)
                            for p in rejection_patterns
                        )
                        
                        # Check if it was accepted
                        was_accepted = (
                            response.status in [200, 201, 302] and
                            any(re.search(p, text, re.IGNORECASE) for p in success_patterns)
                        ) or response.status == 201
                        
                        if was_accepted and not was_rejected:
                            return Vulnerability(
                                vuln_type="Weak Password Accepted",
                                severity=Severity.HIGH,
                                url=url,
                                parameter="password",
                                payload=f"Password: '{weak_password}' (length: {len(weak_password)})",
                                evidence="Weak password was accepted by the application",
                                description=f"Application accepts weak password: '{weak_password}'",
                                cwe_id="CWE-521",
                                remediation="Implement strong password policy with minimum length and complexity requirements."
                            )
            
            except Exception:
                continue
        
        return None
    
    async def _check_password_hints(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for password policy hints in the page"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                text = await response.text()
                
                # Look for weak policy indicators
                weak_policy_patterns = [
                    (r"minimum.*4\s*characters", "4 character minimum"),
                    (r"minimum.*5\s*characters", "5 character minimum"),
                    (r"minimum.*6\s*characters", "6 character minimum"),
                    (r"at\s*least\s*4", "4 character minimum"),
                    (r"at\s*least\s*5", "5 character minimum"),
                    (r"at\s*least\s*6", "6 character minimum"),
                    (r"password.*4.*or\s*more", "4 character minimum"),
                ]
                
                for pattern, description in weak_policy_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Weak Password Policy Indicated",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="Password Policy",
                            payload="N/A",
                            evidence=description,
                            description=f"Page indicates weak password policy: {description}",
                            cwe_id="CWE-521",
                            remediation="Require minimum 8-12 character passwords with complexity."
                        ))
                        break
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_password_in_url(
        self,
        url: str,
        params: Dict[str, str] = None
    ) -> Optional[Vulnerability]:
        """Check if password is transmitted in URL"""
        password_params = ['password', 'passwd', 'pwd', 'pass', 'secret']
        
        # Check URL query string
        parsed = urlparse(url)
        query_lower = parsed.query.lower()
        
        for param in password_params:
            if f"{param}=" in query_lower:
                return Vulnerability(
                    vuln_type="Password in URL",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload="Password transmitted via GET",
                    evidence=f"URL contains password parameter: {param}",
                    description="Password is transmitted in URL query string",
                    cwe_id="CWE-598",
                    remediation="Always transmit passwords via POST over HTTPS."
                )
        
        # Check params dict
        if params:
            for param in password_params:
                if param in params or param.lower() in [p.lower() for p in params.keys()]:
                    return Vulnerability(
                        vuln_type="Password in GET Parameters",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload="Password in query parameters",
                        evidence=f"Password transmitted as GET parameter: {param}",
                        description="Password may be logged in server logs and browser history",
                        cwe_id="CWE-598",
                        remediation="Use POST method for password transmission."
                    )
        
        return None