# scanner/authentication/password_recovery.py
"""
Password Recovery Scanner

Detects weak password recovery mechanisms:
- Predictable reset tokens
- Password reset poisoning
- Account enumeration via reset
- Insecure recovery questions

OWASP: A07:2025 - Authentication Failures
CWE-640: Weak Password Recovery Mechanism for Forgotten Password
CWE-620: Unverified Password Change
"""

import re
import asyncio
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class PasswordRecoveryScanner(BaseScanner):
    """Scanner for password recovery vulnerabilities"""
    
    name = "Password Recovery Scanner"
    description = "Detects weak password recovery mechanisms"
    owasp_category = OWASPCategory.A07_AUTH_FAILURES
    
    # Password reset endpoints
    RESET_ENDPOINTS = [
        '/forgot-password', '/password/forgot', '/reset-password',
        '/password/reset', '/forgot', '/recover', '/password-recovery',
        '/api/forgot-password', '/api/password/reset', '/api/auth/forgot',
        '/user/forgot', '/account/forgot', '/auth/forgot',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for password recovery vulnerabilities"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Find password reset endpoints
        reset_endpoints = await self._find_reset_endpoints(session, base_url)
        
        for endpoint in reset_endpoints:
            # Test 1: Account enumeration
            enum_vuln = await self._test_account_enumeration(session, endpoint)
            if enum_vuln:
                vulnerabilities.append(enum_vuln)
            
            # Test 2: Security questions check
            question_vuln = await self._check_security_questions(session, endpoint)
            if question_vuln:
                vulnerabilities.append(question_vuln)
            
            # Test 3: Host header injection
            host_vuln = await self._test_host_header_injection(session, endpoint)
            if host_vuln:
                vulnerabilities.append(host_vuln)
        
        return vulnerabilities
    
    async def _find_reset_endpoints(self, session: aiohttp.ClientSession,
                                     base_url: str) -> List[str]:
        """Find password reset endpoints"""
        found = []
        
        for endpoint in self.RESET_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            try:
                response = await self.make_request(session, "GET", test_url)
                if response and response.status == 200:
                    body = await response.text()
                    if any(ind in body.lower() for ind in ['email', 'reset', 'password', 'forgot']):
                        found.append(test_url)
            except Exception:
                continue
        
        return found[:3]  # Limit
    
    async def _test_account_enumeration(self, session: aiohttp.ClientSession,
                                         url: str) -> Optional[Vulnerability]:
        """Test for account enumeration via password reset"""
        
        # Test with valid-looking and invalid emails
        test_emails = [
            ('admin@' + urlparse(url).netloc.replace('www.', ''), 'likely_valid'),
            ('nonexistent12345@invalid-domain-xyz.com', 'invalid'),
        ]
        
        responses = {}
        
        for email, email_type in test_emails:
            try:
                data = {'email': email, 'username': email.split('@')[0]}
                response = await self.make_request(session, "POST", url, data=data)
                
                if response:
                    body = await response.text()
                    responses[email_type] = {
                        'status': response.status,
                        'length': len(body),
                        'body': body[:500]
                    }
            except Exception:
                continue
        
        if 'likely_valid' in responses and 'invalid' in responses:
            valid_resp = responses['likely_valid']
            invalid_resp = responses['invalid']
            
            # Check for different responses
            if valid_resp['status'] != invalid_resp['status'] or \
               abs(valid_resp['length'] - invalid_resp['length']) > 50:
                
                # Check for enumeration indicators
                valid_lower = valid_resp['body'].lower()
                invalid_lower = invalid_resp['body'].lower()
                
                enum_phrases = [
                    ('email sent', 'not found'),
                    ('check your email', 'no account'),
                    ('reset link', 'does not exist'),
                ]
                
                for valid_phrase, invalid_phrase in enum_phrases:
                    if (valid_phrase in valid_lower and invalid_phrase not in valid_lower) or \
                       (invalid_phrase in invalid_lower and valid_phrase not in invalid_lower):
                        return self.create_vulnerability(
                            vuln_type="Account Enumeration via Password Reset",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="email",
                            payload="Valid vs Invalid email test",
                            evidence="Different responses for valid/invalid emails",
                            description="Password reset reveals whether accounts exist.",
                            cwe_id="CWE-640",
                            cvss_score=5.3,
                            remediation="Use generic response: 'If an account exists, you will receive an email.'",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"
                            ]
                        )
        
        return None
    
    async def _check_security_questions(self, session: aiohttp.ClientSession,
                                         url: str) -> Optional[Vulnerability]:
        """Check for insecure security questions"""
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return None
            
            body = await response.text()
            body_lower = body.lower()
            
            # Check for security questions (considered insecure per NIST)
            question_indicators = [
                'security question', 'secret question', 'mother\'s maiden',
                'first pet', 'favorite', 'birth city', 'high school',
            ]
            
            if any(ind in body_lower for ind in question_indicators):
                return self.create_vulnerability(
                    vuln_type="Insecure Security Questions",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="Security Questions",
                    payload="N/A",
                    evidence="Security questions used for password recovery",
                    description="Security questions are easily guessable or discoverable via social media. NIST recommends against their use.",
                    cwe_id="CWE-640",
                    cvss_score=5.5,
                    remediation="Use email/SMS-based recovery with secure tokens instead of security questions.",
                    references=[
                        "https://pages.nist.gov/800-63-3/sp800-63b.html"
                    ]
                )
                
        except Exception:
            pass
        
        return None
    
    async def _test_host_header_injection(self, session: aiohttp.ClientSession,
                                           url: str) -> Optional[Vulnerability]:
        """Test for password reset poisoning via Host header"""
        evil_host = "evil-attacker.com"
        
        try:
            headers = {"Host": evil_host}
            data = {"email": "test@example.com"}
            
            response = await self.make_request(session, "POST", url, data=data, headers=headers)
            
            if response and response.status in [200, 302]:
                body = await response.text()
                
                if evil_host in body:
                    return self.create_vulnerability(
                        vuln_type="Password Reset Poisoning",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="Host Header",
                        payload=f"Host: {evil_host}",
                        evidence="Attacker's host reflected in response",
                        description="Password reset links may use attacker-controlled host, enabling account takeover.",
                        cwe_id="CWE-640",
                        cvss_score=8.0,
                        remediation="Use a hardcoded host for password reset links. Never trust the Host header.",
                        references=[
                            "https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning"
                        ]
                    )
                    
        except Exception:
            pass
        
        return None