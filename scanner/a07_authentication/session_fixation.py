# scanner/authentication/session_fixation.py
"""
Session Fixation Scanner

Detects session fixation vulnerabilities where:
- Session ID is not regenerated after authentication
- Session ID can be set via URL parameter
- Session ID is not properly validated

OWASP: A07:2021 - Identification and Authentication Failures
CWE-384: Session Fixation
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SessionFixationScanner(BaseScanner):
    """Scanner for session fixation vulnerabilities"""
    
    name="Session Fixation Scanner",
    description="Detects session fixation vulnerabilities",
    owasp_category=OWASPCategory.A07_AUTH_FAILURES

    def __init__(self):
        
        # Session cookie/parameter names
        self.session_names = [
            "PHPSESSID",
            "JSESSIONID",
            "ASP.NET_SessionId",
            "CFID",
            "CFTOKEN",
            "session",
            "sessid",
            "sid",
            "sessionid",
            "session_id",
            "connect.sid",
        ]
        
        # Login form indicators
        self.login_indicators = [
            r"<input[^>]*type=['\"]password['\"]",
            r"<input[^>]*name=['\"]password['\"]",
            r"<form[^>]*login",
            r"<form[^>]*signin",
            r"<form[^>]*auth",
        ]
        
        # Login endpoints
        self.login_endpoints = [
            "/login",
            "/signin",
            "/auth",
            "/authenticate",
            "/api/login",
            "/api/auth",
            "/user/login",
            "/account/login",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for session fixation vulnerabilities.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test session ID in URL
        url_vuln = await self._test_session_in_url(session, url)
        if url_vuln:
            vulnerabilities.append(url_vuln)
        
        # Find login page and test session regeneration
        login_url = await self._find_login_page(session, base_url)
        
        if login_url:
            regen_vuln = await self._test_session_regeneration(session, login_url)
            if regen_vuln:
                vulnerabilities.append(regen_vuln)
        
        # Test session acceptance
        accept_vuln = await self._test_session_acceptance(session, url)
        if accept_vuln:
            vulnerabilities.append(accept_vuln)
        
        return vulnerabilities
    
    async def _test_session_in_url(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test if session ID can be set via URL"""
        fake_session = "ATTACKERSESSION12345678901234567890"
        
        for session_name in self.session_names:
            # Test as URL parameter
            test_url = f"{url}?{session_name}={fake_session}"
            
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    # Check if session ID was accepted
                    cookies = response.cookies
                    
                    for cookie in cookies.values():
                        if session_name.lower() in cookie.key.lower():
                            if fake_session in str(cookie.value):
                                return Vulnerability(
                                    vuln_type="Session Fixation via URL",
                                    severity=Severity.HIGH,
                                    url=url,
                                    parameter=session_name,
                                    payload=test_url,
                                    evidence=f"Session ID accepted from URL: {session_name}={fake_session[:20]}...",
                                    description="Application accepts session ID from URL parameter",
                                    cwe_id="CWE-384",
                                    remediation=self._get_remediation()
                                )
                    
                    # Check Set-Cookie header
                    set_cookie = response.headers.get('Set-Cookie', '')
                    if fake_session in set_cookie:
                        return Vulnerability(
                            vuln_type="Session Fixation via URL",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=session_name,
                            payload=test_url,
                            evidence=f"Session accepted: {set_cookie[:100]}...",
                            description="Application accepts arbitrary session ID from URL",
                            cwe_id="CWE-384",
                            remediation=self._get_remediation()
                        )
            
            except Exception:
                continue
        
        return None
    
    async def _find_login_page(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> Optional[str]:
        """Find the login page"""
        for endpoint in self.login_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        
                        # Check for login form indicators
                        for pattern in self.login_indicators:
                            if re.search(pattern, text, re.IGNORECASE):
                                return test_url
            
            except Exception:
                continue
        
        return None
    
    async def _test_session_regeneration(
        self,
        session: aiohttp.ClientSession,
        login_url: str
    ) -> Optional[Vulnerability]:
        """Test if session ID is regenerated after login attempt"""
        try:
            # Create a new session for this test
            jar = aiohttp.CookieJar()
            
            async with aiohttp.ClientSession(cookie_jar=jar) as test_session:
                # First request - get initial session
                async with test_session.get(
                    login_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    initial_cookies = dict(response.cookies)
                
                # Get session ID
                initial_session_id = None
                session_name = None
                
                for name in self.session_names:
                    for cookie_name, cookie_value in initial_cookies.items():
                        if name.lower() in cookie_name.lower():
                            initial_session_id = cookie_value
                            session_name = cookie_name
                            break
                    if initial_session_id:
                        break
                
                if not initial_session_id:
                    # Try to get from jar
                    for cookie in jar:
                        for name in self.session_names:
                            if name.lower() in cookie.key.lower():
                                initial_session_id = cookie.value
                                session_name = cookie.key
                                break
                
                if not initial_session_id:
                    return None
                
                # Attempt login (will likely fail, but that's okay)
                login_data = {
                    "username": "testuser",
                    "password": "testpass",
                    "email": "test@test.com",
                }
                
                async with test_session.post(
                    login_url,
                    data=login_data,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    post_cookies = dict(response.cookies)
                    
                    # Check if session ID changed
                    post_session_id = None
                    
                    for cookie_name, cookie_value in post_cookies.items():
                        if session_name and session_name.lower() in cookie_name.lower():
                            post_session_id = cookie_value
                            break
                    
                    # If no new cookie in response, check the jar
                    if not post_session_id:
                        for cookie in jar:
                            if session_name and session_name.lower() in cookie.key.lower():
                                post_session_id = cookie.value
                                break
                    
                    # Session should have changed
                    if post_session_id and post_session_id == initial_session_id:
                        return Vulnerability(
                            vuln_type="Session Not Regenerated",
                            severity=Severity.MEDIUM,
                            url=login_url,
                            parameter=session_name or "Session",
                            payload="N/A",
                            evidence=f"Session ID unchanged after login attempt: {initial_session_id[:20]}...",
                            description="Session ID not regenerated after authentication attempt",
                            cwe_id="CWE-384",
                            remediation=self._get_remediation()
                        )
        
        except Exception:
            pass
        
        return None
    
    async def _test_session_acceptance(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test if server accepts arbitrary session IDs"""
        fake_session = "FAKEATTACKERSESSION" + "A" * 40
        
        for session_name in self.session_names:
            try:
                # Set fake session cookie
                cookies = {session_name: fake_session}
                
                async with session.get(
                    url,
                    cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    # Check if server accepted our session (didn't issue new one)
                    set_cookie = response.headers.get('Set-Cookie', '')
                    
                    # If no new session cookie issued, server might have accepted ours
                    if session_name.lower() not in set_cookie.lower():
                        # Verify by checking response for session-related content
                        text = await response.text()
                        
                        # Look for signs the session was accepted
                        if fake_session not in text and response.status == 200:
                            # Check if there's any session functionality
                            session_indicators = ['logout', 'signout', 'profile', 'dashboard', 'welcome']
                            
                            for indicator in session_indicators:
                                if indicator in text.lower():
                                    return Vulnerability(
                                        vuln_type="Session Fixation - Arbitrary Session Accepted",
                                        severity=Severity.MEDIUM,
                                        url=url,
                                        parameter=session_name,
                                        payload=fake_session[:30] + "...",
                                        evidence="Server did not reject arbitrary session ID",
                                        description="Application may accept arbitrary session identifiers",
                                        cwe_id="CWE-384",
                                        remediation=self._get_remediation()
                                    )
                                    break
            
            except Exception:
                continue
        
        return None
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Regenerate session ID after successful authentication
2. Regenerate session ID after privilege level change
3. Don't accept session IDs from URL parameters
4. Validate session IDs against expected format
5. Use secure session management frameworks
6. Implement session timeout and idle timeout

Example session regeneration:
- PHP: session_regenerate_id(true)
- Java: request.getSession().invalidate(); request.getSession(true)
- .NET: SessionIDManager.CreateSessionID()
- Python Flask: session.regenerate()
"""