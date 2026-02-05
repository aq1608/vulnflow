# scanner/authentication/session_management.py
"""
Session Management Scanner

Detects session management vulnerabilities:
- Insufficient session expiration
- Session ID in URL
- Weak session ID generation
- Missing session invalidation on logout
- Concurrent session issues

OWASP: A07:2025 - Authentication Failures
CWE-613: Insufficient Session Expiration
CWE-384: Session Fixation
CWE-539: Use of Persistent Cookies Containing Sensitive Information
"""

import asyncio
import re
import time
import hashlib
from typing import List, Dict, Optional, Set
import aiohttp
from urllib.parse import urlparse, parse_qs

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SessionManagementScanner(BaseScanner):
    """Scanner for session management vulnerabilities"""
    
    name = "Session Management Scanner"
    description = "Detects session management and session expiration vulnerabilities"
    owasp_category = OWASPCategory.A07_AUTH_FAILURES
    
    # Session-related cookie/parameter names
    SESSION_NAMES = [
        'phpsessid', 'jsessionid', 'asp.net_sessionid', 'aspsessionid',
        'session', 'sessionid', 'session_id', 'sid', 'sessid',
        'connect.sid', 'express.sid', 'laravel_session',
        'ci_session', 'cfid', 'cftoken',
    ]
    
    # Token cookie names
    TOKEN_NAMES = [
        'token', 'auth_token', 'access_token', 'jwt', 'bearer',
        'refresh_token', 'id_token', 'api_token',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for session management vulnerabilities"""
        vulnerabilities = []
        
        # Test 1: Session ID in URL
        url_vuln = self._check_session_in_url(url, params)
        if url_vuln:
            vulnerabilities.append(url_vuln)
        
        # Test 2: Get and analyze session cookies
        cookie_vulns = await self._analyze_session_cookies(session, url)
        vulnerabilities.extend(cookie_vulns)
        
        # Test 3: Check session ID entropy
        entropy_vuln = await self._check_session_entropy(session, url)
        if entropy_vuln:
            vulnerabilities.append(entropy_vuln)
        
        # Test 4: Check for session timeout indicators
        timeout_vulns = await self._check_session_timeout(session, url)
        vulnerabilities.extend(timeout_vulns)
        
        # Test 5: Check logout functionality
        logout_vuln = await self._check_logout_functionality(session, url)
        if logout_vuln:
            vulnerabilities.append(logout_vuln)
        
        return vulnerabilities
    
    def _check_session_in_url(self, url: str, params: Dict[str, str] = None) -> Optional[Vulnerability]:
        """Check if session ID is exposed in URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Check URL path for session IDs
        path_lower = parsed.path.lower()
        for session_name in self.SESSION_NAMES:
            if session_name in path_lower:
                return self.create_vulnerability(
                    vuln_type="Session ID in URL Path",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="URL Path",
                    payload=parsed.path,
                    evidence=f"Session identifier '{session_name}' found in URL path",
                    description="Session ID is exposed in the URL path, making it vulnerable to shoulder surfing, browser history, referrer headers, and logs.",
                    cwe_id="CWE-598",
                    cvss_score=7.5,
                    remediation="Store session IDs in secure cookies only, never in URLs.",
                    references=[
                        "https://owasp.org/www-community/attacks/Session_fixation"
                    ]
                )
        
        # Check query parameters
        for param_name in query_params.keys():
            if param_name.lower() in self.SESSION_NAMES:
                return self.create_vulnerability(
                    vuln_type="Session ID in URL Query String",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=f"{param_name}={query_params[param_name][0][:20]}...",
                    evidence=f"Session ID exposed in query parameter: {param_name}",
                    description="Session ID in URL query string can be leaked via Referrer headers, browser history, and server logs.",
                    cwe_id="CWE-598",
                    cvss_score=7.5,
                    remediation="Use secure cookies for session management.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/598.html"
                    ]
                )
        
        # Check provided params
        if params:
            for param_name in params.keys():
                if param_name.lower() in self.SESSION_NAMES:
                    return self.create_vulnerability(
                        vuln_type="Session ID in Request Parameters",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=param_name,
                        payload=f"Parameter contains session: {param_name}",
                        evidence="Session identifier passed as request parameter",
                        description="Session ID being passed as a request parameter may indicate insecure session management.",
                        cwe_id="CWE-598",
                        cvss_score=5.5,
                        remediation="Use HTTP-only secure cookies for session tokens.",
                        references=[]
                    )
        
        return None
    
    async def _analyze_session_cookies(self, session: aiohttp.ClientSession,
                                         url: str) -> List[Vulnerability]:
        """Analyze session cookie security attributes"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            cookies = response.headers.getall('Set-Cookie', [])
            parsed_url = urlparse(url)
            is_https = parsed_url.scheme == 'https'
            
            for cookie_str in cookies:
                cookie_lower = cookie_str.lower()
                
                # Check if it's a session cookie
                is_session = any(name in cookie_lower for name in self.SESSION_NAMES + self.TOKEN_NAMES)
                
                if not is_session:
                    continue
                
                # Extract cookie name
                cookie_name = cookie_str.split('=')[0].strip()
                
                # Check expiration (persistent session cookies)
                if 'expires=' in cookie_lower or 'max-age=' in cookie_lower:
                    # Check for very long expiration
                    max_age_match = re.search(r'max-age=(\d+)', cookie_lower)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age > 86400 * 30:  # More than 30 days
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Long-lived Session Cookie",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter=cookie_name,
                                payload=f"max-age={max_age}",
                                evidence=f"Session cookie expires in {max_age // 86400} days",
                                description="Session cookie has very long expiration, increasing session hijacking risk.",
                                cwe_id="CWE-613",
                                cvss_score=5.0,
                                remediation="Limit session cookie lifetime. Use session cookies (no expiration) where possible.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/613.html"
                                ]
                            ))
                
                # Check for missing Secure flag on HTTPS
                if is_https and 'secure' not in cookie_lower:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Session Cookie Missing Secure Flag",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=cookie_name,
                        payload=cookie_str[:100],
                        evidence="Session cookie without Secure flag on HTTPS site",
                        description="Session cookie can be transmitted over HTTP, enabling session hijacking via MITM.",
                        cwe_id="CWE-614",
                        cvss_score=6.5,
                        remediation="Add 'Secure' flag to all session cookies.",
                        references=[
                            "https://owasp.org/www-community/controls/SecureCookieAttribute"
                        ]
                    ))
                
                # Check for missing HttpOnly
                if 'httponly' not in cookie_lower:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Session Cookie Missing HttpOnly Flag",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=cookie_name,
                        payload=cookie_str[:100],
                        evidence="Session cookie accessible via JavaScript",
                        description="Session cookie can be stolen via XSS attacks without HttpOnly flag.",
                        cwe_id="CWE-1004",
                        cvss_score=5.5,
                        remediation="Add 'HttpOnly' flag to session cookies.",
                        references=[
                            "https://owasp.org/www-community/HttpOnly"
                        ]
                    ))
                
                # Check for missing SameSite
                if 'samesite' not in cookie_lower:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Session Cookie Missing SameSite Attribute",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=cookie_name,
                        payload=cookie_str[:100],
                        evidence="Session cookie vulnerable to CSRF",
                        description="Session cookie without SameSite attribute may be vulnerable to CSRF attacks.",
                        cwe_id="CWE-1275",
                        cvss_score=4.5,
                        remediation="Add 'SameSite=Strict' or 'SameSite=Lax' to session cookies.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                        ]
                    ))
                    
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_session_entropy(self, session: aiohttp.ClientSession,
                                      url: str) -> Optional[Vulnerability]:
        """Check session ID randomness/entropy"""
        session_ids: List[str] = []
        
        try:
            # Collect multiple session IDs
            for _ in range(5):
                # Create new session for each request
                jar = aiohttp.CookieJar()
                async with aiohttp.ClientSession(cookie_jar=jar) as new_session:
                    response = await new_session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    )
                    
                    # Extract session cookie
                    for cookie in jar:
                        if any(name in cookie.key.lower() for name in self.SESSION_NAMES):
                            session_ids.append(cookie.value)
                            break
                
                await asyncio.sleep(0.1)
            
            if len(session_ids) < 3:
                return None
            
            # Analyze session IDs
            issues = []
            
            # Check length (should be at least 128 bits = 32 hex chars)
            avg_length = sum(len(sid) for sid in session_ids) / len(session_ids)
            if avg_length < 24:
                issues.append(f"Short session IDs (avg {avg_length:.0f} chars)")
            
            # Check for sequential patterns
            if all(sid.isdigit() for sid in session_ids):
                issues.append("Session IDs are numeric only")
                try:
                    numeric_ids = [int(sid) for sid in session_ids]
                    differences = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
                    if len(set(differences)) == 1:
                        issues.append("Session IDs appear sequential")
                except:
                    pass
            
            # Check for common prefixes (might indicate weak randomness)
            if len(session_ids) >= 3:
                common_prefix = session_ids[0]
                for sid in session_ids[1:]:
                    i = 0
                    while i < len(common_prefix) and i < len(sid) and common_prefix[i] == sid[i]:
                        i += 1
                    common_prefix = common_prefix[:i]
                
                if len(common_prefix) > len(session_ids[0]) * 0.3:
                    issues.append(f"Session IDs share common prefix ({len(common_prefix)} chars)")
            
            if issues:
                return self.create_vulnerability(
                    vuln_type="Weak Session ID Generation",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="Session ID",
                    payload=f"Sample: {session_ids[0][:30]}...",
                    evidence="; ".join(issues),
                    description="Session IDs may be predictable due to weak generation.",
                    cwe_id="CWE-330",
                    cvss_score=6.0,
                    remediation="Use cryptographically secure random number generator for session IDs with at least 128 bits of entropy.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length"
                    ]
                )
                
        except Exception:
            pass
        
        return None
    
    async def _check_session_timeout(self, session: aiohttp.ClientSession,
                                      url: str) -> List[Vulnerability]:
        """Check for session timeout indicators"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            body = await response.text()
            
            # Check for "keep me logged in" / "remember me" without warning
            remember_patterns = [
                r'remember\s*me',
                r'keep\s*me\s*logged\s*in',
                r'stay\s*signed\s*in',
                r'persistent\s*login',
            ]
            
            for pattern in remember_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    # Check if there's a warning about public computers
                    warning_patterns = [
                        r'public\s*computer', r'shared\s*computer',
                        r'not\s*recommended', r'security\s*risk',
                    ]
                    
                    has_warning = any(re.search(wp, body, re.IGNORECASE) for wp in warning_patterns)
                    
                    if not has_warning:
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Remember Me Without Security Warning",
                            severity=Severity.LOW,
                            url=url,
                            parameter="Remember Me",
                            payload="N/A",
                            evidence="'Remember me' option without security warning",
                            description="Persistent login option without warning about shared computers.",
                            cwe_id="CWE-613",
                            cvss_score=3.0,
                            remediation="Add warning about using 'Remember Me' on shared computers.",
                            references=[]
                        ))
                    break
                    
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_logout_functionality(self, session: aiohttp.ClientSession,
                                           url: str) -> Optional[Vulnerability]:
        """Check if logout properly invalidates session"""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Find logout endpoint
            logout_endpoints = [
                '/logout', '/signout', '/sign-out', '/log-out',
                '/api/logout', '/api/auth/logout', '/user/logout',
            ]
            
            response = await self.make_request(session, "GET", url)
            if response:
                body = await response.text()
                
                # Look for logout link in page
                logout_match = re.search(r'href=["\']([^"\']*(?:logout|signout|log-out|sign-out)[^"\']*)["\']', body, re.IGNORECASE)
                if logout_match:
                    logout_endpoints.insert(0, logout_match.group(1))
            
            # Check if any logout endpoint exists and returns a clear response
            for endpoint in logout_endpoints:
                if endpoint.startswith('http'):
                    logout_url = endpoint
                else:
                    logout_url = base_url + (endpoint if endpoint.startswith('/') else '/' + endpoint)
                
                response = await self.make_request(session, "GET", logout_url, allow_redirects=False)
                
                if response and response.status in [200, 302, 303]:
                    # Check if session cookie is being cleared
                    cookies = response.headers.getall('Set-Cookie', [])
                    
                    session_cleared = False
                    for cookie in cookies:
                        cookie_lower = cookie.lower()
                        if any(name in cookie_lower for name in self.SESSION_NAMES):
                            # Check if cookie is being cleared (expires in past or max-age=0)
                            if 'expires=' in cookie_lower or 'max-age=0' in cookie_lower:
                                if '1970' in cookie or 'max-age=0' in cookie_lower:
                                    session_cleared = True
                                    break
                    
                    if response.status == 200 and not session_cleared:
                        # Logout page exists but might not clear session properly
                        return self.create_vulnerability(
                            vuln_type="Potential Incomplete Logout",
                            severity=Severity.LOW,
                            url=logout_url,
                            parameter="Logout",
                            payload="N/A",
                            evidence="Logout endpoint doesn't explicitly clear session cookie",
                            description="Logout may not properly invalidate the session server-side.",
                            cwe_id="CWE-613",
                            cvss_score=4.0,
                            remediation="Ensure logout invalidates server-side session and clears client-side cookies.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                            ]
                        )
                    
                    break  # Found working logout endpoint
                    
        except Exception:
            pass
        
        return None