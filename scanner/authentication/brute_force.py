# scanner/authentication/brute_force.py
"""
Brute Force Scanner

Detects vulnerabilities to brute force attacks:
- Missing rate limiting on login endpoints
- Missing account lockout mechanisms
- Weak CAPTCHA implementation
- Enumerable usernames

OWASP: A07:2021 - Identification and Authentication Failures
CWE-307: Improper Restriction of Excessive Authentication Attempts
"""

import asyncio
import aiohttp
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class BruteForceScanner(BaseScanner):
    """Scanner for brute force vulnerabilities"""
    name="Brute Force Scanner",
    description="Detects vulnerabilities to brute force attacks",
    owasp_category=OWASPCategory.A07_AUTH_FAILURES
    
    def __init__(self):

        # Common login endpoints
        self.login_endpoints = [
            "/login",
            "/signin",
            "/sign-in",
            "/auth/login",
            "/api/login",
            "/api/auth/login",
            "/api/v1/login",
            "/api/v1/auth/login",
            "/user/login",
            "/users/login",
            "/account/login",
            "/admin/login",
            "/wp-login.php",
            "/administrator",
        ]
        
        # Common username/email field names
        self.username_fields = [
            "username", "user", "email", "login", "user_name",
            "userName", "user_email", "userEmail", "account",
            "userid", "user_id", "userId"
        ]
        
        # Common password field names
        self.password_fields = [
            "password", "pass", "passwd", "pwd", "secret",
            "user_password", "userPassword", "user_pass"
        ]
        
        # Test credentials
        self.test_username = "testuser_nonexistent_12345"
        self.test_password = "wrongpassword123"
        
        # Number of requests to test rate limiting
        self.rate_limit_requests = 10
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for brute force vulnerabilities.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Find login endpoints
        login_urls = await self._find_login_endpoints(session, base_url)
        
        # If no login endpoints found, check if current URL is a login page
        if not login_urls:
            is_login = await self._is_login_page(session, url)
            if is_login:
                login_urls = [url]
        
        # Test each login endpoint
        for login_url in login_urls:
            # Test 1: Rate limiting
            rate_vulns = await self._test_rate_limiting(session, login_url)
            vulnerabilities.extend(rate_vulns)
            
            # Test 2: Account lockout
            lockout_vulns = await self._test_account_lockout(session, login_url)
            vulnerabilities.extend(lockout_vulns)
            
            # Test 3: Username enumeration
            enum_vulns = await self._test_username_enumeration(session, login_url)
            vulnerabilities.extend(enum_vulns)
        
        return vulnerabilities
    
    async def _find_login_endpoints(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[str]:
        """Find login endpoints"""
        found_endpoints = []
        
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
                        content = await response.text()
                        if self._is_login_page_content(content):
                            found_endpoints.append(test_url)
            except:
                continue
        
        return found_endpoints
    
    async def _is_login_page(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> bool:
        """Check if URL is a login page"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    return self._is_login_page_content(content)
        except:
            pass
        return False
    
    def _is_login_page_content(self, content: str) -> bool:
        """Check if content appears to be a login page"""
        content_lower = content.lower()
        
        # Must have password field
        if 'type="password"' not in content_lower and "type='password'" not in content_lower:
            return False
        
        # Should have login-related keywords
        login_keywords = ["login", "sign in", "log in", "signin", "authenticate"]
        return any(keyword in content_lower for keyword in login_keywords)
    
    async def _test_rate_limiting(
        self,
        session: aiohttp.ClientSession,
        login_url: str
    ) -> List[Vulnerability]:
        """Test if rate limiting is implemented"""
        vulnerabilities = []
        
        # Determine login payload format
        payload = await self._get_login_payload(session, login_url)
        if not payload:
            return vulnerabilities
        
        success_count = 0
        start_time = time.time()
        
        # Send multiple rapid requests
        for i in range(self.rate_limit_requests):
            try:
                async with session.post(
                    login_url,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    # Count non-rate-limited responses
                    if response.status not in [429, 503]:
                        success_count += 1
                    else:
                        # Rate limiting detected
                        break
            except:
                continue
        
        elapsed_time = time.time() - start_time
        
        # If all requests succeeded without rate limiting
        if success_count >= self.rate_limit_requests:
            vulnerabilities.append(Vulnerability(
                vuln_type="Brute Force - Missing Rate Limiting",
                severity=Severity.HIGH,
                url=login_url,
                parameter="login endpoint",
                payload=f"{self.rate_limit_requests} requests in {elapsed_time:.2f}s",
                evidence=f"All {success_count} login attempts accepted without rate limiting",
                description="Login endpoint lacks rate limiting, allowing unlimited authentication attempts",
                cwe_id="CWE-307",
                remediation=self._get_rate_limit_remediation()
            ))
        
        return vulnerabilities
    
    async def _test_account_lockout(
        self,
        session: aiohttp.ClientSession,
        login_url: str
    ) -> List[Vulnerability]:
        """Test if account lockout is implemented"""
        vulnerabilities = []
        
        payload = await self._get_login_payload(session, login_url)
        if not payload:
            return vulnerabilities
        
        # Track response patterns
        responses = []
        
        # Send multiple failed login attempts for same "user"
        for i in range(15):  # Typical lockout threshold is 3-10 attempts
            try:
                async with session.post(
                    login_url,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    content = await response.text()
                    responses.append({
                        "status": response.status,
                        "length": len(content),
                        "locked": self._check_lockout_indicators(content)
                    })
            except:
                continue
        
        # Check if account was ever locked
        if responses and not any(r["locked"] for r in responses):
            # Check for consistent responses (no lockout behavior)
            statuses = [r["status"] for r in responses]
            if len(set(statuses)) <= 2:  # Consistent behavior
                vulnerabilities.append(Vulnerability(
                    vuln_type="Brute Force - Missing Account Lockout",
                    severity=Severity.MEDIUM,
                    url=login_url,
                    parameter="login endpoint",
                    payload=f"15 failed attempts for same account",
                    evidence="No account lockout detected after multiple failed attempts",
                    description="Login endpoint does not implement account lockout after failed attempts",
                    cwe_id="CWE-307",
                    remediation=self._get_lockout_remediation()
                ))
        
        return vulnerabilities
    
    def _check_lockout_indicators(self, content: str) -> bool:
        """Check for account lockout indicators in response"""
        lockout_phrases = [
            "account locked",
            "account has been locked",
            "too many attempts",
            "temporarily locked",
            "try again later",
            "exceeded maximum",
            "account disabled",
            "locked out",
            "maximum login attempts",
        ]
        
        content_lower = content.lower()
        return any(phrase in content_lower for phrase in lockout_phrases)
    
    async def _test_username_enumeration(
        self,
        session: aiohttp.ClientSession,
        login_url: str
    ) -> List[Vulnerability]:
        """Test for username enumeration"""
        vulnerabilities = []
        
        payload = await self._get_login_payload(session, login_url)
        if not payload:
            return vulnerabilities
        
        # Test with non-existent user
        invalid_user_response = await self._get_login_response(
            session, login_url, payload
        )
        
        # Test with likely valid username format
        likely_valid_payloads = [
            {**payload, self._get_username_field(payload): "admin"},
            {**payload, self._get_username_field(payload): "administrator"},
            {**payload, self._get_username_field(payload): "test"},
            {**payload, self._get_username_field(payload): "user"},
        ]
        
        for test_payload in likely_valid_payloads:
            valid_user_response = await self._get_login_response(
                session, login_url, test_payload
            )
            
            if valid_user_response and invalid_user_response:
                # Check for different error messages
                if self._responses_differ(invalid_user_response, valid_user_response):
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Brute Force - Username Enumeration",
                        severity=Severity.MEDIUM,
                        url=login_url,
                        parameter="username",
                        payload=f"Tested: {test_payload.get(self._get_username_field(payload), 'unknown')}",
                        evidence="Different responses for valid vs invalid usernames",
                        description="Login page reveals whether username exists through different error messages",
                        cwe_id="CWE-204",
                        remediation=self._get_enumeration_remediation()
                    ))
                    break
        
        return vulnerabilities
    
    async def _get_login_payload(
        self,
        session: aiohttp.ClientSession,
        login_url: str
    ) -> Optional[Dict]:
        """Determine login payload format"""
        try:
            async with session.get(
                login_url,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False
            ) as response:
                content = await response.text()
                
                # Find username field
                username_field = None
                for field in self.username_fields:
                    if f'name="{field}"' in content or f"name='{field}'" in content:
                        username_field = field
                        break
                
                # Find password field
                password_field = None
                for field in self.password_fields:
                    if f'name="{field}"' in content or f"name='{field}'" in content:
                        password_field = field
                        break
                
                if username_field and password_field:
                    return {
                        username_field: self.test_username,
                        password_field: self.test_password
                    }
        except:
            pass
        
        # Default payload
        return {
            "username": self.test_username,
            "password": self.test_password
        }
    
    def _get_username_field(self, payload: Dict) -> str:
        """Get username field from payload"""
        for field in self.username_fields:
            if field in payload:
                return field
        return "username"
    
    async def _get_login_response(
        self,
        session: aiohttp.ClientSession,
        login_url: str,
        payload: Dict
    ) -> Optional[Dict]:
        """Get login response details"""
        try:
            async with session.post(
                login_url,
                data=payload,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False
            ) as response:
                content = await response.text()
                return {
                    "status": response.status,
                    "length": len(content),
                    "content": content[:500]  # First 500 chars for comparison
                }
        except:
            return None
    
    def _responses_differ(self, resp1: Dict, resp2: Dict) -> bool:
        """Check if responses significantly differ"""
        # Different status codes
        if resp1["status"] != resp2["status"]:
            return True
        
        # Significantly different content length
        if abs(resp1["length"] - resp2["length"]) > 50:
            return True
        
        # Check for different error messages
        invalid_user_phrases = ["user not found", "invalid username", "no such user", "username does not exist"]
        invalid_pass_phrases = ["invalid password", "wrong password", "incorrect password"]
        
        content1_lower = resp1["content"].lower()
        content2_lower = resp2["content"].lower()
        
        for phrase in invalid_user_phrases:
            if (phrase in content1_lower) != (phrase in content2_lower):
                return True
        
        for phrase in invalid_pass_phrases:
            if (phrase in content1_lower) != (phrase in content2_lower):
                return True
        
        return False
    
    def _get_rate_limit_remediation(self) -> str:
        """Get rate limiting remediation advice"""
        return """
1. Implement rate limiting on authentication endpoints
2. Use exponential backoff for repeated failures
3. Consider CAPTCHA after several failed attempts
4. Implement IP-based and account-based rate limiting

Example (Node.js with express-rate-limit):
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts, please try again later'
});

app.post('/login', loginLimiter, (req, res) => {
    // Login logic
});
"""

    def _get_lockout_remediation(self) -> str:
        """Get account lockout remediation advice"""
        return """
    Implement account lockout after 5-10 failed attempts
    Use progressive delays between attempts
    Notify users of suspicious login activity
    Provide secure account recovery mechanisms
    Example policy:

    Lock account for 15 minutes after 5 failed attempts

    Extend lockout duration with repeated lockouts

    Send email notification on lockout

    Allow unlock via email verification
    """

    def _get_enumeration_remediation(self) -> str:
        """Get username enumeration remediation advice"""
        return """

        Use generic error messages for all login failures
        Ensure consistent response times for valid and invalid users
        Implement CAPTCHA to prevent automated enumeration
        Example (generic message):

        text
        // Instead of:
        "Username not found" or "Invalid password"

        // Use:
        "Invalid username or password"
        """