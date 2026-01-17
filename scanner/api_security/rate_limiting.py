# scanner/api_security/rate_limiting.py
"""
Rate Limiting Scanner

Detects missing or weak rate limiting on:
- Authentication endpoints
- API endpoints
- Password reset
- User registration

OWASP API Security: API4:2019 - Lack of Resources & Rate Limiting
"""

import asyncio
import aiohttp
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class RateLimitingScanner(BaseScanner):
    """Scanner for rate limiting vulnerabilities"""
    
    name="Rate Limiting Scanner",
    description="Detects missing or weak rate limiting",
    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION

    def __init__(self):
        # Endpoints to test for rate limiting
        self.sensitive_endpoints = {
            "login": ["/login", "/api/login", "/auth/login", "/api/v1/auth/login", "/signin", "/api/signin"],
            "register": ["/register", "/api/register", "/signup", "/api/signup", "/api/v1/users"],
            "password_reset": ["/forgot-password", "/reset-password", "/api/password/reset", "/api/forgot"],
            "otp": ["/verify-otp", "/api/otp", "/api/verify", "/2fa/verify"],
            "api": ["/api/users", "/api/v1/users", "/api/data", "/api/search"],
        }
        
        # Rate limit headers to check
        self.rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "RateLimit-Reset",
            "Retry-After",
            "X-Rate-Limit-Limit",
        ]
        
        # Number of requests to test
        self.test_request_count = 50
        self.burst_request_count = 20
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for rate limiting issues"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test each category of endpoints
        for category, endpoints in self.sensitive_endpoints.items():
            for endpoint in endpoints:
                test_url = urljoin(base_url, endpoint)
                
                # Check if endpoint exists
                exists = await self._check_endpoint_exists(session, test_url)
                if not exists:
                    continue
                
                # Test rate limiting
                vuln = await self._test_rate_limiting(session, test_url, category)
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Found issue in this category, move to next
        
        # Test the main URL
        main_vuln = await self._test_rate_limiting(session, url, "main")
        if main_vuln:
            vulnerabilities.append(main_vuln)
        
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
                allow_redirects=False
            ) as response:
                # Endpoint exists if not 404
                return response.status != 404
        except:
            return False
    
    async def _test_rate_limiting(
        self,
        session: aiohttp.ClientSession,
        url: str,
        category: str
    ) -> Optional[Vulnerability]:
        """Test rate limiting on an endpoint"""
        
        # First, check for rate limit headers
        has_headers = await self._check_rate_limit_headers(session, url)
        
        # Send burst of requests
        results = await self._send_burst_requests(session, url, self.burst_request_count)
        
        # Analyze results
        success_count = sum(1 for r in results if r["status"] < 400)
        rate_limited_count = sum(1 for r in results if r["status"] == 429)
        
        # Calculate severity based on category
        severity_map = {
            "login": Severity.HIGH,
            "password_reset": Severity.HIGH,
            "otp": Severity.CRITICAL,
            "register": Severity.MEDIUM,
            "api": Severity.MEDIUM,
            "main": Severity.LOW,
        }
        
        severity = severity_map.get(category, Severity.MEDIUM)
        
        # No rate limiting detected
        if rate_limited_count == 0 and success_count >= self.burst_request_count * 0.9:
            description_map = {
                "login": "Login endpoint lacks rate limiting, enabling brute force attacks",
                "password_reset": "Password reset lacks rate limiting, enabling account enumeration",
                "otp": "OTP verification lacks rate limiting, enabling OTP bypass",
                "register": "Registration lacks rate limiting, enabling mass account creation",
                "api": "API endpoint lacks rate limiting, enabling abuse",
                "main": "Endpoint lacks rate limiting",
            }
            
            return Vulnerability(
                vuln_type="Missing Rate Limiting",
                severity=severity,
                url=url,
                parameter="N/A",
                payload=f"Sent {self.burst_request_count} requests in burst",
                evidence=f"{success_count}/{self.burst_request_count} requests succeeded without throttling",
                description=description_map.get(category, "Endpoint lacks rate limiting"),
                cwe_id="CWE-770",
                remediation=self._get_remediation(category)
            )
        
        # Weak rate limiting (too high threshold)
        if rate_limited_count > 0 and success_count > 30:
            return Vulnerability(
                vuln_type="Weak Rate Limiting",
                severity=Severity.LOW if severity == Severity.LOW else Severity.MEDIUM,
                url=url,
                parameter="N/A",
                payload=f"Sent {self.burst_request_count} requests",
                evidence=f"{success_count} requests succeeded before rate limiting",
                description=f"Rate limiting threshold too high ({success_count} requests allowed)",
                cwe_id="CWE-770",
                remediation="Lower rate limiting thresholds for sensitive endpoints."
            )
        
        # Check if rate limit headers are missing even if limiting exists
        if not has_headers and rate_limited_count > 0:
            return Vulnerability(
                vuln_type="Missing Rate Limit Headers",
                severity=Severity.INFO,
                url=url,
                parameter="N/A",
                payload="N/A",
                evidence="Rate limiting exists but headers are not provided",
                description="Rate limit headers missing, making it difficult for clients to handle limits gracefully",
                cwe_id="CWE-200",
                remediation="Add X-RateLimit-* headers to inform clients of rate limits."
            )
        
        return None
    
    async def _check_rate_limit_headers(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> bool:
        """Check for rate limit headers"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False
            ) as response:
                for header in self.rate_limit_headers:
                    if header.lower() in [h.lower() for h in response.headers.keys()]:
                        return True
        except:
            pass
        
        return False
    
    async def _send_burst_requests(
        self,
        session: aiohttp.ClientSession,
        url: str,
        count: int
    ) -> List[Dict]:
        """Send burst of requests and collect results"""
        results = []
        
        async def send_request(index: int):
            start_time = time.time()
            try:
                # Alternate between GET and POST
                if index % 2 == 0:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        return {
                            "index": index,
                            "status": response.status,
                            "duration": time.time() - start_time
                        }
                else:
                    async with session.post(
                        url,
                        json={"test": "test"},
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        return {
                            "index": index,
                            "status": response.status,
                            "duration": time.time() - start_time
                        }
            except Exception as e:
                return {
                    "index": index,
                    "status": 0,
                    "duration": time.time() - start_time,
                    "error": str(e)
                }
        
        # Send requests concurrently
        tasks = [send_request(i) for i in range(count)]
        results = await asyncio.gather(*tasks)
        
        return results
    
    def _get_remediation(self, category: str) -> str:
        """Get remediation advice based on category"""
        remediations = {
            "login": """
1. Implement rate limiting: 5-10 attempts per minute per IP/user
2. Add progressive delays after failed attempts
3. Implement account lockout after repeated failures
4. Use CAPTCHA after 3-5 failed attempts
5. Monitor and alert on brute force patterns
""",
            "password_reset": """
1. Rate limit: 3-5 requests per hour per email/IP
2. Use unique, time-limited tokens
3. Don't reveal if email exists in error messages
4. Log all password reset attempts
""",
            "otp": """
1. Strict rate limiting: 3-5 attempts per OTP
2. Expire OTP after few failed attempts
3. Progressive lockout for repeated failures
4. Use time-based OTPs (TOTP) with limited validity
""",
            "register": """
1. Rate limit: 2-5 registrations per IP per hour
2. Implement CAPTCHA
3. Require email verification
4. Monitor for bulk registration patterns
""",
            "api": """
1. Implement token bucket or sliding window rate limiting
2. Return rate limit headers (X-RateLimit-*)
3. Use HTTP 429 status code with Retry-After header
4. Consider different limits for authenticated vs anonymous users
""",
        }
        
        return remediations.get(category, """
Implement rate limiting using:
1. Token bucket algorithm
2. Sliding window counters
3. Fixed window counters
Use libraries like express-rate-limit, Flask-Limiter, or API gateway rate limiting.
""")