# scanner/injection/hhi.py
"""
Host Header Injection Scanner

Detects Host Header Injection vulnerabilities leading to:
- Password reset poisoning
- Cache poisoning
- Server-Side Request Forgery
- Open redirect
- Virtual host routing bypass

OWASP: A03:2021 - Injection
CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class HostHeaderInjectionScanner(BaseScanner):
    """Scanner for Host Header Injection vulnerabilities"""
    
    name="Host Header Injection Scanner",
    description="Detects Host Header Injection vulnerabilities",
    owasp_category=OWASPCategory.A03_INJECTION

    def __init__(self):
        # Evil host values to test
        self.evil_hosts = [
            "evil.com",
            "attacker.com",
            "localhost",
            "127.0.0.1",
            "169.254.169.254",  # AWS metadata
            "internal.server",
        ]
        
        # Password reset endpoints to test
        self.reset_endpoints = [
            "/forgot-password",
            "/password/reset",
            "/reset-password",
            "/api/password/forgot",
            "/api/v1/auth/forgot",
            "/account/forgot",
            "/user/forgot",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for Host Header Injection vulnerabilities.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        original_host = parsed.netloc
        
        # Test basic host header injection
        basic_vuln = await self._test_basic_injection(session, url, original_host)
        if basic_vuln:
            vulnerabilities.append(basic_vuln)
        
        # Test X-Forwarded-Host injection
        xfh_vuln = await self._test_x_forwarded_host(session, url, original_host)
        if xfh_vuln:
            vulnerabilities.append(xfh_vuln)
        
        # Test password reset poisoning
        reset_vulns = await self._test_password_reset_poisoning(
            session, base_url, original_host
        )
        vulnerabilities.extend(reset_vulns)
        
        # Test cache poisoning
        cache_vuln = await self._test_cache_poisoning(session, url, original_host)
        if cache_vuln:
            vulnerabilities.append(cache_vuln)
        
        # Test absolute URL injection
        absolute_vuln = await self._test_absolute_url(session, url, original_host)
        if absolute_vuln:
            vulnerabilities.append(absolute_vuln)
        
        return vulnerabilities
    
    async def _test_basic_injection(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_host: str
    ) -> Optional[Vulnerability]:
        """Test basic Host header injection"""
        evil_host = "evil.com"
        
        # Test techniques
        test_headers = [
            # Direct replacement
            {"Host": evil_host},
            # Double Host header
            {"Host": f"{original_host}\r\nHost: {evil_host}"},
            # Host with port
            {"Host": f"{evil_host}:80"},
            # Absolute URL in Host
            {"Host": f"http://{evil_host}"},
        ]
        
        for headers in test_headers:
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    text = await response.text()
                    
                    # Check if evil host appears in response
                    if evil_host in text:
                        return Vulnerability(
                            vuln_type="Host Header Injection",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="Host Header",
                            payload=str(headers),
                            evidence=f"Evil host '{evil_host}' reflected in response",
                            description="Host header value is reflected in the response",
                            cwe_id="CWE-644",
                            remediation=self._get_remediation()
                        )
                    
                    # Check Location header
                    location = response.headers.get("Location", "")
                    if evil_host in location:
                        return Vulnerability(
                            vuln_type="Host Header Injection - Open Redirect",
                            severity=Severity.HIGH,
                            url=url,
                            parameter="Host Header",
                            payload=str(headers),
                            evidence=f"Redirect to: {location}",
                            description="Host header injection leads to open redirect",
                            cwe_id="CWE-644",
                            remediation=self._get_remediation()
                        )
            
            except Exception:
                continue
        
        return None
    
    async def _test_x_forwarded_host(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_host: str
    ) -> Optional[Vulnerability]:
        """Test X-Forwarded-Host injection"""
        evil_host = "evil.com"
        
        # Various forwarded headers
        forward_headers = [
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
            {"X-Forwarded-Server": evil_host},
            {"X-HTTP-Host-Override": evil_host},
            {"Forwarded": f"host={evil_host}"},
            {"X-Original-URL": f"http://{evil_host}/"},
            {"X-Rewrite-URL": f"http://{evil_host}/"},
        ]
        
        for headers in forward_headers:
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    text = await response.text()
                    
                    if evil_host in text:
                        header_name = list(headers.keys())[0]
                        return Vulnerability(
                            vuln_type=f"Host Header Injection via {header_name}",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=header_name,
                            payload=headers[header_name],
                            evidence=f"Evil host reflected in response",
                            description=f"Application trusts {header_name} header",
                            cwe_id="CWE-644",
                            remediation=self._get_remediation()
                        )
            
            except Exception:
                continue
        
        return None
    
    async def _test_password_reset_poisoning(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        original_host: str
    ) -> List[Vulnerability]:
        """Test password reset poisoning"""
        vulnerabilities = []
        evil_host = "evil.com"
        
        for endpoint in self.reset_endpoints:
            reset_url = urljoin(base_url, endpoint)
            
            try:
                # Check if endpoint exists
                async with session.get(
                    reset_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    if response.status == 404:
                        continue
                
                # Test with evil host
                headers = {"Host": evil_host}
                test_data = {
                    "email": "test@example.com",
                    "username": "testuser",
                }
                
                async with session.post(
                    reset_url,
                    data=test_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    text = await response.text()
                    
                    # Check if evil host is in response or reset link would use it
                    if evil_host in text:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Password Reset Poisoning",
                            severity=Severity.HIGH,
                            url=reset_url,
                            parameter="Host Header",
                            payload=f"Host: {evil_host}",
                            evidence=f"Reset link may contain attacker's host",
                            description="Password reset links can be poisoned via Host header",
                            cwe_id="CWE-644",
                            remediation="Use a hardcoded/configured host for password reset links."
                        ))
                        break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_cache_poisoning(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_host: str
    ) -> Optional[Vulnerability]:
        """Test for cache poisoning via Host header"""
        evil_host = "evil.com"
        
        try:
            # First request with evil host
            headers = {"Host": evil_host}
            
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                first_text = await response.text()
                cache_headers = {
                    k: v for k, v in response.headers.items()
                    if any(c in k.lower() for c in ['cache', 'age', 'x-cache'])
                }
            
            # Second request with normal host
            await asyncio.sleep(0.5)
            
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                second_text = await response.text()
            
            # Check if evil host was cached
            if evil_host in second_text:
                return Vulnerability(
                    vuln_type="Web Cache Poisoning",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="Host Header",
                    payload=f"Host: {evil_host}",
                    evidence="Poisoned response served from cache",
                    description="Web cache can be poisoned via Host header manipulation",
                    cwe_id="CWE-444",
                    remediation="Configure cache to include Host header in cache key. Validate Host header."
                )
            
            # Check for cache-related headers that might indicate caching
            if cache_headers and evil_host in first_text:
                return Vulnerability(
                    vuln_type="Potential Web Cache Poisoning",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="Host Header",
                    payload=f"Host: {evil_host}",
                    evidence=f"Cache headers present: {cache_headers}",
                    description="Response with poisoned Host may be cached",
                    cwe_id="CWE-444",
                    remediation="Review cache configuration and Host header handling."
                )
        
        except Exception:
            pass
        
        return None
    
    async def _test_absolute_url(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_host: str
    ) -> Optional[Vulnerability]:
        """Test absolute URL routing bypass"""
        parsed = urlparse(url)
        path = parsed.path or "/"
        evil_host = "evil.com"
        
        try:
            # Use absolute URL in request line with different Host
            # This tests if the server routes based on absolute URL vs Host header
            async with session.get(
                url,
                headers={
                    "Host": evil_host,
                },
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
                allow_redirects=False
            ) as response:
                # If we get a valid response with evil host
                if response.status == 200:
                    text = await response.text()
                    
                    # Check if application uses the evil host
                    if evil_host in text:
                        return Vulnerability(
                            vuln_type="Host Header Routing Bypass",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="Host Header",
                            payload=f"Absolute URL with Host: {evil_host}",
                            evidence="Server accepts mismatched Host header",
                            description="Server routing may be exploitable via Host header",
                            cwe_id="CWE-644",
                            remediation="Validate that Host header matches expected values."
                        )
        
        except Exception:
            pass
        
        return None
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Validate Host header against a whitelist of allowed hosts
2. Don't trust X-Forwarded-Host or similar headers from untrusted sources
3. Use hardcoded URLs for sensitive operations (password reset, etc.)
4. Configure web server to reject requests with unexpected Host headers
5. If using a reverse proxy, ensure it overwrites Host headers
6. Include Host header in cache keys if using a cache

Example nginx configuration:
    server {
        listen 80;
        server_name example.com www.example.com;
        
        if ($host !~ ^(example\.com|www\.example\.com)$ ) {
            return 444;
        }
    }
"""