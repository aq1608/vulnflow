
# scanner/access_control/open_redirect.py
"""
Open Redirect Scanner

Detects open redirect vulnerabilities:
- URL parameter-based redirects
- Header-based redirects
- JavaScript-based redirects
- Meta refresh redirects

OWASP: A01:2025 - Broken Access Control
CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class OpenRedirectScanner(BaseScanner):
    """Scanner for Open Redirect vulnerabilities"""
    
    name = "Open Redirect Scanner"
    description = "Detects Open Redirect vulnerabilities"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    def __init__(self):
        super().__init__()
        
        # Parameters commonly used for redirects
        self.redirect_params = [
            'url', 'uri', 'redirect', 'redirect_url', 'redirect_uri',
            'return', 'return_url', 'returnUrl', 'return_to', 'returnTo',
            'next', 'next_url', 'nextUrl', 'goto', 'go', 'to',
            'dest', 'destination', 'target', 'link', 'redir',
            'continue', 'continueTo', 'forward', 'forward_url',
            'callback', 'callback_url', 'callbackUrl',
            'success_url', 'successUrl', 'failure_url', 'failureUrl',
            'login_url', 'logout_url', 'signout', 'signin',
            'checkout_url', 'out', 'view', 'path', 'ref',
            'ReturnUrl', 'RedirectUrl', 'TargetUrl',  # ASP.NET style
        ]
        
        # Test payloads - external domains
        self.external_payloads = [
            # Direct external URLs
            ('https://evil.com', 'direct_https'),
            ('http://evil.com', 'direct_http'),
            ('//evil.com', 'protocol_relative'),
            
            # URL encoding bypass
            ('https:%2F%2Fevil.com', 'url_encoded'),
            ('https:%252F%252Fevil.com', 'double_encoded'),
            
            # Backslash tricks (for Windows/IIS)
            ('https:\\\\evil.com', 'backslash'),
            ('//evil.com\\@legitimate.com', 'backslash_at'),
            
            # @ symbol tricks
            ('https://legitimate.com@evil.com', 'at_sign'),
            ('https://evil.com#legitimate.com', 'fragment'),
            ('https://evil.com?legitimate.com', 'query'),
            
            # Null byte (older systems)
            ('https://evil.com%00.legitimate.com', 'null_byte'),
            
            # Tab/newline injection
            ('https://evil.com%09', 'tab'),
            ('https://evil.com%0d%0a', 'crlf'),
            
            # Data URI (potential XSS vector)
            ('data:text/html,<script>alert(1)</script>', 'data_uri'),
            
            # JavaScript pseudo-protocol
            ('javascript:alert(1)', 'javascript'),
            ('javascript://evil.com/%0aalert(1)', 'javascript_bypass'),
            
            # Unicode normalization bypass
            ('https://evil。com', 'unicode_dot'),  # fullwidth dot
            ('https://ⓔⓥⓘⓛ.com', 'unicode_letters'),
            
            # Subdomain tricks
            ('https://legitimate.com.evil.com', 'subdomain_trick'),
            ('https://legitimatecom.evil.com', 'missing_dot'),
        ]
        
        # Endpoints commonly vulnerable to open redirect
        self.vulnerable_endpoints = [
            '/login', '/signin', '/auth', '/authenticate',
            '/logout', '/signout', '/redirect', '/redir',
            '/goto', '/out', '/link', '/url', '/exit',
            '/external', '/leave', '/away', '/jump',
            '/oauth', '/oauth/authorize', '/oauth/callback',
            '/sso', '/saml', '/cas', '/openid',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for open redirect vulnerabilities"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test 1: Check existing parameters for redirect
        if params:
            param_vulns = await self._test_params_for_redirect(session, url, params)
            vulnerabilities.extend(param_vulns)
        
        # Test 2: Check common redirect endpoints
        endpoint_vulns = await self._test_redirect_endpoints(session, base_url)
        vulnerabilities.extend(endpoint_vulns)
        
        # Test 3: Check URL path for redirect parameters
        path_vulns = await self._test_url_path(session, url)
        vulnerabilities.extend(path_vulns)
        
        # Test 4: Check for header-based redirects
        header_vulns = await self._test_header_redirect(session, url)
        vulnerabilities.extend(header_vulns)
        
        return vulnerabilities
    
    async def _test_params_for_redirect(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str]
    ) -> List[Vulnerability]:
        """Test existing parameters for open redirect"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            # Check if parameter name suggests redirect
            if self._is_redirect_param(param_name):
                vuln = await self._test_param_redirect(session, url, params, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_redirect_param(self, param_name: str) -> bool:
        """Check if parameter name suggests redirect functionality"""
        param_lower = param_name.lower()
        return any(rp in param_lower for rp in self.redirect_params)
    
    async def _test_param_redirect(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str],
        param_name: str
    ) -> Optional[Vulnerability]:
        """Test a specific parameter for open redirect"""
        
        for payload, payload_type in self.external_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                response = await self.make_request(
                    session, "GET", url,
                    params=test_params,
                    allow_redirects=False
                )
                
                if not response:
                    continue
                
                # Check for redirect response
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self._is_external_redirect(location, url):
                        return self.create_vulnerability(
                            vuln_type="Open Redirect",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Redirect to external URL: {location}",
                            description=f"The parameter '{param_name}' is vulnerable to open redirect. Attackers can redirect users to malicious sites.",
                            cwe_id="CWE-601",
                            cvss_score=6.1,
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                                "https://cwe.mitre.org/data/definitions/601.html"
                            ]
                        )
                
                # Check for JavaScript-based redirect in response body
                if response.status == 200:
                    body = await response.text()
                    if self._has_js_redirect(body, payload):
                        return self.create_vulnerability(
                            vuln_type="Open Redirect (JavaScript)",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"JavaScript redirect found with user-controlled URL",
                            description=f"The parameter '{param_name}' is used in JavaScript redirect without validation.",
                            cwe_id="CWE-601",
                            cvss_score=5.4,
                            remediation=self._get_remediation()
                        )
                    
                    # Check for meta refresh redirect
                    if self._has_meta_redirect(body, payload):
                        return self.create_vulnerability(
                            vuln_type="Open Redirect (Meta Refresh)",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Meta refresh redirect found with user-controlled URL",
                            description=f"The parameter '{param_name}' is used in meta refresh redirect.",
                            cwe_id="CWE-601",
                            cvss_score=5.4,
                            remediation=self._get_remediation()
                        )
            
            except Exception:
                continue
        
        return None
    
    async def _test_redirect_endpoints(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Test common redirect endpoints"""
        vulnerabilities = []
        
        for endpoint in self.vulnerable_endpoints:
            for param in ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto']:
                for payload, payload_type in self.external_payloads[:5]:  # Test with fewer payloads
                    test_url = f"{base_url}{endpoint}?{param}={quote(payload)}"
                    
                    try:
                        response = await self.make_request(
                            session, "GET", test_url,
                            allow_redirects=False
                        )
                        
                        if not response:
                            continue
                        
                        # Skip if endpoint doesn't exist
                        if response.status == 404:
                            break
                        
                        if response.status in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            
                            if self._is_external_redirect(location, base_url):
                                vulnerabilities.append(self.create_vulnerability(
                                    vuln_type="Open Redirect",
                                    severity=Severity.MEDIUM,
                                    url=test_url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=f"Redirect to: {location}",
                                    description=f"Endpoint {endpoint} is vulnerable to open redirect via '{param}' parameter.",
                                    cwe_id="CWE-601",
                                    cvss_score=6.1,
                                    remediation=self._get_remediation()
                                ))
                                break  # Found vuln for this endpoint
                    
                    except Exception:
                        continue
        
        return vulnerabilities
    
    async def _test_url_path(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for redirect parameters in URL path"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Check existing query parameters
        for param_name, values in query_params.items():
            if self._is_redirect_param(param_name):
                for value in values:
                    if self._looks_like_url(value):
                        # This parameter might be a redirect target
                        test_params = {param_name: 'https://evil.com'}
                        
                        try:
                            response = await self.make_request(
                                session, "GET",
                                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                params=test_params,
                                allow_redirects=False
                            )
                            
                            if response and response.status in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if 'evil.com' in location:
                                    vulnerabilities.append(self.create_vulnerability(
                                        vuln_type="Open Redirect",
                                        severity=Severity.MEDIUM,
                                        url=url,
                                        parameter=param_name,
                                        payload='https://evil.com',
                                        evidence=f"Redirect to: {location}",
                                        description=f"URL parameter '{param_name}' vulnerable to open redirect.",
                                        cwe_id="CWE-601",
                                        cvss_score=6.1,
                                        remediation=self._get_remediation()
                                    ))
                        
                        except Exception:
                            pass
        
        return vulnerabilities
    
    async def _test_header_redirect(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for header-based redirect vulnerabilities"""
        vulnerabilities = []
        
        # Headers that might influence redirects
        redirect_headers = [
            ('X-Forwarded-Host', 'evil.com'),
            ('X-Original-URL', 'https://evil.com'),
            ('X-Rewrite-URL', 'https://evil.com'),
            ('Host', 'evil.com'),
        ]
        
        for header_name, header_value in redirect_headers:
            try:
                headers = {header_name: header_value}
                
                response = await self.make_request(
                    session, "GET", url,
                    headers=headers,
                    allow_redirects=False
                )
                
                if not response:
                    continue
                
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if 'evil.com' in location.lower():
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Open Redirect (Header-Based)",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=header_name,
                            payload=f"{header_name}: {header_value}",
                            evidence=f"Header injection caused redirect to: {location}",
                            description=f"The {header_name} header can be used to control redirect destination.",
                            cwe_id="CWE-601",
                            cvss_score=7.4,
                            remediation=self._get_remediation()
                        ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_external_redirect(self, location: str, original_url: str) -> bool:
        """Check if redirect location is external"""
        if not location:
            return False
        
        original_parsed = urlparse(original_url)
        original_domain = original_parsed.netloc.lower()
        
        # Handle protocol-relative URLs
        if location.startswith('//'):
            location = 'https:' + location
        
        # Handle relative URLs
        if not location.startswith(('http://', 'https://', '//')):
            return False
        
        try:
            location_parsed = urlparse(location)
            location_domain = location_parsed.netloc.lower()
            
            # Check for evil.com or similar test domains
            test_domains = ['evil.com', 'attacker.com', 'malicious.com']
            if any(d in location_domain for d in test_domains):
                return True
            
            # Check if domain is different (excluding subdomains)
            original_base = '.'.join(original_domain.split('.')[-2:])
            location_base = '.'.join(location_domain.split('.')[-2:])
            
            return original_base != location_base
        
        except Exception:
            return False
    
    def _has_js_redirect(self, body: str, payload: str) -> bool:
        """Check for JavaScript redirect with payload"""
        payload_escaped = re.escape(payload)
        
        # Common JavaScript redirect patterns
        patterns = [
            rf'window\.location\s*=\s*["\']?{payload_escaped}',
            rf'location\.href\s*=\s*["\']?{payload_escaped}',
            rf'location\.replace\s*\(\s*["\']?{payload_escaped}',
            rf'location\.assign\s*\(\s*["\']?{payload_escaped}',
            rf'window\.navigate\s*\(\s*["\']?{payload_escaped}',
        ]
        
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        
        return False
    
    def _has_meta_redirect(self, body: str, payload: str) -> bool:
        """Check for meta refresh redirect with payload"""
        # Meta refresh pattern: <meta http-equiv="refresh" content="0;url=...">
        meta_pattern = rf'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*{re.escape(payload)}'
        
        return bool(re.search(meta_pattern, body, re.IGNORECASE))
    
    def _looks_like_url(self, value: str) -> bool:
        """Check if value looks like a URL"""
        return bool(re.match(r'^(https?://|//|/)', value, re.IGNORECASE))
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Use a whitelist of allowed redirect destinations
2. Validate redirect URLs against your domain
3. For internal redirects, use relative paths only
4. If external redirects are needed, use an intermediate warning page
5. Never redirect based on user input without validation

Example (Python):
```python
from urllib.parse import urlparse

ALLOWED_HOSTS = ['example.com', 'www.example.com']

def safe_redirect(url):
    parsed = urlparse(url)
    
    # Allow relative URLs
    if not parsed.netloc:
        return url
    
    # Check against whitelist
    if parsed.netloc in ALLOWED_HOSTS:
        return url
    
    # Reject external URLs
    return '/default-page'
```
Example (JavaScript):

```javascript
function safeRedirect(url) {
    try {
        const parsed = new URL(url, window.location.origin);
        if (parsed.origin === window.location.origin) {
            return url;
        }
    } catch (e) {}
    return '/default-page';
}
```
"""
