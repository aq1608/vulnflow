# scanner/authentication/auth_bypass.py
"""
Authentication Bypass Scanner

Detects authentication bypass vulnerabilities:
- Missing authentication on critical endpoints
- Authentication bypass via parameter manipulation
- Alternate path/channel authentication bypass
- Direct object reference to bypass auth

OWASP: A07:2025 - Authentication Failures
CWE-287: Improper Authentication
CWE-288: Authentication Bypass Using an Alternate Path or Channel
CWE-302: Authentication Bypass by Assumed-Immutable Data
CWE-306: Missing Authentication for Critical Function
"""

import re
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class AuthBypassScanner(BaseScanner):
    """Scanner for authentication bypass vulnerabilities"""
    
    name = "Authentication Bypass Scanner"
    description = "Detects authentication bypass and missing authentication vulnerabilities"
    owasp_category = OWASPCategory.A07_AUTH_FAILURES
    
    # Critical endpoints that should require authentication
    CRITICAL_ENDPOINTS = [
        # Admin endpoints
        '/admin', '/admin/', '/administrator', '/admin/dashboard',
        '/admin/users', '/admin/settings', '/admin/config',
        '/manage', '/management', '/backend',
        
        # User data endpoints
        '/api/users', '/api/user', '/api/profile',
        '/api/account', '/api/settings',
        '/user/profile', '/user/settings',
        '/account', '/profile', '/settings',
        
        # Sensitive operations
        '/api/export', '/api/download', '/export',
        '/api/delete', '/api/update', '/api/create',
        '/api/admin', '/api/v1/admin',
        
        # Financial/sensitive
        '/api/payments', '/api/orders', '/api/transactions',
        '/payment', '/orders', '/transactions', '/billing',
        
        # System endpoints
        '/api/system', '/api/config', '/api/logs',
        '/system', '/config', '/logs', '/debug',
        '/status', '/health', '/metrics',
        '/phpinfo.php', '/info.php',
    ]
    
    # Parameters that might bypass authentication
    BYPASS_PARAMS = [
        ('admin', 'true'),
        ('admin', '1'),
        ('auth', 'true'),
        ('authenticated', 'true'),
        ('authenticated', '1'),
        ('bypass', 'true'),
        ('debug', 'true'),
        ('test', 'true'),
        ('role', 'admin'),
        ('user_role', 'administrator'),
        ('access', 'admin'),
        ('isAdmin', 'true'),
        ('is_admin', 'true'),
    ]
    
    # Headers that might bypass authentication
    BYPASS_HEADERS = [
        ('X-Forwarded-For', '127.0.0.1'),
        ('X-Real-IP', '127.0.0.1'),
        ('X-Original-URL', '/admin'),
        ('X-Rewrite-URL', '/admin'),
        ('X-Custom-IP-Authorization', '127.0.0.1'),
        ('X-Forwarded-Host', 'localhost'),
        ('X-Remote-IP', '127.0.0.1'),
        ('X-Client-IP', '127.0.0.1'),
        ('X-Host', 'localhost'),
        ('X-Originating-IP', '127.0.0.1'),
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for authentication bypass vulnerabilities"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test 1: Check critical endpoints without authentication
        unauth_vulns = await self._test_unauthenticated_access(session, base_url)
        vulnerabilities.extend(unauth_vulns)
        
        # Test 2: Check for parameter-based bypass
        param_vulns = await self._test_parameter_bypass(session, url, params)
        vulnerabilities.extend(param_vulns)
        
        # Test 3: Check for header-based bypass
        header_vulns = await self._test_header_bypass(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Test 4: Check for HTTP method bypass
        method_vulns = await self._test_method_bypass(session, url)
        vulnerabilities.extend(method_vulns)
        
        # Test 5: Check for path traversal bypass
        path_vulns = await self._test_path_bypass(session, base_url)
        vulnerabilities.extend(path_vulns)
        
        return vulnerabilities
    
    async def _test_unauthenticated_access(self, session: aiohttp.ClientSession,
                                            base_url: str) -> List[Vulnerability]:
        """Test if critical endpoints are accessible without authentication"""
        vulnerabilities = []
        
        for endpoint in self.CRITICAL_ENDPOINTS[:20]:  # Limit for speed
            test_url = urljoin(base_url, endpoint)
            
            try:
                response = await self.make_request(session, "GET", test_url)
                
                if not response:
                    continue
                
                # Check if we got access (not redirect to login, not 401/403)
                if response.status == 200:
                    body = await response.text()
                    
                    # Check for actual content (not error page or login redirect)
                    is_accessible = self._check_endpoint_accessible(body, endpoint)
                    
                    if is_accessible:
                        severity = Severity.CRITICAL if any(s in endpoint for s in ['admin', 'payment', 'user']) else Severity.HIGH
                        
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Missing Authentication on Critical Endpoint",
                            severity=severity,
                            url=test_url,
                            parameter="Endpoint",
                            payload=endpoint,
                            evidence=f"Endpoint accessible without authentication (HTTP 200)",
                            description=f"Critical endpoint {endpoint} is accessible without authentication.",
                            cwe_id="CWE-306",
                            cvss_score=9.0 if severity == Severity.CRITICAL else 7.5,
                            remediation="Implement authentication checks on all sensitive endpoints.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/306.html"
                            ]
                        ))
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_endpoint_accessible(self, body: str, endpoint: str) -> bool:
        """Check if endpoint content indicates real access"""
        body_lower = body.lower()
        
        # Negative indicators (not really accessible)
        negative_patterns = [
            'login', 'sign in', 'log in', 'authenticate',
            'unauthorized', 'forbidden', 'access denied',
            'not found', '404', 'error',
        ]
        
        # Positive indicators (real access)
        positive_patterns = [
            'dashboard', 'welcome', 'settings', 'profile',
            'users', 'data', 'admin', 'manage', 'configuration',
            'logout', 'sign out',
        ]
        
        has_negative = any(p in body_lower for p in negative_patterns)
        has_positive = any(p in body_lower for p in positive_patterns)
        
        # Also check if the endpoint name suggests sensitive data
        if endpoint:
            endpoint_lower = endpoint.lower()
            if any(s in endpoint_lower for s in ['admin', 'api', 'user', 'account']):
                # For API endpoints, check if we got JSON data
                if 'application/json' in body_lower or body.strip().startswith('{') or body.strip().startswith('['):
                    return True
        
        return has_positive and not has_negative
    
    async def _test_parameter_bypass(self, session: aiohttp.ClientSession,
                                      url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Test authentication bypass via parameters"""
        vulnerabilities = []
        
        base_params = params.copy() if params else {}
        
        for param_name, param_value in self.BYPASS_PARAMS:
            test_params = base_params.copy()
            test_params[param_name] = param_value
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    # Check for privilege escalation indicators
                    if self._check_privilege_indicators(body):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Authentication Bypass via Parameter",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=f"{param_name}={param_value}",
                            evidence="Elevated privileges detected with bypass parameter",
                            description=f"Authentication can be bypassed using parameter {param_name}={param_value}",
                            cwe_id="CWE-302",
                            cvss_score=9.8,
                            remediation="Never trust client-supplied authentication parameters. Validate session server-side.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/302.html"
                            ]
                        ))
                        return vulnerabilities
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_header_bypass(self, session: aiohttp.ClientSession,
                                   url: str) -> List[Vulnerability]:
        """Test authentication bypass via headers"""
        vulnerabilities = []
        
        # First get baseline response
        baseline_response = await self.make_request(session, "GET", url)
        if not baseline_response:
            return vulnerabilities
        
        baseline_status = baseline_response.status
        baseline_body = await baseline_response.text()
        
        for header_name, header_value in self.BYPASS_HEADERS:
            try:
                headers = {header_name: header_value}
                response = await self.make_request(session, "GET", url, headers=headers)
                
                if response:
                    body = await response.text()
                    
                    # Check if response changed significantly
                    if response.status != baseline_status or \
                       (response.status == 200 and len(body) != len(baseline_body)):
                        
                        if self._check_privilege_indicators(body):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Authentication Bypass via Header",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=header_name,
                                payload=f"{header_name}: {header_value}",
                                evidence=f"Response changed with header injection (status: {response.status})",
                                description=f"Authentication may be bypassed using {header_name} header.",
                                cwe_id="CWE-290",
                                cvss_score=8.0,
                                remediation="Don't trust client-supplied headers for authentication/authorization decisions.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/290.html"
                                ]
                            ))
                            return vulnerabilities
                            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_method_bypass(self, session: aiohttp.ClientSession,
                                   url: str) -> List[Vulnerability]:
        """Test authentication bypass via HTTP method change"""
        vulnerabilities = []
        
        # Methods to test
        methods = ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        # Get baseline with GET
        baseline = await self.make_request(session, "GET", url)
        if not baseline:
            return vulnerabilities
        
        baseline_status = baseline.status
        
        # If GET is blocked (401/403), try other methods
        if baseline_status in [401, 403]:
            for method in methods:
                try:
                    response = await self.make_request(session, method, url)
                    
                    if response and response.status == 200:
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Authentication Bypass via HTTP Method",
                            severity=Severity.HIGH,
                            url=url,
                            parameter="HTTP Method",
                            payload=method,
                            evidence=f"GET blocked ({baseline_status}) but {method} allowed (200)",
                            description=f"Authentication can be bypassed by changing HTTP method from GET to {method}.",
                            cwe_id="CWE-288",
                            cvss_score=7.5,
                            remediation="Implement authentication checks for all HTTP methods.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/288.html"
                            ]
                        ))
                        break
                        
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_path_bypass(self, session: aiohttp.ClientSession,
                                 base_url: str) -> List[Vulnerability]:
        """Test authentication bypass via path manipulation"""
        vulnerabilities = []
        
        # Path bypass patterns
        bypass_patterns = [
            '/admin/../admin',
            '/admin/..;/admin',
            '/./admin',
            '//admin',
            '/admin%2f',
            '/admin%252f',
            '/admin/',
            '/admin/.',
            '/.;/admin',
            '/admin;/',
            '/admin/..',
        ]
        
        # Test against /admin endpoint
        test_endpoint = '/admin'
        baseline_url = urljoin(base_url, test_endpoint)
        
        baseline = await self.make_request(session, "GET", baseline_url)
        if not baseline or baseline.status not in [401, 403]:
            return vulnerabilities  # Endpoint not protected or doesn't exist
        
        for pattern in bypass_patterns:
            try:
                test_url = base_url + pattern
                response = await self.make_request(session, "GET", test_url)
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    if 'login' not in body.lower() and 'unauthorized' not in body.lower():
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Authentication Bypass via Path Manipulation",
                            severity=Severity.HIGH,
                            url=test_url,
                            parameter="URL Path",
                            payload=pattern,
                            evidence=f"Protected endpoint accessible via path: {pattern}",
                            description="Authentication can be bypassed using URL path manipulation.",
                            cwe_id="CWE-289",
                            cvss_score=8.0,
                            remediation="Normalize URLs before authentication checks. Use proper URL parsing.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/289.html"
                            ]
                        ))
                        break
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_privilege_indicators(self, body: str) -> bool:
        """Check if response indicates elevated privileges"""
        body_lower = body.lower()
        
        privilege_indicators = [
            'admin', 'administrator', 'dashboard', 'manage',
            'configuration', 'settings', 'users list', 'user management',
            'delete user', 'create user', 'system', 'control panel',
        ]
        
        negative_indicators = [
            'unauthorized', 'forbidden', 'access denied', 'login',
            'sign in', 'permission denied', 'not allowed',
        ]
        
        has_privilege = any(p in body_lower for p in privilege_indicators)
        has_denial = any(p in body_lower for p in negative_indicators)
        
        return has_privilege and not has_denial