# scanner/misconfig/default_credentials.py
"""
Default Credentials Scanner

Detects default and common credentials:
- Default admin accounts
- Common username/password combinations
- Vendor default credentials
- Test accounts

OWASP: A02:2025 - Security Misconfiguration
CWE-1392: Use of Default Credentials
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class DefaultCredentialsScanner(BaseScanner):
    """Scanner for default and common credentials"""
    
    name = "Default Credentials Scanner"
    description = "Detects default and common credentials on login forms and admin panels"
    owasp_category = OWASPCategory.A02_SECURITY_MISCONFIGURATION
    
    def __init__(self):
        super().__init__()
        
        # Common default credentials
        self.default_credentials = [
            # Generic defaults
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('admin', ''),
            ('administrator', 'administrator'),
            ('administrator', 'password'),
            ('root', 'root'),
            ('root', 'password'),
            ('root', 'toor'),
            ('user', 'user'),
            ('user', 'password'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('demo', 'demo'),
            
            # Database defaults
            ('postgres', 'postgres'),
            ('mysql', 'mysql'),
            ('sa', ''),
            ('sa', 'sa'),
            ('oracle', 'oracle'),
            
            # Application specific
            ('tomcat', 'tomcat'),
            ('manager', 'manager'),
            ('weblogic', 'weblogic'),
            ('admin', 'tomcat'),
            ('admin', 'manager'),
        ]
        
        # Vendor-specific default credentials
        self.vendor_credentials = {
            'wordpress': [
                ('/wp-login.php', 'log', 'pwd', [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('admin', 'wordpress'),
                ]),
            ],
            'phpmyadmin': [
                ('/phpmyadmin/', 'pma_username', 'pma_password', [
                    ('root', ''),
                    ('root', 'root'),
                    ('root', 'mysql'),
                    ('pma', ''),
                ]),
            ],
            'tomcat': [
                ('/manager/html', 'username', 'password', [
                    ('tomcat', 'tomcat'),
                    ('admin', 'admin'),
                    ('manager', 'manager'),
                    ('tomcat', 's3cret'),
                ]),
            ],
            'jenkins': [
                ('/login', 'j_username', 'j_password', [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('jenkins', 'jenkins'),
                ]),
            ],
            'joomla': [
                ('/administrator/', 'username', 'passwd', [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                ]),
            ],
            'drupal': [
                ('/user/login', 'name', 'pass', [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                ]),
            ],
        }
        
        # Login endpoints to check
        self.login_endpoints = [
            ('/login', 'username', 'password'),
            ('/admin/login', 'username', 'password'),
            ('/admin', 'username', 'password'),
            ('/administrator', 'username', 'password'),
            ('/user/login', 'username', 'password'),
            ('/signin', 'email', 'password'),
            ('/auth/login', 'username', 'password'),
            ('/api/login', 'username', 'password'),
            ('/api/auth', 'username', 'password'),
            ('/account/login', 'username', 'password'),
        ]
        
        # Success indicators
        self.success_indicators = [
            'dashboard', 'welcome', 'logout', 'sign out', 'my account',
            'profile', 'settings', 'admin panel', 'control panel',
            'logged in', 'authenticated', 'session', 'token',
        ]
        
        # Failure indicators
        self.failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error', 'wrong',
            'denied', 'unauthorized', 'not found', 'bad credentials',
            'login failed', 'authentication failed',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for default credentials"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check vendor-specific login pages
        vendor_vulns = await self._check_vendor_credentials(session, base_url)
        vulnerabilities.extend(vendor_vulns)
        
        # Check generic login endpoints
        generic_vulns = await self._check_generic_logins(session, base_url)
        vulnerabilities.extend(generic_vulns)
        
        # Check HTTP Basic Auth endpoints
        basic_vulns = await self._check_basic_auth(session, base_url)
        vulnerabilities.extend(basic_vulns)
        
        return vulnerabilities
    
    async def _check_vendor_credentials(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check vendor-specific default credentials"""
        vulnerabilities = []
        
        for vendor, endpoints in self.vendor_credentials.items():
            for endpoint, user_field, pass_field, creds in endpoints:
                login_url = urljoin(base_url, endpoint)
                
                # First check if endpoint exists
                try:
                    response = await self.make_request(session, "GET", login_url)
                    
                    if not response or response.status == 404:
                        continue
                    
                except Exception:
                    continue
                
                # Try each credential pair
                for username, password in creds:
                    vuln = await self._try_login(
                        session, login_url, user_field, pass_field,
                        username, password, vendor
                    )
                    
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # Found working creds for this endpoint
        
        return vulnerabilities
    
    async def _check_generic_logins(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check generic login endpoints for default credentials"""
        vulnerabilities = []
        
        for endpoint, user_field, pass_field in self.login_endpoints:
            login_url = urljoin(base_url, endpoint)
            
            # Check if endpoint exists
            try:
                response = await self.make_request(
                    session, "GET", login_url,
                    allow_redirects=False
                )
                
                if not response or response.status == 404:
                    continue
                
            except Exception:
                continue
            
            # Try top 5 default credentials
            for username, password in self.default_credentials[:5]:
                vuln = await self._try_login(
                    session, login_url, user_field, pass_field,
                    username, password, "Generic"
                )
                
                if vuln:
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    async def _check_basic_auth(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check for default credentials on Basic Auth protected endpoints"""
        vulnerabilities = []
        
        # Endpoints commonly protected by Basic Auth
        basic_auth_endpoints = [
            '/admin',
            '/manager/html',
            '/server-status',
            '/server-info',
            '/.htpasswd',
            '/phpmyadmin',
            '/status',
        ]
        
        for endpoint in basic_auth_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            try:
                # First check if it requires Basic Auth
                response = await self.make_request(session, "GET", test_url)
                
                if not response:
                    continue
                
                # Check for 401 with WWW-Authenticate: Basic
                if response.status == 401:
                    www_auth = response.headers.get('WWW-Authenticate', '')
                    
                    if 'Basic' in www_auth:
                        # Try default credentials
                        for username, password in self.default_credentials[:10]:
                            auth = aiohttp.BasicAuth(username, password)
                            
                            try:
                                async with session.get(
                                    test_url,
                                    auth=auth,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    ssl=False
                                ) as auth_response:
                                    if auth_response.status == 200:
                                        vulnerabilities.append(self.create_vulnerability(
                                            vuln_type="Default Credentials - Basic Authentication",
                                            severity=Severity.CRITICAL,
                                            url=test_url,
                                            parameter="Authorization",
                                            payload=f"{username}:{password}",
                                            evidence=f"Successfully authenticated with {username}:{password}",
                                            description=f"The endpoint '{endpoint}' accepts default credentials ({username}:{password}) via HTTP Basic Authentication.",
                                            cwe_id="CWE-1392",
                                            cvss_score=9.8,
                                            remediation=self._get_remediation(),
                                            references=[
                                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials"
                                            ]
                                        ))
                                        break
                            
                            except Exception:
                                continue
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _try_login(
        self,
        session: aiohttp.ClientSession,
        login_url: str,
        user_field: str,
        pass_field: str,
        username: str,
        password: str,
        vendor: str
    ) -> Optional[Vulnerability]:
        """Try to login with given credentials"""
        
        # Prepare login data
        login_data = {
            user_field: username,
            pass_field: password,
        }
        
        try:
            # Try form-based login
            async with session.post(
                login_url,
                data=login_data,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
                allow_redirects=True
            ) as response:
                body = await response.text()
                body_lower = body.lower()
                
                # Check for success
                if self._is_login_successful(response, body_lower):
                    return self.create_vulnerability(
                        vuln_type=f"Default Credentials - {vendor}",
                        severity=Severity.CRITICAL,
                        url=login_url,
                        parameter=f"{user_field}/{pass_field}",
                        payload=f"{username}:{password}",
                        evidence=f"Successfully authenticated with default credentials",
                        description=f"The application accepts default credentials ({username}:{password}). This allows unauthorized access to the system.",
                        cwe_id="CWE-1392",
                        cvss_score=9.8,
                        remediation=self._get_remediation(),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials"
                        ]
                    )
            
            # Also try JSON login
            async with session.post(
                login_url,
                json=login_data,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
                headers={'Content-Type': 'application/json'}
            ) as response:
                body = await response.text()
                body_lower = body.lower()
                
                if self._is_login_successful(response, body_lower):
                    return self.create_vulnerability(
                        vuln_type=f"Default Credentials (API) - {vendor}",
                        severity=Severity.CRITICAL,
                        url=login_url,
                        parameter="JSON body",
                        payload=f"{username}:{password}",
                        evidence=f"Successfully authenticated via API with default credentials",
                        description=f"The API accepts default credentials ({username}:{password}).",
                        cwe_id="CWE-1392",
                        cvss_score=9.8,
                        remediation=self._get_remediation()
                    )
        
        except Exception:
            pass
        
        return None
    
    def _is_login_successful(self, response, body_lower: str) -> bool:
        """Determine if login was successful"""
        
        # Check for success indicators
        success = any(indicator in body_lower for indicator in self.success_indicators)
        
        # Check for failure indicators
        failure = any(indicator in body_lower for indicator in self.failure_indicators)
        
        # Check status code and cookies
        has_session = bool(response.cookies)
        
        # Redirect to dashboard/admin area
        redirect_success = response.status in [302, 303] and any(
            loc in str(response.headers.get('Location', '')).lower()
            for loc in ['dashboard', 'admin', 'home', 'welcome', 'panel']
        )
        
        return (success and not failure) or redirect_success or (response.status == 200 and has_session and not failure)
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Change all default passwords immediately after installation

2. Implement strong password policies:
   - Minimum 12 characters
   - Mix of uppercase, lowercase, numbers, and symbols
   - No dictionary words or common patterns

3. Disable or remove default accounts when possible

4. Implement account lockout after failed login attempts

5. Use multi-factor authentication (MFA)

6. Regularly audit accounts for weak/default passwords

7. Consider using a password manager for generating and storing credentials

8. Implement monitoring and alerting for authentication failures
"""