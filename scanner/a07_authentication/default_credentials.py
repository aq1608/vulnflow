# scanner/authentication/default_credentials.py
"""
Default Credentials Scanner

Detects use of default, hardcoded, or well-known credentials:
- Default admin passwords
- Well-known service credentials
- Hardcoded API keys in responses
- Common username/password combinations

OWASP: A07:2025 - Authentication Failures
CWE-798: Use of Hard-coded Credentials
CWE-259: Use of Hard-coded Password
CWE-1392: Use of Default Credentials
CWE-1393: Use of Default Password
"""

import asyncio
import re
from typing import List, Dict, Optional, Tuple
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class DefaultCredentials07Scanner(BaseScanner):
    """Scanner for default and hardcoded credentials"""
    
    name = "Default Credentials Scanner"
    description = "Detects default, hardcoded, and well-known credentials"
    owasp_category = OWASPCategory.A07_AUTH_FAILURES
    
    # Default credentials database organized by product/service
    DEFAULT_CREDENTIALS = {
        'generic': [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('admin', '123456'),
            ('admin', ''),
            ('administrator', 'administrator'),
            ('administrator', 'password'),
            ('root', 'root'),
            ('root', 'toor'),
            ('root', 'password'),
            ('user', 'user'),
            ('user', 'password'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('demo', 'demo'),
            ('operator', 'operator'),
        ],
        'databases': [
            ('sa', ''),  # MSSQL
            ('sa', 'sa'),
            ('postgres', 'postgres'),
            ('mysql', 'mysql'),
            ('root', ''),  # MySQL
            ('mongo', 'mongo'),
            ('admin', 'admin'),  # MongoDB
        ],
        'cms': [
            ('admin', 'admin'),  # WordPress, Drupal, Joomla
            ('wp-admin', 'wp-admin'),
            ('drupal', 'drupal'),
            ('joomla', 'joomla'),
        ],
        'network_devices': [
            ('admin', 'admin'),
            ('cisco', 'cisco'),
            ('admin', 'cisco'),
            ('admin', '1234'),
            ('admin', 'default'),
            ('ubnt', 'ubnt'),
            ('admin', 'motorola'),
            ('admin', 'password1'),
        ],
        'iot': [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', ''),
            ('root', ''),
            ('user', 'user'),
        ],
        'web_servers': [
            ('tomcat', 'tomcat'),
            ('manager', 'manager'),
            ('admin', 'manager'),
            ('role1', 'tomcat'),
            ('both', 'tomcat'),
            ('admin', 'j2deployer'),
        ],
        'applications': [
            ('admin', 'changeme'),
            ('admin', 'secret'),
            ('admin', 'nimda'),
            ('administrator', 'changeme'),
            ('sysadmin', 'sysadmin'),
            ('supervisor', 'supervisor'),
        ],
    }
    
    # Login endpoints to test
    LOGIN_ENDPOINTS = [
        '/login', '/signin', '/admin', '/admin/login',
        '/administrator', '/wp-admin', '/wp-login.php',
        '/user/login', '/account/login', '/auth/login',
        '/manager/html', '/manager', '/console',
        '/phpmyadmin', '/pma', '/mysql', '/adminer',
        '/api/login', '/api/auth', '/api/v1/login',
    ]
    
    # Patterns indicating successful login
    SUCCESS_PATTERNS = [
        r'dashboard', r'welcome', r'logout', r'sign\s*out',
        r'my\s*account', r'profile', r'settings', r'admin\s*panel',
        r'control\s*panel', r'cpanel', r'logged\s*in',
        r'"authenticated"\s*:\s*true', r'"success"\s*:\s*true',
        r'"status"\s*:\s*"ok"', r'token', r'session',
    ]
    
    # Patterns indicating failed login
    FAILURE_PATTERNS = [
        r'invalid', r'incorrect', r'wrong', r'failed',
        r'error', r'denied', r'unauthorized', r'bad\s*credentials',
        r'"authenticated"\s*:\s*false', r'"success"\s*:\s*false',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for default credentials"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Find login endpoints
        login_endpoints = await self._discover_login_endpoints(session, base_url)
        
        # Test each endpoint
        for endpoint in login_endpoints[:5]:  # Limit to 5 endpoints
            cred_vulns = await self._test_default_credentials(session, endpoint)
            vulnerabilities.extend(cred_vulns)
            
            if cred_vulns:  # Found working credentials, stop testing this endpoint
                break
        
        # Check for hardcoded credentials in responses
        hardcoded_vulns = await self._check_hardcoded_credentials(session, url)
        vulnerabilities.extend(hardcoded_vulns)
        
        # Check for exposed configuration files
        config_vulns = await self._check_config_files(session, base_url)
        vulnerabilities.extend(config_vulns)
        
        return vulnerabilities
    
    async def _discover_login_endpoints(self, session: aiohttp.ClientSession,
                                         base_url: str) -> List[str]:
        """Discover login endpoints"""
        discovered = []
        
        for endpoint in self.LOGIN_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            try:
                response = await self.make_request(session, "GET", test_url)
                if response and response.status in [200, 401, 403]:
                    body = await response.text()
                    
                    # Check if it's a login page
                    if self._is_login_page(body):
                        discovered.append(test_url)
                        
            except Exception:
                continue
        
        return discovered
    
    def _is_login_page(self, body: str) -> bool:
        """Check if page is a login form"""
        body_lower = body.lower()
        
        has_password_field = 'type="password"' in body_lower or "type='password'" in body_lower
        has_login_indicator = any(ind in body_lower for ind in [
            'login', 'sign in', 'log in', 'authenticate', 'username', 'password'
        ])
        
        return has_password_field or has_login_indicator
    
    async def _test_default_credentials(self, session: aiohttp.ClientSession,
                                         login_url: str) -> List[Vulnerability]:
        """Test default credentials against login endpoint"""
        vulnerabilities = []
        
        # Get login form structure
        form_data = await self._analyze_login_form(session, login_url)
        if not form_data:
            return vulnerabilities
        
        username_field = form_data.get('username_field', 'username')
        password_field = form_data.get('password_field', 'password')
        
        # Test credentials from all categories
        all_credentials = []
        for category, creds in self.DEFAULT_CREDENTIALS.items():
            for username, password in creds:
                all_credentials.append((username, password, category))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_creds = []
        for cred in all_credentials:
            key = (cred[0], cred[1])
            if key not in seen:
                seen.add(key)
                unique_creds.append(cred)
        
        # Test credentials (limit to prevent lockouts)
        for username, password, category in unique_creds[:20]:
            result = await self._try_login(
                session, login_url, username_field, password_field,
                username, password
            )
            
            if result['success']:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Default Credentials Found",
                    severity=Severity.CRITICAL,
                    url=login_url,
                    parameter=f"{username_field}/{password_field}",
                    payload=f"Username: {username}, Password: {'*' * len(password) if password else '(empty)'}",
                    evidence=f"Successful login with default credentials ({category})",
                    description=f"The application accepts default credentials: {username}/{password or '(empty)'}. This allows unauthorized access.",
                    cwe_id="CWE-1392",
                    cvss_score=9.8,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
                        "https://cwe.mitre.org/data/definitions/1392.html"
                    ]
                ))
                return vulnerabilities  # Stop after first success
            
            # Small delay to avoid triggering rate limits
            await asyncio.sleep(0.2)
        
        return vulnerabilities
    
    async def _analyze_login_form(self, session: aiohttp.ClientSession,
                                   login_url: str) -> Optional[Dict]:
        """Analyze login form to find field names"""
        try:
            response = await self.make_request(session, "GET", login_url)
            if not response:
                return None
            
            body = await response.text()
            
            # Find username field
            username_patterns = [
                r'name=["\']?(username|user|email|login|userid|user_name|userName)["\']?',
                r'id=["\']?(username|user|email|login|userid)["\']?',
            ]
            
            username_field = 'username'
            for pattern in username_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    username_field = match.group(1)
                    break
            
            # Find password field
            password_patterns = [
                r'name=["\']?(password|passwd|pwd|pass|secret)["\']?',
                r'id=["\']?(password|passwd|pwd|pass)["\']?',
            ]
            
            password_field = 'password'
            for pattern in password_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    password_field = match.group(1)
                    break
            
            # Find form action
            action_match = re.search(r'<form[^>]*action=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
            form_action = action_match.group(1) if action_match else login_url
            
            # Find CSRF token if present
            csrf_patterns = [
                r'name=["\']?(csrf|_token|csrfToken|csrf_token|_csrf)["\']?\s*value=["\']?([^"\'>\s]+)',
                r'value=["\']?([^"\'>\s]+)["\']?\s*name=["\']?(csrf|_token|csrfToken|csrf_token|_csrf)',
            ]
            
            csrf_token = None
            csrf_field = None
            for pattern in csrf_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    csrf_field = match.group(1) if 'name=' in pattern[:10] else match.group(2)
                    csrf_token = match.group(2) if 'name=' in pattern[:10] else match.group(1)
                    break
            
            return {
                'username_field': username_field,
                'password_field': password_field,
                'form_action': form_action,
                'csrf_field': csrf_field,
                'csrf_token': csrf_token,
            }
            
        except Exception:
            return None
    
    async def _try_login(self, session: aiohttp.ClientSession,
                          login_url: str, username_field: str,
                          password_field: str, username: str,
                          password: str) -> Dict:
        """Attempt login with given credentials"""
        try:
            # Build login payload
            payload = {
                username_field: username,
                password_field: password,
            }
            
            response = await self.make_request(
                session, "POST", login_url, 
                data=payload,
                allow_redirects=True
            )
            
            if not response:
                return {'success': False, 'reason': 'no_response'}
            
            body = await response.text()
            body_lower = body.lower()
            
            # Check for success indicators
            is_success = False
            
            # Status code check
            if response.status in [200, 302, 303]:
                # Check for success patterns
                for pattern in self.SUCCESS_PATTERNS:
                    if re.search(pattern, body_lower):
                        is_success = True
                        break
                
                # Check that failure patterns are NOT present
                if is_success:
                    for pattern in self.FAILURE_PATTERNS:
                        if re.search(pattern, body_lower):
                            is_success = False
                            break
            
            # Check for session cookie (indicates login)
            if response.cookies:
                session_cookies = [c for c in response.cookies.keys() 
                                  if any(s in c.lower() for s in ['session', 'auth', 'token', 'jwt'])]
                if session_cookies and not any(re.search(p, body_lower) for p in self.FAILURE_PATTERNS):
                    is_success = True
            
            return {
                'success': is_success,
                'status': response.status,
                'body_length': len(body),
            }
            
        except Exception as e:
            return {'success': False, 'reason': str(e)}
    
    async def _check_hardcoded_credentials(self, session: aiohttp.ClientSession,
                                            url: str) -> List[Vulnerability]:
        """Check for hardcoded credentials in page source"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            body = await response.text()
            
            # Patterns for hardcoded credentials
            credential_patterns = [
                # API keys
                (r'api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key'),
                (r'apikey\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key'),
                
                # AWS
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
                (r'aws[_-]?secret[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key'),
                
                # Passwords
                (r'password\s*[=:]\s*["\']([^"\']{4,})["\']', 'Hardcoded Password'),
                (r'passwd\s*[=:]\s*["\']([^"\']{4,})["\']', 'Hardcoded Password'),
                (r'pwd\s*[=:]\s*["\']([^"\']{4,})["\']', 'Hardcoded Password'),
                
                # Private keys
                (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', 'Private Key'),
                
                # Database connection strings
                (r'(?:mysql|postgres|mongodb)://[^:]+:([^@]+)@', 'Database Password'),
                
                # JWT secrets
                (r'jwt[_-]?secret\s*[=:]\s*["\']([^"\']{10,})["\']', 'JWT Secret'),
                
                # Generic secrets
                (r'secret[_-]?key\s*[=:]\s*["\']([^"\']{10,})["\']', 'Secret Key'),
            ]
            
            for pattern, cred_type in credential_patterns:
                matches = re.finditer(pattern, body, re.IGNORECASE)
                for match in matches:
                    # Get context
                    start = max(0, match.start() - 20)
                    end = min(len(body), match.end() + 20)
                    context = body[start:end]
                    
                    # Skip if it looks like a placeholder
                    matched_value = match.group(1) if match.lastindex else match.group()
                    if any(placeholder in matched_value.lower() for placeholder in 
                           ['example', 'placeholder', 'your_', 'xxx', 'changeme', 'insert']):
                        continue
                    
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type=f"Hardcoded Credentials - {cred_type}",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="Source Code",
                        payload="N/A",
                        evidence=f"Found in source: ...{context}...",
                        description=f"Hardcoded {cred_type} found in page source. This may expose sensitive credentials.",
                        cwe_id="CWE-798",
                        cvss_score=7.5,
                        remediation="Remove hardcoded credentials. Use environment variables or secure vaults.",
                        references=[
                            "https://cwe.mitre.org/data/definitions/798.html"
                        ]
                    ))
                    break  # One finding per type
                    
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_config_files(self, session: aiohttp.ClientSession,
                                   base_url: str) -> List[Vulnerability]:
        """Check for exposed configuration files with credentials"""
        vulnerabilities = []
        
        config_files = [
            '/.env', '/config.php', '/config.inc.php', '/wp-config.php',
            '/configuration.php', '/settings.py', '/config.json',
            '/config.yml', '/config.yaml', '/database.yml',
            '/secrets.json', '/credentials.json', '/.git/config',
            '/web.config', '/appsettings.json', '/app.config',
        ]
        
        for config_file in config_files:
            try:
                test_url = urljoin(base_url, config_file)
                response = await self.make_request(session, "GET", test_url)
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    # Check for credential indicators
                    credential_indicators = [
                        'password', 'passwd', 'pwd', 'secret', 'api_key',
                        'apikey', 'db_pass', 'database_password', 'mysql',
                        'postgres', 'mongodb', 'redis_password',
                    ]
                    
                    if any(ind in body.lower() for ind in credential_indicators):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Exposed Configuration File",
                            severity=Severity.CRITICAL,
                            url=test_url,
                            parameter="Configuration File",
                            payload=config_file,
                            evidence=f"Configuration file accessible: {config_file}",
                            description=f"Configuration file {config_file} is publicly accessible and may contain credentials.",
                            cwe_id="CWE-259",
                            cvss_score=9.0,
                            remediation="Block access to configuration files via web server configuration.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/259.html"
                            ]
                        ))
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
Default Credentials Prevention:

1. **Change All Default Credentials**
   - Change default passwords immediately upon deployment
   - Use strong, unique passwords for each system
   - Document credential changes securely

2. **Implement Password Policy**
   - Require strong passwords on first login
   - Force password change after initial setup
   - Prevent use of common/default passwords

3. **Remove Default Accounts**
   - Delete or disable default admin accounts
   - Create named accounts for administrators
   - Implement principle of least privilege

4. **Automated Checks**
   - Include default credential checks in CI/CD
   - Scan for hardcoded credentials in code reviews
   - Use secrets management tools

5. **Configuration Management**
   - Use environment variables for credentials
   - Implement secrets vault (HashiCorp Vault, AWS Secrets Manager)
   - Never commit credentials to version control

Example - Environment Variables:
```python
import os

# Instead of:
DB_PASSWORD = "admin123"

# Use:
DB_PASSWORD = os.environ.get('DB_PASSWORD')
if not DB_PASSWORD:
    raise ValueError("DB_PASSWORD environment variable not set")
```
"""