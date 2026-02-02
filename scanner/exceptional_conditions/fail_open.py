# scanner/exceptional_conditions/fail_open.py`
"""
Fail Open Scanner

Detects systems that fail open under stress or error conditions:
- Authentication bypass under load
- Authorization bypass on errors
- Missing security controls after exceptions
- Insecure default behaviors

OWASP: A10:2025 - Mishandling of Exceptional Conditions
CWE-636: Not Failing Securely ('Failing Open')
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class FailOpenScanner(BaseScanner):
    """Scanner for fail-open vulnerabilities"""
    
    name = "Fail Open Scanner"
    description = "Detects systems that fail open under exceptional conditions"
    owasp_category = OWASPCategory.A10_EXCEPTIONAL_CONDITIONS
    
    def __init__(self):
        super().__init__()
        
        # Protected paths commonly requiring authentication
        self.protected_paths = [
            '/admin',
            '/admin/',
            '/dashboard',
            '/account',
            '/profile',
            '/settings',
            '/api/admin',
            '/api/user',
            '/api/private',
            '/manage',
            '/internal',
            '/secure',
            '/protected',
            '/members',
            '/user/settings',
        ]
        
        # Headers that might bypass security checks
        self.bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': 'localhost'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'X-Original-URL': '/'},
            {'X-Rewrite-URL': '/'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'Host': 'localhost'},
        ]
        
        # Malformed auth headers to test fail-open
        self.malformed_auth_headers = [
            {'Authorization': ''},
            {'Authorization': 'Bearer '},
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            {'Authorization': 'Bearer [object Object]'},
            {'Authorization': 'Basic '},
            {'Authorization': 'Basic null'},
            {'Cookie': ''},
            {'Cookie': 'session='},
            {'Cookie': 'session=null'},
            {'Cookie': 'session=undefined'},
            {'Cookie': 'token=; session='},
        ]
        
        # Content that indicates successful access to protected areas
        self.protected_content_indicators = [
            'dashboard', 'admin panel', 'settings', 'profile',
            'account', 'manage', 'configuration', 'users list',
            'edit', 'delete', 'create new', 'admin actions',
            'logout', 'sign out', 'my account',
        ]
        
        # Content that indicates denied access
        self.denied_indicators = [
            'login', 'sign in', 'authenticate', 'unauthorized',
            'forbidden', 'access denied', 'not authorized',
            'please log in', 'session expired', 'invalid token',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for fail-open vulnerabilities."""
        vulnerabilities = []
        
        # Test 1: Check if protected paths fail open with special headers
        header_vulns = await self._test_header_bypass(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Test 2: Check if malformed auth causes fail-open
        auth_vulns = await self._test_malformed_auth(session, url)
        vulnerabilities.extend(auth_vulns)
        
        # Test 3: Test concurrent request race conditions
        race_vulns = await self._test_race_conditions(session, url)
        vulnerabilities.extend(race_vulns)
        
        # Test 4: Check for insecure defaults
        default_vulns = await self._test_insecure_defaults(session, url)
        vulnerabilities.extend(default_vulns)
        
        # Test 5: Test error-condition bypass
        error_vulns = await self._test_error_bypass(session, url)
        vulnerabilities.extend(error_vulns)
        
        return vulnerabilities
    
    async def _test_header_bypass(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test if special headers can bypass security controls."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.protected_paths:
            test_url = urljoin(base_url, path)
            
            # First, get baseline response without special headers
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=False
                ) as baseline:
                    baseline_status = baseline.status
                    baseline_content = await baseline.text()
            except:
                continue
            
            # Skip if path doesn't exist or is already accessible
            if baseline_status == 404:
                continue
            if baseline_status == 200 and self._has_protected_content(baseline_content):
                continue  # Already accessible without bypass
            
            # Test each bypass header
            for bypass_header in self.bypass_headers:
                try:
                    async with session.get(
                        test_url,
                        headers=bypass_header,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        
                        # Check for bypass success
                        if self._is_bypass_successful(
                            baseline_status, response.status,
                            baseline_content, content
                        ):
                            header_name = list(bypass_header.keys())[0]
                            header_value = bypass_header[header_name]
                            
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Security Control Bypass via Header",
                                severity=Severity.HIGH,
                                url=test_url,
                                parameter=header_name,
                                payload=f"{header_name}: {header_value}",
                                evidence=f"Access changed from HTTP {baseline_status} to {response.status} with header",
                                description=f"Security controls can be bypassed using {header_name} header (potential fail-open)",
                                cwe_id="CWE-636",
                                owasp_category=self.owasp_category,
                                remediation=self._get_header_bypass_remediation()
                            ))
                            break  # Found bypass for this path
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_malformed_auth(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test if malformed authentication causes fail-open."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.protected_paths[:5]:  # Limit paths
            test_url = urljoin(base_url, path)
            
            # Get baseline without auth
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=False
                ) as baseline:
                    baseline_status = baseline.status
                    if baseline_status == 404:
                        continue
            except:
                continue
            
            # Test malformed auth headers
            for auth_header in self.malformed_auth_headers:
                try:
                    async with session.get(
                        test_url,
                        headers=auth_header,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        
                        # Check if malformed auth grants access
                        if response.status == 200 and self._has_protected_content(content):
                            if not self._has_denied_content(content):
                                header_name = list(auth_header.keys())[0]
                                header_value = auth_header[header_name]
                                
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Fail-Open on Malformed Authentication",
                                    severity=Severity.CRITICAL,
                                    url=test_url,
                                    parameter=header_name,
                                    payload=f"{header_name}: {header_value}",
                                    evidence=f"Access granted with malformed auth (HTTP {response.status})",
                                    description="Application fails open when authentication header is malformed or empty",
                                    cwe_id="CWE-636",
                                    owasp_category=self.owasp_category,
                                    remediation=self._get_auth_remediation()
                                ))
                                break
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_race_conditions(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for race condition vulnerabilities in security checks."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test a few protected paths
        for path in self.protected_paths[:3]:
            test_url = urljoin(base_url, path)
            
            try:
                # Send multiple concurrent requests
                tasks = []
                for _ in range(10):
                    task = session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False,
                        allow_redirects=False
                    )
                    tasks.append(task)
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Analyze responses for inconsistencies
                statuses = []
                successful_access = False
                
                for resp in responses:
                    if isinstance(resp, Exception):
                        continue
                    async with resp:
                        statuses.append(resp.status)
                        if resp.status == 200:
                            content = await resp.text()
                            if self._has_protected_content(content) and not self._has_denied_content(content):
                                successful_access = True
                
                # Check for inconsistent responses (potential race condition)
                if len(set(statuses)) > 1:
                    if 200 in statuses and (401 in statuses or 403 in statuses):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Potential Race Condition in Access Control",
                            severity=Severity.MEDIUM,
                            url=test_url,
                            parameter="concurrent_requests",
                            payload=f"10 concurrent requests",
                            evidence=f"Inconsistent responses: {dict((s, statuses.count(s)) for s in set(statuses))}",
                            description="Access control may be vulnerable to race conditions under concurrent load",
                            cwe_id="CWE-362",
                            owasp_category=self.owasp_category,
                            remediation=self._get_race_remediation()
                        ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_insecure_defaults(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for insecure default configurations."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check for default credentials paths
        default_cred_paths = [
            '/phpmyadmin/',
            '/adminer.php',
            '/wp-admin/',
            '/administrator/',
            '/admin/login',
            '/.env',
            '/config.php',
            '/configuration.php',
            '/wp-config.php.bak',
            '/.git/config',
        ]
        
        for path in default_cred_paths:
            try:
                test_url = urljoin(base_url, path)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for sensitive content indicators
                        sensitive_patterns = [
                            (r'DB_PASSWORD|DATABASE_PASSWORD', 'Database credentials'),
                            (r'API_KEY|SECRET_KEY|APP_KEY', 'API/Secret key'),
                            (r'\[core\][\s\S]*repositoryformatversion', 'Git configuration'),
                            (r'phpMyAdmin', 'phpMyAdmin interface'),
                            (r'Adminer', 'Adminer interface'),
                        ]
                        
                        for pattern, desc in sensitive_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                vulnerabilities.append(Vulnerability(
                                    vuln_type=f"Insecure Default - {desc}",
                                    severity=Severity.HIGH if 'credential' in desc.lower() or 'key' in desc.lower() else Severity.MEDIUM,
                                    url=test_url,
                                    parameter="path",
                                    payload=path,
                                    evidence=f"{desc} accessible at {path}",
                                    description=f"Sensitive resource ({desc}) accessible due to insecure default configuration",
                                    cwe_id="CWE-1188",
                                    owasp_category=self.owasp_category,
                                    remediation=self._get_default_remediation()
                                ))
                                break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_error_bypass(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test if error conditions cause security bypass."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Headers that might cause errors in security middleware
        error_inducing_headers = [
            {'Content-Length': '-1'},
            {'Content-Length': '999999999999'},
            {'Transfer-Encoding': 'chunked, chunked'},
            {'Content-Type': 'multipart/form-data; boundary='},
            {'Host': ''},
            {'Accept-Encoding': 'gzip' * 100},
        ]
        
        for path in self.protected_paths[:3]:
            test_url = urljoin(base_url, path)
            
            for headers in error_inducing_headers:
                try:
                    async with session.get(
                        test_url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        content = await response.text()
                        
                        # Check if error condition granted access
                        if response.status == 200 and self._has_protected_content(content):
                            if not self._has_denied_content(content):
                                header_name = list(headers.keys())[0]
                                
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Fail-Open on Malformed Request",
                                    severity=Severity.HIGH,
                                    url=test_url,
                                    parameter=header_name,
                                    payload=f"{header_name}: {headers[header_name]}",
                                    evidence=f"Access granted with malformed header (HTTP {response.status})",
                                    description="Security controls fail open when processing malformed request headers",
                                    cwe_id="CWE-636",
                                    owasp_category=self.owasp_category,
                                    remediation=self._get_error_bypass_remediation()
                                ))
                                break
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _has_protected_content(self, content: str) -> bool:
        """Check if content appears to be from a protected area."""
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in self.protected_content_indicators)
    
    def _has_denied_content(self, content: str) -> bool:
        """Check if content indicates access was denied."""
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in self.denied_indicators)
    
    def _is_bypass_successful(
        self,
        baseline_status: int,
        new_status: int,
        baseline_content: str,
        new_content: str
    ) -> bool:
        """Determine if a bypass was successful."""
        # Status code changed from error to success
        if baseline_status in [401, 403, 302] and new_status == 200:
            # Verify new content looks like protected content
            if self._has_protected_content(new_content) and not self._has_denied_content(new_content):
                return True
        
        # Content significantly changed and now has protected indicators
        if new_status == 200:
            if self._has_protected_content(new_content) and not self._has_protected_content(baseline_content):
                return True
        
        return False
    
    def _get_header_bypass_remediation(self) -> str:
        """Get remediation for header-based bypass."""
        return """
1. Never trust client-provided headers for security decisions:

```python
# BAD - trusting X-Forwarded-For
def check_admin(request):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    return client_ip in ALLOWED_IPS  # Easily bypassed!

# GOOD - use authenticated session
def check_admin(request):
    user = get_authenticated_user(request)
    return user and user.is_admin
    Configure reverse proxy to strip or overwrite security-sensitive headers:
Nginx:

nginx
proxy_set_header X-Forwarded-For $remote_addr;  # Overwrite, don't append
proxy_set_header X-Real-IP $remote_addr;
Implement defense in depth - multiple security checks

If IP-based restrictions are needed, get IP from trusted source (not headers)

Log and alert on suspicious header manipulation attempts
"""

    def _get_auth_remediation(self) -> str:
        """Get remediation for authentication fail-open."""
        return """

Always fail secure - deny access on ANY authentication error:

python
def authenticate(request):
    try:
        token = request.headers.get('Authorization', '')
        if not token:
            raise AuthenticationError("No token provided")
        
        user = validate_token(token)
        if not user:
            raise AuthenticationError("Invalid token")
        
        return user
    
    except Exception as e:
        # ALWAYS deny on error - fail secure!
        log.warning(f"Auth failed: {e}")
        raise AuthenticationError("Authentication failed")
Validate authentication data strictly:

Check token format before processing
Reject empty, null, or malformed values
Use allowlist validation for expected formats
Implement authentication at infrastructure level (reverse proxy, API gateway)

Use well-tested authentication libraries instead of custom code

Add monitoring for unusual authentication patterns
"""

    def _get_race_remediation(self) -> str:
        """Get remediation for race condition vulnerabilities."""
        return """

Use database transactions for security-critical operations:

python
with db.transaction():
    user = db.get_user(user_id, for_update=True)  # Lock row
    if not user.can_access(resource):
        raise PermissionError()
    # Perform action
Implement idempotency tokens for sensitive operations

Use atomic operations where possible:

python
# Atomic check-and-set
result = db.execute(
    "UPDATE resources SET owner = %s WHERE id = %s AND owner IS NULL",
    [user_id, resource_id]
)
if result.rowcount == 0:
    raise AlreadyClaimedError()
Add rate limiting to prevent rapid concurrent requests

Use pessimistic locking for critical sections

Test under load with concurrent requests
"""

    def _get_default_remediation(self) -> str:
        """Get remediation for insecure defaults."""
        return """

Remove or restrict access to sensitive files:

Nginx:

nginx
location ~ /\\. {
    deny all;
}

location ~ \\.(env|git|config|bak|sql)$ {
    deny all;
}
Apache (.htaccess):

apache
<FilesMatch "^\\.|\\.(env|config|bak|sql)$">
    Order allow,deny
    Deny from all
</FilesMatch>
Never deploy development/debug tools to production:

Remove phpMyAdmin, Adminer in production
Disable debug endpoints
Remove backup files
Change default credentials immediately after installation

Use environment variables for sensitive configuration:

bash
export DB_PASSWORD="secure_password"
Implement infrastructure-as-code with secure defaults

Regular security audits for exposed files
"""

    def _get_error_bypass_remediation(self) -> str:
        """Get remediation for error condition bypass."""
        return """

Implement security checks before parsing request body:

python
@app.before_request
def security_check():
    # Check authentication FIRST
    if not is_authenticated(request):
        return "Unauthorized", 401
    
    # THEN validate request format
    try:
        validate_request(request)
    except Exception:
        return "Bad Request", 400
Handle all exceptions securely:
python
try:
    process_request(request)
except Exception as e:
    log.error(f"Request processing failed: {e}")
    return "Error", 500  # Don't fail open!
Validate and sanitize all headers at the edge (WAF, API Gateway)

Set reasonable limits on request size, header count, etc.

Implement circuit breakers for security middleware

Test error paths specifically for security bypass
"""