# scanner/access_control/privilege_escalation.py
"""
Privilege Escalation Scanner

Detects potential privilege escalation vulnerabilities:
- Vertical privilege escalation (user -> admin)
- Horizontal privilege escalation (user A -> user B)
- Role manipulation
- Permission bypass

OWASP: A01:2021 - Broken Access Control
CWE-269: Improper Privilege Management
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class PrivilegeEscalationScanner(BaseScanner):
    """Scanner for privilege escalation vulnerabilities"""
    name="Privilege Escalation Scanner",
    description="Detects privilege escalation vulnerabilities",
    owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    def __init__(self):
        
        # Admin/privileged endpoints to test
        self.admin_endpoints = [
            "/admin",
            "/admin/",
            "/administrator",
            "/admin/dashboard",
            "/admin/users",
            "/admin/settings",
            "/admin/config",
            "/dashboard/admin",
            "/management",
            "/manage",
            "/manager",
            "/control-panel",
            "/cp",
            "/admincp",
            "/sysadmin",
            "/system",
            "/system/admin",
            "/backend",
            "/admin.php",
            "/admin.html",
            "/wp-admin",
            "/wp-admin/",
        ]
        
        # Role/privilege parameters to manipulate
        self.privilege_params = [
            ("role", ["admin", "administrator", "root", "superuser", "manager"]),
            ("user_role", ["admin", "administrator", "root", "superuser"]),
            ("userRole", ["admin", "administrator", "root", "superuser"]),
            ("is_admin", ["true", "1", "yes"]),
            ("isAdmin", ["true", "1", "yes"]),
            ("admin", ["true", "1", "yes"]),
            ("privilege", ["admin", "high", "elevated", "root"]),
            ("access_level", ["admin", "10", "100", "999"]),
            ("accessLevel", ["admin", "10", "100", "999"]),
            ("permission", ["admin", "all", "*", "full"]),
            ("permissions", ["admin", "all", "*", "full"]),
            ("group", ["admin", "administrators", "root"]),
            ("user_type", ["admin", "administrator", "staff"]),
            ("userType", ["admin", "administrator", "staff"]),
            ("level", ["admin", "10", "100", "0"]),
            ("auth_level", ["admin", "high", "10"]),
        ]
        
        # Headers that might control access
        self.privilege_headers = [
            ("X-Admin", "true"),
            ("X-Is-Admin", "true"),
            ("X-Role", "admin"),
            ("X-User-Role", "administrator"),
            ("X-Access-Level", "admin"),
            ("X-Privilege", "admin"),
            ("X-Auth-Admin", "true"),
            ("Admin", "true"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for privilege escalation vulnerabilities.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test 1: Direct admin endpoint access
        admin_vulns = await self._test_admin_endpoints(session, base_url)
        vulnerabilities.extend(admin_vulns)
        
        # Test 2: Parameter-based privilege escalation
        if params:
            param_vulns = await self._test_privilege_params(session, url, params)
            vulnerabilities.extend(param_vulns)
        
        # Test 3: Header-based privilege escalation
        header_vulns = await self._test_privilege_headers(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Test 4: Role manipulation in requests
        role_vulns = await self._test_role_manipulation(session, url)
        vulnerabilities.extend(role_vulns)
        
        return vulnerabilities
    
    async def _test_admin_endpoints(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Test direct access to admin endpoints"""
        vulnerabilities = []
        
        for endpoint in self.admin_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    # Check for successful access (200) without authentication
                    if response.status == 200:
                        content = await response.text()
                        
                        # Verify it's actually an admin page
                        admin_indicators = [
                            "admin", "dashboard", "manage", "control panel",
                            "settings", "configuration", "users list",
                            "system", "administrator"
                        ]
                        
                        content_lower = content.lower()
                        if any(indicator in content_lower for indicator in admin_indicators):
                            # Check it's not a login page
                            login_indicators = ["login", "sign in", "password", "authenticate"]
                            if not any(login in content_lower for login in login_indicators):
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Privilege Escalation - Unprotected Admin Endpoint",
                                    severity=Severity.CRITICAL,
                                    url=test_url,
                                    parameter="endpoint",
                                    payload=endpoint,
                                    evidence=f"Admin endpoint accessible without authentication (HTTP {response.status})",
                                    description=f"Administrative endpoint {endpoint} is accessible without proper authentication",
                                    cwe_id="CWE-269",
                                    remediation=self._get_remediation()
                                ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_privilege_params(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_params: Dict[str, str]
    ) -> List[Vulnerability]:
        """Test parameter-based privilege escalation"""
        vulnerabilities = []
        
        for param_name, test_values in self.privilege_params:
            for test_value in test_values:
                try:
                    # Add privilege parameter to existing params
                    test_params = original_params.copy()
                    test_params[param_name] = test_value
                    
                    async with session.get(
                        url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for privilege escalation indicators
                            priv_indicators = [
                                "admin", "administrator", "elevated",
                                "full access", "all permissions", "superuser"
                            ]
                            
                            content_lower = content.lower()
                            if any(indicator in content_lower for indicator in priv_indicators):
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Privilege Escalation - Parameter Manipulation",
                                    severity=Severity.HIGH,
                                    url=url,
                                    parameter=param_name,
                                    payload=f"{param_name}={test_value}",
                                    evidence=f"Privilege parameter accepted (HTTP {response.status})",
                                    description=f"Application may accept privilege escalation via {param_name} parameter",
                                    cwe_id="CWE-269",
                                    remediation=self._get_remediation()
                                ))
                                break  # Found vulnerability for this param
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_privilege_headers(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test header-based privilege escalation"""
        vulnerabilities = []
        
        # First, get baseline response
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as baseline:
                baseline_status = baseline.status
                baseline_length = len(await baseline.text())
        except:
            return vulnerabilities
        
        # Test each privilege header
        for header_name, header_value in self.privilege_headers:
            try:
                headers = {header_name: header_value}
                
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    response_length = len(await response.text())
                    
                    # Check if response significantly changed
                    if response.status == 200 and baseline_status != 200:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Privilege Escalation - Header Bypass",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=header_name,
                            payload=f"{header_name}: {header_value}",
                            evidence=f"Header bypass successful (status changed from {baseline_status} to {response.status})",
                            description=f"Access control bypassed using {header_name} header",
                            cwe_id="CWE-269",
                            remediation=self._get_remediation()
                        ))
                    elif abs(response_length - baseline_length) > 500:
                        # Significant content change
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Privilege Escalation - Header Manipulation",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=header_name,
                            payload=f"{header_name}: {header_value}",
                            evidence=f"Response content changed significantly ({baseline_length} -> {response_length} bytes)",
                            description=f"Application behavior changed with {header_name} header",
                            cwe_id="CWE-269",
                            remediation=self._get_remediation()
                        ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_role_manipulation(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test role manipulation in POST/PUT requests"""
        vulnerabilities = []
        
        # Test payloads for role manipulation
        role_payloads = [
            {"role": "admin"},
            {"role": "administrator"},
            {"isAdmin": True},
            {"is_admin": True},
            {"admin": True},
            {"user": {"role": "admin"}},
            {"user": {"isAdmin": True}},
            {"permissions": ["admin", "write", "delete"]},
            {"access_level": "admin"},
        ]
        
        for payload in role_payloads:
            try:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status in [200, 201]:
                        try:
                            response_json = await response.json()
                            
                            # Check if role was accepted
                            if self._check_role_accepted(response_json, payload):
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Privilege Escalation - Role Manipulation",
                                    severity=Severity.CRITICAL,
                                    url=url,
                                    parameter="request body",
                                    payload=str(payload),
                                    evidence=f"Role manipulation payload accepted",
                                    description="Application accepts role/privilege modification in request body",
                                    cwe_id="CWE-269",
                                    remediation=self._get_remediation()
                                ))
                                break
                        except:
                            pass
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_role_accepted(self, response: Dict, payload: Dict) -> bool:
        """Check if role manipulation was accepted"""
        if not isinstance(response, dict):
            return False
        
        # Check for role in response
        role_keys = ["role", "isAdmin", "is_admin", "admin", "permissions", "access_level"]
        
        for key in role_keys:
            if key in response:
                if key in payload or (isinstance(payload.get("user"), dict) and key in payload["user"]):
                    return True
        
        # Check nested user object
        if "user" in response and isinstance(response["user"], dict):
            for key in role_keys:
                if key in response["user"]:
                    return True
        
        return False
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Implement proper role-based access control (RBAC) on the server side
2. Never trust client-supplied role or privilege information
3. Validate user permissions on every request server-side
4. Use secure session management to track user roles
5. Implement the principle of least privilege
6. Log and monitor privilege escalation attempts
7. Protect administrative endpoints with strong authentication

Example (Python/Flask):
```python
from functools import wraps
from flask import session, abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Always check role from server-side session/database
        user = get_user_from_session(session['user_id'])
        if not user or user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')
    """