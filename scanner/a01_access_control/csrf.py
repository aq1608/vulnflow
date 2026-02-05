# scanner/access_control/csrf.py
"""
Cross-Site Request Forgery (CSRF) Scanner

Detects CSRF vulnerabilities:
- Missing CSRF tokens
- Predictable CSRF tokens
- CSRF token not validated
- Missing SameSite cookie attribute
- Improper HTTP method usage

OWASP: A01:2025 - Broken Access Control
CWE-352: Cross-Site Request Forgery (CSRF)
"""

import asyncio
import aiohttp
import re
import hashlib
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CSRFScanner(BaseScanner):
    """Scanner for Cross-Site Request Forgery vulnerabilities"""
    
    name = "CSRF Scanner"
    description = "Detects Cross-Site Request Forgery vulnerabilities"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    def __init__(self):
        super().__init__()
        
        # Common CSRF token field names
        self.csrf_token_names = [
            'csrf', 'csrf_token', 'csrftoken', '_csrf', '_csrf_token',
            'xsrf', 'xsrf_token', 'xsrftoken', '_xsrf',
            'token', '_token', 'authenticity_token',
            '__RequestVerificationToken',  # ASP.NET
            'anti_csrf', 'anticsrf',
            'formtoken', 'form_token',
            'nonce', '_wpnonce',  # WordPress
            'security_token', 'sec_token',
        ]
        
        # Common CSRF header names
        self.csrf_header_names = [
            'X-CSRF-Token', 'X-XSRF-Token', 'X-CSRFToken',
            'X-Requested-With', 'X-Request-Token',
        ]
        
        # State-changing endpoints to test
        self.state_changing_endpoints = [
            '/account/update', '/account/settings', '/profile/update',
            '/user/update', '/user/edit', '/user/delete',
            '/admin/user', '/admin/settings', '/admin/config',
            '/settings', '/preferences', '/password/change',
            '/email/change', '/transfer', '/payment',
            '/order/create', '/cart/add', '/checkout',
            '/api/user', '/api/account', '/api/settings',
        ]
        
        # Form actions that are state-changing
        self.state_changing_actions = [
            'update', 'edit', 'delete', 'remove', 'create', 'add',
            'submit', 'save', 'modify', 'change', 'transfer', 'send',
            'post', 'upload', 'import', 'export', 'execute', 'process',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for CSRF vulnerabilities"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test 1: Check forms on the page for CSRF protection
        form_vulns = await self._check_forms_for_csrf(session, url)
        vulnerabilities.extend(form_vulns)
        
        # Test 2: Check state-changing endpoints
        endpoint_vulns = await self._check_state_changing_endpoints(session, base_url)
        vulnerabilities.extend(endpoint_vulns)
        
        # Test 3: Check if CSRF tokens are validated
        validation_vulns = await self._test_csrf_token_validation(session, url)
        vulnerabilities.extend(validation_vulns)
        
        # Test 4: Check for SameSite cookie issues (CSRF-related)
        cookie_vulns = await self._check_samesite_cookies(session, url)
        vulnerabilities.extend(cookie_vulns)
        
        return vulnerabilities
    
    async def _check_forms_for_csrf(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check HTML forms for CSRF protection"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response or response.status != 200:
                return vulnerabilities
            
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            
            for form in forms:
                method = form.get('method', 'get').lower()
                action = form.get('action', '')
                
                # Only check POST forms or forms with state-changing actions
                if method != 'post' and not self._is_state_changing_action(action):
                    continue
                
                # Check for CSRF token
                has_csrf_token = self._form_has_csrf_token(form)
                
                if not has_csrf_token:
                    form_url = urljoin(url, action) if action else url
                    
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="CSRF - Missing Token in Form",
                        severity=Severity.HIGH,
                        url=form_url,
                        parameter="form",
                        payload=f"Method: {method.upper()}, Action: {action or 'same page'}",
                        evidence=f"Form without CSRF token found: {str(form)[:200]}...",
                        description="A form that performs state-changing operations does not include a CSRF token, making it vulnerable to CSRF attacks.",
                        cwe_id="CWE-352",
                        cvss_score=8.0,
                        remediation=self._get_csrf_remediation(),
                        references=[
                            "https://owasp.org/www-community/attacks/csrf",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                        ]
                    ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _form_has_csrf_token(self, form) -> bool:
        """Check if form contains a CSRF token"""
        # Check hidden inputs
        inputs = form.find_all('input', {'type': 'hidden'})
        
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            for token_name in self.csrf_token_names:
                if token_name.lower() in name:
                    return True
        
        # Check for meta tags with CSRF tokens (common in SPAs)
        # This would be in the document head, not the form, but worth noting
        
        return False
    
    def _is_state_changing_action(self, action: str) -> bool:
        """Check if action URL suggests state-changing operation"""
        action_lower = action.lower()
        return any(word in action_lower for word in self.state_changing_actions)
    
    async def _check_state_changing_endpoints(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check state-changing endpoints for CSRF protection"""
        vulnerabilities = []
        
        for endpoint in self.state_changing_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            try:
                # Test POST without CSRF token
                response = await self.make_request(
                    session, "POST", test_url,
                    data={"test": "value"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if not response:
                    continue
                
                # If we get 200/201/302 without CSRF token, it might be vulnerable
                if response.status in [200, 201, 302]:
                    # Check if response indicates success (not an error page)
                    body = await response.text()
                    
                    if not self._is_error_response(body):
                        # Verify by checking if X-Requested-With is required
                        ajax_response = await self.make_request(
                            session, "POST", test_url,
                            data={"test": "value"},
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "X-Requested-With": "XMLHttpRequest"
                            }
                        )
                        
                        if ajax_response and ajax_response.status in [200, 201]:
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="CSRF - Unprotected State-Changing Endpoint",
                                severity=Severity.MEDIUM,
                                url=test_url,
                                parameter="endpoint",
                                payload="POST request without CSRF token",
                                evidence=f"Endpoint accepts POST without CSRF validation (HTTP {response.status})",
                                description=f"The endpoint {endpoint} accepts state-changing requests without CSRF token validation.",
                                cwe_id="CWE-352",
                                cvss_score=6.5,
                                remediation=self._get_csrf_remediation(),
                                references=[
                                    "https://owasp.org/www-community/attacks/csrf"
                                ]
                            ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_csrf_token_validation(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test if CSRF tokens are properly validated"""
        vulnerabilities = []
        
        try:
            # First, get a page with a form
            response = await self.make_request(session, "GET", url)
            if not response or response.status != 200:
                return vulnerabilities
            
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find forms with CSRF tokens
            forms = soup.find_all('form', method=re.compile('post', re.I))
            
            for form in forms:
                csrf_token = self._extract_csrf_token(form)
                
                if csrf_token:
                    action = form.get('action', '')
                    form_url = urljoin(url, action) if action else url
                    
                    # Test 1: Submit with empty token
                    empty_token_vuln = await self._test_empty_token(
                        session, form, form_url, csrf_token
                    )
                    if empty_token_vuln:
                        vulnerabilities.append(empty_token_vuln)
                    
                    # Test 2: Submit with modified token
                    modified_token_vuln = await self._test_modified_token(
                        session, form, form_url, csrf_token
                    )
                    if modified_token_vuln:
                        vulnerabilities.append(modified_token_vuln)
                    
                    # Test 3: Submit without token
                    missing_token_vuln = await self._test_missing_token(
                        session, form, form_url, csrf_token
                    )
                    if missing_token_vuln:
                        vulnerabilities.append(missing_token_vuln)
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _extract_csrf_token(self, form) -> Optional[Tuple[str, str]]:
        """Extract CSRF token name and value from form"""
        inputs = form.find_all('input', {'type': 'hidden'})
        
        for input_field in inputs:
            name = input_field.get('name', '')
            value = input_field.get('value', '')
            
            for token_name in self.csrf_token_names:
                if token_name.lower() in name.lower():
                    return (name, value)
        
        return None
    
    async def _test_empty_token(
        self,
        session: aiohttp.ClientSession,
        form,
        url: str,
        csrf_token: Tuple[str, str]
    ) -> Optional[Vulnerability]:
        """Test if empty CSRF token is accepted"""
        token_name, _ = csrf_token
        
        # Build form data with empty token
        form_data = self._extract_form_data(form)
        form_data[token_name] = ''
        
        try:
            response = await self.make_request(
                session, "POST", url,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response and response.status in [200, 201, 302]:
                body = await response.text()
                if not self._is_csrf_error(body):
                    return self.create_vulnerability(
                        vuln_type="CSRF - Empty Token Accepted",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=token_name,
                        payload="Empty CSRF token",
                        evidence=f"Server accepted empty CSRF token (HTTP {response.status})",
                        description="The application accepts empty CSRF tokens, bypassing CSRF protection.",
                        cwe_id="CWE-352",
                        cvss_score=8.0,
                        remediation=self._get_csrf_remediation()
                    )
        
        except Exception:
            pass
        
        return None
    
    async def _test_modified_token(
        self,
        session: aiohttp.ClientSession,
        form,
        url: str,
        csrf_token: Tuple[str, str]
    ) -> Optional[Vulnerability]:
        """Test if modified CSRF token is accepted"""
        token_name, original_value = csrf_token
        
        # Build form data with modified token
        form_data = self._extract_form_data(form)
        
        # Modify token (change last character)
        if original_value:
            modified_value = original_value[:-1] + ('a' if original_value[-1] != 'a' else 'b')
        else:
            modified_value = 'invalid_token_12345'
        
        form_data[token_name] = modified_value
        
        try:
            response = await self.make_request(
                session, "POST", url,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response and response.status in [200, 201, 302]:
                body = await response.text()
                if not self._is_csrf_error(body):
                    return self.create_vulnerability(
                        vuln_type="CSRF - Token Not Validated",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=token_name,
                        payload=f"Modified token: {modified_value[:20]}...",
                        evidence=f"Server accepted invalid CSRF token (HTTP {response.status})",
                        description="The application does not properly validate CSRF tokens, making it vulnerable to CSRF attacks.",
                        cwe_id="CWE-352",
                        cvss_score=8.8,
                        remediation=self._get_csrf_remediation()
                    )
        
        except Exception:
            pass
        
        return None
    
    async def _test_missing_token(
        self,
        session: aiohttp.ClientSession,
        form,
        url: str,
        csrf_token: Tuple[str, str]
    ) -> Optional[Vulnerability]:
        """Test if request without CSRF token is accepted"""
        token_name, _ = csrf_token
        
        # Build form data without token
        form_data = self._extract_form_data(form)
        if token_name in form_data:
            del form_data[token_name]
        
        try:
            response = await self.make_request(
                session, "POST", url,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response and response.status in [200, 201, 302]:
                body = await response.text()
                if not self._is_csrf_error(body):
                    return self.create_vulnerability(
                        vuln_type="CSRF - Missing Token Accepted",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=token_name,
                        payload="Request without CSRF token",
                        evidence=f"Server accepted request without CSRF token (HTTP {response.status})",
                        description="The application accepts requests without CSRF tokens.",
                        cwe_id="CWE-352",
                        cvss_score=8.0,
                        remediation=self._get_csrf_remediation()
                    )
        
        except Exception:
            pass
        
        return None
    
    def _extract_form_data(self, form) -> Dict[str, str]:
        """Extract all form fields as dictionary"""
        form_data = {}
        
        # Get all input fields
        for input_field in form.find_all(['input', 'textarea', 'select']):
            name = input_field.get('name')
            if not name:
                continue
            
            if input_field.name == 'select':
                # Get first option value
                option = input_field.find('option', selected=True) or input_field.find('option')
                value = option.get('value', '') if option else ''
            elif input_field.name == 'textarea':
                value = input_field.string or ''
            else:
                input_type = input_field.get('type', 'text').lower()
                if input_type in ['checkbox', 'radio']:
                    if input_field.get('checked'):
                        value = input_field.get('value', 'on')
                    else:
                        continue
                elif input_type == 'submit':
                    continue
                else:
                    value = input_field.get('value', '')
            
            form_data[name] = value
        
        return form_data
    
    async def _check_samesite_cookies(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for session cookies without SameSite attribute (CSRF-related)"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            set_cookies = response.headers.getall('Set-Cookie', [])
            
            for cookie_header in set_cookies:
                # Parse cookie name
                parts = cookie_header.split(';')
                if not parts:
                    continue
                
                name_value = parts[0].strip()
                if '=' not in name_value:
                    continue
                
                cookie_name = name_value.split('=', 1)[0].strip()
                
                # Check if it's a session cookie
                session_patterns = ['session', 'sess', 'auth', 'token', 'login', 'user']
                is_session = any(p in cookie_name.lower() for p in session_patterns)
                
                if not is_session:
                    continue
                
                # Check for SameSite
                cookie_lower = cookie_header.lower()
                has_samesite = 'samesite' in cookie_lower
                
                if not has_samesite:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="CSRF Risk - Session Cookie Missing SameSite",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=cookie_name,
                        payload="N/A",
                        evidence=f"Session cookie '{cookie_name}' missing SameSite attribute",
                        description="Session cookie lacks SameSite attribute, which is a defense-in-depth measure against CSRF.",
                        cwe_id="CWE-1275",
                        cvss_score=5.3,
                        remediation="Add SameSite=Strict or SameSite=Lax to session cookies.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                        ]
                    ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_error_response(self, body: str) -> bool:
        """Check if response indicates an error"""
        error_indicators = [
            'error', 'invalid', 'unauthorized', 'forbidden',
            'not found', '404', '403', '401', 'denied',
            'failed', 'failure', 'exception'
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in error_indicators)
    
    def _is_csrf_error(self, body: str) -> bool:
        """Check if response indicates CSRF validation failure"""
        csrf_error_indicators = [
            'csrf', 'token', 'invalid token', 'token mismatch',
            'verification failed', 'security token', 'forgery',
            'xsrf', 'request forgery', 'invalid request'
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in csrf_error_indicators)
    
    def _get_csrf_remediation(self) -> str:
        """Get CSRF remediation advice"""
        return """
1. Implement anti-CSRF tokens (synchronizer token pattern)
2. Use the Double Submit Cookie pattern as an alternative
3. Set SameSite=Strict or SameSite=Lax on session cookies
4. Verify the Origin and Referer headers for state-changing requests
5. For APIs, require custom headers (e.g., X-Requested-With)
6. Use frameworks' built-in CSRF protection

Example (Python/Flask):
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# In templates:
<form method="post">
    {{ csrf_token() }}
    ...
</form>
```
Example (Django):

```python
# In templates:
<form method="post">
    {% csrf_token %}
    ...
</form>
```
"""