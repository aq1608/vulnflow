# scanner/insecure_design/trust_boundary.py
"""
Trust Boundary Violation Scanner

Detects trust boundary violations including:
- Client-side enforcement bypass
- Hidden field manipulation
- Role/privilege parameters
- Debug/admin parameters

OWASP: A06:2025 - Insecure Design
CWE-501: Trust Boundary Violation
CWE-602: Client-Side Enforcement of Server-Side Security
CWE-472: External Control of Assumed-Immutable Web Parameter
"""

import re
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class TrustBoundaryScanner(BaseScanner):
    """Scanner for Trust Boundary Violation vulnerabilities"""
    
    name = "Trust Boundary Scanner"
    description = "Detects trust boundary violations and client-side security bypass"
    owasp_category = OWASPCategory.A06_INSECURE_DESIGN
    
    # Parameters that might grant elevated privileges
    PRIVILEGE_PARAMS = [
        'admin', 'is_admin', 'isAdmin', 'administrator',
        'role', 'user_role', 'userRole', 'access_level', 'accessLevel',
        'permission', 'permissions', 'privilege', 'privileges',
        'moderator', 'superuser', 'super_user', 'staff', 'is_staff',
        'level', 'user_level', 'userLevel', 'type', 'user_type', 'userType',
        'group', 'user_group', 'userGroup', 'tier',
    ]
    
    # Debug/test parameters
    DEBUG_PARAMS = [
        'debug', 'test', 'testing', 'dev', 'development',
        'verbose', 'trace', 'log', 'logging',
        'internal', 'bypass', 'skip', 'override',
        'force', 'mock', 'fake', 'simulate',
    ]
    
    # Hidden field manipulation targets
    HIDDEN_FIELD_PATTERNS = [
        'price', 'amount', 'total', 'cost', 'discount',
        'user_id', 'userId', 'account_id', 'accountId',
        'status', 'state', 'verified', 'approved', 'paid',
        'token', 'csrf', 'nonce', 'signature',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for trust boundary violations"""
        vulnerabilities = []
        
        # Test 1: Privilege escalation parameters
        priv_vulns = await self._test_privilege_params(session, url, params)
        vulnerabilities.extend(priv_vulns)
        
        # Test 2: Debug/test parameter injection
        debug_vulns = await self._test_debug_params(session, url, params)
        vulnerabilities.extend(debug_vulns)
        
        # Test 3: Hidden field manipulation (check HTML)
        hidden_vulns = await self._test_hidden_fields(session, url)
        vulnerabilities.extend(hidden_vulns)
        
        # Test 4: Client-side validation bypass
        client_vulns = await self._test_client_side_bypass(session, url, params)
        vulnerabilities.extend(client_vulns)
        
        return vulnerabilities
    
    async def _test_privilege_params(self, session: aiohttp.ClientSession,
                                      url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test injecting privilege escalation parameters"""
        vulnerabilities = []
        
        # Privilege values to try
        privilege_values = {
            'admin': ['true', '1', 'yes', 'admin'],
            'role': ['admin', 'administrator', 'superuser', 'root'],
            'is_admin': ['true', '1', 'yes'],
            'access_level': ['99', '100', 'admin', 'full'],
            'user_type': ['admin', 'staff', 'internal'],
        }
        
        base_params = params.copy() if params else {}
        
        for param_name, values in privilege_values.items():
            for value in values:
                test_params = base_params.copy()
                test_params[param_name] = value
                
                try:
                    # Test GET
                    response = await self.make_request(session, "GET", url, params=test_params)
                    if response:
                        body = await response.text()
                        
                        # Check for privilege escalation indicators
                        if self._check_privilege_escalation(body, response.status):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Trust Boundary Violation - Privilege Parameter",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=f"{param_name}={value}",
                                evidence="Server accepted privilege escalation parameter",
                                description=f"The application accepts '{param_name}' parameter from client, potentially allowing privilege escalation.",
                                cwe_id="CWE-501",
                                cvss_score=8.0,
                                remediation="Never trust client-provided privilege/role parameters. Determine user privileges server-side only.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/501.html",
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing"
                                ]
                            ))
                            return vulnerabilities
                    
                    # Test POST
                    response = await self.make_request(session, "POST", url, data=test_params)
                    if response:
                        body = await response.text()
                        
                        if self._check_privilege_escalation(body, response.status):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Trust Boundary Violation - Privilege Parameter (POST)",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=f"{param_name}={value}",
                                evidence="Server accepted privilege escalation parameter in POST",
                                description=f"The application accepts '{param_name}' parameter in POST requests.",
                                cwe_id="CWE-501",
                                cvss_score=8.0,
                                remediation="Never trust client-provided privilege parameters.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/501.html"
                                ]
                            ))
                            return vulnerabilities
                            
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_debug_params(self, session: aiohttp.ClientSession,
                                  url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for debug/test parameter acceptance"""
        vulnerabilities = []
        
        base_params = params.copy() if params else {}
        
        debug_payloads = [
            ('debug', 'true'),
            ('debug', '1'),
            ('test', 'true'),
            ('_debug', '1'),
            ('verbose', 'true'),
            ('trace', '1'),
            ('internal', 'true'),
            ('bypass', 'true'),
        ]
        
        for param_name, value in debug_payloads:
            test_params = base_params.copy()
            test_params[param_name] = value
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                original_response = None
                
                # Get baseline for comparison
                if params:
                    original_response = await self.make_request(session, "GET", url, params=params)
                    if original_response:
                        original_body = await original_response.text()
                    else:
                        original_body = ""
                else:
                    original_body = ""
                
                # Check for debug output indicators
                debug_indicators = [
                    'stack trace', 'stacktrace', 'debug', 'trace',
                    'sql query', 'SELECT', 'INSERT', 'UPDATE',
                    'exception', 'error at line', 'file path',
                    '/var/www', '/home/', 'c:\\', 'd:\\',
                    'password', 'secret', 'api_key', 'token',
                    'internal server', 'development mode',
                ]
                
                # Check if response contains more info than baseline
                new_info = False
                for indicator in debug_indicators:
                    if indicator.lower() in body.lower() and indicator.lower() not in original_body.lower():
                        new_info = True
                        break
                
                if new_info or len(body) > len(original_body) * 1.5:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Debug Parameter Accepted",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=param_name,
                        payload=f"{param_name}={value}",
                        evidence="Response changed when debug parameter added",
                        description=f"The application accepts debug parameter '{param_name}', potentially exposing sensitive information.",
                        cwe_id="CWE-489",
                        cvss_score=5.3,
                        remediation="Remove or disable debug parameters in production.",
                        references=[
                            "https://cwe.mitre.org/data/definitions/489.html"
                        ]
                    ))
                    return vulnerabilities
                    
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_hidden_fields(self, session: aiohttp.ClientSession,
                                   url: str) -> List[Vulnerability]:
        """Check for manipulable hidden form fields"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            body = await response.text()
            
            # Find hidden input fields
            hidden_fields = re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]*>',
                body, re.IGNORECASE
            )
            
            sensitive_hidden = []
            for field in hidden_fields:
                # Extract name attribute
                name_match = re.search(r'name=["\']([^"\']+)["\']', field, re.IGNORECASE)
                if name_match:
                    field_name = name_match.group(1).lower()
                    
                    # Check if it's a sensitive field
                    for pattern in self.HIDDEN_FIELD_PATTERNS:
                        if pattern in field_name:
                            sensitive_hidden.append(field)
                            break
            
            if sensitive_hidden:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Sensitive Data in Hidden Fields",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="Hidden Form Fields",
                    payload="N/A",
                    evidence=f"Found {len(sensitive_hidden)} sensitive hidden field(s): {sensitive_hidden[:2]}",
                    description="The application uses hidden form fields for sensitive data that could be manipulated by attackers.",
                    cwe_id="CWE-472",
                    cvss_score=5.5,
                    remediation="Don't rely on hidden fields for security-sensitive data. Validate all values server-side.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/472.html"
                    ]
                ))
                
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _test_client_side_bypass(self, session: aiohttp.ClientSession,
                                        url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for client-side validation bypass"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Test bypassing typical client-side validations
        bypass_tests = [
            # Email validation bypass
            ('email', 'invalid-email', 'Email validation'),
            ('email', "test@test'--", 'Email with SQL chars'),
            
            # Phone validation bypass
            ('phone', 'abc', 'Phone validation'),
            ('telephone', '123', 'Short phone'),
            
            # Length validation bypass
            ('username', 'a' * 1000, 'Length validation'),
            ('password', 'a', 'Minimum length'),
            
            # Format validation bypass
            ('zip', 'abcde', 'Zip code format'),
            ('postcode', '!@#$%', 'Postcode format'),
            ('ssn', 'abc-de-fghi', 'SSN format'),
        ]
        
        for param_pattern, test_value, description in bypass_tests:
            # Find matching parameter
            matching_param = None
            for param_name in params.keys():
                if param_pattern in param_name.lower():
                    matching_param = param_name
                    break
            
            if not matching_param:
                continue
            
            test_params = params.copy()
            test_params[matching_param] = test_value
            
            try:
                response = await self.make_request(session, "POST", url, data=test_params)
                
                if response and response.status in [200, 201]:
                    body = await response.text()
                    
                    # Check if it was accepted (not a validation error)
                    error_indicators = [
                        'invalid', 'error', 'validation', 'required',
                        'format', 'must be', 'should be', 'not valid'
                    ]
                    
                    if not any(ind in body.lower() for ind in error_indicators):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Client-Side Validation Bypass",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=matching_param,
                            payload=test_value,
                            evidence=f"Server accepted invalid value: {description} bypass",
                            description=f"The application relies on client-side validation for '{matching_param}'. Invalid data was accepted by the server.",
                            cwe_id="CWE-602",
                            cvss_score=5.0,
                            remediation="Always validate input server-side. Client-side validation is for UX only.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/602.html"
                            ]
                        ))
                        break
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_privilege_escalation(self, body: str, status: int) -> bool:
        """Check if response indicates successful privilege escalation"""
        if status not in [200, 201]:
            return False
        
        body_lower = body.lower()
        
        # Positive indicators
        positive = [
            'admin', 'administrator', 'dashboard', 'control panel',
            'manage', 'settings', 'configuration', 'system',
            'superuser', 'elevated', 'privileged'
        ]
        
        # Negative indicators
        negative = [
            'unauthorized', 'forbidden', 'access denied', 'not allowed',
            'permission denied', 'invalid', 'error'
        ]
        
        has_positive = any(p in body_lower for p in positive)
        has_negative = any(n in body_lower for n in negative)
        
        return has_positive and not has_negative