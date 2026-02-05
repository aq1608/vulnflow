# scanner/access_control/idor.py
"""Insecure Direct Object Reference (IDOR) Scanner"""

import re
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class IDORScanner(BaseScanner):
    """Scanner for Insecure Direct Object Reference vulnerabilities"""
    
    name = "IDOR Scanner"
    description = "Detects Insecure Direct Object Reference vulnerabilities"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    # Patterns that indicate potential IDOR parameters
    IDOR_PATTERNS = [
        r'id', r'user_id', r'userid', r'uid',
        r'account', r'account_id', r'accountid',
        r'profile', r'profile_id', r'profileid',
        r'order', r'order_id', r'orderid',
        r'doc', r'doc_id', r'docid', r'document',
        r'file', r'file_id', r'fileid',
        r'report', r'report_id', r'reportid',
        r'invoice', r'invoice_id', r'invoiceid',
        r'record', r'record_id', r'recordid',
        r'item', r'item_id', r'itemid',
        r'no', r'num', r'number',
    ]
    
    # Test values to try for IDOR
    TEST_VALUES = [
        '1', '2', '0', '-1', '999999',
        '00001', '00002',
        'admin', 'root', 'test',
        '../1', '1;2', '1,2',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for IDOR vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Get original response for comparison
        original_response = await self.make_request(session, "GET", url, params=params)
        if not original_response:
            return vulnerabilities
        
        original_status = original_response.status
        original_body = await original_response.text()
        original_length = len(original_body)
        
        # Check each parameter for IDOR patterns
        for param_name, param_value in params.items():
            if self._is_potential_idor_param(param_name):
                vuln = await self._test_idor(
                    session, url, params, param_name, param_value,
                    original_status, original_length
                )
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_potential_idor_param(self, param_name: str) -> bool:
        """Check if parameter name matches IDOR patterns"""
        param_lower = param_name.lower()
        for pattern in self.IDOR_PATTERNS:
            if re.search(pattern, param_lower, re.IGNORECASE):
                return True
        # Also check if value looks like an ID (numeric)
        return False
    
    async def _test_idor(self, session: aiohttp.ClientSession,
                         url: str, params: Dict[str, str],
                         param_name: str, original_value: str,
                         original_status: int, original_length: int) -> Optional[Vulnerability]:
        """Test a specific parameter for IDOR"""
        
        for test_value in self.TEST_VALUES:
            if test_value == original_value:
                continue
            
            # Create modified params
            test_params = params.copy()
            test_params[param_name] = test_value
            
            response = await self.make_request(session, "GET", url, params=test_params)
            if not response:
                continue
            
            status = response.status
            body = await response.text()
            length = len(body)
            
            # Check for IDOR indicators
            # 1. Got 200 OK with different content (might be accessing another user's data)
            if status == 200 and abs(length - original_length) > 50:
                # Check if response contains different user data
                if self._contains_user_data(body):
                    return self.create_vulnerability(
                        vuln_type="Insecure Direct Object Reference (IDOR)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=test_value,
                        evidence=f"Different response received when changing {param_name} from {original_value} to {test_value}. Response length changed from {original_length} to {length}",
                        description="The application may be vulnerable to IDOR. Changing the object reference returned different data, suggesting unauthorized access to other users' resources.",
                        cwe_id="CWE-639",
                        cvss_score=7.5,
                        remediation="Implement proper access controls. Verify that the authenticated user has permission to access the requested resource. Use indirect references or UUIDs instead of sequential IDs.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                            "https://cwe.mitre.org/data/definitions/639.html"
                        ]
                    )
            
            # 2. Got 200 instead of 403/404 (no authorization check)
            if status == 200 and test_value in ['0', '-1', '999999']:
                if not self._is_error_page(body):
                    return self.create_vulnerability(
                        vuln_type="Potential IDOR - Missing Authorization",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=param_name,
                        payload=test_value,
                        evidence=f"Request with {param_name}={test_value} returned 200 OK instead of 403/404",
                        description="The application accepted an unusual ID value without returning an error, suggesting missing authorization checks.",
                        cwe_id="CWE-639",
                        cvss_score=5.3,
                        remediation="Implement authorization checks to verify the user has access to the requested resource.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"
                        ]
                    )
        
        return None
    
    def _contains_user_data(self, body: str) -> bool:
        """Check if response contains user-related data"""
        user_data_patterns = [
            r'email.*@.*\.',
            r'username',
            r'phone.*\d{3}',
            r'address',
            r'password',
            r'credit.*card',
            r'ssn',
            r'social.*security',
            r'"name"\s*:',
            r'"user"\s*:',
        ]
        
        for pattern in user_data_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False
    
    def _is_error_page(self, body: str) -> bool:
        """Check if response is an error page"""
        error_indicators = [
            'not found', '404', 'error', 'invalid',
            'does not exist', 'no record', 'forbidden',
            'unauthorized', 'access denied'
        ]
        
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in error_indicators)