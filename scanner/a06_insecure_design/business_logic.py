# scanner/insecure_design/business_logic.py
"""
Business Logic Vulnerability Scanner

Detects business logic flaws including:
- Rate/limit bypass
- Workflow bypass
- Price manipulation
- Quantity manipulation
- Negative value abuse

OWASP: A06:2025 - Insecure Design
CWE-841: Improper Enforcement of Behavioral Workflow
CWE-799: Improper Control of Interaction Frequency
"""

import re
import asyncio
from typing import List, Dict, Optional, Any
import aiohttp
import json

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class BusinessLogicScanner(BaseScanner):
    """Scanner for Business Logic vulnerabilities"""
    
    name = "Business Logic Scanner"
    description = "Detects business logic flaws, workflow bypass, and parameter manipulation"
    owasp_category = OWASPCategory.A06_INSECURE_DESIGN
    
    # Parameters commonly involved in business logic
    NUMERIC_PARAMS = [
        'price', 'amount', 'quantity', 'qty', 'total', 'subtotal',
        'discount', 'tax', 'shipping', 'fee', 'cost', 'value',
        'count', 'limit', 'max', 'min', 'rate', 'points', 'credits',
        'balance', 'withdraw', 'deposit', 'transfer',
    ]
    
    # Workflow/state parameters
    WORKFLOW_PARAMS = [
        'step', 'stage', 'status', 'state', 'phase', 'action',
        'next', 'previous', 'skip', 'complete', 'confirm',
        'approved', 'verified', 'paid', 'processed',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for business logic vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Test 1: Negative value manipulation
        neg_vulns = await self._test_negative_values(session, url, params)
        vulnerabilities.extend(neg_vulns)
        
        # Test 2: Zero value manipulation
        zero_vulns = await self._test_zero_values(session, url, params)
        vulnerabilities.extend(zero_vulns)
        
        # Test 3: Large value manipulation
        large_vulns = await self._test_large_values(session, url, params)
        vulnerabilities.extend(large_vulns)
        
        # Test 4: Decimal/float manipulation
        decimal_vulns = await self._test_decimal_values(session, url, params)
        vulnerabilities.extend(decimal_vulns)
        
        # Test 5: Workflow bypass
        workflow_vulns = await self._test_workflow_bypass(session, url, params)
        vulnerabilities.extend(workflow_vulns)
        
        # Test 6: Parameter removal
        removal_vulns = await self._test_parameter_removal(session, url, params)
        vulnerabilities.extend(removal_vulns)
        
        return vulnerabilities
    
    async def _test_negative_values(self, session: aiohttp.ClientSession,
                                     url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for negative value manipulation"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            # Check if parameter is numeric-related
            if not self._is_numeric_param(param_name, param_value):
                continue
            
            # Test negative values
            negative_values = ['-1', '-100', '-999999']
            
            for neg_val in negative_values:
                test_params = params.copy()
                test_params[param_name] = neg_val
                
                try:
                    response = await self.make_request(session, "POST", url, data=test_params)
                    if not response:
                        response = await self.make_request(session, "GET", url, params=test_params)
                    
                    if response and response.status in [200, 201]:
                        body = await response.text()
                        
                        # Check for success indicators
                        if self._indicates_success(body):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Negative Value Manipulation",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=neg_val,
                                evidence=f"Server accepted negative value for {param_name}",
                                description=f"The application accepts negative values for '{param_name}', which could lead to business logic bypass (e.g., negative prices, refund abuse).",
                                cwe_id="CWE-841",
                                cvss_score=7.5,
                                remediation="Validate that numeric parameters are within expected positive ranges.",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation"
                                ]
                            ))
                            break
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_zero_values(self, session: aiohttp.ClientSession,
                                 url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for zero value manipulation"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            if not self._is_numeric_param(param_name, param_value):
                continue
            
            # Skip if already zero
            if param_value in ['0', '0.0', '0.00']:
                continue
            
            test_params = params.copy()
            test_params[param_name] = '0'
            
            try:
                response = await self.make_request(session, "POST", url, data=test_params)
                if not response:
                    response = await self.make_request(session, "GET", url, params=test_params)
                
                if response and response.status in [200, 201]:
                    body = await response.text()
                    
                    if self._indicates_success(body):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Zero Value Bypass",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload='0',
                            evidence=f"Server accepted zero value for {param_name}",
                            description=f"The application accepts zero for '{param_name}', potentially allowing free purchases or service bypass.",
                            cwe_id="CWE-841",
                            cvss_score=6.5,
                            remediation="Validate that required numeric values are greater than zero where appropriate.",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"
                            ]
                        ))
                        break
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_large_values(self, session: aiohttp.ClientSession,
                                  url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for integer overflow or large value handling"""
        vulnerabilities = []
        
        large_values = [
            '999999999',
            '2147483647',  # Max 32-bit int
            '9223372036854775807',  # Max 64-bit int
            '99999999999999999999',  # Overflow attempt
        ]
        
        for param_name, param_value in params.items():
            if not self._is_numeric_param(param_name, param_value):
                continue
            
            for large_val in large_values:
                test_params = params.copy()
                test_params[param_name] = large_val
                
                try:
                    response = await self.make_request(session, "POST", url, data=test_params)
                    if not response:
                        response = await self.make_request(session, "GET", url, params=test_params)
                    
                    if response:
                        body = await response.text()
                        
                        # Check for errors indicating overflow
                        overflow_indicators = [
                            'overflow', 'out of range', 'too large', 'invalid',
                            'error', 'exception', 'negative', '-'
                        ]
                        
                        if response.status == 500 or any(ind in body.lower() for ind in overflow_indicators):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Integer Overflow/Large Value Handling",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter=param_name,
                                payload=large_val,
                                evidence=f"Server error or unexpected behavior with large value",
                                description=f"The application may have integer overflow issues with '{param_name}'.",
                                cwe_id="CWE-190",
                                cvss_score=5.5,
                                remediation="Implement proper bounds checking and use appropriate data types.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/190.html"
                                ]
                            ))
                            break
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_decimal_values(self, session: aiohttp.ClientSession,
                                    url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for decimal/rounding manipulation"""
        vulnerabilities = []
        
        decimal_payloads = [
            '0.001',
            '0.0001',
            '0.00001',
            '1.999999999999999',
            '0.1 + 0.2',  # Floating point precision test
        ]
        
        for param_name, param_value in params.items():
            if not self._is_numeric_param(param_name, param_value):
                continue
            
            for decimal_val in decimal_payloads:
                test_params = params.copy()
                test_params[param_name] = decimal_val
                
                try:
                    response = await self.make_request(session, "POST", url, data=test_params)
                    if response and response.status in [200, 201]:
                        body = await response.text()
                        
                        if self._indicates_success(body):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Decimal Value Manipulation",
                                severity=Severity.LOW,
                                url=url,
                                parameter=param_name,
                                payload=decimal_val,
                                evidence=f"Server accepted unusual decimal value",
                                description=f"The application accepts unusual decimal values for '{param_name}', which may lead to rounding errors or price manipulation.",
                                cwe_id="CWE-682",
                                cvss_score=4.0,
                                remediation="Use fixed-point arithmetic for financial calculations. Validate decimal precision.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/682.html"
                                ]
                            ))
                            break
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_workflow_bypass(self, session: aiohttp.ClientSession,
                                     url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for workflow/step bypass"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            param_lower = param_name.lower()
            
            # Check if it's a workflow-related parameter
            if not any(wp in param_lower for wp in self.WORKFLOW_PARAMS):
                continue
            
            # Try to skip steps or set to final state
            bypass_values = [
                'complete', 'completed', 'done', 'finished',
                'approved', 'verified', 'confirmed', 'paid',
                '99', '100', 'final', 'last', 'skip',
                'true', '1', 'yes',
            ]
            
            for bypass_val in bypass_values:
                test_params = params.copy()
                test_params[param_name] = bypass_val
                
                try:
                    response = await self.make_request(session, "POST", url, data=test_params)
                    if response and response.status in [200, 201]:
                        body = await response.text()
                        
                        # Check for success indicators
                        success_patterns = [
                            'success', 'complete', 'approved', 'confirmed',
                            'thank you', 'order placed', 'payment received'
                        ]
                        
                        if any(pat in body.lower() for pat in success_patterns):
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="Workflow Bypass",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=bypass_val,
                                evidence=f"Workflow step bypassed by manipulating '{param_name}'",
                                description=f"The application allows bypassing workflow steps by manipulating the '{param_name}' parameter.",
                                cwe_id="CWE-841",
                                cvss_score=8.0,
                                remediation="Enforce workflow state server-side. Don't trust client-provided state values.",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Test_for_the_Circumvention_of_Work_Flows"
                                ]
                            ))
                            return vulnerabilities
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_parameter_removal(self, session: aiohttp.ClientSession,
                                       url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test removing critical parameters"""
        vulnerabilities = []
        
        # Parameters that shouldn't be removable
        critical_params = ['price', 'amount', 'total', 'cost', 'fee', 'tax', 'user_id', 'account']
        
        for param_name in list(params.keys()):
            if not any(cp in param_name.lower() for cp in critical_params):
                continue
            
            # Remove the parameter
            test_params = {k: v for k, v in params.items() if k != param_name}
            
            if not test_params:
                continue
            
            try:
                response = await self.make_request(session, "POST", url, data=test_params)
                if response and response.status in [200, 201]:
                    body = await response.text()
                    
                    if self._indicates_success(body):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Critical Parameter Removal",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload="[REMOVED]",
                            evidence=f"Request succeeded without required parameter '{param_name}'",
                            description=f"The application processes requests even when critical parameter '{param_name}' is removed.",
                            cwe_id="CWE-20",
                            cvss_score=6.0,
                            remediation="Validate that all required parameters are present and have valid values.",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"
                            ]
                        ))
                        break
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_numeric_param(self, param_name: str, param_value: str) -> bool:
        """Check if parameter appears to be numeric"""
        # Check name
        if any(np in param_name.lower() for np in self.NUMERIC_PARAMS):
            return True
        
        # Check if value is numeric
        try:
            float(param_value)
            return True
        except (ValueError, TypeError):
            return False
    
    def _indicates_success(self, body: str) -> bool:
        """Check if response indicates successful operation"""
        body_lower = body.lower()
        
        success_indicators = [
            'success', 'successful', 'completed', 'confirmed',
            'approved', 'accepted', 'processed', 'thank you',
            '"status":"ok"', '"success":true', '"error":false',
            'order placed', 'payment received'
        ]
        
        failure_indicators = [
            'error', 'failed', 'invalid', 'denied', 'rejected',
            'unauthorized', 'forbidden', 'not allowed'
        ]
        
        has_success = any(ind in body_lower for ind in success_indicators)
        has_failure = any(ind in body_lower for ind in failure_indicators)
        
        return has_success and not has_failure