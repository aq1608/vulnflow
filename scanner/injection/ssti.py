# scanner/injection/ssti.py (continued)
"""Server-Side Template Injection (SSTI) Scanner"""

import re
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SSTIScanner(BaseScanner):
    """Scanner for Server-Side Template Injection vulnerabilities"""
    
    name = "SSTI Scanner"
    description = "Detects Server-Side Template Injection vulnerabilities"
    owasp_category = OWASPCategory.A03_INJECTION
    
    # SSTI payloads with expected results
    PAYLOADS = [
        # Generic math-based detection
        ('{{7*7}}', '49', 'Jinja2/Twig'),
        ('${7*7}', '49', 'FreeMarker/Velocity'),
        ('#{7*7}', '49', 'Ruby ERB/Java EL'),
        ('<%= 7*7 %>', '49', 'ERB/EJS'),
        ('{{= 7*7}}', '49', 'Handlebars'),
        ('${{7*7}}', '49', 'Spring'),
        
        # Jinja2 (Python)
        ('{{config}}', 'Config', 'Jinja2'),
        ('{{self}}', 'TemplateReference', 'Jinja2'),
        ("{{''.__class__}}", 'str', 'Jinja2'),
        
        # Twig (PHP)
        ('{{_self}}', 'Template', 'Twig'),
        ('{{_self.env}}', 'Environment', 'Twig'),
        
        # FreeMarker (Java)
        ('${7*7}', '49', 'FreeMarker'),
        ('${class.getClassLoader()}', 'ClassLoader', 'FreeMarker'),
        
        # Velocity (Java)
        ('#set($x=7*7)$x', '49', 'Velocity'),
        
        # Smarty (PHP)
        ('{php}echo 7*7;{/php}', '49', 'Smarty'),
        ('{7*7}', '49', 'Smarty'),
        
        # Mako (Python)
        ('${7*7}', '49', 'Mako'),
        
        # ERB (Ruby)
        ('<%= 7*7 %>', '49', 'ERB'),
        
        # Pebble/Nunjucks
        ('{{7*7}}', '49', 'Pebble/Nunjucks'),
        
        # Thymeleaf (Java)
        ('__${7*7}__', '49', 'Thymeleaf'),
        ('[[${7*7}]]', '49', 'Thymeleaf'),
    ]
    
    # Error patterns indicating SSTI
    SSTI_ERRORS = [
        r'TemplateSyntaxError',
        r'TemplateError',
        r'UndefinedError',
        r'jinja2',
        r'Twig_Error',
        r'freemarker\.core',
        r'VelocityException',
        r'Smarty.*error',
        r'mako.*exception',
        r'ActionView::Template',
        r'thymeleaf',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for SSTI vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        for param_name, param_value in params.items():
            vuln = await self._test_parameter(session, url, params, param_name)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str],
                               param_name: str) -> Optional[Vulnerability]:
        """Test a parameter for SSTI vulnerabilities"""
        
        for payload, expected, engine in self.PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            response = await self.make_request(session, "GET", url, params=test_params)
            if not response:
                continue
            
            body = await response.text()
            
            # Check for expected result (successful template execution)
            if expected in body:
                # Verify it's not just reflected
                if payload not in body:
                    return self.create_vulnerability(
                        vuln_type="Server-Side Template Injection (SSTI)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Template expression evaluated. Expected '{expected}' found in response. Engine: {engine}",
                        description=f"The application is vulnerable to SSTI using {engine}. This can lead to remote code execution.",
                        cwe_id="CWE-1336",
                        cvss_score=9.8,
                        remediation="Never pass user input directly to template engines. Use sandboxed template environments. Implement strict input validation.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                            "https://portswigger.net/research/server-side-template-injection"
                        ]
                    )
            
            # Check for template errors
            for pattern in self.SSTI_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    return self.create_vulnerability(
                        vuln_type="Server-Side Template Injection (Error-based)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Template error detected: {re.search(pattern, body, re.IGNORECASE).group()[:100]}",
                        description="The application exposes template errors, indicating potential SSTI vulnerability.",
                        cwe_id="CWE-1336",
                        cvss_score=7.5,
                        remediation="Handle template errors gracefully. Never expose error messages to users.",
                        references=[
                            "https://portswigger.net/research/server-side-template-injection"
                        ]
                    )
        
        return None