# scanner/misconfig/debug.py
"""Debug Mode Detection Scanner"""

import re
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urljoin

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class DebugModeScanner(BaseScanner):
    """Scanner for Debug Mode and Development Configuration issues"""
    
    name = "Debug Mode Scanner"
    description = "Detects debug mode and development configurations exposed in production"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Debug endpoints to check
    DEBUG_ENDPOINTS = [
        ('/__debug__/', 'Django Debug Toolbar'),
        ('/_debugbar', 'Laravel Debugbar'),
        ('/_profiler/', 'Symfony Profiler'),
        ('/elmah.axd', 'ELMAH Error Log'),
        ('/trace.axd', 'ASP.NET Trace'),
        ('/actuator', 'Spring Boot Actuator'),
        ('/actuator/health', 'Spring Actuator Health'),
        ('/actuator/env', 'Spring Actuator Env'),
        ('/actuator/mappings', 'Spring Actuator Mappings'),
        ('/actuator/configprops', 'Spring Actuator Config'),
        ('/api/debug', 'Debug API'),
        ('/debug', 'Debug Page'),
        ('/console', 'Console'),
        ('/graphql', 'GraphQL (check introspection)'),
        ('/graphiql', 'GraphiQL Interface'),
        ('/__graphql', 'GraphQL Debug'),
        ('/playground', 'GraphQL Playground'),
        ('/metrics', 'Metrics Endpoint'),
        ('/health', 'Health Check'),
        ('/status', 'Status Page'),
        ('/server-status', 'Apache Server Status'),
        ('/server-info', 'Apache Server Info'),
        ('/info', 'Info Endpoint'),
    ]
    
    # Patterns indicating debug mode
    DEBUG_PATTERNS = [
        (r'DEBUG\s*=\s*True', 'Django DEBUG=True'),
        (r'APP_DEBUG\s*=\s*true', 'Laravel APP_DEBUG'),
        (r'FLASK_DEBUG\s*=\s*1', 'Flask Debug Mode'),
        (r'development\s*mode', 'Development Mode'),
        (r'debug\s*mode\s*(is\s*)?(enabled|on|active)', 'Debug Mode Enabled'),
        (r'stack\s*trace', 'Stack Trace Exposed'),
        (r'Traceback\s*\(most\s*recent', 'Python Traceback'),
        (r'at\s+[\w\.]+$[\w\.]+:\d+$', 'Java Stack Trace'),
        (r'Exception\s+in\s+thread', 'Java Exception'),
        (r'<b>Warning</b>:\s+\w+\(\)', 'PHP Warning'),
        (r'<b>Fatal\s+error</b>', 'PHP Fatal Error'),
        (r'Call\s+Stack', 'Debug Call Stack'),
        (r'mysqli?_connect\(', 'Database Connection Info'),
        (r'pg_connect\(', 'PostgreSQL Connection Info'),
        (r'Werkzeug\s+Debugger', 'Werkzeug Debugger'),
        (r'Laravel.*Exception', 'Laravel Exception'),
        (r'Symfony.*Exception', 'Symfony Exception'),
        (r'ExceptionHandler', 'Exception Handler'),
        (r'vendor/laravel', 'Laravel Vendor Path'),
        (r'node_modules', 'Node Modules Path'),
        (r'DOCUMENT_ROOT', 'Document Root Exposed'),
        (r'__FILE__', 'File Path Exposed'),
    ]
    
    # Error trigger payloads
    ERROR_TRIGGERS = [
        ("'", "SQL/Syntax Error"),
        ("{{", "Template Error"),
        ("<script>", "XSS/Parse Error"),
        ("[]", "Type Error"),
        ("null", "Null Reference"),
        ("%s%s%s%s%s", "Format String"),
        ("../../../", "Path Error"),
        ("-1", "Numeric Error"),
        ("9999999999999999", "Integer Overflow"),
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for debug mode and development configurations"""
        vulnerabilities = []
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check debug endpoints
        for endpoint, name in self.DEBUG_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            vuln = await self._check_debug_endpoint(session, test_url, name)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Check for debug info in error responses
        if params:
            vuln = await self._trigger_errors(session, url, params)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Check main page for debug indicators
        vuln = await self._check_page_debug(session, url)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _check_debug_endpoint(self, session: aiohttp.ClientSession,
                                     url: str, name: str) -> Optional[Vulnerability]:
        """Check if a debug endpoint is accessible"""
        
        response = await self.make_request(session, "GET", url)
        if not response:
            return None
        
        if response.status == 200:
            body = await response.text()
            
            # Verify it's actually debug content
            if self._is_debug_content(body, name):
                severity = Severity.HIGH if 'actuator' in url.lower() or 'env' in url.lower() else Severity.MEDIUM
                
                return self.create_vulnerability(
                    vuln_type=f"Debug Endpoint Exposed: {name}",
                    severity=severity,
                    url=url,
                    evidence=f"{name} is accessible at {url}",
                    description=f"The debug endpoint '{name}' is exposed and accessible. This may leak sensitive information about the application.",
                    cwe_id="CWE-489",
                    cvss_score=7.5 if severity == Severity.HIGH else 5.3,
                    remediation="Disable debug endpoints in production. Implement authentication for administrative endpoints.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
                    ]
                )
        
        return None
    
    def _is_debug_content(self, body: str, name: str) -> bool:
        """Verify the content is actually debug-related"""
        debug_keywords = [
            'debug', 'profiler', 'stack', 'trace', 'exception',
            'error', 'dump', 'variable', 'environment', 'config',
            'database', 'query', 'request', 'session', 'actuator',
            'health', 'metrics', 'graphql', 'schema', 'introspection'
        ]
        
        body_lower = body.lower()
        return any(kw in body_lower for kw in debug_keywords)
    
    async def _trigger_errors(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str]) -> Optional[Vulnerability]:
        """Try to trigger error messages"""
        
        for trigger, trigger_name in self.ERROR_TRIGGERS:
            # Test each parameter
            for param_name in params:
                test_params = params.copy()
                test_params[param_name] = trigger
                
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                
                # Check for debug patterns in response
                for pattern, debug_name in self.DEBUG_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        return self.create_vulnerability(
                            vuln_type=f"Debug Information Disclosure: {debug_name}",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload=trigger,
                            evidence=f"Debug pattern '{debug_name}' found in error response",
                            description="The application exposes detailed debug information in error responses, which may help attackers understand the system.",
                            cwe_id="CWE-209",
                            cvss_score=5.3,
                            remediation="Disable debug mode in production. Implement custom error pages that don't expose technical details.",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"
                            ]
                        )
        
        return None
    
    async def _check_page_debug(self, session: aiohttp.ClientSession,
                                 url: str) -> Optional[Vulnerability]:
        """Check the main page for debug indicators"""
        
        response = await self.make_request(session, "GET", url)
        if not response:
            return None
        
        body = await response.text()
        
        for pattern, debug_name in self.DEBUG_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return self.create_vulnerability(
                    vuln_type=f"Debug Mode Indicator: {debug_name}",
                    severity=Severity.LOW,
                    url=url,
                    evidence=f"Debug indicator '{debug_name}' found on page",
                    description="The page contains debug mode indicators, suggesting the application may be running in development mode.",
                    cwe_id="CWE-489",
                    cvss_score=3.1,
                    remediation="Ensure the application is running in production mode with debug features disabled.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
                    ]
                )
        
        return None