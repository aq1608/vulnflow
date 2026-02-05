# scanner/exceptional_conditions/error_handling.py
"""
Error Handling Scanner

Detects improper error handling:
- Verbose error messages exposing sensitive data
- Stack traces in responses
- Debug information leakage
- Database error messages
- Framework-specific error pages

OWASP: A10:2025 - Mishandling of Exceptional Conditions
CWE-209: Generation of Error Message Containing Sensitive Information
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class ErrorHandlingScanner(BaseScanner):
    """Scanner for improper error handling vulnerabilities"""
    
    name = "Error Handling Scanner"
    description = "Detects verbose error messages and improper exception handling"
    owasp_category = OWASPCategory.A10_EXCEPTIONAL_CONDITIONS
    
    def __init__(self):
        super().__init__()
        
        # Payloads designed to trigger errors
        self.error_payloads = {
            'sql_error': [
                "'"
                "1' OR '1'='1",
                "1; DROP TABLE test--",
                "' UNION SELECT NULL--",
            ],
            'type_error': [
                "[]",
                "{}",
                "null",
                "undefined",
                "-1",
                "99999999999999999999",
                "0",
                "NaN",
                "Infinity",
            ],
            'format_string': [
                "%s%s%s%s%s",
                "%x%x%x%x",
                "%n%n%n%n",
                "{0}{1}{2}",
                "{{constructor}}",
            ],
            'path_error': [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "/etc/passwd%00",
                "C:\\Windows\\system.ini",
                "file:///etc/passwd",
            ],
            'xml_error': [
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "<![CDATA[<script>alert(1)</script>]]>",
            ],
            'special_chars': [
                "\x00",
                "\r\n",
                "\n\n",
                "\\",
                "\\\\",
                "${7*7}",
                "{{7*7}}",
            ],
        }
        
        # Patterns indicating sensitive error information
        self.error_patterns = [
            # Stack traces
            {
                'pattern': r'at\s+[\w.]+\s*$[^)]*:\d+:\d+$',
                'type': 'JavaScript Stack Trace',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'File\s+"[^"]+",\s+line\s+\d+',
                'type': 'Python Stack Trace',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'at\s+[\w.]+\.[\w<>]+$[^)]*\.java:\d+$',
                'type': 'Java Stack Trace',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'at\s+[\w.]+\.[\w<>]+$[^)]*\.cs:\d+$',
                'type': '.NET Stack Trace',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'#\d+\s+[\w\\/:]+\.php$\d+$:',
                'type': 'PHP Stack Trace',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'from\s+[\w/]+\.rb:\d+:in\s+',
                'type': 'Ruby Stack Trace',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'goroutine\s+\d+\s+\[[\w\s]+\]:',
                'type': 'Go Stack Trace',
                'severity': Severity.MEDIUM,
            },
            
            # Database errors
            {
                'pattern': r'mysql_fetch|mysql_query|mysqli_|PDOException',
                'type': 'MySQL Error',
                'severity': Severity.HIGH,
            },
            {
                'pattern': r'pg_query|pg_exec|PostgreSQL|PG::',
                'type': 'PostgreSQL Error',
                'severity': Severity.HIGH,
            },
            {
                'pattern': r'ORA-\d{5}|Oracle\s+error',
                'type': 'Oracle Error',
                'severity': Severity.HIGH,
            },
            {
                'pattern': r'Microsoft\s+OLE\s+DB|ODBC\s+SQL\s+Server|SqlException',
                'type': 'SQL Server Error',
                'severity': Severity.HIGH,
            },
            {
                'pattern': r'sqlite3?_|SQLite.*error',
                'type': 'SQLite Error',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'MongoDB\s+Error|MongoError|MongoException',
                'type': 'MongoDB Error',
                'severity': Severity.HIGH,
            },
            
            # Framework errors
            {
                'pattern': r'Django\s+Version:|Traceback.*django',
                'type': 'Django Debug Info',
                'severity': Severity.HIGH,
            },
            {
                'pattern': r'Rails\.root:|ActionController::',
                'type': 'Rails Debug Info',
                'severity': Severity.HIGH,
            },
            {
                'pattern': r'Laravel|Illuminate\\|Whoops!',
                'type': 'Laravel Debug Info',
                'severity': Severity.HIGH,
            },
            {
                'pattern': r'Express\s+Error|at\s+Layer\.handle',
                'type': 'Express.js Error',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'Spring\s+Framework|org\.springframework',
                'type': 'Spring Framework Error',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'ASP\.NET|System\.Web\.|__VIEWSTATE',
                'type': 'ASP.NET Error',
                'severity': Severity.MEDIUM,
            },
            
            # Sensitive information
            {
                'pattern': r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[\w@#$%^&*]+',
                'type': 'Password in Error',
                'severity': Severity.CRITICAL,
            },
            {
                'pattern': r'(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["\']?[\w-]+',
                'type': 'API Key in Error',
                'severity': Severity.CRITICAL,
            },
            {
                'pattern': r'(?:connection[_-]?string|conn[_-]?str)\s*[=:]\s*["\'][^"\']+',
                'type': 'Connection String in Error',
                'severity': Severity.CRITICAL,
            },
            {
                'pattern': r'(?:/home/|/var/www/|C:\\Users\\|C:\\inetpub\\)[\w/\\]+',
                'type': 'File Path Disclosure',
                'severity': Severity.LOW,
            },
            {
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d+)?(?:/[\w.-]+)?',
                'type': 'Internal IP/Path Disclosure',
                'severity': Severity.LOW,
            },
            
            # Error page indicators
            {
                'pattern': r'<title>.*(?:Error|Exception|Fatal|Warning|Notice).*</title>',
                'type': 'Error Page Title',
                'severity': Severity.INFO,
            },
            {
                'pattern': r'(?:Fatal\s+error|Parse\s+error|Warning|Notice):\s+',
                'type': 'PHP Error Message',
                'severity': Severity.MEDIUM,
            },
            {
                'pattern': r'SQLSTATE\[\w+\]',
                'type': 'SQL State Error',
                'severity': Severity.HIGH,
            },
        ]
        
        # Invalid HTTP methods to test error handling
        self.invalid_methods = ['FAKEVERB', 'DEBUG', 'TRACE', 'TRACK', 'CONNECT']
        
        # URLs likely to trigger errors
        self.error_urls = [
            '/error',
            '/404',
            '/500',
            '/undefined',
            '/null',
            '/%00',
            '/..',
            '/~',
            '/?',
            '/#',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for error handling vulnerabilities."""
        vulnerabilities = []
        
        # Test 1: Trigger errors with malformed parameters
        param_vulns = await self._test_parameter_errors(session, url, params)
        vulnerabilities.extend(param_vulns)
        
        # Test 2: Test invalid HTTP methods
        method_vulns = await self._test_invalid_methods(session, url)
        vulnerabilities.extend(method_vulns)
        
        # Test 3: Request non-existent resources
        notfound_vulns = await self._test_error_pages(session, url)
        vulnerabilities.extend(notfound_vulns)
        
        # Test 4: Test malformed requests
        malformed_vulns = await self._test_malformed_requests(session, url)
        vulnerabilities.extend(malformed_vulns)
        
        # Test 5: Analyze existing page for error patterns
        page_vulns = await self._analyze_page_errors(session, url)
        vulnerabilities.extend(page_vulns)
        
        return vulnerabilities
    
    async def _test_parameter_errors(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Test error handling by sending malformed parameters."""
        vulnerabilities = []
        
        if not params:
            params = {'id': '1', 'page': '1', 'search': 'test'}
        
        for category, payloads in self.error_payloads.items():
            for payload in payloads[:3]:  # Limit payloads per category
                for param_name in list(params.keys())[:3]:  # Limit parameters
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        async with session.get(
                            url,
                            params=test_params,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False
                        ) as response:
                            content = await response.text()
                            
                            # Check for error patterns
                            for error_info in self.error_patterns:
                                if re.search(error_info['pattern'], content, re.IGNORECASE):
                                    # Extract a snippet of the error
                                    match = re.search(error_info['pattern'], content, re.IGNORECASE)
                                    snippet = match.group(0)[:200] if match else "Pattern matched"
                                    
                                    vulnerabilities.append(Vulnerability(
                                        vuln_type=f"Error Information Disclosure - {error_info['type']}",
                                        severity=error_info['severity'],
                                        url=url,
                                        parameter=param_name,
                                        payload=payload,
                                        evidence=f"Error pattern detected: {snippet}",
                                        description=f"Application reveals {error_info['type']} when processing malformed input",
                                        cwe_id="CWE-209",
                                        owasp_category=self.owasp_category,
                                        remediation=self._get_error_remediation(error_info['type'])
                                    ))
                                    
                                    # Only report once per parameter/category
                                    break
                    
                    except Exception:
                        continue
        
        return self._deduplicate_vulns(vulnerabilities)
    
    async def _test_invalid_methods(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test error handling for invalid HTTP methods."""
        vulnerabilities = []
        
        for method in self.invalid_methods:
            try:
                async with session.request(
                    method,
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    content = await response.text()
                    
                    # TRACE/TRACK should be disabled
                    if method in ['TRACE', 'TRACK'] and response.status == 200:
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"HTTP {method} Method Enabled",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="HTTP Method",
                            payload=method,
                            evidence=f"{method} method returned HTTP {response.status}",
                            description=f"HTTP {method} method is enabled, which can be used for XST attacks",
                            cwe_id="CWE-16",
                            owasp_category=self.owasp_category,
                            remediation=self._get_method_remediation()
                        ))
                    
                    # Check for verbose error in response
                    for error_info in self.error_patterns:
                        if re.search(error_info['pattern'], content, re.IGNORECASE):
                            vulnerabilities.append(Vulnerability(
                                vuln_type=f"Verbose Error on Invalid Method - {error_info['type']}",
                                severity=Severity.LOW,
                                url=url,
                                parameter="HTTP Method",
                                payload=method,
                                evidence=f"Error details exposed for invalid HTTP method",
                                description=f"Server reveals technical details when handling invalid HTTP method {method}",
                                cwe_id="CWE-209",
                                owasp_category=self.owasp_category,
                                remediation=self._get_error_remediation(error_info['type'])
                            ))
                            break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_error_pages(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test error pages for information disclosure."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for error_path in self.error_urls:
            try:
                test_url = urljoin(base_url, error_path)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    content = await response.text()
                    
                    # Check for verbose error information
                    for error_info in self.error_patterns:
                        if re.search(error_info['pattern'], content, re.IGNORECASE):
                            vulnerabilities.append(Vulnerability(
                                vuln_type=f"Verbose Error Page - {error_info['type']}",
                                severity=error_info['severity'],
                                url=test_url,
                                parameter="error_page",
                                payload=error_path,
                                evidence=f"Error page reveals technical information",
                                description=f"Error page at {error_path} exposes {error_info['type']}",
                                cwe_id="CWE-209",
                                owasp_category=self.owasp_category,
                                remediation=self._get_error_remediation(error_info['type'])
                            ))
                            break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_malformed_requests(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test handling of malformed requests."""
        vulnerabilities = []
        
        malformed_tests = [
            # Malformed Content-Type
            {
                'headers': {'Content-Type': 'application/json'},
                'data': 'not valid json{{{',
                'name': 'Invalid JSON Body'
            },
            # Malformed Accept header
            {
                'headers': {'Accept': '*/*, invalid/type'},
                'data': None,
                'name': 'Malformed Accept Header'
            },
            # Very long header
            {
                'headers': {'X-Custom-Header': 'A' * 10000},
                'data': None,
                'name': 'Oversized Header'
            },
            # Null bytes in header
            {
                'headers': {'X-Test': 'value\x00with\x00nulls'},
                'data': None,
                'name': 'Null Bytes in Header'
            },
        ]
        
        for test in malformed_tests:
            try:
                if test['data']:
                    response = await session.post(
                        url,
                        headers=test['headers'],
                        data=test['data'],
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    )
                else:
                    response = await session.get(
                        url,
                        headers=test['headers'],
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    )
                
                async with response:
                    content = await response.text()
                    
                    for error_info in self.error_patterns:
                        if re.search(error_info['pattern'], content, re.IGNORECASE):
                            vulnerabilities.append(Vulnerability(
                                vuln_type=f"Malformed Request Error - {test['name']}",
                                severity=error_info['severity'],
                                url=url,
                                parameter=test['name'],
                                payload=str(test['headers']),
                                evidence=f"Error exposed when handling {test['name']}",
                                description=f"Application reveals error details when processing {test['name']}",
                                cwe_id="CWE-209",
                                owasp_category=self.owasp_category,
                                remediation=self._get_error_remediation(error_info['type'])
                            ))
                            break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _analyze_page_errors(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Analyze page for existing error patterns."""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                content = await response.text()
                
                # Check for error patterns in normal page content
                for error_info in self.error_patterns:
                    matches = re.findall(error_info['pattern'], content, re.IGNORECASE)
                    if matches:
                        # Increase severity for errors on normal pages
                        severity = error_info['severity']
                        if severity == Severity.LOW:
                            severity = Severity.MEDIUM
                        elif severity == Severity.MEDIUM:
                            severity = Severity.HIGH
                        
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"Error Information in Page - {error_info['type']}",
                            severity=severity,
                            url=url,
                            parameter="page_content",
                            payload="Normal page request",
                            evidence=f"Found {len(matches)} instances of {error_info['type']} in page",
                            description=f"Page contains {error_info['type']} that may expose sensitive information",
                            cwe_id="CWE-209",
                            owasp_category=self.owasp_category,
                            remediation=self._get_error_remediation(error_info['type'])
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _deduplicate_vulns(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            key = (vuln.vuln_type, vuln.url)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def _get_error_remediation(self, error_type: str) -> str:
        """Get error-type-specific remediation advice."""
        return f"""
1. Implement custom error pages that don't reveal technical details:

```python
# Flask example
@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404
```
Disable debug mode in production:
python
# Flask
app.config['DEBUG'] = False

# Django
DEBUG = False

# Express.js
app.set('env', 'production');
Configure logging to file instead of response:
python
import logging
logging.basicConfig(filename='error.log', level=logging.ERROR)
Use try-catch blocks with generic error messages:
python
try:
    # risky operation
except Exception as e:
    logging.error(f"Error: {{e}}")  # Log details
    return "An error occurred", 500  # Generic response
Specific fix for {error_type}:
Ensure database connection strings are in environment variables
Remove debug symbols from production builds
Configure web server to intercept errors before application
"""
    def _get_method_remediation(self) -> str:
        """Get HTTP method remediation advice."""
        return """
Disable TRACE/TRACK methods in web server:
Apache (httpd.conf):

apache
TraceEnable off
nginx (nginx.conf):

nginx
if ($request_method ~ ^(TRACE|TRACK)$) {
    return 405;
}
IIS (web.config):

xml
<system.webServer>
    <security>
        <requestFiltering>
            <verbs>
                <add verb="TRACE" allowed="false" />
                <add verb="TRACK" allowed="false" />
            </verbs>
        </requestFiltering>
    </security>
</system.webServer>
Only allow necessary HTTP methods for each endpoint
Return 405 Method Not Allowed for unsupported methods
Implement proper error handling for unexpected methods
"""