"""Sensitive Log Data Scanner (CWE-532)"""

from typing import List, Dict, Optional
import aiohttp
import re

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SensitiveLogDataScanner(BaseScanner):
    """
    Scanner for Sensitive Information in Log Files / Error Messages (CWE-532).
    
    Detects when applications expose sensitive data in:
    1. Error messages that may be logged
    2. Debug output visible to users
    3. Stack traces containing sensitive info
    4. Verbose error responses
    """
    
    name = "Sensitive Log Data Scanner"
    description = "Detects sensitive information exposure in error responses and logs"
    owasp_category = OWASPCategory.A09_LOGGING_ALERTING_FAILURES
    
    # Patterns indicating sensitive data in responses (potentially logged)
    SENSITIVE_DATA_PATTERNS = {
        'password_in_error': {
            'patterns': [
                r'password["\s:=]+["\']?[\w@#$%^&*!]+["\']?',
                r'pwd["\s:=]+["\']?[\w@#$%^&*!]+["\']?',
                r'passwd["\s:=]+["\']?[\w@#$%^&*!]+',
            ],
            'severity': Severity.HIGH,
            'description': 'Password visible in error response',
            'cwe': 'CWE-532'
        },
        'api_key_exposure': {
            'patterns': [
                r'api[_-]?key["\s:=]+["\']?[a-zA-Z0-9_\-]{20,}["\']?',
                r'apikey["\s:=]+["\']?[a-zA-Z0-9_\-]{16,}["\']?',
                r'secret[_-]?key["\s:=]+["\']?[a-zA-Z0-9_\-]{16,}["\']?',
                r'access[_-]?token["\s:=]+["\']?[a-zA-Z0-9_\-\.]{20,}["\']?',
                r'bearer\s+[a-zA-Z0-9_\-\.]{20,}',
            ],
            'severity': Severity.HIGH,
            'description': 'API key or secret token exposed in response',
            'cwe': 'CWE-532'
        },
        'database_credentials': {
            'patterns': [
                r'(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@',
                r'connection[_-]?string["\s:=]+["\']?[^"\']+["\']?',
                r'(?:db|database)[_-]?(?:user|pass|password)["\s:=]+',
            ],
            'severity': Severity.CRITICAL,
            'description': 'Database credentials exposed in response',
            'cwe': 'CWE-532'
        },
        'session_data': {
            'patterns': [
                r'session[_-]?id["\s:=]+["\']?[a-zA-Z0-9]{16,}["\']?',
                r'PHPSESSID[=:][a-zA-Z0-9]{16,}',
                r'JSESSIONID[=:][a-zA-Z0-9]{16,}',
                r'ASP\.NET_SessionId[=:][a-zA-Z0-9]{16,}',
            ],
            'severity': Severity.MEDIUM,
            'description': 'Session identifier exposed in error response',
            'cwe': 'CWE-532'
        },
        'pii_data': {
            'patterns': [
                r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b.*\b\d{3}-\d{2}-\d{4}\b',  # Name + SSN
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
                r'\b(?:\d{4}[-\s]?){3}\d{4}\b',  # Credit card pattern
                r'(?:email|e-mail)["\s:=]+["\']?[\w\.-]+@[\w\.-]+\.[a-z]{2,}["\']?',
            ],
            'severity': Severity.HIGH,
            'description': 'Personally Identifiable Information (PII) in response',
            'cwe': 'CWE-532'
        },
        'internal_paths': {
            'patterns': [
                r'[C-Z]:\\(?:Users|Windows|Program Files)[\\][^\s<>"]+',
                r'/(?:home|var|etc|usr)/[^\s<>"]+',
                r'/(?:app|application|www|htdocs)/[^\s<>"]+\.(?:py|php|js|rb|java)',
            ],
            'severity': Severity.LOW,
            'description': 'Internal file paths exposed in response',
            'cwe': 'CWE-532'
        },
        'stack_trace': {
            'patterns': [
                r'(?:Exception|Error|Traceback)[\s\S]{0,50}at\s+[\w\.]+$[\w\.]+:\d+$',
                r'File\s+"[^"]+",\s+line\s+\d+',  # Python traceback
                r'#\d+\s+[\w\\/:]+$\d+$:',  # PHP stack trace
                r'java\.[\w\.]+Exception',
                r'System\.[\w\.]+Exception',  # .NET
            ],
            'severity': Severity.MEDIUM,
            'description': 'Stack trace exposed in response',
            'cwe': 'CWE-209'
        },
        'sql_query': {
            'patterns': [
                r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.{10,}(?:FROM|INTO|SET|TABLE)',
                r'(?:sql|query)["\s:=]+["\']?(?:SELECT|INSERT|UPDATE|DELETE)',
            ],
            'severity': Severity.MEDIUM,
            'description': 'SQL query exposed in error response',
            'cwe': 'CWE-209'
        },
    }
    
    # Payloads designed to trigger verbose errors
    ERROR_TRIGGER_PAYLOADS = [
        "{{invalid}}",
        "${invalid}",
        "<?xml version='1.0'?><!DOCTYPE x>",
        "'\"<>",
        "' OR '1'='1",
        "-1",
        "99999999999999999999",
        "null",
        "undefined",
        "NaN",
        "%00",
        "../../../etc/passwd",
        "AAAA" * 1000,  # Long string
    ]

    async def scan(self, session: aiohttp.ClientSession,
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for sensitive data exposure in error responses"""
        vulnerabilities = []
        
        # Check normal response for sensitive data
        normal_vulns = await self._check_normal_response(session, url, params)
        vulnerabilities.extend(normal_vulns)
        
        # Trigger errors and check for sensitive data
        error_vulns = await self._trigger_and_check_errors(session, url, params)
        vulnerabilities.extend(error_vulns)
        
        # Check 404/error pages
        error_page_vulns = await self._check_error_pages(session, url)
        vulnerabilities.extend(error_page_vulns)
        
        return vulnerabilities
    
    async def _check_normal_response(self, session: aiohttp.ClientSession,
                                      url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Check normal response for sensitive data leakage"""
        vulnerabilities = []
        
        response = await self.make_request(session, "GET", url, params=params)
        if not response:
            return vulnerabilities
        
        try:
            body = await response.text()
            vulns = self._analyze_response_for_sensitive_data(url, body, "normal response")
            vulnerabilities.extend(vulns)
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _trigger_and_check_errors(self, session: aiohttp.ClientSession,
                                         url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Trigger error conditions and check for sensitive data"""
        vulnerabilities = []
        found_categories = set()  # Avoid duplicate findings
        
        if not params:
            params = {'test': 'value'}
        
        for param_name in list(params.keys())[:3]:  # Limit params tested
            for payload in self.ERROR_TRIGGER_PAYLOADS[:6]:  # Limit payloads
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                try:
                    body = await response.text()
                    
                    # Look for error indicators
                    if response.status >= 400 or self._looks_like_error(body):
                        vulns = self._analyze_response_for_sensitive_data(
                            url, body, f"error triggered by {param_name}={payload}",
                            found_categories
                        )
                        for vuln in vulns:
                            vuln.parameter = param_name
                            vuln.payload = payload
                        vulnerabilities.extend(vulns)
                        
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _check_error_pages(self, session: aiohttp.ClientSession,
                                  url: str) -> List[Vulnerability]:
        """Check standard error pages for sensitive data"""
        vulnerabilities = []
        
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common paths that might show verbose errors
        error_paths = [
            '/nonexistent-page-' + 'x' * 20,
            '/error',
            '/debug',
            '/.env',
            '/config',
            '/test',
            '/phpinfo.php',
            '/server-status',
        ]
        
        for path in error_paths:
            test_url = base + path
            response = await self.make_request(session, "GET", test_url)
            if not response:
                continue
            
            try:
                body = await response.text()
                vulns = self._analyze_response_for_sensitive_data(
                    test_url, body, f"error page at {path}"
                )
                vulnerabilities.extend(vulns)
            except Exception:
                continue
        
        return vulnerabilities
    
    def _looks_like_error(self, body: str) -> bool:
        """Check if response looks like an error page"""
        error_indicators = [
            'exception', 'error', 'traceback', 'stack trace',
            'fatal', 'warning', 'notice', 'debug', 'failed',
            'syntax error', 'undefined', 'null pointer'
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in error_indicators)
    
    def _analyze_response_for_sensitive_data(self, url: str, body: str,
                                              context: str,
                                              found_categories: set = None) -> List[Vulnerability]:
        """Analyze response body for sensitive data patterns"""
        vulnerabilities = []
        if found_categories is None:
            found_categories = set()
        
        for category, config in self.SENSITIVE_DATA_PATTERNS.items():
            if category in found_categories:
                continue
                
            for pattern in config['patterns']:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    found_categories.add(category)
                    
                    # Sanitize the matched content for the report
                    matched_text = match.group(0)
                    if len(matched_text) > 100:
                        matched_text = matched_text[:100] + "..."
                    # Redact actual sensitive values
                    sanitized_evidence = self._redact_sensitive_value(matched_text)
                    
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type=f"Sensitive Data Exposure: {config['description']}",
                        severity=config['severity'],
                        url=url,
                        evidence=f"Found in {context}: {sanitized_evidence}",
                        description=(
                            f"{config['description']}. "
                            f"Sensitive information was detected in the application response. "
                            "This data may also be written to application logs, potentially exposing it to:\n"
                            "- Unauthorized staff with log access\n"
                            "- Attackers who compromise log storage\n"
                            "- Third-party log aggregation services\n"
                            "- Backup systems containing logs"
                        ),
                        cwe_id=config['cwe'],
                        cvss_score=self._severity_to_cvss(config['severity']),
                        remediation=(
                            "1. Never log sensitive data (passwords, tokens, PII, credentials)\n"
                            "2. Implement log data masking/redaction for sensitive fields\n"
                            "3. Configure error handling to show generic messages to users\n"
                            "4. Use separate detailed logging for development only\n"
                            "5. Implement log data classification and retention policies\n"
                            "6. Review and sanitize all error messages before production"
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                            "https://cwe.mitre.org/data/definitions/532.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
                        ]
                    ))
                    break  # One finding per category
        
        return vulnerabilities
    
    def _redact_sensitive_value(self, text: str) -> str:
        """Redact actual sensitive values from evidence"""
        # Redact anything that looks like a secret value
        redacted = re.sub(r'(password|pwd|secret|key|token)["\s:=]+["\']?[\w@#$%^&*!_\-\.]{4,}',
                         r'\1=*REDACTED*', text, flags=re.IGNORECASE)
        redacted = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****', redacted)  # SSN
        redacted = re.sub(r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '****-****-****-****', redacted)  # CC
        return text
    
    def _severity_to_cvss(self, severity: Severity) -> float:
        """Convert severity to CVSS score"""
        mapping = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 3.1,
            Severity.INFO: 1.0
        }
        return mapping.get(severity, 5.0)