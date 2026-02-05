"""Log File Exposure Scanner"""

from typing import List, Dict, Optional
from urllib.parse import urlparse
import aiohttp
import re

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class LogFileExposureScanner(BaseScanner):
    """
    Scanner for exposed log files accessible via web.
    
    Detects:
    1. Directly accessible log files
    2. Log directories with listing enabled
    3. Backup log files
    4. Common logging endpoints
    """
    
    name = "Log File Exposure Scanner"
    description = "Detects publicly accessible log files and logging endpoints"
    owasp_category = OWASPCategory.A09_LOGGING_ALERTING_FAILURES
    
    # Common log file paths to check
    LOG_FILE_PATHS = [
        # Application logs
        '/logs/',
        '/log/',
        '/logging/',
        '/app/logs/',
        '/application/logs/',
        '/var/log/',
        '/debug/logs/',
        
        # Specific log files
        '/logs/access.log',
        '/logs/error.log',
        '/logs/debug.log',
        '/logs/application.log',
        '/logs/app.log',
        '/logs/system.log',
        '/log/access.log',
        '/log/error.log',
        '/log.txt',
        '/logs.txt',
        '/debug.log',
        '/error.log',
        '/error_log',
        '/access.log',
        '/access_log',
        
        # Framework-specific logs
        '/storage/logs/laravel.log',  # Laravel
        '/var/log/apache2/error.log',
        '/var/log/nginx/error.log',
        '/tmp/logs/',
        '/WEB-INF/logs/',
        '/rails/log/development.log',  # Rails
        '/rails/log/production.log',
        
        # Common backup patterns
        '/logs/error.log.1',
        '/logs/error.log.bak',
        '/logs/error.log.old',
        '/logs/error.log.2024',
        '/logs/error.log.txt',
        '/logs.tar.gz',
        '/logs.zip',
        '/log_backup/',
        
        # Debug/monitoring endpoints
        '/elmah.axd',  # .NET error logging
        '/trace.axd',
        '/server-status',
        '/server-info',
        '/__debug__/',
        '/debug/',
        '/_logs',
        '/actuator/logfile',  # Spring Boot
        '/actuator/logs',
        '/api/logs',
        '/admin/logs',
        '/system/logs',
    ]
    
    # Patterns indicating log file content
    LOG_CONTENT_PATTERNS = [
        r'\d{4}-\d{2}-\d{2}',  # Date in brackets [2024-01-01]
        r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}',  # Timestamp
        r'(?:INFO|DEBUG|WARN|ERROR|FATAL|TRACE)\s*\[',  # Log levels
        r'(?:GET|POST|PUT|DELETE|HEAD)\s+/[^\s]+\s+HTTP/',  # Access log
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+',  # Apache common log
        r'Stack\s*trace:',
        r'Exception\s+in\s+',
        r'Traceback \(most recent',
        r'^\s*at\s+[\w\.]+\$[\w\.]+:+\d+$',  # Java stack trace
        r'PHP\s+(?:Fatal|Warning|Notice|Error)'
    ]

    DIRECTORY_LIST_PATTERNS = [
        r'Index of /',
        r'<title>Directory listing',
        r'Parent Directory',
        r'\[DIR',
        r'<td><a href="[\w\-.]+\.log'
    ]

    async def scan(self, session: aiohttp.ClientSession,
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for exposed log files"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check each potential log path
        for log_path in self.LOG_FILE_PATHS:
            test_url = base_url + log_path
            vuln = await self._check_log_path(session, test_url, log_path)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Check for log files in current directory
        current_dir_vulns = await self._check_current_directory(session, url)
        vulnerabilities.extend(current_dir_vulns)
        
        return vulnerabilities
    
    async def _check_log_path(self, session: aiohttp.ClientSession,
                               url: str, path: str) -> Optional[Vulnerability]:
        """Check if a log path is accessible"""
        response = await self.make_request(session, "GET", url)
        if not response:
            return None
        
        # Skip non-successful responses
        if response.status not in [200, 206]:
            return None
        
        try:
            body = await response.text()
            content_type = response.headers.get('Content-Type', '').lower()
            content_length = len(body)
            
            # Check for directory listing
            if self._is_directory_listing(body):
                # Check if listing contains log files
                if re.search(r'\.log|error|access|debug', body, re.IGNORECASE):
                    return self.create_vulnerability(
                        vuln_type="Log Directory Listing Enabled",
                        severity=Severity.HIGH,
                        url=url,
                        evidence=f"Directory listing enabled at {path}, contains log files",
                        description=(
                            "A directory containing log files is accessible and has directory listing enabled. "
                            "This exposes potentially sensitive information including:\n"
                            "- Application errors and stack traces\n"
                            "- User activity and IP addresses\n"
                            "- Internal system paths and configuration\n"
                            "- Debugging information and credentials"
                        ),
                        cwe_id="CWE-532",
                        cvss_score=7.5,
                        remediation=(
                            "1. Disable directory listing in web server configuration\n"
                            "2. Move log files outside the web root\n"
                            "3. Implement access controls for log directories\n"
                            "4. Use .htaccess or nginx config to deny access to log paths"
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                            "https://cwe.mitre.org/data/definitions/532.html"
                        ]
                    )
            
            # Check for actual log file content
            if self._is_log_content(body):
                severity = self._assess_log_severity(body)
                return self.create_vulnerability(
                    vuln_type="Exposed Log File",
                    severity=severity,
                    url=url,
                    evidence=f"Log file accessible at {path} ({content_length} bytes). Contains log entries.",
                    description=(
                        f"A log file is publicly accessible at {path}. "
                        "Exposed log files can reveal:\n"
                        "- Sensitive user data and PII\n"
                        "- Application internals and vulnerabilities\n"
                        "- Authentication tokens and session IDs\n"
                        "- Infrastructure details and internal IPs\n"
                        "- SQL queries and database information"
                    ),
                    cwe_id="CWE-532",
                    cvss_score=7.5 if severity == Severity.HIGH else 5.3,
                    remediation=(
                        "1. Remove log files from web-accessible directories\n"
                        "2. Configure web server to deny access to .log files\n"
                        "3. Store logs outside the document root\n"
                        "4. Implement proper log rotation and cleanup\n"
                        "5. Use centralized logging systems (ELK, Splunk) instead of file-based logs"
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                        "https://cwe.mitre.org/data/definitions/532.html"
                    ]
                )
            
            # Check for monitoring endpoints (like Spring Actuator)
            if '/actuator' in path or 'elmah' in path.lower():
                if 'log' in body.lower() or 'trace' in body.lower():
                    return self.create_vulnerability(
                        vuln_type="Exposed Logging/Monitoring Endpoint",
                        severity=Severity.MEDIUM,
                        url=url,
                        evidence=f"Logging/monitoring endpoint accessible at {path}",
                        description=(
                            "A logging or monitoring endpoint is publicly accessible. "
                            "These endpoints often expose sensitive debugging information, "
                            "error details, and application internals."
                        ),
                        cwe_id="CWE-532",
                        cvss_score=5.3,
                        remediation=(
                            "1. Restrict access to monitoring endpoints\n"
                            "2. Require authentication for debug/logging endpoints\n"
                            "3. Disable these endpoints in production\n"
                            "4. Use network-level restrictions (IP allowlisting)"
                        ),
                        references=[
                            "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security",
                            "https://cwe.mitre.org/data/definitions/532.html"
                        ]
                    )
                    
        except Exception:
            pass
        
        return None
    
    async def _check_current_directory(self, session: aiohttp.ClientSession,
                                        url: str) -> List[Vulnerability]:
        """Check for log files in the current directory"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_path = '/'.join(parsed.path.split('/')[:-1]) if '/' in parsed.path else ''
        base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"
        
        local_log_files = [
            '/error.log',
            '/debug.log',
            '/app.log',
            '/.log',
            '/log.txt',
        ]
        
        for log_file in local_log_files:
            test_url = base_url + log_file
            response = await self.make_request(session, "GET", test_url)
            if response and response.status == 200:
                try:
                    body = await response.text()
                    if self._is_log_content(body):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Log File in Application Directory",
                            severity=Severity.MEDIUM,
                            url=test_url,
                            evidence=f"Log file found at {log_file}",
                            description=f"A log file was found in the application directory at {test_url}",
                            cwe_id="CWE-532",
                            cvss_score=5.3,
                            remediation="Move log files outside the web root and restrict access.",
                            references=["https://cwe.mitre.org/data/definitions/532.html"]
                        ))
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _is_directory_listing(self, body: str) -> bool:
        """Check if response is a directory listing"""
        for pattern in self.DIRECTORY_LISTING_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False
    
    def _is_log_content(self, body: str) -> bool:
        """Check if response content looks like log data"""
        matches = 0
        for pattern in self.LOG_CONTENT_PATTERNS:
            if re.search(pattern, body, re.MULTILINE | re.IGNORECASE):
                matches += 1
                if matches >= 2:  # Require at least 2 patterns for confidence
                    return True
        return False
    
    def _assess_log_severity(self, body: str) -> Severity:
        """Assess severity based on log content"""
        high_severity_patterns = [
            r'password',
            r'secret',
            r'token',
            r'api.?key',
            r'credit.?card',
            r'ssn',
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
        ]
        
        for pattern in high_severity_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return Severity.HIGH
        
        return Severity.MEDIUM