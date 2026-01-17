# scanner/misconfig/information_disclosure.py
"""
Information Disclosure Scanner

Detects information disclosure vulnerabilities:
- Server version exposure
- Framework/technology disclosure
- Error message leakage
- Debug information
- Source code exposure
- Internal IP addresses
- Directory listings

OWASP: A05:2021 - Security Misconfiguration
CWE-200: Exposure of Sensitive Information
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class InformationDisclosureScanner(BaseScanner):
    """Scanner for information disclosure vulnerabilities"""

    name="Information Disclosure Scanner",
    description="Detects information disclosure vulnerabilities",
    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    def __init__(self):
        
        # Headers that disclose information
        self.disclosure_headers = {
            "Server": {
                "pattern": r".*",
                "severity": Severity.LOW,
                "description": "Server software disclosed"
            },
            "X-Powered-By": {
                "pattern": r".*",
                "severity": Severity.LOW,
                "description": "Technology stack disclosed"
            },
            "X-AspNet-Version": {
                "pattern": r".*",
                "severity": Severity.LOW,
                "description": "ASP.NET version disclosed"
            },
            "X-AspNetMvc-Version": {
                "pattern": r".*",
                "severity": Severity.LOW,
                "description": "ASP.NET MVC version disclosed"
            },
            "X-Runtime": {
                "pattern": r".*",
                "severity": Severity.INFO,
                "description": "Runtime information disclosed"
            },
            "X-Version": {
                "pattern": r".*",
                "severity": Severity.LOW,
                "description": "Application version disclosed"
            },
            "X-Debug-Token": {
                "pattern": r".*",
                "severity": Severity.MEDIUM,
                "description": "Debug token exposed (Symfony)"
            },
            "X-Debug-Token-Link": {
                "pattern": r".*",
                "severity": Severity.MEDIUM,
                "description": "Debug profiler link exposed"
            },
        }
        
        # Sensitive paths to check
        self.sensitive_paths = [
            # Configuration files
            ("/.env", "Environment file"),
            ("/.env.local", "Local environment file"),
            ("/.env.production", "Production environment file"),
            ("/config.php", "PHP configuration"),
            ("/config.yml", "YAML configuration"),
            ("/config.json", "JSON configuration"),
            ("/settings.py", "Python settings"),
            ("/web.config", "IIS configuration"),
            ("/appsettings.json", ".NET configuration"),
            
            # Version control
            ("/.git/config", "Git configuration"),
            ("/.git/HEAD", "Git HEAD"),
            ("/.svn/entries", "SVN entries"),
            ("/.hg/hgrc", "Mercurial config"),
            
            # IDE and editor files
            ("/.idea/workspace.xml", "IntelliJ workspace"),
            ("/.vscode/settings.json", "VS Code settings"),
            ("/.DS_Store", "macOS metadata"),
            ("/Thumbs.db", "Windows thumbnails"),
            
            # Build and dependency files
            ("/package.json", "NPM package file"),
            ("/composer.json", "Composer file"),
            ("/Gemfile", "Ruby Gemfile"),
            ("/requirements.txt", "Python requirements"),
            ("/pom.xml", "Maven POM"),
            
            # Documentation
            ("/README.md", "README file"),
            ("/CHANGELOG.md", "Changelog"),
            ("/LICENSE", "License file"),
            
            # Log files
            ("/error.log", "Error log"),
            ("/access.log", "Access log"),
            ("/debug.log", "Debug log"),
            ("/app.log", "Application log"),
            
            # Database files
            ("/database.sql", "SQL dump"),
            ("/dump.sql", "Database dump"),
            ("/backup.sql", "SQL backup"),
            ("/.sqlite", "SQLite database"),
            ("/data.db", "Database file"),
            
            # Server status
            ("/server-status", "Apache status"),
            ("/server-info", "Apache info"),
            ("/nginx_status", "Nginx status"),
            ("/phpinfo.php", "PHP info"),
            
            # API documentation
            ("/swagger.json", "Swagger spec"),
            ("/swagger.yaml", "Swagger spec"),
            ("/openapi.json", "OpenAPI spec"),
            ("/api-docs", "API documentation"),
        ]
        
        # Patterns in response indicating information disclosure
        self.body_patterns = [
            # Internal IPs
            (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", 
             "Internal IP Address", Severity.LOW),
            
            # Stack traces
            (r"(?:at\s+[\w.$]+$[\w.]+:\d+$|File\s+\"[^\"]+\",\s+line\s+\d+|Traceback\s+\(most\s+recent)", 
             "Stack Trace", Severity.MEDIUM),
            
            # SQL errors
            (r"(?:SQL\s+syntax.*MySQL|Warning.*\Wmysqli?_|PostgreSQL.*ERROR|ORA-\d{5}|Microsoft\s+SQL\s+Server)", 
             "SQL Error Message", Severity.MEDIUM),
            
            # File paths
            (r"(?:[A-Z]:\$?:[\w\s]+\$+[\w\s]+\.[\w]+|/(?:var|home|usr|etc|opt)/[\w/]+)", 
             "File Path Disclosure", Severity.LOW),
            
            # Source code patterns
            (r"(?:<\?php|<%@|<%=|<cfscript|<script\s+runat)", 
             "Source Code Exposure", Severity.HIGH),
            
            # Debug information
            (r"(?:DEBUG|TRACE|development\s+mode|debug\s*=\s*(?:true|1|on))",
             "Debug Mode Enabled", Severity.MEDIUM),
            
            # API keys/secrets (generic patterns)
            (r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w-]{20,}",
             "Potential API Key/Secret", Severity.HIGH),
            
            # Database connection strings
            (r"(?:mongodb://|mysql://|postgres://|redis://|amqp://)[^\s\"']+",
             "Database Connection String", Severity.HIGH),
        ]
        
        # Error page indicators
        self.error_indicators = [
            (r"PHP\s+(?:Parse|Fatal|Warning|Notice)\s+error", "PHP Error"),
            (r"Undefined\s+(?:variable|index|offset)", "PHP Undefined Error"),
            (r"Exception\s+in\s+thread", "Java Exception"),
            (r"\.NET\s+Framework\s+Version", ".NET Error Page"),
            (r"Django\s+Debug", "Django Debug Page"),
            (r"Laravel", "Laravel Error"),
            (r"Symfony\\", "Symfony Error"),
            (r"Rails\s+Error", "Rails Error"),
            (r"Express\s+Error", "Express Error"),
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for information disclosure vulnerabilities.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check response headers
        header_vulns = await self._check_headers(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Check sensitive paths
        path_vulns = await self._check_sensitive_paths(session, base_url)
        vulnerabilities.extend(path_vulns)
        
        # Check response body for information disclosure
        body_vulns = await self._check_response_body(session, url)
        vulnerabilities.extend(body_vulns)
        
        # Check error pages
        error_vulns = await self._check_error_pages(session, base_url)
        vulnerabilities.extend(error_vulns)
        
        # Check directory listing
        dir_vulns = await self._check_directory_listing(session, base_url)
        vulnerabilities.extend(dir_vulns)
        
        return vulnerabilities
    
    async def _check_headers(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check response headers for information disclosure"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                for header_name, config in self.disclosure_headers.items():
                    if header_name in response.headers:
                        header_value = response.headers[header_name]
                        
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Information Disclosure - Header",
                            severity=config["severity"],
                            url=url,
                            parameter=header_name,
                            payload="N/A",
                            evidence=f"{header_name}: {header_value}",
                            description=config["description"],
                            cwe_id="CWE-200",
                            remediation=f"Remove or sanitize the {header_name} header."
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_sensitive_paths(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check for sensitive files and paths"""
        vulnerabilities = []
        
        # Limit concurrent checks
        semaphore = asyncio.Semaphore(10)
        
        async def check_path(path: str, description: str):
            async with semaphore:
                try:
                    test_url = urljoin(base_url, path)
                    
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False,
                        allow_redirects=False
                    ) as response:
                        if response.status == 200:
                            content_length = response.headers.get('Content-Length', '0')
                            content_type = response.headers.get('Content-Type', '')
                            
                            # Skip if it looks like a custom 404 page
                            if int(content_length) > 0 and 'text/html' not in content_type:
                                text = await response.text()
                                
                                # Verify it's not a redirect/404 page
                                if len(text) > 10 and '404' not in text.lower()[:200]:
                                    return Vulnerability(
                                        vuln_type="Sensitive File Exposed",
                                        severity=self._get_path_severity(path),
                                        url=test_url,
                                        parameter="Path",
                                        payload=path,
                                        evidence=f"File accessible: {description}",
                                        description=f"{description} is publicly accessible",
                                        cwe_id="CWE-538",
                                        remediation="Block access to sensitive files via web server configuration."
                                    )
                
                except Exception:
                    pass
                
                return None
        
        # Check paths concurrently
        tasks = [check_path(path, desc) for path, desc in self.sensitive_paths]
        results = await asyncio.gather(*tasks)
        
        vulnerabilities.extend([r for r in results if r is not None])
        
        return vulnerabilities
    
    async def _check_response_body(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check response body for information disclosure"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                text = await response.text()
                
                for pattern, description, severity in self.body_patterns:
                    matches = re.finditer(pattern, text, re.IGNORECASE)
                    
                    for match in matches:
                        # Get context
                        start = max(0, match.start() - 30)
                        end = min(len(text), match.end() + 30)
                        context = text[start:end].replace('\n', ' ')
                        
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"Information Disclosure - {description}",
                            severity=severity,
                            url=url,
                            parameter="Response Body",
                            payload="N/A",
                            evidence=context[:150],
                            description=f"{description} found in response",
                            cwe_id="CWE-200",
                            remediation="Remove or mask sensitive information from responses."
                        ))
                        break  # One finding per pattern type
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_error_pages(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check error pages for information disclosure"""
        vulnerabilities = []
        
        # Trigger various errors
        error_triggers = [
            ("/nonexistent_page_12345", "404 Error"),
            ("/?id='", "SQL Error"),
            ("/?test=<script>", "XSS Error"),
            ("/../../../../etc/passwd", "Path Traversal Error"),
            ("/.%00.html", "Null Byte Error"),
        ]
        
        for path, error_type in error_triggers:
            try:
                test_url = urljoin(base_url, path)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    text = await response.text()
                    
                    for pattern, framework in self.error_indicators:
                        if re.search(pattern, text, re.IGNORECASE):
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Verbose Error Message",
                                severity=Severity.MEDIUM,
                                url=test_url,
                                parameter="Error Page",
                                payload=path,
                                evidence=f"{framework} error page detected",
                                description=f"Error page reveals {framework} details",
                                cwe_id="CWE-209",
                                remediation="Configure custom error pages that don't reveal technical details."
                            ))
                            break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _check_directory_listing(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check for directory listing"""
        vulnerabilities = []
        
        # Common directories to check
        directories = [
            "/images/",
            "/img/",
            "/css/",
            "/js/",
            "/assets/",
            "/uploads/",
            "/files/",
            "/static/",
            "/media/",
            "/backup/",
            "/logs/",
            "/tmp/",
        ]
        
        listing_indicators = [
            r"Index\s+of\s+/",
            r"Directory\s+listing\s+for",
            r"<title>Index of",
            r"Parent\s+Directory",
            r"\[DIR\]",
            r"<h1>Directory listing for",
        ]
        
        for directory in directories:
            try:
                test_url = urljoin(base_url, directory)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        
                        for pattern in listing_indicators:
                            if re.search(pattern, text, re.IGNORECASE):
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Directory Listing Enabled",
                                    severity=Severity.MEDIUM,
                                    url=test_url,
                                    parameter="Directory",
                                    payload=directory,
                                    evidence="Directory listing is enabled",
                                    description=f"Directory listing enabled for {directory}",
                                    cwe_id="CWE-548",
                                    remediation="Disable directory listing in web server configuration."
                                ))
                                break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _get_path_severity(self, path: str) -> Severity:
        """Determine severity based on file type"""
        high_severity = ['.env', 'config', 'secret', 'key', 'passwd', 'shadow', '.sql', 'database']
        medium_severity = ['.git', '.svn', 'log', 'backup']
        
        path_lower = path.lower()
        
        for pattern in high_severity:
            if pattern in path_lower:
                return Severity.HIGH
        
        for pattern in medium_severity:
            if pattern in path_lower:
                return Severity.MEDIUM
        
        return Severity.LOW