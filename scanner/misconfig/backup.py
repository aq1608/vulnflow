# scanner/misconfig/backup.py
"""Backup File Scanner"""

from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class BackupFileScanner(BaseScanner):
    """Scanner for exposed backup and temporary files"""
    
    name = "Backup File Scanner"
    description = "Detects exposed backup, temporary, and old files"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Common backup extensions
    BACKUP_EXTENSIONS = [
        '.bak', '.backup', '.old', '.orig', '.original',
        '.save', '.saved', '.tmp', '.temp', '.swp',
        '.swo', '~', '.copy', '.bkp', '.bk',
        '_backup', '_old', '_bak', '.1', '.2',
    ]
    
    # Files to check for backups
    IMPORTANT_FILES = [
        'index.php', 'index.html', 'config.php', 'wp-config.php',
        'configuration.php', 'settings.php', 'database.php',
        'config.inc.php', 'db.php', 'conn.php', 'connect.php',
        'web.config', 'app.config', 'Global.asax', 'Web.config',
        '.htaccess', 'htaccess', 'passwd', 'shadow',
        'config.yml', 'config.yaml', 'application.yml',
        'database.yml', 'secrets.yml', 'credentials.yml',
        'config.json', 'package.json', 'composer.json',
        '.env', 'env', '.env.local', '.env.production',
    ]
    
    # Archive files
    ARCHIVE_FILES = [
        'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.tgz',
        'backup.rar', 'backup.7z', 'site.zip', 'www.zip',
        'html.zip', 'web.zip', 'public.zip', 'htdocs.zip',
        'database.sql', 'db.sql', 'dump.sql', 'backup.sql',
        'data.sql', 'mysql.sql', 'export.sql',
        'database.sql.gz', 'db.sql.gz', 'dump.sql.gz',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for backup files"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check backup versions of important files
        for filename in self.IMPORTANT_FILES:
            for ext in self.BACKUP_EXTENSIONS:
                # Try different backup patterns
                test_urls = [
                    urljoin(base_url + "/", filename + ext),
                    urljoin(base_url + "/", filename + ext + ".txt"),
                    urljoin(base_url + "/", ext.lstrip('.') + "_" + filename),
                ]
                
                for test_url in test_urls:
                    vuln = await self._check_file(session, test_url, f"Backup of {filename}")
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
        
        # Check for archive files
        for archive in self.ARCHIVE_FILES:
            test_url = urljoin(base_url + "/", archive)
            vuln = await self._check_file(session, test_url, f"Archive: {archive}")
            if vuln:
                vulnerabilities.append(vuln)
        
        # Check for vim swap files of current URL
        if parsed.path:
            current_file = parsed.path.split('/')[-1]
            if current_file:
                swap_files = [
                    f".{current_file}.swp",
                    f".{current_file}.swo",
                    f"{current_file}~",
                ]
                for swap in swap_files:
                    test_url = urljoin(url.rsplit('/', 1)[0] + "/", swap)
                    vuln = await self._check_file(session, test_url, "Editor swap file")
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _check_file(self, session: aiohttp.ClientSession,
                          url: str, description: str) -> Optional[Vulnerability]:
        """Check if a backup file exists and is accessible"""
        
        response = await self.make_request(session, "GET", url)
        if not response:
            return None
        
        if response.status == 200:
            content_type = response.headers.get('Content-Type', '')
            content_length = response.headers.get('Content-Length', '0')
            
            # Verify it's not an error page
            body = await response.text()
            
            if self._is_valid_backup(body, content_type, url):
                severity = self._determine_severity(url, body)
                
                return self.create_vulnerability(
                    vuln_type=f"Backup File Exposed: {description}",
                    severity=severity,
                    url=url,
                    evidence=f"File accessible with {content_length} bytes, Content-Type: {content_type}",
                    description=f"A backup or temporary file is publicly accessible. This may expose source code, configuration, or sensitive data.",
                    cwe_id="CWE-530",
                    cvss_score=self._severity_to_cvss(severity),
                    remediation="Remove backup files from production servers. Configure web server to deny access to backup file extensions.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
                    ]
                )
        
        return None
    
    def _is_valid_backup(self, body: str, content_type: str, url: str) -> bool:
        """Verify this is a real backup file, not an error page"""
        
        # Check for common error indicators
        error_indicators = ['not found', '404', 'error', 'forbidden', 'denied']
        body_lower = body.lower()
        
        if any(indicator in body_lower for indicator in error_indicators):
            if len(body) < 2000:  # Small response is likely an error page
                return False
        
        # SQL files should contain SQL keywords
        if url.endswith('.sql'):
            sql_keywords = ['CREATE', 'INSERT', 'SELECT', 'DROP', 'ALTER', 'TABLE']
            return any(kw in body.upper() for kw in sql_keywords)
        
        # Config files should have config-like content
        if any(cfg in url.lower() for cfg in ['config', '.env', 'settings']):
            return '=' in body or ':' in body
        
        # PHP files should have PHP code
        if url.endswith('.php') or '.php.' in url:
            return '<?php' in body or '<?=' in body
        
        # Default: has meaningful content
        return len(body.strip()) > 100
    
    def _determine_severity(self, url: str, body: str) -> Severity:
        """Determine severity based on file type and content"""
        
        url_lower = url.lower()
        body_lower = body.lower()
        
        # Critical: Database dumps, credentials
        if any(x in url_lower for x in ['.sql', 'database', 'dump', 'credential', 'secret']):
            return Severity.CRITICAL
        
        if any(x in body_lower for x in ['password', 'secret', 'api_key', 'apikey', 'token']):
            return Severity.CRITICAL
        
        # High: Config files, source code
        if any(x in url_lower for x in ['config', '.env', 'settings', 'wp-config']):
            return Severity.HIGH
        
        if '<?php' in body or 'import ' in body or 'require ' in body:
            return Severity.HIGH
        
        # Medium: General backups
        return Severity.MEDIUM
    
    def _severity_to_cvss(self, severity: Severity) -> float:
        """Convert severity to CVSS score"""
        mapping = {
            Severity.CRITICAL: 9.1,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 3.1,
            Severity.INFO: 0.0
        }
        return mapping.get(severity, 5.0)