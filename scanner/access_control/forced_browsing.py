# scanner/access_control/forced_browsing.py
"""Forced Browsing / Directory Enumeration Scanner"""

from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urljoin

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class ForcedBrowsingScanner(BaseScanner):
    """Scanner for Forced Browsing vulnerabilities"""
    
    name = "Forced Browsing Scanner"
    description = "Detects accessible sensitive directories and files"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    # Sensitive paths to check
    SENSITIVE_PATHS = {
        # Admin panels
        "admin": ("Admin Panel", Severity.HIGH),
        "admin/": ("Admin Panel", Severity.HIGH),
        "administrator": ("Admin Panel", Severity.HIGH),
        "administrator/": ("Admin Panel", Severity.HIGH),
        "admin.php": ("Admin Panel", Severity.HIGH),
        "admin/login": ("Admin Login", Severity.HIGH),
        "wp-admin": ("WordPress Admin", Severity.HIGH),
        "wp-admin/": ("WordPress Admin", Severity.HIGH),
        "cpanel": ("cPanel", Severity.CRITICAL),
        "phpmyadmin": ("phpMyAdmin", Severity.CRITICAL),
        "phpmyadmin/": ("phpMyAdmin", Severity.CRITICAL),
        "_phpmyadmin": ("phpMyAdmin", Severity.CRITICAL),
        "myadmin": ("phpMyAdmin", Severity.CRITICAL),
        "mysql": ("MySQL Admin", Severity.CRITICAL),
        "adminer.php": ("Adminer Database", Severity.CRITICAL),
        
        # Configuration files
        ".env": ("Environment File", Severity.CRITICAL),
        ".env.local": ("Environment File", Severity.CRITICAL),
        ".env.production": ("Environment File", Severity.CRITICAL),
        ".env.backup": ("Environment Backup", Severity.CRITICAL),
        "config.php": ("Config File", Severity.HIGH),
        "config.inc.php": ("Config File", Severity.HIGH),
        "configuration.php": ("Config File", Severity.HIGH),
        "settings.php": ("Settings File", Severity.HIGH),
        "database.yml": ("Database Config", Severity.CRITICAL),
        "config/database.yml": ("Database Config", Severity.CRITICAL),
        "wp-config.php": ("WordPress Config", Severity.CRITICAL),
        "web.config": ("IIS Config", Severity.HIGH),
        "app.config": ("App Config", Severity.MEDIUM),
        
        # Version control
        ".git/HEAD": ("Git Repository", Severity.HIGH),
        ".git/config": ("Git Config", Severity.HIGH),
        ".gitignore": ("Git Ignore", Severity.LOW),
        ".svn/entries": ("SVN Repository", Severity.HIGH),
        ".hg/": ("Mercurial Repository", Severity.HIGH),
        
        # Backup files
        "backup/": ("Backup Directory", Severity.HIGH),
        "backups/": ("Backup Directory", Severity.HIGH),
        "backup.sql": ("Database Backup", Severity.CRITICAL),
        "backup.zip": ("Backup Archive", Severity.HIGH),
        "backup.tar.gz": ("Backup Archive", Severity.HIGH),
        "db_backup.sql": ("Database Backup", Severity.CRITICAL),
        "database.sql": ("Database Dump", Severity.CRITICAL),
        "dump.sql": ("Database Dump", Severity.CRITICAL),
        
        # Log files
        "logs/": ("Log Directory", Severity.MEDIUM),
        "log/": ("Log Directory", Severity.MEDIUM),
        "error.log": ("Error Log", Severity.MEDIUM),
        "access.log": ("Access Log", Severity.MEDIUM),
        "debug.log": ("Debug Log", Severity.MEDIUM),
        "error_log": ("Error Log", Severity.MEDIUM),
        
        # Sensitive directories
        "private/": ("Private Directory", Severity.HIGH),
        "internal/": ("Internal Directory", Severity.MEDIUM),
        "secret/": ("Secret Directory", Severity.HIGH),
        "confidential/": ("Confidential Directory", Severity.HIGH),
        "uploads/": ("Uploads Directory", Severity.MEDIUM),
        "files/": ("Files Directory", Severity.LOW),
        "tmp/": ("Temp Directory", Severity.MEDIUM),
        "temp/": ("Temp Directory", Severity.MEDIUM),
        "cache/": ("Cache Directory", Severity.LOW),
        
        # API documentation
        "swagger/": ("Swagger Docs", Severity.LOW),
        "swagger-ui/": ("Swagger UI", Severity.LOW),
        "api-docs": ("API Docs", Severity.LOW),
        "swagger.json": ("Swagger JSON", Severity.LOW),
        "openapi.json": ("OpenAPI Spec", Severity.LOW),
        
        # Server info
        "server-status": ("Apache Status", Severity.MEDIUM),
        "server-info": ("Apache Info", Severity.MEDIUM),
        "phpinfo.php": ("PHP Info", Severity.HIGH),
        "info.php": ("PHP Info", Severity.HIGH),
        "test.php": ("Test File", Severity.MEDIUM),
        
        # Development files
        ".htaccess": ("Apache Config", Severity.MEDIUM),
        ".htpasswd": ("Apache Password", Severity.CRITICAL),
        "composer.json": ("Composer Config", Severity.LOW),
        "package.json": ("NPM Config", Severity.LOW),
        "Gemfile": ("Ruby Gems", Severity.LOW),
        "requirements.txt": ("Python Requirements", Severity.LOW),
        
        # Common CMS paths
        "wp-content/debug.log": ("WordPress Debug", Severity.MEDIUM),
        "wp-includes/": ("WordPress Includes", Severity.LOW),
        "sites/default/settings.php": ("Drupal Settings", Severity.CRITICAL),
        
        # Cloud/DevOps
        ".aws/credentials": ("AWS Credentials", Severity.CRITICAL),
        ".docker/": ("Docker Config", Severity.MEDIUM),
        "docker-compose.yml": ("Docker Compose", Severity.MEDIUM),
        "Dockerfile": ("Dockerfile", Severity.LOW),
        ".kube/config": ("Kubernetes Config", Severity.CRITICAL),
        
        # IDE and editor files
        ".idea/": ("IntelliJ Config", Severity.LOW),
        ".vscode/": ("VS Code Config", Severity.LOW),
        "*.swp": ("Vim Swap", Severity.LOW),
        
        # SSL certificates
        "server.key": ("SSL Private Key", Severity.CRITICAL),
        "private.key": ("Private Key", Severity.CRITICAL),
        "certificate.crt": ("SSL Certificate", Severity.MEDIUM),
    }
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for accessible sensitive paths"""
        vulnerabilities = []
        
        # Extract base URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test each sensitive path
        for path, (description, severity) in self.SENSITIVE_PATHS.items():
            test_url = urljoin(base_url + "/", path)
            
            vuln = await self._test_path(session, test_url, path, description, severity)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_path(self, session: aiohttp.ClientSession,
                         url: str, path: str, description: str,
                         severity: Severity) -> Optional[Vulnerability]:
        """Test if a sensitive path is accessible"""
        
        response = await self.make_request(session, "GET", url, allow_redirects=False)
        if not response:
            return None
        
        status = response.status
        
        # Check if accessible
        if status == 200:
            body = await response.text()
            
            # Verify it's not a generic error page
            if not self._is_error_page(body):
                # Additional validation based on path type
                if self._validate_finding(path, body):
                    return self.create_vulnerability(
                        vuln_type=f"Sensitive Path Exposed: {description}",
                        severity=severity,
                        url=url,
                        evidence=f"HTTP {status} - {description} accessible at {path}",
                        description=f"The sensitive resource '{path}' is publicly accessible. This could expose sensitive information or functionality.",
                        cwe_id="CWE-425",
                        cvss_score=self._severity_to_cvss(severity),
                        remediation="Restrict access to sensitive paths using proper authentication and authorization. Consider removing unnecessary files from production servers.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
                        ]
                    )
        
        # Check for directory listing
        elif status == 200 and path.endswith('/'):
            body = await response.text()
            if self._is_directory_listing(body):
                return self.create_vulnerability(
                    vuln_type=f"Directory Listing Enabled: {description}",
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=f"Directory listing enabled at {path}",
                    description="Directory listing is enabled, exposing the contents of the directory.",
                    cwe_id="CWE-548",
                    cvss_score=5.3,
                    remediation="Disable directory listing in the web server configuration.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information"
                    ]
                )
        
        return None
    
    def _is_error_page(self, body: str) -> bool:
        """Check if response is an error page"""
        error_indicators = [
            'not found', '404', 'error', 'forbidden',
            'access denied', 'unauthorized', 'page not found'
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in error_indicators)
    
    def _is_directory_listing(self, body: str) -> bool:
        """Check if response is a directory listing"""
        listing_indicators = [
            'index of', 'directory listing', 'parent directory',
            '<title>index of', '[to parent directory]'
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in listing_indicators)
    
    def _validate_finding(self, path: str, body: str) -> bool:
        """Validate that the finding is real"""
        # Validate specific file types
        if path.endswith('.env'):
            return '=' in body and len(body) > 10
        if path.endswith('.sql'):
            return any(kw in body.upper() for kw in ['CREATE', 'INSERT', 'SELECT', 'DROP'])
        if 'git' in path:
            return 'ref:' in body or '[core]' in body
        if 'phpinfo' in path.lower():
            return 'PHP Version' in body or 'phpinfo()' in body
        
        # Default: body has meaningful content
        return len(body.strip()) > 50
    
    def _severity_to_cvss(self, severity: Severity) -> float:
        """Convert severity to CVSS score"""
        mapping = {
            Severity.CRITICAL: 9.8,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 3.1,
            Severity.INFO: 0.0
        }
        return mapping.get(severity, 5.0)