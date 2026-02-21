# scanner/misconfig/backup.py
"""Backup File Scanner"""

from typing import List, Dict, Optional
import aiohttp
import re
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class BackupFileScanner(BaseScanner):
    """Scanner for exposed backup and temporary files"""
    
    name = "Backup File Scanner"
    description = "Detects exposed backup, temporary, and old files"
    owasp_category = OWASPCategory.A02_SECURITY_MISCONFIGURATION
    
    # Minimum content length to consider valid (filters out empty responses)
    MIN_CONTENT_LENGTH = 50
    
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
            content_length_header = response.headers.get('Content-Length', '')
            
            # Read the body
            body = await response.text()
            actual_length = len(body.strip()) if body else 0
            
            # ══════════════════════════════════════════════════════════════
            # FIX 1: Skip empty responses immediately
            # ══════════════════════════════════════════════════════════════
            if actual_length == 0:
                return None
            
            # Check Content-Length header too (might be 0 even if body has whitespace)
            if content_length_header.isdigit() and int(content_length_header) == 0:
                return None
            
            # Skip very small responses (likely empty or error placeholders)
            if actual_length < self.MIN_CONTENT_LENGTH:
                return None
            
            # ══════════════════════════════════════════════════════════════
            # FIX 2: Validate it's actually a backup file, not an error page
            # ══════════════════════════════════════════════════════════════
            if not self._is_valid_backup(body, content_type, url):
                return None
            
            severity = self._determine_severity(url, body)
            
            return self.create_vulnerability(
                vuln_type=f"Backup File Exposed: {description}",
                severity=severity,
                url=url,
                evidence=f"File accessible with {actual_length} bytes, Content-Type: {content_type}",
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
        
        # ══════════════════════════════════════════════════════════════
        # FIX 3: Check for empty/minimal content FIRST
        # ══════════════════════════════════════════════════════════════
        if not body:
            return False
        
        body_stripped = body.strip()
        if len(body_stripped) < self.MIN_CONTENT_LENGTH:
            return False
        
        body_lower = body.lower()
        url_lower = url.lower()
        
        # ══════════════════════════════════════════════════════════════
        # FIX 4: Check for HTML error pages and SPA shells
        # ══════════════════════════════════════════════════════════════
        if self._is_error_or_spa_page(body, content_type):
            return False
        
        # Check for common error indicators
        error_indicators = [
            'not found', '404', 'error', 'forbidden', 'denied',
            'unauthorized', '401', '403', '500', 'internal server error',
            'page not found', 'file not found', 'access denied'
        ]
        
        if any(indicator in body_lower for indicator in error_indicators):
            if len(body) < 2000:  # Small response is likely an error page
                return False
        
        # ══════════════════════════════════════════════════════════════
        # FIX 5: Better pattern matching for backup files
        # ══════════════════════════════════════════════════════════════
        
        # SQL files should contain SQL keywords
        if url_lower.endswith('.sql') or '.sql.' in url_lower or '.sql~' in url_lower:
            sql_keywords = ['CREATE', 'INSERT', 'SELECT', 'DROP', 'ALTER', 'TABLE', 'DATABASE']
            return any(kw in body.upper() for kw in sql_keywords)
        
        # PHP backup files (.php~, .php.bak, .php.old, etc.)
        # Use regex to match various PHP backup patterns
        php_backup_pattern = r'\.php[~.].{0,10}$|\.php$'
        if re.search(php_backup_pattern, url_lower):
            return '<?php' in body or '<?=' in body or '<?PHP' in body
        
        # Config files should have config-like content
        config_patterns = ['config', '.env', 'settings', 'database', 'credentials', 'secrets']
        if any(cfg in url_lower for cfg in config_patterns):
            # Should have key=value or key: value patterns
            has_config_format = bool(
                re.search(r'^[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*.+', body, re.MULTILINE)
            )
            return has_config_format
        
        # Archive files - check for binary signatures or substantial content
        archive_extensions = ['.zip', '.tar', '.gz', '.rar', '.7z', '.tgz']
        if any(url_lower.endswith(ext) for ext in archive_extensions):
            # Binary files will have non-printable characters
            # Or check for magic bytes
            magic_bytes = {
                'zip': b'PK',
                'gzip': b'\x1f\x8b',
                'rar': b'Rar!',
            }
            # For text response, check if it's binary-ish
            return len(body) > 100 and not body.strip().startswith('<')
        
        # YAML/YML files
        if url_lower.endswith(('.yml', '.yaml')) or '.yml' in url_lower or '.yaml' in url_lower:
            # Should have YAML structure
            return bool(re.search(r'^\s*[a-zA-Z_]+:\s*.+$', body, re.MULTILINE))
        
        # JSON files
        if url_lower.endswith('.json') or '.json' in url_lower:
            stripped = body.strip()
            return stripped.startswith(('{', '[')) and (stripped.endswith('}') or stripped.endswith(']'))
        
        # Default: has meaningful content (substantial, not just HTML shell)
        if len(body_stripped) > 100:
            # Make sure it's not just an HTML wrapper
            if '<html' in body_lower or '<!doctype' in body_lower:
                # If it's HTML, it should have substantial content, not just a shell
                # Count actual text content (rough heuristic)
                text_content = re.sub(r'<[^>]+>', '', body)  # Strip HTML tags
                return len(text_content.strip()) > 100
            return True
        
        return False
    
    def _is_error_or_spa_page(self, body: str, content_type: str) -> bool:
        """Check if response is an error page or SPA shell"""
        if not body:
            return True
        
        body_lower = body.lower().strip()
        
        # Too short to be meaningful
        if len(body_lower) < 50:
            return True
        
        # SPA shell indicators (Angular, React, Vue)
        spa_indicators = [
            '<app-root></app-root>',
            '<app-root>',
            '<div id="root"></div>',
            '<div id="app"></div>',
            'ng-version=',
            '__NEXT_DATA__',
            '__NUXT__',
        ]
        
        for indicator in spa_indicators:
            if indicator.lower() in body_lower:
                # Check if there's actual content or just shell
                # SPA shells typically have very few HTML tags with content
                text_without_tags = re.sub(r'<[^>]+>', '', body)
                if len(text_without_tags.strip()) < 100:
                    return True
        
        # HTML response for non-HTML file request is suspicious
        if 'text/html' in content_type.lower():
            # If we're looking for .php~, .bak, etc. and get HTML, 
            # it's probably a custom error page
            if body_lower.startswith('<!doctype html') or body_lower.startswith('<html'):
                # Check if it looks like a proper backup or just an error wrapper
                if '<title>' in body_lower:
                    title_match = re.search(r'<title>([^<]+)</title>', body_lower)
                    if title_match:
                        title = title_match.group(1).lower()
                        error_titles = ['error', 'not found', '404', '403', '500', 'forbidden']
                        if any(err in title for err in error_titles):
                            return True
        
        return False
    
    def _determine_severity(self, url: str, body: str) -> Severity:
        """Determine severity based on file type and content"""
        
        url_lower = url.lower()
        body_lower = body.lower()
        
        # Critical: Database dumps, credentials
        if any(x in url_lower for x in ['.sql', 'database', 'dump', 'credential', 'secret']):
            return Severity.CRITICAL
        
        if any(x in body_lower for x in ['password', 'secret', 'api_key', 'apikey', 'token', 'private_key']):
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