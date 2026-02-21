# scanner/misconfig/config_exposure.py
"""
Configuration Exposure Scanner

Detects exposed configuration and secrets:
- Passwords in configuration files
- Hardcoded secrets and API keys
- Exposed environment variables
- Cloud credentials
- Database connection strings

OWASP: A02:2025 - Security Misconfiguration
CWE-13: Password in Configuration File
CWE-260: Password in Configuration File
CWE-547: Use of Hard-coded, Security-relevant Constants
CWE-526: Exposure of Sensitive Information Through Environmental Variables
"""

import asyncio
import aiohttp
import re
import json
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class ConfigExposureScanner(BaseScanner):
    """Scanner for exposed configuration and secrets"""
    
    name = "Configuration Exposure Scanner"
    description = "Detects exposed configuration files, secrets, and credentials"
    owasp_category = OWASPCategory.A02_SECURITY_MISCONFIGURATION
    
    # Minimum content length to consider a valid response
    MIN_CONTENT_LENGTH = 10
    
    def __init__(self):
        super().__init__()
        
        # Configuration files to check
        self.config_files = [
            # Environment files
            ('.env', 'Environment Configuration'),
            ('.env.local', 'Local Environment'),
            ('.env.development', 'Development Environment'),
            ('.env.production', 'Production Environment'),
            ('.env.staging', 'Staging Environment'),
            ('.env.backup', 'Environment Backup'),
            ('.env.example', 'Environment Example'),
            ('.env.sample', 'Environment Sample'),
            ('env.js', 'JavaScript Environment'),
            ('env.json', 'JSON Environment'),
            
            # PHP Configuration
            ('config.php', 'PHP Configuration'),
            ('config.inc.php', 'PHP Include Config'),
            ('configuration.php', 'PHP Configuration'),
            ('settings.php', 'PHP Settings'),
            ('database.php', 'PHP Database Config'),
            ('db.php', 'PHP Database'),
            ('conn.php', 'PHP Connection'),
            ('connect.php', 'PHP Connection'),
            ('wp-config.php', 'WordPress Config'),
            ('wp-config.php.bak', 'WordPress Config Backup'),
            ('wp-config.php.old', 'WordPress Config Old'),
            ('wp-config.php.txt', 'WordPress Config Text'),
            ('LocalSettings.php', 'MediaWiki Settings'),
            ('local.xml', 'Magento Local Config'),
            
            # Python Configuration
            ('settings.py', 'Django Settings'),
            ('local_settings.py', 'Django Local Settings'),
            ('config.py', 'Python Config'),
            ('secrets.py', 'Python Secrets'),
            ('credentials.py', 'Python Credentials'),
            
            # Ruby/Rails Configuration
            ('database.yml', 'Rails Database Config'),
            ('secrets.yml', 'Rails Secrets'),
            ('credentials.yml.enc', 'Rails Encrypted Credentials'),
            ('config/database.yml', 'Rails Database Config'),
            ('config/secrets.yml', 'Rails Secrets'),
            ('config/master.key', 'Rails Master Key'),
            
            # Java Configuration
            ('application.properties', 'Spring Properties'),
            ('application.yml', 'Spring YAML Config'),
            ('application-dev.properties', 'Spring Dev Properties'),
            ('application-prod.properties', 'Spring Prod Properties'),
            ('hibernate.cfg.xml', 'Hibernate Config'),
            ('persistence.xml', 'JPA Persistence'),
            
            # .NET Configuration
            ('web.config', 'ASP.NET Config'),
            ('app.config', '.NET App Config'),
            ('appsettings.json', '.NET Settings'),
            ('appsettings.Development.json', '.NET Dev Settings'),
            ('appsettings.Production.json', '.NET Prod Settings'),
            ('connectionStrings.config', '.NET Connection Strings'),
            
            # Node.js Configuration
            ('config.json', 'Node Config'),
            ('config.js', 'Node Config JS'),
            ('default.json', 'Node Default Config'),
            ('production.json', 'Node Production Config'),
            ('development.json', 'Node Development Config'),
            ('.npmrc', 'NPM Config'),
            ('.yarnrc', 'Yarn Config'),
            
            # Cloud Provider Configs
            ('.aws/credentials', 'AWS Credentials'),
            ('.aws/config', 'AWS Config'),
            ('credentials', 'Generic Credentials'),
            ('.boto', 'Boto Config'),
            ('.s3cfg', 'S3 Config'),
            ('gcloud/credentials', 'GCloud Credentials'),
            ('.azure/credentials', 'Azure Credentials'),
            
            # CI/CD Configuration
            ('.travis.yml', 'Travis CI Config'),
            ('.gitlab-ci.yml', 'GitLab CI Config'),
            ('Jenkinsfile', 'Jenkins Pipeline'),
            ('.circleci/config.yml', 'CircleCI Config'),
            ('bitbucket-pipelines.yml', 'Bitbucket Pipelines'),
            ('.github/workflows', 'GitHub Actions'),
            
            # Docker Configuration
            ('docker-compose.yml', 'Docker Compose'),
            ('docker-compose.override.yml', 'Docker Compose Override'),
            ('Dockerfile', 'Dockerfile'),
            ('.dockerenv', 'Docker Environment'),
            
            # Kubernetes Configuration
            ('kubeconfig', 'Kubernetes Config'),
            ('.kube/config', 'Kubernetes Config'),
            ('kubernetes.yml', 'Kubernetes Manifest'),
            ('secrets.yaml', 'Kubernetes Secrets'),
            
            # SSH/SSL Keys
            ('id_rsa', 'SSH Private Key'),
            ('id_rsa.pub', 'SSH Public Key'),
            ('id_dsa', 'DSA Private Key'),
            ('id_ecdsa', 'ECDSA Private Key'),
            ('id_ed25519', 'ED25519 Private Key'),
            ('.ssh/id_rsa', 'SSH Private Key'),
            ('.ssh/authorized_keys', 'SSH Authorized Keys'),
            ('server.key', 'SSL Private Key'),
            ('private.key', 'Private Key'),
            ('privatekey.pem', 'PEM Private Key'),
            ('certificate.pem', 'PEM Certificate'),
            ('ssl-cert.pem', 'SSL Certificate'),
            
            # Other sensitive files
            ('.htpasswd', 'Apache Password File'),
            ('.htaccess', 'Apache Config'),
            ('htpasswd', 'Password File'),
            ('.netrc', 'Netrc Credentials'),
            ('.pgpass', 'PostgreSQL Password'),
            ('.my.cnf', 'MySQL Config'),
            ('my.cnf', 'MySQL Config'),
            ('.git-credentials', 'Git Credentials'),
            ('config/initializers/secret_token.rb', 'Rails Secret Token'),
        ]
        
        # Patterns for detecting secrets in content
        self.secret_patterns = [
            # Generic patterns
            (r'(?i)password\s*[=:]\s*["\']?([^\s"\']+)', 'Password', Severity.CRITICAL),
            (r'(?i)passwd\s*[=:]\s*["\']?([^\s"\']+)', 'Password', Severity.CRITICAL),
            (r'(?i)pwd\s*[=:]\s*["\']?([^\s"\']+)', 'Password', Severity.CRITICAL),
            (r'(?i)secret\s*[=:]\s*["\']?([^\s"\']+)', 'Secret', Severity.CRITICAL),
            (r'(?i)secret_key\s*[=:]\s*["\']?([^\s"\']+)', 'Secret Key', Severity.CRITICAL),
            
            # API Keys
            (r'(?i)api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'API Key', Severity.HIGH),
            (r'(?i)apikey\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'API Key', Severity.HIGH),
            (r'(?i)access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'Access Key', Severity.HIGH),
            (r'(?i)auth[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'Auth Token', Severity.HIGH),
            
            # AWS
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', Severity.CRITICAL),
            (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})', 'AWS Secret Key', Severity.CRITICAL),
            (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})', 'AWS Access Key', Severity.CRITICAL),
            
            # Google Cloud
            (r'(?i)google[_-]?api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{39})', 'Google API Key', Severity.HIGH),
            (r'AIza[0-9A-Za-z_\-]{35}', 'Google API Key', Severity.HIGH),
            
            # Azure
            (r'(?i)azure[_-]?storage[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{88})', 'Azure Storage Key', Severity.CRITICAL),
            
            # Stripe
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Secret Key', Severity.CRITICAL),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Secret Key', Severity.HIGH),
            (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Live Publishable Key', Severity.MEDIUM),
            
            # GitHub
            (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token', Severity.CRITICAL),
            (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token', Severity.CRITICAL),
            (r'ghu_[0-9a-zA-Z]{36}', 'GitHub User Token', Severity.CRITICAL),
            (r'ghs_[0-9a-zA-Z]{36}', 'GitHub Server Token', Severity.CRITICAL),
            
            # Slack
            (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token', Severity.HIGH),
            
            # Twilio
            (r'SK[0-9a-fA-F]{32}', 'Twilio API Key', Severity.HIGH),
            
            # Database connection strings
            (r'(?i)mongodb(?:\+srv)?://[^\s"\']+', 'MongoDB Connection String', Severity.CRITICAL),
            (r'(?i)mysql://[^\s"\']+', 'MySQL Connection String', Severity.CRITICAL),
            (r'(?i)postgres(?:ql)?://[^\s"\']+', 'PostgreSQL Connection String', Severity.CRITICAL),
            (r'(?i)redis://[^\s"\']+', 'Redis Connection String', Severity.HIGH),
            (r'(?i)amqp://[^\s"\']+', 'AMQP Connection String', Severity.HIGH),
            
            # Private keys
            (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Private Key', Severity.CRITICAL),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', Severity.CRITICAL),
            
            # JWT Secrets
            (r'(?i)jwt[_-]?secret\s*[=:]\s*["\']?([^\s"\']{16,})', 'JWT Secret', Severity.CRITICAL),
            
            # Generic tokens
            (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+', 'Bearer Token', Severity.HIGH),
            (r'(?i)token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{32,})', 'Generic Token', Severity.MEDIUM),
        ]
        
        # Environment variable patterns in HTML/JS
        self.env_var_patterns = [
            (r'process\.env\.([A-Z_]+)', 'Node.js Environment Variable'),
            (r'\$ENV\{([A-Z_]+)\}', 'Perl Environment Variable'),
            (r'os\.environ\[[\'"]([A-Z_]+)[\'"]\]', 'Python Environment Variable'),
            (r'ENV\[[\'"]([A-Z_]+)[\'"]\]', 'Ruby Environment Variable'),
            (r'\$_ENV\[[\'"]([A-Z_]+)[\'"]\]', 'PHP Environment Variable'),
            (r'getenv\([\'"]([A-Z_]+)[\'"]\)', 'PHP getenv'),
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for exposed configuration and secrets"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check for exposed config files
        config_vulns = await self._check_config_files(session, base_url)
        vulnerabilities.extend(config_vulns)
        
        # Check page content for leaked secrets
        content_vulns = await self._check_page_content(session, url)
        vulnerabilities.extend(content_vulns)
        
        # Check JavaScript files for hardcoded secrets
        js_vulns = await self._check_javascript_files(session, url)
        vulnerabilities.extend(js_vulns)
        
        # Check for environment variable exposure
        env_vulns = await self._check_env_exposure(session, url)
        vulnerabilities.extend(env_vulns)
        
        return vulnerabilities
    
    async def _check_config_files(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Vulnerability]:
        """Check for accessible configuration files"""
        vulnerabilities = []
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(10)
        
        async def check_file(path: str, description: str) -> Optional[Vulnerability]:
            async with semaphore:
                test_url = urljoin(base_url + '/', path)
                
                try:
                    response = await self.make_request(
                        session, "GET", test_url,
                        allow_redirects=False
                    )
                    
                    if not response or response.status != 200:
                        return None
                    
                    content = await response.text()
                    content_type = response.headers.get('Content-Type', '')
                    content_length = len(content.strip())
                    
                    # Skip empty responses (0 bytes)
                    if content_length == 0:
                        return None
                    
                    # Skip very small responses that are likely empty or error placeholders
                    if content_length < self.MIN_CONTENT_LENGTH:
                        return None
                    
                    # Validate it's actual config content
                    if not self._is_config_content(content, path, content_type):
                        return None
                    
                    # Check for secrets in the content
                    secrets_found = self._find_secrets(content)
                    
                    severity = Severity.CRITICAL if secrets_found else Severity.HIGH
                    
                    # Build detailed evidence with content preview
                    content_preview = content # self._get_content_preview(content, max_length=300)
                    
                    evidence = f"Configuration file accessible: {description}\n"
                    evidence += f"Content-Length: {content_length} bytes\n"
                    evidence += f"Content-Type: {content_type}\n"
                    
                    if secrets_found:
                        # Don't expose actual secrets in evidence
                        evidence += f"Found {len(secrets_found)} potential secret(s): {', '.join([s[0] for s in secrets_found[:3]])}\n"
                    
                    evidence += f"\n--- Content Preview ---\n{content_preview}"
                    
                    return self.create_vulnerability(
                        vuln_type="Exposed Configuration File",
                        severity=severity,
                        url=test_url,
                        parameter="file",
                        payload=path,
                        evidence=evidence,
                        description=f"The configuration file '{path}' is publicly accessible and may contain sensitive information including credentials and API keys.",
                        cwe_id="CWE-260" if secrets_found else "CWE-16",
                        cvss_score=9.8 if secrets_found else 7.5,
                        remediation=self._get_config_remediation(),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                            "https://cwe.mitre.org/data/definitions/260.html"
                        ]
                    )
                
                except Exception:
                    return None
        
        # Check all config files
        tasks = [check_file(path, desc) for path, desc in self.config_files]
        results = await asyncio.gather(*tasks)
        
        vulnerabilities.extend([r for r in results if r is not None])
        
        return vulnerabilities
    
    async def _check_page_content(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check page content for leaked secrets"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            
            if not response or response.status != 200:
                return vulnerabilities
            
            content = await response.text()
            
            # Skip empty content
            if not content or len(content.strip()) < self.MIN_CONTENT_LENGTH:
                return vulnerabilities
            
            # Find secrets in page content
            secrets_found = self._find_secrets(content)
            
            for secret_type, severity in secrets_found[:5]:  # Limit to 5 findings
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type=f"Hardcoded Secret in Page: {secret_type}",
                    severity=severity,
                    url=url,
                    parameter="page content",
                    payload="N/A",
                    evidence=f"Potential {secret_type} found in page content",
                    description=f"A potential {secret_type} was found in the page content. This could expose sensitive credentials.",
                    cwe_id="CWE-547",
                    cvss_score=8.0 if severity == Severity.CRITICAL else 6.0,
                    remediation="Remove hardcoded secrets from client-side code. Use environment variables and server-side configuration.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/547.html"
                    ]
                ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_javascript_files(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check JavaScript files for hardcoded secrets"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            
            if not response or response.status != 200:
                return vulnerabilities
            
            content = await response.text()
            
            # Skip empty content
            if not content or len(content.strip()) < self.MIN_CONTENT_LENGTH:
                return vulnerabilities
            
            # Find JavaScript file references
            js_pattern = r'<script[^>]+src=["\']([^"\']+\.js)["\']'
            js_files = re.findall(js_pattern, content, re.IGNORECASE)
            
            # Also check inline scripts
            inline_pattern = r'<script[^>]*>(.*?)</script>'
            inline_scripts = re.findall(inline_pattern, content, re.IGNORECASE | re.DOTALL)
            
            # Check inline scripts
            for script in inline_scripts:
                if len(script) > 50:  # Skip empty/small scripts
                    secrets = self._find_secrets(script)
                    
                    for secret_type, severity in secrets[:2]:
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type=f"Hardcoded Secret in Inline JavaScript: {secret_type}",
                            severity=severity,
                            url=url,
                            parameter="inline script",
                            payload="N/A",
                            evidence=f"Potential {secret_type} found in inline JavaScript",
                            description=f"A potential {secret_type} was found in inline JavaScript code.",
                            cwe_id="CWE-547",
                            cvss_score=7.5,
                            remediation="Never include secrets in client-side JavaScript. Use server-side APIs.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/547.html"
                            ]
                        ))
            
            # Check external JS files
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for js_file in js_files[:10]:  # Limit to 10 files
                if js_file.startswith('//'):
                    js_url = 'https:' + js_file
                elif js_file.startswith('/'):
                    js_url = base_url + js_file
                elif js_file.startswith('http'):
                    js_url = js_file
                else:
                    js_url = urljoin(url, js_file)
                
                try:
                    js_response = await self.make_request(session, "GET", js_url)
                    
                    if js_response and js_response.status == 200:
                        js_content = await js_response.text()
                        
                        # Skip empty JS files
                        if not js_content or len(js_content.strip()) < self.MIN_CONTENT_LENGTH:
                            continue
                        
                        secrets = self._find_secrets(js_content)
                        
                        for secret_type, severity, matched_value in secrets[:2]:
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type=f"Hardcoded Secret in JavaScript File: {secret_type}",
                                severity=severity,
                                url=js_url,
                                parameter="JavaScript file",
                                payload="N/A",
                                evidence=f"Potential {secret_type} found in {js_file}: {matched_value}",
                                description=f"A potential {secret_type} was found in the JavaScript file '{js_file}'.",
                                cwe_id="CWE-547",
                                cvss_score=7.5,
                                remediation="Remove secrets from JavaScript files. Use server-side APIs for authentication.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/547.html"
                                ]
                            ))
                
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_env_exposure(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for environment variable exposure in responses"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            
            if not response or response.status != 200:
                return vulnerabilities
            
            content = await response.text()
            
            # Skip empty content
            if not content or len(content.strip()) < self.MIN_CONTENT_LENGTH:
                return vulnerabilities
            
            # Look for environment variable patterns
            sensitive_vars = [
                'DATABASE_URL', 'DB_PASSWORD', 'DB_USER',
                'SECRET_KEY', 'API_KEY', 'AWS_SECRET',
                'PRIVATE_KEY', 'AUTH_TOKEN', 'PASSWORD',
                'STRIPE_KEY', 'SENDGRID_KEY', 'TWILIO_KEY',
            ]
            
            for pattern, description in self.env_var_patterns:
                matches = re.findall(pattern, content)
                
                for var_name in matches:
                    if any(s in var_name.upper() for s in ['KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'CREDENTIAL']):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type=f"Environment Variable Reference Exposed",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=var_name,
                            payload="N/A",
                            evidence=f"Reference to sensitive environment variable: {var_name}",
                            description=f"The page references a potentially sensitive environment variable '{var_name}'. While the value may not be exposed, this reveals information about the application's configuration.",
                            cwe_id="CWE-526",
                            cvss_score=4.3,
                            remediation="Avoid referencing sensitive environment variables in client-side code.",
                            references=[
                                "https://cwe.mitre.org/data/definitions/526.html"
                            ]
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_config_content(self, content: str, path: str, content_type: str) -> bool:
        """Verify the content is actual configuration data"""
        
        # Reject empty or near-empty content
        if not content or len(content.strip()) < self.MIN_CONTENT_LENGTH:
            return False
        
        # Skip if it looks like an error page
        error_indicators = [
            'not found', '404', 'error', 'forbidden', '403', '401',
            'access denied', 'unauthorized', 'page not found',
            'file not found', 'does not exist', 'cannot be found'
        ]
        content_lower = content.lower()[:500]
        
        if any(indicator in content_lower for indicator in error_indicators):
            if len(content) < 2000:
                return False
        
        # Skip generic HTML error pages
        if self._is_generic_html_page(content):
            return False
        
        # Check based on file type
        if path.endswith('.env') or '.env.' in path:
            # Should contain KEY=VALUE patterns
            return bool(re.search(r'^[A-Z_]+=.+$', content, re.MULTILINE))
        
        if path.endswith('.php'):
            # Should contain PHP code
            return '<?php' in content or '<?=' in content
        
        if path.endswith('.py'):
            # Should contain Python code patterns
            python_patterns = ['import ', 'from ', 'def ', 'class ', '= {', '= [', '"""', "'''"]
            return any(p in content for p in python_patterns)
        
        if path.endswith('.rb'):
            # Should contain Ruby code patterns
            return 'end' in content or '=>' in content or 'do |' in content
        
        if path.endswith('.yml') or path.endswith('.yaml'):
            # Should contain YAML structure
            if ':' not in content or '\n' not in content:
                return False
            # Check for YAML-like structure
            return bool(re.search(r'^\s*[a-zA-Z_]+:\s*.+$', content, re.MULTILINE))
        
        if path.endswith('.json'):
            # Should start with { or [
            stripped = content.strip()
            if not stripped.startswith(('{', '[')):
                return False
            # Verify it's valid JSON structure
            try:
                json.loads(stripped)
                return True
            except (json.JSONDecodeError, ValueError):
                return False
        
        if path.endswith('.xml'):
            return '<?xml' in content or ('<' in content and '>' in content and '</' in content)
        
        if path.endswith('.properties'):
            return '=' in content and bool(re.search(r'^[a-zA-Z._]+\s*=', content, re.MULTILINE))
        
        if path.endswith('.ini') or path.endswith('.cfg') or path.endswith('.conf'):
            # Should have INI-like structure
            return bool(re.search(r'^$$.+$$$', content, re.MULTILINE)) or '=' in content
        
        if 'key' in path.lower() or 'id_rsa' in path or 'id_dsa' in path or 'id_ecdsa' in path:
            return '-----BEGIN' in content or 'ssh-' in content
        
        if 'Dockerfile' in path:
            dockerfile_keywords = ['FROM ', 'RUN ', 'COPY ', 'ENV ', 'WORKDIR ', 'CMD ', 'ENTRYPOINT ']
            return any(kw in content for kw in dockerfile_keywords)
        
        if 'Jenkinsfile' in path:
            return 'pipeline' in content or 'node' in content or 'stage' in content
        
        # Default: has meaningful content with config-like patterns
        return len(content.strip()) > 20 and ('=' in content or ':' in content)
    
    def _is_generic_html_page(self, content: str) -> bool:
        """Check if content is a generic HTML page (not config data)"""
        content_lower = content.lower().strip()
        
        # If it starts with HTML doctype or html tag, it's likely a web page, not config
        if content_lower.startswith('<!doctype html') or content_lower.startswith('<html'):
            # Unless it's a PHP file that outputs HTML (which would show PHP code if misconfigured)
            if '<?php' not in content and '<?=' not in content:
                return True
        
        # Check for common HTML page indicators
        html_indicators = [
            '<head>', '</head>', '<body>', '</body>',
            '<title>', '</title>', '<meta ', '<link rel=',
            '<div ', '<span ', '<header>', '<footer>',
            '<nav>', '</nav>', '<main>', '</main>'
        ]
        indicator_count = sum(1 for ind in html_indicators if ind.lower() in content_lower)
        
        # If multiple HTML indicators, probably a web page
        if indicator_count >= 3:
            return True
        
        # Check for common CMS/framework error pages
        cms_indicators = [
            'wordpress', 'drupal', 'joomla', 'laravel',
            'symfony', 'django', 'rails', 'express',
            'apache', 'nginx', 'iis'
        ]
        
        # If it looks like a styled error page from a framework
        if any(cms in content_lower for cms in cms_indicators):
            if '<html' in content_lower and indicator_count >= 2:
                return True
        
        return False
    
    def _get_content_preview(self, content: str, max_length: int = 200) -> str:
        """Get a sanitized preview of the content for evidence"""
        if not content:
            return "[Empty]"
        
        # Remove sensitive data patterns before showing preview
        sanitized = content.strip()
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "\n... [truncated]"
        
        # Mask potential passwords/secrets in preview
        mask_patterns = [
            (r'(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{0,3})[^\s"\']*', r'\1=\2***[MASKED]'),
            (r'(secret|secret_key)\s*[=:]\s*["\']?([^\s"\']{0,3})[^\s"\']*', r'\1=\2***[MASKED]'),
            (r'(api_?key|apikey)\s*[=:]\s*["\']?([^\s"\']{0,3})[^\s"\']*', r'\1=\2***[MASKED]'),
            (r'(token|auth_token)\s*[=:]\s*["\']?([^\s"\']{0,3})[^\s"\']*', r'\1=\2***[MASKED]'),
            (r'(access_key|secret_access)\s*[=:]\s*["\']?([^\s"\']{0,3})[^\s"\']*', r'\1=\2***[MASKED]'),
            (r'(AKIA[0-9A-Z]{3})[0-9A-Z]{13}', r'\1***[MASKED]'),  # AWS Access Key
            (r'(sk_live_[a-zA-Z0-9]{3})[a-zA-Z0-9]+', r'\1***[MASKED]'),  # Stripe Key
            (r'(ghp_[a-zA-Z0-9]{3})[a-zA-Z0-9]+', r'\1***[MASKED]'),  # GitHub Token
        ]
        
        for pattern, replacement in mask_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    # def _find_secrets(self, content: str) -> List[Tuple[str, Severity]]:
    #     """Find secrets in content"""
    #     secrets_found = []
    #     seen_types = set()  # Avoid duplicate secret types
        
    #     for pattern, secret_type, severity in self.secret_patterns:
    #         if secret_type not in seen_types and re.search(pattern, content):
    #             secrets_found.append((secret_type, severity))
    #             seen_types.add(secret_type)
        
    #     return secrets_found

    def _find_secrets(self, content: str) -> List[Tuple[str, Severity, str]]:
        """Find secrets in content, returning type, severity, and matched value"""
        secrets_found = []
        seen_types = set()  # Avoid duplicate secret types
        
        for pattern, secret_type, severity in self.secret_patterns:
            if secret_type not in seen_types:
                match = re.search(pattern, content)
                if match:
                    # Get the full match or the first group if available
                    matched_value = match.group(1) if match.lastindex else match.group(0)
                    secrets_found.append((secret_type, severity, matched_value))
                    seen_types.add(secret_type)
        
        return secrets_found
    
    def _get_config_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Block access to configuration files via web server configuration:

   Apache (.htaccess):
   <FilesMatch "\.(env|config|yml|yaml|json|ini|xml|key|pem)$">
       Order allow,deny
       Deny from all
   </FilesMatch>

   Nginx:
   location ~ /\.(env|git|svn|htaccess|htpasswd) {
       deny all;
       return 404;
   }
   
   location ~* \.(yml|yaml|json|ini|xml|key|pem|conf|cfg)$ {
       deny all;
       return 404;
   }

2. Store sensitive configuration outside the web root directory

3. Use environment variables instead of config files for secrets

4. Implement proper secret management solutions:
   - HashiCorp Vault
   - AWS Secrets Manager
   - Azure Key Vault
   - Google Cloud Secret Manager

5. Never commit secrets to version control:
   - Add sensitive files to .gitignore
   - Use git-secrets or similar tools to prevent accidental commits
   - Scan repositories for leaked secrets regularly

6. Regularly rotate credentials and API keys

7. Use different credentials for development, staging, and production

8. Implement least privilege access for all credentials

9. Monitor and alert on unauthorized access to configuration endpoints
"""