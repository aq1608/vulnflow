# scanner/supply_chain/outdated_components.py
"""
Outdated Components Scanner

Detects outdated frameworks and server software:
- Web server version disclosure
- Framework version detection
- CMS version detection
- Outdated security headers

OWASP: A03:2025 - Software Supply Chain Failures
CWE-1104: Use of Unmaintained Third Party Components
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class OutdatedComponentsScanner(BaseScanner):
    """Scanner for outdated software components"""
    
    name = "Outdated Components Scanner"
    description = "Detects outdated frameworks, servers, and CMS versions"
    owasp_category = OWASPCategory.A03_SUPPLY_CHAIN_FAILURES
    
    def __init__(self):
        super().__init__()
        
        # Server headers that reveal version info
        self.version_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Generator',
            'X-Drupal-Cache',
            'X-Drupal-Dynamic-Cache',
            'X-Pingback',
            'X-Redirect-By',
        ]
        
        # Meta tag patterns for framework/CMS detection
        self.meta_patterns = [
            (r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', 'Generator'),
            (r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']', 'Generator'),
            (r'<!--\s*This is Squarespace\s*-->', 'Squarespace'),
        ]
        
        # CMS-specific detection patterns
        self.cms_patterns = {
            'WordPress': {
                'patterns': [
                    r'/wp-content/',
                    r'/wp-includes/',
                    r'wp-json',
                    r'<meta name="generator" content="WordPress\s*([\d.]+)?',
                ],
                'version_file': '/wp-includes/version.php',
                'readme_file': '/readme.html',
            },
            'Drupal': {
                'patterns': [
                    r'Drupal',
                    r'/sites/default/',
                    r'drupal\.js',
                    r'<meta name="Generator" content="Drupal\s*([\d.]+)?',
                ],
                'version_file': '/CHANGELOG.txt',
            },
            'Joomla': {
                'patterns': [
                    r'/media/jui/',
                    r'/components/com_',
                    r'<meta name="generator" content="Joomla',
                ],
                'version_file': '/administrator/manifests/files/joomla.xml',
            },
            'Magento': {
                'patterns': [
                    r'/skin/frontend/',
                    r'/js/mage/',
                    r'Mage\.Cookies',
                ],
            },
            'Shopify': {
                'patterns': [
                    r'cdn\.shopify\.com',
                    r'Shopify\.theme',
                ],
            },
        }
        
        # Known vulnerable server versions
        self.vulnerable_servers = {
            'Apache': [
                {'max_version': '2.4.49', 'cve': 'CVE-2021-41773', 'severity': Severity.CRITICAL,
                 'description': 'Path traversal and RCE vulnerability'},
                {'max_version': '2.4.50', 'cve': 'CVE-2021-42013', 'severity': Severity.CRITICAL,
                 'description': 'Path traversal bypass of CVE-2021-41773 fix'},
            ],
            'nginx': [
                {'max_version': '1.20.0', 'cve': 'CVE-2021-23017', 'severity': Severity.HIGH,
                 'description': 'DNS resolver vulnerability'},
            ],
            'Microsoft-IIS': [
                {'max_version': '7.5', 'cve': 'Multiple', 'severity': Severity.HIGH,
                 'description': 'IIS 7.5 and earlier have multiple known vulnerabilities'},
            ],
            'PHP': [
                {'max_version': '7.4.29', 'cve': 'CVE-2022-31626', 'severity': Severity.HIGH,
                 'description': 'Buffer overflow vulnerability'},
                {'max_version': '8.0.19', 'cve': 'CVE-2022-31627', 'severity': Severity.HIGH,
                 'description': 'Heap buffer overflow in finfo_buffer'},
            ],
        }
        
        # Files that often expose version information
        self.version_files = [
            '/VERSION',
            '/version.txt',
            '/CHANGELOG.md',
            '/CHANGELOG.txt',
            '/CHANGES.txt',
            '/README.md',
            '/README.txt',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for outdated components."""
        vulnerabilities = []
        
        # Test 1: Check server headers for version disclosure
        header_vulns = await self._check_server_headers(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Test 2: Detect CMS and version
        cms_vulns = await self._detect_cms(session, url)
        vulnerabilities.extend(cms_vulns)
        
        # Test 3: Check for exposed version files
        file_vulns = await self._check_version_files(session, url)
        vulnerabilities.extend(file_vulns)
        
        # Test 4: Check technology stack via various indicators
        tech_vulns = await self._analyze_technology_stack(session, url)
        vulnerabilities.extend(tech_vulns)
        
        return vulnerabilities
    
    async def _check_server_headers(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check server headers for version information."""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                
                for header in self.version_headers:
                    value = response.headers.get(header, '')
                    if value:
                        # Extract version number
                        version_match = re.search(r'([\d.]+)', value)
                        
                        # Check for known vulnerable versions
                        vuln_found = False
                        for server_name, vulns in self.vulnerable_servers.items():
                            if server_name.lower() in value.lower():
                                if version_match:
                                    version = version_match.group(1)
                                    for vuln in vulns:
                                        if self._is_version_vulnerable(version, vuln['max_version']):
                                            vulnerabilities.append(Vulnerability(
                                                vuln_type=f"Vulnerable {server_name} Version",
                                                severity=vuln['severity'],
                                                url=url,
                                                parameter=header,
                                                payload=value,
                                                evidence=f"Detected {server_name} {version} (vulnerable <= {vuln['max_version']})",
                                                description=f"{vuln['description']} ({vuln['cve']})",
                                                cwe_id="CWE-1104",
                                                owasp_category=self.owasp_category,
                                                remediation=self._get_server_remediation(server_name)
                                            ))
                                            vuln_found = True
                                            break
                        
                        # Even if not known vulnerable, version disclosure is an issue
                        if not vuln_found and version_match:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Server Version Disclosure",
                                severity=Severity.LOW,
                                url=url,
                                parameter=header,
                                payload=value,
                                evidence=f"Server reveals version: {value}",
                                description=f"The {header} header discloses software version information",
                                cwe_id="CWE-200",
                                owasp_category=self.owasp_category,
                                remediation=self._get_disclosure_remediation()
                            ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _detect_cms(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Detect CMS and check for outdated versions."""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                if response.status != 200:
                    return vulnerabilities
                
                content = await response.text()
                
                for cms_name, cms_info in self.cms_patterns.items():
                    detected = False
                    detected_version = None
                    
                    for pattern in cms_info['patterns']:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            detected = True
                            if match.groups():
                                detected_version = match.group(1)
                            break
                    
                    if detected:
                        # Try to get more precise version
                        if not detected_version and 'version_file' in cms_info:
                            detected_version = await self._get_cms_version(
                                session, url, cms_info['version_file'], cms_name
                            )
                        
                        severity = Severity.INFO
                        description = f"{cms_name} CMS detected"
                        
                        if detected_version:
                            description += f" (version {detected_version})"
                            severity = Severity.LOW
                        
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"CMS Detection - {cms_name}",
                            severity=severity,
                            url=url,
                            parameter="cms",
                            payload=cms_name,
                            evidence=f"Detected {cms_name}" + (f" version {detected_version}" if detected_version else ""),
                            description=description + ". Ensure CMS is kept up to date.",
                            cwe_id="CWE-200",
                            owasp_category=self.owasp_category,
                            remediation=self._get_cms_remediation(cms_name)
                        ))
                        break  # Found CMS, stop looking
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _get_cms_version(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        version_file: str,
        cms_name: str
    ) -> Optional[str]:
        """Try to get CMS version from known version files."""
        try:
            parsed = urlparse(base_url)
            version_url = f"{parsed.scheme}://{parsed.netloc}{version_file}"
            
            async with session.get(
                version_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # WordPress version patterns
                    if cms_name == 'WordPress':
                        match = re.search(r"wp_version\s*=\s*'([\d.]+)'", content)
                        if match:
                            return match.group(1)
                    
                    # Drupal version patterns
                    elif cms_name == 'Drupal':
                        match = re.search(r'Drupal ([\d.]+)', content)
                        if match:
                            return match.group(1)
                    
                    # Joomla version patterns
                    elif cms_name == 'Joomla':
                        match = re.search(r'<version>([\d.]+)</version>', content)
                        if match:
                            return match.group(1)
                    
                    # Generic version pattern
                    match = re.search(r'(?:version|Version|VERSION)[:\s]*([\d.]+)', content)
                    if match:
                        return match.group(1)
        
        except Exception:
            pass
        
        return None
    
    async def _check_version_files(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for exposed version/changelog files."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for file_path in self.version_files:
            try:
                test_url = urljoin(base_url, file_path)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if it's actually a version/changelog file
                        if self._is_version_file(content):
                            # Try to extract version
                            version = self._extract_version(content)
                            
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Exposed Version File",
                                severity=Severity.LOW,
                                url=test_url,
                                parameter="file",
                                payload=file_path,
                                evidence=f"Version file accessible" + (f" (version {version})" if version else ""),
                                description=f"Version/changelog file {file_path} is publicly accessible",
                                cwe_id="CWE-200",
                                owasp_category=self.owasp_category,
                                remediation=self._get_file_remediation()
                            ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_version_file(self, content: str) -> bool:
        """Check if content appears to be a version/changelog file."""
        indicators = [
            'version', 'Version', 'VERSION',
            'changelog', 'Changelog', 'CHANGELOG',
            'release', 'Release', 'RELEASE',
            '## [', '# v', 'v1.', 'v2.', 'v3.',
        ]
        return any(indicator in content for indicator in indicators)
    
    def _extract_version(self, content: str) -> Optional[str]:
        """Extract version number from content."""
        patterns = [
            r'(?:version|Version|VERSION)[:\s]*([\d.]+)',
            r'## \[([\d.]+)\]',
            r'# v([\d.]+)',
            r'^([\d.]+)$',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                return match.group(1)
        
        return None
    
    async def _analyze_technology_stack(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Analyze various indicators to detect technology stack."""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                                # Check for deprecated/EOL technologies
                deprecated_techs = [
                    {
                        'pattern': r'jquery[.-]?(1\.[0-9]|2\.[0-2])',
                        'name': 'jQuery 1.x/2.x',
                        'message': 'Using deprecated jQuery version, upgrade to 3.x',
                        'severity': Severity.MEDIUM
                    },
                    {
                        'pattern': r'angular\.js|angularjs',
                        'name': 'AngularJS (1.x)',
                        'message': 'AngularJS is in LTS mode and no longer actively developed',
                        'severity': Severity.LOW
                    },
                    {
                        'pattern': r'backbone[.-]?js',
                        'name': 'Backbone.js',
                        'message': 'Backbone.js is largely unmaintained',
                        'severity': Severity.INFO
                    },
                    {
                        'pattern': r'prototype\.js',
                        'name': 'Prototype.js',
                        'message': 'Prototype.js is deprecated and unmaintained',
                        'severity': Severity.MEDIUM
                    },
                    {
                        'pattern': r'mootools',
                        'name': 'MooTools',
                        'message': 'MooTools is no longer actively maintained',
                        'severity': Severity.LOW
                    },
                    {
                        'pattern': r'ext-all\.js|extjs',
                        'name': 'ExtJS (older versions)',
                        'message': 'Older ExtJS versions may have security issues',
                        'severity': Severity.INFO
                    },
                ]
                
                for tech in deprecated_techs:
                    if re.search(tech['pattern'], content, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"Deprecated Technology - {tech['name']}",
                            severity=tech['severity'],
                            url=url,
                            parameter="technology",
                            payload=tech['name'],
                            evidence=f"Detected {tech['name']} in page source",
                            description=tech['message'],
                            cwe_id="CWE-1104",
                            owasp_category=self.owasp_category,
                            remediation=self._get_deprecated_tech_remediation(tech['name'])
                        ))
                
                # Check for EOL PHP versions in headers
                php_version = headers.get('X-Powered-By', '')
                if 'PHP' in php_version:
                    version_match = re.search(r'PHP/([\d.]+)', php_version)
                    if version_match:
                        version = version_match.group(1)
                        major_minor = '.'.join(version.split('.')[:2])
                        
                        # EOL PHP versions (as of 2024)
                        eol_versions = ['5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0']
                        
                        if major_minor in eol_versions:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="End-of-Life PHP Version",
                                severity=Severity.HIGH,
                                url=url,
                                parameter="X-Powered-By",
                                payload=php_version,
                                evidence=f"PHP {version} is end-of-life and no longer receives security updates",
                                description=f"Server is running PHP {version} which has reached end-of-life",
                                cwe_id="CWE-1104",
                                owasp_category=self.owasp_category,
                                remediation=self._get_php_remediation(version)
                            ))
                
                # Check for ASP.NET version disclosure
                aspnet_version = headers.get('X-AspNet-Version', '')
                if aspnet_version:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="ASP.NET Version Disclosure",
                        severity=Severity.LOW,
                        url=url,
                        parameter="X-AspNet-Version",
                        payload=aspnet_version,
                        evidence=f"ASP.NET version disclosed: {aspnet_version}",
                        description="Server discloses ASP.NET framework version",
                        cwe_id="CWE-200",
                        owasp_category=self.owasp_category,
                        remediation=self._get_aspnet_remediation()
                    ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_version_vulnerable(self, detected: str, max_vulnerable: str) -> bool:
        """Compare versions to determine if detected version is vulnerable."""
        try:
            detected_parts = [int(x) for x in detected.split('.')[:3]]
            max_parts = [int(x) for x in max_vulnerable.split('.')[:3]]
            
            # Pad shorter version
            while len(detected_parts) < 3:
                detected_parts.append(0)
            while len(max_parts) < 3:
                max_parts.append(0)
            
            return detected_parts <= max_parts
        except (ValueError, AttributeError):
            return False
    
    def _get_server_remediation(self, server_name: str) -> str:
        """Get server-specific remediation advice."""
        return f"""
1. Update {server_name} to the latest stable version immediately
2. Subscribe to security mailing lists for {server_name}
3. Implement a patch management process
4. Consider using automated update tools where appropriate

For {server_name}:
{'- Apache: Use apt/yum update or download from httpd.apache.org' if 'Apache' in server_name else ''}
{'- nginx: Use package manager or compile from source (nginx.org)' if 'nginx' in server_name else ''}
{'- IIS: Use Windows Update or Server Manager' if 'IIS' in server_name else ''}
{'- PHP: Use package manager or download from php.net' if 'PHP' in server_name else ''}

5. After updating, hide version information:

Apache (httpd.conf):
```apache
ServerTokens Prod
ServerSignature Off
```
nginx (nginx.conf):

```nginx
server_tokens off;
IIS (web.config):
```

xml
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <remove name="X-Powered-By" />
        </customHeaders>
    </httpProtocol>
</system.webServer>
"""

    def _get_disclosure_remediation(self) -> str:
        """Get version disclosure remediation advice."""
        return """
1. Configure your web server to hide version information:
Apache (httpd.conf):

```apache
ServerTokens Prod
ServerSignature Off
```
nginx (nginx.conf):

```nginx
server_tokens off;
IIS (web.config):
```
```xml
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <remove name="Server" />
            <remove name="X-Powered-By" />
            <remove name="X-AspNet-Version" />
        </customHeaders>
    </httpProtocol>
    <security>
        <requestFiltering removeServerHeader="true" />
    </security>
</system.webServer>
```
PHP (php.ini):

ini
expose_php = Off
2. Use a reverse proxy or WAF to strip version headers

3. Regularly audit response headers for information leakage
"""

    def _get_cms_remediation(self, cms_name: str) -> str:
        """Get CMS-specific remediation advice."""
        cms_advice = {
            'WordPress': """
1. Update WordPress core to the latest version
2. Update all plugins and themes
3. Enable automatic updates for minor releases
4. Use a security plugin (Wordfence, Sucuri, iThemes Security)
5. Remove readme.html and other version-disclosing files
6. Hide WordPress version:
    In functions.php:

    ```php
        remove_action('wp_head', 'wp_generator');
    ```
            """,
            'Drupal': """
Update Drupal core using Composer or Drush
Subscribe to Drupal security announcements
Remove CHANGELOG.txt from production
Use Security Kit module
Regularly audit contributed modules
Update command:

bash
drush pm-update drupal
# or
composer update drupal/core --with-dependencies
""",
'Joomla': """

Update Joomla via Administrator panel

Enable Joomla Update notifications

Remove installation files and version disclosure files

Use Joomla's built-in 2FA

Regularly audit extensions for updates
""",
}

        return cms_advice.get(cms_name, f"""
Keep {cms_name} updated to the latest version

Subscribe to security announcements

Remove version-disclosing files from production

Regularly audit plugins/extensions

Implement security hardening guidelines
""")

    def _get_file_remediation(self) -> str:
        """Get remediation for exposed version files."""
        return """

1. Remove or restrict access to version/changelog files in production:

Nginx:

nginx
location ~* (VERSION|CHANGELOG|README)\\.(txt|md|html)$ {
    deny all;
    return 404;
}
Apache (.htaccess):

apache
<FilesMatch "(VERSION|CHANGELOG|README)\\.(txt|md|html)$">
    Order allow,deny
    Deny from all
</FilesMatch>
Exclude these files from deployment:

Add to .gitignore for production branches
Remove in build/deployment scripts
If files must exist, consider:

Moving to a non-web-accessible directory
Requiring authentication to access
"""
    def _get_deprecated_tech_remediation(self, tech_name: str) -> str:
        """Get remediation for deprecated technologies."""
        return f"""

Plan migration away from {tech_name}:

Evaluate modern alternatives
Create a migration roadmap
Test thoroughly before deployment
If immediate migration isn't possible:

Ensure you're using the latest available version
Monitor for security advisories
Implement additional security controls (WAF, CSP)
Modern alternatives to consider:

jQuery 1.x/2.x → jQuery 3.x or vanilla JavaScript
AngularJS → Angular (2+), React, or Vue.js
Backbone.js → React, Vue.js, or Svelte
Prototype.js → Modern JavaScript (ES6+)
Document all deprecated dependencies

Include technical debt in sprint planning
"""

    def _get_php_remediation(self, version: str) -> str:
        """Get PHP version remediation advice."""
        return f"""
⚠️ CRITICAL: PHP {version} has reached End-of-Life!

Upgrade PHP immediately to a supported version:

PHP 8.1 (Security support until Nov 2024)
PHP 8.2 (Security support until Dec 2025)
PHP 8.3 (Active support)
Before upgrading:

Test application compatibility
Review PHP migration guides
Update deprecated function calls
Upgrade commands:

Ubuntu/Debian:

bash
sudo apt update
sudo apt install php8.2
sudo a2dismod php{version.split('.')[0]}.{version.split('.')[1] if len(version.split('.')) > 1 else '0'}
sudo a2enmod php8.2
sudo systemctl restart apache2
CentOS/RHEL (with Remi):

bash
sudo dnf module reset php
sudo dnf module enable php:remi-8.2
sudo dnf install php
Hide PHP version after upgrade:
ini
; php.ini
expose_php = Off
"""

    def _get_aspnet_remediation(self) -> str:
        """Get ASP.NET remediation advice."""
        return """
Remove ASP.NET version header in web.config:
xml
<system.web>
    <httpRuntime enableVersionHeader="false" />
</system.web>

<system.webServer>
    <httpProtocol>
        <customHeaders>
            <remove name="X-AspNet-Version" />
            <remove name="X-AspNetMvc-Version" />
            <remove name="X-Powered-By" />
        </customHeaders>
    </httpProtocol>
</system.webServer>
For ASP.NET Core, version headers are not sent by default

In Global.asax.cs (for MVC):

csharp
protected void Application_Start()
{
    MvcHandler.DisableMvcResponseHeader = true;
}
Ensure .NET Framework/Core is up to date
Use URL Rewrite module to remove remaining headers
"""