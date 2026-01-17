# scanner/cve/known_cve.py
"""
Known CVE Scanner

Detects known vulnerabilities based on:
- Server/framework version disclosure
- Technology fingerprinting
- Common vulnerable components

OWASP: A06:2021 - Vulnerable and Outdated Components
CWE-1035: OWASP Top 10 2017 - Using Components with Known Vulnerabilities
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class KnownCVEScanner(BaseScanner):
    """Scanner for known CVEs based on version detection"""
    
    name="Known CVE Scanner",
    description="Detects known vulnerabilities in components",
    owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS

    def __init__(self):
        
        # Known vulnerable versions database
        # Format: (product, version_regex, CVE, severity, description)
        self.vulnerability_database = [
            # Apache
            ("Apache", r"Apache/2\.4\.([0-4]\d|50)", "CVE-2021-44790", Severity.CRITICAL,
             "Apache HTTP Server buffer overflow"),
            ("Apache", r"Apache/2\.4\.(1[0-7]|[0-9])[^\d]", "CVE-2017-15715", Severity.HIGH,
             "Apache HTTP Server file upload bypass"),
            ("Apache", r"Apache/2\.2\.", "CVE-2017-3167", Severity.HIGH,
             "Apache HTTP Server authentication bypass (outdated 2.2.x)"),
            
            # Nginx
            ("Nginx", r"nginx/1\.(1[0-7]\.|[0-9]\.)", "CVE-2021-23017", Severity.HIGH,
             "Nginx DNS resolver vulnerability"),
            ("Nginx", r"nginx/1\.1[0-4]\.", "CVE-2019-20372", Severity.MEDIUM,
             "Nginx HTTP request smuggling"),
            
            # PHP
            ("PHP", r"PHP/7\.4\.([0-2]\d|3[0-2])[^\d]", "CVE-2023-3823", Severity.HIGH,
             "PHP XML external entity vulnerability"),
            ("PHP", r"PHP/7\.[0-3]\.", "CVE-2019-11043", Severity.CRITICAL,
             "PHP-FPM remote code execution"),
            ("PHP", r"PHP/5\.", "CVE-2019-11043", Severity.CRITICAL,
             "PHP 5.x - Multiple known vulnerabilities (EOL)"),
            
            # WordPress
            ("WordPress", r"WordPress\s*[0-4]\.", "Multiple CVEs", Severity.HIGH,
             "WordPress < 5.0 - Multiple known vulnerabilities"),
            ("WordPress", r"WordPress\s*5\.[0-7]\.", "CVE-2022-21661", Severity.HIGH,
             "WordPress SQL injection vulnerability"),
            
            # jQuery
            ("jQuery", r"jquery[/\-]1\.", "CVE-2019-11358", Severity.MEDIUM,
             "jQuery < 3.4.0 prototype pollution"),
            ("jQuery", r"jquery[/\-]2\.", "CVE-2019-11358", Severity.MEDIUM,
             "jQuery < 3.4.0 prototype pollution"),
            ("jQuery", r"jquery[/\-]3\.[0-3]\.", "CVE-2019-11358", Severity.MEDIUM,
             "jQuery < 3.4.0 prototype pollution"),
            
            # Express.js
            ("Express", r"express[/\-]4\.[0-9]\.", "CVE-2022-24999", Severity.HIGH,
             "Express.js < 4.17.3 - qs prototype pollution"),
            
            # Django
            ("Django", r"Django/[0-2]\.", "Multiple CVEs", Severity.HIGH,
             "Django < 3.0 - Multiple known vulnerabilities (EOL)"),
            ("Django", r"Django/3\.[0-1]\.", "CVE-2021-44420", Severity.HIGH,
             "Django potential directory traversal"),
            
            # Spring Framework
            ("Spring", r"Spring.*[0-4]\.", "CVE-2022-22965", Severity.CRITICAL,
             "Spring4Shell - Remote code execution"),
            
            # Laravel
            ("Laravel", r"Laravel.*[0-7]\.", "CVE-2021-43503", Severity.HIGH,
             "Laravel < 8.0 - Multiple known vulnerabilities"),
            
            # ASP.NET
            ("ASP.NET", r"ASP\.NET\s*[0-3]\.", "Multiple CVEs", Severity.MEDIUM,
             "ASP.NET < 4.0 - Multiple known vulnerabilities"),
            
            # OpenSSL
            ("OpenSSL", r"OpenSSL/1\.0\.", "CVE-2020-1971", Severity.HIGH,
             "OpenSSL 1.0.x - Multiple vulnerabilities (EOL)"),
            ("OpenSSL", r"OpenSSL/1\.1\.0", "CVE-2020-1971", Severity.MEDIUM,
             "OpenSSL 1.1.0 - NULL pointer dereference"),
            
            # IIS
            ("IIS", r"Microsoft-IIS/[0-7]\.", "Multiple CVEs", Severity.MEDIUM,
             "IIS < 8.0 - Multiple known vulnerabilities"),
            ("IIS", r"Microsoft-IIS/10\.0", "CVE-2021-31166", Severity.CRITICAL,
             "IIS HTTP Protocol Stack RCE (if unpatched)"),
            
            # Tomcat
            ("Tomcat", r"Apache-Coyote.*Tomcat/[0-8]\.", "CVE-2020-1938", Severity.CRITICAL,
             "Apache Tomcat AJP Ghostcat vulnerability"),
            ("Tomcat", r"Tomcat/9\.0\.[0-3][0-9][^\d]", "CVE-2020-9484", Severity.HIGH,
             "Apache Tomcat session persistence RCE"),
            
            # Bootstrap
            ("Bootstrap", r"bootstrap[/\-][0-3]\.", "CVE-2019-8331", Severity.MEDIUM,
             "Bootstrap < 4.3.1 XSS vulnerability"),
            
            # Angular
            ("Angular", r"angular[/\-][1-5]\.", "CVE-2020-7676", Severity.MEDIUM,
             "Angular < 6.0 prototype pollution"),
            
            # lodash
            ("lodash", r"lodash[/\-][0-3]\.", "CVE-2019-10744", Severity.HIGH,
             "lodash < 4.17.12 prototype pollution"),
            ("lodash", r"lodash[/\-]4\.(0|1[0-6])\.", "CVE-2019-10744", Severity.HIGH,
             "lodash < 4.17.12 prototype pollution"),
        ]
        
        # Paths to check for version information
        self.version_paths = [
            "/",
            "/index.html",
            "/index.php",
            "/admin",
            "/login",
            "/wp-admin",
            "/wp-login.php",
            "/readme.html",
            "/README.md",
            "/CHANGELOG.md",
            "/package.json",
            "/composer.json",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for known CVEs based on version detection.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Collect version information from multiple sources
        versions = await self._collect_versions(session, base_url)
        
        # Check against vulnerability database
        for product, version, source in versions:
            cve_vulns = self._check_vulnerabilities(product, version, url, source)
            vulnerabilities.extend(cve_vulns)
        
        # Deduplicate
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln.vuln_type, vuln.cwe_id)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    async def _collect_versions(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Tuple[str, str, str]]:
        """Collect version information from various sources"""
        versions = []
        
        # Check main page and headers
        main_versions = await self._check_headers_and_body(session, base_url)
        versions.extend(main_versions)
        
        # Check specific paths
        for path in self.version_paths[1:5]:  # Limit checks
            try:
                test_url = urljoin(base_url, path)
                path_versions = await self._check_headers_and_body(session, test_url)
                versions.extend(path_versions)
            except:
                continue
        
        # Check JavaScript libraries
        js_versions = await self._check_javascript_libraries(session, base_url)
        versions.extend(js_versions)
        
        return versions
    
    async def _check_headers_and_body(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Tuple[str, str, str]]:
        """Check response headers and body for version info"""
        versions = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
                allow_redirects=True
            ) as response:
                # Check Server header
                server = response.headers.get('Server', '')
                if server:
                    versions.extend(self._parse_server_header(server, url))
                
                # Check X-Powered-By header
                powered_by = response.headers.get('X-Powered-By', '')
                if powered_by:
                    versions.extend(self._parse_powered_by(powered_by, url))
                
                # Check body for version strings
                if response.status == 200:
                    body = await response.text()
                    body_versions = self._extract_versions_from_body(body, url)
                    versions.extend(body_versions)
        
        except Exception:
            pass
        
        return versions
    
    def _parse_server_header(
        self,
        server: str,
        url: str
    ) -> List[Tuple[str, str, str]]:
        """Parse Server header for version info"""
        versions = []
        
        patterns = [
            (r"Apache/([\d.]+)", "Apache"),
            (r"nginx/([\d.]+)", "Nginx"),
            (r"Microsoft-IIS/([\d.]+)", "IIS"),
            (r"LiteSpeed/([\d.]+)", "LiteSpeed"),
            (r"openresty/([\d.]+)", "OpenResty"),
        ]
        
        for pattern, product in patterns:
            match = re.search(pattern, server, re.IGNORECASE)
            if match:
                versions.append((product, server, f"Server header: {server}"))
        
        return versions
    
    def _parse_powered_by(
        self,
        powered_by: str,
        url: str
    ) -> List[Tuple[str, str, str]]:
        """Parse X-Powered-By header"""
        versions = []
        
        patterns = [
            (r"PHP/([\d.]+)", "PHP"),
            (r"ASP\.NET", "ASP.NET"),
            (r"Express", "Express"),
            (r"Django", "Django"),
        ]
        
        for pattern, product in patterns:
            if re.search(pattern, powered_by, re.IGNORECASE):
                versions.append((product, powered_by, f"X-Powered-By: {powered_by}"))
        
        return versions
    
    def _extract_versions_from_body(
        self,
        body: str,
        url: str
    ) -> List[Tuple[str, str, str]]:
        """Extract version info from response body"""
        versions = []
        
        # WordPress
        wp_match = re.search(r'<meta[^>]*generator[^>]*WordPress\s*([\d.]+)', body, re.IGNORECASE)
        if wp_match:
            versions.append(("WordPress", f"WordPress {wp_match.group(1)}", "Meta generator tag"))
        
        # Drupal
        drupal_match = re.search(r'Drupal\s*([\d.]+)', body)
        if drupal_match:
            versions.append(("Drupal", f"Drupal {drupal_match.group(1)}", "Body content"))
        
        # Joomla
        joomla_match = re.search(r'Joomla!?\s*([\d.]+)', body)
        if joomla_match:
            versions.append(("Joomla", f"Joomla {joomla_match.group(1)}", "Body content"))
        
        return versions
    
    async def _check_javascript_libraries(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Tuple[str, str, str]]:
        """Check for vulnerable JavaScript libraries"""
        versions = []
        
        try:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                if response.status == 200:
                    body = await response.text()
                    
                    # jQuery version patterns
                    jquery_patterns = [
                        r'jquery[.-](\d+\.\d+\.\d+)',
                        r'jQuery\s+v?(\d+\.\d+\.\d+)',
                        r'jquery\.min\.js\?v=(\d+\.\d+\.\d+)',
                    ]
                    
                    for pattern in jquery_patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            versions.append(("jQuery", f"jquery/{match.group(1)}", "JavaScript include"))
                            break
                    
                    # Bootstrap version
                    bootstrap_match = re.search(r'bootstrap[.-](\d+\.\d+\.\d+)', body, re.IGNORECASE)
                    if bootstrap_match:
                        versions.append(("Bootstrap", f"bootstrap/{bootstrap_match.group(1)}", "JavaScript/CSS include"))
                    
                    # Angular version
                    angular_match = re.search(r'angular[.-](\d+\.\d+\.\d+)', body, re.IGNORECASE)
                    if angular_match:
                        versions.append(("Angular", f"angular/{angular_match.group(1)}", "JavaScript include"))
                    
                    # lodash version
                    lodash_match = re.search(r'lodash[.-](\d+\.\d+\.\d+)', body, re.IGNORECASE)
                    if lodash_match:
                        versions.append(("lodash", f"lodash/{lodash_match.group(1)}", "JavaScript include"))
        
        except Exception:
            pass
        
        return versions
    
    def _check_vulnerabilities(
        self,
        product: str,
        version_string: str,
        url: str,
        source: str
    ) -> List[Vulnerability]:
        """Check version against vulnerability database"""
        vulnerabilities = []
        
        for db_product, version_pattern, cve, severity, description in self.vulnerability_database:
            if product.lower() == db_product.lower():
                if re.search(version_pattern, version_string, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        vuln_type=f"Known Vulnerability: {cve}",
                        severity=severity,
                        url=url,
                        parameter=product,
                        payload="N/A",
                        evidence=f"{source}",
                        description=f"{description} (Version: {version_string})",
                        cwe_id="CWE-1035",
                        remediation=f"Update {product} to the latest version. CVE: {cve}"
                    ))
        
        return vulnerabilities