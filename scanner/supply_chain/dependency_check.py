# scanner/supply_chain/dependency_check.py
"""
Dependency Check Scanner

Detects vulnerable JavaScript libraries and frameworks:
- Known vulnerable versions of popular libraries
- Libraries with known CVEs
- Outdated dependencies with security issues

OWASP: A03:2025 - Software Supply Chain Failures
CWE-1035: OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities
"""

import asyncio
import aiohttp
import re
import json
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class DependencyCheckScanner(BaseScanner):
    """Scanner for vulnerable JavaScript dependencies"""
    
    name = "Dependency Check Scanner"
    description = "Detects vulnerable JavaScript libraries and frameworks"
    owasp_category = OWASPCategory.A03_SUPPLY_CHAIN_FAILURES
    
    def __init__(self):
        super().__init__()
        
        # Known vulnerable library patterns with version detection
        # Format: (library_name, pattern, vulnerable_versions, severity, cve, description)
        self.vulnerable_libraries = [
            # jQuery vulnerabilities
            {
                "name": "jQuery",
                "patterns": [
                    r"jquery[.-]?([\d.]+)(?:\.min)?\.js",
                    r"jquery\.js\?v=([\d.]+)",
                    r"/jquery/([\d.]+)/",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "1.6.2",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2011-4969",
                        "description": "XSS vulnerability in jQuery before 1.6.3"
                    },
                    {
                        "max_version": "1.11.3",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2015-9251",
                        "description": "jQuery before 3.0.0 vulnerable to XSS via cross-domain ajax requests"
                    },
                    {
                        "max_version": "3.4.1",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2020-11022",
                        "description": "jQuery before 3.5.0 vulnerable to XSS in htmlPrefilter"
                    },
                ]
            },
            # Angular.js vulnerabilities
            {
                "name": "AngularJS",
                "patterns": [
                    r"angular[.-]?([\d.]+)(?:\.min)?\.js",
                    r"angular\.js\?v=([\d.]+)",
                    r"/angularjs/([\d.]+)/",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "1.5.11",
                        "severity": Severity.HIGH,
                        "cve": "CVE-2019-10768",
                        "description": "AngularJS XSS via SVG or MathML"
                    },
                    {
                        "max_version": "1.7.9",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2022-25869",
                        "description": "AngularJS ReDoS vulnerability"
                    },
                ]
            },
            # Lodash vulnerabilities
            {
                "name": "Lodash",
                "patterns": [
                    r"lodash[.-]?([\d.]+)(?:\.min)?\.js",
                    r"lodash\.js\?v=([\d.]+)",
                    r"/lodash/([\d.]+)/",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "4.17.11",
                        "severity": Severity.HIGH,
                        "cve": "CVE-2019-10744",
                        "description": "Lodash prototype pollution vulnerability"
                    },
                    {
                        "max_version": "4.17.20",
                        "severity": Severity.HIGH,
                        "cve": "CVE-2021-23337",
                        "description": "Lodash command injection via template function"
                    },
                ]
            },
            # Moment.js vulnerabilities
            {
                "name": "Moment.js",
                "patterns": [
                    r"moment[.-]?([\d.]+)(?:\.min)?\.js",
                    r"moment\.js\?v=([\d.]+)",
                    r"/moment/([\d.]+)/",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "2.29.3",
                        "severity": Severity.HIGH,
                        "cve": "CVE-2022-24785",
                        "description": "Moment.js path traversal vulnerability"
                    },
                    {
                        "max_version": "2.29.1",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2022-31129",
                        "description": "Moment.js ReDoS vulnerability"
                    },
                ]
            },
            # Bootstrap vulnerabilities
            {
                "name": "Bootstrap",
                "patterns": [
                    r"bootstrap[.-]?([\d.]+)(?:\.min)?\.js",
                    r"bootstrap\.js\?v=([\d.]+)",
                    r"/bootstrap/([\d.]+)/",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "3.3.7",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2018-14041",
                        "description": "Bootstrap XSS in data-target attribute"
                    },
                    {
                        "max_version": "4.3.1",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2019-8331",
                        "description": "Bootstrap XSS in tooltip/popover data-template"
                    },
                ]
            },
            # Vue.js vulnerabilities
            {
                "name": "Vue.js",
                "patterns": [
                    r"vue[.-]?([\d.]+)(?:\.min)?\.js",
                    r"vue\.js\?v=([\d.]+)",
                    r"/vue/([\d.]+)/",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "2.6.11",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2021-3762",
                        "description": "Vue.js ReDoS in parseHTML"
                    },
                ]
            },
            # React vulnerabilities
            {
                "name": "React",
                "patterns": [
                    r"react[.-]?([\d.]+)(?:\.min)?\.js",
                    r"react\.production\.min\.js",
                    r"/react/([\d.]+)/",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "0.14.0",
                        "severity": Severity.HIGH,
                        "cve": "CVE-2015-1164",
                        "description": "React XSS vulnerability in server rendering"
                    },
                ]
            },
            # Handlebars vulnerabilities
            {
                "name": "Handlebars",
                "patterns": [
                    r"handlebars[.-]?([\d.]+)(?:\.min)?\.js",
                    r"handlebars\.js\?v=([\d.]+)",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "4.7.6",
                        "severity": Severity.CRITICAL,
                        "cve": "CVE-2021-23369",
                        "description": "Handlebars prototype pollution leading to RCE"
                    },
                ]
            },
            # DOMPurify vulnerabilities
            {
                "name": "DOMPurify",
                "patterns": [
                    r"purify[.-]?([\d.]+)(?:\.min)?\.js",
                    r"dompurify[.-]?([\d.]+)(?:\.min)?\.js",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "2.2.6",
                        "severity": Severity.MEDIUM,
                        "cve": "CVE-2021-23358",
                        "description": "DOMPurify mutation XSS bypass"
                    },
                ]
            },
            # Axios vulnerabilities
            {
                "name": "Axios",
                "patterns": [
                    r"axios[.-]?([\d.]+)(?:\.min)?\.js",
                    r"axios\.js\?v=([\d.]+)",
                ],
                "vulnerabilities": [
                    {
                        "max_version": "0.21.1",
                        "severity": Severity.HIGH,
                        "cve": "CVE-2021-3749",
                        "description": "Axios ReDoS vulnerability"
                    },
                ]
            },
        ]
        
        # Patterns to find script sources
        self.script_patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\']',
            r'<script[^>]+src=([^\s>]+)',
        ]
        
        # CDN patterns to extract library info
        self.cdn_patterns = [
            r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([\d.]+)',
            r'cdn\.jsdelivr\.net/npm/([^@]+)@([\d.]+)',
            r'unpkg\.com/([^@]+)@([\d.]+)',
            r'ajax\.googleapis\.com/ajax/libs/([^/]+)/([\d.]+)',
            r'code\.jquery\.com/([^/]+)-([\d.]+)',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for vulnerable dependencies."""
        vulnerabilities = []
        
        # Test 1: Analyze page for script includes
        page_vulns = await self._analyze_page_scripts(session, url)
        vulnerabilities.extend(page_vulns)
        
        # Test 2: Check for exposed package.json
        package_vulns = await self._check_package_json(session, url)
        vulnerabilities.extend(package_vulns)
        
        # Test 3: Check for exposed package-lock.json or yarn.lock
        lock_vulns = await self._check_lock_files(session, url)
        vulnerabilities.extend(lock_vulns)
        
        # Test 4: Check for exposed node_modules
        node_vulns = await self._check_node_modules(session, url)
        vulnerabilities.extend(node_vulns)
        
        return vulnerabilities
    
    async def _analyze_page_scripts(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Analyze scripts included in the page."""
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
                
                # Extract all script sources
                script_sources = []
                for pattern in self.script_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    script_sources.extend(matches)
                
                # Also check inline version comments
                version_comments = re.findall(
                    r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/',
                    content
                )
                
                # Analyze each script source
                for src in script_sources:
                    vulns = self._check_script_vulnerability(url, src)
                    vulnerabilities.extend(vulns)
                
                # Check CDN patterns in content
                for pattern in self.cdn_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if len(match) >= 2:
                            lib_name, version = match[0], match[1]
                            vulns = self._check_library_version(url, lib_name, version)
                            vulnerabilities.extend(vulns)
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_script_vulnerability(
        self,
        page_url: str,
        script_src: str
    ) -> List[Vulnerability]:
        """Check if a script source references a vulnerable library."""
        vulnerabilities = []
        
        for lib_info in self.vulnerable_libraries:
            for pattern in lib_info["patterns"]:
                match = re.search(pattern, script_src, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    if version:
                        vulns = self._check_version_vulnerabilities(
                            page_url, script_src, lib_info, version
                        )
                        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _check_library_version(
        self,
        page_url: str,
        lib_name: str,
        version: str
    ) -> List[Vulnerability]:
        """Check if a specific library version is vulnerable."""
        vulnerabilities = []
        
        # Normalize library name
        lib_name_lower = lib_name.lower()
        
        for lib_info in self.vulnerable_libraries:
            if lib_info["name"].lower() in lib_name_lower or lib_name_lower in lib_info["name"].lower():
                vulns = self._check_version_vulnerabilities(
                    page_url, f"{lib_name}@{version}", lib_info, version
                )
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _check_version_vulnerabilities(
        self,
        page_url: str,
        script_src: str,
        lib_info: Dict,
        version: str
    ) -> List[Vulnerability]:
        """Check version against known vulnerabilities."""
        vulnerabilities = []
        
        for vuln in lib_info["vulnerabilities"]:
            if self._is_version_vulnerable(version, vuln["max_version"]):
                vulnerabilities.append(Vulnerability(
                    vuln_type="Vulnerable JavaScript Library",
                    severity=vuln["severity"],
                    url=page_url,
                    parameter="script_src",
                    payload=script_src,
                    evidence=f"{lib_info['name']} version {version} <= {vuln['max_version']}",
                    description=f"{vuln['description']}. Detected version: {version}",
                    cwe_id="CWE-1035",
                    owasp_category=self.owasp_category,
                    remediation=self._get_remediation(lib_info['name'], version),
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}",
                        f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln['cve']}"
                    ]
                ))
        
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
    
    async def _check_package_json(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for exposed package.json files."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        package_paths = [
            "/package.json",
            "/app/package.json",
            "/src/package.json",
            "/frontend/package.json",
            "/client/package.json",
        ]
        
        for path in package_paths:
            try:
                test_url = urljoin(base_url, path)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'json' in content_type or 'text' in content_type:
                            try:
                                data = await response.json()
                                if 'dependencies' in data or 'devDependencies' in data:
                                    vulnerabilities.append(Vulnerability(
                                        vuln_type="Exposed Package.json",
                                        severity=Severity.MEDIUM,
                                        url=test_url,
                                        parameter="file",
                                        payload=path,
                                        evidence=f"package.json exposed with {len(data.get('dependencies', {}))} dependencies",
                                        description="package.json file is publicly accessible, exposing dependency information",
                                        cwe_id="CWE-200",
                                        owasp_category=self.owasp_category,
                                        remediation=self._get_package_remediation()
                                    ))
                                    
                                    # Also check dependencies for known vulnerabilities
                                    dep_vulns = self._analyze_package_dependencies(test_url, data)
                                    vulnerabilities.extend(dep_vulns)
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue
        
        return vulnerabilities
    
    def _analyze_package_dependencies(
        self,
        url: str,
        package_data: Dict
    ) -> List[Vulnerability]:
        """Analyze package.json dependencies for vulnerabilities."""
        vulnerabilities = []
        
        all_deps = {}
        all_deps.update(package_data.get('dependencies', {}))
        all_deps.update(package_data.get('devDependencies', {}))
        
        for dep_name, version_spec in all_deps.items():
            # Extract version number from spec
            version_match = re.search(r'[\d.]+', version_spec)
            if version_match:
                version = version_match.group(0)
                
                for lib_info in self.vulnerable_libraries:
                    if lib_info["name"].lower() == dep_name.lower():
                        vulns = self._check_version_vulnerabilities(
                            url, f"{dep_name}@{version}", lib_info, version
                        )
                        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _check_lock_files(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for exposed lock files."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        lock_files = [
            ("/package-lock.json", "npm"),
            ("/yarn.lock", "Yarn"),
            ("/pnpm-lock.yaml", "pnpm"),
            ("/composer.lock", "Composer (PHP)"),
            ("/Gemfile.lock", "Bundler (Ruby)"),
            ("/Pipfile.lock", "Pipenv (Python)"),
            ("/poetry.lock", "Poetry (Python)"),
        ]
        
        for path, package_manager in lock_files:
            try:
                test_url = urljoin(base_url, path)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Verify it's actually a lock file
                        if self._is_valid_lock_file(path, content):
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Exposed Dependency Lock File",
                                severity=Severity.LOW,
                                url=test_url,
                                parameter="file",
                                payload=path,
                                evidence=f"{package_manager} lock file exposed ({len(content)} bytes)",
                                description=f"Dependency lock file ({path}) is publicly accessible, exposing exact dependency versions",
                                cwe_id="CWE-200",
                                owasp_category=self.owasp_category,
                                remediation=self._get_package_remediation()
                            ))
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_valid_lock_file(self, path: str, content: str) -> bool:
        """Validate if content is actually a lock file."""
        if 'package-lock.json' in path:
            return '"lockfileVersion"' in content or '"dependencies"' in content
        elif 'yarn.lock' in path:
            return 'resolved' in content and '@' in content
        elif 'composer.lock' in path:
            return '"packages"' in content
        elif 'Gemfile.lock' in path:
            return 'GEM' in content or 'BUNDLED' in content
        elif 'Pipfile.lock' in path or 'poetry.lock' in path:
            return '"hash"' in content or 'content-hash' in content
        return len(content) > 100
    
    async def _check_node_modules(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for exposed node_modules directory."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        test_paths = [
            "/node_modules/",
            "/node_modules/jquery/package.json",
            "/node_modules/lodash/package.json",
            "/node_modules/.package-lock.json",
        ]
        
        for path in test_paths:
            try:
                test_url = urljoin(base_url, path)
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if it's actually node_modules content
                        if 'node_modules' in path and ('Index of' in content or 'package.json' in content or '"name"' in content):
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Exposed Node Modules",
                                severity=Severity.HIGH,
                                url=test_url,
                                parameter="directory",
                                payload=path,
                                evidence=f"node_modules directory/files accessible",
                                description="node_modules directory is publicly accessible, exposing all installed packages",
                                cwe_id="CWE-200",
                                owasp_category=self.owasp_category,
                                remediation=self._get_package_remediation()
                            ))
                            break  # One finding is enough
            except Exception:
                continue
        
        return vulnerabilities
    
    def _get_remediation(self, lib_name: str, version: str) -> str:
        """Get remediation advice for vulnerable library."""
        return f"""
1. Update {lib_name} to the latest stable version
2. Review the changelog for breaking changes before updating
3. Use a dependency management tool to track vulnerabilities:
   - npm audit (for Node.js)
   - Snyk (snyk.io)
   - OWASP Dependency-Check
   - GitHub Dependabot

4. Implement a Software Bill of Materials (SBOM) process
5. Pin dependencies to specific versions in production
6. Regularly audit and update dependencies

Commands to update:
# npm
npm update {lib_name.lower()}
npm audit fix

# yarn
yarn upgrade {lib_name.lower()}
yarn audit"""

    def _get_package_remediation(self) -> str:
        """Get remediation for exposed package files."""
        return """
1. Configure web server to block access to package management files:
Nginx:
location ~ (package\\.json|package-lock\\.json|yarn\\.lock|node_modules) {
    deny all;
    return 404;
}
Apache (.htaccess):
<FilesMatch "(package\\.json|package-lock\\.json|yarn\\.lock)$">
    Order allow,deny
    Deny from all
</FilesMatch>

RedirectMatch 404 /node_modules(/|$)
2. Ensure build processes don't copy these files to production
3. Use a proper build pipeline that only deploys compiled assets
4. Review deployment scripts for information leakage
"""