# scanner/deserialization/subresource_integrity.py
"""
Subresource Integrity (SRI) Scanner

Detects missing or misconfigured Subresource Integrity:
- External scripts without SRI
- External stylesheets without SRI
- CDN resources without integrity verification
- Mixed integrity configurations

OWASP: A08:2025 - Software or Data Integrity Failures
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
CWE-830: Inclusion of Web Functionality from an Untrusted Source
CWE-494: Download of Code Without Integrity Check
"""

import re
from typing import List, Dict, Optional, Set
import aiohttp
from urllib.parse import urlparse, urljoin

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SubresourceIntegrityScanner(BaseScanner):
    """Scanner for Subresource Integrity (SRI) vulnerabilities"""
    
    name = "Subresource Integrity Scanner"
    description = "Detects missing SRI on external scripts and stylesheets"
    owasp_category = OWASPCategory.A08_DATA_INTEGRITY_FAILURES
    
    # Well-known CDNs that should have SRI
    KNOWN_CDNS = [
        'cdn.jsdelivr.net',
        'cdnjs.cloudflare.com',
        'unpkg.com',
        'ajax.googleapis.com',
        'code.jquery.com',
        'stackpath.bootstrapcdn.com',
        'maxcdn.bootstrapcdn.com',
        'cdn.bootcdn.net',
        'cdn.bootcss.com',
        'libs.baidu.com',
        'ajax.aspnetcdn.com',
        'cdn.staticfile.org',
        'lib.sinaapp.com',
        'fonts.googleapis.com',
        'use.fontawesome.com',
        'kit.fontawesome.com',
    ]
    
    # High-risk libraries that definitely need SRI
    HIGH_RISK_LIBRARIES = [
        'jquery', 'angular', 'react', 'vue', 'bootstrap',
        'lodash', 'moment', 'axios', 'backbone', 'ember',
        'knockout', 'handlebars', 'mustache', 'underscore',
        'chart.js', 'd3', 'three.js', 'socket.io',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for missing SRI on external resources"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            body = await response.text()
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            
            # Check external scripts
            script_vulns = self._check_scripts(body, url, base_domain)
            vulnerabilities.extend(script_vulns)
            
            # Check external stylesheets
            style_vulns = self._check_stylesheets(body, url, base_domain)
            vulnerabilities.extend(style_vulns)
            
            # Check for dynamic script loading without integrity
            dynamic_vulns = self._check_dynamic_loading(body, url)
            vulnerabilities.extend(dynamic_vulns)
            
            # Check for inline event handlers loading external content
            inline_vulns = self._check_inline_loading(body, url)
            vulnerabilities.extend(inline_vulns)
            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_scripts(self, body: str, url: str, base_domain: str) -> List[Vulnerability]:
        """Check external scripts for SRI"""
        vulnerabilities = []
        found_issues: Set[str] = set()
        
        # Find all script tags
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        matches = re.finditer(script_pattern, body, re.IGNORECASE)
        
        for match in matches:
            full_tag = match.group(0)
            src = match.group(1)
            
            # Skip data URIs and inline scripts
            if src.startswith('data:') or src.startswith('javascript:'):
                continue
            
            # Determine if external
            is_external = self._is_external_resource(src, base_domain)
            
            if not is_external:
                continue
            
            # Check for integrity attribute
            has_integrity = 'integrity=' in full_tag.lower()
            has_crossorigin = 'crossorigin' in full_tag.lower()
            
            # Determine severity based on source
            src_lower = src.lower()
            is_cdn = any(cdn in src_lower for cdn in self.KNOWN_CDNS)
            is_high_risk = any(lib in src_lower for lib in self.HIGH_RISK_LIBRARIES)
            
            if not has_integrity:
                # Avoid duplicate findings
                if src in found_issues:
                    continue
                found_issues.add(src)
                
                if is_cdn or is_high_risk:
                    severity = Severity.HIGH
                    description = f"External script from CDN loaded without SRI: {src[:100]}"
                else:
                    severity = Severity.MEDIUM
                    description = f"External script loaded without integrity verification: {src[:100]}"
                
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Missing Subresource Integrity (Script)",
                    severity=severity,
                    url=url,
                    parameter="script src",
                    payload=src[:200],
                    evidence=full_tag[:200],
                    description=description,
                    cwe_id="CWE-829",
                    cvss_score=6.5 if severity == Severity.HIGH else 4.5,
                    remediation=self._get_script_remediation(src),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                        "https://www.srihash.org/",
                        "https://cwe.mitre.org/data/definitions/829.html"
                    ]
                ))
            
            elif has_integrity and not has_crossorigin:
                # Has integrity but missing crossorigin (won't work properly)
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="SRI Without Crossorigin Attribute",
                    severity=Severity.LOW,
                    url=url,
                    parameter="script",
                    payload=src[:200],
                    evidence=full_tag[:200],
                    description="Script has integrity attribute but missing crossorigin, SRI may not work correctly.",
                    cwe_id="CWE-829",
                    cvss_score=3.0,
                    remediation='Add crossorigin="anonymous" attribute to the script tag.',
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
                    ]
                ))
        
        return vulnerabilities
    
    def _check_stylesheets(self, body: str, url: str, base_domain: str) -> List[Vulnerability]:
        """Check external stylesheets for SRI"""
        vulnerabilities = []
        found_issues: Set[str] = set()
        
        # Find all link tags for stylesheets
        link_pattern = r'<link[^>]*href=["\']([^"\']+)["\'][^>]*>'
        matches = re.finditer(link_pattern, body, re.IGNORECASE)
        
        for match in matches:
            full_tag = match.group(0)
            href = match.group(1)
            
            # Check if it's a stylesheet
            if 'rel=' not in full_tag.lower() or 'stylesheet' not in full_tag.lower():
                # Check if it looks like CSS by extension
                if not href.endswith('.css') and 'css' not in href.lower():
                    continue
            
            # Skip data URIs
            if href.startswith('data:'):
                continue
            
            # Determine if external
            is_external = self._is_external_resource(href, base_domain)
            
            if not is_external:
                continue
            
            # Check for integrity attribute
            has_integrity = 'integrity=' in full_tag.lower()
            
            if not has_integrity:
                if href in found_issues:
                    continue
                found_issues.add(href)
                
                href_lower = href.lower()
                is_cdn = any(cdn in href_lower for cdn in self.KNOWN_CDNS)
                
                severity = Severity.MEDIUM if is_cdn else Severity.LOW
                
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Missing Subresource Integrity (Stylesheet)",
                    severity=severity,
                    url=url,
                    parameter="link href",
                    payload=href[:200],
                    evidence=full_tag[:200],
                    description=f"External stylesheet loaded without integrity verification: {href[:100]}",
                    cwe_id="CWE-830",
                    cvss_score=4.0 if severity == Severity.MEDIUM else 2.5,
                    remediation=self._get_stylesheet_remediation(href),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
                    ]
                ))
        
        return vulnerabilities
    
    def _check_dynamic_loading(self, body: str, url: str) -> List[Vulnerability]:
        """Check for dynamically loaded scripts without integrity verification"""
        vulnerabilities = []
        
        # Patterns for dynamic script loading
        dynamic_patterns = [
            # document.createElement('script')
            (r'createElement\s*$\s*["\']script["\']\s*$(?:(?!\.integrity).)*\.src\s*=', 
             'createElement without integrity'),
            
            # jQuery.getScript
            (r'\$\.getScript\s*$[^)]+$', 
             'jQuery.getScript'),
            
            # RequireJS without integrity
            (r'require\s*\(\s*\[', 
             'RequireJS dynamic loading'),
            
            # Dynamic import without integrity
            (r'import\s*\([^)]+https?://', 
             'Dynamic import of external module'),
            
            # Fetch/XHR loading scripts
            (r'fetch\s*$[^)]*\.js["\'][^)]*$(?:(?!integrity).)*\.text\(\)', 
             'Fetch loading JavaScript'),
        ]
        
        for pattern, description in dynamic_patterns:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Dynamic Script Loading Without Integrity",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="JavaScript Code",
                    payload=description,
                    evidence=f"Pattern detected: {description}",
                    description=f"Scripts are loaded dynamically without integrity verification: {description}",
                    cwe_id="CWE-494",
                    cvss_score=5.0,
                    remediation="Implement integrity verification for dynamically loaded scripts. Use import maps with integrity.",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap"
                    ]
                ))
                break  # One finding is enough
        
        return vulnerabilities
    
    def _check_inline_loading(self, body: str, url: str) -> List[Vulnerability]:
        """Check for inline event handlers that load external content"""
        vulnerabilities = []
        
        # Check for onclick/onload etc that load external scripts
        dangerous_patterns = [
            r'on\w+=["\'][^"\']*document\.write\s*\([^)]*<script[^>]*src=',
            r'on\w+=["\'][^"\']*\.src\s*=\s*["\']https?://',
            r'javascript:.*\.src\s*=',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Inline Script Loading External Resources",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="Inline Handler",
                    payload="N/A",
                    evidence="Inline event handler loads external resources",
                    description="Inline event handlers dynamically load external scripts, bypassing SRI.",
                    cwe_id="CWE-829",
                    cvss_score=5.0,
                    remediation="Avoid inline event handlers. Load scripts statically with SRI.",
                    references=[]
                ))
                break
        
        return vulnerabilities
    
    def _is_external_resource(self, src: str, base_domain: str) -> bool:
        """Check if a resource URL is external"""
        # Absolute URLs
        if src.startswith('http://') or src.startswith('https://') or src.startswith('//'):
            parsed = urlparse(src if not src.startswith('//') else 'https:' + src)
            resource_domain = parsed.netloc.lower()
            base_domain_lower = base_domain.lower()
            
            # Check if it's a different domain
            if resource_domain != base_domain_lower:
                # Also check if it's not a subdomain of the same base
                if not resource_domain.endswith('.' + base_domain_lower):
                    return True
        
        return False
    
    def _get_script_remediation(self, src: str) -> str:
        """Get specific remediation for script SRI"""
        return f"""
Add Subresource Integrity (SRI) to external scripts:

1. Generate the SRI hash for the resource:
   ```bash
   curl -s "{src}" | openssl dgst -sha384 -binary | openssl base64 -A
   ```

2. Or use https://www.srihash.org/
3. Update the script tag:
    ```html
    <script 
        src="{src[:80]}"
        integrity="sha384-HASH_HERE"
        crossorigin="anonymous">
    </script>
    ```
4. For dynamically loaded scripts, verify integrity in code:
    ```javascript
    async function loadScriptWithIntegrity(url, expectedHash) {{
        const response = await fetch(url);
        const text = await response.text();
        const hash = await crypto.subtle.digest('SHA-384', 
            new TextEncoder().encode(text));
        // Compare hash before executing
    }}
    ```
"""
    
    def _get_stylesheet_remediation(self, href: str) -> str:
        """Get specific remediation for stylesheet SRI"""
        return f"""
Add Subresource Integrity (SRI) to external stylesheets:
1. Generate the SRI hash:
    ```bash
    curl -s "{href}" | openssl dgst -sha384 -binary | openssl base64 -A
    ```
2. Update the link tag:
    ```html
    <link 
        rel="stylesheet"
        href="{href[:80]}"
        integrity="sha384-HASH_HERE"
        crossorigin="anonymous">
    ```
"""