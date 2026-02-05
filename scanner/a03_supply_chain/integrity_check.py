# scanner/supply_chain/integrity_check.py
"""
Integrity Check Scanner

Detects missing or weak integrity controls:
- Missing Subresource Integrity (SRI) on external scripts/styles
- Resources loaded over HTTP (mixed content)
- Missing Content Security Policy
- Unsigned/unverified external resources

OWASP: A03:2025 - Software Supply Chain Failures
CWE-353: Missing Support for Integrity Check
"""

import asyncio
import aiohttp
import re
import hashlib
import base64
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class IntegrityCheckScanner(BaseScanner):
    """Scanner for missing integrity verification"""
    
    name = "Integrity Check Scanner"
    description = "Detects missing Subresource Integrity and other integrity controls"
    owasp_category = OWASPCategory.A03_SUPPLY_CHAIN_FAILURES
    
    def __init__(self):
        super().__init__()
        
        # Known CDN domains that should always have SRI
        self.cdn_domains = [
            'cdnjs.cloudflare.com',
            'cdn.jsdelivr.net',
            'unpkg.com',
            'ajax.googleapis.com',
            'code.jquery.com',
            'stackpath.bootstrapcdn.com',
            'maxcdn.bootstrapcdn.com',
            'cdn.bootcss.com',
            'libs.baidu.com',
            'ajax.aspnetcdn.com',
            'cdn.staticfile.org',
        ]
        
        # Critical libraries that should definitely have SRI
        self.critical_libraries = [
            'jquery',
            'angular',
            'react',
            'vue',
            'bootstrap',
            'lodash',
            'moment',
            'axios',
            'd3',
            'chart',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for integrity issues."""
        vulnerabilities = []
        
        # Test 1: Check for missing SRI on external resources
        sri_vulns = await self._check_missing_sri(session, url)
        vulnerabilities.extend(sri_vulns)
        
        # Test 2: Check for mixed content (HTTP resources on HTTPS page)
        mixed_vulns = await self._check_mixed_content(session, url)
        vulnerabilities.extend(mixed_vulns)
        
        # Test 3: Check Content Security Policy
        csp_vulns = await self._check_csp(session, url)
        vulnerabilities.extend(csp_vulns)
        
        # Test 4: Check for inline scripts without nonce/hash
        inline_vulns = await self._check_inline_scripts(session, url)
        vulnerabilities.extend(inline_vulns)
        
        return vulnerabilities
    
    async def _check_missing_sri(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for external resources missing SRI."""
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
                page_domain = urlparse(url).netloc
                
                # Find all script tags
                script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
                scripts = re.findall(script_pattern, content, re.IGNORECASE)
                
                # Find all stylesheet links
                style_pattern = r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\'][^>]*>'
                styles = re.findall(style_pattern, content, re.IGNORECASE)
                
                # Check scripts
                for script_match in re.finditer(
                    r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>',
                    content,
                    re.IGNORECASE
                ):
                    full_tag = script_match.group(0)
                    src = script_match.group(1)
                    
                    if self._is_external_resource(src, page_domain):
                        has_integrity = 'integrity=' in full_tag.lower()
                        
                        if not has_integrity:
                            severity = self._get_severity_for_resource(src)
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Missing Subresource Integrity (Script)",
                                severity=severity,
                                url=url,
                                parameter="script_src",
                                payload=src,
                                evidence=f"External script loaded without integrity attribute",
                                description=f"External JavaScript from {urlparse(src).netloc} loaded without SRI hash verification",
                                cwe_id="CWE-353",
                                owasp_category=self.owasp_category,
                                remediation=self._get_sri_remediation(src)
                            ))
                
                # Check stylesheets
                for style_match in re.finditer(
                    r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\'][^>]*>',
                    content,
                    re.IGNORECASE
                ):
                    full_tag = style_match.group(0)
                    href = style_match.group(1)
                    
                    if self._is_external_resource(href, page_domain):
                        has_integrity = 'integrity=' in full_tag.lower()
                        
                        if not has_integrity:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Missing Subresource Integrity (Stylesheet)",
                                severity=Severity.LOW,
                                url=url,
                                parameter="link_href",
                                payload=href,
                                evidence=f"External stylesheet loaded without integrity attribute",
                                description=f"External CSS from {urlparse(href).netloc} loaded without SRI hash verification",
                                cwe_id="CWE-353",
                                owasp_category=self.owasp_category,
                                remediation=self._get_sri_remediation(href)
                            ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_external_resource(self, src: str, page_domain: str) -> bool:
        """Check if resource is from external domain."""
        if src.startswith('//'):
            return True
        if src.startswith('http://') or src.startswith('https://'):
            resource_domain = urlparse(src).netloc
            return resource_domain != page_domain
        return False
    
    def _get_severity_for_resource(self, src: str) -> Severity:
        """Determine severity based on resource type and source."""
        src_lower = src.lower()
        
        # Critical libraries without SRI are high severity
        for lib in self.critical_libraries:
            if lib in src_lower:
                return Severity.HIGH
        
        # CDN resources should always have SRI
        for cdn in self.cdn_domains:
            if cdn in src_lower:
                return Severity.MEDIUM
        
        return Severity.LOW
    
    async def _check_mixed_content(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for HTTP resources on HTTPS pages."""
        vulnerabilities = []
        
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            return vulnerabilities  # Only check HTTPS pages
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                if response.status != 200:
                    return vulnerabilities
                
                content = await response.text()
                
                # Find HTTP resources
                http_resources = re.findall(
                    r'(?:src|href|action)=["\']?(http://[^"\'>\s]+)',
                    content,
                    re.IGNORECASE
                )
                
                seen = set()
                for resource in http_resources:
                    if resource not in seen:
                        seen.add(resource)
                        
                        # Determine resource type
                        if any(ext in resource.lower() for ext in ['.js', '.mjs']):
                            resource_type = "JavaScript"
                            severity = Severity.HIGH
                        elif any(ext in resource.lower() for ext in ['.css']):
                            resource_type = "Stylesheet"
                            severity = Severity.MEDIUM
                        elif any(ext in resource.lower() for ext in ['.png', '.jpg', '.gif', '.svg', '.ico']):
                            resource_type = "Image"
                            severity = Severity.LOW
                        else:
                            resource_type = "Resource"
                            severity = Severity.MEDIUM
                        
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"Mixed Content - {resource_type}",
                            severity=severity,
                            url=url,
                            parameter="resource_url",
                            payload=resource,
                            evidence=f"HTTP {resource_type.lower()} loaded on HTTPS page",
                            description=f"Insecure HTTP resource loaded on secure HTTPS page, vulnerable to MITM attacks",
                            cwe_id="CWE-319",
                            owasp_category=self.owasp_category,
                            remediation=self._get_mixed_content_remediation()
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_csp(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check Content Security Policy configuration."""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                csp = response.headers.get('Content-Security-Policy', '')
                csp_ro = response.headers.get('Content-Security-Policy-Report-Only', '')
                
                if not csp and not csp_ro:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Missing Content Security Policy",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="header",
                        payload="Content-Security-Policy",
                        evidence="No CSP header present",
                        description="Content Security Policy header is not configured, reducing protection against XSS and injection attacks",
                        cwe_id="CWE-693",
                        owasp_category=self.owasp_category,
                        remediation=self._get_csp_remediation()
                    ))
                elif csp:
                    # Check for weak CSP directives
                    csp_issues = self._analyze_csp(csp)
                    for issue in csp_issues:
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"Weak CSP - {issue['type']}",
                            severity=issue['severity'],
                            url=url,
                            parameter="Content-Security-Policy",
                            payload=issue['directive'],
                            evidence=issue['evidence'],
                            description=issue['description'],
                            cwe_id="CWE-693",
                            owasp_category=self.owasp_category,
                            remediation=self._get_csp_remediation()
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _analyze_csp(self, csp: str) -> List[Dict]:
        """Analyze CSP for weaknesses."""
        issues = []
        csp_lower = csp.lower()
        
        # Check for unsafe-inline
        if "'unsafe-inline'" in csp_lower:
            issues.append({
                "type": "unsafe-inline",
                "directive": "script-src 'unsafe-inline'",
                "severity": Severity.MEDIUM,
                "evidence": "CSP allows unsafe-inline scripts",
                "description": "CSP allows inline scripts which defeats much of CSP's XSS protection"
            })
        
        # Check for unsafe-eval
        if "'unsafe-eval'" in csp_lower:
            issues.append({
                "type": "unsafe-eval",
                "directive": "script-src 'unsafe-eval'",
                "severity": Severity.MEDIUM,
                "evidence": "CSP allows unsafe-eval",
                "description": "CSP allows eval() and similar functions which can be exploited"
            })
        
        # Check for wildcard sources
        if "script-src *" in csp_lower or "script-src: *" in csp_lower:
            issues.append({
                "type": "Wildcard script-src",
                "directive": "script-src *",
                "severity": Severity.HIGH,
                "evidence": "CSP allows scripts from any source",
                "description": "Wildcard in script-src allows loading scripts from any domain"
            })
        
        # Check for data: URIs in script-src
        if "script-src" in csp_lower and "data:" in csp_lower:
            issues.append({
                "type": "data: URI in script-src",
                "directive": "script-src data:",
                "severity": Severity.MEDIUM,
                "evidence": "CSP allows data: URIs for scripts",
                "description": "data: URIs in script-src can be used to bypass CSP"
            })
        
        # Check for missing script-src
        if "script-src" not in csp_lower and "default-src" not in csp_lower:
            issues.append({
                "type": "Missing script-src",
                "directive": "script-src (missing)",
                "severity": Severity.MEDIUM,
                "evidence": "CSP has no script-src or default-src directive",
                "description": "Without script-src or default-src, scripts can be loaded from anywhere"
            })
        
        return issues
    
    async def _check_inline_scripts(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for inline scripts without nonce/hash."""
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
                csp = response.headers.get('Content-Security-Policy', '')
                
                # Count inline scripts
                inline_scripts = re.findall(
                    r'<script(?![^>]*src=)[^>]*>(.*?)</script>',
                    content,
                    re.IGNORECASE | re.DOTALL
                )
                
                # Filter out empty scripts
                inline_scripts = [s for s in inline_scripts if s.strip()]
                
                if inline_scripts and csp and "'unsafe-inline'" not in csp.lower():
                    # Check if CSP uses nonces or hashes
                    has_nonce = "'nonce-" in csp.lower()
                    has_hash = any(h in csp.lower() for h in ["'sha256-", "'sha384-", "'sha512-"])
                    
                    if not has_nonce and not has_hash:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Inline Scripts Without CSP Protection",
                            severity=Severity.INFO,
                            url=url,
                            parameter="inline_scripts",
                            payload=f"{len(inline_scripts)} inline scripts found",
                            evidence=f"Page has {len(inline_scripts)} inline scripts but CSP doesn't use nonces or hashes",
                            description="Inline scripts found without CSP nonce or hash protection",
                            cwe_id="CWE-693",
                            owasp_category=self.owasp_category,
                            remediation=self._get_nonce_remediation()
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _get_sri_remediation(self, resource_url: str) -> str:
        """Get SRI remediation advice."""
        return f"""
1. Add integrity attribute with SHA-384 hash to external resources:

```html
<script src="{resource_url}" 
        integrity="sha384-HASH_HERE" 
        crossorigin="anonymous"></script>

2. Generate SRI hash using:
- Online: https://www.srihash.org/
- Command line:
        curl -s "{resource_url}" | openssl dgst -sha384 -binary | openssl base64 -A

3. Also add crossorigin="anonymous" attribute for CORS resources

4. Use tools to automate SRI generation in your build process:
- webpack-subresource-integrity
- gulp-sri-hash
- rollup-plugin-sri

5. Monitor for hash mismatches in production (indicates tampering)
"""

    def _get_mixed_content_remediation(self) -> str:
        """Get mixed content remediation advice."""
        return """

1. Update all resource URLs to use HTTPS:
- Change http:// to https://
- Or use protocol-relative URLs: //example.com/resource.js

2. Add upgrade-insecure-requests CSP directive:
        Content-Security-Policy: upgrade-insecure-requests

3. Use HSTS to enforce HTTPS:
        Strict-Transport-Security: max-age=31536000; includeSubDomains

4. Audit all external resources and ensure HTTPS availability

5. For legacy resources without HTTPS, consider:
- Hosting them locally
- Finding HTTPS alternatives
- Using a proxy
"""
    def _get_csp_remediation(self) -> str:
        """Get CSP remediation advice."""
        return """
1. Implement a strong Content Security Policy:
    Content-Security-Policy: 
        default-src 'self';
        script-src 'self' https://trusted-cdn.com;
        style-src 'self' 'unsafe-inline';
        img-src 'self' data: https:;
        font-src 'self';
        connect-src 'self' https://api.example.com;
        frame-ancestors 'none';
        base-uri 'self';
        form-action 'self';

2. Avoid 'unsafe-inline' and 'unsafe-eval' where possible

3. Use nonces or hashes for necessary inline scripts:
        Content-Security-Policy: script-src 'nonce-RANDOM_VALUE'

4. Start with Content-Security-Policy-Report-Only to test

5. Use CSP reporting to monitor violations:
        Content-Security-Policy: ...; report-uri /csp-report
"""

    def _get_nonce_remediation(self) -> str:
        """Get nonce remediation advice."""
        return """
1. Generate a unique nonce for each page load:
Server-side (Python example):
    import secrets
    nonce = secrets.token_urlsafe(16)
2. Add nonce to CSP header:
    Content-Security-Policy: script-src 'nonce-{nonce}'
3. Add nonce to inline scripts:
<script nonce="{nonce}">
    // Your inline code
</script>
4. Alternatively, use hashes for static inline scripts:
    Content-Security-Policy: script-src 'sha256-BASE64_HASH'
5. Never reuse nonces across requests
"""