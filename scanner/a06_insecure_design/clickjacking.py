# scanner/insecure_design/clickjacking.py
"""
Clickjacking and UI Redressing Scanner

Detects clickjacking vulnerabilities and related UI security issues:
- Missing X-Frame-Options
- Missing/weak frame-ancestors CSP
- window.opener vulnerabilities
- UI misrepresentation

OWASP: A06:2025 - Insecure Design
CWE-1021: Improper Restriction of Rendered UI Layers or Frames
CWE-1022: Use of Web Link to Untrusted Target with window.opener Access
"""

import re
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class ClickjackingScanner(BaseScanner):
    """Scanner for Clickjacking and UI Redressing vulnerabilities"""
    
    name = "Clickjacking Scanner"
    description = "Detects clickjacking, frame-busting bypasses, and window.opener vulnerabilities"
    owasp_category = OWASPCategory.A06_INSECURE_DESIGN
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for clickjacking vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            headers = dict(response.headers)
            body = await response.text()
            
            # Check X-Frame-Options
            xfo_vulns = self._check_x_frame_options(url, headers)
            vulnerabilities.extend(xfo_vulns)
            
            # Check Content-Security-Policy frame-ancestors
            csp_vulns = self._check_csp_frame_ancestors(url, headers)
            vulnerabilities.extend(csp_vulns)
            
            # Check for weak frame-busting scripts
            framebust_vulns = self._check_frame_busting(url, body)
            vulnerabilities.extend(framebust_vulns)
            
            # Check for window.opener vulnerabilities
            opener_vulns = self._check_window_opener(url, body)
            vulnerabilities.extend(opener_vulns)
            
            # Check for target="_blank" without rel="noopener"
            link_vulns = self._check_unsafe_links(url, body)
            vulnerabilities.extend(link_vulns)
            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_x_frame_options(self, url: str, headers: Dict) -> List[Vulnerability]:
        """Check X-Frame-Options header"""
        vulnerabilities = []
        
        xfo = headers.get('X-Frame-Options', '').upper()
        
        if not xfo:
            # Check if CSP frame-ancestors exists (which would override XFO)
            csp = headers.get('Content-Security-Policy', '')
            if 'frame-ancestors' not in csp:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Missing Clickjacking Protection",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="X-Frame-Options",
                    payload="N/A",
                    evidence="Neither X-Frame-Options nor CSP frame-ancestors present",
                    description="The page can be embedded in an iframe, potentially allowing clickjacking attacks.",
                    cwe_id="CWE-1021",
                    cvss_score=6.1,
                    remediation=self._get_clickjacking_remediation(),
                    references=[
                        "https://owasp.org/www-community/attacks/Clickjacking",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                    ]
                ))
        elif xfo == 'ALLOWALL' or xfo == 'ALLOW-FROM *':
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Weak X-Frame-Options Configuration",
                severity=Severity.MEDIUM,
                url=url,
                parameter="X-Frame-Options",
                payload=f"X-Frame-Options: {xfo}",
                evidence="X-Frame-Options allows framing from any origin",
                description="X-Frame-Options is set to allow framing from any origin, defeating its purpose.",
                cwe_id="CWE-1021",
                cvss_score=6.1,
                remediation=self._get_clickjacking_remediation(),
                references=[
                    "https://owasp.org/www-community/attacks/Clickjacking"
                ]
            ))
        elif 'ALLOW-FROM' in xfo:
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="X-Frame-Options ALLOW-FROM Deprecated",
                severity=Severity.LOW,
                url=url,
                parameter="X-Frame-Options",
                payload=f"X-Frame-Options: {xfo}",
                evidence="ALLOW-FROM directive not supported by modern browsers",
                description="X-Frame-Options ALLOW-FROM is deprecated and ignored by modern browsers. Use CSP frame-ancestors instead.",
                cwe_id="CWE-1021",
                cvss_score=4.3,
                remediation="Use Content-Security-Policy frame-ancestors directive instead.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                ]
            ))
        
        return vulnerabilities
    
    def _check_csp_frame_ancestors(self, url: str, headers: Dict) -> List[Vulnerability]:
        """Check Content-Security-Policy frame-ancestors directive"""
        vulnerabilities = []
        
        csp = headers.get('Content-Security-Policy', '')
        
        if 'frame-ancestors' in csp:
            # Extract frame-ancestors value
            match = re.search(r"frame-ancestors\s+([^;]+)", csp)
            if match:
                frame_ancestors = match.group(1).strip()
                
                # Check for overly permissive settings
                if frame_ancestors == '*':
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Weak CSP frame-ancestors",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="Content-Security-Policy",
                        payload=f"frame-ancestors {frame_ancestors}",
                        evidence="frame-ancestors allows any origin",
                        description="CSP frame-ancestors is set to wildcard, allowing framing from any origin.",
                        cwe_id="CWE-1021",
                        cvss_score=6.1,
                        remediation="Set frame-ancestors to 'self' or specific trusted origins.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
                        ]
                    ))
                elif "'unsafe-eval'" in frame_ancestors or "'unsafe-inline'" in frame_ancestors:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Misconfigured CSP frame-ancestors",
                        severity=Severity.LOW,
                        url=url,
                        parameter="Content-Security-Policy",
                        payload=f"frame-ancestors {frame_ancestors}",
                        evidence="frame-ancestors contains invalid directives",
                        description="CSP frame-ancestors contains directives that don't apply (unsafe-eval/unsafe-inline).",
                        cwe_id="CWE-1021",
                        cvss_score=3.0,
                        remediation="Use only 'self', 'none', or specific origin URLs in frame-ancestors.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
                        ]
                    ))
        
        return vulnerabilities
    
    def _check_frame_busting(self, url: str, body: str) -> List[Vulnerability]:
        """Check for weak or bypassable frame-busting scripts"""
        vulnerabilities = []
        
        # Common frame-busting patterns
        framebust_patterns = [
            # Weak patterns that can be bypassed
            (r'if\s*$\s*top\s*!=\s*self\s*$', 'top != self check'),
            (r'if\s*$\s*top\s*!==\s*self\s*$', 'top !== self check'),
            (r'if\s*$\s*parent\s*!=\s*self\s*$', 'parent != self check'),
            (r'if\s*$\s*window\s*!=\s*top\s*$', 'window != top check'),
            (r'if\s*$\s*self\s*!=\s*top\s*$', 'self != top check'),
        ]
        
        # Weak redirect patterns
        weak_redirects = [
            (r'top\.location\s*=\s*self\.location', 'top.location redirect'),
            (r'top\.location\s*=\s*location\.href', 'top.location href redirect'),
        ]
        
        for pattern, desc in framebust_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                # Check if it's followed by a weak action
                for weak_pattern, weak_desc in weak_redirects:
                    if re.search(weak_pattern, body, re.IGNORECASE):
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="Bypassable Frame-Busting Script",
                            severity=Severity.LOW,
                            url=url,
                            parameter="JavaScript",
                            payload=f"{desc} with {weak_desc}",
                            evidence="Client-side frame-busting can be bypassed",
                            description="The page uses JavaScript frame-busting which can be bypassed using sandbox attribute or other techniques.",
                            cwe_id="CWE-1021",
                            cvss_score=4.3,
                            remediation="Use server-side X-Frame-Options or CSP frame-ancestors instead of JavaScript frame-busting.",
                            references=[
                                "https://www.codemagi.com/blog/post/196",
                                "https://owasp.org/www-community/attacks/Clickjacking"
                            ]
                        ))
                        break
        
        return vulnerabilities
    
    def _check_window_opener(self, url: str, body: str) -> List[Vulnerability]:
        """Check for window.opener vulnerabilities"""
        vulnerabilities = []
        
        # Check for window.open usage
        window_open_patterns = [
            r'window\.open\s*$[^)]+$',
            r'\.open\s*\(["\'][^"\']+["\']',
        ]
        
        for pattern in window_open_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                # Check if noopener/noreferrer is used
                if 'noopener' not in match.lower() and 'noreferrer' not in match.lower():
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Window.opener Vulnerability",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="JavaScript",
                        payload=match[:100],
                        evidence="window.open() without noopener/noreferrer",
                        description="window.open() is used without noopener, allowing the opened page to access window.opener.",
                        cwe_id="CWE-1022",
                        cvss_score=4.3,
                        remediation="Add 'noopener,noreferrer' to window.open() calls.",
                        references=[
                            "https://owasp.org/www-community/attacks/Reverse_Tabnabbing",
                            "https://cwe.mitre.org/data/definitions/1022.html"
                        ]
                    ))
                    break  # One finding is enough
        
        return vulnerabilities
    
    def _check_unsafe_links(self, url: str, body: str) -> List[Vulnerability]:
        """Check for target=_blank links without rel=noopener"""
        vulnerabilities = []
        
        # Find all links with target="_blank"
        link_pattern = r'<a[^>]+target\s*=\s*["\']_blank["\'][^>]*>'
        matches = re.findall(link_pattern, body, re.IGNORECASE)
        
        unsafe_count = 0
        for match in matches:
            # Check if rel="noopener" or rel="noreferrer" is present
            if 'rel=' not in match.lower() or \
               ('noopener' not in match.lower() and 'noreferrer' not in match.lower()):
                unsafe_count += 1
        
        if unsafe_count > 0:
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Unsafe External Links (Tabnabbing)",
                severity=Severity.LOW,
                url=url,
                parameter="HTML Links",
                payload=f"Found {unsafe_count} link(s) with target='_blank' without rel='noopener'",
                evidence=f"{unsafe_count} vulnerable link(s)",
                description="Links with target='_blank' without rel='noopener noreferrer' can lead to reverse tabnabbing attacks.",
                cwe_id="CWE-1022",
                cvss_score=3.1,
                remediation="Add rel='noopener noreferrer' to all external links with target='_blank'.",
                references=[
                    "https://owasp.org/www-community/attacks/Reverse_Tabnabbing",
                    "https://mathiasbynens.github.io/rel-noopener/"
                ]
            ))
        
        return vulnerabilities
    
    def _get_clickjacking_remediation(self) -> str:
        """Get clickjacking remediation advice"""
        return """
Clickjacking Prevention:

1. **Use X-Frame-Options Header**
```
X-Frame-Options: DENY

or
X-Frame-Options: SAMEORIGIN
```

2. **Use Content-Security-Policy frame-ancestors (Recommended)**
```
Content-Security-Policy: frame-ancestors 'self'

or
Content-Security-Policy: frame-ancestors 'none'
```

3. **For Specific Trusted Origins**

```Content-Security-Policy: frame-ancestors 'self' https://trusted.com```

4. **Server Configuration Examples:**

**Nginx:**
```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;
```
Apache:

```apache
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Content-Security-Policy "frame-ancestors 'self'"
```
Express.js:

```javascript
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'sameorigin' }));
```

5. Avoid JavaScript Frame-Busting
- JavaScript solutions can be bypassed
- Use HTTP headers instead
"""