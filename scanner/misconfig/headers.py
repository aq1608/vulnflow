# websec/scanner/misconfig/headers.py
"""Security Headers Scanner"""

from typing import List, Dict, Optional
import aiohttp
import re

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SecurityHeadersScanner(BaseScanner):
    """Scanner for missing or misconfigured security headers"""
    
    name = "Security Headers Scanner"
    description = "Checks for missing or misconfigured HTTP security headers"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Security headers to check
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': Severity.MEDIUM,
            'description': 'HTTP Strict Transport Security (HSTS) not set',
            'detail': 'HSTS ensures browsers only connect via HTTPS, preventing SSL stripping attacks.',
            'cwe': 'CWE-319',
            'recommended': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        },
        'Content-Security-Policy': {
            'severity': Severity.MEDIUM,
            'description': 'Content Security Policy (CSP) not set',
            'detail': 'CSP helps prevent XSS and data injection attacks by controlling resource loading.',
            'cwe': 'CWE-693',
            'recommended': "Content-Security-Policy: default-src 'self'; script-src 'self'"
        },
        'X-Frame-Options': {
            'severity': Severity.MEDIUM,
            'description': 'X-Frame-Options header not set',
            'detail': 'This header prevents clickjacking attacks by controlling iframe embedding.',
            'cwe': 'CWE-1021',
            'recommended': 'X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'severity': Severity.LOW,
            'description': 'X-Content-Type-Options header not set',
            'detail': 'Prevents MIME type sniffing which can lead to XSS attacks.',
            'cwe': 'CWE-693',
            'recommended': 'X-Content-Type-Options: nosniff'
        },
        'X-XSS-Protection': {
            'severity': Severity.LOW,
            'description': 'X-XSS-Protection header not set',
            'detail': 'Enables browser XSS filtering (legacy, but still useful for older browsers).',
            'cwe': 'CWE-79',
            'recommended': 'X-XSS-Protection: 1; mode=block'
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'description': 'Referrer-Policy header not set',
            'detail': 'Controls how much referrer information is sent with requests.',
            'cwe': 'CWE-200',
            'recommended': 'Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'description': 'Permissions-Policy header not set',
            'detail': 'Controls which browser features can be used (formerly Feature-Policy).',
            'cwe': 'CWE-693',
            'recommended': 'Permissions-Policy: geolocation=(), microphone=(), camera=()'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'severity': Severity.LOW,
            'description': 'X-Permitted-Cross-Domain-Policies header not set',
            'detail': 'Controls cross-domain policies for Flash and PDF.',
            'cwe': 'CWE-693',
            'recommended': 'X-Permitted-Cross-Domain-Policies: none'
        },
    }
    
    # Headers that disclose information
    INFORMATION_DISCLOSURE_HEADERS = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Runtime',
        'X-Version',
        'X-Generator',
    ]
    
    # Insecure cookie attributes to check
    COOKIE_ATTRIBUTES = {
        'Secure': 'Cookie should have Secure flag for HTTPS',
        'HttpOnly': 'Cookie should have HttpOnly flag to prevent XSS access',
        'SameSite': 'Cookie should have SameSite attribute to prevent CSRF',
    }
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for security header issues"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            headers = response.headers
            
            # Check for missing security headers
            missing_vulns = self._check_missing_headers(url, headers)
            vulnerabilities.extend(missing_vulns)
            
            # Check for information disclosure
            disclosure_vulns = self._check_information_disclosure(url, headers)
            vulnerabilities.extend(disclosure_vulns)
            
            # Check for insecure cookies
            cookie_vulns = self._check_cookies(url, headers)
            vulnerabilities.extend(cookie_vulns)
            
            # Check for misconfigured CSP
            csp_vulns = self._check_csp(url, headers)
            vulnerabilities.extend(csp_vulns)
            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_missing_headers(self, url: str, headers: Dict) -> List[Vulnerability]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        for header_name, config in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type=f"Missing Security Header: {header_name}",
                    severity=config['severity'],
                    url=url,
                    evidence=f"Header '{header_name}' is not present in the response",
                    description=f"{config['description']}. {config['detail']}",
                    cwe_id=config['cwe'],
                    cvss_score=self._severity_to_cvss(config['severity']),
                    remediation=f"Add the following header to your server configuration:\n{config['recommended']}",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/"
                    ]
                ))
        
        return vulnerabilities
    
    def _check_information_disclosure(self, url: str, headers: Dict) -> List[Vulnerability]:
        """Check for information disclosure headers"""
        vulnerabilities = []
        
        for header_name in self.INFORMATION_DISCLOSURE_HEADERS:
            if header_name in headers:
                value = headers[header_name]
                
                # Skip generic values
                if value.lower() in ['close', 'keep-alive']:
                    continue
                
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type=f"Information Disclosure: {header_name}",
                    severity=Severity.INFO,
                    url=url,
                    evidence=f"{header_name}: {value}",
                    description=f"The server reveals technology information via the {header_name} header. This information can help attackers identify vulnerabilities specific to the technology stack.",
                    cwe_id="CWE-200",
                    cvss_score=2.0,
                    remediation=f"Remove or suppress the {header_name} header in your server configuration.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                    ]
                ))
        
        return vulnerabilities
    
    def _check_cookies(self, url: str, headers: Dict) -> List[Vulnerability]:
        """Check for insecure cookies"""
        vulnerabilities = []
        
        # Get Set-Cookie headers
        cookies = headers.getall('Set-Cookie', [])
        if isinstance(cookies, str):
            cookies = [cookies]
        
        for cookie in cookies:
            cookie_issues = []
            cookie_name = cookie.split('=')[0] if '=' in cookie else 'Unknown'
            
            # Check for Secure flag (only for HTTPS)
            if url.startswith('https://') and 'secure' not in cookie.lower():
                cookie_issues.append('Missing Secure flag')
            
            # Check for HttpOnly flag
            if 'httponly' not in cookie.lower():
                cookie_issues.append('Missing HttpOnly flag')
            
            # Check for SameSite attribute
            if 'samesite' not in cookie.lower():
                cookie_issues.append('Missing SameSite attribute')
            elif 'samesite=none' in cookie.lower() and 'secure' not in cookie.lower():
                cookie_issues.append('SameSite=None without Secure flag')
            
            if cookie_issues:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type=f"Insecure Cookie Configuration: {cookie_name}",
                    severity=Severity.MEDIUM if 'HttpOnly' in str(cookie_issues) else Severity.LOW,
                    url=url,
                    evidence=f"Cookie: {cookie[:100]}..., Issues: {', '.join(cookie_issues)}",
                    description=f"The cookie '{cookie_name}' is missing important security attributes: {', '.join(cookie_issues)}",
                    cwe_id="CWE-614",
                    cvss_score=4.3,
                    remediation="Set cookies with Secure, HttpOnly, and SameSite=Strict (or Lax) attributes.",
                    references=[
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
                    ]
                ))
        
        return vulnerabilities
    
    def _check_csp(self, url: str, headers: Dict) -> List[Vulnerability]:
        """Check for CSP misconfigurations"""
        vulnerabilities = []
        
        csp = headers.get('Content-Security-Policy', '')
        if not csp:
            return vulnerabilities
        
        # Check for dangerous CSP directives
        dangerous_patterns = {
            r"'unsafe-inline'": "Allows inline scripts, defeating XSS protection",
            r"'unsafe-eval'": "Allows eval(), reducing security",
            r"\*": "Wildcard allows resources from any origin",
            r"data:": "Allows data: URIs which can be used for XSS",
            r"blob:": "Allows blob: URIs which can be used for script injection",
        }
        
        issues = []
        for pattern, description in dangerous_patterns.items():
            if re.search(pattern, csp):
                issues.append(f"{pattern}: {description}")
        
        if issues:
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Weak Content Security Policy",
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"CSP: {csp[:200]}..., Issues: {'; '.join(issues[:3])}",
                description=f"The Content Security Policy contains potentially dangerous directives that weaken its protection.",
                cwe_id="CWE-693",
                cvss_score=4.3,
                remediation="Review and tighten CSP directives. Avoid 'unsafe-inline', 'unsafe-eval', and wildcards where possible.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://csp-evaluator.withgoogle.com/"
                ]
            ))
        
        return vulnerabilities
    
    def _severity_to_cvss(self, severity: Severity) -> float:
        """Convert severity to CVSS score"""
        mapping = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0
        }
        return mapping.get(severity, 5.0)