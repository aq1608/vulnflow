# websec/scanner/misconfig/cors.py
"""CORS Misconfiguration Scanner"""

from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CORSScanner(BaseScanner):
    """Scanner for CORS Misconfiguration vulnerabilities"""
    
    name = "CORS Scanner"
    description = "Detects Cross-Origin Resource Sharing misconfigurations"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Malicious origins to test
    TEST_ORIGINS = [
        'https://evil.com',
        'https://attacker.com',
        'null',
        'https://example.com.evil.com',
        'https://exampleXcom',  # Subdomain bypass attempt
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for CORS misconfigurations"""
        vulnerabilities = []
        
        # Test with different origins
        for origin in self.TEST_ORIGINS:
            vuln = await self._test_origin(session, url, origin)
            if vuln:
                vulnerabilities.append(vuln)
                break  # One finding is enough
        
        # Test for wildcard
        vuln = await self._test_wildcard(session, url)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_origin(self, session: aiohttp.ClientSession,
                           url: str, origin: str) -> Optional[Vulnerability]:
        """Test if arbitrary origin is reflected"""
        
        headers = {'Origin': origin}
        response = await self.make_request(session, "GET", url, headers=headers)
        
        if not response:
            return None
        
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        # Check if arbitrary origin is reflected
        if acao == origin:
            severity = Severity.HIGH if acac.lower() == 'true' else Severity.MEDIUM
            
            return self.create_vulnerability(
                vuln_type="CORS Misconfiguration - Origin Reflection",
                severity=severity,
                url=url,
                evidence=f"Origin '{origin}' reflected in Access-Control-Allow-Origin. Credentials: {acac}",
                description="The server reflects arbitrary origins in CORS headers, potentially allowing cross-origin attacks.",
                cwe_id="CWE-942",
                cvss_score=8.1 if acac.lower() == 'true' else 5.3,
                remediation="Implement a whitelist of allowed origins. Never reflect arbitrary origins. Be cautious with Access-Control-Allow-Credentials.",
                references=[
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    "https://portswigger.net/web-security/cors"
                ]
            )
        
        # Check for null origin (can be exploited via sandboxed iframes)
        if acao == 'null' and origin == 'null':
            return self.create_vulnerability(
                vuln_type="CORS Misconfiguration - Null Origin Allowed",
                severity=Severity.MEDIUM,
                url=url,
                evidence="Access-Control-Allow-Origin: null is accepted",
                description="The server accepts 'null' as a valid origin, which can be exploited using sandboxed iframes.",
                cwe_id="CWE-942",
                cvss_score=5.3,
                remediation="Do not allow 'null' as a valid origin in CORS configuration.",
                references=[
                    "https://portswigger.net/web-security/cors/access-control-allow-origin"
                ]
            )
        
        return None
    
    async def _test_wildcard(self, session: aiohttp.ClientSession,
                             url: str) -> Optional[Vulnerability]:
        """Test for wildcard origin with credentials"""
        
        headers = {'Origin': 'https://test.com'}
        response = await self.make_request(session, "GET", url, headers=headers)
        
        if not response:
            return None
        
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        # Wildcard with credentials is a severe misconfiguration
        if acao == '*' and acac.lower() == 'true':
            return self.create_vulnerability(
                vuln_type="CORS Misconfiguration - Wildcard with Credentials",
                severity=Severity.HIGH,
                url=url,
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                description="CORS is configured to allow all origins with credentials, which is a severe security misconfiguration.",
                cwe_id="CWE-942",
                cvss_score=8.1,
                remediation="Never use wildcard (*) with credentials. Implement proper origin validation.",
                references=[
                    "https://portswigger.net/web-security/cors"
                ]
            )
        
        # Just wildcard (less severe)
        if acao == '*':
            return self.create_vulnerability(
                vuln_type="CORS Configuration - Wildcard Origin",
                severity=Severity.LOW,
                url=url,
                evidence="Access-Control-Allow-Origin: *",
                description="CORS allows all origins. This may be intentional for public APIs but review for sensitive endpoints.",
                cwe_id="CWE-942",
                cvss_score=3.1,
                remediation="Consider restricting CORS to specific trusted origins if the API handles sensitive data.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                ]
            )
        
        return None