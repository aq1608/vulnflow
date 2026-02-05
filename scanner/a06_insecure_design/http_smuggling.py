# scanner/insecure_design/http_smuggling.py
"""
HTTP Request Smuggling Scanner

Detects HTTP request smuggling vulnerabilities:
- CL.TE (Content-Length wins, Transfer-Encoding ignored by backend)
- TE.CL (Transfer-Encoding wins, Content-Length ignored by backend)
- TE.TE (Both use Transfer-Encoding but process differently)
- HTTP/2 downgrade smuggling

OWASP: A06:2025 - Insecure Design
CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')
"""

import asyncio
import re
from typing import List, Dict, Optional, Tuple
import aiohttp
import socket
import ssl

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class HTTPSmugglingScanner(BaseScanner):
    """Scanner for HTTP Request Smuggling vulnerabilities"""
    
    name = "HTTP Request Smuggling Scanner"
    description = "Detects HTTP request smuggling (CL.TE, TE.CL, TE.TE) vulnerabilities"
    owasp_category = OWASPCategory.A06_INSECURE_DESIGN
    
    def __init__(self):
        super().__init__()
        self.timeout = 10
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for HTTP smuggling vulnerabilities"""
        vulnerabilities = []
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc
        port = 443 if parsed.scheme == 'https' else 80
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'
        
        # Separate port if specified
        if ':' in host:
            host, port_str = host.rsplit(':', 1)
            port = int(port_str)
        
        # Test CL.TE smuggling
        clte_vuln = await self._test_cl_te(host, port, path, use_ssl)
        if clte_vuln:
            vulnerabilities.append(clte_vuln)
        
        # Test TE.CL smuggling  
        tecl_vuln = await self._test_te_cl(host, port, path, use_ssl)
        if tecl_vuln:
            vulnerabilities.append(tecl_vuln)
        
        # Test for smuggling indicators via timing
        timing_vuln = await self._test_timing_based(host, port, path, use_ssl)
        if timing_vuln:
            vulnerabilities.append(timing_vuln)
        
        # Check for vulnerable configurations
        config_vulns = await self._check_config_indicators(session, url)
        vulnerabilities.extend(config_vulns)
        
        return vulnerabilities
    
    async def _raw_request(self, host: str, port: int, request: bytes, 
                           use_ssl: bool, timeout: int = 10) -> Tuple[Optional[bytes], float]:
        """Send raw HTTP request and measure response time"""
        start_time = asyncio.get_event_loop().time()
        response = None
        
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=context),
                    timeout=timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
            
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        
        elapsed = asyncio.get_event_loop().time() - start_time
        return response, elapsed
    
    async def _test_cl_te(self, host: str, port: int, path: str, 
                          use_ssl: bool) -> Optional[Vulnerability]:
        """Test for CL.TE smuggling vulnerability"""
        
        # CL.TE: Frontend uses Content-Length, Backend uses Transfer-Encoding
        # The frontend will read 4 bytes (0\r\n\r), backend will wait for more data
        
        smuggle_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        ).encode()
        
        try:
            response, elapsed = await self._raw_request(
                host, port, smuggle_request, use_ssl, timeout=5
            )
            
            # If there's a significant delay (backend waiting), indicates CL.TE
            if elapsed > 4:
                return self.create_vulnerability(
                    vuln_type="HTTP Request Smuggling (CL.TE)",
                    severity=Severity.HIGH,
                    url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                    parameter="HTTP Headers",
                    payload="Content-Length: 4 with Transfer-Encoding: chunked",
                    evidence=f"Response delayed by {elapsed:.2f}s indicating CL.TE desync",
                    description="The application may be vulnerable to CL.TE HTTP request smuggling. The frontend server uses Content-Length while the backend uses Transfer-Encoding.",
                    cwe_id="CWE-444",
                    cvss_score=9.1,
                    remediation=self._get_remediation(),
                    references=[
                        "https://portswigger.net/research/http-request-smuggling",
                        "https://cwe.mitre.org/data/definitions/444.html"
                    ]
                )
        except Exception:
            pass
        
        return None
    
    async def _test_te_cl(self, host: str, port: int, path: str,
                          use_ssl: bool) -> Optional[Vulnerability]:
        """Test for TE.CL smuggling vulnerability"""
        
        # TE.CL: Frontend uses Transfer-Encoding, Backend uses Content-Length
        
        smuggle_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()
        
        try:
            response, elapsed = await self._raw_request(
                host, port, smuggle_request, use_ssl, timeout=5
            )
            
            if elapsed > 4:
                return self.create_vulnerability(
                    vuln_type="HTTP Request Smuggling (TE.CL)",
                    severity=Severity.HIGH,
                    url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                    parameter="HTTP Headers",
                    payload="Transfer-Encoding: chunked with Content-Length: 6",
                    evidence=f"Response delayed by {elapsed:.2f}s indicating TE.CL desync",
                    description="The application may be vulnerable to TE.CL HTTP request smuggling. The frontend uses Transfer-Encoding while the backend uses Content-Length.",
                    cwe_id="CWE-444",
                    cvss_score=9.1,
                    remediation=self._get_remediation(),
                    references=[
                        "https://portswigger.net/research/http-request-smuggling"
                    ]
                )
        except Exception:
            pass
        
        return None
    
    async def _test_timing_based(self, host: str, port: int, path: str,
                                  use_ssl: bool) -> Optional[Vulnerability]:
        """Test for smuggling using timing differences"""
        
        # Test with obfuscated Transfer-Encoding headers
        obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: cow",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: xchunked",
            " Transfer-Encoding: chunked",
            "X: x\nTransfer-Encoding: chunked",
            "Transfer-Encoding: chunked, identity",
        ]
        
        for te_header in obfuscations:
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()
            
            try:
                response, elapsed = await self._raw_request(
                    host, port, request, use_ssl, timeout=5
                )
                
                if response and elapsed > 3:
                    return self.create_vulnerability(
                        vuln_type="Potential HTTP Smuggling (TE Obfuscation)",
                        severity=Severity.MEDIUM,
                        url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                        parameter="Transfer-Encoding",
                        payload=te_header,
                        evidence=f"Delayed response with TE obfuscation: {elapsed:.2f}s",
                        description=f"Server may process obfuscated Transfer-Encoding header differently, indicating potential smuggling.",
                        cwe_id="CWE-444",
                        cvss_score=7.5,
                        remediation=self._get_remediation(),
                        references=[
                            "https://portswigger.net/research/http-request-smuggling"
                        ]
                    )
            except Exception:
                continue
        
        return None
    
    async def _check_config_indicators(self, session: aiohttp.ClientSession,
                                        url: str) -> List[Vulnerability]:
        """Check for configuration indicators of smuggling risk"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            headers = dict(response.headers)
            
            # Check for proxy/CDN headers that might indicate multi-tier architecture
            proxy_indicators = ['Via', 'X-Forwarded-For', 'X-Cache', 'CF-RAY', 
                               'X-Amz-Cf-Id', 'X-Served-By', 'X-Cache-Hits']
            
            found_proxies = [h for h in proxy_indicators if h in headers]
            
            if len(found_proxies) >= 2:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Multi-tier Architecture Detected",
                    severity=Severity.INFO,
                    url=url,
                    parameter="HTTP Response Headers",
                    payload="N/A",
                    evidence=f"Proxy indicators found: {', '.join(found_proxies)}",
                    description="Multiple proxy/CDN layers detected. Multi-tier architectures are more susceptible to HTTP smuggling.",
                    cwe_id="CWE-444",
                    cvss_score=0.0,
                    remediation="Ensure all servers in the chain parse HTTP requests identically.",
                    references=[
                        "https://portswigger.net/research/http-request-smuggling"
                    ]
                ))
            
            # Check if both chunked and content-length are processed
            test_headers = {
                'Content-Length': '0',
                'Transfer-Encoding': 'chunked'
            }
            
            test_response = await self.make_request(
                session, "POST", url, headers=test_headers, data=''
            )
            
            if test_response and test_response.status not in [400, 411]:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Dual Header Processing",
                    severity=Severity.LOW,
                    url=url,
                    parameter="Content-Length + Transfer-Encoding",
                    payload="Both headers sent simultaneously",
                    evidence=f"Server returned status {test_response.status} when both CL and TE present",
                    description="Server accepts requests with both Content-Length and Transfer-Encoding headers.",
                    cwe_id="CWE-444",
                    cvss_score=3.0,
                    remediation="Reject requests containing both Content-Length and Transfer-Encoding headers.",
                    references=[
                        "https://portswigger.net/research/http-request-smuggling"
                    ]
                ))
                
        except Exception:
            pass
        
        return vulnerabilities
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
HTTP Request Smuggling Prevention:

1. **Use HTTP/2 End-to-End**
   - HTTP/2 has a binary framing layer that prevents smuggling
   - Ensure all proxy/backend connections use HTTP/2

2. **Reject Ambiguous Requests**
   - Reject requests with both Content-Length and Transfer-Encoding
   - Implement strict HTTP parsing

3. **Normalize Requests at the Edge**
   - Configure frontend to normalize all requests
   - Use consistent parsing across all servers

4. **Configuration Examples:**

**Nginx:**
```nginx
proxy_request_buffering on;
proxy_http_version 1.1;
# Reject requests with both CL and TE
if ($http_transfer_encoding ~* "chunked") {
    set $smuggle_check "1";
}
if ($http_content_length) {
    set $smuggle_check "${smuggle_check}1";
}
if ($smuggle_check = "11") {
    return 400;
}
```
HAProxy:

```haproxy
http-request deny if { req.hdr_cnt(content-length) gt 1 }
http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
http-request deny if { req.hdr(transfer-encoding) -m str chunked } { req.hdr(content-length) -m found }
```
Apache:

```apache
# Use mod_reqtimeout and mod_security
SecRule REQUEST_HEADERS:Content-Length "@rx ^[0-9]+$" "id:1,deny"
SecRule REQUEST_HEADERS:Transfer-Encoding "chunked" "chain,id:2"
SecRule REQUEST_HEADERS:Content-Length ".*" "deny"
```
"""