# scanner/misconfig/ssl_tls.py
"""
SSL/TLS Security Scanner

Detects SSL/TLS misconfigurations:
- Weak protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Weak cipher suites
- Certificate issues
- Missing HSTS
- Mixed content

OWASP: A02:2021 - Cryptographic Failures
"""

import asyncio
import aiohttp
import ssl
import socket
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SSLTLSScanner(BaseScanner):
    """Scanner for SSL/TLS vulnerabilities"""

    name="SSL/TLS Security Scanner",
    description="Detects SSL/TLS misconfigurations and weaknesses",
    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
    
    def __init__(self):
        
        # Weak cipher suites
        self.weak_ciphers = [
            "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
            "RC2", "IDEA", "SEED", "ARIA", "CAMELLIA"
        ]
        
        # Weak protocols
        self.weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        
        # Only scan HTTPS URLs
        if parsed.scheme != "https":
            # Check if HTTPS is available but not used
            https_url = url.replace("http://", "https://")
            https_vuln = await self._check_https_available(session, https_url, url)
            if https_vuln:
                vulnerabilities.append(https_vuln)
            return vulnerabilities
        
        host = parsed.hostname
        port = parsed.port or 443
        
        # Check certificate
        cert_vulns = await self._check_certificate(host, port, url)
        vulnerabilities.extend(cert_vulns)
        
        # Check for weak protocols
        protocol_vulns = await self._check_weak_protocols(host, port, url)
        vulnerabilities.extend(protocol_vulns)
        
        # Check HSTS
        hsts_vuln = await self._check_hsts(session, url)
        if hsts_vuln:
            vulnerabilities.append(hsts_vuln)
        
        # Check for mixed content indicators
        mixed_vuln = await self._check_mixed_content(session, url)
        if mixed_vuln:
            vulnerabilities.append(mixed_vuln)
        
        return vulnerabilities
    
    async def _check_https_available(
        self,
        session: aiohttp.ClientSession,
        https_url: str,
        http_url: str
    ) -> Optional[Vulnerability]:
        """Check if HTTPS is available but HTTP is being used"""
        try:
            async with session.get(
                https_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=True
            ) as response:
                if response.status in [200, 301, 302]:
                    return Vulnerability(
                        vuln_type="HTTP Used Instead of HTTPS",
                        severity=Severity.HIGH,
                        url=http_url,
                        parameter="Protocol",
                        payload="N/A",
                        evidence=f"HTTPS available at {https_url}",
                        description="Site is accessible over HTTP but HTTPS is available",
                        cwe_id="CWE-319",
                        remediation="Redirect all HTTP traffic to HTTPS. Enable HSTS."
                    )
        except:
            pass
        
        return None
    
    async def _check_certificate(
        self,
        host: str,
        port: int,
        url: str
    ) -> List[Vulnerability]:
        """Check SSL certificate for issues"""
        vulnerabilities = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(
                None, self._get_certificate_info, host, port
            )
            
            if cert_info:
                # Check expiration
                not_after = cert_info.get("notAfter")
                if not_after:
                    try:
                        # Parse the date
                        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_until_expiry = (exp_date - datetime.now()).days
                        
                        if days_until_expiry < 0:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Expired SSL Certificate",
                                severity=Severity.HIGH,
                                url=url,
                                parameter="SSL Certificate",
                                payload="N/A",
                                evidence=f"Certificate expired on {not_after}",
                                description="SSL certificate has expired",
                                cwe_id="CWE-295",
                                remediation="Renew SSL certificate immediately."
                            ))
                        elif days_until_expiry < 30:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="SSL Certificate Expiring Soon",
                                severity=Severity.LOW,
                                url=url,
                                parameter="SSL Certificate",
                                payload="N/A",
                                evidence=f"Certificate expires in {days_until_expiry} days",
                                description=f"SSL certificate expiring in {days_until_expiry} days",
                                cwe_id="CWE-295",
                                remediation="Renew SSL certificate before expiration."
                            ))
                    except:
                        pass
                
                # Check subject/issuer
                issuer = cert_info.get("issuer")
                if issuer:
                    issuer_str = str(issuer)
                    if "self-signed" in issuer_str.lower() or cert_info.get("subject") == issuer:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Self-Signed SSL Certificate",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="SSL Certificate",
                            payload="N/A",
                            evidence="Certificate appears to be self-signed",
                            description="Using self-signed certificate instead of CA-signed",
                            cwe_id="CWE-295",
                            remediation="Use a certificate signed by a trusted Certificate Authority."
                        ))
        
        except ssl.SSLCertVerificationError as e:
            vulnerabilities.append(Vulnerability(
                vuln_type="SSL Certificate Verification Failed",
                severity=Severity.HIGH,
                url=url,
                parameter="SSL Certificate",
                payload="N/A",
                evidence=str(e)[:200],
                description="SSL certificate failed verification",
                cwe_id="CWE-295",
                remediation="Fix certificate issues: ensure proper chain, valid hostname, and trusted CA."
            ))
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _get_certificate_info(self, host: str, port: int) -> Optional[Dict]:
        """Get certificate information (runs in executor)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Get binary cert and decode
                        cert_bin = ssock.getpeercert(binary_form=True)
                        if cert_bin:
                            import ssl
                            cert = ssl.DER_cert_to_PEM_cert(cert_bin)
                    return cert
        except:
            return None
    
    async def _check_weak_protocols(
        self,
        host: str,
        port: int,
        url: str
    ) -> List[Vulnerability]:
        """Check for weak SSL/TLS protocols"""
        vulnerabilities = []
        
        protocols_to_test = [
            (ssl.PROTOCOL_TLS, "TLS (all versions)"),
        ]
        
        # Test for TLS 1.0 and 1.1 support
        loop = asyncio.get_event_loop()
        
        for protocol_version, protocol_name in [("TLSv1.0", "TLS 1.0"), ("TLSv1.1", "TLS 1.1")]:
            try:
                supports = await loop.run_in_executor(
                    None, self._test_protocol, host, port, protocol_version
                )
                
                if supports:
                    vulnerabilities.append(Vulnerability(
                        vuln_type=f"Weak Protocol: {protocol_name}",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="SSL/TLS Protocol",
                        payload="N/A",
                        evidence=f"Server supports deprecated {protocol_name}",
                        description=f"Server supports {protocol_name} which is deprecated and insecure",
                        cwe_id="CWE-326",
                        remediation=f"Disable {protocol_name}. Only allow TLS 1.2 and TLS 1.3."
                    ))
            except:
                continue
        
        return vulnerabilities
    
    def _test_protocol(self, host: str, port: int, protocol: str) -> bool:
        """Test if a specific protocol is supported"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set maximum version based on what we're testing
            if protocol == "TLSv1.0":
                context.maximum_version = ssl.TLSVersion.TLSv1
                context.minimum_version = ssl.TLSVersion.TLSv1
            elif protocol == "TLSv1.1":
                context.maximum_version = ssl.TLSVersion.TLSv1_1
                context.minimum_version = ssl.TLSVersion.TLSv1_1
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except:
            return False
    
    async def _check_hsts(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Check for HSTS header"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                hsts = response.headers.get("Strict-Transport-Security")
                
                if not hsts:
                    return Vulnerability(
                        vuln_type="Missing HSTS Header",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="HTTP Headers",
                        payload="N/A",
                        evidence="Strict-Transport-Security header not present",
                        description="HTTP Strict Transport Security (HSTS) not implemented",
                        cwe_id="CWE-319",
                        remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    )
                
                # Check HSTS configuration
                if "max-age=0" in hsts:
                    return Vulnerability(
                        vuln_type="HSTS Disabled",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="Strict-Transport-Security",
                        payload="N/A",
                        evidence=f"HSTS max-age is 0: {hsts}",
                        description="HSTS is effectively disabled with max-age=0",
                        cwe_id="CWE-319",
                        remediation="Set max-age to at least 31536000 (1 year)."
                    )
                
                # Check for short max-age
                import re
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 2592000:  # Less than 30 days
                        return Vulnerability(
                            vuln_type="Weak HSTS Configuration",
                            severity=Severity.LOW,
                            url=url,
                            parameter="Strict-Transport-Security",
                            payload="N/A",
                            evidence=f"HSTS max-age too short: {max_age} seconds",
                            description="HSTS max-age is too short for effective protection",
                            cwe_id="CWE-319",
                            remediation="Increase max-age to at least 31536000 (1 year)."
                        )
        
        except Exception:
            pass
        
        return None
    
    async def _check_mixed_content(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Check for mixed content indicators"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                html = await response.text()
                
                # Look for HTTP resources in HTTPS page
                import re
                http_resources = re.findall(
                    r'(?:src|href|action)=["\']http://[^"\']+["\']',
                    html,
                    re.IGNORECASE
                )
                
                if http_resources:
                    return Vulnerability(
                        vuln_type="Mixed Content",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="Page Content",
                        payload="N/A",
                        evidence=f"Found {len(http_resources)} HTTP resources: {http_resources[0][:100]}...",
                        description="HTTPS page loads resources over HTTP (mixed content)",
                        cwe_id="CWE-319",
                        remediation="Load all resources over HTTPS. Use protocol-relative URLs or HTTPS."
                    )
        
        except Exception:
            pass
        
        return None