# websec/scanner/ssrf/ssrf.py
"""Server-Side Request Forgery (SSRF) Scanner"""

import re
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import quote

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SSRFScanner(BaseScanner):
    """Scanner for Server-Side Request Forgery vulnerabilities"""
    
    name = "SSRF Scanner"
    description = "Detects Server-Side Request Forgery vulnerabilities"
    owasp_category = OWASPCategory.A10_SSRF
    
    # URL parameter patterns that might be vulnerable
    URL_PARAM_PATTERNS = [
        r'url', r'uri', r'path', r'dest', r'destination',
        r'redirect', r'redir', r'return', r'return_url',
        r'next', r'target', r'link', r'site', r'host',
        r'fetch', r'file', r'document', r'doc', r'page',
        r'feed', r'proxy', r'src', r'source', r'ref',
        r'img', r'image', r'load', r'request', r'callback',
        r'data', r'domain', r'window', r'continue', r'go',
    ]
    
    # SSRF payloads
    PAYLOADS = [
        # Localhost variations
        ('http://127.0.0.1/', 'localhost'),
        ('http://localhost/', 'localhost'),
        ('http://127.0.0.1:80/', 'localhost'),
        ('http://127.0.0.1:443/', 'localhost'),
        ('http://127.0.0.1:22/', 'localhost'),
        ('http://127.0.0.1:8080/', 'localhost'),
        ('http://[::1]/', 'ipv6_localhost'),
        ('http://0.0.0.0/', 'zero_ip'),
        ('http://0/', 'zero_short'),
        
        # Decimal IP
        ('http://2130706433/', 'decimal_localhost'),  # 127.0.0.1 in decimal
        
        # Hex IP
        ('http://0x7f000001/', 'hex_localhost'),
        
        # Octal IP
        ('http://0177.0.0.1/', 'octal_localhost'),
        
        # AWS metadata
        ('http://169.254.169.254/', 'aws_metadata'),
        ('http://169.254.169.254/latest/meta-data/', 'aws_metadata'),
        ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'aws_credentials'),
        
        # GCP metadata
        ('http://metadata.google.internal/', 'gcp_metadata'),
        ('http://169.254.169.254/computeMetadata/v1/', 'gcp_metadata'),
        
        # Azure metadata
        ('http://169.254.169.254/metadata/instance', 'azure_metadata'),
        
        # Internal networks
        ('http://192.168.0.1/', 'internal_network'),
        ('http://192.168.1.1/', 'internal_network'),
        ('http://10.0.0.1/', 'internal_network'),
        ('http://172.16.0.1/', 'internal_network'),
        
        # DNS rebinding (conceptual - would need actual rebinding domain)
        # ('http://rebind.network/', 'dns_rebinding'),
        
        # File protocol
        ('file:///etc/passwd', 'file_protocol'),
        ('file:///c:/windows/win.ini', 'file_protocol'),
        
        # Other protocols
        ('dict://127.0.0.1:6379/info', 'dict_protocol'),
        ('gopher://127.0.0.1:6379/_INFO', 'gopher_protocol'),
    ]
    
    # Evidence patterns for successful SSRF
    LOCALHOST_EVIDENCE = [
        r'root:.*:0:0:',              # Linux /etc/passwd via file://
        r'\[extensions\]',            # Windows win.ini via file://
        r'127\.0\.0\.1',              # Loopback IP
        r'localhost',                 # Local hostname
        r'It works!',                 # Apache default index page
        r'Welcome to nginx',          # Nginx default index page
        r'IIS Windows Server',        # Microsoft IIS default page
        r'X-Powered-By: ',            # Internal header disclosure
        r'content-length: 0'          # Common for internal port scanning
    ]
    
    AWS_EVIDENCE = [
        r'ami-id',
        r'instance-id',
        r'instance-type',
        r'AccessKeyId',
        r'SecretAccessKey',
        r'availability-zone',
        r'iam/security-credentials',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for SSRF vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Find parameters that might accept URLs
        for param_name, param_value in params.items():
            if self._is_url_parameter(param_name, param_value):
                vuln = await self._test_parameter(session, url, params, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_url_parameter(self, param_name: str, param_value: str) -> bool:
        """Check if parameter might accept URLs"""
        param_lower = param_name.lower()
        
        # Check parameter name
        for pattern in self.URL_PARAM_PATTERNS:
            if re.search(pattern, param_lower, re.IGNORECASE):
                return True
        
        # Check if value looks like a URL
        if param_value.startswith(('http://', 'https://', '//', 'ftp://')):
            return True
        
        return False
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str],
                               param_name: str) -> Optional[Vulnerability]:
        """Test a parameter for SSRF"""
        
        for payload, payload_type in self.PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            response = await self.make_request(session, "GET", url, params=test_params)
            if not response:
                continue
            
            body = await response.text()
            status = response.status
            
            # Check for localhost evidence
            if payload_type == 'localhost':
                for pattern in self.LOCALHOST_EVIDENCE:
                    if re.search(pattern, body, re.IGNORECASE):
                        return self.create_vulnerability(
                            vuln_type="Server-Side Request Forgery (SSRF)",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Localhost content detected: {re.search(pattern, body, re.IGNORECASE).group()[:50]}",
                            description="The application is vulnerable to SSRF. Internal services can be accessed through the vulnerable parameter.",
                            cwe_id="CWE-918",
                            cvss_score=8.6,
                            remediation="Validate and sanitize all URL inputs. Implement allowlists for allowed domains. Block requests to internal IP ranges and metadata endpoints.",
                            references=[
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                "https://portswigger.net/web-security/ssrf"
                            ]
                        )
            
            # Check for AWS metadata
            if payload_type in ['aws_metadata', 'aws_credentials']:
                for pattern in self.AWS_EVIDENCE:
                    if re.search(pattern, body, re.IGNORECASE):
                        return self.create_vulnerability(
                            vuln_type="SSRF - Cloud Metadata Access",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"AWS metadata/credentials detected: {pattern}",
                            description="The application is vulnerable to SSRF allowing access to cloud metadata services. This can lead to credential theft.",
                            cwe_id="CWE-918",
                            cvss_score=9.8,
                            remediation="Block access to metadata IP ranges (169.254.169.254). Use IMDSv2 which requires session tokens.",
                            references=[
                                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
                                "https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af"
                            ]
                        )
            
            # Check for file protocol
            if payload_type == 'file_protocol':
                if 'root:' in body or '[extensions]' in body.lower():
                    return self.create_vulnerability(
                        vuln_type="SSRF - Local File Read via File Protocol",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence="Local file content retrieved via file:// protocol",
                        description="The application allows file:// protocol, enabling local file read through SSRF.",
                        cwe_id="CWE-918",
                        cvss_score=9.1,
                        remediation="Block file:// and other dangerous protocols. Only allow http:// and https:// to whitelisted domains.",
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                        ]
                    )
            
            # Check for internal network access
            if payload_type == 'internal_network':
                # Response shouldn't be accessible from external request
                if status == 200 and len(body) > 100:
                    if not self._is_error_page(body):
                        return self.create_vulnerability(
                            vuln_type="SSRF - Internal Network Access",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Internal network resource accessible. Response length: {len(body)}",
                            description="The application can access internal network resources through SSRF.",
                            cwe_id="CWE-918",
                            cvss_score=7.5,
                            remediation="Block requests to private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x).",
                            references=[
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                            ]
                        )
        
        return None
    
    def _is_error_page(self, body: str) -> bool:
        """Check if response is an error page"""
        error_indicators = [
            'not found', '404', 'error', 'forbidden',
            'access denied', 'unauthorized', 'invalid url',
            'could not connect', 'connection refused'
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in error_indicators)