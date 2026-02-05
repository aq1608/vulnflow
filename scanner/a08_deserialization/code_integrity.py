# scanner/deserialization/code_integrity.py
"""
Code Integrity Scanner

Detects code and data integrity issues:
- Missing integrity verification on updates
- Unsigned code/scripts
- Unverified external resources
- Auto-update without integrity checks

OWASP: A08:2025 - Software or Data Integrity Failures
CWE-345: Insufficient Verification of Data Authenticity
CWE-353: Missing Support for Integrity Check
CWE-494: Download of Code Without Integrity Check
"""

import re
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CodeIntegrityScanner(BaseScanner):
    """Scanner for code and data integrity vulnerabilities"""
    
    name = "Code Integrity Scanner"
    description = "Detects missing integrity verification on code and data"
    owasp_category = OWASPCategory.A08_DATA_INTEGRITY_FAILURES
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for code integrity issues"""
        vulnerabilities = []
        
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return vulnerabilities
            
            body = await response.text()
            headers = dict(response.headers)
            
            # Check for Content-Security-Policy require-sri-for
            csp_vulns = self._check_csp_sri(headers, url)
            vulnerabilities.extend(csp_vulns)
            
            # Check for unsafe eval/inline in CSP
            eval_vulns = self._check_unsafe_eval(headers, url)
            vulnerabilities.extend(eval_vulns)
            
            # Check for document.write with external content
            docwrite_vulns = self._check_document_write(body, url)
            vulnerabilities.extend(docwrite_vulns)
            
            # Check for eval with external data
            eval_data_vulns = self._check_eval_external_data(body, url)
            vulnerabilities.extend(eval_data_vulns)
            
            # Check for postMessage without origin validation
            postmsg_vulns = self._check_postmessage(body, url)
            vulnerabilities.extend(postmsg_vulns)
            
            # Check for automatic update mechanisms
            update_vulns = self._check_auto_update(body, url)
            vulnerabilities.extend(update_vulns)
            
            # Check for WebSocket without integrity
            ws_vulns = self._check_websocket_integrity(body, url)
            vulnerabilities.extend(ws_vulns)
            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_csp_sri(self, headers: Dict, url: str) -> List[Vulnerability]:
        """Check if CSP requires SRI"""
        vulnerabilities = []
        
        csp = headers.get('Content-Security-Policy', '')
        
        # Check for require-sri-for directive (deprecated but indicates awareness)
        # Modern approach is to use strict CSP with hashes/nonces
        
        if csp:
            # Check if CSP allows unsafe sources without SRI
            if "'unsafe-inline'" in csp and 'script-src' in csp:
                if 'sha256-' not in csp and 'sha384-' not in csp and 'sha512-' not in csp:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="CSP Allows Unsafe Inline Without Hashes",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="Content-Security-Policy",
                        payload=csp[:200],
                        evidence="unsafe-inline without hash-based allowlist",
                        description="CSP allows inline scripts without requiring integrity hashes.",
                        cwe_id="CWE-353",
                        cvss_score=5.0,
                        remediation="Use hash-based CSP ('sha256-...') instead of 'unsafe-inline'.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                        ]
                    ))
        else:
            # No CSP at all
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Missing Content Security Policy",
                severity=Severity.LOW,
                url=url,
                parameter="HTTP Headers",
                payload="N/A",
                evidence="No Content-Security-Policy header",
                description="No CSP header to enforce script integrity requirements.",
                cwe_id="CWE-353",
                cvss_score=3.0,
                remediation="Implement Content-Security-Policy with strict-dynamic or hash-based policies.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                ]
            ))
        
        return vulnerabilities
    
    def _check_unsafe_eval(self, headers: Dict, url: str) -> List[Vulnerability]:
        """Check for unsafe-eval in CSP"""
        vulnerabilities = []
        
        csp = headers.get('Content-Security-Policy', '')
        
        if "'unsafe-eval'" in csp:
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="CSP Allows Unsafe Eval",
                severity=Severity.MEDIUM,
                url=url,
                parameter="Content-Security-Policy",
                payload="'unsafe-eval'",
                evidence="CSP contains 'unsafe-eval'",
                description="CSP allows eval(), which can execute unverified code strings.",
                cwe_id="CWE-95",
                cvss_score=5.5,
                remediation="Remove 'unsafe-eval' from CSP. Refactor code to avoid eval().",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                ]
            ))
        
        return vulnerabilities
    
    def _check_document_write(self, body: str, url: str) -> List[Vulnerability]:
        """Check for document.write with external content"""
        vulnerabilities = []
        
        # Patterns for dangerous document.write usage
        dangerous_patterns = [
            (r'document\.write\s*\([^)]*https?://', 'document.write with external URL'),
            (r'document\.write\s*\([^)]*<script', 'document.write with script tag'),
            (r'document\.writeln\s*\([^)]*https?://', 'document.writeln with external URL'),
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Unsafe document.write Usage",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="JavaScript",
                    payload=description,
                    evidence=f"Found: {description}",
                    description="document.write() is used to inject external content without integrity verification.",
                    cwe_id="CWE-494",
                    cvss_score=5.0,
                    remediation="Avoid document.write(). Use DOM methods with proper sanitization.",
                    references=[]
                ))
                break
        
        return vulnerabilities
    
    def _check_eval_external_data(self, body: str, url: str) -> List[Vulnerability]:
        """Check for eval with external data"""
        vulnerabilities = []
        
        # Patterns for eval with external data
        eval_patterns = [
            (r'eval\s*\(\s*(?:response|data|result|json|xhr|fetch)', 'eval with response data'),
            (r'eval\s*\(\s*(?:localStorage|sessionStorage)', 'eval with storage data'),
            (r'new\s+Function\s*\([^)]*(?:response|data|result)', 'Function constructor with external data'),
            (r'setTimeout\s*\([^,]*(?:response|data|result)', 'setTimeout with string from external'),
            (r'setInterval\s*\([^,]*(?:response|data|result)', 'setInterval with string from external'),
        ]
        
        for pattern, description in eval_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Code Execution from External Data",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="JavaScript",
                    payload=description,
                    evidence=f"Found: {description}",
                    description="Code is executed from external/untrusted data without integrity verification.",
                    cwe_id="CWE-494",
                    cvss_score=7.5,
                    remediation="Never eval() external data. Use JSON.parse() for data. Implement integrity checks.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/494.html"
                    ]
                ))
                break
        
        return vulnerabilities
    
    def _check_postmessage(self, body: str, url: str) -> List[Vulnerability]:
        """Check for postMessage without origin validation"""
        vulnerabilities = []
        
        # Check for message event listeners
        if 'addEventListener' in body and 'message' in body:
            # Check if origin is being validated
            has_listener = re.search(
                r'addEventListener\s*\(\s*["\']message["\']',
                body,
                re.IGNORECASE
            )
            
            if has_listener:
                # Check for origin validation
                has_origin_check = re.search(
                    r'\.origin\s*(?:===|==|!==|!=)',
                    body,
                    re.IGNORECASE
                )
                
                # Check for dangerous operations without origin check
                has_dangerous_op = re.search(
                    r'addEventListener\s*\(\s*["\']message["\'][^}]*(?:eval|innerHTML|document\.write|location)',
                    body,
                    re.IGNORECASE | re.DOTALL
                )
                
                if has_dangerous_op and not has_origin_check:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="postMessage Without Origin Validation",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="postMessage handler",
                        payload="N/A",
                        evidence="Message handler executes code without validating origin",
                        description="postMessage handler performs dangerous operations without verifying the message origin.",
                        cwe_id="CWE-345",
                        cvss_score=7.0,
                        remediation="Always validate event.origin against an allowlist before processing postMessage data.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns"
                        ]
                    ))
        
        return vulnerabilities
    
    def _check_auto_update(self, body: str, url: str) -> List[Vulnerability]:
        """Check for auto-update mechanisms without integrity"""
        vulnerabilities = []
        
        # Patterns for auto-update mechanisms
        update_patterns = [
            (r'auto.?update', 'auto-update functionality'),
            (r'check.?update', 'update checking'),
            (r'download.?update', 'update download'),
            (r'install.?update', 'update installation'),
            (r'\.update\s*$\s*$', 'update method call'),
        ]
        
        for pattern, description in update_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                # Check if integrity is mentioned
                has_integrity = re.search(
                    r'(integrity|signature|hash|verify|checksum)',
                    body,
                    re.IGNORECASE
                )
                
                if not has_integrity:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Auto-Update Without Integrity Verification",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="Update Mechanism",
                        payload=description,
                        evidence=f"Found {description} without apparent integrity checks",
                        description="Application has update functionality without visible integrity verification.",
                        cwe_id="CWE-494",
                        cvss_score=6.0,
                        remediation="Implement code signing and verify signatures before applying updates.",
                        references=[
                            "https://cwe.mitre.org/data/definitions/494.html"
                        ]
                    ))
                    break
        
        return vulnerabilities
    
    def _check_websocket_integrity(self, body: str, url: str) -> List[Vulnerability]:
        """Check for WebSocket connections without integrity measures"""
        vulnerabilities = []
        
        # Check for WebSocket usage
        ws_match = re.search(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', body)
        
        if ws_match:
            ws_url = ws_match.group(1)
            
            # Check if it's using ws:// instead of wss://
            if ws_url.startswith('ws://') or ('ws://' in ws_url and 'wss://' not in ws_url):
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Insecure WebSocket Connection",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="WebSocket",
                    payload=ws_url,
                    evidence="WebSocket using ws:// instead of wss://",
                    description="WebSocket connection is unencrypted, allowing data interception and manipulation.",
                    cwe_id="CWE-319",
                    cvss_score=5.5,
                    remediation="Use wss:// for secure WebSocket connections.",
                    references=[]
                ))
            
            # Check if messages are processed without validation
            has_json_parse = 'JSON.parse' in body
            has_eval_ws = re.search(r'onmessage[^}]*eval\s*\(', body, re.IGNORECASE | re.DOTALL)
            
            if has_eval_ws:
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="WebSocket Data Execution",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="WebSocket handler",
                    payload="N/A",
                    evidence="WebSocket message handler uses eval()",
                    description="WebSocket messages are executed without integrity verification.",
                    cwe_id="CWE-345",
                    cvss_score=7.5,
                    remediation="Never eval() WebSocket data. Use JSON.parse() and validate message structure.",
                    references=[]
                ))
        
        return vulnerabilities