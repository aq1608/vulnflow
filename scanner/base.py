# scanner/base.py
"""Base classes for all vulnerability scanners"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
from urllib.parse import urlparse, urlencode
import aiohttp
import asyncio
import re


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(Enum):
    """OWASP Top 10 2025 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2025 - Broken Access Control"
    A02_SECURITY_MISCONFIGURATION = "A02:2025 - Security Misconfiguration"
    A03_SUPPLY_CHAIN_FAILURES = "A03:2025 - Software Supply Chain Failures"
    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025 - Cryptographic Failures"
    A05_INJECTION = "A05:2025 - Injection"
    A06_INSECURE_DESIGN = "A06:2025 - Insecure Design"
    A07_AUTH_FAILURES = "A07:2025 - Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2025 - Software or Data Integrity Failures"
    A09_LOGGING_ALERTING_FAILURES = "A09:2025 - Security Logging and Alerting Failures"
    A10_EXCEPTIONAL_CONDITIONS = "A10:2025 - Mishandling of Exceptional Conditions"
    OTHER = "Other"
    
    @classmethod
    def from_legacy(cls, legacy_value: str) -> 'OWASPCategory':
        """Convert OWASP 2021 category strings to 2025 equivalents"""
        legacy_mapping = {
            "A01:2021 - Broken Access Control": cls.A01_BROKEN_ACCESS_CONTROL,
            "A02:2021 - Cryptographic Failures": cls.A04_CRYPTOGRAPHIC_FAILURES,
            "A03:2021 - Injection": cls.A05_INJECTION,
            "A04:2021 - Insecure Design": cls.A06_INSECURE_DESIGN,
            "A05:2021 - Security Misconfiguration": cls.A02_SECURITY_MISCONFIGURATION,
            "A06:2021 - Vulnerable and Outdated Components": cls.A03_SUPPLY_CHAIN_FAILURES,
            "A07:2021 - Identification and Authentication Failures": cls.A07_AUTH_FAILURES,
            "A08:2021 - Software and Data Integrity Failures": cls.A08_DATA_INTEGRITY_FAILURES,
            "A09:2021 - Security Logging and Monitoring Failures": cls.A09_LOGGING_ALERTING_FAILURES,
            "A10:2021 - Server-Side Request Forgery": cls.A01_BROKEN_ACCESS_CONTROL,
        }
        return legacy_mapping.get(legacy_value, cls.OTHER)


@dataclass
class HTTPMessage:
    """Represents a captured HTTP request or response"""
    # Request fields
    method: Optional[str] = None
    url: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    
    # Response fields
    status_code: Optional[int] = None
    status_reason: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    
    # Metadata
    response_time_ms: Optional[float] = None
    payload_reflected: bool = False
    reflection_context: Optional[str] = None  # Where payload was found
    
    def format_request(self) -> str:
        """Format the HTTP request as a string (like in ZAP)"""
        if not self.method or not self.url:
            return ""
        
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        
        lines = [f"{self.method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        
        for header, value in self.request_headers.items():
            if header.lower() != 'host':
                lines.append(f"{header}: {value}")
        
        if self.request_body:
            lines.append("")
            lines.append(self.request_body)
        
        return "\n".join(lines)
    
    def format_response(self, max_body_length: int = 5000) -> str:
        """Format the HTTP response as a string (like in ZAP)"""
        if self.status_code is None:
            return ""
        
        reason = self.status_reason or self._get_status_reason(self.status_code)
        lines = [f"HTTP/1.1 {self.status_code} {reason}"]
        
        for header, value in self.response_headers.items():
            lines.append(f"{header}: {value}")
        
        lines.append("")
        
        if self.response_body:
            body = self.response_body
            if len(body) > max_body_length:
                body = body[:max_body_length] + f"\n\n... [Truncated - {len(self.response_body)} bytes total]"
            lines.append(body)
        
        return "\n".join(lines)
    
    def format_full(self, max_body_length: int = 5000) -> str:
        """Format both request and response"""
        parts = []
        
        request = self.format_request()
        if request:
            parts.append("=" * 60)
            parts.append("REQUEST")
            parts.append("=" * 60)
            parts.append(request)
        
        response = self.format_response(max_body_length)
        if response:
            parts.append("")
            parts.append("=" * 60)
            parts.append("RESPONSE")
            parts.append("=" * 60)
            parts.append(response)
        
        if self.response_time_ms:
            parts.append("")
            parts.append(f"[Response Time: {self.response_time_ms:.0f}ms]")
        
        return "\n".join(parts)
    
    def _get_status_reason(self, code: int) -> str:
        """Get HTTP status reason phrase"""
        reasons = {
            200: "OK", 201: "Created", 204: "No Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
            500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable"
        }
        return reasons.get(code, "Unknown")


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    vuln_type: str
    severity: Severity
    url: str
    description: str
    evidence: str
    owasp_category: OWASPCategory = OWASPCategory.OTHER
    parameter: Optional[str] = None
    payload: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    # NEW: Full HTTP capture (like ZAP)
    request: Optional[str] = None      # Formatted request string
    response: Optional[str] = None     # Formatted response string
    http_message: Optional[HTTPMessage] = None  # Full structured capture
    
    # NEW: Evidence highlighting
    evidence_highlight: Optional[str] = None  # The exact matched/reflected content
    evidence_context: Optional[str] = None    # Surrounding context with highlight


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners"""
    
    name: str = "Base Scanner"
    description: str = "Base scanner class"
    owasp_category: OWASPCategory = OWASPCategory.OTHER
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.timeout = aiohttp.ClientTimeout(total=10)
        self._capture_traffic = True  # Enable HTTP capture by default
    
    @abstractmethod
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for vulnerabilities. Must be implemented by subclasses."""
        pass
    
    async def make_request(self, session: aiohttp.ClientSession,
                          method: str, url: str, 
                          params: Dict = None,
                          data: Dict = None,
                          headers: Dict = None,
                          allow_redirects: bool = True,
                          capture: bool = True) -> Optional[aiohttp.ClientResponse]:
        """Helper method to make HTTP requests with error handling"""
        try:
            if method.upper() == "GET":
                return await session.get(
                    url, params=params, headers=headers,
                    allow_redirects=allow_redirects, timeout=self.timeout
                )
            elif method.upper() == "POST":
                return await session.post(
                    url, params=params, data=data, headers=headers,
                    allow_redirects=allow_redirects, timeout=self.timeout
                )
            elif method.upper() == "PUT":
                return await session.put(
                    url, params=params, data=data, headers=headers,
                    allow_redirects=allow_redirects, timeout=self.timeout
                )
            elif method.upper() == "DELETE":
                return await session.delete(
                    url, params=params, headers=headers,
                    allow_redirects=allow_redirects, timeout=self.timeout
                )
            elif method.upper() == "OPTIONS":
                return await session.options(
                    url, headers=headers,
                    allow_redirects=allow_redirects, timeout=self.timeout
                )
        except asyncio.TimeoutError:
            return None
        except aiohttp.ClientError:
            return None
        except Exception:
            return None
        
        return None
    
    async def make_request_with_capture(
        self, 
        session: aiohttp.ClientSession,
        method: str, 
        url: str, 
        params: Dict = None,
        data: Dict = None,
        headers: Dict = None,
        allow_redirects: bool = True,
        payload: str = None  # The payload to look for in response
    ) -> Tuple[Optional[aiohttp.ClientResponse], Optional[HTTPMessage]]:
        """
        Make HTTP request and capture full request/response details.
        Returns tuple of (response, HTTPMessage)
        """
        import time
        
        http_msg = HTTPMessage()
        http_msg.method = method.upper()
        http_msg.url = url
        http_msg.request_headers = dict(headers) if headers else {}
        
        # Build request body string
        if data:
            if isinstance(data, dict):
                http_msg.request_body = urlencode(data)
            else:
                http_msg.request_body = str(data)
        
        # Add params to URL for capture
        if params:
            if '?' in url:
                http_msg.url = f"{url}&{urlencode(params)}"
            else:
                http_msg.url = f"{url}?{urlencode(params)}"
        
        start_time = time.time()
        
        try:
            response = await self.make_request(
                session, method, url, params, data, headers, allow_redirects
            )
            
            elapsed_ms = (time.time() - start_time) * 1000
            http_msg.response_time_ms = elapsed_ms
            
            if response:
                http_msg.status_code = response.status
                http_msg.response_headers = dict(response.headers)
                
                try:
                    body = await response.text()
                    http_msg.response_body = body
                    
                    # Check if payload is reflected
                    if payload and payload in body:
                        http_msg.payload_reflected = True
                        http_msg.reflection_context = self._find_reflection_context(body, payload)
                except Exception:
                    pass
                
                return response, http_msg
            
            return None, http_msg
            
        except Exception as e:
            http_msg.response_body = f"Error: {str(e)}"
            return None, http_msg
    
    def _find_reflection_context(self, body: str, payload: str, context_chars: int = 100) -> str:
        """Find where payload is reflected and return surrounding context"""
        try:
            index = body.find(payload)
            if index == -1:
                return ""
            
            start = max(0, index - context_chars)
            end = min(len(body), index + len(payload) + context_chars)
            
            context = body[start:end]
            
            # Add markers around the payload
            highlighted = context.replace(
                payload, 
                f">>>PAYLOAD_START>>>{payload}<<<PAYLOAD_END<<<"
            )
            
            prefix = "..." if start > 0 else ""
            suffix = "..." if end < len(body) else ""
            
            return f"{prefix}{highlighted}{suffix}"
        except Exception:
            return ""
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(vuln)
    
    def create_vulnerability(self, http_capture: HTTPMessage = None, **kwargs) -> Vulnerability:
        """Helper to create a vulnerability with scanner defaults and HTTP capture"""
        if 'owasp_category' not in kwargs:
            kwargs['owasp_category'] = self.owasp_category
        
        # Add HTTP capture if provided
        if http_capture:
            kwargs['request'] = http_capture.format_request()
            kwargs['response'] = http_capture.format_response()
            kwargs['http_message'] = http_capture
            
            # Add reflection context to evidence if found
            if http_capture.reflection_context and 'evidence_context' not in kwargs:
                kwargs['evidence_context'] = http_capture.reflection_context
        
        return Vulnerability(**kwargs)
    
    def highlight_payload_in_response(self, response_body: str, payload: str, 
                                       context_lines: int = 3) -> str:
        """
        Extract and highlight the payload location in response.
        Returns a formatted string showing where the payload appears.
        """
        if not payload or payload not in response_body:
            return ""
        
        lines = response_body.split('\n')
        result_lines = []
        
        for i, line in enumerate(lines):
            if payload in line:
                # Add context lines before
                start = max(0, i - context_lines)
                for j in range(start, i):
                    result_lines.append(f"  {j+1}: {lines[j][:200]}")
                
                # Add the matching line with highlight marker
                highlighted_line = line.replace(payload, f"【{payload}】")
                result_lines.append(f"→ {i+1}: {highlighted_line[:300]}")
                
                # Add context lines after
                end = min(len(lines), i + context_lines + 1)
                for j in range(i + 1, end):
                    result_lines.append(f"  {j+1}: {lines[j][:200]}")
                
                result_lines.append("")  # Blank line between matches
        
        return "\n".join(result_lines[:50])  # Limit output