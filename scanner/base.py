# websec/scanner/base.py
"""Base classes for all vulnerability scanners"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import aiohttp
import asyncio


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(Enum):
    """OWASP Top 10 2021 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"
    OTHER = "Other"


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
    request: Optional[str] = None
    response: Optional[str] = None


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners"""
    
    name: str = "Base Scanner"
    description: str = "Base scanner class"
    owasp_category: OWASPCategory = OWASPCategory.OTHER
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.timeout = aiohttp.ClientTimeout(total=10)
    
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
                          allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
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
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(vuln)
    
    def create_vulnerability(self, **kwargs) -> Vulnerability:
        """Helper to create a vulnerability with scanner defaults"""
        if 'owasp_category' not in kwargs:
            kwargs['owasp_category'] = self.owasp_category
        return Vulnerability(**kwargs)