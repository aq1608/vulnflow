# websec/scanner/vuln_scanner.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
from urllib.parse import urlparse, parse_qs
import aiohttp
import asyncio
import re


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    vuln_type: str
    severity: Severity
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: str
    description: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


class BaseScanner(ABC):
    """Abstract base class for vulnerability scanners"""
    
    @abstractmethod
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str]) -> List[Vulnerability]:
        pass


class SQLInjectionScanner(BaseScanner):
    """SQL Injection vulnerability scanner"""
    
    PAYLOADS = [
        ("'", "error"),
        ("\"", "error"),
        ("' OR '1'='1", "boolean"),
        ("' OR '1'='1'--", "boolean"),
        ("1' ORDER BY 1--", "error"),
        ("1' ORDER BY 100--", "error"),
        ("1' UNION SELECT NULL--", "union"),
        ("1' UNION SELECT NULL,NULL--", "union"),
        ("'; WAITFOR DELAY '0:0:3'--", "time"),
        ("' AND SLEEP(3)--", "time"),
        ("1; SELECT SLEEP(3)--", "time"),
    ]
    
    SQL_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"Warning.*mysqli_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"PostgreSQL.*ERROR",
        r"pg_query",
        r"pg_exec",
        r"PG::SyntaxError",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"SQLite.*error",
        r"sqlite3\.OperationalError",
        r"SQLite3::SQLException",
        r"System\.Data\.SqlClient",
        r"System\.Data\.OleDb",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"Incorrect syntax near",
        r"Syntax error in string in query expression",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"ODBC SQL Server Driver",
        r"ODBC.*Driver.*Error",
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for param_name in params:
            for payload, payload_type in self.PAYLOADS:
                vuln = await self._test_parameter(
                    session, url, param_name, params, payload, payload_type
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Found vulnerability, move to next parameter
        
        return vulnerabilities
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                              url: str, param: str, original_params: Dict,
                              payload: str, payload_type: str) -> Optional[Vulnerability]:
        test_params = original_params.copy()
        test_params[param] = payload
        
        try:
            start_time = asyncio.get_event_loop().time()
            
            async with session.get(url, params=test_params, 
                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
                elapsed = asyncio.get_event_loop().time() - start_time
                body = await response.text()
                
                # Check for error-based SQLi
                for error_pattern in self.SQL_ERRORS:
                    match = re.search(error_pattern, body, re.IGNORECASE)
                    if match:
                        return Vulnerability(
                            vuln_type="SQL Injection (Error-based)",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=match.group()[:100],
                            description="SQL error message detected in response, indicating SQL injection vulnerability",
                            cwe_id="CWE-89",
                            cvss_score=9.8
                        )
                
                # Check for time-based SQLi
                if payload_type == "time" and elapsed > 2.5:
                    return Vulnerability(
                        vuln_type="SQL Injection (Time-based Blind)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f} seconds",
                        description="Time-based blind SQL injection detected",
                        cwe_id="CWE-89",
                        cvss_score=9.8
                    )
                    
        except asyncio.TimeoutError:
            if payload_type == "time":
                return Vulnerability(
                    vuln_type="SQL Injection (Time-based Blind)",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence="Request timed out (possible time-based injection)",
                    description="Time-based blind SQL injection detected",
                    cwe_id="CWE-89",
                    cvss_score=9.8
                )
        except Exception:
            pass
        
        return None


class XSSScanner(BaseScanner):
    """Cross-Site Scripting vulnerability scanner"""
    
    PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        "javascript:alert(1)",
        '<iframe src="javascript:alert(1)">',
        '{{constructor.constructor("alert(1)")()}}',
        '${alert(1)}',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for param_name in params:
            for payload in self.PAYLOADS:
                vuln = await self._test_reflection(
                    session, url, param_name, params, payload
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    async def _test_reflection(self, session: aiohttp.ClientSession,
                               url: str, param: str, original_params: Dict,
                               payload: str) -> Optional[Vulnerability]:
        test_params = original_params.copy()
        test_params[param] = payload
        
        try:
            async with session.get(url, params=test_params) as response:
                body = await response.text()
                
                # Check if payload is reflected without encoding
                if payload in body:
                    context = self._analyze_context(body, payload)
                    if context["exploitable"]:
                        return Vulnerability(
                            vuln_type=f"Cross-Site Scripting ({context['type']})",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=context.get("evidence", "Payload reflected without encoding")[:100],
                            description=f"XSS vulnerability - user input reflected in {context['type']} context",
                            cwe_id="CWE-79",
                            cvss_score=6.1
                        )
                    
        except Exception:
            pass
        
        return None
    
    def _analyze_context(self, body: str, payload: str) -> Dict:
        """Analyze the context where payload is reflected"""
        pos = body.find(payload)
        if pos == -1:
            return {"exploitable": False}
        
        # Get surrounding context
        start = max(0, pos - 100)
        end = min(len(body), pos + len(payload) + 100)
        context = body[start:end]
        
        # Check if in script context
        if re.search(r'<script[^>]*>.*' + re.escape(payload), context, re.DOTALL | re.IGNORECASE):
            return {"exploitable": True, "type": "Script Context", "evidence": context[:200]}
        
        # Check if in event handler
        if re.search(r'on\w+\s*=\s*["\']?.*' + re.escape(payload), context, re.IGNORECASE):
            return {"exploitable": True, "type": "Event Handler", "evidence": context[:200]}
        
        # Check if creates new tag
        if '<script' in payload.lower() or '<img' in payload.lower() or '<svg' in payload.lower():
            return {"exploitable": True, "type": "HTML Injection", "evidence": context[:200]}
        
        # Check if in href/src
        if re.search(r'(href|src)\s*=\s*["\']?.*' + re.escape(payload), context, re.IGNORECASE):
            return {"exploitable": True, "type": "URL Context", "evidence": context[:200]}
        
        return {"exploitable": True, "type": "Reflected", "evidence": context[:200]}


class HeadersScanner(BaseScanner):
    """Security Headers scanner"""
    
    SECURITY_HEADERS = {
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "Missing X-Frame-Options header - vulnerable to clickjacking attacks",
            "cwe": "CWE-1021"
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "description": "Missing X-Content-Type-Options header - vulnerable to MIME type sniffing",
            "cwe": "CWE-693"
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "Missing Content-Security-Policy header - reduced XSS protection",
            "cwe": "CWE-693"
        },
        "Strict-Transport-Security": {
            "severity": Severity.MEDIUM,
            "description": "Missing HSTS header - vulnerable to SSL stripping attacks",
            "cwe": "CWE-319"
        },
        "X-XSS-Protection": {
            "severity": Severity.LOW,
            "description": "Missing X-XSS-Protection header (legacy browser XSS protection)",
            "cwe": "CWE-79"
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "description": "Missing Referrer-Policy header - may leak sensitive URL information",
            "cwe": "CWE-200"
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "description": "Missing Permissions-Policy header - browser features not restricted",
            "cwe": "CWE-693"
        },
    }
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            async with session.get(url) as response:
                headers = response.headers
                
                for header_name, info in self.SECURITY_HEADERS.items():
                    if header_name not in headers:
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"Missing Security Header: {header_name}",
                            severity=info["severity"],
                            url=url,
                            parameter=None,
                            payload=None,
                            evidence=f"Header '{header_name}' not present in response",
                            description=info["description"],
                            cwe_id=info["cwe"],
                            cvss_score=4.0
                        ))
                
                # Check for information disclosure headers
                info_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
                for header in info_headers:
                    if header in headers:
                        vulnerabilities.append(Vulnerability(
                            vuln_type=f"Information Disclosure: {header}",
                            severity=Severity.INFO,
                            url=url,
                            parameter=None,
                            payload=None,
                            evidence=f"{header}: {headers[header]}",
                            description=f"Server reveals technology information via {header} header",
                            cwe_id="CWE-200",
                            cvss_score=2.0
                        ))
                        
        except Exception:
            pass
        
        return vulnerabilities


class CSRFScanner(BaseScanner):
    """CSRF vulnerability scanner"""
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        # This scanner works on forms, check if it's a POST form without CSRF token
        csrf_token_names = [
            'csrf', 'csrf_token', 'csrftoken', '_csrf', 'token',
            '__RequestVerificationToken', 'authenticity_token',
            'csrfmiddlewaretoken', '_token', 'XSRF-TOKEN'
        ]
        
        has_csrf_token = any(
            name.lower() in [p.lower() for p in params.keys()]
            for name in csrf_token_names
        )
        
        if not has_csrf_token and params:
            vulnerabilities.append(Vulnerability(
                vuln_type="Potential CSRF Vulnerability",
                severity=Severity.MEDIUM,
                url=url,
                parameter=None,
                payload=None,
                evidence="Form does not contain a CSRF token",
                description="Form submission may be vulnerable to Cross-Site Request Forgery",
                cwe_id="CWE-352",
                cvss_score=6.5
            ))
        
        return vulnerabilities


class VulnerabilityScanner:
    """Main scanner orchestrator"""
    
    def __init__(self):
        self.scanners: List[BaseScanner] = [
            SQLInjectionScanner(),
            XSSScanner(),
            HeadersScanner(),
            CSRFScanner(),
        ]
    
    async def scan_target(self, crawl_results: Dict) -> List[Vulnerability]:
        """Scan all discovered targets"""
        all_vulnerabilities = []
        
        # Prepare targets
        targets = self._prepare_targets(crawl_results)
        
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Scan headers on discovered URLs
            headers_scanner = HeadersScanner()
            for url in list(crawl_results.get("urls", {}).keys())[:5]:  # Check first 5 URLs
                vulns = await headers_scanner.scan(session, url)
                all_vulnerabilities.extend(vulns)
            
            # Scan each target with all scanners
            for target in targets:
                for scanner in self.scanners:
                    if isinstance(scanner, HeadersScanner):
                        continue  # Already scanned
                    
                    vulns = await scanner.scan(
                        session, 
                        target['url'], 
                        target['params']
                    )
                    all_vulnerabilities.extend(vulns)
        
        # Remove duplicates
        unique_vulns = self._deduplicate_vulns(all_vulnerabilities)
        
        return unique_vulns
    
    def _prepare_targets(self, crawl_results: Dict) -> List[Dict]:
        """Prepare scan targets from crawl results"""
        targets = []
        
        # From forms
        for form in crawl_results.get("forms", []):
            if form.get("inputs"):
                params = {}
                for inp in form["inputs"]:
                    if inp.get("name"):
                        params[inp["name"]] = inp.get("value", "test")
                
                if params:
                    targets.append({
                        "url": form["action"],
                        "method": form["method"],
                        "params": params
                    })
        
        # From URLs with query parameters
        for url in crawl_results.get("urls", {}):
            parsed = urlparse(url)
            if parsed.query:
                params = {}
                for key, values in parse_qs(parsed.query).items():
                    params[key] = values[0] if values else ""
                
                targets.append({
                    "url": url.split("?")[0],
                    "method": "GET",
                    "params": params
                })
        
        return targets
    
    def _deduplicate_vulns(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in vulns:
            key = (vuln.vuln_type, vuln.url, vuln.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique