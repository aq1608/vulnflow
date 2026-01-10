# run_scan.py - Place in project root
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional
from enum import Enum
import re
import json
import argparse
from datetime import datetime

# ============================================
# DATA CLASSES
# ============================================

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

# ============================================
# CRAWLER
# ============================================

class AsyncWebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.discovered_urls: Dict[str, dict] = {}
        self.forms: List[dict] = []
        self.endpoints: List[dict] = []
        
    async def crawl(self) -> Dict:
        """Main crawl entry point"""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            await self._crawl_url(session, self.base_url, 0)
        
        return {
            "urls": self.discovered_urls,
            "forms": self.forms,
            "endpoints": self.endpoints,
            "total_pages": len(self.visited)
        }
    
    async def _crawl_url(self, session: aiohttp.ClientSession, url: str, depth: int):
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        if not self._is_same_domain(url):
            return
            
        self.visited.add(url)
        print(f"  [Crawl] Visiting: {url[:80]}...")
        
        try:
            async with session.get(url, allow_redirects=True) as response:
                content_type = response.headers.get('Content-Type', '')
                
                self.discovered_urls[url] = {
                    "status": response.status,
                    "content_type": content_type,
                    "headers": dict(response.headers)
                }
                
                if response.status == 200 and 'text/html' in content_type:
                    html = await response.text()
                    await self._parse_page(session, url, html, depth)
                        
        except Exception as e:
            self.discovered_urls[url] = {"error": str(e)}
    
    async def _parse_page(self, session: aiohttp.ClientSession, 
                          base_url: str, html: str, depth: int):
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract links
        tasks = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('#') or href.startswith('javascript:'):
                continue
            full_url = urljoin(base_url, href)
            # Remove fragments
            full_url = full_url.split('#')[0]
            if full_url not in self.visited:
                tasks.append(self._crawl_url(session, full_url, depth + 1))
        
        # Extract forms
        for form in soup.find_all('form'):
            form_data = self._parse_form(base_url, form)
            if form_data not in self.forms:
                self.forms.append(form_data)
        
        # Run crawl tasks
        if tasks:
            await asyncio.gather(*tasks[:10])  # Limit concurrent tasks
    
    def _parse_form(self, base_url: str, form) -> dict:
        action = form.get('action', '')
        return {
            "action": urljoin(base_url, action) if action else base_url,
            "method": form.get('method', 'GET').upper(),
            "inputs": [
                {
                    "name": inp.get('name'),
                    "type": inp.get('type', 'text'),
                    "value": inp.get('value', '')
                }
                for inp in form.find_all(['input', 'textarea', 'select'])
                if inp.get('name')
            ]
        }
    
    def _is_same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == urlparse(self.base_url).netloc
        except:
            return False

# ============================================
# SQL INJECTION SCANNER
# ============================================

class SQLInjectionScanner:
    PAYLOADS = [
        ("'", "error"),
        ("\"", "error"),
        ("' OR '1'='1", "boolean"),
        ("' OR '1'='1'--", "boolean"),
        ("1' ORDER BY 1--", "error"),
        ("1' UNION SELECT NULL--", "union"),
        ("'; WAITFOR DELAY '0:0:3'--", "time"),
        ("' AND SLEEP(3)--", "time"),
    ]
    
    SQL_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"pg_query",
        r"pg_exec",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"ORA-\d{5}",
        r"Oracle error",
        r"SQLite.*error",
        r"sqlite3.OperationalError",
        r"System\.Data\.SqlClient",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"ODBC SQL Server Driver",
    ]
    
    async def scan(self, session: aiohttp.ClientSession, url: str, 
                   params: Dict[str, str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for param_name in params:
            for payload, payload_type in self.PAYLOADS:
                vuln = await self._test_parameter(
                    session, url, param_name, params, payload, payload_type
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Move to next parameter
        
        return vulnerabilities
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                              url: str, param: str, original_params: Dict,
                              payload: str, payload_type: str) -> Optional[Vulnerability]:
        # Create test params
        test_params = original_params.copy()
        test_params[param] = payload
        
        try:
            start_time = asyncio.get_event_loop().time()
            
            async with session.get(url, params=test_params, timeout=aiohttp.ClientTimeout(total=10)) as response:
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
        except Exception as e:
            pass
        
        return None

# ============================================
# XSS SCANNER
# ============================================

class XSSScanner:
    PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
    ]
    
    async def scan(self, session: aiohttp.ClientSession, url: str,
                   params: Dict[str, str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        for param_name in params:
            for payload in self.PAYLOADS:
                vuln = await self._test_reflection(session, url, param_name, params, payload)
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
                    return Vulnerability(
                        vuln_type="Cross-Site Scripting (Reflected)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Payload reflected in response without encoding",
                        description="XSS vulnerability - user input is reflected in the page without proper encoding",
                        cwe_id="CWE-79",
                        cvss_score=6.1
                    )
                    
        except Exception as e:
            pass
        
        return None

# ============================================
# SECURITY HEADERS SCANNER
# ============================================

class HeadersScanner:
    SECURITY_HEADERS = {
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "Missing X-Frame-Options header - vulnerable to clickjacking"
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "description": "Missing X-Content-Type-Options header - vulnerable to MIME sniffing"
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "Missing Content-Security-Policy header - reduced XSS protection"
        },
        "Strict-Transport-Security": {
            "severity": Severity.MEDIUM,
            "description": "Missing HSTS header - vulnerable to SSL stripping attacks"
        },
        "X-XSS-Protection": {
            "severity": Severity.LOW,
            "description": "Missing X-XSS-Protection header (legacy browser protection)"
        },
    }
    
    async def scan(self, session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
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
                            cwe_id="CWE-693",
                            cvss_score=4.0
                        ))
        except Exception as e:
            pass
        
        return vulnerabilities

# ============================================
# MAIN SCANNER ORCHESTRATOR
# ============================================

class VulnFlowScanner:
    def __init__(self, target_url: str, max_depth: int = 2, max_pages: int = 50):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.vulnerabilities: List[Vulnerability] = []
        
    async def run_scan(self) -> Dict:
        print(f"\n{'='*60}")
        print(f"  VulnFlow Security Scanner")
        print(f"  Target: {self.target_url}")
        print(f"{'='*60}\n")
        
        # Phase 1: Crawl
        print("[Phase 1/4] Crawling target website...")
        crawler = AsyncWebCrawler(self.target_url, self.max_depth, self.max_pages)
        crawl_results = await crawler.crawl()
        print(f"  ✓ Found {len(crawl_results['urls'])} URLs")
        print(f"  ✓ Found {len(crawl_results['forms'])} forms")
        
        # Phase 2: Prepare targets
        print("\n[Phase 2/4] Analyzing attack surface...")
        targets = self._prepare_targets(crawl_results)
        print(f"  ✓ Identified {len(targets)} testable endpoints")
        
        # Phase 3: Scan for vulnerabilities
        print("\n[Phase 3/4] Scanning for vulnerabilities...")
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Initialize scanners
            sqli_scanner = SQLInjectionScanner()
            xss_scanner = XSSScanner()
            headers_scanner = HeadersScanner()
            
            # Scan headers on main page
            print("  → Checking security headers...")
            header_vulns = await headers_scanner.scan(session, self.target_url)
            self.vulnerabilities.extend(header_vulns)
            
            # Scan each target
            for i, target in enumerate(targets):
                print(f"  → Testing endpoint {i+1}/{len(targets)}: {target['url'][:50]}...")
                
                # SQL Injection
                sqli_vulns = await sqli_scanner.scan(session, target['url'], target['params'])
                self.vulnerabilities.extend(sqli_vulns)
                
                # XSS
                xss_vulns = await xss_scanner.scan(session, target['url'], target['params'])
                self.vulnerabilities.extend(xss_vulns)
        
        # Phase 4: Generate report
        print("\n[Phase 4/4] Generating report...")
        
        results = {
            "target": self.target_url,
            "scan_time": datetime.now().isoformat(),
            "pages_crawled": len(crawl_results['urls']),
            "forms_found": len(crawl_results['forms']),
            "vulnerabilities": self.vulnerabilities,
            "summary": self._generate_summary()
        }
        
        return results
    
    def _prepare_targets(self, crawl_results: Dict) -> List[Dict]:
        targets = []
        
        # From forms
        for form in crawl_results.get("forms", []):
            if form["inputs"]:
                params = {}
                for inp in form["inputs"]:
                    if inp["name"]:
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
    
    def _generate_summary(self) -> Dict:
        summary = {
            "total": len(self.vulnerabilities),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value
            if severity in summary:
                summary[severity] += 1
        
        return summary

# ============================================
# REPORT PRINTER
# ============================================

def print_report(results: Dict):
    """Print a formatted report to console"""
    print(f"\n{'='*60}")
    print(f"  SCAN RESULTS")
    print(f"{'='*60}")
    
    summary = results["summary"]
    print(f"\n📊 Summary:")
    print(f"   Target: {results['target']}")
    print(f"   Scan Time: {results['scan_time']}")
    print(f"   Pages Crawled: {results['pages_crawled']}")
    print(f"   Forms Found: {results['forms_found']}")
    print(f"\n   Vulnerabilities Found: {summary['total']}")
    print(f"   ├── 🔴 Critical: {summary['critical']}")
    print(f"   ├── 🟠 High: {summary['high']}")
    print(f"   ├── 🟡 Medium: {summary['medium']}")
    print(f"   ├── 🔵 Low: {summary['low']}")
    print(f"   └── ⚪ Info: {summary['info']}")
    
    if results["vulnerabilities"]:
        print(f"\n{'─'*60}")
        print(f"  VULNERABILITY DETAILS")
        print(f"{'─'*60}")
        
        for i, vuln in enumerate(results["vulnerabilities"], 1):
            severity_icons = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }
            icon = severity_icons.get(vuln.severity.value, "⚪")
            
            print(f"\n[{i}] {icon} {vuln.vuln_type}")
            print(f"    Severity: {vuln.severity.value.upper()}")
            print(f"    URL: {vuln.url}")
            if vuln.parameter:
                print(f"    Parameter: {vuln.parameter}")
            if vuln.payload:
                print(f"    Payload: {vuln.payload[:50]}...")
            print(f"    Evidence: {vuln.evidence[:80]}...")
            if vuln.cwe_id:
                print(f"    CWE: {vuln.cwe_id}")
            print(f"    Description: {vuln.description}")
    else:
        print(f"\n✅ No vulnerabilities found!")
    
    print(f"\n{'='*60}")

def save_json_report(results: Dict, filename: str):
    """Save results to JSON file"""
    # Convert vulnerabilities to serializable format
    output = {
        "target": results["target"],
        "scan_time": results["scan_time"],
        "pages_crawled": results["pages_crawled"],
        "forms_found": results["forms_found"],
        "summary": results["summary"],
        "vulnerabilities": [
            {
                "type": v.vuln_type,
                "severity": v.severity.value,
                "url": v.url,
                "parameter": v.parameter,
                "payload": v.payload,
                "evidence": v.evidence,
                "description": v.description,
                "cwe_id": v.cwe_id,
                "cvss_score": v.cvss_score
            }
            for v in results["vulnerabilities"]
        ]
    }
    
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n📄 Report saved to: {filename}")

# ============================================
# MAIN ENTRY POINT
# ============================================

async def main():
    parser = argparse.ArgumentParser(
        description="VulnFlow - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_scan.py http://testphp.vulnweb.com
  python run_scan.py http://localhost:5000 --depth 3 --max-pages 100
  python run_scan.py http://example.com --output report.json
        """
    )
    
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("--depth", "-d", type=int, default=2, 
                        help="Maximum crawl depth (default: 2)")
    parser.add_argument("--max-pages", "-m", type=int, default=50,
                        help="Maximum pages to crawl (default: 50)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output JSON file (optional)")
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'http://' + args.target
    
    # Run scanner
    scanner = VulnFlowScanner(args.target, args.depth, args.max_pages)
    results = await scanner.run_scan()
    
    # Print report
    print_report(results)
    
    # Save JSON if requested
    if args.output:
        save_json_report(results, args.output)
    
    # Return exit code based on findings
    if results["summary"]["critical"] > 0:
        return 2
    elif results["summary"]["high"] > 0:
        return 1
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)