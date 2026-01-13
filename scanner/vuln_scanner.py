# websec/scanner/vuln_scanner.py
"""Main vulnerability scanner orchestrator"""

from typing import List, Dict
from urllib.parse import urlparse, parse_qs
import aiohttp

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory

# Import all scanner modules
from .injection.sqli import SQLInjectionScanner
from .injection.nosqli import NoSQLInjectionScanner
from .injection.cmdi import CommandInjectionScanner
from .injection.ssti import SSTIScanner

from .access_control.idor import IDORScanner
from .access_control.path_traversal import PathTraversalScanner
from .access_control.forced_browsing import ForcedBrowsingScanner

from .misconfig.headers import SecurityHeadersScanner
from .misconfig.cors import CORSScanner
from .misconfig.debug import DebugModeScanner
from .misconfig.backup import BackupFileScanner

from .ssrf.ssrf import SSRFScanner

from .xss.xss import XSSScanner


class VulnerabilityScanner:
    """Main scanner orchestrator that coordinates all vulnerability scanners"""
    
    def __init__(self, scan_config: Dict = None):
        """
        Initialize the scanner with optional configuration.
        
        Args:
            scan_config: Dictionary with scanner configuration
                - enabled_scanners: List of scanner names to enable
                - disabled_scanners: List of scanner names to disable
                - scan_depth: How thorough the scan should be ('quick', 'normal', 'deep')
        """
        self.config = scan_config or {}
        self.scan_depth = self.config.get('scan_depth', 'normal')
        
        # Initialize all available scanners
        self.all_scanners = {
            # A01: Broken Access Control
            'idor': IDORScanner(),
            'path_traversal': PathTraversalScanner(),
            'forced_browsing': ForcedBrowsingScanner(),
            
            # A03: Injection
            'sqli': SQLInjectionScanner(),
            'nosqli': NoSQLInjectionScanner(),
            'cmdi': CommandInjectionScanner(),
            'ssti': SSTIScanner(),
            'xss': XSSScanner(),
            
            # A05: Security Misconfiguration
            'headers': SecurityHeadersScanner(),
            'cors': CORSScanner(),
            'debug': DebugModeScanner(),
            'backup': BackupFileScanner(),
            
            # A10: SSRF
            'ssrf': SSRFScanner(),
        }
        
        # Select scanners based on config
        self.active_scanners = self._select_scanners()
    
    def _select_scanners(self) -> List[BaseScanner]:
        """Select which scanners to run based on configuration"""
        enabled = self.config.get('enabled_scanners', [])
        disabled = self.config.get('disabled_scanners', [])
        
        if enabled:
            # Only run explicitly enabled scanners
            return [
                scanner for name, scanner in self.all_scanners.items()
                if name in enabled
            ]
        elif disabled:
            # Run all except disabled
            return [
                scanner for name, scanner in self.all_scanners.items()
                if name not in disabled
            ]
        else:
            # Run all scanners
            return list(self.all_scanners.values())
    
    async def scan_target(self, crawl_results: Dict) -> List[Vulnerability]:
        """
        Scan all discovered targets for vulnerabilities.
        
        Args:
            crawl_results: Results from the crawler containing URLs and forms
            
        Returns:
            List of discovered vulnerabilities
        """
        all_vulnerabilities = []
        
        # Prepare targets
        targets = self._prepare_targets(crawl_results)
        
        # Create HTTP session
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Get base URL for site-wide scans
            base_url = self._get_base_url(crawl_results)
            
            # Run site-wide scanners first (headers, forced browsing, etc.)
            site_vulns = await self._run_site_scanners(session, base_url)
            all_vulnerabilities.extend(site_vulns)
            
            # Run parameter-based scanners on each target
            for target in targets:
                param_vulns = await self._run_param_scanners(
                    session, target['url'], target['params']
                )
                all_vulnerabilities.extend(param_vulns)
        
        # Deduplicate vulnerabilities
        unique_vulns = self._deduplicate(all_vulnerabilities)
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        return unique_vulns
    
    async def _run_site_scanners(self, session: aiohttp.ClientSession,
                                  base_url: str) -> List[Vulnerability]:
        """Run scanners that check site-wide issues"""
        vulnerabilities = []
        
        site_scanner_names = ['headers', 'cors', 'debug', 'backup', 'forced_browsing']
        
        for name in site_scanner_names:
            if name in self.all_scanners:
                scanner = self.all_scanners[name]
                if scanner in self.active_scanners:
                    try:
                        vulns = await scanner.scan(session, base_url)
                        vulnerabilities.extend(vulns)
                    except Exception as e:
                        print(f"    [!] Error in {scanner.name}: {e}")
        
        return vulnerabilities
    
    async def _run_param_scanners(self, session: aiohttp.ClientSession,
                                   url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Run scanners that test parameters"""
        vulnerabilities = []
        
        param_scanner_names = [
            'sqli', 'nosqli', 'xss', 'cmdi', 'ssti',
            'idor', 'path_traversal', 'ssrf'
        ]
        
        for name in param_scanner_names:
            if name in self.all_scanners:
                scanner = self.all_scanners[name]
                if scanner in self.active_scanners:
                    try:
                        vulns = await scanner.scan(session, url, params)
                        vulnerabilities.extend(vulns)
                    except Exception as e:
                        print(f"    [!] Error in {scanner.name}: {e}")
        
        return vulnerabilities
    
    def _prepare_targets(self, crawl_results: Dict) -> List[Dict]:
        """Prepare scan targets from crawl results"""
        targets = []
        seen = set()
        
        # From forms
        for form in crawl_results.get("forms", []):
            if form.get("inputs"):
                params = {}
                for inp in form["inputs"]:
                    if inp.get("name"):
                        params[inp["name"]] = inp.get("value", "test")
                
                if params:
                    key = (form["action"], frozenset(params.keys()))
                    if key not in seen:
                        seen.add(key)
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
                
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                key = (base_url, frozenset(params.keys()))
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        "url": base_url,
                        "method": "GET",
                        "params": params
                    })
        
        return targets
    
    def _get_base_url(self, crawl_results: Dict) -> str:
        """Get base URL from crawl results"""
        urls = list(crawl_results.get("urls", {}).keys())
        if urls:
            parsed = urlparse(urls[0])
            return f"{parsed.scheme}://{parsed.netloc}"
        return ""
    
    def _deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create a key based on type, URL, and parameter
            key = (vuln.vuln_type, vuln.url, vuln.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def get_scanner_info(self) -> Dict:
        """Get information about available scanners"""
        return {
            name: {
                "name": scanner.name,
                "description": scanner.description,
                "owasp_category": scanner.owasp_category.value,
                "active": scanner in self.active_scanners
            }
            for name, scanner in self.all_scanners.items()
        }