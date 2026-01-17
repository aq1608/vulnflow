# scanner/vuln_scanner.py
"""Main vulnerability scanner orchestrator with parallel execution"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs
import asyncio
import aiohttp

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory
from .parallel_executor import ParallelScanExecutor, ScanWorkerPool

# Injection scanners
from .injection.sqli import SQLInjectionScanner
from .injection.nosqli import NoSQLInjectionScanner
from .injection.cmdi import CommandInjectionScanner
from .injection.ssti import SSTIScanner
from .injection.ldapi import LDAPInjectionScanner
from .injection.xpath import XPathInjectionScanner
from .injection.hhi import HostHeaderInjectionScanner

# XSS scanners
from .xss.xss import XSSScanner
from .xss.dom_xss import DOMXSSScanner

# Access control scanners
from .access_control.idor import IDORScanner
from .access_control.path_traversal import PathTraversalScanner
from .access_control.forced_browsing import ForcedBrowsingScanner
from .access_control.privilege_escalation import PrivilegeEscalationScanner
from .access_control.jwt_vulnerabilities import JWTVulnerabilitiesScanner

# Misconfiguration scanners
from .misconfig.headers import SecurityHeadersScanner
from .misconfig.cors import CORSScanner
from .misconfig.debug import DebugModeScanner
from .misconfig.backup import BackupFileScanner
from .misconfig.ssl_tls import SSLTLSScanner
from .misconfig.cookie_security import CookieSecurityScanner
from .misconfig.information_disclosure import InformationDisclosureScanner

# SSRF scanner
from .ssrf.ssrf import SSRFScanner

# XXE scanner
from .xxe.xxe import XXEScanner

# Deserialization scanner
from .deserialization.insecure_deserialization import InsecureDeserializationScanner

# API security scanners
from .api_security.rate_limiting import RateLimitingScanner
from .api_security.mass_assignment import MassAssignmentScanner
from .api_security.graphql import GraphQLScanner

# Authentication scanners
from .authentication.brute_force import BruteForceScanner
from .authentication.session_fixation import SessionFixationScanner
from .authentication.weak_password import WeakPasswordPolicyScanner

# Cryptographic scanners
from .cryptographic.weak_crypto import WeakCryptoScanner
from .cryptographic.sensitive_data_exposure import SensitiveDataExposureScanner

# CVE scanner
from .cve.known_cve import KnownCVEScanner


class VulnerabilityScanner:
    """Main scanner orchestrator that coordinates all vulnerability scanners with parallel execution"""
    
    def __init__(self, scan_config: Dict = None):
        """
        Initialize the scanner with optional configuration.
        
        Args:
            scan_config: Dictionary with scanner configuration
                - enabled_scanners: List of scanner names to enable
                - disabled_scanners: List of scanner names to disable
                - scan_depth: How thorough the scan should be ('quick', 'normal', 'deep')
                - parallel: Enable parallel scanning (default: True)
                - max_concurrent_scanners: Max parallel scanners per target (default: 5)
                - max_concurrent_targets: Max parallel targets (default: 10)
                - requests_per_second: Rate limit (default: 50)
                - timeout: Timeout per scan in seconds (default: 30)
        """
        self.config = scan_config or {}
        self.scan_depth = self.config.get('scan_depth', 'normal')
        self.parallel_enabled = self.config.get('parallel', True)
        
        # Parallel execution settings
        self.max_concurrent_scanners = self.config.get('max_concurrent_scanners', 5)
        self.max_concurrent_targets = self.config.get('max_concurrent_targets', 10)
        self.requests_per_second = self.config.get('requests_per_second', 50)
        self.timeout = self.config.get('timeout', 30)
        
        # Progress callback
        self._progress_callback = None
        
        # Initialize all available scanners
        self.all_scanners = {
            # ==========================================
            # A01:2021 - Broken Access Control
            # ==========================================
            'idor': IDORScanner(),
            'path_traversal': PathTraversalScanner(),
            'forced_browsing': ForcedBrowsingScanner(),
            'privilege_escalation': PrivilegeEscalationScanner(),
            'jwt': JWTVulnerabilitiesScanner(),
            
            # ==========================================
            # A02:2021 - Cryptographic Failures
            # ==========================================
            'ssl_tls': SSLTLSScanner(),
            'weak_crypto': WeakCryptoScanner(),
            'sensitive_data': SensitiveDataExposureScanner(),
            
            # ==========================================
            # A03:2021 - Injection
            # ==========================================
            'sqli': SQLInjectionScanner(),
            'nosqli': NoSQLInjectionScanner(),
            'cmdi': CommandInjectionScanner(),
            'ssti': SSTIScanner(),
            'xss': XSSScanner(),
            'dom_xss': DOMXSSScanner(),
            'ldapi': LDAPInjectionScanner(),
            'xpath': XPathInjectionScanner(),
            'hhi': HostHeaderInjectionScanner(),
            
            # ==========================================
            # A04:2021 - Insecure Design
            # ==========================================
            'rate_limiting': RateLimitingScanner(),
            'brute_force': BruteForceScanner(),
            
            # ==========================================
            # A05:2021 - Security Misconfiguration
            # ==========================================
            'headers': SecurityHeadersScanner(),
            'cors': CORSScanner(),
            'debug': DebugModeScanner(),
            'backup': BackupFileScanner(),
            'cookie_security': CookieSecurityScanner(),
            'info_disclosure': InformationDisclosureScanner(),
            
            # ==========================================
            # A06:2021 - Vulnerable Components
            # ==========================================
            'known_cve': KnownCVEScanner(),
            
            # ==========================================
            # A07:2021 - Auth Failures
            # ==========================================
            'session_fixation': SessionFixationScanner(),
            'weak_password': WeakPasswordPolicyScanner(),
            
            # ==========================================
            # A08:2021 - Software/Data Integrity
            # ==========================================
            'deserialization': InsecureDeserializationScanner(),
            
            # ==========================================
            # A09:2021 - Logging/Monitoring
            # ==========================================
            # (Typically requires access to server logs)
            
            # ==========================================
            # A10:2021 - SSRF
            # ==========================================
            'ssrf': SSRFScanner(),
            
            # ==========================================
            # Additional Scanners
            # ==========================================
            'xxe': XXEScanner(),
            'graphql': GraphQLScanner(),
            'mass_assignment': MassAssignmentScanner(),
        }
        
        # Categorize scanners
        self.site_scanner_names = [
            'headers', 'cors', 'debug', 'backup', 'forced_browsing',
            'ssl_tls', 'cookie_security', 'info_disclosure', 'rate_limiting',
            'graphql', 'known_cve'
        ]
        
        self.param_scanner_names = [
            'sqli', 'nosqli', 'xss', 'dom_xss', 'cmdi', 'ssti',
            'ldapi', 'xpath', 'hhi',
            'idor', 'path_traversal', 'ssrf', 'xxe',
            'deserialization', 'mass_assignment',
            'jwt', 'session_fixation',
            'weak_crypto', 'sensitive_data'
        ]
        
        # Scan mode presets
        self.scan_modes = {
            'quick': [
                'sqli', 'xss', 'headers', 'cors', 'ssl_tls'
            ],
            'standard': [
                'sqli', 'nosqli', 'xss', 'cmdi', 'ssti',
                'headers', 'cors', 'debug', 'backup',
                'idor', 'path_traversal', 'ssrf', 'ssl_tls'
            ],
            'owasp': [
                # All OWASP Top 10 related scanners
                'sqli', 'nosqli', 'xss', 'cmdi', 'ssti', 'xxe',
                'idor', 'path_traversal', 'forced_browsing', 'jwt',
                'ssl_tls', 'weak_crypto', 'sensitive_data',
                'headers', 'cors', 'debug', 'backup', 'cookie_security',
                'rate_limiting', 'session_fixation', 'deserialization',
                'ssrf', 'known_cve'
            ],
            'full': list(self.all_scanners.keys()),
            'api': [
                'sqli', 'nosqli', 'cmdi', 'ssrf', 'xxe',
                'idor', 'jwt', 'rate_limiting', 'cors',
                'mass_assignment', 'graphql', 'headers',
                'deserialization', 'info_disclosure'
            ],
            'injection': [
                'sqli', 'nosqli', 'xss', 'dom_xss', 'cmdi',
                'ssti', 'ldapi', 'xpath', 'hhi', 'xxe'
            ],
            'auth': [
                'jwt', 'session_fixation', 'brute_force',
                'weak_password', 'idor', 'privilege_escalation'
            ],
        }
        
        # Select scanners based on config
        self.active_scanners = self._select_scanners()
        
        # Initialize parallel executor
        self.executor = ParallelScanExecutor(
            max_concurrent_scanners=self.max_concurrent_scanners,
            max_concurrent_targets=self.max_concurrent_targets,
            max_requests_per_second=self.requests_per_second,
            timeout_per_scan=self.timeout
        )
    
    def set_progress_callback(self, callback):
        """Set progress callback: callback(completed, total, message)"""
        self._progress_callback = callback
        self.executor.set_progress_callback(callback)
    
    def _select_scanners(self) -> List[BaseScanner]:
        """Select which scanners to run based on configuration"""
        enabled = self.config.get('enabled_scanners', [])
        disabled = self.config.get('disabled_scanners', [])
        
        if enabled:
            return [
                scanner for name, scanner in self.all_scanners.items()
                if name in enabled
            ]
        elif disabled:
            return [
                scanner for name, scanner in self.all_scanners.items()
                if name not in disabled
            ]
        else:
            return list(self.all_scanners.values())
    
    def _get_active_site_scanners(self) -> List[tuple]:
        """Get active site-wide scanners as (name, scanner) tuples"""
        return [
            (name, self.all_scanners[name])
            for name in self.site_scanner_names
            if name in self.all_scanners and self.all_scanners[name] in self.active_scanners
        ]
    
    def _get_active_param_scanners(self) -> List[tuple]:
        """Get active parameter scanners as (name, scanner) tuples"""
        return [
            (name, self.all_scanners[name])
            for name in self.param_scanner_names
            if name in self.all_scanners and self.all_scanners[name] in self.active_scanners
        ]
    
    async def scan_target(self, crawl_results: Dict) -> List[Vulnerability]:
        """
        Scan all discovered targets for vulnerabilities using parallel execution.
        
        Args:
            crawl_results: Results from the crawler containing URLs and forms
            
        Returns:
            List of discovered vulnerabilities
        """
        # Prepare targets
        targets = self._prepare_targets(crawl_results)
        base_url = self._get_base_url(crawl_results)
        
        # Get active scanners
        site_scanners = self._get_active_site_scanners()
        param_scanners = self._get_active_param_scanners()
        
        # Create HTTP session with connection pooling
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self.max_concurrent_targets * 2,  # Allow headroom for concurrent requests
            limit_per_host=self.max_concurrent_targets,
            ttl_dns_cache=300
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout * 2)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            if self.parallel_enabled:
                # Use parallel executor
                all_vulnerabilities = await self.executor.execute_all_scans(
                    session,
                    targets,
                    site_scanners,
                    param_scanners,
                    base_url
                )
            else:
                # Fall back to sequential scanning
                all_vulnerabilities = await self._sequential_scan(
                    session, targets, site_scanners, param_scanners, base_url
                )
        
        # Deduplicate and sort vulnerabilities
        unique_vulns = self._deduplicate(all_vulnerabilities)
        
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        return unique_vulns
    
    async def scan_target_fast(self, crawl_results: Dict) -> List[Vulnerability]:
        """
        Fast scan using worker pool pattern for maximum parallelism.
        
        Args:
            crawl_results: Results from the crawler
            
        Returns:
            List of discovered vulnerabilities
        """
        targets = self._prepare_targets(crawl_results)
        base_url = self._get_base_url(crawl_results)
        
        site_scanners = self._get_active_site_scanners()
        param_scanners = self._get_active_param_scanners()
        
        # Build task list
        tasks = []
        
        # Site-wide scan tasks
        for name, scanner in site_scanners:
            tasks.append((scanner, base_url, {}, "site"))
        
        # Parameter scan tasks
        for target in targets:
            for name, scanner in param_scanners:
                tasks.append((scanner, target['url'], target['params'], "param"))
        
        # Create connection pool
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self.max_concurrent_targets * 3,
            limit_per_host=self.max_concurrent_targets
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout * 2)
        
        # Run with worker pool
        worker_pool = ScanWorkerPool(num_workers=self.max_concurrent_scanners)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            all_vulnerabilities = await worker_pool.run(session, tasks)
        
        # Deduplicate and sort
        unique_vulns = self._deduplicate(all_vulnerabilities)
        
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        return unique_vulns
    
    async def _sequential_scan(
        self,
        session: aiohttp.ClientSession,
        targets: List[Dict],
        site_scanners: List[tuple],
        param_scanners: List[tuple],
        base_url: str
    ) -> List[Vulnerability]:
        """Fallback sequential scanning (original behavior)"""
        all_vulnerabilities = []
        
        # Site-wide scans
        for name, scanner in site_scanners:
            try:
                vulns = await scanner.scan(session, base_url)
                all_vulnerabilities.extend(vulns)
            except Exception as e:
                print(f"    [!] Error in {name}: {e}")
        
        # Parameter scans
        for target in targets:
            for name, scanner in param_scanners:
                try:
                    vulns = await scanner.scan(session, target['url'], target['params'])
                    all_vulnerabilities.extend(vulns)
                except Exception as e:
                    print(f"    [!] Error in {name}: {e}")
        
        return all_vulnerabilities
    
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
    
    def get_execution_stats(self) -> Dict:
        """Get execution statistics from the parallel executor"""
        return self.executor.stats
    
    def shutdown(self):
        """Clean up resources"""
        self.executor.shutdown()