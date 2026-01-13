# websec/scanner/fast_scanner.py
"""
High-performance vulnerability scanner with optimized concurrency
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
import time
from concurrent.futures import ProcessPoolExecutor
import multiprocessing

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory


@dataclass
class ScanConfig:
    """Scanner configuration"""
    max_concurrent_requests: int = 20          # Max simultaneous requests
    request_timeout: int = 10                   # Timeout per request (seconds)
    max_retries: int = 2                        # Retry failed requests
    delay_between_requests: float = 0.05        # Rate limiting (seconds)
    quick_mode: bool = False                    # Use reduced payload sets
    smart_scan: bool = True                     # Skip unlikely vulnerabilities
    max_payloads_per_param: int = 10            # Limit payloads in quick mode
    batch_size: int = 10                        # Requests per batch


class RateLimiter:
    """Simple rate limiter for requests"""
    
    def __init__(self, requests_per_second: float = 20):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            time_passed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + time_passed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class ResponseCache:
    """Cache for HTTP responses to avoid duplicate requests"""
    
    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, Tuple[int, str, float]] = {}  # url -> (status, body_hash, timestamp)
        self.max_size = max_size
    
    def _make_key(self, url: str, params: Dict) -> str:
        param_str = "&".join(f"{k}={v}" for k, v in sorted(params.items())) if params else ""
        return f"{url}?{param_str}"
    
    def get(self, url: str, params: Dict = None) -> Optional[Tuple[int, str]]:
        key = self._make_key(url, params or {})
        if key in self.cache:
            status, body_hash, _ = self.cache[key]
            return status, body_hash
        return None
    
    def set(self, url: str, params: Dict, status: int, body: str):
        if len(self.cache) >= self.max_size:
            # Remove oldest entries
            oldest = sorted(self.cache.items(), key=lambda x: x[1][2])[:100]
            for key, _ in oldest:
                del self.cache[key]
        
        key = self._make_key(url, params or {})
        self.cache[key] = (status, hash(body), time.time())


class FastVulnerabilityScanner:
    """High-performance vulnerability scanner"""
    
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self.rate_limiter = RateLimiter(1 / self.config.delay_between_requests)
        self.cache = ResponseCache()
        self.semaphore = None  # Will be created in scan
        self.vulnerabilities: List[Vulnerability] = []
        self._vuln_lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            'requests_made': 0,
            'cache_hits': 0,
            'errors': 0,
            'start_time': 0,
            'end_time': 0
        }
    
    async def scan_target(self, crawl_results: Dict, 
                          progress_callback=None) -> List[Vulnerability]:
        """
        Scan all discovered targets with optimized concurrency.
        
        Args:
            crawl_results: Results from crawler
            progress_callback: Optional callback for progress updates
        """
        self.stats['start_time'] = time.time()
        self.vulnerabilities = []
        
        # Create semaphore for concurrent request limiting
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        
        # Prepare targets
        targets = self._prepare_targets(crawl_results)
        base_url = self._get_base_url(crawl_results)
        
        total_tasks = len(targets) + 1  # +1 for site-wide scans
        completed = 0
        
        # Create optimized HTTP session
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent_requests,
            limit_per_host=self.config.max_concurrent_requests,
            ssl=False,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # 1. Run site-wide scans (headers, forced browsing, etc.)
            if progress_callback:
                progress_callback(0, total_tasks, "Running site-wide scans...")
            
            site_vulns = await self._run_site_scans_fast(session, base_url)
            self.vulnerabilities.extend(site_vulns)
            completed += 1
            
            # 2. Run parameter-based scans concurrently
            if progress_callback:
                progress_callback(completed, total_tasks, "Scanning parameters...")
            
            # Process targets in batches
            batch_size = self.config.batch_size
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i + batch_size]
                
                tasks = [
                    self._scan_target_fast(session, target)
                    for target in batch
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, list):
                        self.vulnerabilities.extend(result)
                    elif isinstance(result, Exception):
                        self.stats['errors'] += 1
                
                completed += len(batch)
                if progress_callback:
                    progress_callback(completed, total_tasks, f"Scanned {completed}/{len(targets)} targets")
        
        self.stats['end_time'] = time.time()
        
        # Deduplicate
        unique_vulns = self._deduplicate(self.vulnerabilities)
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4
        }
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        return unique_vulns
    
    async def _run_site_scans_fast(self, session: aiohttp.ClientSession,
                                    base_url: str) -> List[Vulnerability]:
        """Run site-wide scans concurrently"""
        vulnerabilities = []
        
        # Import scanners
        from .misconfig.headers import SecurityHeadersScanner
        from .misconfig.cors import CORSScanner
        from .misconfig.debug import DebugModeScanner
        from .misconfig.backup import BackupFileScanner
        from .access_control.forced_browsing import ForcedBrowsingScanner
        
        scanners = [
            SecurityHeadersScanner(),
            CORSScanner(),
            DebugModeScanner(),
        ]
        
        # Add slower scanners only if not in quick mode
        if not self.config.quick_mode:
            scanners.extend([
                BackupFileScanner(),
                ForcedBrowsingScanner(),
            ])
        
        # Run all site scanners concurrently
        tasks = [
            self._run_scanner_safe(scanner, session, base_url, {})
            for scanner in scanners
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
        
        return vulnerabilities
    
    async def _scan_target_fast(self, session: aiohttp.ClientSession,
                                 target: Dict) -> List[Vulnerability]:
        """Scan a single target with all relevant scanners"""
        vulnerabilities = []
        url = target['url']
        params = target['params']
        
        # Import scanners
        from .injection.sqli import SQLInjectionScanner
        from .injection.cmdi import CommandInjectionScanner
        from .injection.ssti import SSTIScanner
        from .xss.xss import XSSScanner
        from .ssrf.ssrf import SSRFScanner
        from .access_control.idor import IDORScanner
        from .access_control.path_traversal import PathTraversalScanner
        
        # Smart scan: Choose scanners based on parameter names
        scanners = []
        
        if self.config.smart_scan:
            scanners = self._select_smart_scanners(params)
        else:
            scanners = [
                SQLInjectionScanner(),
                XSSScanner(),
                CommandInjectionScanner(),
                SSTIScanner(),
                SSRFScanner(),
                IDORScanner(),
                PathTraversalScanner(),
            ]
        
        # Apply quick mode optimizations to scanners
        if self.config.quick_mode:
            for scanner in scanners:
                self._apply_quick_mode(scanner)
        
        # Run all scanners concurrently for this target
        tasks = [
            self._run_scanner_safe(scanner, session, url, params)
            for scanner in scanners
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
        
        return vulnerabilities
    
    async def _run_scanner_safe(self, scanner: BaseScanner,
                                 session: aiohttp.ClientSession,
                                 url: str, params: Dict) -> List[Vulnerability]:
        """Run a scanner with error handling and rate limiting"""
        try:
            async with self.semaphore:
                await self.rate_limiter.acquire()
                self.stats['requests_made'] += 1
                return await scanner.scan(session, url, params)
        except asyncio.TimeoutError:
            self.stats['errors'] += 1
            return []
        except Exception as e:
            self.stats['errors'] += 1
            return []
    
    def _select_smart_scanners(self, params: Dict) -> List[BaseScanner]:
        """Select scanners based on parameter names"""
        from .injection.sqli import SQLInjectionScanner
        from .injection.cmdi import CommandInjectionScanner
        from .injection.ssti import SSTIScanner
        from .xss.xss import XSSScanner
        from .ssrf.ssrf import SSRFScanner
        from .access_control.idor import IDORScanner
        from .access_control.path_traversal import PathTraversalScanner
        
        scanners = set()
        
        # Always include these basic scanners
        scanners.add(SQLInjectionScanner)
        scanners.add(XSSScanner)
        
        param_names_lower = [p.lower() for p in params.keys()]
        param_values = list(params.values())
        
        # Check for ID-like parameters -> IDOR
        id_patterns = ['id', 'uid', 'user_id', 'userid', 'account', 'order', 'doc']
        if any(pattern in name for name in param_names_lower for pattern in id_patterns):
            scanners.add(IDORScanner)
        
        # Check for file-like parameters -> Path Traversal
        file_patterns = ['file', 'path', 'page', 'document', 'template', 'include']
        if any(pattern in name for name in param_names_lower for pattern in file_patterns):
            scanners.add(PathTraversalScanner)
        
        # Check for URL-like parameters -> SSRF
        url_patterns = ['url', 'uri', 'link', 'src', 'source', 'redirect', 'callback']
        if any(pattern in name for name in param_names_lower for pattern in url_patterns):
            scanners.add(SSRFScanner)
        
        # Check for URL values -> SSRF
        if any(v.startswith(('http://', 'https://')) for v in param_values):
            scanners.add(SSRFScanner)
        
        # Check for command-like parameters -> Command Injection
        cmd_patterns = ['cmd', 'exec', 'command', 'ping', 'host', 'ip']
        if any(pattern in name for name in param_names_lower for pattern in cmd_patterns):
            scanners.add(CommandInjectionScanner)
        
        # Check for template-like parameters -> SSTI
        template_patterns = ['template', 'name', 'message', 'title', 'content']
        if any(pattern in name for name in param_names_lower for pattern in template_patterns):
            scanners.add(SSTIScanner)
        
        return [cls() for cls in scanners]
    
    def _apply_quick_mode(self, scanner: BaseScanner):
        """Reduce payload count for quick mode"""
        max_payloads = self.config.max_payloads_per_param
        
        # Truncate payload lists
        if hasattr(scanner, 'PAYLOADS') and isinstance(scanner.PAYLOADS, list):
            scanner.PAYLOADS = scanner.PAYLOADS[:max_payloads]
        
        if hasattr(scanner, 'ERROR_BASED_PAYLOADS'):
            scanner.ERROR_BASED_PAYLOADS = scanner.ERROR_BASED_PAYLOADS[:max_payloads]
        
        if hasattr(scanner, 'BOOLEAN_BASED_PAYLOADS'):
            scanner.BOOLEAN_BASED_PAYLOADS = scanner.BOOLEAN_BASED_PAYLOADS[:5]
        
        if hasattr(scanner, 'TIME_BASED_PAYLOADS'):
            scanner.TIME_BASED_PAYLOADS = scanner.TIME_BASED_PAYLOADS[:3]
        
        if hasattr(scanner, 'BASIC_PAYLOADS'):
            scanner.BASIC_PAYLOADS = scanner.BASIC_PAYLOADS[:max_payloads]
    
    def _prepare_targets(self, crawl_results: Dict) -> List[Dict]:
        """Prepare scan targets from crawl results"""
        targets = []
        seen = set()
        
        # From forms
        for form in crawl_results.get("forms", []):
            if form.get("inputs"):
                params = {
                    inp["name"]: inp.get("value", "test")
                    for inp in form["inputs"]
                    if inp.get("name")
                }
                
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
                params = {
                    key: values[0] if values else ""
                    for key, values in parse_qs(parsed.query).items()
                }
                
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
    
    def get_stats(self) -> Dict:
        """Get scan statistics"""
        elapsed = self.stats['end_time'] - self.stats['start_time']
        return {
            'total_time': f"{elapsed:.2f}s",
            'requests_made': self.stats['requests_made'],
            'cache_hits': self.stats['cache_hits'],
            'errors': self.stats['errors'],
            'requests_per_second': self.stats['requests_made'] / elapsed if elapsed > 0 else 0,
            'vulnerabilities_found': len(self.vulnerabilities)
        }