"""
Enhanced Vulnerability Scanner with Groq AI Integration
Optimized for speed while maintaining low noise/false positives
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs
import asyncio
import aiohttp
import time

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory
from .parallel_executor import ParallelScanExecutor
from .ai.groq_analyzer import GroqAnalyzer, AIAnalysisResult

# Import all scanner modules (same as original)
from .injection.sqli import SQLInjectionScanner
from .injection.nosqli import NoSQLInjectionScanner
from .injection.cmdi import CommandInjectionScanner
from .injection.ssti import SSTIScanner
from .xss.xss import XSSScanner
from .access_control.idor import IDORScanner
from .access_control.path_traversal import PathTraversalScanner
from .access_control.jwt_vulnerabilities import JWTVulnerabilitiesScanner
from .misconfig.headers import SecurityHeadersScanner
from .misconfig.cors import CORSScanner
from .misconfig.ssl_tls import SSLTLSScanner
from .ssrf.ssrf import SSRFScanner
from .xxe.xxe import XXEScanner
from .deserialization.insecure_deserialization import InsecureDeserializationScanner
from .api_security.graphql import GraphQLScanner
from .api_security.rate_limiting import RateLimitingScanner


class EnhancedVulnerabilityScanner:
    """
    Enhanced vulnerability scanner with:
    1. Groq AI integration for smarter detection
    2. Optimized parallel execution
    3. Smart payload selection
    4. False positive reduction
    5. Automatic fallback to non-AI mode
    """
    
    def __init__(self, scan_config: Dict = None):
        """
        Initialize enhanced scanner.
        
        Args:
            scan_config: Configuration dict with options:
                - ai_enabled: Enable AI analysis (auto-detected from GROQ_API_KEY or api_key)
                - api_key: Groq API key (optional - overrides environment variable)
                - scan_depth: 'quick', 'normal', 'deep'
                - parallel: Enable parallel scanning (default: True)
                - max_concurrent_scanners: Default 8 (increased from 5)
                - max_concurrent_targets: Default 15 (increased from 10)
                - requests_per_second: Default 75 (increased from 50)
                - timeout: Default 20 (decreased from 30 for speed)
                - smart_payloads: Use AI-generated payloads (default: True)
                - confidence_threshold: Minimum confidence to report (default: 0.6)
        
        Examples:
            # Option 1: Use environment variable GROQ_API_KEY
            scanner = EnhancedVulnerabilityScanner()
            
            # Option 2: Provide API key directly in config
            config = {'api_key': 'gsk_your_api_key_here'}
            scanner = EnhancedVulnerabilityScanner(config)
            
            # Option 3: Full configuration with API key
            config = {
                'api_key': 'gsk_...',
                'mode': 'owasp',
                'confidence_threshold': 0.75,
                'max_concurrent_scanners': 10
            }
            scanner = EnhancedVulnerabilityScanner(config)
        """
        self.config = scan_config or {}
        self.scan_depth = self.config.get('scan_depth', 'normal')
        self.parallel_enabled = self.config.get('parallel', True)
        
        # Enhanced parallel execution settings (optimized for speed)
        self.max_concurrent_scanners = self.config.get('max_concurrent_scanners', 8)
        self.max_concurrent_targets = self.config.get('max_concurrent_targets', 15)
        self.requests_per_second = self.config.get('requests_per_second', 75)
        self.timeout = self.config.get('timeout', 20)  # Reduced for faster scans
        
        # AI settings
        self.smart_payloads = self.config.get('smart_payloads', True)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.6)
        
        # Initialize Groq analyzer with optional API key
        # Priority: config['api_key'] > environment variable > None
        api_key = self.config.get('api_key', None)
        self.ai_analyzer = GroqAnalyzer(api_key=api_key)
        
        # Progress callback
        self._progress_callback = None
        
        # Initialize all available scanners (same as original)
        self.all_scanners = {
            # A01:2021 - Broken Access Control
            'idor': IDORScanner(),
            'path_traversal': PathTraversalScanner(),
            'jwt': JWTVulnerabilitiesScanner(),
            
            # A02:2021 - Cryptographic Failures
            'ssl_tls': SSLTLSScanner(),
            
            # A03:2021 - Injection
            'sqli': SQLInjectionScanner(),
            'nosqli': NoSQLInjectionScanner(),
            'cmdi': CommandInjectionScanner(),
            'ssti': SSTIScanner(),
            'xxe': XXEScanner(),
            
            # A04:2021 - Insecure Design
            'ssrf': SSRFScanner(),
            
            # A05:2021 - Security Misconfiguration
            'headers': SecurityHeadersScanner(),
            'cors': CORSScanner(),
            
            # A06:2021 - Vulnerable Components
            # (handled by tech detection + CVE scanner)
            
            # A07:2021 - Identification and Authentication Failures
            # (JWT already covered above)
            
            # A08:2021 - Software and Data Integrity Failures
            'deserialization': InsecureDeserializationScanner(),
            
            # A09:2021 - Security Logging and Monitoring Failures
            # (passive detection)
            
            # A10:2021 - Server-Side Request Forgery
            # (SSRF already covered above)
            
            # API Security
            'graphql': GraphQLScanner(),
            'rate_limiting': RateLimitingScanner(),
            
            # Cross-Site Scripting (part of A03)
            'xss': XSSScanner(),
        }
        
        # Scan mode presets (optimized)
        self.scan_modes = {
            'quick': [
                'sqli', 'xss', 'headers', 'cors', 'ssl_tls'
            ],
            'standard': [
                'sqli', 'nosqli', 'xss', 'cmdi', 'ssti',
                'headers', 'cors', 'idor', 'path_traversal',
                'ssrf', 'ssl_tls', 'jwt'
            ],
            'owasp': [
                'sqli', 'nosqli', 'xss', 'cmdi', 'ssti', 'xxe',
                'idor', 'path_traversal', 'jwt', 'ssl_tls',
                'headers', 'cors', 'rate_limiting',
                'deserialization', 'ssrf', 'graphql'
            ],
            'full': list(self.all_scanners.keys()),
        }
        
        # Select active scanners
        self.active_scanners = self._select_scanners()
        
        # Initialize parallel executor with optimized settings
        self.executor = ParallelScanExecutor(
            max_concurrent_scanners=self.max_concurrent_scanners,
            max_concurrent_targets=self.max_concurrent_targets,
            max_requests_per_second=self.requests_per_second,
            timeout_per_scan=self.timeout
        )
        
        # Performance metrics
        self.metrics = {
            'ai_enhanced_findings': 0,
            'false_positives_filtered': 0,
            'smart_payloads_used': 0,
            'total_ai_calls': 0
        }
    
    def _select_scanners(self) -> Dict:
        """Select scanners based on configuration"""
        enabled = self.config.get('enabled_scanners')
        disabled = self.config.get('disabled_scanners', [])
        mode = self.config.get('mode', self.scan_depth)
        
        if enabled:
            return {k: v for k, v in self.all_scanners.items() if k in enabled}
        
        if mode in self.scan_modes:
            scanner_list = self.scan_modes[mode]
        else:
            scanner_list = self.scan_modes['standard']
        
        # Remove disabled scanners
        scanner_list = [s for s in scanner_list if s not in disabled]
        
        return {k: v for k, v in self.all_scanners.items() if k in scanner_list}
    
    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self._progress_callback = callback
        if self.executor:
            self.executor.set_progress_callback(callback)
    
    async def scan_async(
        self,
        crawl_results: Dict,
        tech_stack: List[str] = None
    ) -> List[Vulnerability]:
        """
        Main async scanning method with AI enhancement.
        
        Args:
            crawl_results: Results from crawler
            tech_stack: Detected technologies
        
        Returns:
            List of validated vulnerabilities
        """
        print(f"\n{'='*60}")
        print(f"  Enhanced VulnFlow Scanner (AI: {self.ai_analyzer.mode.value})")
        print(f"  Active Scanners: {len(self.active_scanners)}")
        print(f"  Parallel Workers: {self.max_concurrent_scanners}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        # Validate crawl results
        if not crawl_results:
            print("❌ Error: No crawl results provided")
            return []
        
        # Ensure required keys exist
        if 'urls' not in crawl_results:
            crawl_results['urls'] = []
        if 'forms' not in crawl_results:
            crawl_results['forms'] = []
        
        # Check if we have anything to scan
        urls_count = len(crawl_results.get('urls', []))
        forms_count = len(crawl_results.get('forms', []))
        
        if urls_count == 0 and forms_count == 0:
            print("⚠️  Warning: No URLs or forms found to scan")
            print("    The crawler may not have found any content.")
            print("    Check your target URL and try again.")
            return []
        
        print(f"[*] Crawl results: {urls_count} URLs, {forms_count} forms")
        
        # Auto-detect tech stack if not provided
        if not tech_stack or len(tech_stack) == 0:
            print(f"\n[*] Auto-detecting tech stack...")
            tech_stack = await self._detect_tech_stack(crawl_results)
            if tech_stack:
                print(f"  ✓ Detected: {', '.join(tech_stack)}")
            else:
                # Fallback to common stack
                tech_stack = ['PHP', 'MySQL', 'Apache']
                print(f"  ⚠️  Could not detect - using default: {', '.join(tech_stack)}")
        
        # Generate smart payloads if AI is enabled
        if self.smart_payloads and tech_stack:
            await self._generate_contextual_payloads(tech_stack)
        
        # Prepare targets
        targets = self._prepare_targets(crawl_results)
        
        if not targets:
            print("⚠️  Warning: No valid targets prepared for scanning")
            return []
        
        base_url = self._get_base_url(crawl_results)
        
        print(f"[*] Prepared {len(targets)} targets for scanning")
        
        # Get active scanners
        site_scanners = self._get_active_site_scanners()
        param_scanners = self._get_active_param_scanners()
        
        # Create optimized HTTP session
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self.max_concurrent_targets * 3,  # Increased pool
            limit_per_host=self.max_concurrent_targets,
            ttl_dns_cache=300,
            force_close=False,  # Reuse connections
            enable_cleanup_closed=True
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'VulnFlow-Enhanced/2.0'}
        ) as session:
            # Execute parallel scans
            # Convert dicts to lists of tuples for executor
            site_scanners_list = list(site_scanners.items())
            param_scanners_list = list(param_scanners.items())
            
            raw_vulnerabilities = await self.executor.execute_all_scans(
                session,
                targets,
                site_scanners_list,
                param_scanners_list,
                base_url
            )
            
            print(f"\n[*] Initial scan found {len(raw_vulnerabilities)} potential issues")
            
            # AI-enhanced validation and filtering
            validated_vulns = await self._ai_validate_vulnerabilities(
                raw_vulnerabilities,
                session,
                tech_stack or []
            )
        
        # Deduplicate
        unique_vulns = self._deduplicate(validated_vulns)
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"  Scan Complete in {elapsed:.2f}s")
        print(f"  Validated Vulnerabilities: {len(unique_vulns)}")
        print(f"  AI Enhanced: {self.metrics['ai_enhanced_findings']}")
        print(f"  False Positives Filtered: {self.metrics['false_positives_filtered']}")
        print(f"{'='*60}\n")
        
        return unique_vulns
    
    async def _detect_tech_stack(self, crawl_results: Dict) -> List[str]:
        """
        Auto-detect technology stack from crawl results
        
        Args:
            crawl_results: Results from crawler
            
        Returns:
            List of detected technologies
        """
        tech_stack = []
        
        # Get first URL to test
        urls_data = crawl_results.get('urls', {})
        test_url = None
        
        if isinstance(urls_data, dict):
            url_keys = list(urls_data.keys())
            if url_keys:
                test_url = url_keys[0]
                # Check if we have response data
                if test_url in urls_data and 'headers' in urls_data[test_url]:
                    headers = urls_data[test_url]['headers']
                else:
                    headers = {}
        
        if not test_url:
            return []
        
        # Detect from headers if available
        if headers:
            # Detect web server
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                tech_stack.append('Apache')
            elif 'nginx' in server:
                tech_stack.append('Nginx')
            elif 'iis' in server or 'microsoft' in server:
                tech_stack.append('IIS')
            
            # Detect programming language
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                tech_stack.append('PHP')
                if 'MySQL' not in tech_stack:
                    tech_stack.append('MySQL')  # Common with PHP
            elif 'express' in powered_by or 'node' in powered_by:
                tech_stack.append('Node.js')
                if 'MongoDB' not in tech_stack:
                    tech_stack.append('MongoDB')  # Common with Node
            elif 'asp.net' in powered_by:
                tech_stack.append('ASP.NET')
                if 'MSSQL' not in tech_stack:
                    tech_stack.append('MSSQL')  # Common with ASP.NET
        
        # Detect from URL patterns
        if '.php' in test_url:
            if 'PHP' not in tech_stack:
                tech_stack.append('PHP')
            if 'MySQL' not in tech_stack:
                tech_stack.append('MySQL')
        elif '.jsp' in test_url:
            if 'Java' not in tech_stack:
                tech_stack.append('Java')
        elif '.aspx' in test_url or '.asp' in test_url:
            if 'ASP.NET' not in tech_stack:
                tech_stack.append('ASP.NET')
            if 'MSSQL' not in tech_stack:
                tech_stack.append('MSSQL')
        
        # Check multiple URLs for patterns
        if isinstance(urls_data, dict):
            php_count = sum(1 for url in urls_data.keys() if '.php' in url)
            if php_count > 0 and 'PHP' not in tech_stack:
                tech_stack.append('PHP')
                if 'MySQL' not in tech_stack:
                    tech_stack.append('MySQL')
        
        return tech_stack
    
    async def _generate_contextual_payloads(self, tech_stack: List[str]):
        """Generate smart payloads based on tech stack"""
        print("[AI] Generating contextual payloads...")
        
        # Generate payloads for injection scanners
        for scanner_name in ['sqli', 'xss', 'cmdi']:
            if scanner_name in self.active_scanners:
                scanner = self.active_scanners[scanner_name]
                
                # Map scanner names to vulnerability types
                vuln_type_map = {
                    'sqli': 'SQL Injection',
                    'xss': 'XSS',
                    'cmdi': 'Command Injection'
                }
                
                if scanner_name in vuln_type_map:
                    payloads = await self.ai_analyzer.generate_smart_payloads(
                        vuln_type_map[scanner_name],
                        tech_stack
                    )
                    
                    if payloads and hasattr(scanner, 'payloads'):
                        # Prepend AI payloads to existing ones
                        scanner.payloads = payloads + scanner.payloads[:10]
                        self.metrics['smart_payloads_used'] += len(payloads)
                        print(f"  ✓ Added {len(payloads)} smart payloads for {scanner_name}")
    
    async def _ai_validate_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        session: aiohttp.ClientSession,
        tech_stack: List[str]
    ) -> List[Vulnerability]:
        """
        Validate vulnerabilities using AI analysis to reduce false positives.
        """
        if not vulnerabilities:
            return []
        
        print(f"[AI] Validating {len(vulnerabilities)} findings...")
        
        validated = []
        
        # Process in batches to avoid overwhelming the API
        batch_size = 10
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i+batch_size]
            
            # Analyze each vulnerability
            tasks = []
            for vuln in batch:
                task = self._analyze_single_vulnerability(vuln, tech_stack)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for vuln, result in zip(batch, results):
                if isinstance(result, Exception):
                    # On error, include the vulnerability with original confidence
                    validated.append(vuln)
                    continue
                
                ai_result: AIAnalysisResult = result
                self.metrics['total_ai_calls'] += 1
                
                # Filter based on confidence threshold
                if ai_result.confidence_score >= self.confidence_threshold:
                    # Enhance vulnerability with AI insights
                    enhanced_vuln = self._enhance_vulnerability(vuln, ai_result)
                    validated.append(enhanced_vuln)
                    self.metrics['ai_enhanced_findings'] += 1
                else:
                    # Likely false positive
                    self.metrics['false_positives_filtered'] += 1
                    print(f"  [Filtered] {vuln.vuln_type} (confidence: {ai_result.confidence_score:.2f})")
        
        return validated
    
    async def _analyze_single_vulnerability(
        self,
        vuln: Vulnerability,
        tech_stack: List[str]
    ) -> AIAnalysisResult:
        """Analyze a single vulnerability with AI"""
        context = {
            'tech_stack': tech_stack,
            'severity': vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
        }
        
        return await self.ai_analyzer.analyze_vulnerability(
            vuln_type=vuln.vuln_type,
            url=vuln.url,
            parameter=vuln.parameter or "N/A",
            payload=vuln.payload or "N/A",
            response_evidence=vuln.evidence or "",
            context=context
        )
    
    def _enhance_vulnerability(
        self,
        vuln: Vulnerability,
        ai_result: AIAnalysisResult
    ) -> Vulnerability:
        """Enhance vulnerability with AI insights"""
        # Adjust severity if recommended
        new_severity = vuln.severity
        if ai_result.severity_adjustment == "increase":
            severity_map = {
                Severity.LOW: Severity.MEDIUM,
                Severity.MEDIUM: Severity.HIGH,
                Severity.HIGH: Severity.CRITICAL
            }
            new_severity = severity_map.get(vuln.severity, vuln.severity)
        elif ai_result.severity_adjustment == "decrease":
            severity_map = {
                Severity.CRITICAL: Severity.HIGH,
                Severity.HIGH: Severity.MEDIUM,
                Severity.MEDIUM: Severity.LOW
            }
            new_severity = severity_map.get(vuln.severity, vuln.severity)
        
        # Create enhanced description
        enhanced_description = f"{vuln.description}\n\n"
        enhanced_description += f"AI Analysis (Confidence: {ai_result.confidence_score:.0%}):\n"
        enhanced_description += f"{ai_result.ai_reasoning}\n\n"
        enhanced_description += f"Exploitation Complexity: {ai_result.exploitation_complexity.title()}\n"
        enhanced_description += f"Business Impact: {ai_result.business_impact}"
        
        # Create new vulnerability with enhanced data
        return Vulnerability(
            vuln_type=vuln.vuln_type,
            severity=new_severity,
            url=vuln.url,
            parameter=vuln.parameter,
            payload=vuln.payload,
            evidence=vuln.evidence,
            description=enhanced_description,
            cwe_id=vuln.cwe_id,
            remediation=vuln.remediation
        )
    
    def _prepare_targets(self, crawl_results: Dict) -> List[Dict]:
        """Prepare scan targets from crawl results (optimized)"""
        targets = []
        
        # URL-based targets
        urls_data = crawl_results.get('urls', {})
        
        # Handle both dict and list formats
        url_list = []
        if isinstance(urls_data, dict):
            # Dictionary format: {'url': {'status': 200, ...}}
            url_list = list(urls_data.keys())
        elif isinstance(urls_data, list):
            # List format: ['url1', 'url2', ...]
            url_list = urls_data
        
        for url in url_list:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            if query_params:
                for param in query_params:
                    targets.append({
                        'url': url,
                        'params': param,  # Changed from 'param' to 'params'
                        'type': 'query'
                    })
            else:
                targets.append({
                    'url': url,
                    'params': None,  # Changed from 'param' to 'params'
                    'type': 'page'
                })
        
        # Form-based targets
        for form_data in crawl_results.get('forms', []):
            for input_field in form_data.get('inputs', []):
                targets.append({
                    'url': form_data['action'],
                    'params': input_field['name'],  # Changed from 'param' to 'params'
                    'type': 'form',
                    'method': form_data.get('method', 'GET'),
                    'form_data': form_data
                })
        
        return targets
    
    def _get_base_url(self, crawl_results: Dict) -> str:
        """Extract base URL from crawl results"""
        
        # Method 1: Try urls field (can be dict or list)
        urls_data = crawl_results.get('urls')
        if urls_data:
            # If it's a dictionary (your crawler format)
            if isinstance(urls_data, dict):
                # Get first URL from dictionary keys
                url_keys = list(urls_data.keys())
                if url_keys:
                    parsed = urlparse(url_keys[0])
                    return f"{parsed.scheme}://{parsed.netloc}"
            # If it's a list (standard format)
            elif isinstance(urls_data, list) and len(urls_data) > 0:
                parsed = urlparse(urls_data[0])
                return f"{parsed.scheme}://{parsed.netloc}"
        
        # Method 2: Try base_url field
        if crawl_results.get('base_url'):
            parsed = urlparse(crawl_results['base_url'])
            return f"{parsed.scheme}://{parsed.netloc}"
        
        # Method 3: Try target field
        if crawl_results.get('target'):
            parsed = urlparse(crawl_results['target'])
            return f"{parsed.scheme}://{parsed.netloc}"
        
        # Method 4: Get from forms
        forms = crawl_results.get('forms', [])
        if forms and len(forms) > 0:
            form = forms[0]
            if 'action' in form and form['action']:
                parsed = urlparse(form['action'])
                if parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
        
        return ""
    
    def _get_active_site_scanners(self) -> Dict:
        """Get scanners that scan entire sites"""
        site_scanner_names = [
            'headers', 'cors', 'ssl_tls', 'rate_limiting', 'graphql'
        ]
        return {k: v for k, v in self.active_scanners.items() 
                if k in site_scanner_names}
    
    def _get_active_param_scanners(self) -> Dict:
        """Get scanners that test parameters"""
        site_scanner_names = [
            'headers', 'cors', 'ssl_tls', 'rate_limiting', 'graphql'
        ]
        return {k: v for k, v in self.active_scanners.items() 
                if k not in site_scanner_names}
    
    def _deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            key = (
                vuln.vuln_type,
                vuln.url,
                vuln.parameter,
                vuln.payload[:50] if vuln.payload else ""
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def get_metrics(self) -> Dict:
        """Get performance and AI metrics"""
        return {
            **self.metrics,
            'executor_stats': self.executor.stats if self.executor else {}
        }