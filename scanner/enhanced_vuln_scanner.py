# scanner/enhanced_vuln_scanner.py
"""
Enhanced Vulnerability Scanner with Groq AI Integration - OWASP 2025 VERSION
Optimized for speed while maintaining low noise/false positives
"""

from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import asyncio
import aiohttp
import time

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory
from .parallel_executor import ParallelScanExecutor
from .ai.groq_analyzer import GroqAnalyzer, AIAnalysisResult

# =====================================================
# COMPLETE SCANNER IMPORTS - ALL 35+ SCANNERS
# Organized by OWASP Top 10 2025
# =====================================================

# ----- A01:2025 - Broken Access Control (now includes SSRF) -----
from .a01_access_control.csrf import CSRFScanner
from .a01_access_control.open_redirect import OpenRedirectScanner
from .a01_access_control.idor import IDORScanner
from .a01_access_control.path_traversal import PathTraversalScanner
from .a01_access_control.forced_browsing import ForcedBrowsingScanner
from .a01_access_control.privilege_escalation import PrivilegeEscalationScanner
from .a01_access_control.jwt_vulnerabilities import JWTVulnerabilitiesScanner
from .a01_access_control.ssrf import SSRFScanner  # Moved from A10:2021 to A01:2025

# ----- A02:2025 - Security Misconfiguration (moved up from A05:2021) -----
from .a02_misconfig.headers import SecurityHeadersScanner
from .a02_misconfig.cors import CORSScanner
from .a02_misconfig.debug import DebugModeScanner
from .a02_misconfig.backup import BackupFileScanner
from .a02_misconfig.ssl_tls import SSLTLSScanner
from .a02_misconfig.cookie_security import CookieSecurityScanner
from .a02_misconfig.information_disclosure import InformationDisclosureScanner
from .a02_misconfig.config_exposure import ConfigExposureScanner
from .a02_misconfig.default_credentials import DefaultCredentialsScanner

# ----- A03:2025 - Software Supply Chain Failures (expanded from A06:2021) -----
from .cve.known_cve import KnownCVEScanner
from .a03_supply_chain.dependency_check import DependencyCheckScanner
from .a03_supply_chain.integrity_check import IntegrityCheckScanner
from .a03_supply_chain.outdated_components import OutdatedComponentsScanner

# ----- A04:2025 - Cryptographic Failures (moved down from A02:2021) -----
from .a04_cryptographic.weak_crypto import WeakCryptoScanner
from .a04_cryptographic.sensitive_data_exposure import SensitiveDataExposureScanner

# ----- A05:2025 - Injection (moved down from A03:2021, still critical) -----
from .a05_injection.sqli import SQLInjectionScanner
from .a05_injection.nosqli import NoSQLInjectionScanner
from .a05_injection.cmdi import CommandInjectionScanner
from .a05_injection.ssti import SSTIScanner
from .a05_injection.ldapi import LDAPInjectionScanner
from .a05_injection.xpath import XPathInjectionScanner
from .a05_injection.hhi import HostHeaderInjectionScanner
from .a05_injection.xss import XSSScanner
from .a05_injection.dom_xss import DOMXSSScanner
from .a05_injection.code_injection import CodeInjectionScanner
from .a05_injection.crlf import CRLFInjectionScanner
from .a05_injection.el_injection import ELInjectionScanner
from .xxe.xxe import XXEScanner

# Playwright-based scanners (browser-based detection)
try:
    from .a05_injection.xss_playwright import PlaywrightXSSScanner
    PLAYWRIGHT_XSS_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_XSS_AVAILABLE = False

try:
    from .a05_injection.sqli_playwright import PlaywrightSQLiScanner, DatabaseInfo
    PLAYWRIGHT_SQLI_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_SQLI_AVAILABLE = False

# ----- A06:2025 - Insecure Design -----
from .a06_insecure_design.business_logic import BusinessLogicScanner
from .a06_insecure_design.clickjacking import ClickjackingScanner
from .a06_insecure_design.file_upload import FileUploadScanner
from .a06_insecure_design.http_smuggling import HTTPSmugglingScanner
from .a06_insecure_design.race_condition import RaceConditionScanner
from .a06_insecure_design.trust_boundary import TrustBoundaryScanner
from .api_security.rate_limiting import RateLimitingScanner

# ----- A07:2025 - Authentication Failures -----
from .a07_authentication.auth_bypass import AuthBypassScanner
from .a07_authentication.brute_force import BruteForceScanner
from .a07_authentication.default_credentials import DefaultCredentials07Scanner
from .a07_authentication.mfa_check import MFAScanner
from .a07_authentication.session_fixation import SessionFixationScanner
from .a07_authentication.session_management import SessionManagementScanner
from .a07_authentication.weak_password import WeakPasswordPolicyScanner

# ----- A08:2025 - Software or Data Integrity Failures -----
from .a08_deserialization.code_integrity import CodeIntegrityScanner
from .a08_deserialization.cookie_integrity import CookieIntegrityScanner
from .a08_deserialization.insecure_deserialization import InsecureDeserializationScanner
from .a08_deserialization.subresource_integrity import SubresourceIntegrityScanner

# ----- A09:2025 - Security Logging and Alerting Failures -----
from .a09_logging.log_injection import LogInjectionScanner
from .a09_logging.sensitive_log_data import SensitiveLogDataScanner
from .a09_logging.log_file_exposure import LogFileExposureScanner
from .a09_logging.insufficient_logging import InsufficientLoggingScanner
from .a09_logging.alert_detection import AlertDetectionScanner

# ----- A10:2025 - Mishandling of Exceptional Conditions (NEW) -----
from .a10_exceptional_conditions.error_handling import ErrorHandlingScanner
from .a10_exceptional_conditions.fail_open import FailOpenScanner
from .a10_exceptional_conditions.resource_limits import ResourceLimitsScanner

# ----- API Security (Additional) -----
from .api_security.mass_assignment import MassAssignmentScanner
from .api_security.graphql import GraphQLScanner


class EnhancedVulnerabilityScanner:
    """
    Enhanced vulnerability scanner with:
    1. Groq AI integration for smarter detection
    2. ALL 35+ scanners covering OWASP Top 10 2025
    3. Optimized parallel execution
    4. Smart payload selection
    5. False positive reduction
    6. Automatic fallback to non-AI mode
    7. Playwright-based XSS and SQLi detection
    """
    
    def __init__(self, scan_config: Dict = None):
        """
        Initialize enhanced scanner with ALL available scanners.
        
        Args:
            scan_config: Configuration dict with options:
                - ai_enabled: Enable AI analysis (auto-detected from GROQ_API_KEY or api_key)
                - api_key: Groq API key (optional - overrides environment variable)
                - scan_depth: 'quick', 'normal', 'deep'
                - parallel: Enable parallel scanning (default: True)
                - max_concurrent_scanners: Default 8
                - max_concurrent_targets: Default 15
                - requests_per_second: Default 75
                - timeout: Default 20
                - smart_payloads: Use AI-generated payloads (default: True)
                - confidence_threshold: Minimum confidence to report (default: 0.6)
                - playwright_xss: Enable Playwright XSS scanner (default: True)
                - playwright_sqli: Enable Playwright SQLi scanner (default: True)
                - playwright_enumerate_db: Enable database enumeration (default: True)
                - headless: Run Playwright in headless mode (default: True)
                - auth_token: Authentication token for authenticated scanning
        """
        self.config = scan_config or {}
        self.scan_depth = self.config.get('scan_depth', 'normal')
        self.parallel_enabled = self.config.get('parallel', True)
        
        # Enhanced parallel execution settings (optimized for speed)
        self.max_concurrent_scanners = self.config.get('max_concurrent_scanners', 8)
        self.max_concurrent_targets = self.config.get('max_concurrent_targets', 15)
        self.requests_per_second = self.config.get('requests_per_second', 75)
        self.timeout = self.config.get('timeout', 20)
        
        # AI settings
        self.smart_payloads = self.config.get('smart_payloads', True)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.6)
        
        # Initialize Groq analyzer with optional API key
        api_key = self.config.get('api_key', None)
        self.ai_analyzer = GroqAnalyzer(api_key=api_key)
        
        # Progress callback
        self._progress_callback = None

        # Playwright scanner settings
        self.playwright_xss_enabled = self.config.get('playwright_xss', True) and PLAYWRIGHT_XSS_AVAILABLE
        self.playwright_sqli_enabled = self.config.get('playwright_sqli', True) and PLAYWRIGHT_SQLI_AVAILABLE
        self.playwright_enumerate_db = self.config.get('playwright_enumerate_db', True)
        self.playwright_headless = self.config.get('headless', True)
        self._auth_token: Optional[str] = self.config.get('auth_token', None)
        
        # Database info extracted by SQLi scanner
        self._extracted_db_info: Optional[DatabaseInfo] = None
        
        # Print Playwright availability
        if PLAYWRIGHT_XSS_AVAILABLE:
            print(f"[*] Playwright XSS Scanner: {'Enabled' if self.playwright_xss_enabled else 'Disabled'}")
        else:
            print(f"[*] Playwright XSS Scanner: Not Available (install playwright)")
        
        if PLAYWRIGHT_SQLI_AVAILABLE:
            print(f"[*] Playwright SQLi Scanner: {'Enabled' if self.playwright_sqli_enabled else 'Disabled'}")
        else:
            print(f"[*] Playwright SQLi Scanner: Not Available (install playwright)")
        
        self.all_scanners = {
            # ==========================================
            # A01:2025 - Broken Access Control
            # (Now includes SSRF - previously A10:2021)
            # ==========================================
            'idor': IDORScanner(),
            'path_traversal': PathTraversalScanner(),
            'forced_browsing': ForcedBrowsingScanner(),
            'privilege_escalation': PrivilegeEscalationScanner(),
            'jwt': JWTVulnerabilitiesScanner(),
            'ssrf': SSRFScanner(),  # Moved from A10:2021
            'csrf': CSRFScanner(),
            'open_redirect': OpenRedirectScanner(),
            
            # ==========================================
            # A02:2025 - Security Misconfiguration
            # (Moved UP from A05:2021, expanded for cloud/infra)
            # ==========================================
            'headers': SecurityHeadersScanner(),
            'cors': CORSScanner(),
            'debug': DebugModeScanner(),
            'backup': BackupFileScanner(),
            'ssl_tls': SSLTLSScanner(),
            'cookie_security': CookieSecurityScanner(),
            'information_disclosure': InformationDisclosureScanner(),
            'config_exposure': ConfigExposureScanner(),
            'default_credentials': DefaultCredentialsScanner(),
            
            # ==========================================
            # A03:2025 - Software Supply Chain Failures
            # (Renamed from "Vulnerable Components", now covers CI/CD, deps)
            # ==========================================
            'known_cve': KnownCVEScanner(),
            'dependency_check': DependencyCheckScanner(),
            'integrity_check': IntegrityCheckScanner(),
            'outdated_components': OutdatedComponentsScanner(),
            
            # ==========================================
            # A04:2025 - Cryptographic Failures
            # (Moved DOWN from A02:2021)
            # ==========================================
            'weak_crypto': WeakCryptoScanner(),
            'sensitive_data_exposure': SensitiveDataExposureScanner(),
            
            # ==========================================
            # A05:2025 - Injection
            # (Moved DOWN from A03:2021, still critical)
            # ==========================================
            'sqli': SQLInjectionScanner(),
            'nosqli': NoSQLInjectionScanner(),
            'cmdi': CommandInjectionScanner(),
            'ssti': SSTIScanner(),
            'ldapi': LDAPInjectionScanner(),
            'xpath': XPathInjectionScanner(),
            'hhi': HostHeaderInjectionScanner(),
            'xss': XSSScanner(),
            'dom_xss': DOMXSSScanner(),
            'xxe': XXEScanner(),
            'code_injection': CodeInjectionScanner(),
            'crlf': CRLFInjectionScanner(),
            'el_injection': ELInjectionScanner(),
            
            # ==========================================
            # A06:2025 - Insecure Design
            # ==========================================
            'rate_limiting': RateLimitingScanner(),
            'business_logic': BusinessLogicScanner(),
            'clickjacking': ClickjackingScanner(),
            'file_upload': FileUploadScanner(),
            'http_smuggling': HTTPSmugglingScanner(),
            'race_condition': RaceConditionScanner(),
            'trust_boundary': TrustBoundaryScanner(),
            
            # ==========================================
            # A07:2025 - Authentication Failures
            # ==========================================
            'auth_bypass': AuthBypassScanner(),
            'brute_force': BruteForceScanner(),
            'default_credentials': DefaultCredentials07Scanner(),
            'mfa_check': MFAScanner(),
            'session_fixation': SessionFixationScanner(),
            'session_management': SessionManagementScanner(),
            'weak_password': WeakPasswordPolicyScanner(),
            
            # ==========================================
            # A08:2025 - Software or Data Integrity Failures
            # ==========================================
            'code_integrity': CodeIntegrityScanner(),
            'cookie_integrity': CookieIntegrityScanner(),
            'deserialization': InsecureDeserializationScanner(),
            
            # ==========================================
            # A09:2025 - Security Logging and Alerting Failures
            # ==========================================
            'log_injection': LogInjectionScanner(),
            'sensitive_log_data': SensitiveLogDataScanner(),
            'log_file_exposure': LogFileExposureScanner(),
            'insufficient_logging': InsufficientLoggingScanner(),
            'alert_detection': AlertDetectionScanner(),
            
            # ==========================================
            # A10:2025 - Mishandling of Exceptional Conditions
            # (🆕 NEW CATEGORY - replaces SSRF which moved to A01)
            # ==========================================
            'error_handling': ErrorHandlingScanner(),
            'fail_open': FailOpenScanner(),
            'resource_limits': ResourceLimitsScanner(),
            
            # ==========================================
            # API Security (Additional)
            # ==========================================
            'graphql': GraphQLScanner(),
            'mass_assignment': MassAssignmentScanner(),
        }
        
        print(f"[*] Initialized {len(self.all_scanners)} total scanners (OWASP 2025)")
        
        # =====================================================
        # SCAN MODE PRESETS - OWASP 2025 ALIGNED
        # =====================================================
        self.scan_modes = {
            'quick': [
                # Fast scan - only most critical/common
                'sqli', 'xss', 'headers', 'cors', 'ssl_tls'
            ],
            'standard': [
                # Balanced scan - common vulnerabilities
                'sqli', 'nosqli', 'xss', 'cmdi', 'ssti',
                'headers', 'cors', 'idor', 'path_traversal',
                'ssrf', 'ssl_tls', 'jwt', 'rate_limiting',
                'information_disclosure', 'cookie_security',
                'error_handling'
            ],
            'full': list(self.all_scanners.keys()),  # ALL 35+ scanners
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
            'total_ai_calls': 0,
            'playwright_xss_findings': 0,
            'playwright_sqli_findings': 0,
            'auth_bypass_findings': 0,
            'database_enumerated': False,
            'tables_extracted': 0,
            'data_extracted': False,
            'owasp_coverage': self._calculate_owasp_coverage()
        }
    
    def _calculate_owasp_coverage(self) -> Dict:
        """Calculate OWASP 2025 category coverage"""
        owasp_mapping = {
            'A01': ['idor', 'path_traversal', 'forced_browsing', 'privilege_escalation', 'jwt', 'ssrf', 'csrf', 'open_redirect'],
            'A02': ['headers', 'cors', 'debug', 'backup', 'ssl_tls', 'cookie_security', 'information_disclosure', 'config_exposure', 'default_credentials'],
            'A03': ['known_cve', 'dependency_check', 'integrity_check', 'outdated_components'],
            'A04': ['weak_crypto', 'sensitive_data_exposure'],
            'A05': ['sqli', 'nosqli', 'xss', 'dom_xss', 'cmdi', 'ssti', 'ldapi', 'xpath', 'hhi', 'xxe', 'code_injection', 'crlf', 'el_injection'],
            'A06': ['rate_limiting', 'business_logic', 'clickjacking', 'file_upload', 'http_smuggling', 'race_condition', 'trust_boundary'],
            'A07': ['session_fixation', 'weak_password', 'brute_force', 'auth_bypass', 'default_credentials', 'mfa_check', 'session_management'],
            'A08': ['deserialization', 'code_integrity', 'cookie_integrity'],
            'A09': ['log_injection', 'sensitive_log_data', 'log_file_exposure', 'insufficient_logging', 'alert_detection'],
            'A10': ['error_handling', 'fail_open', 'resource_limits'],
        }
        
        coverage = {}
        active_names = set(self.active_scanners.keys())
        
        for category, scanners in owasp_mapping.items():
            if not scanners:
                coverage[category] = {'covered': 0, 'total': 0, 'percentage': 0}
            else:
                covered = len(set(scanners) & active_names)
                total = len(scanners)
                coverage[category] = {
                    'covered': covered,
                    'total': total,
                    'percentage': round((covered / total) * 100) if total > 0 else 0
                }
        
        return coverage
    
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
    
    def set_auth_token(self, token: str):
        """Set authentication token for authenticated scanning"""
        self._auth_token = token
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PLAYWRIGHT SCANNER METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _run_playwright_xss_parallel(
        self,
        crawl_results: Dict,
        base_url: str
    ) -> List[Vulnerability]:
        """
        Run Playwright XSS scanner in parallel with HTTP scanners.
        This method is designed to run concurrently without blocking.
        """
        if not PLAYWRIGHT_XSS_AVAILABLE:
            return []
        
        if not base_url:
            return []
        
        try:
            print(f"\n[Playwright XSS] Starting browser-based XSS scan...")
            
            xss_scanner = PlaywrightXSSScanner(headless=self.playwright_headless)
            
            vulns = await xss_scanner.scan_with_browser(
                base_url=base_url,
                forms=crawl_results.get('forms', []),
                urls=crawl_results.get('urls', {}),
                auth_token=self._auth_token
            )
            
            self.metrics['playwright_xss_findings'] = len(vulns)
            
            if vulns:
                print(f"[Playwright XSS] Found {len(vulns)} XSS vulnerabilities")
            else:
                print(f"[Playwright XSS] Scan complete (no XSS found)")
            
            return vulns
            
        except Exception as e:
            print(f"[Playwright XSS] Error: {str(e)[:100]}")
            return []
    
    async def _run_playwright_sqli_parallel(
        self,
        crawl_results: Dict,
        base_url: str
    ) -> Tuple[List[Vulnerability], Optional[DatabaseInfo]]:
        """
        Run Playwright SQL Injection scanner in parallel with HTTP scanners.
        This method is designed to run concurrently without blocking.
        
        Returns:
            Tuple of (vulnerabilities, database_info)
        """
        if not PLAYWRIGHT_SQLI_AVAILABLE:
            return [], None
        
        if not base_url:
            return [], None
        
        try:
            print(f"\n[Playwright SQLi] Starting browser-based SQL Injection scan...")
            
            sqli_scanner = PlaywrightSQLiScanner(
                headless=self.playwright_headless,
                verbose=True
            )
            
            # Prepare URLs with parameters
            urls_with_params = []
            urls_data = crawl_results.get('urls', {})
            
            if isinstance(urls_data, dict):
                for url in urls_data.keys():
                    if '?' in url:  # Has query parameters
                        urls_with_params.append(url)
            elif isinstance(urls_data, list):
                for url in urls_data:
                    if '?' in url:
                        urls_with_params.append(url)
            
            # Run the scan
            vulns, db_info = await sqli_scanner.scan_with_browser(
                base_url=base_url,
                forms=crawl_results.get('forms', []),
                urls_with_params=urls_with_params,
                auth_token=self._auth_token,
                enumerate_db=self.playwright_enumerate_db
            )
            
            # Update metrics
            self.metrics['playwright_sqli_findings'] = len(vulns)
            
            # Count auth bypass findings
            auth_bypass_count = sum(1 for v in vulns if 'auth' in v.vuln_type.lower() or 'bypass' in v.vuln_type.lower())
            self.metrics['auth_bypass_findings'] = auth_bypass_count
            
            if db_info:
                self.metrics['database_enumerated'] = True
                self.metrics['tables_extracted'] = len(db_info.tables)
                self.metrics['data_extracted'] = bool(db_info.extracted_data)
                self._extracted_db_info = db_info
            
            if vulns:
                print(f"[Playwright SQLi] Found {len(vulns)} SQL Injection vulnerabilities")
                if auth_bypass_count:
                    print(f"[Playwright SQLi]   - {auth_bypass_count} authentication bypass(es)")
                if db_info:
                    print(f"[Playwright SQLi]   - Database: {db_info.db_type.value}")
                    if db_info.tables:
                        print(f"[Playwright SQLi]   - Extracted {len(db_info.tables)} table names")
                    if db_info.extracted_data:
                        print(f"[Playwright SQLi]   - Extracted data from {len(db_info.extracted_data)} tables")
            else:
                print(f"[Playwright SQLi] Scan complete (no SQLi found)")
            
            return vulns, db_info
            
        except Exception as e:
            print(f"[Playwright SQLi] Error: {str(e)[:100]}")
            import traceback
            traceback.print_exc()
            return [], None
    
    async def _run_all_playwright_scanners(
        self,
        crawl_results: Dict,
        base_url: str
    ) -> List[Vulnerability]:
        """
        Run all Playwright-based scanners in parallel.
        
        Returns:
            Combined list of vulnerabilities from all Playwright scanners
        """
        tasks = []
        task_names = []
        
        # Add XSS scanner task if enabled
        if self.playwright_xss_enabled and 'xss' in self.active_scanners:
            tasks.append(self._run_playwright_xss_parallel(crawl_results, base_url))
            task_names.append("XSS")
        
        # Add SQLi scanner task if enabled
        if self.playwright_sqli_enabled and 'sqli' in self.active_scanners:
            tasks.append(self._run_playwright_sqli_parallel(crawl_results, base_url))
            task_names.append("SQLi")
        
        if not tasks:
            return []
        
        print(f"\n[Playwright] Running {len(tasks)} browser-based scanner(s): {', '.join(task_names)}")
        
        # Run all Playwright scanners in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_vulns = []
        
        for i, result in enumerate(results):
            scanner_name = task_names[i]
            
            if isinstance(result, Exception):
                print(f"[Playwright {scanner_name}] Error: {result}")
                continue
            
            # Handle SQLi result (tuple)
            if scanner_name == "SQLi":
                if isinstance(result, tuple):
                    vulns, db_info = result
                    all_vulns.extend(vulns)
                else:
                    # Unexpected format
                    print(f"[Playwright SQLi] Unexpected result format")
            else:
                # XSS result (list)
                if isinstance(result, list):
                    all_vulns.extend(result)
        
        return all_vulns
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MAIN SCANNING METHOD
    # ═══════════════════════════════════════════════════════════════════════════
    
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
        print(f"  OWASP Version: Top 10 2025")
        print(f"  Active Scanners: {len(self.active_scanners)}")
        print(f"  Total Available: {len(self.all_scanners)}")
        print(f"  Parallel Workers: {self.max_concurrent_scanners}")
        print(f"  Playwright XSS: {'Enabled' if self.playwright_xss_enabled else 'Disabled'}")
        print(f"  Playwright SQLi: {'Enabled' if self.playwright_sqli_enabled else 'Disabled'}")
        print(f"{'='*60}\n")
        
        # Print OWASP coverage
        self._print_owasp_coverage()
        
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
            return []
        
        print(f"[*] Crawl results: {urls_count} URLs, {forms_count} forms")
        
        # Auto-detect tech stack if not provided
        if not tech_stack or len(tech_stack) == 0:
            print(f"\n[*] Auto-detecting tech stack...")
            tech_stack = await self._detect_tech_stack(crawl_results)
            if tech_stack:
                print(f"  ✓ Detected: {', '.join(tech_stack)}")
            else:
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
            limit=self.max_concurrent_targets * 3,
            limit_per_host=self.max_concurrent_targets,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'VulnFlow/2.0 AI-Enhanced Security Scanner (OWASP 2025)',
                'Accept': '*/*'
            }
        ) as session:
            # Convert to list for parallel executor
            site_scanners_list = list(site_scanners.items())
            param_scanners_list = list(param_scanners.items())
            
            # ═══════════════════════════════════════════════════════════
            # Execute all scans in parallel (HTTP + Playwright)
            # ═══════════════════════════════════════════════════════════
            
            # Create task for HTTP-based scanners
            http_scan_task = asyncio.create_task(
                self.executor.execute_all_scans(
                    session,
                    targets,
                    site_scanners_list,
                    param_scanners_list,
                    base_url
                )
            )
            
            # Check if any Playwright scanners are enabled
            playwright_enabled = (
                (self.playwright_xss_enabled and 'xss' in self.active_scanners) or
                (self.playwright_sqli_enabled and 'sqli' in self.active_scanners)
            )
            
            # Create task for Playwright scanners (if enabled)
            playwright_task = None
            if playwright_enabled:
                playwright_task = asyncio.create_task(
                    self._run_all_playwright_scanners(crawl_results, base_url)
                )
            
            # Gather results from all tasks
            if playwright_task:
                print(f"\n[*] Running HTTP scanners and Playwright scanners in parallel...")
                
                results = await asyncio.gather(
                    http_scan_task,
                    playwright_task,
                    return_exceptions=True
                )
                
                # Process HTTP scan results
                if isinstance(results[0], Exception):
                    print(f"  [!] HTTP scan error: {results[0]}")
                    http_vulns = []
                else:
                    http_vulns = results[0]
                
                # Process Playwright results
                if isinstance(results[1], Exception):
                    print(f"  [!] Playwright scan error: {results[1]}")
                    playwright_vulns = []
                else:
                    playwright_vulns = results[1]
                
                print(f"\n[*] HTTP scanners found: {len(http_vulns)} issues")
                print(f"[*] Playwright scanners found: {len(playwright_vulns)} issues")
                
                raw_vulnerabilities = http_vulns + playwright_vulns
            else:
                # Just run HTTP scanners
                raw_vulnerabilities = await http_scan_task
            
            print(f"\n[*] Total findings: {len(raw_vulnerabilities)} potential issues")
            
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
        print(f"  Playwright XSS Findings: {self.metrics['playwright_xss_findings']}")
        print(f"  Playwright SQLi Findings: {self.metrics['playwright_sqli_findings']}")
        if self.metrics['auth_bypass_findings']:
            print(f"  Auth Bypass Findings: {self.metrics['auth_bypass_findings']}")
        if self.metrics['database_enumerated']:
            print(f"  Database Enumerated: Yes")
            print(f"    Tables Found: {self.metrics['tables_extracted']}")
            print(f"    Data Extracted: {'Yes' if self.metrics['data_extracted'] else 'No'}")
        self._print_findings_by_owasp(unique_vulns)
        print(f"{'='*60}\n")
        
        return unique_vulns
    
    def get_extracted_database_info(self) -> Optional[Dict]:
        """
        Get database information extracted during SQLi scanning.
        
        Returns:
            Dictionary with database info or None if not available
        """
        if self._extracted_db_info:
            return self._extracted_db_info.to_dict()
        return None
    
    def _print_owasp_coverage(self):
        """Print OWASP 2025 coverage summary"""
        print("[*] OWASP 2025 Coverage:")
        coverage = self._calculate_owasp_coverage()
        
        owasp_names = {
            'A01': 'Broken Access Control',
            'A02': 'Security Misconfiguration',
            'A03': 'Supply Chain Failures',
            'A04': 'Cryptographic Failures',
            'A05': 'Injection',
            'A06': 'Insecure Design',
            'A07': 'Auth Failures',
            'A08': 'Data Integrity',
            'A09': 'Logging Failures',
            'A10': 'Exceptional Conditions',
        }
        
        for cat_id, data in coverage.items():
            name = owasp_names.get(cat_id, cat_id)
            pct = data['percentage']
            bar = '█' * (pct // 10) + '░' * (10 - pct // 10)
            status = '✓' if pct >= 50 else '○'
            print(f"  {status} {cat_id}: {name[:22]:<22} [{bar}] {pct:>3}%")
        print()
    
    def _print_findings_by_owasp(self, vulnerabilities: List[Vulnerability]):
        """Print findings summary grouped by OWASP category"""
        if not vulnerabilities:
            return
        
        print(f"\n  Findings by OWASP 2025 Category:")
        
        # Group by OWASP category
        by_category = {}
        for vuln in vulnerabilities:
            owasp_cat = getattr(vuln, 'owasp_category', None)
            if owasp_cat:
                cat_value = owasp_cat.value if hasattr(owasp_cat, 'value') else str(owasp_cat)
            else:
                cat_value = "Other"
            
            # Extract category ID (e.g., "A01" from "A01:2025 - Broken Access Control")
            if ':' in cat_value:
                cat_id = cat_value.split(':')[0]
            else:
                cat_id = "Other"
            
            if cat_id not in by_category:
                by_category[cat_id] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if severity in by_category[cat_id]:
                by_category[cat_id][severity] += 1
        
        for cat_id in sorted(by_category.keys()):
            counts = by_category[cat_id]
            total = sum(counts.values())
            parts = []
            if counts['critical']: parts.append(f"🔴{counts['critical']}")
            if counts['high']: parts.append(f"🟠{counts['high']}")
            if counts['medium']: parts.append(f"🟡{counts['medium']}")
            if counts['low']: parts.append(f"🔵{counts['low']}")
            
            print(f"    {cat_id}: {total} findings ({' '.join(parts)})")
    
    async def _detect_tech_stack(self, crawl_results: Dict) -> List[str]:
        """Auto-detect technology stack from crawl results"""
        tech_stack = []
        
        # Get first URL to test
        urls_data = crawl_results.get('urls', {})
        test_url = None
        
        if isinstance(urls_data, dict):
            url_keys = list(urls_data.keys())
            if url_keys:
                test_url = url_keys[0]
                url_data = urls_data[test_url]
        elif isinstance(urls_data, list) and len(urls_data) > 0:
            test_url = urls_data[0]
            url_data = {}
        else:
            return tech_stack
        
        if not test_url:
            return tech_stack
        
        # Detect from headers (if available)
        if isinstance(url_data, dict):
            headers = url_data.get('headers', {})
            
            # Server detection
            server = headers.get('Server', '').lower()
            if 'nginx' in server:
                tech_stack.append('Nginx')
            elif 'apache' in server:
                tech_stack.append('Apache')
            elif 'iis' in server:
                tech_stack.append('IIS')
            
            # Framework detection
            x_powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in x_powered_by:
                tech_stack.append('PHP')
            elif 'asp.net' in x_powered_by:
                tech_stack.append('ASP.NET')
                if 'MSSQL' not in tech_stack:
                    tech_stack.append('MSSQL')
        
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
        
        # Check for Juice Shop (Node.js + SQLite)
        if 'juice' in test_url.lower() or ':3000' in test_url:
            if 'Node.js' not in tech_stack:
                tech_stack.append('Node.js')
            if 'SQLite' not in tech_stack:
                tech_stack.append('SQLite')
            if 'Angular' not in tech_stack:
                tech_stack.append('Angular')
        
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
                        scanner.payloads = payloads + scanner.payloads[:10]
                        self.metrics['smart_payloads_used'] += len(payloads)
                        print(f"  ✓ Added {len(payloads)} smart payloads for {scanner_name}")
    
    async def _ai_validate_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        session: aiohttp.ClientSession,
        tech_stack: List[str]
    ) -> List[Vulnerability]:
        """Validate vulnerabilities using AI analysis to reduce false positives."""
        if not vulnerabilities:
            return []
        
        print(f"[AI] Validating {len(vulnerabilities)} findings...")
        
        validated = []
        
        # Process in batches
        batch_size = 10
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i+batch_size]
            
            tasks = []
            for vuln in batch:
                task = self._analyze_single_vulnerability(vuln, tech_stack)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for vuln, result in zip(batch, results):
                if isinstance(result, Exception):
                    validated.append(vuln)
                    continue
                
                ai_result: AIAnalysisResult = result
                self.metrics['total_ai_calls'] += 1
                
                if ai_result.confidence_score >= self.confidence_threshold:
                    enhanced_vuln = self._enhance_vulnerability(vuln, ai_result)
                    validated.append(enhanced_vuln)
                    self.metrics['ai_enhanced_findings'] += 1
                else:
                    self.metrics['false_positives_filtered'] += 1
                    print(f"  [Filtered] {vuln.vuln_type} (confidence: {ai_result.confidence_score:.2f})")
        
        return validated
    
    async def _analyze_single_vulnerability(
        self,
        vuln: Vulnerability,
        tech_stack: List[str]
    ) -> AIAnalysisResult:
        """Analyze a single vulnerability with AI"""
        # Get OWASP category for context
        owasp_cat = getattr(vuln, 'owasp_category', None)
        if owasp_cat:
            owasp_value = owasp_cat.value if hasattr(owasp_cat, 'value') else str(owasp_cat)
        else:
            owasp_value = "Unknown"
        
        context = {
            'tech_stack': tech_stack,
            'severity': vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
            'owasp_category': owasp_value
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
        
        # Preserve OWASP category
        owasp_cat = getattr(vuln, 'owasp_category', OWASPCategory.OTHER)
        
        return Vulnerability(
            vuln_type=vuln.vuln_type,
            severity=new_severity,
            url=vuln.url,
            parameter=vuln.parameter,
            payload=vuln.payload,
            evidence=vuln.evidence,
            description=enhanced_description,
            cwe_id=vuln.cwe_id,
            owasp_category=owasp_cat,
            remediation=vuln.remediation,
            request=vuln.request,
            response=vuln.response,
            http_message=vuln.http_message
        )
    
    def _prepare_targets(self, crawl_results: Dict) -> List[Dict]:
        """Prepare scan targets from crawl results"""
        targets = []
        
        # URL-based targets
        urls_data = crawl_results.get('urls', {})
        
        url_list = []
        if isinstance(urls_data, dict):
            url_list = list(urls_data.keys())
        elif isinstance(urls_data, list):
            url_list = urls_data
        
        for url in url_list:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            if query_params:
                for param in query_params:
                    targets.append({
                        'url': url,
                        'params': param,
                        'type': 'query'
                    })
            else:
                targets.append({
                    'url': url,
                    'params': None,
                    'type': 'page'
                })
        
        # Form-based targets
        for form_data in crawl_results.get('forms', []):
            for input_field in form_data.get('inputs', []):
                targets.append({
                    'url': form_data['action'],
                    'params': input_field['name'],
                    'type': 'form',
                    'method': form_data.get('method', 'GET'),
                    'form_data': form_data
                })
        
        return targets
    
    def _get_base_url(self, crawl_results: Dict) -> str:
        """Extract base URL from crawl results"""
        urls_data = crawl_results.get('urls')
        if urls_data:
            if isinstance(urls_data, dict):
                url_keys = list(urls_data.keys())
                if url_keys:
                    parsed = urlparse(url_keys[0])
                    return f"{parsed.scheme}://{parsed.netloc}"
            elif isinstance(urls_data, list) and len(urls_data) > 0:
                parsed = urlparse(urls_data[0])
                return f"{parsed.scheme}://{parsed.netloc}"
        
        if crawl_results.get('base_url'):
            parsed = urlparse(crawl_results['base_url'])
            return f"{parsed.scheme}://{parsed.netloc}"
        
        if crawl_results.get('target'):
            parsed = urlparse(crawl_results['target'])
            return f"{parsed.scheme}://{parsed.netloc}"
        
        forms = crawl_results.get('forms', [])
        if forms and len(forms) > 0:
            form = forms[0]
            if 'action' in form and form['action']:
                parsed = urlparse(form['action'])
                if parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
        
        return ""
    
    def _get_active_site_scanners(self) -> Dict:
        """Get scanners that scan entire sites (not parameter-specific)"""
        site_scanner_names = [
            'headers', 'cors', 'ssl_tls', 'debug', 'backup', 
            'cookie_security', 'information_disclosure',
            'known_cve', 'dependency_check', 'outdated_components',
            'weak_crypto', 'sensitive_data_exposure',
            'rate_limiting',
            'log_file_exposure', 'insufficient_logging', 'alert_detection',
            'error_handling', 'fail_open', 'resource_limits',
            'graphql',
        ]
        return {k: v for k, v in self.active_scanners.items() 
                if k in site_scanner_names}
    
    def _get_active_param_scanners(self) -> Dict:
        """Get scanners that test parameters"""
        site_scanner_names = [
            'headers', 'cors', 'ssl_tls', 'debug', 'backup', 
            'cookie_security', 'information_disclosure',
            'known_cve', 'dependency_check', 'outdated_components',
            'weak_crypto', 'sensitive_data_exposure',
            'rate_limiting',
            'error_handling', 'fail_open', 'resource_limits',
            'graphql',
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
            'executor_stats': self.executor.stats if self.executor else {},
            'owasp_coverage': self._calculate_owasp_coverage()
        }
    
    def get_available_scan_modes(self) -> Dict[str, List[str]]:
        """Get all available scan modes and their scanners"""
        return {
            mode: scanners for mode, scanners in self.scan_modes.items()
        }
    
    def get_owasp_mapping(self) -> Dict[str, List[str]]:
        """Get mapping of OWASP 2025 categories to scanners"""
        return {
            'A01:2025 - Broken Access Control': [
                'idor', 'path_traversal', 'forced_browsing', 
                'privilege_escalation', 'jwt', 'ssrf', 'csrf', 'open_redirect'
            ],
            'A02:2025 - Security Misconfiguration': [
                'headers', 'cors', 'debug', 'backup', 'ssl_tls',
                'cookie_security', 'information_disclosure'
            ],
            'A03:2025 - Software Supply Chain Failures': [
                'known_cve', 'dependency_check', 'integrity_check', 'outdated_components'
            ],
            'A04:2025 - Cryptographic Failures': [
                'weak_crypto', 'sensitive_data_exposure'
            ],
            'A05:2025 - Injection': [
                'sqli', 'nosqli', 'xss', 'dom_xss', 'cmdi', 
                'ssti', 'ldapi', 'xpath', 'hhi', 'xxe',
                'code_injection', 'crlf', 'el_injection'
            ],
            'A06:2025 - Insecure Design': [
                'rate_limiting', 'business_logic', 'clickjacking',
                'file_upload', 'http_smuggling', 'race_condition', 'trust_boundary'
            ],
            'A07:2025 - Authentication Failures': [
                'session_fixation', 'weak_password', 'jwt', 'brute_force',
                'auth_bypass', 'default_credentials', 'mfa_check', 'session_management'
            ],
            'A08:2025 - Software or Data Integrity Failures': [
                'deserialization', 'code_integrity', 'cookie_integrity'
            ],
            'A09:2025 - Security Logging and Alerting Failures': [
                'log_injection', 'sensitive_log_data', 'log_file_exposure',
                'insufficient_logging', 'alert_detection'
            ],
            'A10:2025 - Mishandling of Exceptional Conditions': [
                'error_handling', 'fail_open', 'resource_limits'
            ],
        }
    
    def shutdown(self):
        """Clean shutdown"""
        if self.executor:
            self.executor.shutdown()