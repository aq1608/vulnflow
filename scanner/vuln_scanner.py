# scanner/vuln_scanner.py
"""
Vulnerability Scanner Orchestrator — OWASP 2025 VERSION
Full-featured scanning with Playwright browser-based detection,
parallel execution, auto-tuning, and early termination.

All features from EnhancedVulnerabilityScanner EXCEPT AI/Groq integration.
"""

from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import asyncio
import aiohttp
import time

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory
from .parallel_executor import ParallelScanExecutor

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
from .a01_access_control.ssrf import SSRFScanner

# ----- A02:2025 - Security Misconfiguration -----
from .a02_misconfig.headers import SecurityHeadersScanner
from .a02_misconfig.cors import CORSScanner
from .a02_misconfig.debug import DebugModeScanner
from .a02_misconfig.backup import BackupFileScanner
from .a02_misconfig.ssl_tls import SSLTLSScanner
from .a02_misconfig.cookie_security import CookieSecurityScanner
from .a02_misconfig.information_disclosure import InformationDisclosureScanner
from .a02_misconfig.config_exposure import ConfigExposureScanner
from .a02_misconfig.default_credentials import DefaultCredentialsScanner

# ----- A03:2025 - Software Supply Chain Failures -----
from .cve.known_cve import KnownCVEScanner
from .a03_supply_chain.dependency_check import DependencyCheckScanner
from .a03_supply_chain.integrity_check import IntegrityCheckScanner
from .a03_supply_chain.outdated_components import OutdatedComponentsScanner

# ----- A04:2025 - Cryptographic Failures -----
from .a04_cryptographic.weak_crypto import WeakCryptoScanner
from .a04_cryptographic.sensitive_data_exposure import SensitiveDataExposureScanner

# ----- A05:2025 - Injection -----
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

# ----- A10:2025 - Mishandling of Exceptional Conditions -----
from .a10_exceptional_conditions.error_handling import ErrorHandlingScanner
from .a10_exceptional_conditions.fail_open import FailOpenScanner
from .a10_exceptional_conditions.resource_limits import ResourceLimitsScanner

# ----- API Security (Additional) -----
from .api_security.mass_assignment import MassAssignmentScanner
from .api_security.graphql import GraphQLScanner


# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Indicators that the target is a small / single-threaded lab environment
_LAB_TARGET_INDICATORS = (
    'juice', ':3000', ':42000', ':8080', ':8888',
    'localhost', '127.0.0.1', '192.168', '10.0', '172.16',
    'dvwa', 'webgoat', 'hackthebox', 'tryhackme',
)

# Max time (seconds) the HTTP scanning phase is allowed to run
_MAX_HTTP_PHASE_SECONDS = 15 * 60   # 15 minutes


class VulnerabilityScanner:
    """
    Main scanner orchestrator with:
    1. ALL 35+ scanners covering OWASP Top 10 2025
    2. Playwright-based XSS and SQLi detection
    3. Optimised parallel execution
    4. Auto-tuning for lab / CTF targets
    5. Early termination on high failure rates
    6. Global phase timeouts
    7. Authentication token support
    8. Database enumeration via SQLi
    """

    def __init__(self, scan_config: Dict = None):
        """
        Initialise the scanner.

        Args:
            scan_config: Configuration dict with options:
                - mode / scan_depth: 'quick', 'standard', 'owasp', 'full', 'api', 'injection', 'auth'
                - enabled_scanners:  Explicit list of scanner keys to enable
                - disabled_scanners: List of scanner keys to skip
                - parallel:          Enable parallel scanning (default: True)
                - max_concurrent_scanners: Default 8
                - max_concurrent_targets:  Default 15
                - requests_per_second:     Default 75
                - timeout:                 Default 20
                - playwright_xss:          Enable Playwright XSS   (default: True)
                - playwright_sqli:         Enable Playwright SQLi  (default: True)
                - playwright_enumerate_db: Enable DB enumeration    (default: True)
                - headless:                Headless browser mode    (default: True)
                - auth_token:              Bearer / session token
        """
        self.config = scan_config or {}
        self.scan_depth = self.config.get('scan_depth', 'normal')
        self.parallel_enabled = self.config.get('parallel', True)

        # Parallel execution settings (optimised defaults)
        self.max_concurrent_scanners = self.config.get('max_concurrent_scanners', 8)
        self.max_concurrent_targets = self.config.get('max_concurrent_targets', 15)
        self.requests_per_second = self.config.get('requests_per_second', 75)
        self.timeout = self.config.get('timeout', 20)

        # Progress callback
        self._progress_callback = None

        # ── Playwright settings ───────────────────────────────────────────
        self.playwright_xss_enabled = (
            self.config.get('playwright_xss', True) and PLAYWRIGHT_XSS_AVAILABLE
        )
        self.playwright_sqli_enabled = (
            self.config.get('playwright_sqli', True) and PLAYWRIGHT_SQLI_AVAILABLE
        )
        self.playwright_enumerate_db = self.config.get('playwright_enumerate_db', True)
        self.playwright_headless = self.config.get('headless', True)

        # ── Auth ──────────────────────────────────────────────────────────
        self._auth_token: Optional[str] = self.config.get('auth_token', None)

        # ── Database info from SQLi scanner ───────────────────────────────
        self._extracted_db_info: Optional['DatabaseInfo'] = None

        # ── Print Playwright availability ─────────────────────────────────
        if PLAYWRIGHT_XSS_AVAILABLE:
            print(f"[*] Playwright XSS Scanner: "
                  f"{'Enabled' if self.playwright_xss_enabled else 'Disabled'}")
        else:
            print("[*] Playwright XSS Scanner: Not Available (install playwright)")

        if PLAYWRIGHT_SQLI_AVAILABLE:
            print(f"[*] Playwright SQLi Scanner: "
                  f"{'Enabled' if self.playwright_sqli_enabled else 'Disabled'}")
        else:
            print("[*] Playwright SQLi Scanner: Not Available (install playwright)")

        # ══════════════════════════════════════════════════════════════════
        # ALL SCANNERS — keyed by short name
        # ══════════════════════════════════════════════════════════════════
        self.all_scanners: Dict[str, BaseScanner] = {
            # A01:2025 - Broken Access Control
            'idor':                   IDORScanner(),
            'path_traversal':         PathTraversalScanner(),
            'forced_browsing':        ForcedBrowsingScanner(),
            'privilege_escalation':   PrivilegeEscalationScanner(),
            'jwt':                    JWTVulnerabilitiesScanner(),
            'ssrf':                   SSRFScanner(),
            'csrf':                   CSRFScanner(),
            'open_redirect':          OpenRedirectScanner(),

            # A02:2025 - Security Misconfiguration
            'headers':                SecurityHeadersScanner(),
            'cors':                   CORSScanner(),
            'debug':                  DebugModeScanner(),
            'backup':                 BackupFileScanner(),
            'ssl_tls':                SSLTLSScanner(),
            'cookie_security':        CookieSecurityScanner(),
            'information_disclosure': InformationDisclosureScanner(),
            'config_exposure':        ConfigExposureScanner(),
            # 'default_creds_misconfig': DefaultCredentialsScanner(),

            # A03:2025 - Software Supply Chain Failures
            'known_cve':              KnownCVEScanner(),
            'dependency_check':       DependencyCheckScanner(),
            'integrity_check':        IntegrityCheckScanner(),
            'outdated_components':    OutdatedComponentsScanner(),

            # A04:2025 - Cryptographic Failures
            'weak_crypto':            WeakCryptoScanner(),
            'sensitive_data_exposure': SensitiveDataExposureScanner(),

            # A05:2025 - Injection
            'sqli':                   SQLInjectionScanner(),
            'nosqli':                 NoSQLInjectionScanner(),
            'cmdi':                   CommandInjectionScanner(),
            'ssti':                   SSTIScanner(),
            'ldapi':                  LDAPInjectionScanner(),
            'xpath':                  XPathInjectionScanner(),
            'hhi':                    HostHeaderInjectionScanner(),
            'xss':                    XSSScanner(),
            'dom_xss':                DOMXSSScanner(),
            'xxe':                    XXEScanner(),
            'code_injection':         CodeInjectionScanner(),
            'crlf':                   CRLFInjectionScanner(),
            'el_injection':           ELInjectionScanner(),

            # A06:2025 - Insecure Design
            'rate_limiting':          RateLimitingScanner(),
            'business_logic':         BusinessLogicScanner(),
            'clickjacking':           ClickjackingScanner(),
            'file_upload':            FileUploadScanner(),
            'http_smuggling':         HTTPSmugglingScanner(),
            'race_condition':         RaceConditionScanner(),
            'trust_boundary':         TrustBoundaryScanner(),

            # A07:2025 - Authentication Failures
            'auth_bypass':            AuthBypassScanner(),
            'brute_force':            BruteForceScanner(),
            # 'default_credentials':  DefaultCredentials07Scanner(),
            'mfa_check':              MFAScanner(),
            'session_fixation':       SessionFixationScanner(),
            'session_management':     SessionManagementScanner(),
            'weak_password':          WeakPasswordPolicyScanner(),

            # A08:2025 - Software or Data Integrity Failures
            'code_integrity':         CodeIntegrityScanner(),
            'cookie_integrity':       CookieIntegrityScanner(),
            'deserialization':        InsecureDeserializationScanner(),

            # A09:2025 - Security Logging and Alerting Failures
            'log_injection':          LogInjectionScanner(),
            'sensitive_log_data':     SensitiveLogDataScanner(),
            'log_file_exposure':      LogFileExposureScanner(),
            'insufficient_logging':   InsufficientLoggingScanner(),
            'alert_detection':        AlertDetectionScanner(),

            # A10:2025 - Mishandling of Exceptional Conditions
            'error_handling':         ErrorHandlingScanner(),
            'fail_open':              FailOpenScanner(),
            'resource_limits':        ResourceLimitsScanner(),

            # API Security (Additional)
            'graphql':                GraphQLScanner(),
            'mass_assignment':        MassAssignmentScanner(),
        }

        print(f"[*] Initialised {len(self.all_scanners)} scanners (OWASP 2025)")

        # ══════════════════════════════════════════════════════════════════
        # SCAN MODE PRESETS
        # ══════════════════════════════════════════════════════════════════
        self.scan_modes = {
            'quick': [
                'sqli', 'xss', 'headers', 'cors', 'ssl_tls',
            ],
            'standard': [
                'sqli', 'nosqli', 'xss', 'cmdi', 'ssti',
                'headers', 'cors', 'idor', 'path_traversal',
                'ssrf', 'ssl_tls', 'jwt', 'rate_limiting',
                'information_disclosure', 'cookie_security',
                'error_handling',
            ],
            'owasp': [
                'sqli', 'nosqli', 'xss', 'dom_xss', 'cmdi', 'ssti', 'xxe',
                'idor', 'path_traversal', 'forced_browsing', 'jwt',
                'ssl_tls', 'weak_crypto', 'sensitive_data_exposure',
                'headers', 'cors', 'debug', 'backup', 'cookie_security',
                'rate_limiting', 'session_fixation', 'deserialization',
                'ssrf', 'known_cve', 'error_handling',
            ],
            'full': list(self.all_scanners.keys()),
            'api': [
                'sqli', 'nosqli', 'cmdi', 'ssrf', 'xxe',
                'idor', 'jwt', 'rate_limiting', 'cors',
                'mass_assignment', 'graphql', 'headers',
                'deserialization', 'information_disclosure',
            ],
            'injection': [
                'sqli', 'nosqli', 'xss', 'dom_xss', 'cmdi',
                'ssti', 'ldapi', 'xpath', 'hhi', 'xxe',
                'code_injection', 'crlf', 'el_injection',
            ],
            'auth': [
                'jwt', 'session_fixation', 'session_management',
                'brute_force', 'weak_password', 'auth_bypass',
                'mfa_check', 'idor', 'privilege_escalation',
            ],
        }

        # Select active scanners
        self.active_scanners: Dict[str, BaseScanner] = self._select_scanners()

        # Initialise parallel executor
        self.executor = ParallelScanExecutor(
            max_concurrent_scanners=self.max_concurrent_scanners,
            max_concurrent_targets=self.max_concurrent_targets,
            max_requests_per_second=self.requests_per_second,
            timeout_per_scan=self.timeout,
        )

        # ── Metrics ───────────────────────────────────────────────────────
        self.metrics: Dict = {
            'total_tasks':              0,
            'completed_tasks':          0,
            'failed_tasks':             0,
            'total_duration':           0.0,
            'playwright_xss_findings':  0,
            'playwright_sqli_findings': 0,
            'auth_bypass_findings':     0,
            'database_enumerated':      False,
            'tables_extracted':         0,
            'data_extracted':           False,
            'owasp_coverage':           self._calculate_owasp_coverage(),
        }

    # ══════════════════════════════════════════════════════════════════════
    # CONFIGURATION HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def _select_scanners(self) -> Dict[str, BaseScanner]:
        """Select scanners based on config."""
        enabled = self.config.get('enabled_scanners')
        disabled = self.config.get('disabled_scanners', [])
        mode = self.config.get('mode', self.scan_depth)

        if enabled:
            return {k: v for k, v in self.all_scanners.items() if k in enabled}

        if mode in self.scan_modes:
            scanner_list = self.scan_modes[mode]
        else:
            scanner_list = self.scan_modes['standard']

        scanner_list = [s for s in scanner_list if s not in disabled]
        return {k: v for k, v in self.all_scanners.items() if k in scanner_list}

    def set_progress_callback(self, callback):
        """Set callback: callback(completed, total, message)."""
        self._progress_callback = callback
        if self.executor:
            self.executor.set_progress_callback(callback)

    def set_auth_token(self, token: str):
        """Set authentication token for authenticated scanning."""
        self._auth_token = token

    # ══════════════════════════════════════════════════════════════════════
    # OWASP COVERAGE
    # ══════════════════════════════════════════════════════════════════════

    _OWASP_MAPPING = {
        'A01': [
            'idor', 'path_traversal', 'forced_browsing',
            'privilege_escalation', 'jwt', 'ssrf', 'csrf', 'open_redirect',
        ],
        'A02': [
            'headers', 'cors', 'debug', 'backup', 'ssl_tls',
            'cookie_security', 'information_disclosure', 'config_exposure',
            'default_creds_misconfig',
        ],
        'A03': [
            'known_cve', 'dependency_check', 'integrity_check',
            'outdated_components',
        ],
        'A04': ['weak_crypto', 'sensitive_data_exposure'],
        'A05': [
            'sqli', 'nosqli', 'xss', 'dom_xss', 'cmdi', 'ssti',
            'ldapi', 'xpath', 'hhi', 'xxe', 'code_injection',
            'crlf', 'el_injection',
        ],
        'A06': [
            'rate_limiting', 'business_logic', 'clickjacking',
            'file_upload', 'http_smuggling', 'race_condition',
            'trust_boundary',
        ],
        'A07': [
            'session_fixation', 'weak_password', 'brute_force',
            'auth_bypass', 'default_credentials', 'mfa_check',
            'session_management',
        ],
        'A08': ['deserialization', 'code_integrity', 'cookie_integrity'],
        'A09': [
            'log_injection', 'sensitive_log_data', 'log_file_exposure',
            'insufficient_logging', 'alert_detection',
        ],
        'A10': ['error_handling', 'fail_open', 'resource_limits'],
    }

    _OWASP_NAMES = {
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

    def _calculate_owasp_coverage(self) -> Dict:
        active_names = set(self.active_scanners.keys())
        coverage = {}
        for cat, scanners in self._OWASP_MAPPING.items():
            total = len(scanners)
            covered = len(set(scanners) & active_names)
            coverage[cat] = {
                'covered': covered,
                'total': total,
                'percentage': round((covered / total) * 100) if total else 0,
            }
        return coverage

    def _print_owasp_coverage(self):
        coverage = self._calculate_owasp_coverage()
        print("[*] OWASP 2025 Coverage:")
        for cat_id, data in coverage.items():
            name = self._OWASP_NAMES.get(cat_id, cat_id)
            pct = data['percentage']
            bar = '█' * (pct // 10) + '░' * (10 - pct // 10)
            status = '✓' if pct >= 50 else '○'
            print(f"  {status} {cat_id}: {name:<22} [{bar}] {pct:>3}%")
        print()

    def _print_findings_by_owasp(self, vulns: List[Vulnerability]):
        if not vulns:
            return
        print(f"\n  Findings by OWASP 2025 Category:")
        by_cat: Dict[str, Dict[str, int]] = {}
        for vuln in vulns:
            owasp = getattr(vuln, 'owasp_category', None)
            cat_val = owasp.value if owasp and hasattr(owasp, 'value') else 'Other'
            cat_id = cat_val.split(':')[0] if ':' in cat_val else 'Other'
            if cat_id not in by_cat:
                by_cat[cat_id] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev in by_cat[cat_id]:
                by_cat[cat_id][sev] += 1
        for cat_id in sorted(by_cat):
            c = by_cat[cat_id]
            total = sum(c.values())
            parts = []
            if c['critical']: parts.append(f"🔴{c['critical']}")
            if c['high']:     parts.append(f"🟠{c['high']}")
            if c['medium']:   parts.append(f"🟡{c['medium']}")
            if c['low']:      parts.append(f"🔵{c['low']}")
            print(f"    {cat_id}: {total} findings ({' '.join(parts)})")

    # ══════════════════════════════════════════════════════════════════════
    # SCANNER CATEGORISATION
    # ══════════════════════════════════════════════════════════════════════

    # Scanners that run ONCE against the base URL (not per-parameter)
    _SITE_SCANNER_NAMES = frozenset([
        'headers', 'cors', 'ssl_tls', 'debug', 'backup',
        'cookie_security', 'information_disclosure',
        'known_cve', 'dependency_check', 'outdated_components',
        'weak_crypto', 'sensitive_data_exposure',
        'rate_limiting',
        'log_file_exposure', 'insufficient_logging', 'alert_detection',
        'error_handling', 'fail_open', 'resource_limits',
        'graphql',
        'default_creds_misconfig', 'default_credentials',
        'config_exposure', 'integrity_check',
    ])

    def _get_active_site_scanners(self) -> Dict[str, BaseScanner]:
        return {k: v for k, v in self.active_scanners.items()
                if k in self._SITE_SCANNER_NAMES}

    def _get_active_param_scanners(self) -> Dict[str, BaseScanner]:
        return {k: v for k, v in self.active_scanners.items()
                if k not in self._SITE_SCANNER_NAMES}

    # ══════════════════════════════════════════════════════════════════════
    # TECH STACK AUTO-DETECTION
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    async def _detect_tech_stack(crawl_results: Dict) -> List[str]:
        """Auto-detect technology stack from crawl results."""
        tech: List[str] = []
        urls_data = crawl_results.get('urls', {})

        test_url = None
        url_data: Dict = {}
        if isinstance(urls_data, dict):
            keys = list(urls_data.keys())
            if keys:
                test_url = keys[0]
                url_data = urls_data[test_url] if isinstance(urls_data[test_url], dict) else {}
        elif isinstance(urls_data, list) and urls_data:
            test_url = urls_data[0]

        if not test_url:
            return tech

        # Detect from headers
        headers = url_data.get('headers', {})
        server = headers.get('Server', '').lower()
        if 'nginx' in server:     tech.append('Nginx')
        elif 'apache' in server:  tech.append('Apache')
        elif 'iis' in server:     tech.append('IIS')

        xpb = headers.get('X-Powered-By', '').lower()
        if 'php' in xpb:          tech.append('PHP')
        elif 'asp.net' in xpb:    tech.extend(['ASP.NET', 'MSSQL'])

        # URL pattern detection
        if '.php' in test_url:
            tech.extend(x for x in ['PHP', 'MySQL'] if x not in tech)
        elif '.jsp' in test_url:
            if 'Java' not in tech: tech.append('Java')
        elif '.aspx' in test_url or '.asp' in test_url:
            tech.extend(x for x in ['ASP.NET', 'MSSQL'] if x not in tech)

        # Juice Shop / Node.js detection
        if 'juice' in test_url.lower() or ':3000' in test_url or ':42000' in test_url:
            tech.extend(x for x in ['Node.js', 'SQLite', 'Angular'] if x not in tech)

        return tech

    # ══════════════════════════════════════════════════════════════════════
    # PLAYWRIGHT SCANNER METHODS
    # ══════════════════════════════════════════════════════════════════════

    async def _run_playwright_xss(
        self, crawl_results: Dict, base_url: str,
    ) -> List[Vulnerability]:
        if not PLAYWRIGHT_XSS_AVAILABLE or not base_url:
            return []
        try:
            print(f"\n[Playwright XSS] Starting browser-based XSS scan...")
            scanner = PlaywrightXSSScanner(headless=self.playwright_headless)
            vulns = await scanner.scan_with_browser(
                base_url=base_url,
                forms=crawl_results.get('forms', []),
                urls=crawl_results.get('urls', {}),
                auth_token=self._auth_token,
            )
            self.metrics['playwright_xss_findings'] = len(vulns)
            if vulns:
                print(f"[Playwright XSS] Found {len(vulns)} XSS vulnerabilities")
            else:
                print(f"[Playwright XSS] Scan complete (no XSS found)")
            return vulns
        except Exception as e:
            print(f"[Playwright XSS] Error: {str(e)[:120]}")
            return []

    async def _run_playwright_sqli(
        self, crawl_results: Dict, base_url: str,
    ) -> Tuple[List[Vulnerability], Optional['DatabaseInfo']]:
        if not PLAYWRIGHT_SQLI_AVAILABLE or not base_url:
            return [], None
        try:
            print(f"\n[Playwright SQLi] Starting browser-based SQLi scan...")
            scanner = PlaywrightSQLiScanner(
                headless=self.playwright_headless, verbose=True,
            )
            urls_with_params: List[str] = []
            urls_data = crawl_results.get('urls', {})
            url_iter = urls_data.keys() if isinstance(urls_data, dict) else urls_data
            for u in url_iter:
                if '?' in str(u):
                    urls_with_params.append(str(u))

            vulns, db_info = await scanner.scan_with_browser(
                base_url=base_url,
                forms=crawl_results.get('forms', []),
                urls_with_params=urls_with_params,
                auth_token=self._auth_token,
                enumerate_db=self.playwright_enumerate_db,
            )
            self.metrics['playwright_sqli_findings'] = len(vulns)
            auth_bypasses = sum(
                1 for v in vulns
                if 'auth' in v.vuln_type.lower() or 'bypass' in v.vuln_type.lower()
            )
            self.metrics['auth_bypass_findings'] = auth_bypasses
            if db_info:
                self.metrics['database_enumerated'] = True
                self.metrics['tables_extracted'] = len(db_info.tables)
                self.metrics['data_extracted'] = bool(db_info.extracted_data)
                self._extracted_db_info = db_info
            if vulns:
                print(f"[Playwright SQLi] Found {len(vulns)} SQL Injection vulnerabilities")
                if auth_bypasses:
                    print(f"[Playwright SQLi]   - {auth_bypasses} authentication bypass(es)")
                if db_info:
                    print(f"[Playwright SQLi]   - Database: {db_info.db_type.value}")
                    if db_info.tables:
                        print(f"[Playwright SQLi]   - Extracted {len(db_info.tables)} table names")
                    if db_info.extracted_data:
                        print(f"[Playwright SQLi]   - Extracted data from "
                              f"{len(db_info.extracted_data)} tables")
            else:
                print(f"[Playwright SQLi] Scan complete (no SQLi found)")
            return vulns, db_info
        except Exception as e:
            print(f"[Playwright SQLi] Error: {str(e)[:120]}")
            import traceback
            traceback.print_exc()
            return [], None

    async def _run_all_playwright_scanners(
        self, crawl_results: Dict, base_url: str,
    ) -> List[Vulnerability]:
        """
        Run Playwright scanners SEQUENTIALLY to avoid overwhelming single-
        threaded targets.  Order: SQLi first (faster), then XSS.
        """
        all_vulns: List[Vulnerability] = []

        # ── SQLi ──────────────────────────────────────────────────────────
        if self.playwright_sqli_enabled and 'sqli' in self.active_scanners:
            print(f"\n[Playwright] Running SQLi scanner...")
            vulns, _ = await self._run_playwright_sqli(crawl_results, base_url)
            all_vulns.extend(vulns)

        # Brief cooldown between scanners
        if self.playwright_xss_enabled and 'xss' in self.active_scanners:
            print(f"[Playwright] Cooldown 2 s before XSS scanner...")
            await asyncio.sleep(2)

        # ── XSS ───────────────────────────────────────────────────────────
        if self.playwright_xss_enabled and 'xss' in self.active_scanners:
            print(f"\n[Playwright] Running XSS scanner...")
            vulns = await self._run_playwright_xss(crawl_results, base_url)
            all_vulns.extend(vulns)

        return all_vulns

    # ══════════════════════════════════════════════════════════════════════
    # AUTO-TUNING
    # ══════════════════════════════════════════════════════════════════════

    def _auto_tune_for_target(self, base_url: str):
        """
        Reduce concurrency and timeout for lab / CTF targets that cannot
        handle heavy concurrent load (e.g. Juice Shop, DVWA, WebGoat).
        """
        lower = base_url.lower()
        if not any(ind in lower for ind in _LAB_TARGET_INDICATORS):
            return

        prev_targets = self.executor.max_concurrent_targets
        prev_rps = self.executor.max_requests_per_second
        prev_timeout = self.executor.timeout_per_scan

        self.executor.max_concurrent_targets = min(5, prev_targets)
        self.executor.max_requests_per_second = min(20.0, prev_rps)
        self.executor.timeout_per_scan = min(10.0, prev_timeout)

        print(
            f"[*] Auto-tuned for lab target: "
            f"targets={self.executor.max_concurrent_targets} "
            f"(was {prev_targets}), "
            f"rps={self.executor.max_requests_per_second} "
            f"(was {prev_rps}), "
            f"timeout={self.executor.timeout_per_scan}s "
            f"(was {prev_timeout}s)"
        )

    # ══════════════════════════════════════════════════════════════════════
    # MAIN SCANNING METHOD
    # ══════════════════════════════════════════════════════════════════════

    async def scan_target(self, crawl_results: Dict) -> List[Vulnerability]:
        """
        Main async scanning method.

        Args:
            crawl_results: Results from the crawler.

        Returns:
            Deduplicated, severity-sorted list of vulnerabilities.
        """
        print(f"\n{'=' * 60}")
        print(f"  VulnFlow Scanner (No AI)")
        print(f"  OWASP Version: Top 10 2025")
        print(f"  Active Scanners: {len(self.active_scanners)}")
        print(f"  Total Available: {len(self.all_scanners)}")
        print(f"  Parallel Workers: {self.max_concurrent_scanners}")
        print(f"  Playwright XSS: "
              f"{'Enabled' if self.playwright_xss_enabled else 'Disabled'}")
        print(f"  Playwright SQLi: "
              f"{'Enabled' if self.playwright_sqli_enabled else 'Disabled'}")
        print(f"{'=' * 60}\n")

        self._print_owasp_coverage()

        start_time = time.time()

        # ── Validate crawl results ────────────────────────────────────────
        if not crawl_results:
            print("❌ Error: No crawl results provided")
            return []

        crawl_results.setdefault('urls', {})
        crawl_results.setdefault('forms', [])

        urls_count = len(crawl_results['urls'])
        forms_count = len(crawl_results['forms'])

        if urls_count == 0 and forms_count == 0:
            print("⚠️  Warning: No URLs or forms found to scan")
            return []

        print(f"[*] Crawl results: {urls_count} URLs, {forms_count} forms")

        # ── Auto-detect tech stack ────────────────────────────────────────
        print(f"\n[*] Auto-detecting tech stack...")
        tech_stack = await self._detect_tech_stack(crawl_results)
        if tech_stack:
            print(f"  ✓ Detected: {', '.join(tech_stack)}")
        else:
            tech_stack = ['PHP', 'MySQL', 'Apache']
            print(f"  ⚠️  Could not detect — using default: {', '.join(tech_stack)}")

        # ── Prepare targets ───────────────────────────────────────────────
        targets = self._prepare_targets(crawl_results)
        base_url = self._get_base_url(crawl_results)

        if not targets:
            print("⚠️  Warning: No valid targets prepared for scanning")
            # Even with no targets, Playwright + site scanners can still run
            if not base_url:
                return []

        print(f"[*] Prepared {len(targets)} targets for scanning")

        # ── Auto-tune for lab targets ─────────────────────────────────────
        if base_url:
            self._auto_tune_for_target(base_url)

        # ── Scanner categorisation ────────────────────────────────────────
        site_scanners = self._get_active_site_scanners()
        param_scanners = self._get_active_param_scanners()

        site_scanners_list = list(site_scanners.items())
        param_scanners_list = list(param_scanners.items())

        # ══════════════════════════════════════════════════════════════════
        # PHASE 1 — Playwright scanners (sequential, before HTTP load)
        # ══════════════════════════════════════════════════════════════════
        playwright_enabled = (
            (self.playwright_xss_enabled and 'xss' in self.active_scanners)
            or (self.playwright_sqli_enabled and 'sqli' in self.active_scanners)
        )

        playwright_vulns: List[Vulnerability] = []
        if playwright_enabled:
            print(f"\n[*] Phase 1: Playwright browser-based scanners...")
            try:
                playwright_vulns = await self._run_all_playwright_scanners(
                    crawl_results, base_url,
                )
            except Exception as e:
                print(f"  [!] Playwright scan error: {e}")

            print(f"[*] Playwright scanners found: {len(playwright_vulns)} issues")
            print(f"[*] Waiting 3 s for target to recover before HTTP scans...")
            await asyncio.sleep(3)

        # ══════════════════════════════════════════════════════════════════
        # PHASE 2 — HTTP scanners (parallel, with global timeout)
        # ══════════════════════════════════════════════════════════════════
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self.executor.max_concurrent_targets * 3,
            limit_per_host=self.executor.max_concurrent_targets,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True,
        )
        session_timeout = aiohttp.ClientTimeout(
            total=self.executor.timeout_per_scan * 2, connect=5,
        )

        http_vulns: List[Vulnerability] = []

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=session_timeout,
            headers={
                'User-Agent': 'VulnFlow/3.0 Security Scanner (OWASP 2025)',
                'Accept': '*/*',
            },
        ) as session:

            print(f"\n[*] Phase 2: HTTP scanners "
                  f"({len(site_scanners_list)} site + "
                  f"{len(param_scanners_list)} param × "
                  f"{len(targets)} targets)...")

            http_task = asyncio.create_task(
                self.executor.execute_all_scans(
                    session,
                    targets,
                    site_scanners_list,
                    param_scanners_list,
                    base_url,
                )
            )

            try:
                http_vulns = await asyncio.wait_for(
                    http_task, timeout=_MAX_HTTP_PHASE_SECONDS,
                )
            except asyncio.TimeoutError:
                print(
                    f"\n  [!] HTTP scanning hit "
                    f"{_MAX_HTTP_PHASE_SECONDS // 60}min global timeout — "
                    f"collecting partial results..."
                )
                http_task.cancel()
                try:
                    await http_task
                except (asyncio.CancelledError, Exception):
                    pass
                http_vulns = []
            except Exception as e:
                print(f"  [!] HTTP scan error: {e}")

        print(f"\n[*] HTTP scanners found: {len(http_vulns)} issues")

        # ══════════════════════════════════════════════════════════════════
        # COMBINE + DEDUPLICATE + SORT
        # ══════════════════════════════════════════════════════════════════
        raw = playwright_vulns + http_vulns
        print(f"[*] Total findings: {len(raw)} potential issues")

        unique_vulns = self._deduplicate(raw)

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))

        # ── Update metrics ────────────────────────────────────────────────
        self.metrics.update(self.executor.stats)
        self.metrics['owasp_coverage'] = self._calculate_owasp_coverage()

        elapsed = time.time() - start_time

        print(f"\n{'=' * 60}")
        print(f"  Scan Complete in {elapsed:.2f}s")
        print(f"  Validated Vulnerabilities: {len(unique_vulns)}")
        print(f"  Playwright XSS Findings: {self.metrics['playwright_xss_findings']}")
        print(f"  Playwright SQLi Findings: {self.metrics['playwright_sqli_findings']}")
        if self.metrics['auth_bypass_findings']:
            print(f"  Auth Bypass Findings: {self.metrics['auth_bypass_findings']}")
        if self.metrics['database_enumerated']:
            print(f"  Database Enumerated: Yes")
            print(f"    Tables Found: {self.metrics['tables_extracted']}")
            print(f"    Data Extracted: "
                  f"{'Yes' if self.metrics['data_extracted'] else 'No'}")
        self._print_findings_by_owasp(unique_vulns)
        print(f"{'=' * 60}\n")

        return unique_vulns

    # ══════════════════════════════════════════════════════════════════════
    # TARGET PREPARATION
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _prepare_targets(crawl_results: Dict) -> List[Dict]:
        """Prepare scan targets from crawl results."""
        targets: List[Dict] = []

        # URL-based targets
        urls_data = crawl_results.get('urls', {})
        url_list = (
            list(urls_data.keys()) if isinstance(urls_data, dict)
            else list(urls_data) if isinstance(urls_data, list)
            else []
        )

        for url in url_list:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if query_params:
                for param in query_params:
                    targets.append({
                        'url': url,
                        'params': param,
                        'type': 'query',
                    })
            else:
                targets.append({
                    'url': url,
                    'params': None,
                    'type': 'page',
                })

        # Form-based targets
        for form_data in crawl_results.get('forms', []):
            for inp in form_data.get('inputs', []):
                if inp.get('name'):
                    targets.append({
                        'url': form_data['action'],
                        'params': inp['name'],
                        'type': 'form',
                        'method': form_data.get('method', 'GET'),
                        'form_data': form_data,
                    })

        return targets

    @staticmethod
    def _get_base_url(crawl_results: Dict) -> str:
        """Extract base URL from crawl results with multiple fallbacks."""
        # Try urls dict/list
        urls_data = crawl_results.get('urls')
        if urls_data:
            if isinstance(urls_data, dict):
                keys = list(urls_data.keys())
                if keys:
                    p = urlparse(keys[0])
                    return f"{p.scheme}://{p.netloc}"
            elif isinstance(urls_data, list) and urls_data:
                p = urlparse(urls_data[0])
                return f"{p.scheme}://{p.netloc}"

        # Try explicit base_url / target keys
        for key in ('base_url', 'target'):
            val = crawl_results.get(key)
            if val:
                p = urlparse(val)
                return f"{p.scheme}://{p.netloc}"

        # Try forms
        forms = crawl_results.get('forms', [])
        if forms:
            action = forms[0].get('action', '')
            if action:
                p = urlparse(action)
                if p.netloc:
                    return f"{p.scheme}://{p.netloc}"

        return ""

    # ══════════════════════════════════════════════════════════════════════
    # DEDUPLICATION
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _deduplicate(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique: List[Vulnerability] = []
        for vuln in vulnerabilities:
            key = (
                vuln.vuln_type,
                vuln.url,
                vuln.parameter,
                vuln.payload[:50] if vuln.payload else '',
            )
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        return unique

    # ══════════════════════════════════════════════════════════════════════
    # PUBLIC ACCESSORS
    # ══════════════════════════════════════════════════════════════════════

    def get_extracted_database_info(self) -> Optional[Dict]:
        """Get database info extracted during SQLi scanning."""
        if self._extracted_db_info:
            return self._extracted_db_info.to_dict()
        return None

    def get_scanner_info(self) -> Dict:
        """Get information about all available scanners."""
        return {
            name: {
                'name': scanner.name,
                'description': scanner.description,
                'owasp_category': scanner.owasp_category.value,
                'active': name in self.active_scanners,
            }
            for name, scanner in self.all_scanners.items()
        }

    def get_execution_stats(self) -> Dict:
        """Get combined execution statistics."""
        return {
            **self.metrics,
            'executor_stats': self.executor.stats if self.executor else {},
            'owasp_coverage': self._calculate_owasp_coverage(),
        }

    def get_metrics(self) -> Dict:
        """Alias for get_execution_stats (API compatibility with enhanced scanner)."""
        return self.get_execution_stats()

    def get_available_scan_modes(self) -> Dict[str, List[str]]:
        return dict(self.scan_modes)

    def get_owasp_mapping(self) -> Dict[str, List[str]]:
        return {
            f"{cat_id}:2025 - {self._OWASP_NAMES.get(cat_id, cat_id)}": scanners
            for cat_id, scanners in self._OWASP_MAPPING.items()
        }

    def shutdown(self):
        """Clean shutdown."""
        if self.executor:
            self.executor.shutdown()