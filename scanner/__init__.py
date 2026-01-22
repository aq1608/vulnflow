# scanner/__init__.py
"""
VulnFlow Scanner Module

Comprehensive vulnerability scanning covering OWASP Top 10

Provides parallel vulnerability scanning with multiple scanner types.
"""

from .base import BaseScanner, Vulnerability, Severity, OWASPCategory
from .enhanced_vuln_scanner import EnhancedVulnerabilityScanner  # ✅ ADDED: AI-enhanced scanner
from .vuln_scanner import VulnerabilityScanner
from .parallel_executor import ParallelScanExecutor, ScanWorkerPool, RateLimiter
from .scheduler import ScanScheduler, TaskPriority, get_scanner_priority
from .async_utils import (
    AsyncBatcher,
    AsyncRetry,
    AsyncTimeout,
    TaskQueue,
    gather_with_concurrency,
    ScanMetrics,
    ConnectionPool,
    HostRateLimiter,
    CircuitBreaker,
    async_map,
    chunk_list
)

# Import all scanner classes for direct access
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

__all__ = [
    # Core
    'BaseScanner',
    'Vulnerability', 
    'Severity',
    'OWASPCategory',
    'VulnerabilityScanner',
    'EnhancedVulnerabilityScanner',  # ✅ ADDED
    
    # Parallel execution
    'ParallelScanExecutor',
    'ScanWorkerPool',
    'RateLimiter',
    
    # Scheduling
    'ScanScheduler',
    'TaskPriority',
    'get_scanner_priority',
    
    # Utilities
    'AsyncBatcher',
    'AsyncRetry',
    'AsyncTimeout',
    'TaskQueue',
    'gather_with_concurrency',
    'ScanMetrics',
    'ConnectionPool',
    'HostRateLimiter',
    'CircuitBreaker',
    'async_map',
    'chunk_list',

    # Individual scanners
    'SQLInjectionScanner',
    'NoSQLInjectionScanner',
    'CommandInjectionScanner',
    'SSTIScanner',
    'XSSScanner',
    'IDORScanner',
    'PathTraversalScanner',
    'JWTVulnerabilitiesScanner',
    'SecurityHeadersScanner',
    'CORSScanner',
    'SSLTLSScanner',
    'SSRFScanner',
    'XXEScanner',
    'InsecureDeserializationScanner',
    'GraphQLScanner',
    'RateLimitingScanner',
]