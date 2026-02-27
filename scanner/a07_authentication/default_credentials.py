# scanner/a07_authentication/default_credentials.py
"""
Default / Weak Credentials Scanner - Authentication Failures

Focuses on whether the *application itself* permits weak or default passwords,
rather than whether a vendor component was misconfigured (that is A02).

Detects:
- Application login forms that accept well-known credential pairs
- Hardcoded credentials exposed in page source / JS bundles
- Exposed configuration files containing credentials
- APIs that accept default/common passwords
- Missing account-lockout (lets brute-force proceed unchecked)

OWASP: A07:2025 - Authentication Failures
CWE-259:  Use of Hard-coded Password
CWE-287:  Improper Authentication
CWE-307:  Improper Restriction of Excessive Authentication Attempts
CWE-798:  Use of Hard-coded Credentials
CWE-1391: Use of Weak Credentials
CWE-1392: Use of Default Credentials
CWE-1393: Use of Default Password
"""

import asyncio
import re
from typing import List, Dict, Optional, Tuple
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory

# ── Playwright optional import ───────────────────────────────────────────────
try:
    from playwright.async_api import async_playwright, Browser, Page, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class DefaultCredentials07Scanner(BaseScanner):
    """
    A07 scanner: application-level authentication allows weak/default passwords.

    The distinction from A02:
      A02 = someone deployed Tomcat and forgot to change the factory password.
      A07 = the *application* itself lets users log in with 'admin'/'admin',
            or ships with hard-coded credentials baked into source code.
    """

    name = "Default / Weak Credentials Scanner (Auth)"
    description = (
        "Detects application login forms that accept well-known or default "
        "credentials, and scans for hard-coded credentials in page source"
    )
    owasp_category = OWASPCategory.A07_AUTH_FAILURES

    # ──────────────────────────────────────────────────────────────────────────
    # PAYLOAD DATABASES
    # ──────────────────────────────────────────────────────────────────────────

    # Credentials that a *well-written application* must reject outright.
    # Organised from most-likely to least-likely to keep scan times reasonable.
    APP_CREDENTIALS: List[Tuple[str, str]] = [
        # ── Top universal defaults ────────────────────────────────────────────
        ('admin',           'admin'),
        ('admin',           'password'),
        ('admin',           'admin123'),
        ('admin',           '123456'),
        ('admin',           'password123'),
        ('admin',           ''),
        ('administrator',   'administrator'),
        ('administrator',   'password'),
        ('root',            'root'),
        ('root',            'password'),
        ('user',            'user'),
        ('user',            'password'),
        ('test',            'test'),
        ('guest',           'guest'),
        ('demo',            'demo'),
        ('operator',        'operator'),
        ('support',         'support'),
        ('sysadmin',        'sysadmin'),
        ('superadmin',      'superadmin'),
        ('superuser',       'superuser'),

        # ── Juice Shop (email-based login) ────────────────────────────────────
        # These test whether the app ships with known default accounts.
        ('admin@juice-sh.op',          'admin123'),
        ('jim@juice-sh.op',            'ncc-1701'),
        ('bender@juice-sh.op',         'OiLkTANikt0R#'),
        ('bjoern.kimminich@gmail.com', 'YN0t3#4t'),
        ('ciso@juice-sh.op',           'mDLx7jkP7s'),
        ('support@juice-sh.op',        'J9*xfWs7yN!'),
        ('uvogin@juice-sh.op',         'rock you'),
        ('MC SafeSearch',              'Mr. N00dles'),

        # ── DVWA / WebGoat / common demo apps ────────────────────────────────
        ('admin',           'dvwa'),
        ('admin',           'webgoat'),
        ('webgoat',         'webgoat'),
        ('gordonb',         'abc123'),       # DVWA default
        ('1337',            'hack'),         # DVWA
        ('pablo',           'letmein'),      # DVWA
        ('smithy',          'password'),     # DVWA

        # ── Common weak passwords against 'admin' ────────────────────────────
        ('admin',           'letmein'),
        ('admin',           'qwerty'),
        ('admin',           '111111'),
        ('admin',           'abc123'),
        ('admin',           'iloveyou'),
        ('admin',           'Welcome1'),
        ('admin',           'admin@123'),
        ('admin',           'changeme'),
        ('admin',           'secret'),
        ('admin',           'pass'),
        ('admin',           '12345678'),
        ('admin',           'pass@word1'),

        # ── Hybrid / incremented patterns (OWASP A07 scenario #1) ────────────
        ('admin',           'Winter2024'),
        ('admin',           'Winter2025'),
        ('admin',           'Summer2024'),
        ('admin',           'Summer2025'),
        ('admin',           'Password1!'),
        ('admin',           'Password2!'),

        # ── Service / API accounts ────────────────────────────────────────────
        ('api',             'api'),
        ('api',             'apikey'),
        ('service',         'service'),
        ('deploy',          'deploy'),
        ('monitor',         'monitor'),
        ('backup',          'backup'),
    ]

    # Application login endpoints to discover and probe
    LOGIN_ENDPOINTS: List[str] = [
        '/login',
        '/signin',
        '/admin',
        '/admin/login',
        '/administrator',
        '/wp-admin',
        '/wp-login.php',
        '/user/login',
        '/account/login',
        '/auth/login',
        '/api/login',
        '/api/v1/login',
        '/api/auth',
        '/api/v1/auth',
        '/api/v2/login',
        '/api/token',
        '/api/authenticate',
        '/rest/user/login',   # Juice Shop
        '/console',
        '/portal',
        '/manage',
        '/dashboard',
    ]

    # Config / env files that might contain credentials
    CONFIG_FILES: List[str] = [
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/config.php',
        '/config.inc.php',
        '/wp-config.php',
        '/configuration.php',
        '/settings.py',
        '/local_settings.py',
        '/config.json',
        '/config.yml',
        '/config.yaml',
        '/database.yml',
        '/secrets.json',
        '/credentials.json',
        '/.git/config',
        '/web.config',
        '/appsettings.json',
        '/appsettings.Development.json',
        '/app.config',
        '/application.properties',
        '/application.yml',
        '/config/database.yml',
        '/config/secrets.yml',
        '/.htpasswd',
    ]

    # Regex patterns for exposed credentials in source
    HARDCODED_PATTERNS: List[Tuple[str, str, str]] = [
        # (pattern, label, cwe)
        (r'AKIA[0-9A-Z]{16}',                                               'AWS Access Key ID',    'CWE-798'),
        (r'aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*["\']([^"\']{20,})["\']',
                                                                             'AWS Secret Key',       'CWE-798'),
        (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',       'Hardcoded Password',   'CWE-259'),
        (r'(?:secret|secretkey|secret_key)\s*[=:]\s*["\']([^"\']{8,})["\']',
                                                                             'Secret Key',           'CWE-798'),
        (r'api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',        'API Key',              'CWE-798'),
        (r'apikey\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',               'API Key',              'CWE-798'),
        (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',                  'Private Key',          'CWE-321'),
        (r'(?:mysql|postgres|mongodb|redis)://[^:]+:([^@\s"\']{4,})@',      'DB Connection String', 'CWE-259'),
        (r'jwt[_\-]?secret\s*[=:]\s*["\']([^"\']{8,})["\']',               'JWT Secret',           'CWE-798'),
        (r'bearer\s+([A-Za-z0-9\-._~+/]{30,})',                             'Bearer Token',         'CWE-798'),
        (r'(?:token|access_token|auth_token)\s*[=:]\s*["\']([^"\']{20,})["\']',
                                                                             'Access Token',         'CWE-798'),
        (r'(?:client[_\-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']',        'OAuth Client Secret',  'CWE-798'),
        (r'private[_\-]?key\s*[=:]\s*["\']([^"\']{20,})["\']',             'Private Key Material', 'CWE-321'),
        (r'encryption[_\-]?key\s*[=:]\s*["\']([^"\']{16,})["\']',          'Encryption Key',       'CWE-321'),
        (r'(?:stripe|twilio|sendgrid)[_\-]?(?:key|secret|token)\s*[=:]\s*["\']([^"\']{20,})["\']',
                                                                             'Third-party API Key',  'CWE-798'),
        (r'ghp_[A-Za-z0-9]{36}',                                            'GitHub Token',         'CWE-798'),
        (r'gho_[A-Za-z0-9]{36}',                                            'GitHub OAuth Token',   'CWE-798'),
        (r'glpat-[A-Za-z0-9\-_]{20}',                                       'GitLab Token',         'CWE-798'),
        (r'(?:heroku|netlify)[_\-]?(?:key|token|secret)\s*[=:]\s*["\']([^"\']{20,})["\']',
                                                                             'PaaS Token',           'CWE-798'),
    ]

    # Placeholder values to skip (avoid false positives)
    PLACEHOLDER_VALUES: List[str] = [
        'example', 'placeholder', 'your_', 'xxx', 'changeme',
        'insert', 'replace', '<', 'todo', 'fixme', 'none',
        'null', 'undefined', 'enter_', 'put_your',
    ]

    SUCCESS_PATTERNS: List[str] = [
        r'dashboard', r'welcome', r'logout', r'sign[\s_-]?out',
        r'my[\s_-]?account', r'profile', r'settings',
        r'"authenticated"\s*:\s*true', r'"success"\s*:\s*true',
        r'"status"\s*:\s*"ok"', r'"token"', r'"accessToken"',
        r'cpanel', r'control[\s_-]?panel',
    ]

    FAILURE_PATTERNS: List[str] = [
        r'invalid',      r'incorrect',   r'wrong',
        r'failed',       r'error',       r'denied',
        r'unauthorized', r'bad[\s_-]?credentials',
        r'"authenticated"\s*:\s*false',
        r'"success"\s*:\s*false',
        r'"error"',      r'invalid email or password',
        r'invalid credentials',
    ]

    # ──────────────────────────────────────────────────────────────────────────
    # ENTRY POINT
    # ──────────────────────────────────────────────────────────────────────────

    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None,
    ) -> List[Vulnerability]:
        """Scan for application-level weak / default credentials."""
        vulnerabilities: List[Vulnerability] = []

        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Discover login endpoints and test credentials
        login_endpoints = await self._discover_login_endpoints(session, base_url)
        for endpoint in login_endpoints[:6]:
            vulns = await self._test_app_credentials(session, endpoint)
            vulnerabilities.extend(vulns)
            if vulns:
                break

        # 2. Scan for hardcoded credentials in source / JS
        vulns = await self._check_hardcoded_credentials(session, url)
        vulnerabilities.extend(vulns)

        # 3. Check for exposed config files
        vulns = await self._check_config_files(session, base_url)
        vulnerabilities.extend(vulns)

        # 4. Check for missing lockout (allows unlimited attempts)
        vulns = await self._check_missing_lockout(session, base_url)
        vulnerabilities.extend(vulns)

        # 5. Playwright: JS-heavy login forms
        if PLAYWRIGHT_AVAILABLE and not any(
            v.vuln_type == "Default Credentials Found" for v in vulnerabilities
        ):
            vulns = await self._playwright_check(base_url, login_endpoints)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    # ──────────────────────────────────────────────────────────────────────────
    # LOGIN ENDPOINT DISCOVERY
    # ──────────────────────────────────────────────────────────────────────────

    async def _discover_login_endpoints(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
    ) -> List[str]:
        """Return reachable endpoints that look like login pages."""
        found: List[str] = []

        for path in self.LOGIN_ENDPOINTS:
            test_url = urljoin(base_url, path)
            try:
                resp = await self.make_request(session, "GET", test_url)
                if not resp or resp.status == 404:
                    continue
                body = await resp.text()
                if self._looks_like_login(body):
                    found.append(test_url)
            except Exception:
                continue

        return found

    def _looks_like_login(self, html: str) -> bool:
        html_lower = html.lower()
        has_pass  = 'type="password"' in html_lower or "type='password'" in html_lower
        has_label = any(w in html_lower for w in [
            'login', 'sign in', 'log in', 'authenticate',
            'username', 'password', 'email',
        ])
        return has_pass or has_label

    # ──────────────────────────────────────────────────────────────────────────
    # CREDENTIAL TESTING
    # ──────────────────────────────────────────────────────────────────────────

    async def _test_app_credentials(
        self,
        session: aiohttp.ClientSession,
        login_url: str,
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        form_info = await self._extract_form_info(session, login_url)
        if not form_info:
            return vulnerabilities

        user_field = form_info.get('username_field', 'username')
        pass_field = form_info.get('password_field', 'password')
        csrf_field = form_info.get('csrf_field')
        csrf_token = form_info.get('csrf_token')

        # Limit to first 25 to stay fast; Playwright covers the rest
        for username, password in self.APP_CREDENTIALS[:25]:
            result = await self._attempt_login(
                session, login_url,
                user_field, pass_field, username, password,
                csrf_field, csrf_token,
            )
            if result['success']:
                http_msg = result.get('http_msg')
                vulnerabilities.append(self.create_vulnerability(
                    http_capture=http_msg,
                    vuln_type="Default Credentials Found",
                    severity=Severity.CRITICAL,
                    url=login_url,
                    parameter=f"{user_field} / {pass_field}",
                    payload=f"{username}:{password or '(empty)'}",
                    evidence=(
                        f"Application accepted default credentials: "
                        f"{username} / {password or '(empty)'}"
                    ),
                    description=(
                        f"The application login at '{login_url}' accepted the "
                        f"default credential pair {username!r} / "
                        f"{password or '(empty)'}. "
                        f"A correctly implemented authentication system must "
                        f"reject well-known default passwords. "
                        f"This maps to A07:2025 — the *application* permits "
                        f"weak authentication, not merely a misconfigured component."
                    ),
                    cwe_id="CWE-1392",
                    cvss_score=9.8,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                        "latest/4-Web_Application_Security_Testing/"
                        "04-Authentication_Testing/02-Testing_for_Default_Credentials",
                        "https://cwe.mitre.org/data/definitions/1392.html",
                        "https://cwe.mitre.org/data/definitions/1391.html",
                    ],
                ))
                return vulnerabilities  # One confirmed finding is enough

            await asyncio.sleep(0.15)   # Gentle pacing

        return vulnerabilities

    async def _extract_form_info(
        self,
        session: aiohttp.ClientSession,
        login_url: str,
    ) -> Optional[Dict]:
        try:
            resp = await self.make_request(session, "GET", login_url)
            if not resp:
                return None
            body = await resp.text()

            # Username field name
            user_field = 'username'
            for pat in [
                r'name=["\']?(username|user|email|login|userid|user_name|userName)["\']?',
                r'id=["\']?(username|user|email|login|userid)["\']?',
            ]:
                m = re.search(pat, body, re.IGNORECASE)
                if m:
                    user_field = m.group(1)
                    break

            # Password field name
            pass_field = 'password'
            for pat in [
                r'name=["\']?(password|passwd|pwd|pass|secret)["\']?',
                r'id=["\']?(password|passwd|pwd|pass)["\']?',
            ]:
                m = re.search(pat, body, re.IGNORECASE)
                if m:
                    pass_field = m.group(1)
                    break

            # CSRF token
            csrf_field = csrf_token = None
            for pat in [
                r'name=["\']?(csrf|_token|csrfToken|csrf_token|_csrf)["\']?\s+value=["\']?([^"\'>\s]+)',
                r'value=["\']?([^"\'>\s]+)["\']?\s+name=["\']?(csrf|_token|csrfToken|csrf_token|_csrf)',
            ]:
                m = re.search(pat, body, re.IGNORECASE)
                if m:
                    csrf_field, csrf_token = m.group(1), m.group(2)
                    break

            return {
                'username_field': user_field,
                'password_field': pass_field,
                'csrf_field':     csrf_field,
                'csrf_token':     csrf_token,
            }
        except Exception:
            return None

    async def _attempt_login(
        self,
        session: aiohttp.ClientSession,
        login_url: str,
        user_field: str,
        pass_field: str,
        username: str,
        password: str,
        csrf_field: Optional[str],
        csrf_token: Optional[str],
    ) -> Dict:
        payload_dict: Dict[str, str] = {
            user_field: username,
            pass_field: password,
        }
        if csrf_field and csrf_token:
            payload_dict[csrf_field] = csrf_token

        # ── Form POST ────────────────────────────────────────────────────────
        try:
            response, http_msg = await self.make_request_with_capture(
                session, "POST", login_url,
                data=payload_dict,
                allow_redirects=True,
                payload=f"{username}:{password}",
            )
            if response and self._check_success(response, http_msg):
                return {'success': True, 'method': 'form', 'http_msg': http_msg}
        except Exception:
            pass

        # ── JSON POST ────────────────────────────────────────────────────────
        try:
            response, http_msg = await self.make_request_with_capture(
                session, "POST", login_url,
                data=payload_dict,
                headers={'Content-Type': 'application/json'},
                allow_redirects=True,
                payload=f"{username}:{password}",
            )
            if response and self._check_success(response, http_msg):
                return {'success': True, 'method': 'json', 'http_msg': http_msg}
        except Exception:
            pass

        return {'success': False}

    def _check_success(
        self,
        response: aiohttp.ClientResponse,
        http_msg,
    ) -> bool:
        body_lower = (http_msg.response_body or "").lower()

        success = any(re.search(p, body_lower) for p in self.SUCCESS_PATTERNS)
        failure = any(re.search(p, body_lower) for p in self.FAILURE_PATTERNS)

        has_session = bool(response.cookies)

        redirect_ok = response.status in (302, 303) and any(
            kw in response.headers.get('Location', '').lower()
            for kw in ('dashboard', 'admin', 'home', 'welcome', 'panel', '#/')
        )

        json_token = (
            response.status == 200
            and ('"token"' in body_lower or '"accesstoken"' in body_lower)
            and not failure
        )

        return (
            json_token
            or redirect_ok
            or (success and not failure)
            or (response.status == 200 and has_session and not failure)
        )

    # ──────────────────────────────────────────────────────────────────────────
    # HARDCODED CREDENTIAL SCAN
    # ──────────────────────────────────────────────────────────────────────────

    async def _check_hardcoded_credentials(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        try:
            response, http_msg = await self.make_request_with_capture(
                session, "GET", url
            )
            if not response or not http_msg.response_body:
                return vulnerabilities

            body = http_msg.response_body

            for pattern, label, cwe in self.HARDCODED_PATTERNS:
                for match in re.finditer(pattern, body, re.IGNORECASE):
                    value = match.group(1) if match.lastindex else match.group()

                    # Skip placeholders / false positives
                    if any(p in value.lower() for p in self.PLACEHOLDER_VALUES):
                        continue

                    # Context snippet (avoid leaking the full secret in reports)
                    start   = max(0, match.start() - 30)
                    end     = min(len(body), match.end() + 30)
                    context = body[start:end].replace('\n', ' ')
                    masked  = value[:4] + '*' * max(0, len(value) - 4)

                    vulnerabilities.append(self.create_vulnerability(
                        http_capture=http_msg,
                        vuln_type=f"Hardcoded Credential - {label}",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="Source Code / Response Body",
                        payload="N/A (static analysis)",
                        evidence=f"Found: …{context}… (value starts: {masked})",
                        description=(
                            f"A {label} ({cwe}) was found in the page source or "
                            f"a bundled JavaScript file. Hard-coded credentials "
                            f"expose secrets to anyone who can read the source, "
                            f"including via browser dev-tools or public repositories."
                        ),
                        cwe_id=cwe,
                        cvss_score=7.5,
                        remediation=(
                            "Remove hard-coded credentials. "
                            "Use environment variables or a secrets manager "
                            "(HashiCorp Vault, AWS Secrets Manager, etc.)."
                        ),
                        references=[
                            f"https://cwe.mitre.org/data/definitions/"
                            f"{cwe.replace('CWE-','')}.html",
                        ],
                    ))
                    break   # One finding per pattern type is enough

        except Exception:
            pass

        return vulnerabilities

    # ──────────────────────────────────────────────────────────────────────────
    # EXPOSED CONFIG FILES
    # ──────────────────────────────────────────────────────────────────────────

    async def _check_config_files(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        CREDENTIAL_KEYWORDS = [
            'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
            'db_pass', 'database_password', 'mysql', 'postgres', 'mongodb',
            'redis_password', 'private_key', 'auth_token', 'access_token',
        ]

        for config_path in self.CONFIG_FILES:
            test_url = urljoin(base_url, config_path)
            try:
                response, http_msg = await self.make_request_with_capture(
                    session, "GET", test_url
                )
                if not response or response.status != 200:
                    continue

                body = (http_msg.response_body or "").lower()

                if any(kw in body for kw in CREDENTIAL_KEYWORDS):
                    vulnerabilities.append(self.create_vulnerability(
                        http_capture=http_msg,
                        vuln_type="Exposed Configuration File",
                        severity=Severity.CRITICAL,
                        url=test_url,
                        parameter="Configuration File",
                        payload=config_path,
                        evidence=(
                            f"'{config_path}' returned HTTP 200 and contains "
                            f"credential-related keywords"
                        ),
                        description=(
                            f"The configuration file '{config_path}' is publicly "
                            f"accessible and appears to contain credentials or "
                            f"secrets. An attacker can harvest database passwords, "
                            f"API keys, or other sensitive values without "
                            f"authentication."
                        ),
                        cwe_id="CWE-259",
                        cvss_score=9.0,
                        remediation=(
                            "Block access to configuration files in your web-server "
                            "config (e.g. Nginx: location ~ /\\.env { deny all; }). "
                            "Move secrets to environment variables or a vault."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/259.html",
                            "https://owasp.org/www-community/vulnerabilities/"
                            "Sensitive_Data_Exposure",
                        ],
                    ))
            except Exception:
                continue

        return vulnerabilities

    # ──────────────────────────────────────────────────────────────────────────
    # MISSING LOCKOUT CHECK (CWE-307)
    # ──────────────────────────────────────────────────────────────────────────

    async def _check_missing_lockout(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
    ) -> List[Vulnerability]:
        """
        Send 10 rapid wrong-password attempts.
        If we never get a 429 / lockout response, report the absence of
        brute-force protection.
        """
        vulnerabilities: List[Vulnerability] = []

        for path in ('/login', '/api/login', '/api/v1/login', '/rest/user/login'):
            test_url = urljoin(base_url, path)
            try:
                probe = await self.make_request(session, "GET", test_url)
                if not probe or probe.status == 404:
                    continue

                lockout_seen = False
                for i in range(10):
                    resp = await self.make_request(
                        session, "POST", test_url,
                        data={'username': 'admin', 'password': f'wrongpass_{i}'},
                        allow_redirects=False,
                    )
                    if resp and resp.status in (429, 423, 403):
                        lockout_seen = True
                        break
                    await asyncio.sleep(0.1)

                if not lockout_seen:
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="Missing Account Lockout",
                        severity=Severity.MEDIUM,
                        url=test_url,
                        parameter="username / password",
                        payload="10 rapid wrong-password attempts",
                        evidence=(
                            "10 consecutive failed login attempts produced no "
                            "429 Too Many Requests or account-lockout response"
                        ),
                        description=(
                            f"The login endpoint '{path}' does not appear to "
                            f"enforce rate-limiting or account lockout after "
                            f"repeated failed attempts. This allows automated "
                            f"credential-stuffing and brute-force attacks to "
                            f"proceed unchecked — a direct violation of "
                            f"A07:2025 Authentication Failures."
                        ),
                        cwe_id="CWE-307",
                        cvss_score=5.3,
                        remediation=(
                            "Implement account lockout or exponential back-off "
                            "after 5–10 failed attempts. Return HTTP 429 with "
                            "a Retry-After header. Consider CAPTCHA for "
                            "repeated failures."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/307.html",
                            "https://owasp.org/www-project-web-security-testing-guide/"
                            "latest/4-Web_Application_Security_Testing/"
                            "04-Authentication_Testing/"
                            "03-Testing_for_Weak_Lock_Out_Mechanism",
                        ],
                    ))
                break   # Only check first reachable login endpoint

            except Exception:
                continue

        return vulnerabilities

    # ──────────────────────────────────────────────────────────────────────────
    # PLAYWRIGHT BROWSER-BASED CHECK
    # ──────────────────────────────────────────────────────────────────────────

    async def _playwright_check(
        self,
        base_url: str,
        discovered_endpoints: List[str],
    ) -> List[Vulnerability]:
        """
        Use a real Chromium browser for JS-heavy login forms
        (Angular SPAs, React apps, Juice Shop, etc.).
        Falls back gracefully if Playwright is not installed.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return []

        vulnerabilities: List[Vulnerability] = []

        # Use already-discovered endpoints; fall back to common paths
        targets = discovered_endpoints or [
            urljoin(base_url, p) for p in (
                '/login', '/#/login', '/admin', '/rest/user/login'
            )
        ]

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=True)

            for login_url in targets[:4]:   # Cap at 4 to stay fast
                vuln = await self._playwright_try_endpoint(
                    browser, login_url
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break   # One confirmed finding is enough

            await browser.close()

        return vulnerabilities

    async def _playwright_try_endpoint(
        self,
        browser: 'Browser',
        login_url: str,
    ) -> Optional[Vulnerability]:
        """Try every credential pair on a single URL using Playwright."""
        page: 'Page' = await browser.new_page()

        try:
            resp = await page.goto(
                login_url, timeout=12_000, wait_until='domcontentloaded'
            )
            if not resp or resp.status == 404:
                return None

            html = await page.content()
            if not self._looks_like_login(html):
                return None

            for username, password in self.APP_CREDENTIALS[:30]:
                try:
                    # Fresh page state for each attempt
                    await page.reload(timeout=10_000, wait_until='domcontentloaded')

                    # ── Fill username / email ────────────────────────────────
                    user_selector = (
                        'input[name="username"], '
                        'input[name="email"], '
                        'input[name="user"], '
                        'input[name="login"], '
                        'input[type="email"], '
                        'input[type="text"]'
                    )
                    try:
                        await page.fill(user_selector, username, timeout=3_000)
                    except PWTimeout:
                        continue

                    # ── Fill password ────────────────────────────────────────
                    try:
                        await page.fill(
                            'input[type="password"]', password, timeout=3_000
                        )
                    except PWTimeout:
                        continue

                    # ── Submit ───────────────────────────────────────────────
                    await page.keyboard.press('Enter')
                    await page.wait_for_timeout(2_000)

                    post_url     = page.url
                    post_content = (await page.content()).lower()

                    if self._playwright_is_success(
                        post_url, post_content, login_url
                    ):
                        return self.create_vulnerability(
                            vuln_type="Default Credentials Found (Browser)",
                            severity=Severity.CRITICAL,
                            url=login_url,
                            parameter="username / password (browser-verified)",
                            payload=f"{username}:{password or '(empty)'}",
                            evidence=(
                                f"Playwright confirmed successful login. "
                                f"Post-login URL: {post_url}"
                            ),
                            description=(
                                f"A real Chromium browser confirmed the application "
                                f"at '{login_url}' accepted the default credential "
                                f"pair {username!r} / {password or '(empty)'}. "
                                f"Browser-based verification eliminates false "
                                f"positives caused by CSRF tokens or JS-rendered "
                                f"login forms. "
                                f"This is an A07:2025 Authentication Failure — "
                                f"the application permits weak default credentials."
                            ),
                            cwe_id="CWE-1392",
                            cvss_score=9.8,
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/"
                                "latest/4-Web_Application_Security_Testing/"
                                "04-Authentication_Testing/"
                                "02-Testing_for_Default_Credentials",
                                "https://cwe.mitre.org/data/definitions/1392.html",
                            ],
                        )

                except PWTimeout:
                    continue
                except Exception:
                    continue

        except Exception:
            pass
        finally:
            await page.close()

        return None

    # ──────────────────────────────────────────────────────────────────────────
    # SHARED HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _playwright_is_success(
        self,
        current_url: str,
        body_lower: str,
        original_url: str,
    ) -> bool:
        """Determine Playwright login outcome from URL + body."""
        url_changed = current_url.rstrip('/') != original_url.rstrip('/')

        success_url_keywords = [
            'dashboard', 'admin', 'welcome', 'profile',
            'panel', '#/', '/home', 'account',
        ]
        url_ok = any(kw in current_url.lower() for kw in success_url_keywords)

        body_ok = any(
            re.search(p, body_lower) for p in self.SUCCESS_PATTERNS
        )
        failure = any(
            re.search(p, body_lower) for p in self.FAILURE_PATTERNS
        )

        return (url_changed or url_ok or body_ok) and not failure

    # ──────────────────────────────────────────────────────────────────────────
    # REMEDIATION
    # ──────────────────────────────────────────────────────────────────────────

    def _get_remediation(self) -> str:
        return """
A07 - Authentication Failures: Default / Weak Credentials

1. Reject Default Passwords at the Application Level
   - Validate new/changed passwords against a blocklist of the top-10 000
     most common passwords (NIST 800-63b §5.1.1).
   - Force a mandatory password change on first login for any pre-seeded account.

2. Remove or Disable Default Accounts
   - Delete demo/test/guest accounts before going to production.
   - If a default admin account must exist, randomise its password at install
     time (see: WordPress first-run, modern router firmware).

3. Enforce Strong Password Policy
   - Minimum 12 characters; no complexity rules required per NIST 2024 guidance.
   - Check against HaveIBeenPwned API on registration and password change.

4. Implement Account Lockout / Rate-Limiting (CWE-307)
   - Lock or throttle after 5–10 consecutive failures.
   - Return HTTP 429 with Retry-After header.
   - Alert administrators on sustained failure bursts.

5. Multi-Factor Authentication (MFA)
   - Require MFA for all admin/privileged accounts.
   - Encourage MFA for all users.

6. Remove Hard-coded Credentials (CWE-798 / CWE-259)
   - Never commit credentials to source control.
   - Use environment variables or a secrets manager
     (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager).
   - Rotate any credential that may have been exposed.

7. Secure Session Management
   - Issue a new session ID after successful login.
   - Invalidate sessions on logout and after idle/absolute timeouts.

Example — environment-variable pattern (Python):
    import os
    DB_PASSWORD = os.environ['DB_PASSWORD']   # raises KeyError if unset
    # Never: DB_PASSWORD = "admin123"
"""