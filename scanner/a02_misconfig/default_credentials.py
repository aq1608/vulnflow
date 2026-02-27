# scanner/a02_misconfig/default_credentials.py
"""
Default Credentials Scanner - Security Misconfiguration

Detects default credentials on infrastructure and vendor components:
- Vendor-shipped default accounts never changed after deployment
- Admin panels with factory credentials
- HTTP Basic Auth with default credentials
- Database admin interfaces
- SPA / API-first apps (Juice Shop, etc.)

OWASP: A02:2025 - Security Misconfiguration
CWE-16:   Configuration
CWE-1392: Use of Default Credentials
CWE-1393: Use of Default Password
"""

import asyncio
import json
import re
from typing import List, Dict, Optional, Tuple
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory, HTTPMessage

# ── Playwright optional import ────────────────────────────────────────────────
try:
    from playwright.async_api import (
        async_playwright, Browser, Page,
        TimeoutError as PWTimeout,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class DefaultCredentialsScanner(BaseScanner):
    """
    A02 scanner: infrastructure / vendor default credentials.

    Targets components that ship with known-default accounts and are commonly
    left unchanged after deployment (Tomcat, Jenkins, phpMyAdmin, Juice Shop…).
    Application-level login forms are handled by the A07 scanner.
    """

    name        = "Default Credentials Scanner (Misconfig)"
    description = (
        "Detects default vendor credentials on admin panels, "
        "HTTP Basic Auth endpoints, database interfaces, and API-first apps"
    )
    owasp_category = OWASPCategory.A02_SECURITY_MISCONFIGURATION

    # ─────────────────────────────────────────────────────────────────────────
    # PAYLOAD DATABASES
    # ─────────────────────────────────────────────────────────────────────────

    GENERIC_CREDENTIALS: List[Tuple[str, str]] = [
        # Universal defaults
        ('admin',         'admin'),
        ('admin',         'password'),
        ('admin',         'admin123'),
        ('admin',         '123456'),
        ('admin',         'password123'),
        ('admin',         ''),
        ('administrator', 'administrator'),
        ('administrator', 'password'),
        ('administrator', 'admin'),
        ('root',          'root'),
        ('root',          'toor'),
        ('root',          'password'),
        ('root',          ''),
        ('user',          'user'),
        ('user',          'password'),
        ('test',          'test'),
        ('guest',         'guest'),
        ('guest',         ''),
        ('demo',          'demo'),
        ('operator',      'operator'),
        ('support',       'support'),
        ('service',       'service'),
        ('superuser',     'superuser'),
        ('sysadmin',      'sysadmin'),
        # Database defaults
        ('sa',            ''),
        ('sa',            'sa'),
        ('sa',            'password'),
        ('postgres',      'postgres'),
        ('postgres',      'password'),
        ('mysql',         'mysql'),
        ('root',          'mysql'),
        ('mongo',         'mongo'),
        ('oracle',        'oracle'),
        ('oracle',        'change_on_install'),
        # Web / app-server defaults
        ('tomcat',        'tomcat'),
        ('tomcat',        's3cret'),
        ('tomcat',        'password'),
        ('manager',       'manager'),
        ('admin',         'tomcat'),
        ('admin',         'manager'),
        ('role1',         'tomcat'),
        ('both',          'tomcat'),
        ('jenkins',       'jenkins'),
        ('admin',         'jenkins'),
        ('elastic',       'changeme'),
        ('admin',         'changeme'),
        ('admin',         'letmein'),
        ('admin',         'Welcome1'),
        ('admin',         'admin@123'),
        # Network / IoT defaults
        ('admin',         '1234'),
        ('admin',         '12345'),
        ('admin',         'default'),
        ('cisco',         'cisco'),
        ('ubnt',          'ubnt'),
        ('pi',            'raspberry'),
    ]

    # Juice Shop known default accounts (email-based, JSON API)
    JUICE_SHOP_CREDENTIALS: List[Tuple[str, str]] = [
        ('admin@juice-sh.op',          'admin123'),
        ('jim@juice-sh.op',            'ncc-1701'),
        ('bender@juice-sh.op',         'OiLkTANikt0R#'),
        ('bjoern.kimminich@gmail.com', 'YN0t3#4t'),
        ('ciso@juice-sh.op',           'mDLx7jkP7s'),
        ('support@juice-sh.op',        'J9*xfWs7yN!'),
        ('uvogin@juice-sh.op',         'rock you'),
        ('MC SafeSearch',              'Mr. N00dles'),
    ]

    # Vendor-specific panels: (path, user_field, pass_field, creds_list, use_json)
    # use_json=True  → POST application/json
    # use_json=False → POST application/x-www-form-urlencoded
    VENDOR_PANELS: Dict[str, List[Tuple[str, str, str, List[Tuple[str, str]], bool]]] = {
        'tomcat': [
            ('/manager/html', 'username', 'password', [
                ('tomcat',  'tomcat'),
                ('tomcat',  's3cret'),
                ('admin',   'admin'),
                ('manager', 'manager'),
            ], False),
            ('/host-manager/html', 'username', 'password', [
                ('tomcat', 'tomcat'),
                ('admin',  'admin'),
            ], False),
        ],
        'phpmyadmin': [
            ('/phpmyadmin/', 'pma_username', 'pma_password', [
                ('root', ''),
                ('root', 'root'),
                ('root', 'mysql'),
                ('pma',  ''),
            ], False),
            ('/pma/', 'pma_username', 'pma_password', [
                ('root', ''),
                ('root', 'root'),
            ], False),
        ],
        'jenkins': [
            ('/login', 'j_username', 'j_password', [
                ('admin',   'admin'),
                ('admin',   'password'),
                ('jenkins', 'jenkins'),
            ], False),
        ],
        'wordpress': [
            ('/wp-login.php', 'log', 'pwd', [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', 'wordpress'),
            ], False),
        ],
        'joomla': [
            ('/administrator/', 'username', 'passwd', [
                ('admin', 'admin'),
                ('admin', 'password'),
            ], False),
        ],
        'drupal': [
            ('/user/login', 'name', 'pass', [
                ('admin', 'admin'),
                ('admin', 'password'),
            ], False),
        ],
        'grafana': [
            ('/login', 'user', 'password', [
                ('admin', 'admin'),
                ('admin', 'grafana'),
            ], False),
        ],
        'sonarqube': [
            ('/sessions/new', 'login', 'password', [
                ('admin', 'admin'),
                ('sonar', 'sonar'),
            ], False),
        ],
        'weblogic': [
            ('/console/login/LoginForm.jsp', 'j_username', 'j_password', [
                ('weblogic', 'weblogic'),
                ('weblogic', 'welcome1'),
            ], False),
        ],
        # ── Juice Shop ────────────────────────────────────────────────────────
        # Must use JSON POST to /rest/user/login
        # Response shape: {"authentication": {"token": "...", "umail": "..."}}
        'juice_shop': [
            ('/rest/user/login', 'email', 'password', [
                ('admin@juice-sh.op',          'admin123'),
                ('jim@juice-sh.op',            'ncc-1701'),
                ('bender@juice-sh.op',         'OiLkTANikt0R#'),
                ('bjoern.kimminich@gmail.com', 'YN0t3#4t'),
                ('ciso@juice-sh.op',           'mDLx7jkP7s'),
                ('support@juice-sh.op',        'J9*xfWs7yN!'),
            ], True),   # ← use_json = True
        ],
    }

    GENERIC_LOGIN_ENDPOINTS: List[Tuple[str, str, str, bool]] = [
        # (path, user_field, pass_field, use_json)
        ('/rest/user/login', 'email',    'password', True),
        ('/login',           'username', 'password', False),
        ('/admin/login',     'username', 'password', False),
        ('/admin',           'username', 'password', False),
        ('/administrator',   'username', 'password', False),
        ('/user/login',      'username', 'password', False),
        ('/signin',          'email',    'password', False),
        ('/auth/login',      'username', 'password', False),
        ('/api/login',       'username', 'password', True),
        ('/api/v1/login',    'username', 'password', True),
        ('/api/auth',        'username', 'password', True),
        ('/account/login',   'username', 'password', False),
        ('/console',         'username', 'password', False),
        
    ]

    BASIC_AUTH_PATHS: List[str] = [
        '/admin',
        '/manager/html',
        '/server-status',
        '/server-info',
        '/phpmyadmin',
        '/status',
        '/metrics',
        '/actuator',
        '/actuator/env',
        '/_cat/indices',
        '/_nodes',
    ]

    # Juice Shop success: nested authentication object
    JUICE_SHOP_SUCCESS_KEYS = ('authentication',)

    SUCCESS_INDICATORS: List[str] = [
        'dashboard', 'welcome', 'logout', 'sign out', 'my account',
        'profile', 'settings', 'admin panel', 'control panel',
        'logged in', 'authenticated',
        '"token"',         # generic JSON token
        '"accesstoken"',   # some APIs
        '"authentication"', # Juice Shop
        '"success":true',
        '"status":"ok"',
    ]

    FAILURE_INDICATORS: List[str] = [
        'invalid', 'incorrect', 'failed', 'error', 'wrong',
        'denied', 'unauthorized', 'bad credentials',
        'login failed', 'authentication failed',
        '"success":false',
        'invalid credentials',
        'invalid email or password',
        '"error"',
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────

    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None,
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Vendor-specific panels
        vulns = await self._check_vendor_panels(session, base_url)
        vulnerabilities.extend(vulns)

        # 2. Generic login endpoints
        vulns = await self._check_generic_logins(session, base_url)
        vulnerabilities.extend(vulns)

        # 3. HTTP Basic Auth
        vulns = await self._check_basic_auth(session, base_url)
        vulnerabilities.extend(vulns)

        # 4. Playwright browser-based (JS-heavy SPAs)
        if PLAYWRIGHT_AVAILABLE and not vulnerabilities:
            vulns = await self._check_with_playwright(base_url)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # VENDOR PANEL CHECKS
    # ─────────────────────────────────────────────────────────────────────────

    async def _check_vendor_panels(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        for vendor, panel_list in self.VENDOR_PANELS.items():
            for path, user_field, pass_field, creds, use_json in panel_list:
                login_url = urljoin(base_url, path)

                # Probe endpoint (use HEAD-then-GET to save bandwidth)
                if not await self._endpoint_exists(session, login_url):
                    continue

                for username, password in creds:
                    vuln = await self._try_login(
                        session, login_url,
                        user_field, pass_field,
                        username, password,
                        vendor, use_json,
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
                    await asyncio.sleep(0.15)

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # GENERIC LOGIN ENDPOINT CHECKS
    # ─────────────────────────────────────────────────────────────────────────

    async def _check_generic_logins(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        for path, user_field, pass_field, use_json in self.GENERIC_LOGIN_ENDPOINTS:
            login_url = urljoin(base_url, path)

            if not await self._endpoint_exists(session, login_url):
                continue

            for username, password in self.GENERIC_CREDENTIALS[:15]:
                vuln = await self._try_login(
                    session, login_url,
                    user_field, pass_field,
                    username, password,
                    "Generic", use_json,
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break
                await asyncio.sleep(0.1)

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP BASIC AUTH CHECKS
    # ─────────────────────────────────────────────────────────────────────────

    async def _check_basic_auth(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        for path in self.BASIC_AUTH_PATHS:
            test_url = urljoin(base_url, path)
            try:
                probe = await self.make_request(session, "GET", test_url)
                if not probe or probe.status != 401:
                    continue

                www_auth = probe.headers.get('WWW-Authenticate', '')
                if 'Basic' not in www_auth:
                    continue

                for username, password in self.GENERIC_CREDENTIALS[:12]:
                    auth = aiohttp.BasicAuth(username, password)
                    try:
                        async with session.get(
                            test_url,
                            auth=auth,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False,
                        ) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                http_msg = HTTPMessage(
                                    method="GET",
                                    url=test_url,
                                    status_code=resp.status,
                                    response_headers=dict(resp.headers),
                                    response_body=body[:2000],
                                )
                                vulnerabilities.append(self.create_vulnerability(
                                    http_capture=http_msg,
                                    vuln_type="Default Credentials - HTTP Basic Auth",
                                    severity=Severity.CRITICAL,
                                    url=test_url,
                                    parameter="Authorization",
                                    payload=f"{username}:{password or '(empty)'}",
                                    evidence=(
                                        f"HTTP 200 with Basic Auth "
                                        f"{username}:{password or '(empty)'}"
                                    ),
                                    description=(
                                        f"'{path}' accepts default Basic Auth credentials "
                                        f"({username}/{password or 'empty'}). "
                                        f"Vendor defaults were never changed post-deployment."
                                    ),
                                    cwe_id="CWE-1392",
                                    cvss_score=9.8,
                                    remediation=self._get_remediation(),
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/1392.html",
                                    ],
                                ))
                                break
                    except Exception:
                        continue

            except Exception:
                continue

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # CORE LOGIN ATTEMPT — FORM + JSON
    # ─────────────────────────────────────────────────────────────────────────

    async def _try_login(
        self,
        session: aiohttp.ClientSession,
        login_url: str,
        user_field: str,
        pass_field: str,
        username: str,
        password: str,
        vendor: str,
        prefer_json: bool = False,
    ) -> Optional[Vulnerability]:
        """
        Attempt login.  Order:
          prefer_json=True  → JSON first, then form
          prefer_json=False → form first, then JSON
        """
        methods = (
            [self._post_json, self._post_form]
            if prefer_json
            else [self._post_form, self._post_json]
        )

        payload_dict = {user_field: username, pass_field: password}

        for post_fn in methods:
            try:
                response, http_msg = await post_fn(
                    session, login_url, payload_dict
                )
                if response is None:
                    continue

                if self._is_success(response, http_msg):
                    return self._build_vuln(
                        login_url, user_field, pass_field,
                        username, password, vendor, http_msg,
                        "JSON" if post_fn is self._post_json else "Form",
                    )
            except Exception:
                continue

        return None

    async def _post_form(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: Dict[str, str],
    ) -> Tuple[Optional[aiohttp.ClientResponse], HTTPMessage]:
        """POST application/x-www-form-urlencoded and capture."""
        http_msg = HTTPMessage(
            method="POST",
            url=url,
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        from urllib.parse import urlencode
        http_msg.request_body = urlencode(payload)

        try:
            async with session.post(
                url,
                data=payload,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as resp:
                body = await resp.text()
                http_msg.status_code        = resp.status
                http_msg.status_reason      = resp.reason
                http_msg.response_headers   = dict(resp.headers)
                http_msg.response_body      = body[:4000]
                return resp, http_msg
        except Exception as exc:
            http_msg.response_body = f"[Error: {exc}]"
            return None, http_msg

    async def _post_json(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: Dict[str, str],
    ) -> Tuple[Optional[aiohttp.ClientResponse], HTTPMessage]:
        """
        POST application/json — built directly so we avoid base.py's
        make_request_with_capture which has no json= support.
        """
        body_str = json.dumps(payload)
        http_msg = HTTPMessage(
            method="POST",
            url=url,
            request_headers={"Content-Type": "application/json"},
            request_body=body_str,
        )

        try:
            async with session.post(
                url,
                data=body_str,
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as resp:
                body = await resp.text()
                http_msg.status_code      = resp.status
                http_msg.status_reason    = resp.reason
                http_msg.response_headers = dict(resp.headers)
                http_msg.response_body    = body[:4000]
                return resp, http_msg
        except Exception as exc:
            http_msg.response_body = f"[Error: {exc}]"
            return None, http_msg

    # ─────────────────────────────────────────────────────────────────────────
    # SUCCESS DETECTION
    # ─────────────────────────────────────────────────────────────────────────

    def _is_success(
        self,
        response: aiohttp.ClientResponse,
        http_msg: HTTPMessage,
    ) -> bool:
        body     = http_msg.response_body or ""
        body_low = body.lower()

        # ── Juice Shop specific ───────────────────────────────────────────────
        # Response: {"authentication":{"token":"...","umail":"...","bid":1}}
        if '"authentication"' in body_low and '"token"' in body_low:
            try:
                data = json.loads(body)
                if isinstance(data.get('authentication'), dict):
                    if data['authentication'].get('token'):
                        return True
            except json.JSONDecodeError:
                pass

        # ── Generic JSON token ────────────────────────────────────────────────
        if response.status == 200:
            try:
                data = json.loads(body)
                # Any top-level or nested 'token' / 'access_token'
                token = (
                    data.get('token')
                    or data.get('access_token')
                    or data.get('accessToken')
                )
                failure = any(
                    ind in body_low for ind in self.FAILURE_INDICATORS
                )
                if token and not failure:
                    return True
            except json.JSONDecodeError:
                pass

        # ── Redirect to known success paths ──────────────────────────────────
        if response.status in (302, 303):
            location = response.headers.get('Location', '').lower()
            if any(
                kw in location
                for kw in ('dashboard', 'admin', 'home', 'welcome', 'panel', '#/')
            ):
                return True

        # ── Text / HTML heuristic ─────────────────────────────────────────────
        success = any(ind in body_low for ind in self.SUCCESS_INDICATORS)
        failure = any(ind in body_low for ind in self.FAILURE_INDICATORS)
        has_session = bool(response.cookies)

        if (success and not failure):
            return True
        if response.status == 200 and has_session and not failure:
            return True

        return False

    # ─────────────────────────────────────────────────────────────────────────
    # PLAYWRIGHT — SPA / JS-HEAVY PANELS
    # ─────────────────────────────────────────────────────────────────────────

    async def _check_with_playwright(
        self,
        base_url: str,
    ) -> List[Vulnerability]:
        if not PLAYWRIGHT_AVAILABLE:
            return []

        vulnerabilities: List[Vulnerability] = []

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=True)

            # ── Juice Shop SPA login ──────────────────────────────────────────
            js_vuln = await self._playwright_juice_shop(browser, base_url)
            if js_vuln:
                vulnerabilities.append(js_vuln)

            # ── Generic vendor panels ─────────────────────────────────────────
            for vendor, panel_list in self.VENDOR_PANELS.items():
                if vendor == 'juice_shop':
                    continue   # already handled above
                for path, user_field, pass_field, creds, _ in panel_list:
                    login_url = urljoin(base_url, path)
                    vuln = await self._playwright_try_panel(
                        browser, login_url,
                        user_field, pass_field,
                        creds, vendor,
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break

            await browser.close()

        return vulnerabilities

    async def _playwright_juice_shop(
        self,
        browser: Browser,
        base_url: str,
    ) -> Optional[Vulnerability]:
        """
        Juice Shop SPA login via Playwright.

        Strategy (mirrors spa_spider._api_login exactly):
          1. POST JSON to /rest/user/login
          2. Parse {"authentication":{"token":"..."}} from response
          3. If token present → confirmed
        We do this via page.request (like spa_spider does) rather than
        filling the Angular form, which is fragile.
        """
        page: Page = await browser.new_page()
        login_api   = urljoin(base_url, '/rest/user/login')

        try:
            for email, password in self.JUICE_SHOP_CREDENTIALS:
                payload = json.dumps({'email': email, 'password': password})
                try:
                    resp = await page.request.post(
                        login_api,
                        headers={'Content-Type': 'application/json'},
                        data=payload,
                    )
                    status = resp.status
                    body   = await resp.text()

                    if status in (200, 201):
                        try:
                            data = json.loads(body)
                            auth = data.get('authentication', {})
                            if isinstance(auth, dict) and auth.get('token'):
                                return self.create_vulnerability(
                                    vuln_type="Default Credentials - Juice Shop (API)",
                                    severity=Severity.CRITICAL,
                                    url=login_api,
                                    parameter="email / password",
                                    payload=f"{email}:{password}",
                                    evidence=(
                                        f"Juice Shop /rest/user/login returned token "
                                        f"for {email}. "
                                        f"Token prefix: {auth['token'][:30]}…"
                                    ),
                                    description=(
                                        f"The Juice Shop instance at '{base_url}' "
                                        f"accepts the pre-seeded default account "
                                        f"{email!r} / {password!r}. "
                                        f"These accounts ship with every Juice Shop "
                                        f"installation and must be disabled or have "
                                        f"their passwords changed before deployment."
                                    ),
                                    cwe_id="CWE-1392",
                                    cvss_score=9.8,
                                    remediation=self._get_remediation(),
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/1392.html",
                                        "https://owasp.org/www-project-juice-shop/",
                                    ],
                                )
                        except json.JSONDecodeError:
                            pass

                except PWTimeout:
                    continue
                except Exception:
                    continue

        finally:
            await page.close()

        return None

    async def _playwright_try_panel(
        self,
        browser: Browser,
        login_url: str,
        user_field: str,
        pass_field: str,
        creds: List[Tuple[str, str]],
        vendor: str,
    ) -> Optional[Vulnerability]:
        """Try credentials on a vendor panel using real browser."""
        page: Page = await browser.new_page()

        try:
            resp = await page.goto(
                login_url, timeout=12_000, wait_until='domcontentloaded'
            )
            if not resp or resp.status == 404:
                return None

            html = await page.content()
            if 'password' not in html.lower():
                return None

            for username, password in creds:
                try:
                    await page.reload(
                        timeout=10_000, wait_until='domcontentloaded'
                    )

                    # Fill username — try multiple selector strategies
                    user_sel = ", ".join([
                        f'input[name="{user_field}"]',
                        f'input[id="{user_field}"]',
                        f'input[formcontrolname="{user_field}"]',
                        'input[type="email"]',
                        'input[type="text"]',
                    ])
                    await page.fill(user_sel, username, timeout=4_000)

                    # Fill password
                    pass_sel = ", ".join([
                        f'input[name="{pass_field}"]',
                        f'input[id="{pass_field}"]',
                        f'input[formcontrolname="{pass_field}"]',
                        'input[type="password"]',
                    ])
                    await page.fill(pass_sel, password, timeout=4_000)

                    await page.keyboard.press('Enter')
                    await page.wait_for_timeout(2_000)

                    post_url     = page.url
                    post_content = (await page.content()).lower()

                    if self._playwright_success(post_url, post_content, login_url):
                        return self.create_vulnerability(
                            vuln_type=f"Default Credentials (Browser) - {vendor}",
                            severity=Severity.CRITICAL,
                            url=login_url,
                            parameter=f"{user_field} / {pass_field}",
                            payload=f"{username}:{password or '(empty)'}",
                            evidence=(
                                f"Browser confirmed login. "
                                f"Post-login URL: {post_url}"
                            ),
                            description=(
                                f"Playwright confirmed {vendor} at '{login_url}' "
                                f"accepts default credentials "
                                f"({username}/{password or 'empty'})."
                            ),
                            cwe_id="CWE-1392",
                            cvss_score=9.8,
                            remediation=self._get_remediation(),
                            references=[
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

    # ─────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    async def _endpoint_exists(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> bool:
        """Return True if endpoint responds with something other than 404."""
        try:
            resp = await self.make_request(
                session, "GET", url, allow_redirects=True
            )
            return resp is not None and resp.status != 404
        except Exception:
            return False

    def _playwright_success(
        self,
        current_url: str,
        body_lower: str,
        original_url: str,
    ) -> bool:
        url_changed = current_url.rstrip('/') != original_url.rstrip('/')
        url_ok = any(
            kw in current_url.lower()
            for kw in ('dashboard', 'admin', 'welcome', 'panel', '#/', '/home')
        )
        body_ok = any(ind in body_lower for ind in self.SUCCESS_INDICATORS)
        failure = any(ind in body_lower for ind in self.FAILURE_INDICATORS)
        return (url_changed or url_ok or body_ok) and not failure

    def _build_vuln(
        self,
        url: str,
        user_field: str,
        pass_field: str,
        username: str,
        password: str,
        vendor: str,
        http_msg: HTTPMessage,
        method: str,
    ) -> Vulnerability:
        return self.create_vulnerability(
            http_capture=http_msg,
            vuln_type=f"Default Credentials - {vendor}",
            severity=Severity.CRITICAL,
            url=url,
            parameter=f"{user_field} / {pass_field}",
            payload=f"{username}:{password or '(empty)'}",
            evidence=(
                f"Successful {method} login with "
                f"{username}:{password or '(empty)'}"
            ),
            description=(
                f"The {vendor} component at '{url}' accepts default credentials "
                f"({username} / {password or 'empty'}) via {method}. "
                f"Vendor defaults were never changed post-deployment — "
                f"A02:2025 Security Misconfiguration."
            ),
            cwe_id="CWE-1392",
            cvss_score=9.8,
            remediation=self._get_remediation(),
            references=[
                "https://cwe.mitre.org/data/definitions/1392.html",
                "https://cwe.mitre.org/data/definitions/1393.html",
            ],
        )

    def _get_remediation(self) -> str:
        return """
A02 - Security Misconfiguration: Default Credentials

1. Change ALL vendor default passwords immediately after installation.
2. Automate the check in your deployment pipeline — fail deploys that
   still use factory credentials.
3. Disable or remove default accounts that are not needed:
   - Tomcat: remove default <user> entries from tomcat-users.xml
   - WordPress: rename the 'admin' account
   - Juice Shop: disable pre-seeded accounts before production use
4. Restrict admin panel access by IP / VPN where possible.
5. Enable account-lockout or rate-limiting on every login endpoint.
6. Use a secrets manager instead of storing credentials in config files.
7. Run periodic audits to catch newly-deployed components using defaults.
"""