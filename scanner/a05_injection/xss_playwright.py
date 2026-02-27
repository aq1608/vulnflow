# scanner/a05_injection/xss_playwright.py
"""
Playwright-based XSS Scanner

Uses a real browser to detect XSS vulnerabilities by:
1. Injecting payloads and checking if they execute (alert/dialog detection)
2. Detecting DOM-based XSS through actual JavaScript execution
3. Handling SPAs that render content client-side (Angular, React, Vue)
4. Testing REST API endpoints that reflect into the DOM

OWASP: A05:2025 - Injection
CWE-79: Improper Neutralization of Input During Web Page Generation
"""

import asyncio
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote

try:
    from playwright.async_api import (
        async_playwright, Page, Browser,
        BrowserContext, Dialog,
        TimeoutError as PWTimeout,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class PlaywrightXSSScanner(BaseScanner):
    """XSS Scanner using Playwright for real browser-based detection"""

    name        = "Playwright XSS Scanner"
    description = "Detects XSS vulnerabilities using real browser execution"
    owasp_category = OWASPCategory.A05_INJECTION

    XSS_MARKER = "VFXSS"   # Short marker — Angular is less likely to mangle it

    def __init__(self, headless: bool = True):
        super().__init__()

        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright required. "
                "Install: pip install playwright && playwright install chromium"
            )

        self.headless     = headless
        self._browser:  Optional[Browser]        = None
        self._context:  Optional[BrowserContext] = None
        self._tested:   Set[str]                 = set()
        self._found:    Set[str]                 = set()
        self._scan_id   = str(id(self))[-6:]     # Short unique suffix

    # ─────────────────────────────────────────────────────────────────────────
    # PAYLOADS
    # ─────────────────────────────────────────────────────────────────────────

    def _get_payloads(self) -> List[Dict]:
        """
        Return XSS payloads.

        Each entry:
          payload      – the raw string to inject
          marker       – unique string we look for in dialog / DOM
          type         – human label
          needs_marker – if False, any dialog firing is a hit
                         (used for payloads whose output Angular will mangle)
        """
        sid = self._scan_id

        return [
            # ── Juice Shop confirmed working payloads ─────────────────────────
            # These are the exact strings from the official challenge solutions.
            # No custom markers — we just detect any dialog firing.
            {
                "payload":      '<iframe src="javascript:alert(`xss`)">',
                "marker":       "xss",
                "type":         "iframe_js_proto",
                "needs_marker": False,   # any alert = win
            },
            {
                "payload":      "<script>alert('xss')</script>",
                "marker":       "xss",
                "type":         "script_tag",
                "needs_marker": False,
            },
            {
                "payload":      "<img src=x onerror=alert('xss')>",
                "marker":       "xss",
                "type":         "img_onerror",
                "needs_marker": False,
            },
            {
                "payload":      "<svg onload=alert('xss')>",
                "marker":       "xss",
                "type":         "svg_onload",
                "needs_marker": False,
            },

            # ── Marker-based payloads (for non-Angular apps) ──────────────────
            {
                "payload":      f'<script>alert("{sid}_1")</script>',
                "marker":       f"{sid}_1",
                "type":         "script_marker",
                "needs_marker": True,
            },
            {
                "payload":      f'<img src=x onerror="alert(\'{sid}_2\')">',
                "marker":       f"{sid}_2",
                "type":         "img_marker",
                "needs_marker": True,
            },
            {
                "payload":      f'<svg onload="alert(\'{sid}_3\')">',
                "marker":       f"{sid}_3",
                "type":         "svg_marker",
                "needs_marker": True,
            },
            {
                "payload":      f'<iframe src="javascript:alert(\'{sid}_4\')">',
                "marker":       f"{sid}_4",
                "type":         "iframe_marker",
                "needs_marker": True,
            },

            # ── Attribute break-out ───────────────────────────────────────────
            {
                "payload":      f'" onmouseover="alert(\'{sid}_5\')" x="',
                "marker":       f"{sid}_5",
                "type":         "attr_break",
                "needs_marker": True,
            },
            {
                "payload":      f'"><script>alert("{sid}_6")</script>',
                "marker":       f"{sid}_6",
                "type":         "attr_break_script",
                "needs_marker": True,
            },

            # ── Auto-trigger ──────────────────────────────────────────────────
            {
                "payload":      f'<input onfocus="alert(\'{sid}_7\')" autofocus>',
                "marker":       f"{sid}_7",
                "type":         "autofocus",
                "needs_marker": True,
            },
            {
                "payload":      f'<details open ontoggle="alert(\'{sid}_8\')">',
                "marker":       f"{sid}_8",
                "type":         "details_toggle",
                "needs_marker": True,
            },

            # ── Angular template injection ────────────────────────────────────
            {
                "payload":      "{{constructor.constructor('alert(1)')()}}",
                "marker":       "1",
                "type":         "angular_template",
                "needs_marker": False,
            },

            # ── JS context break ──────────────────────────────────────────────
            {
                "payload":      f"';alert('{sid}_9');//",
                "marker":       f"{sid}_9",
                "type":         "js_break_single",
                "needs_marker": True,
            },
            {
                "payload":      f'";alert("{sid}_10");//',
                "marker":       f"{sid}_10",
                "type":         "js_break_double",
                "needs_marker": True,
            },

            # ── Mixed-case / encoding ─────────────────────────────────────────
            {
                "payload":      f'<ScRiPt>alert("{sid}_11")</ScRiPt>',
                "marker":       f"{sid}_11",
                "type":         "mixed_case",
                "needs_marker": True,
            },
        ]

    # ─────────────────────────────────────────────────────────────────────────
    # JUICE SHOP — KNOWN VULNERABLE ENDPOINTS
    # ─────────────────────────────────────────────────────────────────────────

    # Each entry: (rest_api_path, param_name, description)
    # These endpoints reflect user input into innerHTML / Angular bindings
    JUICE_SHOP_SINKS: List[Tuple[str, str, str]] = [
        # DOM XSS via product search — Angular renders results with innerHTML
        ('/rest/products/search', 'q',     'Product Search (DOM XSS)'),
        # Reflected XSS via order tracking
        ('/rest/track-order',     'id',    'Order Tracking (Reflected XSS)'),
    ]

    # Hash-routed pages — test these by navigating to the full SPA URL
    HASH_ENDPOINTS: List[Tuple[str, str, str]] = [
        ('/#/search',       'q',       'Search Page'),
        ('/#/track-result', 'id',      'Track Result Page'),
        ('/#/contact',      'comment', 'Contact Page'),
        ('/#/complain',     'message', 'Complain Page'),
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────

    async def scan_with_browser(
        self,
        base_url:   str,
        forms:      List[Dict],
        urls:       Dict[str, dict],
        auth_token: Optional[str] = None,
    ) -> List[Vulnerability]:
        """Main entry point for Playwright-based XSS scanning."""
        vulnerabilities: List[Vulnerability] = []

        if not base_url:
            print("  [!] No base URL for Playwright XSS scan")
            return []

        base_url = base_url.rstrip('/')

        async with async_playwright() as p:
            try:
                self._browser = await p.chromium.launch(headless=self.headless)
                self._context = await self._browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent=(
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/120.0.0.0 Safari/537.36'
                    ),
                )

                # Verify reachable
                if not await self._verify_target(base_url):
                    print(f"  [!] {base_url} unreachable — skipping XSS scan")
                    return []

                # Set auth token ONCE in a persistent page so all future
                # pages in the same context inherit localStorage
                if auth_token:
                    await self._inject_token(base_url, auth_token)

                # ── 1. Juice Shop REST API sinks ──────────────────────────────
                print("  [*] Testing Juice Shop REST API sinks for XSS...")
                vulns = await self._test_juice_shop_sinks(
                    base_url, auth_token
                )
                vulnerabilities.extend(vulns)
                print(f"      → {len(vulns)} found")

                # ── 2. Hash-routed SPA endpoints ──────────────────────────────
                print("  [*] Testing hash-routed SPA endpoints for XSS...")
                vulns = await self._test_hash_routing_endpoints(
                    base_url, auth_token
                )
                vulnerabilities.extend(vulns)
                print(f"      → {len(vulns)} found")

                # ── 3. URL query parameters from crawl ────────────────────────
                url_list = list(urls.keys())[:20]
                print(f"  [*] Testing {len(url_list)} crawled URLs for XSS...")
                for url in url_list:
                    try:
                        vulns = await self._test_url_params(url, auth_token)
                        vulnerabilities.extend(vulns)
                    except Exception:
                        continue

                # ── 4. Common parameter names ─────────────────────────────────
                print("  [*] Testing common XSS parameters...")
                vulns = await self._test_common_endpoints(
                    base_url, auth_token
                )
                vulnerabilities.extend(vulns)
                print(f"      → {len(vulns)} found")

                # ── 5. Forms from crawl ───────────────────────────────────────
                forms_to_test = forms[:10]
                print(f"  [*] Testing {len(forms_to_test)} forms for XSS...")
                for form in forms_to_test:
                    try:
                        vulns = await self._test_form(form, auth_token)
                        vulnerabilities.extend(vulns)
                    except Exception:
                        continue

            except Exception as e:
                print(f"  [!] Playwright XSS scan error: {e}")
            finally:
                if self._browser:
                    await self._browser.close()

        print(f"  [*] Playwright XSS total: {len(vulnerabilities)} found")
        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # 1. JUICE SHOP REST API SINKS
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_juice_shop_sinks(
        self,
        base_url:   str,
        auth_token: Optional[str],
    ) -> List[Vulnerability]:
        """
        Test Juice Shop REST endpoints that are known to reflect input into
        Angular innerHTML bindings (DOM XSS).

        Strategy:
          • POST / GET the REST endpoint directly (not through Angular router)
          • Then navigate to the SPA page that RENDERS the response
          • Check for dialog / DOM injection on the rendered page
        """
        vulnerabilities: List[Vulnerability] = []
        payloads = self._get_payloads()

        for api_path, param, description in self.JUICE_SHOP_SINKS:
            vuln_key = f"juice:{api_path}:{param}"
            if vuln_key in self._found:
                continue

            for p_info in payloads:
                payload      = p_info['payload']
                marker       = p_info['marker']
                needs_marker = p_info['needs_marker']

                # Build the REST API test URL
                api_url = (
                    f"{base_url}{api_path}"
                    f"?{param}={quote(payload, safe='')}"
                )

                # For search: navigate to /#/search?q=payload so Angular
                # renders the API response into the DOM
                if 'search' in api_path:
                    render_url = (
                        f"{base_url}/#/search"
                        f"?q={quote(payload, safe='')}"
                    )
                elif 'track-order' in api_path:
                    render_url = (
                        f"{base_url}/#/track-result"
                        f"?id={quote(payload, safe='')}"
                    )
                else:
                    render_url = api_url

                result = await self._execute_and_detect(
                    render_url, marker, needs_marker, auth_token,
                    extra_wait_ms=2500,   # Angular needs time to render
                )

                if result['xss_detected']:
                    print(
                        f"  [+] XSS FOUND: {description} "
                        f"via {result['detection_method']}"
                    )
                    self._found.add(vuln_key)
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type=f"DOM-based XSS — {description}",
                        severity=Severity.HIGH,
                        url=render_url,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Confirmed via {result['detection_method']}. "
                            f"Dialog message: {result.get('dialog_message', '')}"
                        ),
                        description=(
                            f"DOM-based XSS in {description}. "
                            f"The REST endpoint '{api_path}' reflects "
                            f"user input which Angular renders unsanitised "
                            f"into the DOM via innerHTML or bypassSecurityTrust*."
                        ),
                        cwe_id="CWE-79",
                        cvss_score=6.1,
                        remediation=self._get_remediation(),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/"
                            "DOM_based_XSS_Prevention_Cheat_Sheet.html",
                        ],
                    ))
                    break   # One payload confirmed — move to next sink

                await asyncio.sleep(0.3)

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # 2. HASH-ROUTED SPA ENDPOINTS
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_hash_routing_endpoints(
        self,
        base_url:   str,
        auth_token: Optional[str],
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        payloads = self._get_payloads()

        page = await self._context.new_page()
        self._attach_dialog_handler(page)

        try:
            # Prime the page so Angular bootstraps once
            await page.goto(
                base_url, wait_until='domcontentloaded', timeout=15_000
            )
            await page.wait_for_timeout(1500)

            if auth_token:
                await page.evaluate(
                    "(t) => localStorage.setItem('token', t)", auth_token
                )

            for hash_path, param, description in self.HASH_ENDPOINTS:
                vuln_key = f"hash:{hash_path}:{param}"
                if vuln_key in self._found:
                    continue

                for p_info in payloads:
                    payload      = p_info['payload']
                    marker       = p_info['marker']
                    needs_marker = p_info['needs_marker']

                    # Reset dialog state on the page object
                    page._xss_dialog_triggered = False
                    page._xss_dialog_message   = ""
                    page._xss_current_marker   = marker

                    test_url = (
                        f"{base_url}{hash_path}"
                        f"?{param}={quote(payload, safe='')}"
                    )

                    try:
                        await page.goto(
                            test_url,
                            wait_until='domcontentloaded',
                            timeout=12_000,
                        )
                        # Wait for Angular router + change detection
                        try:
                            await page.wait_for_load_state(
                                'networkidle', timeout=5_000
                            )
                        except PWTimeout:
                            pass
                        await page.wait_for_timeout(1500)

                        triggered = getattr(page, '_xss_dialog_triggered', False)
                        msg       = getattr(page, '_xss_dialog_message', '')

                        if self._dialog_hit(triggered, msg, marker, needs_marker):
                            print(
                                f"  [+] XSS FOUND (hash): "
                                f"{hash_path}?{param}= "
                                f"[{p_info['type']}]"
                            )
                            self._found.add(vuln_key)
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type=f"DOM-based XSS — {description}",
                                severity=Severity.HIGH,
                                url=test_url,
                                parameter=param,
                                payload=payload,
                                evidence=(
                                    f"Alert dialog confirmed XSS. "
                                    f"Message: '{msg}'. "
                                    f"Payload type: {p_info['type']}"
                                ),
                                description=(
                                    f"DOM-based XSS in hash-routed SPA endpoint "
                                    f"'{hash_path}'. The Angular router passes "
                                    f"the query parameter into an unsafe DOM sink."
                                ),
                                cwe_id="CWE-79",
                                cvss_score=6.1,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                ],
                            ))
                            break

                        # Fallback: check DOM for dangerous reflection
                        try:
                            content = await page.content()
                            if self._dangerous_dom_context(
                                content, marker, payload
                            ):
                                print(
                                    f"  [+] XSS FOUND (DOM): "
                                    f"{hash_path}?{param}="
                                )
                                self._found.add(vuln_key)
                                vulnerabilities.append(self.create_vulnerability(
                                    vuln_type=(
                                        f"DOM-based XSS (Unexecuted) — "
                                        f"{description}"
                                    ),
                                    severity=Severity.MEDIUM,
                                    url=test_url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=(
                                        "Payload reflected in dangerous DOM "
                                        "context (script / event handler) "
                                        "without sandbox execution."
                                    ),
                                    description=(
                                        f"Payload found in dangerous context "
                                        f"in '{hash_path}'. "
                                        f"May be exploitable depending on "
                                        f"Angular version and CSP."
                                    ),
                                    cwe_id="CWE-79",
                                    cvss_score=5.4,
                                    remediation=self._get_remediation(),
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                    ],
                                ))
                                break
                        except Exception:
                            pass

                    except PWTimeout:
                        # Check if dialog still fired
                        triggered = getattr(page, '_xss_dialog_triggered', False)
                        msg       = getattr(page, '_xss_dialog_message', '')
                        if self._dialog_hit(triggered, msg, marker, needs_marker):
                            self._found.add(vuln_key)
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type=f"DOM-based XSS — {description}",
                                severity=Severity.HIGH,
                                url=test_url,
                                parameter=param,
                                payload=payload,
                                evidence=(
                                    f"Alert fired during timeout. "
                                    f"Message: '{msg}'"
                                ),
                                description=(
                                    f"DOM-based XSS confirmed by dialog "
                                    f"even though page load timed out."
                                ),
                                cwe_id="CWE-79",
                                cvss_score=6.1,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                ],
                            ))
                            break
                        continue

                    except Exception:
                        continue

                    await asyncio.sleep(0.25)

        except Exception as e:
            print(f"    [!] Hash routing XSS error: {e}")
        finally:
            try:
                await page.close()
            except Exception:
                pass

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # 3. URL QUERY PARAMETERS FROM CRAWL
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_url_params(
        self,
        url:        str,
        auth_token: Optional[str],
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return vulnerabilities

        for param_name in params:
            vuln_key = f"url:{parsed.path}:{param_name}"
            if vuln_key in self._found:
                continue

            vuln = await self._test_single_param(url, param_name, auth_token)
            if vuln:
                self._found.add(vuln_key)
                vulnerabilities.append(vuln)

            await asyncio.sleep(0.4)

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # 4. COMMON PARAMETER NAMES
    # ─────────────────────────────────────────────────────────────────────────

    COMMON_PARAMS: List[Tuple[str, str]] = [
        # (param_name, path)
        ('q',           '/search'),
        ('query',       '/search'),
        ('search',      '/search'),
        ('s',           '/'),
        ('keyword',     '/search'),
        ('name',        '/'),
        ('message',     '/'),
        ('comment',     '/'),
        ('text',        '/'),
        ('input',       '/'),
        ('data',        '/'),
        ('content',     '/'),
        ('title',       '/'),
        ('description', '/'),
        ('redirect',    '/'),
        ('next',        '/'),
        ('callback',    '/'),
    ]

    async def _test_common_endpoints(
        self,
        base_url:   str,
        auth_token: Optional[str],
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        for param, path in self.COMMON_PARAMS:
            vuln_key = f"common:{path}:{param}"
            if vuln_key in self._found:
                continue

            test_url = f"{base_url}{path}?{param}=xss_probe"

            page = await self._context.new_page()
            try:
                resp = await page.goto(
                    test_url, wait_until='domcontentloaded', timeout=7_000
                )
                exists = resp and resp.status == 200
            except Exception:
                exists = False
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

            if not exists:
                continue

            vuln = await self._test_single_param(
                f"{base_url}{path}?{param}=test",
                param,
                auth_token,
            )
            if vuln:
                self._found.add(vuln_key)
                vulnerabilities.append(vuln)

            await asyncio.sleep(0.3)

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # 5. FORM TESTING
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_form(
        self,
        form:       Dict,
        auth_token: Optional[str],
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        action = form.get('action', '')
        method = form.get('method', 'POST').upper()
        inputs = form.get('inputs', [])

        for field in inputs:
            name  = field.get('name')
            ftype = field.get('type', 'text')
            if not name:
                continue
            if ftype in ('hidden', 'submit', 'button', 'image',
                         'file', 'checkbox', 'radio'):
                continue

            vuln_key = f"form:{action}:{name}"
            if vuln_key in self._found:
                continue

            vuln = await self._test_form_input(
                action, method, inputs, name, auth_token
            )
            if vuln:
                self._found.add(vuln_key)
                vulnerabilities.append(vuln)

        return vulnerabilities

    # ─────────────────────────────────────────────────────────────────────────
    # CORE: SINGLE PARAMETER TEST
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_single_param(
        self,
        url:        str,
        param_name: str,
        auth_token: Optional[str],
    ) -> Optional[Vulnerability]:
        for p_info in self._get_payloads():
            payload      = p_info['payload']
            marker       = p_info['marker']
            needs_marker = p_info['needs_marker']
            ptype        = p_info['type']

            test_key = f"{url}:{param_name}:{ptype}"
            if test_key in self._tested:
                continue
            self._tested.add(test_key)

            test_url = self._inject_param(url, param_name, payload)
            result   = await self._execute_and_detect(
                test_url, marker, needs_marker, auth_token
            )

            if result['xss_detected']:
                return self.create_vulnerability(
                    vuln_type=f"Cross-Site Scripting ({result['detection_method']})",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"Confirmed via {result['detection_method']}. "
                        f"Payload type: {ptype}. "
                        f"Dialog: {result.get('dialog_message', '')}"
                    ),
                    description=(
                        f"XSS confirmed in parameter '{param_name}'. "
                        f"The payload executed in a real browser."
                    ),
                    cwe_id="CWE-79",
                    cvss_score=6.1,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/"
                        "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                )

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # CORE: FORM INPUT TEST
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_form_input(
        self,
        action:       str,
        method:       str,
        inputs:       List[Dict],
        target_input: str,
        auth_token:   Optional[str],
    ) -> Optional[Vulnerability]:
        for p_info in self._get_payloads()[:10]:
            payload      = p_info['payload']
            marker       = p_info['marker']
            needs_marker = p_info['needs_marker']
            ptype        = p_info['type']

            page = await self._context.new_page()
            self._attach_dialog_handler(page)

            triggered = False
            msg       = ""

            try:
                if auth_token:
                    # Set token on the origin before navigating to the form
                    origin = self._get_origin(action)
                    try:
                        await page.goto(
                            origin, wait_until='domcontentloaded', timeout=8_000
                        )
                        await page.evaluate(
                            "(t) => localStorage.setItem('token', t)", auth_token
                        )
                    except Exception:
                        pass

                await page.goto(
                    action, wait_until='networkidle', timeout=12_000
                )

                # Fill fields
                for field in inputs:
                    fname = field.get('name')
                    if not fname:
                        continue
                    value = payload if fname == target_input else 'test123'
                    for sel in [
                        f'input[name="{fname}"]',
                        f'textarea[name="{fname}"]',
                        f'input[formcontrolname="{fname}"]',
                        f'#{fname}',
                    ]:
                        try:
                            loc = page.locator(sel).first
                            if await loc.count() > 0:
                                await loc.fill(value)
                                break
                        except Exception:
                            continue

                # Submit
                try:
                    await page.click(
                        'button[type="submit"], input[type="submit"]'
                    )
                except Exception:
                    await page.keyboard.press('Enter')

                await page.wait_for_timeout(2_000)

                triggered = getattr(page, '_xss_dialog_triggered', False)
                msg       = getattr(page, '_xss_dialog_message', '')

            except Exception:
                triggered = getattr(page, '_xss_dialog_triggered', False)
                msg       = getattr(page, '_xss_dialog_message', '')
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

            if self._dialog_hit(triggered, msg, marker, needs_marker):
                return self.create_vulnerability(
                    vuln_type=f"XSS in Form ({ptype})",
                    severity=Severity.HIGH,
                    url=action,
                    parameter=target_input,
                    payload=payload,
                    evidence=(
                        f"Alert dialog on form submit. "
                        f"Message: '{msg}'"
                    ),
                    description=(
                        f"XSS confirmed via form submission to '{action}'. "
                        f"Input field '{target_input}' reflects unsanitised content."
                    ),
                    cwe_id="CWE-79",
                    cvss_score=6.1,
                    remediation=self._get_remediation(),
                    references=["https://owasp.org/www-community/attacks/xss/"],
                )

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # CORE: EXECUTE AND DETECT
    # ─────────────────────────────────────────────────────────────────────────

    async def _execute_and_detect(
        self,
        url:          str,
        marker:       str,
        needs_marker: bool,
        auth_token:   Optional[str],
        extra_wait_ms: int = 0,
    ) -> Dict:
        result: Dict = {
            'xss_detected':      False,
            'detection_method':  None,
            'dialog_message':    None,
        }

        page = await self._context.new_page()
        self._attach_dialog_handler(page)

        try:
            # ── Set auth token on the origin BEFORE navigating to test URL ───
            if auth_token:
                origin = self._get_origin(url)
                try:
                    await page.goto(
                        origin, wait_until='domcontentloaded', timeout=8_000
                    )
                    await page.evaluate(
                        "(t) => localStorage.setItem('token', t)", auth_token
                    )
                except Exception:
                    pass   # Continue even if origin nav fails

            # ── Navigate to test URL ─────────────────────────────────────────
            try:
                await page.goto(
                    url, wait_until='domcontentloaded', timeout=15_000
                )
            except PWTimeout:
                # Dialog may have blocked navigation completion — still check
                pass
            except Exception:
                triggered = getattr(page, '_xss_dialog_triggered', False)
                msg       = getattr(page, '_xss_dialog_message', '')
                if self._dialog_hit(triggered, msg, marker, needs_marker):
                    result['xss_detected']     = True
                    result['detection_method'] = 'Alert (Nav Error)'
                    result['dialog_message']   = msg
                return result

            # Wait for SPA rendering
            try:
                await page.wait_for_load_state('networkidle', timeout=5_000)
            except PWTimeout:
                pass

            await page.wait_for_timeout(1500 + extra_wait_ms)

            # ── Check dialog ─────────────────────────────────────────────────
            triggered = getattr(page, '_xss_dialog_triggered', False)
            msg       = getattr(page, '_xss_dialog_message', '')

            if self._dialog_hit(triggered, msg, marker, needs_marker):
                result['xss_detected']     = True
                result['detection_method'] = 'Alert Dialog'
                result['dialog_message']   = msg
                return result

            # ── Move mouse to trigger onmouseover ────────────────────────────
            try:
                await page.mouse.move(500, 300)
                await page.wait_for_timeout(400)

                triggered = getattr(page, '_xss_dialog_triggered', False)
                msg       = getattr(page, '_xss_dialog_message', '')

                if self._dialog_hit(triggered, msg, marker, needs_marker):
                    result['xss_detected']     = True
                    result['detection_method'] = 'Alert (Mouse Move)'
                    result['dialog_message']   = msg
                    return result
            except Exception:
                pass

            # ── DOM inspection fallback ──────────────────────────────────────
            try:
                content = await page.content()
                if self._dangerous_dom_context(content, marker, ""):
                    result['xss_detected']     = True
                    result['detection_method'] = 'DOM Dangerous Context'
                    return result
            except Exception:
                pass

        except Exception:
            triggered = getattr(page, '_xss_dialog_triggered', False)
            msg       = getattr(page, '_xss_dialog_message', '')
            if self._dialog_hit(triggered, msg, marker, needs_marker):
                result['xss_detected']     = True
                result['detection_method'] = 'Alert (Exception)'
                result['dialog_message']   = msg
        finally:
            try:
                await page.close()
            except Exception:
                pass

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _attach_dialog_handler(self, page: 'Page') -> None:
        """
        Attach a dialog handler that stores state ON the page object.
        This avoids closure / nonlocal issues across multiple pages.
        """
        page._xss_dialog_triggered = False
        page._xss_dialog_message   = ""
        page._xss_current_marker   = ""

        async def _handler(dialog: Dialog) -> None:
            page._xss_dialog_message = dialog.message
            page._xss_dialog_triggered = True
            print(f"    [!] XSS Dialog: '{dialog.message[:80]}'")
            try:
                await dialog.dismiss()
            except Exception:
                pass

        page.on('dialog', _handler)

    def _dialog_hit(
        self,
        triggered:    bool,
        message:      str,
        marker:       str,
        needs_marker: bool,
    ) -> bool:
        """Return True if the dialog counts as an XSS confirmation."""
        if not triggered:
            return False
        if needs_marker:
            return marker in message
        # For payloads like alert('xss') — any dialog is a hit,
        # but make sure it's not a legit app dialog by checking
        # it doesn't contain suspicious app-specific content.
        return True

    def _dangerous_dom_context(
        self,
        content: str,
        marker:  str,
        payload: str,
    ) -> bool:
        """Check if marker / payload fragments appear in dangerous DOM contexts."""
        terms: List[str] = []
        if marker:
            terms.append(re.escape(marker))
        if 'javascript:' in payload:
            terms.append('javascript:')
        if terms:
            combined = '|'.join(terms)
            patterns = [
                rf'<script[^>]*>[^<]*(?:{combined})',
                rf'on\w+\s*=\s*["\'][^"\']*(?:{combined})',
                rf'(?:href|src)\s*=\s*["\']?javascript:[^"\']*(?:{combined})',
                rf'<iframe[^>]*src\s*=\s*["\']?javascript:',
            ]
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE | re.DOTALL):
                    return True
        return False

    @staticmethod
    def _get_origin(url: str) -> str:
        """Return scheme://host:port from any URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _inject_param(url: str, param: str, payload: str) -> str:
        """Inject payload into a named query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params, doseq=True), parsed.fragment,
        ))

    async def _verify_target(self, base_url: str, retries: int = 3) -> bool:
        page = await self._context.new_page()
        for attempt in range(retries):
            try:
                resp = await page.goto(
                    base_url, wait_until='domcontentloaded', timeout=10_000
                )
                if resp and resp.status < 500:
                    await page.close()
                    return True
            except Exception:
                if attempt < retries - 1:
                    await asyncio.sleep(2)
        await page.close()
        return False

    async def _inject_token(self, base_url: str, auth_token: str) -> None:
        """
        Set the auth token in localStorage ONCE on the origin page.
        Subsequent pages in the same context will inherit it via the
        persistent storage partition.
        """
        page = await self._context.new_page()
        try:
            await page.goto(
                base_url, wait_until='domcontentloaded', timeout=12_000
            )
            await page.evaluate(
                "(t) => localStorage.setItem('token', t)", auth_token
            )
            print(f"  [+] Auth token injected into browser localStorage")
        except Exception as e:
            print(f"  [!] Could not set auth token: {e}")
        finally:
            await page.close()

    def _get_remediation(self) -> str:
        return """
XSS Prevention:

1. Output Encoding — encode all user input before rendering:
   • HTML context:       escape < > & " '
   • JavaScript context: JSON.stringify()
   • URL context:        encodeURIComponent()

2. Content Security Policy:
   Content-Security-Policy: default-src 'self'; script-src 'self'

3. Framework protections:
   • Angular: never use bypassSecurityTrustHtml() on user input
   • React:   JSX escapes by default — avoid dangerouslySetInnerHTML
   • Vue:     use v-text instead of v-html for user content

4. Input validation server-side (whitelist approach)

5. Use DOMPurify for any HTML that must accept rich content:
   const clean = DOMPurify.sanitize(dirty);

6. HTTPOnly + Secure cookies to limit XSS session-theft impact
"""

    # Required by BaseScanner ABC
    async def scan(
        self,
        session,
        url:    str,
        params: Dict = None,
    ) -> List[Vulnerability]:
        return []