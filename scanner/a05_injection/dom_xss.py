# scanner/injection/dom_xss.py
"""
DOM-based XSS Scanner with HTTP Traffic Capture

Detects DOM-based Cross-Site Scripting vulnerabilities where:
- User input flows to dangerous JavaScript sinks
- Client-side code uses unsafe DOM manipulation
- URL fragments/parameters are reflected unsafely

OWASP: A05:2025 - Injection
CWE-79: Improper Neutralization of Input During Web Page Generation
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory, HTTPMessage


class DOMXSSScanner(BaseScanner):
    """Scanner for DOM-based XSS vulnerabilities with HTTP capture"""

    name = "DOM-based XSS Scanner"
    description = "Detects DOM-based Cross-Site Scripting vulnerabilities"
    owasp_category = OWASPCategory.A05_INJECTION
    
    def __init__(self):
        super().__init__()
        
        # DOM XSS sources (where user input enters)
        self.sources = [
            r"document\.URL",
            r"document\.documentURI",
            r"document\.URLUnencoded",
            r"document\.baseURI",
            r"location",
            r"location\.href",
            r"location\.search",
            r"location\.hash",
            r"location\.pathname",
            r"document\.cookie",
            r"document\.referrer",
            r"window\.name",
            r"history\.pushState",
            r"history\.replaceState",
            r"localStorage",
            r"sessionStorage",
            r"postMessage",
            r"IndexedDB",
            r"Database",
        ]
        
        # DOM XSS sinks (where input can be dangerous)
        self.sinks = [
            # HTML sinks
            (r"\.innerHTML\s*=", "innerHTML assignment"),
            (r"\.outerHTML\s*=", "outerHTML assignment"),
            (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
            (r"document\.write\s*\(", "document.write()"),
            (r"document\.writeln\s*\(", "document.writeln()"),
            
            # JavaScript execution sinks
            (r"eval\s*\(", "eval()"),
            (r"setTimeout\s*\(", "setTimeout()"),
            (r"setInterval\s*\(", "setInterval()"),
            (r"Function\s*\(", "Function constructor"),
            (r"execScript\s*\(", "execScript()"),
            (r"ScriptElement\.src\s*=", "Script src assignment"),
            (r"ScriptElement\.text\s*=", "Script text assignment"),
            
            # URL sinks
            (r"location\s*=", "location assignment"),
            (r"location\.href\s*=", "location.href assignment"),
            (r"location\.replace\s*\(", "location.replace()"),
            (r"location\.assign\s*\(", "location.assign()"),
            (r"window\.open\s*\(", "window.open()"),
            
            # DOM manipulation sinks
            (r"\.src\s*=", "src attribute assignment"),
            (r"\.href\s*=", "href attribute assignment"),
            (r"\.action\s*=", "action attribute assignment"),
            (r"\.data\s*=", "data attribute assignment"),
            
            # jQuery sinks
            (r"\$\s*\(\s*['\"]<", "jQuery HTML construction"),
            (r"\.html\s*\(", "jQuery .html()"),
            (r"\.append\s*\(", "jQuery .append()"),
            (r"\.prepend\s*\(", "jQuery .prepend()"),
            (r"\.after\s*\(", "jQuery .after()"),
            (r"\.before\s*\(", "jQuery .before()"),
            (r"\.replaceWith\s*\(", "jQuery .replaceWith()"),
            (r"\.wrap\s*\(", "jQuery .wrap()"),
            
            # Angular sinks
            (r"\$sce\.trustAsHtml", "Angular trustAsHtml"),
            (r"bypassSecurityTrustHtml", "Angular bypassSecurityTrustHtml"),
            (r"\[innerHTML\]", "Angular innerHTML binding"),
            
            # React sinks
            (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML"),
        ]
        
        # Test payloads for URL fragment
        self.hash_payloads = [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "</script><script>alert(1)</script>",
            "{{constructor.constructor('alert(1)')()}}",
        ]
        
        # Test payloads for URL parameters
        self.param_payloads = [
            "<script>alert(1)</script>",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "javascript:alert(1)",
            "<img/src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            '<iframe src="javascript:alert(`xss`)">',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for DOM-based XSS vulnerabilities with HTTP capture.
        """
        vulnerabilities = []
        
        # Fetch and analyze JavaScript for source-sink patterns
        js_vulns = await self._analyze_javascript(session, url)
        vulnerabilities.extend(js_vulns)
        
        # Test hash-based DOM XSS
        hash_vulns = await self._test_hash_based(session, url)
        vulnerabilities.extend(hash_vulns)
        
        # Test parameter-based DOM XSS
        if params:
            param_vulns = await self._test_param_based(session, url, params)
            vulnerabilities.extend(param_vulns)
        
        # Check for postMessage vulnerabilities
        postmsg_vuln = await self._check_postmessage(session, url)
        if postmsg_vuln:
            vulnerabilities.append(postmsg_vuln)
        
        return vulnerabilities
    
    async def _analyze_javascript(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Analyze JavaScript for dangerous source-sink patterns with HTTP capture"""
        vulnerabilities = []
        
        try:
            # Make request with capture
            response, http_capture = await self.make_request_with_capture(
                session, "GET", url
            )
            
            if not response or not http_capture or not http_capture.response_body:
                return vulnerabilities
            
            html = http_capture.response_body
            
            # Extract inline JavaScript
            inline_scripts = re.findall(
                r'<script[^>]*>(.*?)</script>',
                html,
                re.DOTALL | re.IGNORECASE
            )
            
            # Extract external script URLs
            script_urls = re.findall(
                r'<script[^>]*src=["\']([^"\']+)["\']',
                html,
                re.IGNORECASE
            )
            
            # Analyze inline scripts
            all_js = "\n".join(inline_scripts)
            js_sources: Dict[str, HTTPMessage] = {"inline": http_capture}
            
            # Fetch and add external scripts (limit to same origin)
            parsed_url = urlparse(url)
            base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for script_url in script_urls[:10]:  # Limit to 10 scripts
                if script_url.startswith('/'):
                    script_url = base_domain + script_url
                elif not script_url.startswith('http'):
                    continue
                
                # Only analyze same-origin scripts
                if urlparse(script_url).netloc == parsed_url.netloc:
                    try:
                        script_response, script_capture = await self.make_request_with_capture(
                            session, "GET", script_url
                        )
                        if script_response and script_capture and script_capture.response_body:
                            all_js += "\n" + script_capture.response_body
                            js_sources[script_url] = script_capture
                    except Exception:
                        continue
            
            # Check for source-sink patterns
            source_sink_vulns = self._find_source_sink_patterns(all_js, url, http_capture)
            vulnerabilities.extend(source_sink_vulns)
            
            # Check for dangerous patterns
            dangerous_vulns = self._find_dangerous_patterns(all_js, url, http_capture)
            vulnerabilities.extend(dangerous_vulns)
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _find_source_sink_patterns(
        self,
        js_code: str,
        url: str,
        http_capture: HTTPMessage
    ) -> List[Vulnerability]:
        """Find patterns where sources flow to sinks"""
        vulnerabilities = []
        found_patterns: Set[str] = set()
        
        # Check for each source
        for source_pattern in self.sources:
            source_matches = list(re.finditer(source_pattern, js_code, re.IGNORECASE))
            
            for source_match in source_matches:
                # Get context around the source (next 300 chars)
                context_start = max(0, source_match.start() - 50)
                context_end = min(len(js_code), source_match.end() + 300)
                context = js_code[context_start:context_end]
                
                # Check if any sink is in the context
                for sink_pattern, sink_name in self.sinks:
                    if re.search(sink_pattern, context, re.IGNORECASE):
                        pattern_key = f"{source_pattern}->{sink_pattern}"
                        
                        if pattern_key not in found_patterns:
                            found_patterns.add(pattern_key)
                            
                            # Extract the specific code with line context
                            code_sample = self._extract_code_context(js_code, source_match.start())
                            
                            # Find the line number
                            line_number = js_code[:source_match.start()].count('\n') + 1
                            
                            # Create highlighted evidence
                            highlighted_context = self._highlight_source_sink(
                                context, source_pattern, sink_pattern
                            )
                            
                            vulnerabilities.append(self.create_vulnerability(
                                vuln_type="DOM XSS - Source to Sink Flow",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter="JavaScript Code",
                                payload="N/A (static analysis)",
                                evidence=f"Source '{source_pattern}' flows to sink '{sink_name}' at line ~{line_number}",
                                evidence_highlight=source_match.group(),
                                evidence_context=highlighted_context,
                                description=(
                                    f"A user-controllable DOM source flows to a dangerous sink.\n\n"
                                    f"**Source:** `{source_pattern}` (user input entry point)\n"
                                    f"**Sink:** `{sink_name}` (dangerous function)\n"
                                    f"**Location:** Line ~{line_number}\n\n"
                                    f"This pattern can allow attackers to inject malicious scripts "
                                    f"by manipulating the URL, cookies, or other client-side inputs."
                                ),
                                cwe_id="CWE-79",
                                cvss_score=6.1,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                                    "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                                    "https://cwe.mitre.org/data/definitions/79.html"
                                ],
                                http_capture=http_capture
                            ))
                            break
        
        return vulnerabilities
    
    def _find_dangerous_patterns(
        self,
        js_code: str,
        url: str,
        http_capture: HTTPMessage
    ) -> List[Vulnerability]:
        """Find standalone dangerous patterns"""
        vulnerabilities = []
        
        # Dangerous patterns to look for with descriptions
        dangerous_patterns = [
            # Direct eval of URL data
            (r"eval\s*$\s*(?:location|document\.URL|window\.location)[^)]*$", 
             "eval() with URL data",
             "Direct evaluation of URL-controlled data - critical DOM XSS vector",
             Severity.HIGH),
            
            # innerHTML with URL data
            (r"\.innerHTML\s*=\s*[^;]*(?:location|document\.URL|decodeURI|unescape)",
             "innerHTML with URL data",
             "URL data directly assigned to innerHTML without sanitization",
             Severity.HIGH),
            
            # document.write with URL data
            (r"document\.write(?:ln)?\s*\(\s*[^)]*(?:location|document\.URL|unescape)",
             "document.write() with URL data",
             "URL data passed to document.write - classic DOM XSS",
             Severity.HIGH),
            
            # jQuery selector with URL data
            (r"\$\s*\(\s*(?:location\.hash|location\.search|document\.URL)",
             "jQuery selector with URL data",
             "jQuery selector constructed from URL data can execute scripts",
             Severity.HIGH),
            
            # Unsafe postMessage handler without origin check
            (r"addEventListener\s*\(\s*['\"]message['\"][^}]+(?:eval|innerHTML|document\.write)\s*\(",
             "Unsafe postMessage handler",
             "postMessage handler uses dangerous sink without visible origin validation",
             Severity.MEDIUM),
            
            # Unsafe JSON parsing with eval
            (r"eval\s*\(\s*['\"]?\s*\(?\s*['\"]?\s*\+[^)]*(?:response|data|json)",
             "Unsafe JSON parsing with eval",
             "Using eval() to parse JSON instead of JSON.parse()",
             Severity.MEDIUM),
            
            # location.hash directly used
            (r"(?:innerHTML|outerHTML)\s*=\s*[^;]*location\.hash",
             "location.hash to innerHTML",
             "URL fragment directly assigned to innerHTML",
             Severity.HIGH),
            
            # Unescaped template literals with user data
            (r"`[^`]*\$\{[^}]*(?:location|document\.URL|user|input)[^}]*\}[^`]*`\s*(?:\.innerHTML|document\.write)",
             "Template literal with user data to sink",
             "Template literal containing user data flows to dangerous sink",
             Severity.MEDIUM),
        ]
        
        found_patterns: Set[str] = set()
        
        for pattern, name, description, severity in dangerous_patterns:
            matches = list(re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL))
            
            for match in matches:
                if name in found_patterns:
                    continue
                found_patterns.add(name)
                
                # Get code context
                code_sample = match.group()[:150]
                line_number = js_code[:match.start()].count('\n') + 1
                
                # Get surrounding context with highlighting
                context_start = max(0, match.start() - 100)
                context_end = min(len(js_code), match.end() + 100)
                full_context = js_code[context_start:context_end]
                
                # Highlight the matched code
                highlighted = full_context.replace(
                    match.group(),
                    f">>>PAYLOAD_START>>>{match.group()}<<<PAYLOAD_END<<<"
                )
                
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type=f"DOM XSS - {name}",
                    severity=severity,
                    url=url,
                    parameter="JavaScript Code",
                    payload="N/A (static analysis)",
                    evidence=f"Line ~{line_number}: {code_sample}",
                    evidence_highlight=code_sample,
                    evidence_context=f"...\n{highlighted}\n...",
                    description=(
                        f"**Pattern Detected:** {name}\n\n"
                        f"{description}\n\n"
                        f"**Code Location:** Line ~{line_number}\n"
                        f"**Matched Code:**\n```javascript\n{code_sample}\n```"
                    ),
                    cwe_id="CWE-79",
                    cvss_score=7.5 if severity == Severity.HIGH else 5.4,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                        "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
                    ],
                    http_capture=http_capture
                ))
                break  # One finding per pattern type
        
        return vulnerabilities
    
    async def _test_hash_based(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for hash-based DOM XSS with HTTP capture"""
        vulnerabilities = []
        
        for payload in self.hash_payloads:
            test_url = f"{url}#{payload}"
            
            try:
                response, http_capture = await self.make_request_with_capture(
                    session, "GET", test_url,
                    payload=payload
                )
                
                if not response or not http_capture:
                    continue
                
                html = http_capture.response_body or ""
                
                # Check if payload is reflected in a dangerous context
                reflection_type, is_dangerous = self._check_dangerous_reflection(html, payload)
                
                if is_dangerous:
                    # Get reflection context
                    reflection_context = self._find_reflection_context(html, payload)
                    
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_type="DOM XSS - Hash/Fragment Based",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="URL Fragment (#)",
                        payload=payload,
                        evidence=f"Payload reflected in {reflection_type}",
                        evidence_highlight=payload,
                        evidence_context=reflection_context,
                        description=(
                            f"The URL fragment (hash) is processed unsafely by client-side JavaScript.\n\n"
                            f"**Injection Point:** URL fragment after #\n"
                            f"**Reflection Context:** {reflection_type}\n"
                            f"**Test URL:** `{test_url}`\n\n"
                            f"An attacker can craft a malicious URL with a payload in the fragment "
                            f"that will execute in the victim's browser when they visit the link."
                        ),
                        cwe_id="CWE-79",
                        cvss_score=7.5,
                        remediation=self._get_remediation(),
                        references=[
                            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                            "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                            "https://cwe.mitre.org/data/definitions/79.html"
                        ],
                        http_capture=http_capture
                    ))
                    return vulnerabilities  # Found one, stop testing
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_param_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str]
    ) -> List[Vulnerability]:
        """Test for parameter-based DOM XSS with HTTP capture"""
        vulnerabilities = []
        
        for param_name in params.keys():
            for payload in self.param_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response, http_capture = await self.make_request_with_capture(
                        session, "GET", url,
                        params=test_params,
                        payload=payload
                    )
                    
                    if not response or not http_capture:
                        continue
                    
                    html = http_capture.response_body or ""
                    
                    # Check for dangerous reflection
                    reflection_type, is_dangerous = self._check_dangerous_reflection(html, payload)
                    
                    if is_dangerous:
                        # Get reflection context
                        reflection_context = self._find_reflection_context(html, payload)
                        
                        # Build the test URL for evidence
                        test_url_display = f"{url}?{urlencode(test_params)}"
                        
                        vulnerabilities.append(self.create_vulnerability(
                            vuln_type="DOM XSS - Parameter Based",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Parameter '{param_name}' reflected in {reflection_type}",
                            evidence_highlight=payload,
                            evidence_context=reflection_context,
                            description=(
                                f"The URL parameter `{param_name}` is processed unsafely by client-side JavaScript.\n\n"
                                f"**Vulnerable Parameter:** `{param_name}`\n"
                                f"**Reflection Context:** {reflection_type}\n"
                                f"**Test URL:** `{test_url_display[:200]}...`\n\n"
                                f"User input from the URL parameter flows to a dangerous JavaScript sink, "
                                f"allowing script injection."
                            ),
                            cwe_id="CWE-79",
                            cvss_score=7.5,
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                                "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                                "https://cwe.mitre.org/data/definitions/79.html"
                            ],
                            http_capture=http_capture
                        ))
                        return vulnerabilities  # Found one for this param
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _check_postmessage(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Check for insecure postMessage handlers with HTTP capture"""
        try:
            response, http_capture = await self.make_request_with_capture(
                session, "GET", url
            )
            
            if not response or not http_capture or not http_capture.response_body:
                return None
            
            html = http_capture.response_body
            
            # Look for postMessage event listeners with issues
            postmessage_patterns = [
                # No origin check at all
                (r"addEventListener\s*$\s*['\"]message['\"]\s*,\s*function\s*\(\s*\w+\s*$\s*\{(?:(?!\.origin).){0,500}?(?:innerHTML|eval|document\.write)",
                 "No origin validation",
                 Severity.HIGH),
                # Weak origin check with indexOf
                (r"addEventListener\s*\(\s*['\"]message['\"].*?\.origin\s*\.indexOf\s*\(",
                 "Weak origin check using indexOf() - can be bypassed",
                 Severity.MEDIUM),
                # Origin check with includes (can be bypassed)
                (r"addEventListener\s*\(\s*['\"]message['\"].*?\.origin\s*\.includes\s*\(",
                 "Weak origin check using includes() - can be bypassed",
                 Severity.MEDIUM),
                # Origin compared with != instead of !==
                (r"addEventListener\s*\(\s*['\"]message['\"].*?\.origin\s*!=\s*['\"]",
                 "Loose origin comparison using != instead of !==",
                 Severity.LOW),
            ]
            
            for pattern, issue_desc, severity in postmessage_patterns:
                match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
                if match:
                    code_sample = match.group()[:200]
                    line_number = html[:match.start()].count('\n') + 1
                    
                    # Get context
                    context_start = max(0, match.start() - 50)
                    context_end = min(len(html), match.end() + 50)
                    context = html[context_start:context_end]
                    
                    return self.create_vulnerability(
                        vuln_type="DOM XSS - Insecure postMessage Handler",
                        severity=severity,
                        url=url,
                        parameter="postMessage event handler",
                        payload="N/A (static analysis)",
                        evidence=f"Line ~{line_number}: {issue_desc}",
                        evidence_highlight=code_sample[:100],
                        evidence_context=f"...\n{context}\n...",
                        description=(
                            f"An insecure postMessage event handler was detected.\n\n"
                            f"**Issue:** {issue_desc}\n"
                            f"**Location:** Line ~{line_number}\n\n"
                            f"**Risk:** An attacker can host a malicious page that sends crafted messages "
                            f"to this page via postMessage. Without proper origin validation, "
                            f"the malicious message data may be processed unsafely.\n\n"
                            f"**Attack Scenario:**\n"
                            f"1. Attacker hosts evil.com with an iframe pointing to the vulnerable page\n"
                            f"2. Attacker's page sends: `iframe.contentWindow.postMessage('<script>alert(1)</script>', '*')`\n"
                            f"3. Vulnerable page processes the message without checking origin"
                        ),
                        cwe_id="CWE-79",
                        cvss_score=6.1 if severity == Severity.HIGH else 4.3,
                        remediation=(
                            "**Always validate event.origin strictly:**\n\n"
                            "```javascript\n"
                            "window.addEventListener('message', function(event) {\n"
                            "    // Strict origin check\n"
                            "    if (event.origin !== 'https://trusted-domain.com') {\n"
                            "        return; // Reject messages from untrusted origins\n"
                            "    }\n"
                            "    \n"
                            "    // Also validate message structure/type\n"
                            "    if (typeof event.data !== 'object' || !event.data.type) {\n"
                            "        return;\n"
                            "    }\n"
                            "    \n"
                            "    // Safe to process event.data\n"
                            "});\n"
                            "```\n\n"
                            "**Never use:**\n"
                            "- `origin.indexOf()` - can be bypassed with subdomains\n"
                            "- `origin.includes()` - can be bypassed\n"
                            "- Loose comparison `!=` instead of `!==`"
                        ),
                        references=[
                            "https://portswigger.net/web-security/dom-based/controlling-the-web-message-source",
                            "https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns",
                            "https://owasp.org/www-community/attacks/DOM_Based_XSS"
                        ],
                        http_capture=http_capture
                    )
        
        except Exception:
            pass
        
        return None
    
    def _check_dangerous_reflection(self, html: str, payload: str) -> Tuple[str, bool]:
        """
        Check if payload is reflected in a dangerous context.
        Returns (context_type, is_dangerous)
        """
        # Check for reflection in script tags
        if re.search(
            rf'<script[^>]*>[^<]*{re.escape(payload)}[^<]*</script>',
            html,
            re.IGNORECASE | re.DOTALL
        ):
            return ("JavaScript code block", True)
        
        # Check for reflection in event handlers
        event_handlers = [
            'onclick', 'onerror', 'onload', 'onmouseover', 'onfocus',
            'onblur', 'onsubmit', 'onchange', 'oninput', 'onmouseenter',
            'onkeydown', 'onkeyup', 'onkeypress'
        ]
        
        for handler in event_handlers:
            if re.search(
                rf'{handler}\s*=\s*["\'][^"\']*{re.escape(payload)}',
                html,
                re.IGNORECASE
            ):
                return (f"'{handler}' event handler", True)
        
        # Check for reflection in href javascript:
        if re.search(
            rf'href\s*=\s*["\']javascript:[^"\']*{re.escape(payload)}',
            html,
            re.IGNORECASE
        ):
            return ("javascript: URL", True)
        
        # Check for reflection in src with javascript:
        if re.search(
            rf'src\s*=\s*["\']javascript:[^"\']*{re.escape(payload)}',
            html,
            re.IGNORECASE
        ):
            return ("javascript: src attribute", True)
        
        # Check if payload appears unescaped (potential reflection)
        if payload in html:
            # Check if it's in a script context
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
            for block in script_blocks:
                if payload in block:
                    return ("JavaScript code (unescaped)", True)
            
            return ("HTML body (needs further analysis)", False)
        
        return ("Not reflected", False)
    
    def _find_reflection_context(self, html: str, payload: str, context_chars: int = 150) -> str:
        """Find where payload is reflected and return highlighted context"""
        if payload not in html:
            return "Payload not found in response"
        
        index = html.find(payload)
        start = max(0, index - context_chars)
        end = min(len(html), index + len(payload) + context_chars)
        
        context = html[start:end]
        
        # Add markers around the payload
        highlighted = context.replace(
            payload,
            f">>>PAYLOAD_START>>>{payload}<<<PAYLOAD_END<<<"
        )
        
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(html) else ""
        
        # Try to find line number
        line_num = html[:index].count('\n') + 1
        
        return f"Line ~{line_num}:\n{prefix}{highlighted}{suffix}"
    
    def _extract_code_context(self, js_code: str, position: int, lines_before: int = 2, lines_after: int = 3) -> str:
        """Extract code context around a position with line numbers"""
        lines = js_code.split('\n')
        
        # Find which line the position is on
        current_pos = 0
        target_line = 0
        for i, line in enumerate(lines):
            if current_pos + len(line) >= position:
                target_line = i
                break
            current_pos += len(line) + 1  # +1 for newline
        
        start_line = max(0, target_line - lines_before)
        end_line = min(len(lines), target_line + lines_after + 1)
        
        result_lines = []
        for i in range(start_line, end_line):
            prefix = "→ " if i == target_line else "  "
            result_lines.append(f"{prefix}{i+1}: {lines[i][:120]}")
        
        return "\n".join(result_lines)
    
    def _highlight_source_sink(self, context: str, source_pattern: str, sink_pattern: str) -> str:
        """Highlight source and sink in code context"""
        highlighted = context
        
        # Highlight source
        source_match = re.search(source_pattern, context, re.IGNORECASE)
        if source_match:
            highlighted = highlighted.replace(
                source_match.group(),
                f"[SOURCE: {source_match.group()}]"
            )
        
        # Highlight sink
        for sink_pat, sink_name in self.sinks:
            sink_match = re.search(sink_pat, highlighted, re.IGNORECASE)
            if sink_match:
                highlighted = highlighted.replace(
                    sink_match.group(),
                    f"[SINK: {sink_match.group()}]"
                )
                break
        
        return highlighted
    
    def _get_remediation(self) -> str:
        """Get detailed remediation advice"""
        return """DOM XSS Prevention:

1. Avoid Dangerous Sinks
   - Never use `innerHTML`, `outerHTML`, `document.write()` with user data
   - Avoid `eval()`, `setTimeout(string)`, `setInterval(string)`, `Function()`

2. Use Safe Alternatives
   ```javascript
   // Instead of innerHTML:
   element.textContent = userInput;
   
   // Instead of eval for JSON:
   const data = JSON.parse(jsonString);
   
   // Instead of innerHTML for HTML:
   const sanitized = DOMPurify.sanitize(userInput);
   element.innerHTML = sanitized;
   ```
3. Sanitize User Input
- Use DOMPurify for HTML sanitization: DOMPurify.sanitize(input)
- Encode output based on context (HTML, JS, URL, CSS)

4. Content Security Policy
- Implement strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self'
- Avoid 'unsafe-inline' and 'unsafe-eval'

5. Validate URL Parameters
```javascript
// Validate and sanitize URL data
const param = new URLSearchParams(location.search).get('q');
const safeParam = encodeURIComponent(param);
```
6. Secure postMessage Handlers
```javascript
window.addEventListener('message', (event) => {
    if (event.origin !== 'https://trusted.com') return;
    // Process safely
});
```
References:
- OWASP DOM XSS Prevention Cheat Sheet
- DOMPurify Library: https://github.com/cure53/DOMPurify"""