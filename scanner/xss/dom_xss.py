# scanner/xss/dom_xss.py
"""
DOM-based XSS Scanner

Detects DOM-based Cross-Site Scripting vulnerabilities where:
- User input flows to dangerous JavaScript sinks
- Client-side code uses unsafe DOM manipulation
- URL fragments/parameters are reflected unsafely

OWASP: A03:2021 - Injection
CWE-79: Improper Neutralization of Input During Web Page Generation
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class DOMXSSScanner(BaseScanner):
    """Scanner for DOM-based XSS vulnerabilities"""

    name="DOM-based XSS Scanner",
    description="Detects DOM-based Cross-Site Scripting vulnerabilities",
    owasp_category=OWASPCategory.A03_INJECTION
    
    def __init__(self):

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
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"\.insertAdjacentHTML\s*\(",
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            
            # JavaScript execution sinks
            r"eval\s*\(",
            r"setTimeout\s*\(",
            r"setInterval\s*\(",
            r"Function\s*\(",
            r"execScript\s*\(",
            r"crypto\.generateCRMFRequest\s*\(",
            r"ScriptElement\.src\s*=",
            r"ScriptElement\.text\s*=",
            r"ScriptElement\.textContent\s*=",
            r"ScriptElement\.innerText\s*=",
            
            # URL sinks
            r"location\s*=",
            r"location\.href\s*=",
            r"location\.replace\s*\(",
            r"location\.assign\s*\(",
            r"window\.open\s*\(",
            
            # DOM manipulation sinks
            r"\.src\s*=",
            r"\.href\s*=",
            r"\.action\s*=",
            r"\.data\s*=",
            
            # jQuery sinks
            r"\$\s*\(\s*['\"]<",
            r"\.html\s*\(",
            r"\.append\s*\(",
            r"\.prepend\s*\(",
            r"\.after\s*\(",
            r"\.before\s*\(",
            r"\.replaceWith\s*\(",
            r"\.wrap\s*\(",
            r"\.wrapAll\s*\(",
            
            # Angular sinks
            r"\$sce\.trustAsHtml",
            r"bypassSecurityTrustHtml",
            r"\[innerHTML\]",
            
            # React sinks
            r"dangerouslySetInnerHTML",
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
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for DOM-based XSS vulnerabilities.
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
        """Analyze JavaScript for dangerous source-sink patterns"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                html = await response.text()
            
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
                        async with session.get(
                            script_url,
                            timeout=aiohttp.ClientTimeout(total=5),
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                js_content = await resp.text()
                                all_js += "\n" + js_content
                    except:
                        continue
            
            # Check for source-sink patterns
            source_sink_vulns = self._find_source_sink_patterns(all_js, url)
            vulnerabilities.extend(source_sink_vulns)
            
            # Check for dangerous patterns
            dangerous_vulns = self._find_dangerous_patterns(all_js, url)
            vulnerabilities.extend(dangerous_vulns)
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _find_source_sink_patterns(
        self,
        js_code: str,
        url: str
    ) -> List[Vulnerability]:
        """Find patterns where sources flow to sinks"""
        vulnerabilities = []
        found_patterns: Set[str] = set()
        
        # Check for each source
        for source_pattern in self.sources:
            source_matches = re.finditer(source_pattern, js_code, re.IGNORECASE)
            
            for source_match in source_matches:
                # Get context around the source (next 200 chars)
                context_start = source_match.start()
                context_end = min(len(js_code), source_match.end() + 200)
                context = js_code[context_start:context_end]
                
                # Check if any sink is in the context
                for sink_pattern in self.sinks:
                    if re.search(sink_pattern, context, re.IGNORECASE):
                        pattern_key = f"{source_pattern}->{sink_pattern}"
                        
                        if pattern_key not in found_patterns:
                            found_patterns.add(pattern_key)
                            
                            # Extract the specific code
                            code_sample = context[:150].replace('\n', ' ')
                            
                            vulnerabilities.append(Vulnerability(
                                vuln_type="DOM XSS - Source to Sink",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter="JavaScript Code",
                                payload="N/A (code analysis)",
                                evidence=f"Source: {source_pattern}, Code: {code_sample}...",
                                description=f"User-controllable source flows to dangerous sink",
                                cwe_id="CWE-79",
                                remediation=self._get_remediation()
                            ))
                            break
        
        return vulnerabilities
    
    def _find_dangerous_patterns(
        self,
        js_code: str,
        url: str
    ) -> List[Vulnerability]:
        """Find standalone dangerous patterns"""
        vulnerabilities = []
        
        # Dangerous patterns to look for
        dangerous_patterns = [
            # Direct eval of URL data
            (r"eval\s*\(\s*(?:location|document\.URL|window\.location)", 
             "eval() with URL data", Severity.HIGH),
            
            # innerHTML with URL data
            (r"\.innerHTML\s*=\s*(?:location|document\.URL|decodeURI)",
             "innerHTML with URL data", Severity.HIGH),
            
            # document.write with URL data
            (r"document\.write\s*\(\s*(?:location|document\.URL|unescape)",
             "document.write with URL data", Severity.HIGH),
            
            # jQuery with URL data
            (r"\$\s*\(\s*(?:location\.hash|location\.search|document\.URL)",
             "jQuery selector with URL data", Severity.HIGH),
            
            # Unsafe postMessage handler
            (r"addEventListener\s*\(\s*['\"]message['\"].*(?:eval|innerHTML|document\.write)",
             "Unsafe postMessage handler", Severity.MEDIUM),
            
            # Unsafe JSON parsing
            (r"eval\s*\(\s*['\"]?\s*\(\s*['\"]?\s*\+.*JSON",
             "Unsafe JSON parsing with eval", Severity.MEDIUM),
        ]
        
        for pattern, description, severity in dangerous_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                code_sample = match.group()[:100]
                
                vulnerabilities.append(Vulnerability(
                    vuln_type="DOM XSS - Dangerous Pattern",
                    severity=severity,
                    url=url,
                    parameter="JavaScript Code",
                    payload="N/A (code analysis)",
                    evidence=code_sample,
                    description=description,
                    cwe_id="CWE-79",
                    remediation=self._get_remediation()
                ))
                break  # One per pattern
        
        return vulnerabilities
    
    async def _test_hash_based(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for hash-based DOM XSS"""
        vulnerabilities = []
        
        for payload in self.hash_payloads:
            test_url = f"{url}#{payload}"
            
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    html = await response.text()
                    
                    # Check if payload is reflected in a dangerous context
                    if self._check_dangerous_reflection(html, payload):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="DOM XSS - Hash Based",
                            severity=Severity.HIGH,
                            url=url,
                            parameter="URL Fragment (#)",
                            payload=payload,
                            evidence="Payload reflected in potentially dangerous context",
                            description="URL hash is processed unsafely by client-side code",
                            cwe_id="CWE-79",
                            remediation=self._get_remediation()
                        ))
                        break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_param_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str]
    ) -> List[Vulnerability]:
        """Test for parameter-based DOM XSS"""
        vulnerabilities = []
        
        for param_name in params.keys():
            for payload in self.param_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    async with session.get(
                        url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        html = await response.text()
                        
                        if self._check_dangerous_reflection(html, payload):
                            vulnerabilities.append(Vulnerability(
                                vuln_type="DOM XSS - Parameter Based",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence="Parameter reflected via JavaScript",
                                description="URL parameter processed unsafely by client-side code",
                                cwe_id="CWE-79",
                                remediation=self._get_remediation()
                            ))
                            return vulnerabilities
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _check_postmessage(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Check for insecure postMessage handlers"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                html = await response.text()
            
            # Look for postMessage event listeners
            postmessage_patterns = [
                # No origin check
                r"addEventListener\s*$\s*['\"]message['\"].*function\s*\([^)]*$\s*\{(?:(?!origin).)*?(innerHTML|eval|document\.write)",
                # Weak origin check
                r"addEventListener\s*\(\s*['\"]message['\"].*\.origin\s*\.indexOf\s*\(",
                # Origin check with includes (can be bypassed)
                r"addEventListener\s*\(\s*['\"]message['\"].*\.origin\s*\.includes\s*\(",
            ]
            
            for pattern in postmessage_patterns:
                if re.search(pattern, html, re.IGNORECASE | re.DOTALL):
                    return Vulnerability(
                        vuln_type="DOM XSS - Insecure postMessage",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="postMessage handler",
                        payload="N/A",
                        evidence="Potentially insecure postMessage handler found",
                        description="postMessage handler may not properly validate origin",
                        cwe_id="CWE-79",
                        remediation="Always validate event.origin against a whitelist before processing postMessage data."
                    )
        
        except Exception:
            pass
        
        return None
    
    def _check_dangerous_reflection(self, html: str, payload: str) -> bool:
        """Check if payload is reflected in a dangerous context"""
        # Check for reflection in script tags
        if re.search(
            rf'<script[^>]*>.*{re.escape(payload)}.*</script>',
            html,
            re.IGNORECASE | re.DOTALL
        ):
            return True
        
        # Check for reflection in event handlers
        event_handlers = [
            'onclick', 'onerror', 'onload', 'onmouseover', 'onfocus',
            'onblur', 'onsubmit', 'onchange', 'oninput'
        ]
        
        for handler in event_handlers:
            if re.search(
                rf'{handler}\s*=\s*["\'][^"\']*{re.escape(payload)}',
                html,
                re.IGNORECASE
            ):
                return True
        
        # Check for reflection in href javascript:
        if re.search(
            rf'href\s*=\s*["\']javascript:[^"\']*{re.escape(payload)}',
            html,
            re.IGNORECASE
        ):
            return True
        
        return False
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Avoid using dangerous sinks like innerHTML, eval(), document.write()
2. Use safe alternatives:
   - textContent instead of innerHTML
   - JSON.parse() instead of eval() for JSON
   - createElement/appendChild instead of innerHTML
3. Sanitize user input before use with DOMPurify or similar
4. Use Content Security Policy (CSP) to mitigate impact
5. Validate and sanitize URL parameters and fragments
6. For postMessage, always validate event.origin strictly

Example safe code:
```javascript
// Instead of:
element.innerHTML = userInput;

// Use:
element.textContent = userInput;
// Or with DOMPurify:
element.innerHTML = DOMPurify.sanitize(userInput);
"""