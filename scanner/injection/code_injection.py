# scanner/injection/code_injection.py
"""
Code Injection Scanner

Detects code injection vulnerabilities including:
- eval() injection
- Dynamic code execution
- Server-side code injection
- Static code injection

OWASP: A05:2025 - Injection
CWE-94: Improper Control of Generation of Code ('Code Injection')
CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')
"""

import re
import asyncio
import time
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class CodeInjectionScanner(BaseScanner):
    """Scanner for Code/Eval Injection vulnerabilities"""
    
    name = "Code Injection Scanner"
    description = "Detects code injection, eval injection, and dynamic code execution vulnerabilities"
    owasp_category = OWASPCategory.A05_INJECTION
    
    # Unique canary for detection
    CANARY = "CodeInjTest7391"
    MATH_RESULT = "5765041"  # 2401 * 2401
    
    # Code injection payloads by language
    PAYLOADS = {
        'php': [
            # Basic eval
            (f"';echo '{CANARY}';'", CANARY, "PHP echo injection"),
            (f"\";echo \"{CANARY}\";\"", CANARY, "PHP double quote echo"),
            (f"1;echo '{CANARY}';", CANARY, "PHP semicolon injection"),
            
            # Function injection
            (f"phpinfo()", "PHP Version", "PHP phpinfo()"),
            (f"';phpinfo();'", "PHP Version", "PHP phpinfo() injection"),
            
            # Math-based detection
            ("${2401*2401}", MATH_RESULT, "PHP variable math"),
            ("{{2401*2401}}", MATH_RESULT, "PHP template math"),
            
            # System functions
            ("';system('id');'", "uid=", "PHP system() injection"),
            ("';passthru('id');'", "uid=", "PHP passthru() injection"),
            ("';exec('id');'", "uid=", "PHP exec() injection"),
            
            # File operations
            ("';print_r(file_get_contents('/etc/passwd'));'", "root:", "PHP file read"),
            
            # Preg_replace /e modifier (legacy)
            ("/e%00", "preg_replace", "PHP preg_replace /e"),
        ],
        
        'python': [
            # Eval injection
            (f"'+str(__import__('os').popen('echo {CANARY}').read())+'", CANARY, "Python os.popen"),
            ("__import__('os').system('id')", "uid=", "Python os.system"),
            
            # Exec injection
            ("exec('import os; os.system(\"id\")')", "uid=", "Python exec()"),
            
            # Math-based
            ("2401*2401", MATH_RESULT, "Python math eval"),
            ("str(2401*2401)", MATH_RESULT, "Python str(math)"),
            
            # Object introspection
            ("''.__class__.__mro__[2].__subclasses__()", "subprocess", "Python subclasses"),
            ("[].__class__.__base__.__subclasses__()", "subprocess", "Python list subclasses"),
        ],
        
        'ruby': [
            # System execution
            (f"`echo {CANARY}`", CANARY, "Ruby backtick injection"),
            (f"%x(echo {CANARY})", CANARY, "Ruby %x injection"),
            ("system('id')", "uid=", "Ruby system()"),
            ("exec('id')", "uid=", "Ruby exec()"),
            
            # Kernel methods
            ("Kernel.system('id')", "uid=", "Ruby Kernel.system"),
            
            # ERB injection
            ("<%= 2401*2401 %>", MATH_RESULT, "Ruby ERB math"),
            ("<%= `id` %>", "uid=", "Ruby ERB command"),
        ],
        
        'javascript': [
            # Node.js
            (f"require('child_process').execSync('echo {CANARY}')", CANARY, "Node.js execSync"),
            ("process.mainModule.require('child_process').execSync('id')", "uid=", "Node.js RCE"),
            
            # Eval injection
            ("eval('2401*2401')", MATH_RESULT, "JS eval math"),
            
            # Constructor injection
            ("constructor.constructor('return 2401*2401')()", MATH_RESULT, "JS constructor"),
            ("this.constructor.constructor('return process')().exit()", "process", "JS process access"),
        ],
        
        'perl': [
            # System execution
            (f"`echo {CANARY}`", CANARY, "Perl backtick"),
            ("system('id')", "uid=", "Perl system()"),
            ("exec('id')", "uid=", "Perl exec()"),
            
            # Eval
            ("eval('2401*2401')", MATH_RESULT, "Perl eval"),
        ],
        
        'generic': [
            # Math-based (works in many languages)
            ("2401*2401", MATH_RESULT, "Math evaluation"),
            ("${2401*2401}", MATH_RESULT, "Variable interpolation math"),
            ("{{2401*2401}}", MATH_RESULT, "Template math"),
            ("{2401*2401}", MATH_RESULT, "Brace math"),
            ("<%=2401*2401%>", MATH_RESULT, "ERB-style math"),
            ("#{2401*2401}", MATH_RESULT, "Ruby/CoffeeScript math"),
        ],
    }
    
    # Time-based payloads for blind detection
    TIME_PAYLOADS = [
        # PHP
        ("';sleep(5);'", 5, "php", "PHP sleep"),
        ("';usleep(5000000);'", 5, "php", "PHP usleep"),
        
        # Python
        ("__import__('time').sleep(5)", 5, "python", "Python time.sleep"),
        ("import time;time.sleep(5)", 5, "python", "Python time import"),
        
        # Ruby
        ("sleep(5)", 5, "ruby", "Ruby sleep"),
        ("Kernel.sleep(5)", 5, "ruby", "Ruby Kernel.sleep"),
        
        # Node.js
        ("require('child_process').execSync('sleep 5')", 5, "javascript", "Node.js sleep"),
        
        # Perl
        ("sleep(5)", 5, "perl", "Perl sleep"),
        
        # Generic (command based)
        (";sleep 5;", 5, "generic", "Command sleep"),
        ("`sleep 5`", 5, "generic", "Backtick sleep"),
    ]
    
    # Error patterns indicating code injection
    ERROR_PATTERNS = {
        'php': [
            r"Parse error:.*eval\(\)",
            r"syntax error.*eval'd",
            r"eval\(\).*failed",
            r"Unexpected.*eval",
            r"Call to undefined function",
            r"preg_replace\(\).*/e",
        ],
        'python': [
            r"SyntaxError:",
            r"NameError:",
            r"eval\(\).*error",
            r"exec\(\).*error",
            r"Traceback \(most recent",
            r"IndentationError:",
        ],
        'ruby': [
            r"SyntaxError.*eval",
            r"NoMethodError",
            r"undefined.*method",
            r"NameError.*eval",
            r"erb.*error",
        ],
        'javascript': [
            r"SyntaxError:",
            r"ReferenceError:",
            r"eval.*error",
            r"Unexpected token",
            r"constructor.*error",
        ],
        'generic': [
            r"syntax error",
            r"parse error",
            r"unexpected.*token",
            r"illegal.*character",
            r"unterminated.*string",
        ],
    }
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for code injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        for param_name, param_value in params.items():
            # Test output-based detection
            output_vuln = await self._test_output_based(
                session, url, params, param_name
            )
            if output_vuln:
                vulnerabilities.append(output_vuln)
                continue
            
            # Test error-based detection
            error_vuln = await self._test_error_based(
                session, url, params, param_name
            )
            if error_vuln:
                vulnerabilities.append(error_vuln)
                continue
            
            # Test time-based detection
            time_vuln = await self._test_time_based(
                session, url, params, param_name
            )
            if time_vuln:
                vulnerabilities.append(time_vuln)
        
        return vulnerabilities
    
    async def _test_output_based(self, session: aiohttp.ClientSession,
                                  url: str, params: Dict[str, str],
                                  param_name: str) -> Optional[Vulnerability]:
        """Test for output-based code injection detection"""
        
        # Test all language payloads
        for lang, payloads in self.PAYLOADS.items():
            for payload, expected, description in payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = await self.make_request(session, "GET", url, params=test_params)
                    if not response:
                        continue
                    
                    body = await response.text()
                    
                    # Check for expected output
                    if expected in body:
                        # Verify it's not just reflection
                        if payload not in body or expected != payload:
                            return self.create_vulnerability(
                                vuln_type="Code Injection",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Code executed, '{expected}' found in response. Language: {lang}",
                                description=f"Code injection vulnerability detected ({description}). The application executes user-supplied code.",
                                cwe_id="CWE-94",
                                cvss_score=9.8,
                                remediation=self._get_remediation(lang),
                                references=[
                                    "https://owasp.org/www-community/attacks/Code_Injection",
                                    "https://cwe.mitre.org/data/definitions/94.html",
                                    "https://cwe.mitre.org/data/definitions/95.html"
                                ]
                            )
                
                except Exception:
                    continue
        
        return None
    
    async def _test_error_based(self, session: aiohttp.ClientSession,
                                 url: str, params: Dict[str, str],
                                 param_name: str) -> Optional[Vulnerability]:
        """Test for error-based code injection detection"""
        
        # Payloads designed to trigger syntax errors
        error_payloads = [
            ("'\"", "Quote mismatch"),
            ("${", "Unclosed variable"),
            ("{{", "Unclosed template"),
            ("<%", "Unclosed ERB"),
            ("){", "Syntax break"),
            ("eval(", "Unclosed eval"),
            ("exec(", "Unclosed exec"),
        ]
        
        for payload, description in error_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                
                # Check for error patterns
                for lang, patterns in self.ERROR_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            return self.create_vulnerability(
                                vuln_type="Potential Code Injection (Error-based)",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Code execution error detected: {re.search(pattern, body, re.IGNORECASE).group()[:100]}",
                                description=f"Error-based code injection indicator ({description}). Language: {lang}",
                                cwe_id="CWE-95",
                                cvss_score=7.5,
                                remediation=self._get_remediation(lang),
                                references=[
                                    "https://cwe.mitre.org/data/definitions/95.html"
                                ]
                            )
            
            except Exception:
                continue
        
        return None
    
    async def _test_time_based(self, session: aiohttp.ClientSession,
                                url: str, params: Dict[str, str],
                                param_name: str) -> Optional[Vulnerability]:
        """Test for time-based blind code injection"""
        
        # Establish baseline
        baseline_times = []
        for _ in range(2):
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
        
        # Test time-based payloads
        for payload, delay, lang, description in self.TIME_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                start = asyncio.get_event_loop().time()
                response = await self.make_request(session, "GET", url, params=test_params)
                elapsed = asyncio.get_event_loop().time() - start
                
                # Check if response was delayed
                if elapsed >= (delay - 1) and elapsed >= (avg_baseline + delay - 1):
                    return self.create_vulnerability(
                        vuln_type="Code Injection (Time-based Blind)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (expected: {delay}s, baseline: {avg_baseline:.2f}s)",
                        description=f"Time-based blind code injection detected ({description}). Language: {lang}",
                        cwe_id="CWE-94",
                        cvss_score=9.8,
                        remediation=self._get_remediation(lang),
                        references=[
                            "https://cwe.mitre.org/data/definitions/94.html"
                        ]
                    )
            
            except asyncio.TimeoutError:
                return self.create_vulnerability(
                    vuln_type="Potential Code Injection (Timeout)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Request timed out with sleep payload",
                    description=f"Potential time-based code injection ({description})",
                    cwe_id="CWE-94",
                    cvss_score=8.0,
                    remediation=self._get_remediation(lang),
                    references=[
                        "https://cwe.mitre.org/data/definitions/94.html"
                    ]
                )
            except Exception:
                continue
        
        return None
    
    def _get_remediation(self, lang: str) -> str:
        """Get language-specific remediation advice"""
        
        base = """
Code Injection Prevention:

1. **NEVER use eval() or similar functions with user input**
2. Use safe alternatives that don't execute code
3. Implement strict input validation with allowlists
4. Use sandboxed environments if dynamic execution is required
5. Apply principle of least privilege
6. Use Content Security Policy (CSP) for client-side protection
"""
        
        lang_specific = {
            'php': """
PHP Specific:
- AVOID: eval(), create_function(), preg_replace with /e, assert()
- AVOID: include/require with user input
- Use prepared statements for database queries
- Use escapeshellarg() for shell commands (but prefer avoiding shell entirely)

WRONG:
```php
eval("echo " . $_GET['input'] . ";");
```
CORRECT:
```php
// Use a whitelist of allowed operations
$allowed = ['add', 'subtract', 'multiply'];
if (in_array($_GET['operation'], $allowed)) {
    // Perform operation safely
}
```
""",
            'python': """
Python Specific:

AVOID: eval(), exec(), compile() with user input
AVOID: import() with user input
Use ast.literal_eval() for safe literal evaluation
Use subprocess with shell=False
WRONG:
```python
result = eval(user_input)
```
CORRECT:
```python
import ast
# Only for simple literals
result = ast.literal_eval(user_input)

# Or use explicit parsing
import operator
ops = {'+': operator.add, '-': operator.sub}
# Parse and execute safely
```
""",
            'ruby': """
Ruby Specific:

AVOID: eval(), instance_eval(), class_eval() with user input
AVOID: send() with user-controlled method names
AVOID: system(), exec(), backticks with user input
Use Open3 with proper escaping for commands
WRONG:
```ruby
eval(params[:code])
```
CORRECT:
```ruby
# Use a whitelist approach
allowed_methods = ['safe_method1', 'safe_method2']
if allowed_methods.include?(params[:method])
  send(params[:method])
end
```
""",
            'javascript': """
JavaScript/Node.js Specific:

AVOID: eval(), Function(), setTimeout/setInterval with strings
AVOID: vm.runInContext() with user input
Use JSON.parse() instead of eval() for JSON
Use child_process.execFile() instead of exec()
WRONG:
```javascript
eval(userInput);
new Function(userInput)();
```
CORRECT:
```javascript
// For JSON parsing
const data = JSON.parse(userInput);

// For dynamic property access
const allowedProps = ['name', 'age'];
if (allowedProps.includes(propName)) {
    value = obj[propName];
}
```
""",
            'perl': """
Perl Specific:

AVOID: eval() with user input
AVOID: backticks and system() with user input
Use taint mode (-T flag)
Use IPC::Run for safe command execution
WRONG:
```perl
eval($user_input);
```
CORRECT:
```perl
use strict;
use warnings;
# Use explicit parsing instead of eval
```
"""}

        return base + lang_specific.get(lang, "")