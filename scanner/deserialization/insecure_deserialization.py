# scanner/deserialization/insecure_deserialization.py
"""
Insecure Deserialization Scanner

Detects insecure deserialization vulnerabilities in:
- Java (ObjectInputStream)
- PHP (unserialize)
- Python (pickle)
- .NET (BinaryFormatter)
- Node.js (node-serialize)

OWASP: A08:2021 - Software and Data Integrity Failures
CWE-502: Deserialization of Untrusted Data
"""

import asyncio
import aiohttp
import base64
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class InsecureDeserializationScanner(BaseScanner):
    """Scanner for insecure deserialization vulnerabilities"""
    
    name="Insecure Deserialization Scanner",
    description="Detects insecure deserialization vulnerabilities",
    owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES

    def __init__(self):
        
        # Java serialized object signatures
        self.java_signatures = [
            b'\xac\xed\x00\x05',  # Java serialization magic bytes
            "rO0AB",              # Base64 encoded Java object
            "H4sIA",              # Gzip compressed Java object
        ]
        
        # PHP serialization payloads
        self.php_payloads = [
            # Basic object injection
            'O:8:"stdClass":0:{}',
            # POP chain attempt
            'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
            # Dangerous classes (common in vulnerable apps)
            'O:17:"__PHP_Incomplete_Class":0:{}',
            # Serialized array
            'a:1:{s:4:"test";s:4:"test";}',
            # Boolean true
            'b:1;',
            # With null byte
            'O:1:"A":1:{s:1:"a";N;}',
        ]
        
        # Python pickle payloads (detection only, not exploitation)
        self.python_signatures = [
            b'\x80\x03',      # Protocol 3
            b'\x80\x04',      # Protocol 4
            b'\x80\x05',      # Protocol 5
            "gASV",          # Base64 pickle
            "KGxw",          # Base64 pickle (protocol 0)
        ]
        
        # .NET serialization signatures
        self.dotnet_signatures = [
            "AAEAAAD/////",   # BinaryFormatter
            "TVqQ",           # .NET assembly
        ]
        
        # Node.js serialize payloads
        self.nodejs_payloads = [
            '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}',
            '{"__proto__":{"admin":true}}',
            '{"constructor":{"prototype":{"admin":true}}}',
        ]
        
        # Error messages indicating deserialization
        self.error_indicators = [
            # Java
            r"java\.io\.ObjectInputStream",
            r"ClassNotFoundException",
            r"InvalidClassException",
            r"java\.io\.StreamCorruptedException",
            r"java\.lang\.ClassCastException.*deserial",
            r"org\.apache\.commons\.collections",
            r"ysoserial",
            
            # PHP
            r"unserialize\(\)",
            r"__wakeup",
            r"__destruct",
            r"PHP Warning.*unserialize",
            r"allowed_classes",
            
            # Python
            r"pickle\.loads",
            r"_pickle\.UnpicklingError",
            r"cPickle",
            r"marshal\.loads",
            
            # .NET
            r"BinaryFormatter",
            r"ObjectStateFormatter",
            r"NetDataContractSerializer",
            r"SoapFormatter",
            
            # Node.js
            r"node-serialize",
            r"serialize-javascript",
            r"funcster",
        ]
        
        # Common parameter names that might accept serialized data
        self.target_params = [
            "data", "object", "obj", "payload", "state",
            "viewstate", "__VIEWSTATE", "session", "token",
            "serialized", "encoded", "blob", "cache",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for insecure deserialization vulnerabilities.
        """
        vulnerabilities = []
        
        # Detect serialization format in use
        format_detected = await self._detect_serialization_format(session, url, params)
        
        # Test PHP deserialization
        php_vulns = await self._test_php_deserialization(session, url, params)
        vulnerabilities.extend(php_vulns)
        
        # Test Java deserialization
        java_vulns = await self._test_java_deserialization(session, url, params)
        vulnerabilities.extend(java_vulns)
        
        # Test Node.js deserialization
        nodejs_vulns = await self._test_nodejs_deserialization(session, url, params)
        vulnerabilities.extend(nodejs_vulns)
        
        # Test Python pickle
        python_vulns = await self._test_python_pickle(session, url, params)
        vulnerabilities.extend(python_vulns)
        
        # Check for .NET ViewState issues
        viewstate_vulns = await self._test_viewstate(session, url)
        vulnerabilities.extend(viewstate_vulns)
        
        return vulnerabilities
    
    async def _detect_serialization_format(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> Optional[str]:
        """Detect what serialization format is in use"""
        
        if params:
            for key, value in params.items():
                # Check for Java
                if any(sig in str(value) for sig in ["rO0AB", "H4sIA"]):
                    return "java"
                
                # Check for PHP
                if re.match(r'^[OasidbN]:\d+:', str(value)):
                    return "php"
                
                # Check for Python pickle
                if any(sig in str(value) for sig in ["gASV", "KGxw"]):
                    return "python"
                
                # Check for .NET
                if "AAEAAAD" in str(value):
                    return "dotnet"
                
                # Check for JSON (Node.js)
                try:
                    import json
                    data = json.loads(value)
                    if "__proto__" in str(data) or "_$$ND_FUNC$$_" in str(data):
                        return "nodejs"
                except:
                    pass
        
        return None
    
    async def _test_php_deserialization(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Test for PHP unserialize vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            params = {p: "test" for p in self.target_params[:5]}
        
        for param_name in params.keys():
            for payload in self.php_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    async with session.get(
                        url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        response_text = await response.text()
                        
                        # Check for PHP deserialization indicators
                        if self._check_php_indicators(response_text):
                            vulnerabilities.append(Vulnerability(
                                vuln_type="PHP Insecure Deserialization",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=self._extract_evidence(response_text, "php"),
                                description="PHP unserialize() accepts user input, potentially allowing object injection",
                                cwe_id="CWE-502",
                                remediation="Use json_decode() instead of unserialize(). If unserialize is required, use allowed_classes option."
                            ))
                            break
                    
                    # Also test POST
                    async with session.post(
                        url,
                        data=test_params,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        response_text = await response.text()
                        
                        if self._check_php_indicators(response_text):
                            vulnerabilities.append(Vulnerability(
                                vuln_type="PHP Insecure Deserialization",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=self._extract_evidence(response_text, "php"),
                                description="PHP unserialize() accepts user input via POST",
                                cwe_id="CWE-502",
                                remediation="Use json_decode() instead of unserialize(). Validate and sanitize input."
                            ))
                            break
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _test_java_deserialization(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Test for Java deserialization vulnerabilities"""
        vulnerabilities = []
        
        # Java serialized object (minimal, detection purposes)
        # This is a serialized empty HashMap
        java_payload_b64 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAAAdA"
        
        if not params:
            params = {p: "test" for p in self.target_params[:5]}
        
        for param_name in params.keys():
            try:
                test_params = params.copy()
                test_params[param_name] = java_payload_b64
                
                async with session.post(
                    url,
                    data=test_params,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    response_text = await response.text()
                    
                    if self._check_java_indicators(response_text):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Java Insecure Deserialization",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload="Base64 encoded Java object",
                            evidence=self._extract_evidence(response_text, "java"),
                            description="Java ObjectInputStream processes untrusted data, potentially allowing RCE",
                            cwe_id="CWE-502",
                            remediation="Use look-ahead deserialization. Implement ObjectInputFilter. Avoid deserializing untrusted data."
                        ))
                        break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_nodejs_deserialization(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Test for Node.js deserialization and prototype pollution"""
        vulnerabilities = []
        
        for payload in self.nodejs_payloads:
            try:
                # Test as JSON body
                async with session.post(
                    url,
                    json={"data": payload},
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    response_text = await response.text()
                    
                    # Check for prototype pollution success
                    if '"admin":true' in response_text or 'admin' in response_text:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Node.js Prototype Pollution",
                            severity=Severity.HIGH,
                            url=url,
                            parameter="JSON body",
                            payload=payload[:100],
                            evidence="Prototype pollution may have succeeded",
                            description="Application is vulnerable to prototype pollution via deserialization",
                            cwe_id="CWE-1321",
                            remediation="Freeze Object.prototype. Use Map instead of object literals. Validate JSON schema."
                        ))
                        break
                    
                    # Check for node-serialize vulnerability
                    if "_$$ND_FUNC$$_" in payload and self._check_nodejs_indicators(response_text):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Node.js Insecure Deserialization",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter="JSON body",
                            payload=payload[:100],
                            evidence=self._extract_evidence(response_text, "nodejs"),
                            description="node-serialize or similar library allows code execution",
                            cwe_id="CWE-502",
                            remediation="Don't use node-serialize. Use JSON.parse() for data parsing."
                        ))
                        break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_python_pickle(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Test for Python pickle vulnerabilities"""
        vulnerabilities = []
        
        # Simple pickle payload (detection only)
        # This is pickle.dumps({"test": "test"})
        pickle_payload_b64 = "gASVFQAAAAAAAAB9lIwEdGVzdJSMBHRlc3SUcy4="
        
        if not params:
            params = {p: "test" for p in self.target_params[:5]}
        
        for param_name in params.keys():
            try:
                test_params = params.copy()
                test_params[param_name] = pickle_payload_b64
                
                async with session.post(
                    url,
                    data=test_params,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    response_text = await response.text()
                    
                    if self._check_python_indicators(response_text):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Python Pickle Deserialization",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload="Base64 encoded pickle object",
                            evidence=self._extract_evidence(response_text, "python"),
                            description="Python pickle.loads() processes untrusted data, allowing arbitrary code execution",
                            cwe_id="CWE-502",
                            remediation="Never unpickle untrusted data. Use JSON or other safe formats."
                        ))
                        break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_viewstate(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Test for .NET ViewState deserialization issues"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                response_text = await response.text()
                
                # Find ViewState
                viewstate_match = re.search(
                    r'<input[^>]*name="__VIEWSTATE"[^>]*value="([^"]*)"',
                    response_text,
                    re.IGNORECASE
                )
                
                if viewstate_match:
                    viewstate = viewstate_match.group(1)
                    
                    # Check if ViewState is not MAC protected
                    # Unprotected ViewState typically starts without MAC signature
                    try:
                        decoded = base64.b64decode(viewstate)
                        
                        # Check for unprotected ViewState indicators
                        if decoded.startswith(b'\xff\x01'):
                            vulnerabilities.append(Vulnerability(
                                vuln_type=".NET ViewState Deserialization",
                                severity=Severity.HIGH,
                                url=url,
                                parameter="__VIEWSTATE",
                                payload="ViewState detected",
                                evidence=f"ViewState found: {viewstate[:50]}...",
                                description="ASP.NET ViewState may be vulnerable to deserialization attacks",
                                cwe_id="CWE-502",
                                remediation="Enable ViewState MAC validation. Set enableViewStateMac=true."
                            ))
                    except:
                        pass
                    
                    # Check for ViewStateUserKey
                    if '__VIEWSTATEGENERATOR' in response_text and '__EVENTVALIDATION' not in response_text:
                        vulnerabilities.append(Vulnerability(
                            vuln_type=".NET ViewState Missing Protections",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="__VIEWSTATE",
                            payload="N/A",
                            evidence="ViewState without full validation",
                            description="ASP.NET ViewState may lack proper CSRF protection",
                            cwe_id="CWE-352",
                            remediation="Enable EventValidation. Set ViewStateUserKey in Page_Init."
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_php_indicators(self, response: str) -> bool:
        """Check for PHP deserialization indicators"""
        php_patterns = [
            r"unserialize\(\)",
            r"__wakeup",
            r"PHP Warning.*unserialize",
            r"Object of class.*could not be converted",
        ]
        return any(re.search(p, response, re.IGNORECASE) for p in php_patterns)
    
    def _check_java_indicators(self, response: str) -> bool:
        """Check for Java deserialization indicators"""
        java_patterns = [
            r"java\.io\.ObjectInputStream",
            r"ClassNotFoundException",
            r"InvalidClassException",
            r"StreamCorruptedException",
        ]
        return any(re.search(p, response, re.IGNORECASE) for p in java_patterns)
    
    def _check_python_indicators(self, response: str) -> bool:
        """Check for Python pickle indicators"""
        python_patterns = [
            r"pickle\.loads",
            r"UnpicklingError",
            r"cPickle",
            r"_pickle",
        ]
        return any(re.search(p, response, re.IGNORECASE) for p in python_patterns)
    
    def _check_nodejs_indicators(self, response: str) -> bool:
        """Check for Node.js deserialization indicators"""
        nodejs_patterns = [
            r"node-serialize",
            r"serialize-javascript",
            r"IIFE.*function",
        ]
        return any(re.search(p, response, re.IGNORECASE) for p in nodejs_patterns)
    
    def _extract_evidence(self, response: str, tech: str) -> str:
        """Extract relevant evidence from response"""
        patterns = {
            "php": r"(unserialize.*|__wakeup.*|PHP Warning.*)",
            "java": r"(java\.io\.[A-Za-z]+Exception.*|ClassNotFoundException.*)",
            "python": r"(pickle\.[a-z]+.*|UnpicklingError.*)",
            "nodejs": r"(node-serialize.*|prototype.*)",
        }
        
        pattern = patterns.get(tech, r"(error.*|exception.*)")
        match = re.search(pattern, response, re.IGNORECASE)
        
        if match:
            return match.group(1)[:200]
        
        return "Deserialization behavior detected"