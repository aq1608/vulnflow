# scanner/cryptographic/weak_crypto.py
"""
Weak Cryptography Scanner

Detects weak cryptographic implementations:
- Weak hashing algorithms (MD5, SHA1)
- Weak encryption (DES, RC4)
- Hardcoded cryptographic keys
- Insecure random number generation

OWASP: A02:2021 - Cryptographic Failures
CWE-327: Use of a Broken or Risky Cryptographic Algorithm
"""

import asyncio
import aiohttp
import re
import hashlib
from typing import List, Dict, Optional
from urllib.parse import urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class WeakCryptoScanner(BaseScanner):
    """Scanner for weak cryptography vulnerabilities"""
    
    name="Weak Cryptography Scanner",
    description="Detects weak cryptographic implementations",
    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES

    def __init__(self):
        
        # Patterns for weak crypto detection
        self.weak_crypto_patterns = {
            # Weak hashing algorithms
            "md5_hash": {
                "pattern": r"\b[a-fA-F0-9]{32}\b",
                "context_pattern": r"(?:md5|hash|checksum|password).*[a-fA-F0-9]{32}|[a-fA-F0-9]{32}.*(?:md5|hash)",
                "description": "MD5 hash detected",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-328"
            },
            "sha1_hash": {
                "pattern": r"\b[a-fA-F0-9]{40}\b",
                "context_pattern": r"(?:sha1|hash|checksum|password).*[a-fA-F0-9]{40}|[a-fA-F0-9]{40}.*(?:sha1|hash)",
                "description": "SHA1 hash detected (considered weak)",
                "severity": Severity.LOW,
                "cwe": "CWE-328"
            },
            
            # Hardcoded keys/secrets in JavaScript
            "hardcoded_key": {
                "pattern": r"(?:key|secret|password|api_key|apiKey|token)\s*[=:]\s*['\"][a-zA-Z0-9+/=]{16,}['\"]",
                "description": "Hardcoded cryptographic key or secret",
                "severity": Severity.HIGH,
                "cwe": "CWE-798"
            },
            "hardcoded_iv": {
                "pattern": r"(?:iv|nonce|salt)\s*[=:]\s*['\"][a-zA-Z0-9+/=]{8,}['\"]",
                "description": "Hardcoded IV/nonce/salt",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-329"
            },
            
            # Weak encryption references
            "des_encryption": {
                "pattern": r"(?:DES|3DES|TripleDES)(?:[^a-zA-Z]|$)",
                "description": "DES encryption detected (deprecated)",
                "severity": Severity.HIGH,
                "cwe": "CWE-327"
            },
            "rc4_encryption": {
                "pattern": r"(?:RC4|ARC4|ARCFOUR)(?:[^a-zA-Z]|$)",
                "description": "RC4 encryption detected (broken)",
                "severity": Severity.HIGH,
                "cwe": "CWE-327"
            },
            "ecb_mode": {
                "pattern": r"(?:ECB|ecb)(?:_mode|Mode|\s*mode)?",
                "description": "ECB mode detected (insecure block cipher mode)",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-327"
            },
            
            # Insecure random
            "math_random": {
                "pattern": r"Math\.random\s*$\s*$",
                "description": "Math.random() used (not cryptographically secure)",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-338"
            },
            "weak_random": {
                "pattern": r"(?:rand|random|srand)\s*\(",
                "context_pattern": r"(?:crypto|encrypt|key|token|session|password).*(?:rand|random)\s*\(",
                "description": "Potentially weak random number generation",
                "severity": Severity.LOW,
                "cwe": "CWE-338"
            },
            
            # Base64 encoded secrets (often mistaken for encryption)
            "base64_secret": {
                "pattern": r"(?:password|secret|key|token)\s*[=:]\s*['\"](?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?['\"]",
                "description": "Base64-encoded secret (encoding is not encryption)",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-261"
            },
        }
        
        # Common weak/test encryption keys
        self.weak_keys = [
            "0000000000000000",
            "1234567890123456",
            "abcdefghijklmnop",
            "password12345678",
            "secretkey1234567",
            "0123456789abcdef",
            "aaaaaaaaaaaaaaaa",
            "test",
            "key",
            "secret",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for weak cryptography vulnerabilities.
        """
        vulnerabilities = []
        
        # Scan main URL
        main_vulns = await self._scan_url(session, url)
        vulnerabilities.extend(main_vulns)
        
        # Scan JavaScript files
        js_vulns = await self._scan_javascript_files(session, url)
        vulnerabilities.extend(js_vulns)
        
        # Check response headers for crypto-related issues
        header_vulns = await self._check_headers(session, url)
        vulnerabilities.extend(header_vulns)
        
        # Deduplicate
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln.vuln_type, vuln.url, vuln.evidence[:50] if vuln.evidence else "")
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    async def _scan_url(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Scan URL content for weak crypto patterns"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check each pattern
                    for pattern_name, config in self.weak_crypto_patterns.items():
                        matches = re.findall(config["pattern"], content, re.IGNORECASE)
                        
                        if matches:
                            # If context pattern exists, verify context
                            if "context_pattern" in config:
                                context_matches = re.findall(
                                    config["context_pattern"], 
                                    content, 
                                    re.IGNORECASE
                                )
                                if not context_matches:
                                    continue
                            
                            # Limit evidence
                            evidence = matches[0] if matches else ""
                            if len(evidence) > 50:
                                evidence = evidence[:47] + "..."
                            
                            vulnerabilities.append(Vulnerability(
                                vuln_type=f"Weak Cryptography - {config['description']}",
                                severity=config["severity"],
                                url=url,
                                parameter="response content",
                                payload="N/A",
                                evidence=f"Pattern found: {evidence}",
                                description=config["description"],
                                cwe_id=config["cwe"],
                                remediation=self._get_remediation(pattern_name)
                            ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _scan_javascript_files(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Scan JavaScript files for weak crypto"""
        vulnerabilities = []
        
        try:
            # Get main page
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Find JavaScript file references
                    js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
                    js_files = re.findall(js_pattern, content, re.IGNORECASE)
                    
                    parsed = urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    
                    # Scan each JS file (limit to first 5)
                    for js_file in js_files[:5]:
                        if js_file.startswith("//"):
                            js_url = f"{parsed.scheme}:{js_file}"
                        elif js_file.startswith("/"):
                            js_url = f"{base_url}{js_file}"
                        elif js_file.startswith("http"):
                            js_url = js_file
                        else:
                            js_url = f"{base_url}/{js_file}"
                        
                        js_vulns = await self._scan_js_content(session, js_url)
                        vulnerabilities.extend(js_vulns)
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _scan_js_content(
        self,
        session: aiohttp.ClientSession,
        js_url: str
    ) -> List[Vulnerability]:
        """Scan JavaScript file content"""
        vulnerabilities = []
        
        try:
            async with session.get(
                js_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check for hardcoded keys
                    key_patterns = [
                        (r'(?:encryption|crypto|aes|des)Key\s*[=:]\s*["\']([^"\']+)["\']', "Encryption key"),
                        (r'(?:secret|api)Key\s*[=:]\s*["\']([^"\']+)["\']', "API/Secret key"),
                        (r'(?:iv|nonce)\s*[=:]\s*["\']([^"\']+)["\']', "IV/Nonce"),
                        (r'CryptoJS\.enc\.Utf8\.parse$["\']([^"\']+)["\']$', "CryptoJS key"),
                    ]
                    
                    for pattern, key_type in key_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if len(match) >= 8:  # Minimum key length
                                # Check if it's a weak/test key
                                is_weak = match.lower() in [k.lower() for k in self.weak_keys]
                                
                                vulnerabilities.append(Vulnerability(
                                    vuln_type=f"Weak Cryptography - Hardcoded {key_type}",
                                    severity=Severity.HIGH if is_weak else Severity.MEDIUM,
                                    url=js_url,
                                    parameter="JavaScript source",
                                    payload="N/A",
                                    evidence=f"{key_type}: {match[:20]}..." if len(match) > 20 else f"{key_type}: {match}",
                                    description=f"Hardcoded {key_type.lower()} found in JavaScript",
                                    cwe_id="CWE-798",
                                    remediation=self._get_remediation("hardcoded_key")
                                ))
                    
                    # Check for Math.random() in crypto context
                    if "Math.random()" in content:
                        # Check if used near crypto operations
                        crypto_keywords = ["encrypt", "decrypt", "token", "key", "random", "generate"]
                        lines = content.split('\n')
                        
                        for i, line in enumerate(lines):
                            if "Math.random()" in line:
                                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+3)])
                                if any(kw in context.lower() for kw in crypto_keywords):
                                    vulnerabilities.append(Vulnerability(
                                        vuln_type="Weak Cryptography - Insecure Random",
                                        severity=Severity.MEDIUM,
                                        url=js_url,
                                        parameter="JavaScript source",
                                        payload="Math.random()",
                                        evidence="Math.random() used in potentially cryptographic context",
                                        description="Math.random() is not cryptographically secure",
                                        cwe_id="CWE-338",
                                        remediation=self._get_remediation("math_random")
                                    ))
                                    break
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_headers(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check response headers for crypto issues"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                # Check for weak cipher suites indication
                # This is limited without TLS inspection
                
                # Check Set-Cookie for weak session handling
                cookies = response.headers.getall('Set-Cookie', [])
                for cookie in cookies:
                    # Check for MD5-looking session IDs
                    if re.search(r'session[^=]*=\s*[a-f0-9]{32}[;\s]', cookie, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Weak Cryptography - MD5 Session ID",
                            severity=Severity.LOW,
                            url=url,
                            parameter="Set-Cookie",
                            payload="N/A",
                            evidence="Session ID appears to be MD5 hash",
                            description="Session ID may be using weak MD5 hash",
                            cwe_id="CWE-328",
                            remediation="Use cryptographically secure session ID generation"
                        ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation advice based on pattern"""
        remediations = {
            "md5_hash": """
Use stronger hashing algorithms:
- For passwords: bcrypt, scrypt, or Argon2
- For integrity: SHA-256 or SHA-3
- Never use MD5 for security purposes
""",
            "sha1_hash": """
Upgrade to SHA-256 or SHA-3:
- SHA-1 is deprecated for cryptographic use
- For passwords, use bcrypt, scrypt, or Argon2
""",
            "hardcoded_key": """
Never hardcode cryptographic keys:
1. Use environment variables for keys
2. Use secure key management systems (AWS KMS, HashiCorp Vault)
3. Generate keys dynamically when possible
4. Rotate keys regularly

Example:
// Bad
const key = "hardcodedSecretKey123";

// Good
const key = process.env.ENCRYPTION_KEY;
""",
            "hardcoded_iv": """
Never hardcode IVs or nonces:

Generate unique IV for each encryption
IVs don't need to be secret but must be unique
Store IV alongside ciphertext
Example:

const iv = crypto.randomBytes(16); // Generate fresh IV
""",
            "des_encryption": """
Replace DES with AES:

DES has 56-bit keys (easily brute-forced)
Use AES-256 for symmetric encryption
Use authenticated encryption (AES-GCM)
""",
            "rc4_encryption": """
Replace RC4 with AES:
RC4 has known biases and vulnerabilities
Use AES-GCM for authenticated encryption
Ensure proper key management
""",
            "ecb_mode": """
Never use ECB mode:
ECB reveals patterns in data
Use CBC, CTR, or GCM mode
Prefer authenticated encryption (GCM)
Example:

// Bad
crypto.createCipheriv('aes-256-ecb', key, null);

// Good
crypto.createCipheriv('aes-256-gcm', key, iv);
""",
            "math_random": """
Use cryptographically secure random:

// Bad
const token = Math.random().toString(36);

// Good (Node.js)
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');

// Good (Browser)
const array = new Uint8Array(32);
crypto.getRandomValues(array);
""",
            "base64_secret": """
Base64 is encoding, not encryption:

Base64 provides no security

Use proper encryption (AES-GCM)

Never expose secrets in client-side code
""",
            }


        return remediations.get(pattern_name, "Use modern, secure cryptographic algorithms and practices.")