# scanner/cryptographic/sensitive_data_exposure.py
"""
Sensitive Data Exposure Scanner

Detects exposure of sensitive data:
- Credit card numbers
- Social Security Numbers
- API keys and secrets
- Private keys
- Passwords in responses
- PII (Personally Identifiable Information)

OWASP: A02:2021 - Cryptographic Failures
CWE-200: Exposure of Sensitive Information
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class SensitiveDataExposureScanner(BaseScanner):
    """Scanner for sensitive data exposure"""
    
    name="Sensitive Data Exposure Scanner",
    description="Detects exposure of sensitive data in responses",
    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES

    def __init__(self):
        
        # Sensitive data patterns with descriptions
        self.patterns = {
            # Credit Cards
            "credit_card_visa": {
                "pattern": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
                "description": "Visa credit card number",
                "severity": Severity.CRITICAL,
            },
            "credit_card_mastercard": {
                "pattern": r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b",
                "description": "Mastercard credit card number",
                "severity": Severity.CRITICAL,
            },
            "credit_card_amex": {
                "pattern": r"\b3[47][0-9]{13}\b",
                "description": "American Express card number",
                "severity": Severity.CRITICAL,
            },
            
            # SSN
            "ssn": {
                "pattern": r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
                "description": "Social Security Number",
                "severity": Severity.CRITICAL,
            },
            
            # API Keys and Secrets
            "aws_access_key": {
                "pattern": r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
                "description": "AWS Access Key ID",
                "severity": Severity.CRITICAL,
            },
            "aws_secret_key": {
                "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
                "description": "AWS Secret Access Key",
                "severity": Severity.CRITICAL,
            },
            "github_token": {
                "pattern": r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
                "description": "GitHub Personal Access Token",
                "severity": Severity.HIGH,
            },
            "google_api_key": {
                "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b",
                "description": "Google API Key",
                "severity": Severity.HIGH,
            },
            "stripe_key": {
                "pattern": r"\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}\b",
                "description": "Stripe API Key",
                "severity": Severity.CRITICAL,
            },
            "slack_token": {
                "pattern": r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b",
                "description": "Slack Token",
                "severity": Severity.HIGH,
            },
            "jwt_token": {
                "pattern": r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b",
                "description": "JWT Token (may contain sensitive claims)",
                "severity": Severity.MEDIUM,
            },
            
            # Private Keys
            "private_key_rsa": {
                "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
                "description": "RSA Private Key",
                "severity": Severity.CRITICAL,
            },
            "private_key_generic": {
                "pattern": r"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----",
                "description": "Private Key",
                "severity": Severity.CRITICAL,
            },
            "private_key_pgp": {
                "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
                "description": "PGP Private Key",
                "severity": Severity.CRITICAL,
            },
            
            # Passwords
            "password_field": {
                "pattern": r"(?i)['\"]?password['\"]?\s*[:=]\s*['\"]([^'\"]{3,})['\"]",
                "description": "Password in response",
                "severity": Severity.HIGH,
            },
            "password_hash_md5": {
                "pattern": r"\b[a-fA-F0-9]{32}\b(?=.*(?:password|pwd|pass|hash))",
                "description": "MD5 password hash",
                "severity": Severity.MEDIUM,
            },
            "password_hash_sha": {
                "pattern": r"\b[a-fA-F0-9]{64}\b(?=.*(?:password|pwd|pass|hash))",
                "description": "SHA-256 password hash",
                "severity": Severity.MEDIUM,
            },
            "password_hash_bcrypt": {
                "pattern": r"\$2[aby]?\$\d{1,2}\$[.\/A-Za-z0-9]{53}",
                "description": "Bcrypt password hash",
                "severity": Severity.LOW,  # Lower since bcrypt is more secure
            },
            
            # Database Connection Strings
            "mongodb_uri": {
                "pattern": r"mongodb(?:\+srv)?://[^\s\"']+",
                "description": "MongoDB Connection String",
                "severity": Severity.CRITICAL,
            },
            "mysql_uri": {
                "pattern": r"mysql://[^\s\"']+",
                "description": "MySQL Connection String",
                "severity": Severity.CRITICAL,
            },
            "postgres_uri": {
                "pattern": r"postgres(?:ql)?://[^\s\"']+",
                "description": "PostgreSQL Connection String",
                "severity": Severity.CRITICAL,
            },
            
            # Email Addresses (in bulk may indicate data leak)
            "email_bulk": {
                "pattern": r"[\w.+-]+@[\w-]+\.[\w.-]+",
                "description": "Email addresses",
                "severity": Severity.LOW,
                "min_count": 10,  # Only flag if many found
            },
            
            # Phone Numbers
            "phone_us": {
                "pattern": r"\b(?:\+1[-.\s]?)?$?[0-9]{3}$?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
                "description": "US Phone Number",
                "severity": Severity.LOW,
                "min_count": 5,
            },
            
            # Internal URLs/IPs
            "internal_ip": {
                "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
                "description": "Internal IP Address",
                "severity": Severity.LOW,
            },
        }
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for sensitive data exposure.
        """
        vulnerabilities = []
        
        # Scan main URL
        main_vulns = await self._scan_url(session, url)
        vulnerabilities.extend(main_vulns)
        
        # Scan with parameters if provided
        if params:
            param_vulns = await self._scan_url_with_params(session, url, params)
            vulnerabilities.extend(param_vulns)
        
        # Scan common API endpoints
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        api_endpoints = [
            "/api/users",
            "/api/user",
            "/api/profile",
            "/api/account",
            "/api/config",
            "/api/settings",
        ]
        
        for endpoint in api_endpoints:
            try:
                endpoint_url = urljoin(base_url, endpoint)
                endpoint_vulns = await self._scan_url(session, endpoint_url)
                vulnerabilities.extend(endpoint_vulns)
            except:
                continue
        
        # Deduplicate
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln.vuln_type, vuln.evidence[:50])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    async def _scan_url(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Scan a URL for sensitive data"""
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
                    for pattern_name, config in self.patterns.items():
                        matches = list(re.finditer(config["pattern"], content))
                        
                        min_count = config.get("min_count", 1)
                        
                        if len(matches) >= min_count:
                            # Get sample evidence (mask sensitive data)
                            evidence = self._mask_sensitive_data(
                                matches[0].group(), pattern_name
                            )
                            
                            vulnerabilities.append(Vulnerability(
                                vuln_type=f"Sensitive Data Exposure - {config['description']}",
                                severity=config["severity"],
                                url=url,
                                parameter="Response Body",
                                payload="N/A",
                                evidence=f"Found {len(matches)} instance(s): {evidence}",
                                description=f"{config['description']} exposed in response",
                                cwe_id="CWE-200",
                                remediation=self._get_remediation(pattern_name)
                            ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _scan_url_with_params(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str]
    ) -> List[Vulnerability]:
        """Scan URL with parameters"""
        vulnerabilities = []
        
        try:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check for sensitive data patterns
                    for pattern_name, config in self.patterns.items():
                        if re.search(config["pattern"], content):
                            evidence = self._mask_sensitive_data(
                                re.search(config["pattern"], content).group(),
                                pattern_name
                            )
                            
                            vulnerabilities.append(Vulnerability(
                                vuln_type=f"Sensitive Data Exposure - {config['description']}",
                                severity=config["severity"],
                                url=url,
                                parameter=str(list(params.keys())),
                                payload="N/A",
                                evidence=evidence,
                                description=f"{config['description']} exposed with parameters",
                                cwe_id="CWE-200",
                                remediation=self._get_remediation(pattern_name)
                            ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _mask_sensitive_data(self, data: str, pattern_name: str) -> str:
        """Mask sensitive data for safe logging"""
        if len(data) <= 8:
            return data[:2] + "*" * (len(data) - 2)
        
        # Show first 4 and last 4 characters
        if "credit_card" in pattern_name or "ssn" in pattern_name:
            return data[:4] + "*" * (len(data) - 8) + data[-4:]
        
        if "key" in pattern_name.lower() or "token" in pattern_name.lower():
            return data[:8] + "*" * (len(data) - 12) + data[-4:]
        
        if "password" in pattern_name.lower():
            return "*" * len(data)
        
        # Default masking
        return data[:4] + "*" * (len(data) - 8) + data[-4:] if len(data) > 8 else data
    
    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation advice based on pattern type"""
        remediations = {
            "credit_card": "Never store or transmit credit card numbers in plaintext. Use tokenization and PCI-DSS compliant payment processors.",
            "ssn": "Never expose SSNs. Implement proper access controls and data masking.",
            "aws": "Rotate AWS credentials immediately. Use IAM roles instead of access keys. Never commit credentials to code.",
            "private_key": "Revoke and regenerate private keys immediately. Never expose private keys in responses.",
            "password": "Never return passwords in API responses. Use proper authentication flows.",
            "database": "Move connection strings to environment variables. Never expose database credentials.",
            "token": "Implement proper token handling. Don't expose tokens in URLs or responses unnecessarily.",
        }
        
        for key, advice in remediations.items():
            if key in pattern_name.lower():
                return advice
        
        return "Implement proper data handling and access controls. Minimize exposure of sensitive data."