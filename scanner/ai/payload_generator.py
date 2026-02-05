# scanner/ai/payload_generator.py
"""
AI-Powered Payload Generator

Generates context-aware payloads for each scanner module.
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class PayloadSet:
    """Generated payload set for a scanner"""
    scanner_name: str
    payloads: List[str]
    detection_patterns: List[str]
    encoding_variants: List[str]
    bypass_techniques: List[str]
    tech_specific: bool
    reasoning: str


class AIPayloadGenerator:
    """
    Generates intelligent payloads for scanner modules.
    
    Works WITH your existing scanners - enhances their payloads.
    """
    
    def __init__(self, groq_analyzer):
        self.ai = groq_analyzer
        self.cache = {}
    
    async def generate_for_scanner(
        self,
        scanner_name: str,
        tech_stack: List[str],
        target_info: Dict = None,
        existing_payloads: List[str] = None
    ) -> PayloadSet:
        """
        Generate enhanced payloads for a specific scanner.
        
        Args:
            scanner_name: Name of scanner (e.g., 'sqli', 'xss')
            tech_stack: Detected technologies
            target_info: Additional target information
            existing_payloads: Scanner's existing payloads (to avoid duplicates)
        
        Returns:
            PayloadSet with enhanced payloads
        """
        cache_key = f"{scanner_name}_{'-'.join(sorted(tech_stack))}"
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        if self.ai.mode.value == "non_ai":
            return self._get_default_payloads(scanner_name, tech_stack)
        
        result = await self._generate_ai_payloads(
            scanner_name, tech_stack, target_info, existing_payloads
        )
        
        self.cache[cache_key] = result
        return result
    
    async def _generate_ai_payloads(
        self,
        scanner_name: str,
        tech_stack: List[str],
        target_info: Dict,
        existing_payloads: List[str]
    ) -> PayloadSet:
        """Generate payloads using AI"""
        
        # Map scanner names to vulnerability types
        vuln_type_map = {
            'sqli': 'SQL Injection',
            'nosqli': 'NoSQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'dom_xss': 'DOM-based XSS',
            'cmdi': 'OS Command Injection',
            'ssti': 'Server-Side Template Injection',
            'xxe': 'XML External Entity (XXE)',
            'ssrf': 'Server-Side Request Forgery (SSRF)',
            'path_traversal': 'Path Traversal',
            'idor': 'Insecure Direct Object Reference (IDOR)',
            'csrf': 'Cross-Site Request Forgery (CSRF)',
            'ldapi': 'LDAP Injection',
            'xpath': 'XPath Injection',
            'deserialization': 'Insecure Deserialization',
            'jwt': 'JWT Vulnerabilities',
            'error_handling': 'Error Information Disclosure',
            'fail_open': 'Security Control Bypass (Fail-Open)',
        }
        
        vuln_type = vuln_type_map.get(scanner_name, scanner_name)
        
        prompt = f"""Generate advanced payloads for testing {vuln_type} vulnerabilities.

Target Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Scanner Module: {scanner_name}
OWASP 2025 Context: Focus on latest attack techniques

Requirements:
1. Generate 10-15 effective payloads
2. Include WAF bypass techniques
3. Include encoding variants
4. Consider the specific tech stack
5. Include detection patterns (what to look for in responses)

{"Existing payloads (avoid duplicates): " + str(existing_payloads[:5]) if existing_payloads else ""}

Return JSON:
{{
  "payloads": [
    "payload1",
    "payload2",
    ...
  ],
  "detection_patterns": [
    "error pattern 1",
    "success indicator 1",
    ...
  ],
  "encoding_variants": [
    "URL encode",
    "Double URL encode",
    "Unicode",
    ...
  ],
  "bypass_techniques": [
    "Technique 1: description",
    ...
  ],
  "reasoning": "Why these payloads are effective for this tech stack"
}}"""

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.ai.api_key}",
                    "Content-Type": "application/json"
                }
                
                data = {
                    "model": self.ai.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a penetration testing expert specializing in payload crafting for OWASP Top 10 2025 vulnerabilities."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 1000,
                    "response_format": {"type": "json_object"}
                }
                
                async with session.post(
                    self.ai.base_url,
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        analysis = json.loads(result["choices"][0]["message"]["content"])
                        
                        return PayloadSet(
                            scanner_name=scanner_name,
                            payloads=analysis.get('payloads', []),
                            detection_patterns=analysis.get('detection_patterns', []),
                            encoding_variants=analysis.get('encoding_variants', []),
                            bypass_techniques=analysis.get('bypass_techniques', []),
                            tech_specific=bool(tech_stack),
                            reasoning=analysis.get('reasoning', '')
                        )
        
        except Exception as e:
            print(f"  ⚠️ AI payload generation failed for {scanner_name}: {e}")
        
        return self._get_default_payloads(scanner_name, tech_stack)
    
    def _get_default_payloads(self, scanner_name: str, tech_stack: List[str]) -> PayloadSet:
        """Return default payloads when AI is unavailable"""
        
        # Your existing payloads from groq_analyzer._non_ai_payload_generation
        default_payloads = {
            'sqli': {
                'payloads': ["'", "' OR '1'='1", "' OR '1'='1'--", "1' AND '1'='1", "'; SELECT version()--"],
                'detection_patterns': ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "sqlite3"],
            },
            'xss': {
                'payloads': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
                'detection_patterns': ["<script>alert(1)</script>", "onerror=alert"],
            },
            'cmdi': {
                'payloads': ["; ls", "| whoami", "&& id", "$(id)", "; cat /etc/passwd"],
                'detection_patterns': ["root:", "uid=", "bin/bash"],
            },
            'ssrf': {
                'payloads': ["http://localhost/", "http://127.0.0.1/", "http://169.254.169.254/"],
                'detection_patterns': ["localhost", "127.0.0.1", "meta-data"],
            },
            'path_traversal': {
                'payloads': ["../../../etc/passwd", "....//....//etc/passwd", "..\\..\\..\\windows\\win.ini"],
                'detection_patterns': ["root:x:", "[fonts]", "bin/bash"],
            },
        }
        
        default = default_payloads.get(scanner_name, {'payloads': [], 'detection_patterns': []})
        
        return PayloadSet(
            scanner_name=scanner_name,
            payloads=default.get('payloads', []),
            detection_patterns=default.get('detection_patterns', []),
            encoding_variants=['URL encode', 'Double URL encode'],
            bypass_techniques=[],
            tech_specific=False,
            reasoning='Default payloads (AI unavailable)'
        )
    
    async def generate_for_all_scanners(
        self,
        scanner_names: List[str],
        tech_stack: List[str],
        priority_scanners: List[str] = None
    ) -> Dict[str, PayloadSet]:
        """
        Generate payloads for multiple scanners.
        
        Args:
            scanner_names: List of scanner names
            tech_stack: Detected technologies
            priority_scanners: Scanners to generate AI payloads for (others get defaults)
        
        Returns:
            Dict mapping scanner names to PayloadSets
        """
        results = {}
        
        # Use AI for priority scanners only (to save API calls)
        priority = priority_scanners or scanner_names[:5]
        
        for scanner_name in scanner_names:
            if scanner_name in priority:
                results[scanner_name] = await self.generate_for_scanner(
                    scanner_name, tech_stack
                )
            else:
                results[scanner_name] = self._get_default_payloads(scanner_name, tech_stack)
        
        return results