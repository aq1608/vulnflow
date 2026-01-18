"""
Groq LLM Integration for VulnFlow
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


class GroqAnalyzer:
    """
    Groq LLM-powered vulnerability analyzer with automatic fallback.
    
    Features:
    - Smart vulnerability validation
    - Context-aware payload generation
    - False positive reduction
    - Severity assessment refinement
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
        
        Examples:
            # Option 1: Use environment variable
            analyzer = GroqAnalyzer()
            
            # Option 2: Provide API key directly
            analyzer = GroqAnalyzer(api_key="gsk_...")
            
            # Option 3: No API key (non-AI mode)
            analyzer = GroqAnalyzer()  # Will use fallback if no env var
        """
        # Priority: Manual input > Environment variable > None
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.mode = AnalysisMode.AI_ENABLED if self.api_key else AnalysisMode.NON_AI
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.3-70b-versatile"  # Fast and accurate
        
        # Rate limiting
        self._request_count = 0
        self._last_reset = asyncio.get_event_loop().time()
        self._max_requests_per_minute = 30
        
        # Cache for repeated analysis
        self._analysis_cache: Dict[str, AIAnalysisResult] = {}
        
        if self.mode == AnalysisMode.NON_AI:
            print("⚠️  No GROQ_API_KEY found - running in non-AI mode")
            print("    Set GROQ_API_KEY environment variable or pass api_key parameter to enable AI")
        else:
            # Mask API key in output for security
            masked_key = f"{self.api_key[:7]}...{self.api_key[-4:]}" if len(self.api_key) > 11 else "***"
            print(f"✓ Groq AI enabled - using llama-3.3-70b-versatile")
            print(f"  API Key: {masked_key}")
    
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
        
        Args:
            vuln_type: Type of vulnerability (e.g., "SQL Injection")
            url: Target URL
            parameter: Parameter being tested
            payload: Payload used
            response_evidence: Response/evidence from the test
            context: Additional context (tech stack, previous findings, etc.)
        
        Returns:
            AIAnalysisResult with confidence score and recommendations
        """
        # Create cache key
        cache_key = f"{vuln_type}:{url}:{parameter}:{payload[:50]}"
        
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]
        
        if self.mode == AnalysisMode.AI_ENABLED:
            result = await self._ai_analyze(
                vuln_type, url, parameter, payload, response_evidence, context
            )
        else:
            result = self._non_ai_analyze(
                vuln_type, url, parameter, payload, response_evidence, context
            )
        
        # Cache the result
        self._analysis_cache[cache_key] = result
        return result
    
    async def _ai_analyze(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        response_evidence: str,
        context: Dict[str, Any]
    ) -> AIAnalysisResult:
        """Perform AI-powered analysis using Groq"""
        await self._check_rate_limit()
        
        # Build the analysis prompt
        prompt = self._build_analysis_prompt(
            vuln_type, url, parameter, payload, response_evidence, context
        )
        
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
                            "content": "You are a cybersecurity expert specializing in web application vulnerability analysis. Provide accurate, concise assessments focused on practical exploitation and business impact."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.1,  # Low temperature for consistent security analysis
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
                        
                        return AIAnalysisResult(
                            confidence_score=float(analysis.get("confidence_score", 0.5)),
                            severity_adjustment=analysis.get("severity_adjustment"),
                            ai_reasoning=analysis.get("reasoning", "AI analysis completed"),
                            recommended_payloads=analysis.get("recommended_payloads", []),
                            false_positive_likelihood=float(analysis.get("false_positive_likelihood", 0.5)),
                            exploitation_complexity=analysis.get("exploitation_complexity", "medium"),
                            business_impact=analysis.get("business_impact", "Requires further investigation")
                        )
                    else:
                        # Fallback to non-AI on API error
                        print(f"⚠️  Groq API error (status {response.status}), using fallback analysis")
                        return self._non_ai_analyze(
                            vuln_type, url, parameter, payload, response_evidence, context
                        )
        
        except Exception as e:
            print(f"⚠️  AI analysis failed: {str(e)[:100]}, using fallback")
            return self._non_ai_analyze(
                vuln_type, url, parameter, payload, response_evidence, context
            )
    
    def _non_ai_analyze(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        response_evidence: str,
        context: Dict[str, Any]
    ) -> AIAnalysisResult:
        """Fallback non-AI analysis using heuristics"""
        # Rule-based confidence scoring
        confidence = 0.7  # Default confidence
        
        # Adjust based on evidence quality
        if response_evidence:
            evidence_lower = response_evidence.lower()
            
            # High confidence indicators
            if any(indicator in evidence_lower for indicator in [
                "error", "exception", "stack trace", "warning",
                "mysql", "postgresql", "oracle", "syntax"
            ]):
                confidence = 0.85
            
            # Strong SQL injection indicators
            if vuln_type == "SQL Injection" and any(indicator in evidence_lower for indicator in [
                "sql", "database", "query", "select", "union"
            ]):
                confidence = 0.9
            
            # XSS confirmation
            if vuln_type == "XSS" and any(indicator in evidence_lower for indicator in [
                "<script", "onerror=", "onload=", payload
            ]):
                confidence = 0.95
        
        # Determine exploitation complexity
        complexity_map = {
            "SQL Injection": "medium",
            "XSS": "low",
            "Command Injection": "high",
            "Path Traversal": "low",
            "SSRF": "medium",
            "XXE": "high",
            "IDOR": "low"
        }
        complexity = complexity_map.get(vuln_type, "medium")
        
        # False positive likelihood
        fp_likelihood = 1.0 - confidence
        
        # Business impact assessment
        impact_map = {
            "SQL Injection": "Critical - May allow database extraction or modification",
            "XSS": "High - May allow session hijacking or data theft",
            "Command Injection": "Critical - May allow full system compromise",
            "Path Traversal": "High - May expose sensitive files",
            "SSRF": "High - May allow internal network access",
            "IDOR": "Medium - May expose unauthorized data",
            "XXE": "High - May expose files or cause DoS"
        }
        business_impact = impact_map.get(vuln_type, "Requires manual verification")
        
        return AIAnalysisResult(
            confidence_score=confidence,
            severity_adjustment=None,
            ai_reasoning="Heuristic-based analysis (non-AI mode)",
            recommended_payloads=[],
            false_positive_likelihood=fp_likelihood,
            exploitation_complexity=complexity,
            business_impact=business_impact
        )
    
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
        
        prompt = f"""Generate 5 effective payloads for testing {vuln_type} on a web application.

Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Previous Findings: {', '.join(existing_findings[:3]) if existing_findings else 'None'}

Requirements:
1. Payloads must be realistic and safe for testing
2. Consider the specific tech stack
3. Focus on detection, not exploitation
4. Return as JSON array of strings

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
                        {"role": "system", "content": "You are a penetration testing expert. Generate safe, effective test payloads."},
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
        
        except Exception as e:
            print(f"⚠️  Payload generation failed: {str(e)[:50]}, using fallback")
        
        return self._non_ai_payload_generation(vuln_type, tech_stack)
    
    def _non_ai_payload_generation(
        self,
        vuln_type: str,
        tech_stack: List[str]
    ) -> List[str]:
        """Fallback payload generation"""
        # Tech-specific payload templates
        tech_lower = [t.lower() for t in tech_stack]
        
        payload_map = {
            "SQL Injection": {
                "mysql": ["' OR '1'='1", "' UNION SELECT NULL--", "admin'--"],
                "postgresql": ["'; DROP TABLE test--", "' OR 1=1--"],
                "mssql": ["'; EXEC xp_cmdshell('dir')--", "' OR 1=1--"],
                "default": ["' OR '1'='1", "1' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
            },
            "XSS": {
                "default": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "'-alert(1)-'",
                    "\"><script>alert(document.domain)</script>"
                ]
            },
            "Command Injection": {
                "linux": ["; ls", "| whoami", "; cat /etc/passwd"],
                "windows": ["& dir", "| ipconfig", "; type C:\\Windows\\win.ini"],
                "default": ["; ls", "| whoami", "; id"]
            }
        }
        
        if vuln_type in payload_map:
            # Try to match tech stack
            for tech in tech_lower:
                if tech in payload_map[vuln_type]:
                    return payload_map[vuln_type][tech]
            
            return payload_map[vuln_type].get("default", [])
        
        return []
    
    def _build_analysis_prompt(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        response_evidence: str,
        context: Dict[str, Any]
    ) -> str:
        """Build the analysis prompt for Groq"""
        tech_stack = context.get("tech_stack", []) if context else []
        
        return f"""Analyze this potential {vuln_type} vulnerability:

URL: {url}
Parameter: {parameter}
Payload: {payload}
Response Evidence: {response_evidence[:500]}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}

Provide a JSON response with:
1. confidence_score (0.0-1.0): How confident are you this is a real vulnerability?
2. severity_adjustment ("increase", "decrease", or null): Should severity be adjusted?
3. reasoning: Brief explanation (2-3 sentences)
4. recommended_payloads: List of 3 additional payloads to test (if applicable)
5. false_positive_likelihood (0.0-1.0): Chance this is a false positive
6. exploitation_complexity ("low", "medium", "high")
7. business_impact: One sentence on business impact

Return ONLY valid JSON matching this structure:
{{
  "confidence_score": 0.85,
  "severity_adjustment": null,
  "reasoning": "...",
  "recommended_payloads": ["...", "..."],
  "false_positive_likelihood": 0.15,
  "exploitation_complexity": "medium",
  "business_impact": "..."
}}"""
    
    async def _check_rate_limit(self):
        """Check and enforce rate limiting"""
        current_time = asyncio.get_event_loop().time()
        
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
                self._last_reset = asyncio.get_event_loop().time()
        
        self._request_count += 1
    
    async def summarize_scan_results(
        self,
        vulnerabilities: List[Dict],
        tech_stack: List[str],
        pages_scanned: int
    ) -> str:
        """
        Generate an AI-powered executive summary of scan results.
        
        Returns:
            Markdown-formatted summary
        """
        if self.mode == AnalysisMode.NON_AI or not vulnerabilities:
            return self._non_ai_summary(vulnerabilities, tech_stack, pages_scanned)
        
        await self._check_rate_limit()
        
        # Prepare vulnerability summary
        vuln_summary = {}
        for vuln in vulnerabilities:
            vtype = vuln.get("vuln_type", "Unknown")
            if vtype not in vuln_summary:
                vuln_summary[vtype] = 0
            vuln_summary[vtype] += 1
        
        prompt = f"""Generate an executive summary for this security scan:

Total Pages Scanned: {pages_scanned}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Not detected'}
Vulnerabilities Found: {len(vulnerabilities)}

Vulnerability Breakdown:
{json.dumps(vuln_summary, indent=2)}

Provide:
1. Executive summary (2-3 sentences)
2. Top 3 critical findings
3. Recommended immediate actions
4. Overall risk rating (Low/Medium/High/Critical)

Return as JSON:
{{
  "executive_summary": "...",
  "critical_findings": ["...", "...", "..."],
  "immediate_actions": ["...", "...", "..."],
  "risk_rating": "High"
}}"""
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                data = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a security consultant providing executive summaries."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 600,
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
                        content = json.loads(result["choices"][0]["message"]["content"])
                        
                        return self._format_summary(content)
        
        except Exception:
            pass
        
        return self._non_ai_summary(vulnerabilities, tech_stack, pages_scanned)
    
    def _non_ai_summary(
        self,
        vulnerabilities: List[Dict],
        tech_stack: List[str],
        pages_scanned: int
    ) -> str:
        """Generate non-AI summary"""
        if not vulnerabilities:
            return f"""## Scan Summary

✓ No vulnerabilities detected across {pages_scanned} pages.
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Not detected'}

Continue monitoring for security issues."""
        
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
        
        risk = "Critical" if critical > 0 else "High" if high > 0 else "Medium"
        
        return f"""## Scan Summary

**Risk Rating:** {risk}
**Vulnerabilities Found:** {len(vulnerabilities)}
**Pages Scanned:** {pages_scanned}
**Tech Stack:** {', '.join(tech_stack) if tech_stack else 'Not detected'}

**Immediate Actions:**
1. Address {critical} critical vulnerabilities immediately
2. Review and remediate {high} high-severity issues
3. Implement security best practices

*Non-AI analysis mode*"""
    
    def _format_summary(self, content: Dict) -> str:
        """Format AI summary as markdown"""
        summary = f"""## Executive Summary

{content.get('executive_summary', 'Scan completed')}

**Overall Risk Rating:** {content.get('risk_rating', 'Medium')}

### Critical Findings
"""
        for i, finding in enumerate(content.get('critical_findings', []), 1):
            summary += f"{i}. {finding}\n"
        
        summary += "\n### Immediate Actions\n"
        for i, action in enumerate(content.get('immediate_actions', []), 1):
            summary += f"{i}. {action}\n"
        
        summary += "\n*AI-powered analysis*"
        return summary