# scanner/ai/attack_chain_analyzer.py
"""
AI-Powered Attack Chain Analyzer

Analyzes found vulnerabilities to identify:
1. How vulnerabilities can be chained together
2. Potential escalation paths
3. Business impact assessment
4. Risk prioritization
"""

import json
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class AttackChain:
    """A potential attack chain"""
    name: str
    steps: List[Dict]
    vulnerabilities_used: List[str]
    final_impact: str
    likelihood: str
    severity: str
    mitigation_priority: int


@dataclass
class ChainAnalysisResult:
    """Complete chain analysis result"""
    attack_chains: List[AttackChain]
    critical_paths: List[str]
    business_impact_summary: str
    prioritized_remediations: List[Dict]
    executive_summary: str
    owasp_coverage: Dict[str, int]


class AIAttackChainAnalyzer:
    """
    Analyzes vulnerabilities to find attack chains.
    
    This adds significant value by showing HOW vulnerabilities
    can be exploited together - not just individual findings.
    """
    
    def __init__(self, groq_analyzer):
        self.ai = groq_analyzer
    
    async def analyze_chains(
        self,
        vulnerabilities: List,
        target_info: Dict = None
    ) -> ChainAnalysisResult:
        """
        Analyze vulnerabilities for attack chains.
        
        Args:
            vulnerabilities: List of Vulnerability objects
            target_info: Additional target context
        
        Returns:
            ChainAnalysisResult with attack chains and impact
        """
        if not vulnerabilities:
            return self._empty_result()
        
        # Prepare vulnerability summary for AI
        vuln_summary = self._prepare_vuln_summary(vulnerabilities)
        
        if self.ai.mode.value == "non_ai":
            return self._heuristic_chain_analysis(vulnerabilities, vuln_summary)
        
        return await self._ai_chain_analysis(vulnerabilities, vuln_summary, target_info)
    
    def _prepare_vuln_summary(self, vulnerabilities: List) -> List[Dict]:
        """Prepare vulnerability summary for analysis"""
        summary = []
        
        for i, vuln in enumerate(vulnerabilities):
            summary.append({
                'id': i + 1,
                'type': vuln.vuln_type,
                'severity': vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
                'url': vuln.url,
                'parameter': vuln.parameter,
                'cwe': vuln.cwe_id,
                'owasp': getattr(vuln, 'owasp_category', None)
            })
        
        return summary
    
    async def _ai_chain_analysis(
        self,
        vulnerabilities: List,
        vuln_summary: List[Dict],
        target_info: Dict
    ) -> ChainAnalysisResult:
        """Perform AI-powered chain analysis"""
        
        prompt = f"""Analyze these vulnerabilities for attack chains (OWASP 2025):

Found Vulnerabilities:
{json.dumps(vuln_summary, indent=2)}

Target Info: {json.dumps(target_info or {}, indent=2)}

Analyze:
1. **Attack Chains**: How can these vulnerabilities be combined?
   - Example: XSS → Session Hijacking → Account Takeover
   - Example: IDOR → Data Leak → Privilege Escalation

2. **Critical Paths**: What are the most dangerous attack paths?

3. **Business Impact**: What's the real-world damage potential?

4. **Prioritized Remediation**: What to fix first and why?

Return JSON:
{{
  "attack_chains": [
    {{
      "name": "Account Takeover via XSS Chain",
      "steps": [
        {{"step": 1, "action": "Exploit XSS in search", "vuln_id": 3}},
        {{"step": 2, "action": "Steal session cookie", "vuln_id": null}},
        {{"step": 3, "action": "Access admin panel", "vuln_id": 5}}
      ],
      "vulnerabilities_used": ["XSS", "Session Management"],
      "final_impact": "Full account takeover",
      "likelihood": "high",
      "severity": "critical",
      "mitigation_priority": 1
    }}
  ],
  "critical_paths": [
    "XSS → Session Hijacking → Admin Access",
    "SQLi → Database Dump → Credential Theft"
  ],
  "business_impact_summary": "The combination of these vulnerabilities could lead to...",
  "prioritized_remediations": [
    {{
      "priority": 1,
      "vulnerability": "SQL Injection",
      "reason": "Enables data extraction and is easy to exploit",
      "effort": "medium"
    }}
  ],
  "executive_summary": "This application has critical security issues...",
  "owasp_coverage": {{
    "A01": 3,
    "A05": 5,
    "A07": 2
  }}
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
                            "content": "You are a senior penetration tester analyzing vulnerabilities for attack chains using OWASP 2025 framework."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 2000,
                    "response_format": {"type": "json_object"}
                }
                
                async with session.post(
                    self.ai.base_url,
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        analysis = json.loads(result["choices"][0]["message"]["content"])
                        
                        # Parse attack chains
                        chains = []
                        for chain_data in analysis.get('attack_chains', []):
                            chains.append(AttackChain(
                                name=chain_data.get('name', ''),
                                steps=chain_data.get('steps', []),
                                vulnerabilities_used=chain_data.get('vulnerabilities_used', []),
                                final_impact=chain_data.get('final_impact', ''),
                                likelihood=chain_data.get('likelihood', 'medium'),
                                severity=chain_data.get('severity', 'medium'),
                                mitigation_priority=chain_data.get('mitigation_priority', 99)
                            ))
                        
                        return ChainAnalysisResult(
                            attack_chains=chains,
                            critical_paths=analysis.get('critical_paths', []),
                            business_impact_summary=analysis.get('business_impact_summary', ''),
                            prioritized_remediations=analysis.get('prioritized_remediations', []),
                            executive_summary=analysis.get('executive_summary', ''),
                            owasp_coverage=analysis.get('owasp_coverage', {})
                        )
        
        except Exception as e:
            print(f"  ⚠️ AI chain analysis failed: {e}")
        
        return self._heuristic_chain_analysis(vulnerabilities, vuln_summary)
    
    def _heuristic_chain_analysis(
        self,
        vulnerabilities: List,
        vuln_summary: List[Dict]
    ) -> ChainAnalysisResult:
        """Fallback heuristic chain analysis"""
        
        chains = []
        vuln_types = [v['type'].lower() for v in vuln_summary]
        
        # Common attack chain patterns
        if any('xss' in v for v in vuln_types) and any('session' in v or 'cookie' in v for v in vuln_types):
            chains.append(AttackChain(
                name="XSS to Session Hijacking",
                steps=[
                    {"step": 1, "action": "Inject XSS payload"},
                    {"step": 2, "action": "Steal session cookies"},
                    {"step": 3, "action": "Impersonate user"}
                ],
                vulnerabilities_used=["XSS", "Session Management"],
                final_impact="Account takeover",
                likelihood="high",
                severity="critical",
                mitigation_priority=1
            ))
        
        if any('sql' in v for v in vuln_types):
            chains.append(AttackChain(
                name="SQL Injection Data Breach",
                steps=[
                    {"step": 1, "action": "Exploit SQL injection"},
                    {"step": 2, "action": "Extract database"},
                    {"step": 3, "action": "Access credentials"}
                ],
                vulnerabilities_used=["SQL Injection"],
                final_impact="Data breach, credential theft",
                likelihood="high",
                severity="critical",
                mitigation_priority=1
            ))
        
        if any('ssrf' in v for v in vuln_types):
            chains.append(AttackChain(
                name="SSRF to Internal Access",
                steps=[
                    {"step": 1, "action": "Exploit SSRF"},
                    {"step": 2, "action": "Access internal services"},
                    {"step": 3, "action": "Pivot to cloud metadata"}
                ],
                vulnerabilities_used=["SSRF"],
                final_impact="Internal network access, cloud credential theft",
                likelihood="medium",
                severity="critical",
                mitigation_priority=2
            ))
        
        # Count OWASP categories
        owasp_coverage = {}
        for v in vuln_summary:
            owasp = v.get('owasp')
            if owasp:
                owasp_str = owasp.value if hasattr(owasp, 'value') else str(owasp)
                cat_id = owasp_str.split(':')[0] if ':' in owasp_str else 'Other'
                owasp_coverage[cat_id] = owasp_coverage.get(cat_id, 0) + 1
        
        return ChainAnalysisResult(
            attack_chains=chains,
            critical_paths=[c.name for c in chains[:3]],
            business_impact_summary="Multiple vulnerabilities found that could lead to data breach or account compromise.",
            prioritized_remediations=[
                {"priority": 1, "vulnerability": v['type'], "reason": f"Severity: {v['severity']}", "effort": "medium"}
                for v in sorted(vuln_summary, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4))[:5]
            ],
            executive_summary="Heuristic analysis identified potential attack chains. AI analysis recommended for detailed assessment.",
            owasp_coverage=owasp_coverage
        )
    
    def _empty_result(self) -> ChainAnalysisResult:
        """Return empty result when no vulnerabilities"""
        return ChainAnalysisResult(
            attack_chains=[],
            critical_paths=[],
            business_impact_summary="No vulnerabilities found to analyze.",
            prioritized_remediations=[],
            executive_summary="No security issues detected in this scan.",
            owasp_coverage={}
        )