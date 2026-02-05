# scanner/ai/recon_agent.py
"""
AI-Powered Reconnaissance Agent

Analyzes targets BEFORE scanning to:
1. Detect technology stack with high accuracy
2. Identify attack surfaces
3. Recommend scanner priorities
4. Generate initial payload strategies
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


@dataclass
class ReconResult:
    """Results from AI reconnaissance"""
    tech_stack: List[str]
    frameworks: List[str]
    server_info: Dict[str, str]
    attack_surfaces: List[Dict]
    recommended_scanners: List[str]
    scanner_priorities: Dict[str, int]  # scanner_name -> priority (1-10)
    owasp_focus: List[str]  # Which OWASP categories to focus on
    custom_payloads: Dict[str, List[str]]  # scanner_name -> payloads
    risk_assessment: str
    reasoning: str


class AIReconAgent:
    """
    Pre-scan AI agent that intelligently analyzes targets.
    
    This runs BEFORE your existing scanners to optimize the scan.
    """
    
    def __init__(self, groq_analyzer):
        """
        Initialize with existing Groq analyzer.
        
        Args:
            groq_analyzer: Your existing GroqAnalyzer instance
        """
        self.ai = groq_analyzer
        self.cache = {}
    
    async def analyze_target(
        self,
        base_url: str,
        crawl_results: Dict,
        session: aiohttp.ClientSession
    ) -> ReconResult:
        """
        Perform AI-powered reconnaissance on target.
        
        Args:
            base_url: Target base URL
            crawl_results: Results from crawler
            session: aiohttp session
        
        Returns:
            ReconResult with recommendations
        """
        print(f"\n[AI Recon] Analyzing target: {base_url}")
        
        # Gather intelligence
        intel = await self._gather_intelligence(base_url, crawl_results, session)
        
        # If AI not available, use heuristic analysis
        if self.ai.mode.value == "non_ai":
            return self._heuristic_recon(intel)
        
        # AI-powered analysis
        return await self._ai_recon(intel, base_url)
    
    async def _gather_intelligence(
        self,
        base_url: str,
        crawl_results: Dict,
        session: aiohttp.ClientSession
    ) -> Dict:
        """Gather raw intelligence about target"""
        
        intel = {
            'base_url': base_url,
            'urls_found': len(crawl_results.get('urls', {})),
            'forms_found': len(crawl_results.get('forms', [])),
            'headers': {},
            'technologies': [],
            'endpoints': [],
            'parameters': set(),
            'file_extensions': set(),
            'response_samples': []
        }
        
        # Analyze headers from base URL
        try:
            async with session.get(base_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                intel['headers'] = dict(resp.headers)
                body = await resp.text()
                intel['response_samples'].append({
                    'url': base_url,
                    'body_preview': body[:2000],
                    'status': resp.status
                })
        except Exception as e:
            intel['headers'] = {'error': str(e)}
        
        # Analyze URL patterns
        urls = crawl_results.get('urls', {})
        if isinstance(urls, dict):
            url_list = list(urls.keys())
        else:
            url_list = urls
        
        for url in url_list[:50]:  # Analyze first 50 URLs
            # Extract file extensions
            if '.' in url.split('/')[-1]:
                ext = url.split('.')[-1].split('?')[0].lower()
                if ext in ['php', 'asp', 'aspx', 'jsp', 'do', 'action', 'py', 'rb', 'cgi']:
                    intel['file_extensions'].add(ext)
            
            # Extract parameters
            if '?' in url:
                params = url.split('?')[1].split('&')
                for p in params:
                    if '=' in p:
                        intel['parameters'].add(p.split('=')[0])
            
            # Identify interesting endpoints
            interesting_keywords = ['admin', 'api', 'login', 'auth', 'user', 'account', 
                                   'upload', 'download', 'config', 'debug', 'test']
            for keyword in interesting_keywords:
                if keyword in url.lower():
                    intel['endpoints'].append({'url': url, 'keyword': keyword})
                    break
        
        # Convert sets to lists for JSON serialization
        intel['parameters'] = list(intel['parameters'])
        intel['file_extensions'] = list(intel['file_extensions'])
        
        # Detect technologies from headers
        intel['technologies'] = self._detect_tech_from_headers(intel['headers'])
        
        return intel
    
    def _detect_tech_from_headers(self, headers: Dict) -> List[str]:
        """Detect technologies from HTTP headers"""
        tech = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Server detection
        server = headers_lower.get('server', '').lower()
        if 'nginx' in server:
            tech.append('Nginx')
        if 'apache' in server:
            tech.append('Apache')
        if 'iis' in server:
            tech.append('IIS')
        if 'cloudflare' in server:
            tech.append('Cloudflare')
        
        # Framework detection
        powered_by = headers_lower.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech.append('PHP')
        if 'asp.net' in powered_by:
            tech.append('ASP.NET')
        if 'express' in powered_by:
            tech.append('Express.js')
        
        # Other indicators
        if 'x-drupal' in headers_lower:
            tech.append('Drupal')
        if 'x-wordpress' in headers_lower or 'link' in headers_lower and 'wp-json' in headers_lower.get('link', ''):
            tech.append('WordPress')
        if 'x-aspnet-version' in headers_lower:
            tech.append('ASP.NET')
        
        return tech
    
    async def _ai_recon(self, intel: Dict, base_url: str) -> ReconResult:
        """Perform AI-powered reconnaissance analysis"""
        
        prompt = f"""Analyze this web application for security testing (OWASP 2025):

Target: {base_url}
URLs Found: {intel['urls_found']}
Forms Found: {intel['forms_found']}
File Extensions: {', '.join(intel['file_extensions']) or 'None detected'}
Parameters Found: {', '.join(intel['parameters'][:20]) or 'None'}
Detected Technologies: {', '.join(intel['technologies']) or 'Unknown'}
Server Headers: {json.dumps(dict(list(intel['headers'].items())[:10]), indent=2)}
Interesting Endpoints: {json.dumps(intel['endpoints'][:10], indent=2)}

Response Preview:
{intel['response_samples'][0]['body_preview'][:1000] if intel['response_samples'] else 'N/A'}

Based on this intelligence, provide:

1. **tech_stack**: Complete list of detected/inferred technologies
2. **frameworks**: Web frameworks detected (Laravel, Django, Spring, etc.)
3. **attack_surfaces**: List of potential attack surfaces with risk level
4. **recommended_scanners**: Which scanners to run (from this list):
   - sqli, nosqli, xss, dom_xss, cmdi, ssti, xxe, xpath, ldapi
   - idor, path_traversal, ssrf, csrf, forced_browsing, jwt
   - headers, cors, ssl_tls, debug, backup, cookie_security
   - session_fixation, weak_password, brute_force
   - deserialization, error_handling, fail_open, resource_limits
   - dependency_check, outdated_components
   - graphql, mass_assignment, rate_limiting

5. **scanner_priorities**: Priority 1-10 for each recommended scanner
6. **owasp_focus**: Top 3 OWASP 2025 categories to focus on
7. **custom_payloads**: Tech-specific payloads for top 5 scanners
8. **risk_assessment**: Overall risk level (low/medium/high/critical)
9. **reasoning**: Brief explanation of your analysis

Return as JSON:
{{
  "tech_stack": ["PHP", "MySQL", ...],
  "frameworks": ["Laravel", ...],
  "attack_surfaces": [
    {{"surface": "Login form", "risk": "high", "tests": ["brute_force", "sqli"]}},
    ...
  ],
  "recommended_scanners": ["sqli", "xss", ...],
  "scanner_priorities": {{"sqli": 10, "xss": 9, ...}},
  "owasp_focus": ["A05", "A01", "A03"],
  "custom_payloads": {{
    "sqli": ["' OR '1'='1'--", ...],
    "xss": ["<script>alert(1)</script>", ...]
  }},
  "risk_assessment": "high",
  "reasoning": "This appears to be a PHP/MySQL application with..."
}}"""

        try:
            # Use existing Groq analyzer infrastructure
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
                            "content": "You are an expert penetration tester performing reconnaissance using OWASP Top 10 2025 methodology."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1500,
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
                        
                        return ReconResult(
                            tech_stack=analysis.get('tech_stack', intel['technologies']),
                            frameworks=analysis.get('frameworks', []),
                            server_info={'headers': intel['headers']},
                            attack_surfaces=analysis.get('attack_surfaces', []),
                            recommended_scanners=analysis.get('recommended_scanners', []),
                            scanner_priorities=analysis.get('scanner_priorities', {}),
                            owasp_focus=analysis.get('owasp_focus', ['A05', 'A01', 'A02']),
                            custom_payloads=analysis.get('custom_payloads', {}),
                            risk_assessment=analysis.get('risk_assessment', 'medium'),
                            reasoning=analysis.get('reasoning', 'AI analysis completed')
                        )
        
        except Exception as e:
            print(f"  ⚠️ AI recon failed: {e}, using heuristics")
        
        return self._heuristic_recon(intel)
    
    def _heuristic_recon(self, intel: Dict) -> ReconResult:
        """Fallback heuristic-based reconnaissance"""
        
        tech_stack = intel['technologies'].copy()
        recommended_scanners = []
        priorities = {}
        owasp_focus = []
        
        # Infer from file extensions
        extensions = intel['file_extensions']
        if 'php' in extensions:
            tech_stack.extend(['PHP', 'MySQL'])
            recommended_scanners.extend(['sqli', 'xss', 'path_traversal', 'cmdi'])
            priorities.update({'sqli': 9, 'xss': 8, 'path_traversal': 7, 'cmdi': 7})
            owasp_focus.append('A05')
        
        if 'asp' in extensions or 'aspx' in extensions:
            tech_stack.extend(['ASP.NET', 'MSSQL'])
            recommended_scanners.extend(['sqli', 'xss', 'deserialization'])
            priorities.update({'sqli': 9, 'deserialization': 8})
        
        if 'jsp' in extensions or 'do' in extensions or 'action' in extensions:
            tech_stack.extend(['Java', 'Spring'])
            recommended_scanners.extend(['sqli', 'ssti', 'deserialization', 'xxe'])
            priorities.update({'deserialization': 9, 'xxe': 8, 'ssti': 8})
        
        # Always recommend these
        base_scanners = ['headers', 'cors', 'ssl_tls', 'cookie_security', 'error_handling']
        recommended_scanners.extend(base_scanners)
        
        # Check for interesting endpoints
        for endpoint in intel['endpoints']:
            keyword = endpoint.get('keyword', '')
            if keyword in ['admin', 'login', 'auth']:
                recommended_scanners.extend(['brute_force', 'session_fixation', 'weak_password'])
                priorities.update({'brute_force': 8, 'session_fixation': 7})
                owasp_focus.append('A07')
            if keyword in ['api']:
                recommended_scanners.extend(['idor', 'mass_assignment', 'rate_limiting', 'jwt'])
                priorities.update({'idor': 9, 'jwt': 8})
                owasp_focus.append('A01')
            if keyword in ['upload']:
                recommended_scanners.extend(['path_traversal', 'ssrf'])
                priorities.update({'path_traversal': 9})
        
        # Deduplicate
        recommended_scanners = list(dict.fromkeys(recommended_scanners))
        tech_stack = list(dict.fromkeys(tech_stack))
        owasp_focus = list(dict.fromkeys(owasp_focus))[:3]
        
        if not owasp_focus:
            owasp_focus = ['A05', 'A01', 'A02']
        
        return ReconResult(
            tech_stack=tech_stack,
            frameworks=[],
            server_info={'headers': intel['headers']},
            attack_surfaces=[
                {'surface': 'Web forms', 'risk': 'medium', 'tests': ['sqli', 'xss']},
                {'surface': 'URL parameters', 'risk': 'medium', 'tests': ['sqli', 'xss', 'idor']}
            ],
            recommended_scanners=recommended_scanners,
            scanner_priorities=priorities,
            owasp_focus=owasp_focus,
            custom_payloads={},
            risk_assessment='medium',
            reasoning='Heuristic-based analysis (AI unavailable)'
        )