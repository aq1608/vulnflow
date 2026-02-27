"""
Groq-Optimized AI Enhancement for Vulnflow
==========================================

Maximizes Groq's capabilities for vulnerability scanning:
- Optimized prompts for Llama 3.3 70B
- Structured output parsing
- Smart caching to reduce API calls
- Parallel analysis for speed
- Advanced chain-of-thought reasoning

Installation:
    pip install groq tenacity

Usage:
    from groq_enhanced import GroqEnhancedEngine
    
    engine = GroqEnhancedEngine(api_key=os.getenv('GROQ_API_KEY'))
    result = await engine.analyze_vulnerability(context, vuln_type)
"""

import os
import json
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import hashlib
import time

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("⚠️  Groq not installed: pip install groq")

try:
    from tenacity import retry, stop_after_attempt, wait_exponential
    TENACITY_AVAILABLE = True
except ImportError:
    TENACITY_AVAILABLE = False
    print("⚠️  Tenacity not installed: pip install tenacity")


@dataclass
class GroqConfig:
    """Groq-specific configuration"""
    model: str = "llama-3.3-70b-versatile"  # Best for security analysis
    max_tokens: int = 2048
    temperature: float = 0.1  # Very low for deterministic security analysis
    top_p: float = 0.9
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    
    # Performance settings
    max_retries: int = 3
    timeout: int = 30
    
    # Advanced features
    enable_chain_of_thought: bool = True
    enable_structured_output: bool = True
    enable_caching: bool = True


class GroqEnhancedEngine:
    """
    Enhanced Groq engine optimized for vulnerability scanning.
    
    Key Features:
    - Optimized prompts specifically for Llama 3.3 70B
    - Structured JSON output parsing
    - Intelligent caching (reduce API costs)
    - Parallel analysis for multiple findings
    - Chain-of-thought reasoning for better accuracy
    - Automatic retry with exponential backoff
    """
    
    def __init__(
        self, 
        api_key: Optional[str] = None,
        config: Optional[GroqConfig] = None
    ):
        """
        Initialize Groq enhanced engine.
        
        Args:
            api_key: Groq API key (or uses GROQ_API_KEY env var)
            config: Custom configuration
        """
        if not GROQ_AVAILABLE:
            raise ImportError("Groq library not installed. Run: pip install groq")
        
        self.api_key = api_key or os.getenv('GROQ_API_KEY')
        if not self.api_key:
            raise ValueError("GROQ_API_KEY not found. Set it as environment variable or pass to constructor.")
        
        self.config = config or GroqConfig()
        self.client = Groq(api_key=self.api_key)
        
        # Caching system
        self.cache = {} if self.config.enable_caching else None
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_tokens_used': 0,
            'cache_hits': 0,
            'avg_response_time': []
        }
        
        print(f"✅ Groq Enhanced Engine initialized")
        print(f"   Model: {self.config.model}")
        print(f"   Caching: {'Enabled' if self.config.enable_caching else 'Disabled'}")
        print(f"   Chain-of-Thought: {'Enabled' if self.config.enable_chain_of_thought else 'Disabled'}")
    
    async def analyze_vulnerability(
        self,
        context: Dict[str, Any],
        vulnerability_type: str,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze a potential vulnerability with enhanced Groq analysis.
        
        Args:
            context: Vulnerability context (request, response, tech stack)
            vulnerability_type: Type of vulnerability (sqli, xss, etc.)
            use_cache: Whether to use cached results
        
        Returns:
            Detailed analysis with confidence, reasoning, and recommendations
        """
        # Check cache first
        if use_cache and self.cache is not None:
            cache_key = self._generate_cache_key(context, vulnerability_type)
            if cache_key in self.cache:
                self.cache_hits += 1
                self.stats['cache_hits'] += 1
                print("💾 Cache hit - using cached analysis")
                return self.cache[cache_key]
            self.cache_misses += 1
        
        # Generate optimized prompt
        prompt = self._generate_enhanced_prompt(context, vulnerability_type)
        
        # Analyze with retry logic
        start_time = time.time()
        try:
            result = await self._analyze_with_groq(prompt)
            response_time = time.time() - start_time
            
            self.stats['successful_requests'] += 1
            self.stats['avg_response_time'].append(response_time)
            
            # Cache the result
            if use_cache and self.cache is not None:
                self.cache[cache_key] = result
            
            return result
            
        except Exception as e:
            self.stats['failed_requests'] += 1
            print(f"❌ Groq analysis failed: {str(e)}")
            return self._fallback_analysis(context, vulnerability_type)
    
    async def analyze_batch(
        self,
        contexts: List[Dict],
        vulnerability_types: List[str]
    ) -> List[Dict]:
        """
        Analyze multiple vulnerabilities in parallel.
        
        Args:
            contexts: List of vulnerability contexts
            vulnerability_types: List of corresponding vulnerability types
        
        Returns:
            List of analysis results
        """
        tasks = [
            self.analyze_vulnerability(ctx, vuln_type)
            for ctx, vuln_type in zip(contexts, vulnerability_types)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        return [
            r if not isinstance(r, Exception) else self._fallback_analysis({}, '')
            for r in results
        ]
    
    def _generate_enhanced_prompt(
        self,
        context: Dict,
        vulnerability_type: str
    ) -> str:
        """
        Generate Llama 3.3 70B optimized prompt.
        
        This prompt is specifically designed for Groq's Llama 3.3 70B model
        with structured output and chain-of-thought reasoning.
        """
        
        # Get vulnerability-specific context
        vuln_info = self._get_vulnerability_knowledge(vulnerability_type)
        
        if self.config.enable_chain_of_thought:
            return self._generate_cot_prompt(context, vulnerability_type, vuln_info)
        else:
            return self._generate_direct_prompt(context, vulnerability_type, vuln_info)
    
    def _generate_cot_prompt(
        self,
        context: Dict,
        vulnerability_type: str,
        vuln_info: Dict
    ) -> str:
        """Generate chain-of-thought prompt for deeper analysis"""
        
        return f"""You are an expert security researcher analyzing a potential {vulnerability_type} vulnerability.

**VULNERABILITY TYPE: {vulnerability_type.upper()}**
{vuln_info['description']}

**COMMON INDICATORS:**
{chr(10).join(f"- {ind}" for ind in vuln_info['indicators'])}

**REQUEST DETAILS:**
• URL: {context.get('url', 'N/A')}
• Method: {context.get('method', 'GET')}
• Parameter: {context.get('parameter', 'N/A')}
• Payload: {context.get('payload', 'N/A')}

**RESPONSE DETAILS:**
• Status Code: {context.get('status_code', 0)}
• Response Time: {context.get('response_time', 0)}ms
• Content-Type: {context.get('content_type', 'N/A')}
• Body Preview: {str(context.get('body', ''))[:600]}
• Error Messages: {context.get('errors', [])}

**TECHNOLOGY STACK:**
{', '.join(context.get('tech_stack', ['Unknown']))}

**CHAIN-OF-THOUGHT ANALYSIS:**

Step 1: Initial Assessment
- Is this request suspicious for {vulnerability_type}?
- Does the payload match known attack patterns?

Step 2: Response Analysis
- Did the server respond differently than normal?
- Are there error messages indicating exploitation?
- Is there evidence of WAF/security blocking?

Step 3: Context Evaluation
- Given the technology stack, is this vulnerability possible?
- Are there signs of input sanitization or validation?
- Could this be a false positive?

Step 4: Confidence Calculation
- How confident are you this is a real vulnerability?
- What evidence supports or contradicts this finding?

**OUTPUT REQUIREMENTS:**
Respond ONLY with valid JSON (no markdown, no extra text):

{{
    "is_vulnerable": true or false,
    "confidence": 0.0 to 1.0,
    "severity": "critical" or "high" or "medium" or "low" or "info",
    "reasoning": "Your detailed chain-of-thought reasoning from above",
    "attack_vector": "How this could be exploited (if vulnerable)",
    "false_positive_indicators": ["list any FP signs you noticed"],
    "exploitation_evidence": ["list any actual exploit evidence"],
    "cwe_id": "CWE-XXX",
    "cvss_score": 0.0 to 10.0,
    "recommendations": ["immediate action items"]
}}

Remember: Be thorough but precise. False positives waste time, false negatives are dangerous."""
    
    def _generate_direct_prompt(
        self,
        context: Dict,
        vulnerability_type: str,
        vuln_info: Dict
    ) -> str:
        """Generate direct prompt for faster analysis"""
        
        return f"""Analyze this {vulnerability_type} vulnerability detection.

REQUEST: {context.get('method', 'GET')} {context.get('url', 'N/A')}
PAYLOAD: {context.get('payload', 'N/A')}
RESPONSE STATUS: {context.get('status_code', 0)}
RESPONSE: {str(context.get('body', ''))[:400]}

Is this a true {vulnerability_type} vulnerability?

Respond with JSON only:
{{
    "is_vulnerable": boolean,
    "confidence": float 0-1,
    "severity": "critical/high/medium/low/info",
    "reasoning": "brief explanation",
    "cwe_id": "CWE-XXX"
}}"""
    
    async def _analyze_with_groq(self, prompt: str) -> Dict:
        """
        Call Groq API with retry logic and error handling.
        
        Args:
            prompt: Analysis prompt
        
        Returns:
            Parsed analysis result
        """
        self.stats['total_requests'] += 1
        
        # Use sync API in async context
        response = await asyncio.to_thread(
            self._call_groq_sync,
            prompt
        )
        
        # Track token usage
        if hasattr(response, 'usage'):
            self.stats['total_tokens_used'] += response.usage.total_tokens
        
        # Parse response
        content = response.choices[0].message.content
        return self._parse_json_response(content)
    
    def _call_groq_sync(self, prompt: str):
        """Synchronous Groq API call with retry"""
        
        max_retries = self.config.max_retries
        last_error = None
        
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.config.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert specializing in vulnerability analysis. Always respond with valid JSON only."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    top_p=self.config.top_p,
                    frequency_penalty=self.config.frequency_penalty,
                    presence_penalty=self.config.presence_penalty
                )
                return response
            
            except Exception as e:
                last_error = e
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"⚠️  Groq request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    print(f"   Retrying in {wait_time}s...")
                    time.sleep(wait_time)
        
        raise last_error
    
    def _parse_json_response(self, content: str) -> Dict:
        """
        Parse JSON response from Groq, handling various formats.
        
        Args:
            content: Raw response content
        
        Returns:
            Parsed dictionary
        """
        # Clean up markdown code blocks
        text = content.strip()
        if '```json' in text:
            text = text.split('```json')[1].split('```')[0]
        elif '```' in text:
            text = text.split('```')[1].split('```')[0]
        text = text.strip()
        
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            print(f"⚠️  JSON parse error: {e}")
            print(f"Raw content: {content[:300]}")
            
            # Fallback: try to extract key information
            return {
                'is_vulnerable': 'true' in text.lower() or 'vulnerable' in text.lower(),
                'confidence': 0.5,
                'severity': 'medium',
                'reasoning': f'Failed to parse JSON response. Raw: {text[:200]}',
                'cwe_id': 'CWE-Unknown'
            }
    
    def _get_vulnerability_knowledge(self, vuln_type: str) -> Dict:
        """Get vulnerability-specific knowledge base"""
        
        knowledge_base = {
            'sqli': {
                'description': 'SQL Injection allows attackers to interfere with database queries, potentially reading, modifying, or deleting data.',
                'indicators': [
                    'SQL syntax errors in response',
                    'Database error messages (mysql_fetch, pg_query, etc.)',
                    'Different response for true/false conditions',
                    'Time delays for blind injection',
                    'UNION SELECT data leakage'
                ]
            },
            'xss': {
                'description': 'Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.',
                'indicators': [
                    'Payload reflected in response without encoding',
                    'Script tags in HTML context',
                    'Event handlers (onerror, onload) in attributes',
                    'JavaScript execution context',
                    'DOM manipulation evidence'
                ]
            },
            'cmdi': {
                'description': 'Command Injection allows attackers to execute arbitrary system commands on the server.',
                'indicators': [
                    'System command output (ls, dir, whoami)',
                    'File contents (/etc/passwd)',
                    'Process information',
                    'Time delays from sleep commands',
                    'Command syntax errors'
                ]
            },
            'xxe': {
                'description': 'XML External Entity attacks exploit vulnerable XML parsers to access files, cause DoS, or perform SSRF.',
                'indicators': [
                    'File contents in response',
                    'Internal network access',
                    'XML parsing errors',
                    'Entity expansion evidence'
                ]
            },
            'ssrf': {
                'description': 'Server-Side Request Forgery tricks the server into making requests to unintended locations.',
                'indicators': [
                    'Internal service responses',
                    'Cloud metadata access',
                    'Port scan results',
                    'Time delays indicating connection attempts'
                ]
            },
            'ssti': {
                'description': 'Server-Side Template Injection allows attackers to inject malicious template directives.',
                'indicators': [
                    'Template syntax errors',
                    'Mathematical expressions evaluated',
                    'System information leaked',
                    'Template engine error messages'
                ]
            }
        }
        
        return knowledge_base.get(vuln_type, {
            'description': f'{vuln_type.upper()} vulnerability',
            'indicators': ['Unexpected behavior', 'Error messages', 'Data leakage']
        })
    
    def _generate_cache_key(self, context: Dict, vuln_type: str) -> str:
        """Generate cache key from context"""
        key_data = f"{vuln_type}|{context.get('url', '')}|{context.get('payload', '')}|{context.get('status_code', '')}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _fallback_analysis(self, context: Dict, vuln_type: str) -> Dict:
        """Fallback analysis if Groq fails"""
        return {
            'is_vulnerable': False,
            'confidence': 0.0,
            'severity': 'info',
            'reasoning': 'Groq API request failed - using fallback heuristic',
            'cwe_id': 'CWE-Unknown',
            'recommendations': ['Retry scan', 'Check API quota']
        }
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        avg_time = (
            sum(self.stats['avg_response_time']) / len(self.stats['avg_response_time'])
            if self.stats['avg_response_time'] else 0
        )
        
        return {
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'success_rate': (
                self.stats['successful_requests'] / self.stats['total_requests'] * 100
                if self.stats['total_requests'] > 0 else 0
            ),
            'cache_hits': self.stats['cache_hits'],
            'cache_hit_rate': (
                self.stats['cache_hits'] / self.stats['total_requests'] * 100
                if self.stats['total_requests'] > 0 else 0
            ),
            'total_tokens_used': self.stats['total_tokens_used'],
            'avg_response_time_sec': round(avg_time, 2)
        }
    
    def clear_cache(self):
        """Clear result cache"""
        if self.cache is not None:
            self.cache.clear()
            print("🗑️  Cache cleared")


# Example usage
async def main():
    """Example usage of Groq Enhanced Engine"""
    
    # Initialize engine
    engine = GroqEnhancedEngine()
    
    print("\n" + "="*60)
    print("Testing Groq Enhanced Engine")
    print("="*60 + "\n")
    
    # Test 1: SQL Injection Analysis
    print("🔍 Test 1: SQL Injection Analysis\n")
    
    context1 = {
        'url': 'http://example.com/user?id=1',
        'method': 'GET',
        'parameter': 'id',
        'payload': "1' UNION SELECT username,password FROM users--",
        'status_code': 200,
        'response_time': 145,
        'body': "admin:5f4dcc3b5aa765d61d8327deb882cf99\nuser:e10adc3949ba59abbe56e057f20f883e",
        'headers': {'content-type': 'text/html'},
        'tech_stack': ['nginx', 'php', 'mysql'],
        'errors': []
    }
    
    result1 = await engine.analyze_vulnerability(context1, 'sqli')
    
    print(f"✅ Analysis Complete:")
    print(f"   Vulnerable: {result1['is_vulnerable']}")
    print(f"   Confidence: {result1['confidence']}")
    print(f"   Severity: {result1['severity']}")
    print(f"   CWE: {result1.get('cwe_id', 'N/A')}")
    print(f"   Reasoning: {result1['reasoning'][:150]}...")
    
    # Test 2: False Positive (WAF Block)
    print("\n" + "-"*60)
    print("🔍 Test 2: False Positive Detection (WAF Block)\n")
    
    context2 = {
        'url': 'http://example.com/search?q=test',
        'method': 'GET',
        'parameter': 'q',
        'payload': "<script>alert(1)</script>",
        'status_code': 403,
        'response_time': 25,
        'body': "Access Denied. WAF detected malicious request. Request ID: ABC123",
        'headers': {'x-waf': 'cloudflare', 'content-type': 'text/html'},
        'tech_stack': ['cloudflare', 'nginx'],
        'errors': []
    }
    
    result2 = await engine.analyze_vulnerability(context2, 'xss')
    
    print(f"✅ Analysis Complete:")
    print(f"   Vulnerable: {result2['is_vulnerable']}")
    print(f"   Confidence: {result2['confidence']}")
    print(f"   Severity: {result2['severity']}")
    print(f"   False Positive Indicators: {result2.get('false_positive_indicators', [])}")
    
    # Test 3: Batch Analysis
    print("\n" + "-"*60)
    print("🔍 Test 3: Batch Analysis (3 findings)\n")
    
    contexts = [context1, context2, context1]
    vuln_types = ['sqli', 'xss', 'sqli']
    
    batch_results = await engine.analyze_batch(contexts, vuln_types)
    print(f"✅ Analyzed {len(batch_results)} findings in parallel")
    
    # Statistics
    print("\n" + "="*60)
    print("📊 Engine Statistics")
    print("="*60 + "\n")
    
    stats = engine.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✨ All tests completed!")


if __name__ == "__main__":
    asyncio.run(main())