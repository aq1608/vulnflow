"""
Intelligent False Positive Filter for Vulnflow
==============================================

Multi-stage false positive detection system that significantly
reduces noise in vulnerability scanning results.

Features:
- Pattern-based quick filtering (Stage 1)
- Context-aware analysis (Stage 2)
- AI-powered deep analysis (Stage 3)
- Learning from historical data

Usage:
    filter = IntelligentFalsePositiveFilter(ai_client, learning_engine)
    result = await filter.analyze_finding(vulnerability, request, response)
"""

import re
from typing import Dict, List, Optional, Set
from difflib import SequenceMatcher
import hashlib


class IntelligentFalsePositiveFilter:
    """
    Multi-stage false positive detection system.
    
    Stages:
    1. Pattern Matching - Fast regex-based detection
    2. Context Analysis - Response comparison and heuristics
    3. AI Deep Analysis - LLM-powered verification
    """
    
    def __init__(self, ai_client=None, learning_engine=None):
        """
        Initialize false positive filter.
        
        Args:
            ai_client: Optional AI client for deep analysis
            learning_engine: Optional learning engine for historical patterns
        """
        self.ai_client = ai_client
        self.learning_engine = learning_engine
        self.fp_patterns = self._initialize_patterns()
        
        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'stage1_filtered': 0,
            'stage2_filtered': 0,
            'stage3_filtered': 0,
            'passed': 0
        }
    
    def _initialize_patterns(self) -> Dict[str, List[str]]:
        """Initialize false positive detection patterns"""
        return {
            'waf_indicators': [
                r'waf\s*blocked',
                r'modsecurity',
                r'cloudflare',
                r'imperva',
                r'f5\s*big-?ip',
                r'akamai',
                r'security\s*violation',
                r'access\s*denied',
                r'request\s*blocked',
                r'threat\s*detected',
                r'malicious\s*activity',
                r'suspicious\s*request',
                r'invalid\s*request',
                r'攻击检测',  # Chinese WAF
                r'security.*denied',
            ],
            
            'error_pages': [
                r'404\s*not\s*found',
                r'500\s*internal\s*server\s*error',
                r'403\s*forbidden',
                r'502\s*bad\s*gateway',
                r'503\s*service\s*unavailable',
                r'nginx.*error',
                r'apache.*error',
            ],
            
            'rate_limiting': [
                r'rate\s*limit',
                r'too\s*many\s*requests',
                r'quota\s*exceeded',
                r'throttle',
                r'429\s*too\s*many',
            ],
            
            'generic_errors': [
                r'bad\s*request',
                r'invalid\s*parameter',
                r'malformed\s*request',
                r'syntax\s*error.*unexpected',
                r'parse\s*error.*unexpected',
            ],
            
            'sanitization_indicators': [
                r'input\s*validation\s*failed',
                r'invalid\s*input',
                r'sanitized',
                r'filtered\s*out',
                r'not\s*allowed',
                r'contains\s*illegal',
            ]
        }
    
    async def analyze_finding(
        self,
        vulnerability: Dict,
        request: Dict,
        response: Dict,
        baseline_response: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze a finding through multi-stage filtering.
        
        Args:
            vulnerability: Vulnerability details
            request: Request that triggered the finding
            response: Response received
            baseline_response: Optional baseline response for comparison
        
        Returns:
            Analysis result with FP determination
        """
        self.stats['total_analyzed'] += 1
        
        result = {
            'is_false_positive': False,
            'confidence': vulnerability.get('confidence', 0.6),
            'original_confidence': vulnerability.get('confidence', 0.6),
            'reasons': [],
            'stage_filtered': None,
            'recommendation': 'investigate'
        }
        
        # Stage 1: Pattern Matching (Fast)
        stage1 = await self._stage1_pattern_matching(vulnerability, request, response)
        if stage1['is_false_positive']:
            self.stats['stage1_filtered'] += 1
            result.update(stage1)
            result['stage_filtered'] = 'stage1'
            result['recommendation'] = 'discard'
            return result
        
        # Stage 2: Context Analysis (Medium)
        stage2 = await self._stage2_context_analysis(
            vulnerability, 
            request, 
            response,
            baseline_response
        )
        if stage2['is_false_positive']:
            self.stats['stage2_filtered'] += 1
            result.update(stage2)
            result['stage_filtered'] = 'stage2'
            result['recommendation'] = 'low_priority'
            return result
        
        # Stage 3: AI Deep Analysis (Thorough but slower)
        if self.ai_client:
            stage3 = await self._stage3_ai_deep_analysis(
                vulnerability,
                request,
                response
            )
            if stage3['is_false_positive']:
                self.stats['stage3_filtered'] += 1
                result.update(stage3)
                result['stage_filtered'] = 'stage3'
                result['recommendation'] = 'review'
                return result
        
        # Passed all filters - likely a true positive
        self.stats['passed'] += 1
        result['recommendation'] = 'high_priority'
        return result
    
    async def _stage1_pattern_matching(
        self,
        vulnerability: Dict,
        request: Dict,
        response: Dict
    ) -> Dict:
        """
        Stage 1: Fast pattern-based detection.
        Checks for obvious WAF blocks, error pages, etc.
        """
        response_body = str(response.get('body', '')).lower()
        response_headers = {k.lower(): v.lower() for k, v in response.get('headers', {}).items()}
        status_code = response.get('status_code', 0)
        
        reasons = []
        
        # Check for WAF indicators in body
        for pattern in self.fp_patterns['waf_indicators']:
            if re.search(pattern, response_body, re.IGNORECASE):
                reasons.append(f"WAF indicator detected: {pattern}")
        
        # Check for WAF headers
        waf_headers = {
            'x-waf': 'WAF header present',
            'x-cdn': 'CDN protection detected',
            'cf-ray': 'Cloudflare protection',
            'x-sucuri-id': 'Sucuri WAF detected',
            'x-protected-by': 'Security service detected'
        }
        for header, reason in waf_headers.items():
            if header in response_headers:
                reasons.append(reason)
        
        # Check for error pages
        for pattern in self.fp_patterns['error_pages']:
            if re.search(pattern, response_body, re.IGNORECASE):
                reasons.append(f"Error page detected: {pattern}")
        
        # Check for rate limiting
        if status_code == 429 or 'retry-after' in response_headers:
            reasons.append("Rate limiting detected")
        
        for pattern in self.fp_patterns['rate_limiting']:
            if re.search(pattern, response_body, re.IGNORECASE):
                reasons.append(f"Rate limit indicator: {pattern}")
        
        # Check for input sanitization messages
        for pattern in self.fp_patterns['sanitization_indicators']:
            if re.search(pattern, response_body, re.IGNORECASE):
                reasons.append(f"Input sanitization detected: {pattern}")
        
        # Specific status codes that usually indicate blocking
        blocking_status_codes = {
            403: "Access forbidden",
            406: "Not acceptable",
            418: "I'm a teapot (often used by WAFs)",
            444: "Connection closed (nginx blocking)"
        }
        if status_code in blocking_status_codes:
            reasons.append(f"{blocking_status_codes[status_code]} (Status {status_code})")
        
        is_fp = len(reasons) > 0
        
        return {
            'is_false_positive': is_fp,
            'confidence': 0.9 if is_fp else 0.0,
            'reasons': reasons
        }
    
    async def _stage2_context_analysis(
        self,
        vulnerability: Dict,
        request: Dict,
        response: Dict,
        baseline_response: Optional[Dict] = None
    ) -> Dict:
        """
        Stage 2: Context-aware analysis.
        Compares responses, checks timing, analyzes patterns.
        """
        reasons = []
        response_body = response.get('body', '')
        status_code = response.get('status_code', 0)
        
        # Compare with baseline if available
        if baseline_response:
            similarity = self._calculate_similarity(
                response_body,
                baseline_response.get('body', '')
            )
            
            # If response is too similar to baseline, likely not exploited
            if similarity > 0.95:
                reasons.append(
                    f"Response too similar to baseline ({similarity:.2%}) - "
                    "likely not exploited"
                )
        
        # Check response size
        body_length = len(response_body)
        if body_length < 100:
            reasons.append(
                f"Very short response ({body_length} chars) - "
                "possibly blocked or error"
            )
        
        # Analyze response content characteristics
        if self._is_generic_error_page(response_body):
            reasons.append("Generic error page detected")
        
        # Check for payload reflection without execution
        payload = request.get('payload', '')
        if payload and payload in response_body:
            # Check if it's just reflected, not executed
            if not self._has_execution_evidence(
                payload, 
                response_body, 
                vulnerability.get('type', '')
            ):
                reasons.append(
                    "Payload reflected but no execution evidence found"
                )
        
        # Timing analysis for time-based injections
        if vulnerability.get('type') in ['sqli', 'cmdi', 'xxe']:
            response_time = response.get('response_time', 0)
            baseline_time = baseline_response.get('response_time', 0) if baseline_response else 0
            
            # If it's supposed to be a time-based attack but no delay
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                if response_time < baseline_time + 1000:  # Expected delay
                    reasons.append(
                        f"Time-based payload but no delay detected "
                        f"({response_time}ms vs expected delay)"
                    )
        
        # Check for security headers that might indicate protection
        headers = response.get('headers', {})
        security_headers = ['x-xss-protection', 'content-security-policy', 'x-frame-options']
        if any(h.lower() in [k.lower() for k in headers.keys()] for h in security_headers):
            # Don't mark as FP but reduce confidence
            pass
        
        # Learn from history if available
        if self.learning_engine:
            historical_fp = self.learning_engine.check_historical_false_positive(
                vulnerability.get('type', ''),
                self._hash_response(response_body[:500]),
                request.get('tech_stack', [])
            )
            if historical_fp:
                reasons.append(
                    f"Similar pattern was false positive in past "
                    f"({historical_fp['occurrences']} times)"
                )
        
        is_fp = len(reasons) >= 2  # Require multiple indicators
        
        return {
            'is_false_positive': is_fp,
            'confidence': 0.75 if is_fp else 0.0,
            'reasons': reasons
        }
    
    async def _stage3_ai_deep_analysis(
        self,
        vulnerability: Dict,
        request: Dict,
        response: Dict
    ) -> Dict:
        """
        Stage 3: AI-powered deep analysis.
        Most thorough but slowest stage.
        """
        if not self.ai_client:
            return {'is_false_positive': False, 'confidence': 0.0, 'reasons': []}
        
        prompt = self._generate_fp_analysis_prompt(vulnerability, request, response)
        
        try:
            # Query AI
            ai_result = await self.ai_client.analyze(prompt)
            
            return {
                'is_false_positive': ai_result.get('is_false_positive', False),
                'confidence': ai_result.get('confidence', 0.5),
                'reasons': [ai_result.get('reasoning', 'AI analysis completed')]
            }
        
        except Exception as e:
            print(f"⚠️  AI analysis failed: {e}")
            return {'is_false_positive': False, 'confidence': 0.0, 'reasons': []}
    
    def _generate_fp_analysis_prompt(
        self,
        vulnerability: Dict,
        request: Dict,
        response: Dict
    ) -> str:
        """Generate prompt for AI false positive analysis"""
        return f"""Analyze if this is a FALSE POSITIVE vulnerability detection.

**Vulnerability Details:**
- Type: {vulnerability.get('type', 'unknown')}
- Severity: {vulnerability.get('severity', 'unknown')}
- Confidence: {vulnerability.get('confidence', 0.0)}

**Request:**
- URL: {request.get('url', 'N/A')}
- Method: {request.get('method', 'N/A')}
- Payload: {request.get('payload', 'N/A')}

**Response:**
- Status Code: {response.get('status_code', 'N/A')}
- Response Time: {response.get('response_time', 'N/A')}ms
- Headers: {response.get('headers', {})}
- Body Preview: {str(response.get('body', ''))[:500]}

**Critical Questions:**
1. Is this a WAF or security tool blocking the request?
2. Is the response a generic error page with no exploitation evidence?
3. Does the response show actual exploitation (data leakage, code execution)?
4. Are there signs of input sanitization or validation working correctly?
5. Is the payload merely reflected but not executed?

**Required Analysis:**
Provide evidence-based reasoning about whether this is a false positive.

**Output (JSON only):**
{{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "detailed explanation with evidence",
    "red_flags": ["list", "of", "FP", "indicators"],
    "exploit_evidence": ["list", "of", "actual", "exploitation", "signs"]
}}"""
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings"""
        if not text1 or not text2:
            return 0.0
        
        # Use SequenceMatcher for similarity
        return SequenceMatcher(None, text1, text2).ratio()
    
    def _is_generic_error_page(self, response_body: str) -> bool:
        """Check if response is a generic error page"""
        generic_patterns = [
            r'<title>error</title>',
            r'an error occurred',
            r'something went wrong',
            r'page not found',
            r'error processing request',
            r'exception occurred',
        ]
        
        body_lower = response_body.lower()
        return any(re.search(pattern, body_lower) for pattern in generic_patterns)
    
    def _has_execution_evidence(
        self,
        payload: str,
        response_body: str,
        vuln_type: str
    ) -> bool:
        """
        Check if there's evidence of actual payload execution.
        
        Args:
            payload: The payload that was sent
            response_body: Response body
            vuln_type: Type of vulnerability
        
        Returns:
            True if execution evidence found
        """
        body_lower = response_body.lower()
        
        # Type-specific execution indicators
        if vuln_type == 'xss':
            # Check for actual script execution context
            xss_indicators = [
                r'<script[^>]*>' + re.escape(payload),
                r'onerror\s*=\s*["\']?' + re.escape(payload),
                r'onload\s*=\s*["\']?' + re.escape(payload),
            ]
            return any(re.search(pattern, body_lower) for pattern in xss_indicators)
        
        elif vuln_type == 'sqli':
            # Check for SQL error messages or data leakage
            sql_indicators = [
                r'sql.*error',
                r'mysql.*error',
                r'postgresql.*error',
                r'syntax.*error.*sql',
                r'unclosed.*quote',
                r'database.*error',
                r'table.*not.*found',
                r'column.*not.*found',
            ]
            return any(re.search(pattern, body_lower) for pattern in sql_indicators)
        
        elif vuln_type == 'cmdi':
            # Check for command output indicators
            cmd_indicators = [
                r'root:x:',  # /etc/passwd
                r'uid=\d+',  # id command
                r'total \d+',  # ls -la
                r'drwx',  # directory listing
            ]
            return any(re.search(pattern, body_lower) for pattern in cmd_indicators)
        
        return False
    
    def _hash_response(self, response_text: str) -> str:
        """Generate hash of response for pattern matching"""
        return hashlib.md5(response_text.encode()).hexdigest()
    
    def get_statistics(self) -> Dict:
        """Get filter statistics"""
        total = self.stats['total_analyzed']
        if total == 0:
            return self.stats
        
        return {
            **self.stats,
            'stage1_percentage': round(self.stats['stage1_filtered'] / total * 100, 1),
            'stage2_percentage': round(self.stats['stage2_filtered'] / total * 100, 1),
            'stage3_percentage': round(self.stats['stage3_filtered'] / total * 100, 1),
            'passed_percentage': round(self.stats['passed'] / total * 100, 1),
            'total_filtered': (
                self.stats['stage1_filtered'] + 
                self.stats['stage2_filtered'] + 
                self.stats['stage3_filtered']
            )
        }
    
    def reset_statistics(self):
        """Reset statistics"""
        self.stats = {
            'total_analyzed': 0,
            'stage1_filtered': 0,
            'stage2_filtered': 0,
            'stage3_filtered': 0,
            'passed': 0
        }


# Example usage
async def example_usage():
    """Example of using the false positive filter"""
    
    # Initialize filter (without AI for this example)
    fp_filter = IntelligentFalsePositiveFilter()
    
    # Example 1: WAF blocked request (should be filtered)
    vulnerability1 = {
        'type': 'sqli',
        'severity': 'high',
        'confidence': 0.8
    }
    request1 = {
        'url': 'http://example.com/search?q=test',
        'method': 'GET',
        'payload': "' OR '1'='1",
        'tech_stack': ['nginx', 'php']
    }
    response1 = {
        'status_code': 403,
        'body': 'Access Denied. WAF blocked suspicious request.',
        'headers': {'x-waf': 'blocked'},
        'response_time': 50
    }
    
    result1 = await fp_filter.analyze_finding(vulnerability1, request1, response1)
    print("Example 1 - WAF Blocked:")
    print(f"  Is False Positive: {result1['is_false_positive']}")
    print(f"  Confidence: {result1['confidence']}")
    print(f"  Reasons: {result1['reasons']}")
    print(f"  Recommendation: {result1['recommendation']}\n")
    
    # Example 2: Actual vulnerability (should pass)
    vulnerability2 = {
        'type': 'sqli',
        'severity': 'critical',
        'confidence': 0.9
    }
    request2 = {
        'url': 'http://example.com/user?id=1',
        'method': 'GET',
        'payload': "1' UNION SELECT username,password FROM users--",
        'tech_stack': ['apache', 'mysql']
    }
    response2 = {
        'status_code': 200,
        'body': 'admin:5f4dcc3b5aa765d61d8327deb882cf99\nuser:098f6bcd4621d373cade4e832627b4f6',
        'headers': {'content-type': 'text/html'},
        'response_time': 120
    }
    
    result2 = await fp_filter.analyze_finding(vulnerability2, request2, response2)
    print("Example 2 - Real Vulnerability:")
    print(f"  Is False Positive: {result2['is_false_positive']}")
    print(f"  Confidence: {result2['confidence']}")
    print(f"  Reasons: {result2['reasons']}")
    print(f"  Recommendation: {result2['recommendation']}\n")
    
    # Print statistics
    print("Filter Statistics:")
    stats = fp_filter.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())