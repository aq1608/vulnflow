# scanner/exceptional_conditions/resource_limits.py
"""
Resource Limits Scanner

Detects missing or inadequate resource limits:
- Missing rate limiting
- No request size limits
- Unbounded resource allocation
- Potential DoS vectors

OWASP: A10:2025 - Mishandling of Exceptional Conditions
CWE-770: Allocation of Resources Without Limits or Throttling
"""

import asyncio
import aiohttp
import re
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class ResourceLimitsScanner(BaseScanner):
    """Scanner for missing resource limits"""
    
    name = "Resource Limits Scanner"
    description = "Detects missing rate limiting and resource controls"
    owasp_category = OWASPCategory.A10_EXCEPTIONAL_CONDITIONS
    
    def __init__(self):
        super().__init__()
        
        # Endpoints commonly requiring rate limiting
        self.rate_limit_endpoints = [
            '/api/login',
            '/api/auth',
            '/login',
            '/signin',
            '/auth',
            '/api/password/reset',
            '/api/forgot-password',
            '/forgot-password',
            '/api/register',
            '/register',
            '/signup',
            '/api/otp',
            '/api/verify',
            '/api/send-code',
            '/contact',
            '/api/contact',
            '/search',
            '/api/search',
        ]
        
        # Headers indicating rate limiting
        self.rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset',
            'Retry-After',
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for resource limit vulnerabilities."""
        vulnerabilities = []
        
        # Test 1: Check for rate limiting on sensitive endpoints
        rate_vulns = await self._check_rate_limiting(session, url)
        vulnerabilities.extend(rate_vulns)
        
        # Test 2: Test request size limits
        size_vulns = await self._check_size_limits(session, url)
        vulnerabilities.extend(size_vulns)
        
        # Test 3: Check for ReDoS potential in search/regex endpoints
        regex_vulns = await self._check_regex_dos(session, url, params)
        vulnerabilities.extend(regex_vulns)
        
        # Test 4: Check for pagination limits
        pagination_vulns = await self._check_pagination_limits(session, url)
        vulnerabilities.extend(pagination_vulns)
        
        # Test 5: Check for XML/JSON bomb protection
        bomb_vulns = await self._check_data_bomb_protection(session, url)
        vulnerabilities.extend(bomb_vulns)
        
        return vulnerabilities
    
    async def _check_rate_limiting(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check if rate limiting is implemented on sensitive endpoints."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in self.rate_limit_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            try:
                # First check if endpoint exists
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=True
                ) as initial_response:
                    if initial_response.status == 404:
                        continue
                    
                    # Check for rate limit headers in initial response
                    has_rate_limit_headers = any(
                        header in initial_response.headers
                        for header in self.rate_limit_headers
                    )
                
                # If no rate limit headers, test with multiple rapid requests
                if not has_rate_limit_headers:
                    rate_limited = await self._test_rapid_requests(session, test_url)
                    
                    if not rate_limited:
                        # Determine severity based on endpoint type
                        severity = Severity.HIGH if any(
                            x in endpoint.lower() 
                            for x in ['login', 'auth', 'password', 'otp', 'verify', 'register']
                        ) else Severity.MEDIUM
                        
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Missing Rate Limiting",
                            severity=severity,
                            url=test_url,
                            parameter="endpoint",
                            payload=endpoint,
                            evidence=f"No rate limiting detected after multiple rapid requests",
                            description=f"Endpoint {endpoint} lacks rate limiting, potentially allowing brute force or DoS attacks",
                            cwe_id="CWE-770",
                            owasp_category=self.owasp_category,
                            remediation=self._get_rate_limit_remediation()
                        ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_rapid_requests(
        self,
        session: aiohttp.ClientSession,
        url: str,
        num_requests: int = 20
    ) -> bool:
        """Send rapid requests to test for rate limiting."""
        success_count = 0
        rate_limited = False
        
        tasks = []
        for _ in range(num_requests):
            task = session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
                allow_redirects=True
            )
            tasks.append(task)
        
        try:
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for resp in responses:
                if isinstance(resp, Exception):
                    continue
                
                async with resp:
                    # Check for rate limit responses
                    if resp.status == 429:
                        rate_limited = True
                        break
                    
                    # Check for rate limit headers
                    if any(header in resp.headers for header in self.rate_limit_headers):
                        remaining = resp.headers.get('X-RateLimit-Remaining', 
                                   resp.headers.get('RateLimit-Remaining', ''))
                        if remaining and remaining.isdigit() and int(remaining) == 0:
                            rate_limited = True
                            break
                    
                    if resp.status in [200, 201, 400, 401, 403]:
                        success_count += 1
        
        except Exception:
            pass
        
        # If we got through all requests without being limited, no rate limiting
        return rate_limited
    
    async def _check_size_limits(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check if request size limits are implemented."""
        vulnerabilities = []
        
        # Test with increasingly large payloads
        test_sizes = [
            (1024, '1KB'),           # 1KB
            (10240, '10KB'),         # 10KB
            (102400, '100KB'),       # 100KB
            (1048576, '1MB'),        # 1MB
            (5242880, '5MB'),        # 5MB
        ]
        
        for size, size_label in test_sizes:
            try:
                # Create payload of specified size
                payload = 'A' * size
                
                async with session.post(
                    url,
                    data={'data': payload},
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False
                ) as response:
                    # Check if server accepted the large payload
                    if response.status in [200, 201]:
                        if size >= 1048576:  # 1MB or larger accepted
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Missing Request Size Limit",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter="request_body",
                                payload=f"Payload size: {size_label}",
                                evidence=f"Server accepted {size_label} request body (HTTP {response.status})",
                                description=f"Server accepts request bodies of {size_label} or larger without limiting",
                                cwe_id="CWE-770",
                                owasp_category=self.owasp_category,
                                remediation=self._get_size_limit_remediation()
                            ))
                            break
                    elif response.status == 413:
                        # Server properly rejects large payloads
                        break
            
            except asyncio.TimeoutError:
                # Timeout might indicate server is struggling with large payload
                if size >= 1048576:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Potential DoS via Large Request",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="request_body",
                        payload=f"Payload size: {size_label}",
                        evidence=f"Server timed out processing {size_label} payload",
                        description=f"Server may be vulnerable to DoS via large request bodies",
                        cwe_id="CWE-400",
                        owasp_category=self.owasp_category,
                        remediation=self._get_size_limit_remediation()
                    ))
                break
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _check_regex_dos(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Check for ReDoS (Regular Expression DoS) vulnerabilities."""
        vulnerabilities = []
        
        # ReDoS payloads that exploit catastrophic backtracking
        redos_payloads = [
            ('a' * 30 + '!', 'Exponential backtracking pattern'),
            ('a' * 25 + 'b', 'Nested quantifier pattern'),
            ('@' * 50 + '.com', 'Email validation DoS'),
            ('.' * 30 + 'test', 'Wildcard backtracking'),
            ('aaaaaaaaaaaaaaaaaaaaaaaaaaaa!', 'Simple exponential'),
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test search endpoints
        search_endpoints = ['/search', '/api/search', '/?q=', '/?search=', '/?query=']
        
        for endpoint in search_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for payload, description in redos_payloads:
                try:
                    start_time = time.time()
                    
                    # Test with GET parameter
                    async with session.get(
                        test_url,
                        params={'q': payload, 'search': payload, 'query': payload},
                        timeout=aiohttp.ClientTimeout(total=15),
                        ssl=False
                    ) as response:
                        elapsed = time.time() - start_time
                        
                        # If response takes unusually long, might be ReDoS
                        if elapsed > 5 and response.status != 404:
                            vulnerabilities.append(Vulnerability(
                                vuln_type="Potential ReDoS Vulnerability",
                                severity=Severity.MEDIUM,
                                url=test_url,
                                parameter="search",
                                payload=payload[:50] + '...' if len(payload) > 50 else payload,
                                evidence=f"Response took {elapsed:.2f}s with ReDoS pattern",
                                description=f"Search endpoint may be vulnerable to Regular Expression DoS ({description})",
                                cwe_id="CWE-1333",
                                owasp_category=self.owasp_category,
                                remediation=self._get_redos_remediation()
                            ))
                            break
                
                except asyncio.TimeoutError:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Potential ReDoS Vulnerability",
                        severity=Severity.MEDIUM,
                        url=test_url,
                        parameter="search",
                        payload=payload[:50] + '...' if len(payload) > 50 else payload,
                        evidence="Request timed out with ReDoS pattern",
                        description=f"Search endpoint timed out processing ReDoS pattern ({description})",
                        cwe_id="CWE-1333",
                        owasp_category=self.owasp_category,
                        remediation=self._get_redos_remediation()
                    ))
                    break
                except Exception:
                    continue
        
        # Also test any provided parameters
        if params:
            for param_name, param_value in params.items():
                for payload, description in redos_payloads[:2]:  # Limit tests
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        start_time = time.time()
                        
                        async with session.get(
                            url,
                            params=test_params,
                            timeout=aiohttp.ClientTimeout(total=15),
                            ssl=False
                        ) as response:
                            elapsed = time.time() - start_time
                            
                            if elapsed > 5:
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Potential ReDoS in Parameter",
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    parameter=param_name,
                                    payload=payload[:50] + '...' if len(payload) > 50 else payload,
                                    evidence=f"Response took {elapsed:.2f}s with ReDoS pattern",
                                    description=f"Parameter {param_name} may be vulnerable to ReDoS",
                                    cwe_id="CWE-1333",
                                    owasp_category=self.owasp_category,
                                    remediation=self._get_redos_remediation()
                                ))
                                break
                    
                    except asyncio.TimeoutError:
                        vulnerabilities.append(Vulnerability(
                            vuln_type="Potential ReDoS in Parameter",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload=payload[:50] + '...' if len(payload) > 50 else payload,
                            evidence="Request timed out with ReDoS pattern",
                            description=f"Parameter {param_name} may be vulnerable to ReDoS",
                            cwe_id="CWE-1333",
                            owasp_category=self.owasp_category,
                            remediation=self._get_redos_remediation()
                        ))
                        break
                    except Exception:
                        continue
        
        return vulnerabilities
    
    async def _check_pagination_limits(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for missing pagination limits."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common API endpoints that should have pagination
        api_endpoints = [
            '/api/users',
            '/api/items',
            '/api/products',
            '/api/posts',
            '/api/data',
            '/api/list',
            '/api/records',
        ]
        
        # Test large limit/page_size values
        pagination_params = [
            {'limit': '10000'},
            {'page_size': '10000'},
            {'per_page': '10000'},
            {'count': '10000'},
            {'size': '10000'},
            {'limit': '999999'},
            {'offset': '0', 'limit': '100000'},
        ]
        
        for endpoint in api_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            # First check if endpoint exists
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 404:
                        continue
            except:
                continue
            
            # Test pagination limits
            for params in pagination_params:
                try:
                    start_time = time.time()
                    
                    async with session.get(
                        test_url,
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=30),
                        ssl=False
                    ) as response:
                        elapsed = time.time() - start_time
                        
                        if response.status == 200:
                            content = await response.text()
                            content_length = len(content)
                            
                            # Check if server returned a very large response
                            if content_length > 1000000:  # > 1MB
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Missing Pagination Limit",
                                    severity=Severity.MEDIUM,
                                    url=test_url,
                                    parameter=list(params.keys())[0],
                                    payload=str(params),
                                    evidence=f"Server returned {content_length/1024:.0f}KB with large limit parameter",
                                    description=f"API endpoint accepts unlimited pagination, potentially allowing data extraction or DoS",
                                    cwe_id="CWE-770",
                                    owasp_category=self.owasp_category,
                                    remediation=self._get_pagination_remediation()
                                ))
                                break
                            
                            # Check if response took too long (server under stress)
                            if elapsed > 10:
                                vulnerabilities.append(Vulnerability(
                                    vuln_type="Slow Response with Large Pagination",
                                    severity=Severity.LOW,
                                    url=test_url,
                                    parameter=list(params.keys())[0],
                                    payload=str(params),
                                    evidence=f"Response took {elapsed:.2f}s with large limit",
                                    description="API endpoint may be vulnerable to DoS via large pagination values",
                                    cwe_id="CWE-400",
                                    owasp_category=self.owasp_category,
                                    remediation=self._get_pagination_remediation()
                                ))
                                break
                
                except asyncio.TimeoutError:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Timeout with Large Pagination",
                        severity=Severity.MEDIUM,
                        url=test_url,
                        parameter=list(params.keys())[0],
                        payload=str(params),
                        evidence="Request timed out with large pagination value",
                        description="API endpoint may be vulnerable to DoS via large pagination values",
                        cwe_id="CWE-400",
                        owasp_category=self.owasp_category,
                        remediation=self._get_pagination_remediation()
                    ))
                    break
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _check_data_bomb_protection(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[Vulnerability]:
        """Check for protection against XML/JSON bombs."""
        vulnerabilities = []
        
        # JSON bomb (deeply nested)
        json_bomb_small = '{"a":' * 20 + '1' + '}' * 20
        
        # XML entity expansion (Billion Laughs lite - not actually malicious)
        xml_bomb_test = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol2;</lolz>'''
        
        # Test JSON endpoint
        try:
            start_time = time.time()
            
            async with session.post(
                url,
                json={"data": json_bomb_small},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                elapsed = time.time() - start_time
                
                if elapsed > 5 and response.status in [200, 201, 400, 500]:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Potential JSON Processing DoS",
                        severity=Severity.LOW,
                        url=url,
                        parameter="request_body",
                        payload="Deeply nested JSON object",
                        evidence=f"Server took {elapsed:.2f}s processing nested JSON",
                        description="Server may be vulnerable to DoS via deeply nested JSON structures",
                        cwe_id="CWE-400",
                        owasp_category=self.owasp_category,
                        remediation=self._get_bomb_remediation()
                    ))
        
        except asyncio.TimeoutError:
            vulnerabilities.append(Vulnerability(
                vuln_type="JSON Processing DoS",
                severity=Severity.MEDIUM,
                url=url,
                parameter="request_body",
                payload="Deeply nested JSON object",
                evidence="Server timed out processing nested JSON",
                description="Server vulnerable to DoS via deeply nested JSON structures",
                cwe_id="CWE-400",
                owasp_category=self.owasp_category,
                remediation=self._get_bomb_remediation()
            ))
        except Exception:
            pass
        
        # Test XML endpoint
        try:
            start_time = time.time()
            
            async with session.post(
                url,
                data=xml_bomb_test,
                headers={'Content-Type': 'application/xml'},
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                elapsed = time.time() - start_time
                content = await response.text()
                
                # Check if entities were expanded (vulnerability)
                if 'lollollol' in content.lower():
                    vulnerabilities.append(Vulnerability(
                        vuln_type="XML Entity Expansion Allowed",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="request_body",
                        payload="XML with entity definitions",
                        evidence="XML entities were expanded by server",
                        description="Server expands XML entities, potentially vulnerable to Billion Laughs attack",
                        cwe_id="CWE-776",
                        owasp_category=self.owasp_category,
                        remediation=self._get_xml_remediation()
                    ))
                elif elapsed > 5:
                    vulnerabilities.append(Vulnerability(
                        vuln_type="Slow XML Processing",
                        severity=Severity.LOW,
                        url=url,
                        parameter="request_body",
                        payload="XML with entity definitions",
                        evidence=f"Server took {elapsed:.2f}s processing XML with entities",
                        description="Server may be vulnerable to XML-based DoS attacks",
                        cwe_id="CWE-776",
                        owasp_category=self.owasp_category,
                        remediation=self._get_xml_remediation()
                    ))
        
        except asyncio.TimeoutError:
            vulnerabilities.append(Vulnerability(
                vuln_type="XML Processing DoS",
                severity=Severity.MEDIUM,
                url=url,
                parameter="request_body",
                payload="XML with entity definitions",
                evidence="Server timed out processing XML with entities",
                description="Server may be vulnerable to XML entity expansion attacks",
                cwe_id="CWE-776",
                owasp_category=self.owasp_category,
                remediation=self._get_xml_remediation()
            ))
        except Exception:
            pass
        
        return vulnerabilities
    
    def _get_rate_limit_remediation(self) -> str:
        """Get rate limiting remediation advice."""
        return """
1. Implement rate limiting on all sensitive endpoints:

Python/Flask example:
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # 5 attempts per minute
def login():
    # login logic
    Express.js example:

javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per window
    message: 'Too many login attempts'
});

app.post('/login', loginLimiter, (req, res) => {
    // login logic
});
Use different limits for different endpoint types:

Login/auth: 5-10 per minute
Password reset: 3-5 per hour
API endpoints: Based on tier/plan
Search: 30-60 per minute
Include rate limit headers in responses:

X-RateLimit-Limit
X-RateLimit-Remaining
X-RateLimit-Reset
Implement exponential backoff for repeated failures

Consider using API gateways (Kong, AWS API Gateway) for centralized rate limiting

Log and alert on rate limit violations
"""

    def _get_size_limit_remediation(self) -> str:
        """Get request size limit remediation advice."""
        return """

Configure maximum request body size at web server level:

Nginx:

nginx
client_max_body_size 1m;  # 1MB limit
client_body_buffer_size 10k;
Apache:

apache
LimitRequestBody 1048576  # 1MB in bytes
IIS (web.config):

xml
<system.webServer>
    <security>
        <requestFiltering>
            <requestLimits maxAllowedContentLength="1048576" />
        </requestFiltering>
    </security>
</system.webServer>
Also implement limits in application code:
Python/Flask:

python
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB
Express.js:

javascript
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));
Set appropriate limits based on endpoint needs:

File upload endpoints: Higher limits with validation
API endpoints: Smaller limits (100KB-1MB)
Form submissions: Small limits (10KB-100KB)
Return 413 (Payload Too Large) for oversized requests

Implement request timeout limits

Monitor for unusual request patterns
"""

    def _get_redos_remediation(self) -> str:
        """Get ReDoS remediation advice."""
        return """

Avoid vulnerable regex patterns:

BAD (vulnerable to ReDoS):

python
# Nested quantifiers
re.compile(r'(a+)+')
# Overlapping alternation
re.compile(r'(a|a)+')
# Greedy quantifiers with backtracking
re.compile(r'.*.*')
GOOD (safe patterns):

python
# Use possessive quantifiers or atomic groups (if supported)
# Use specific character classes instead of wildcards
re.compile(r'[a-z]{1,100}')
# Set explicit limits
Implement regex execution timeouts:
Python:

python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Regex timeout")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(1)  # 1 second timeout
try:
    result = re.search(pattern, user_input)
finally:
    signal.alarm(0)
Use RE2 or other linear-time regex engines:
python
import re2  # Google's RE2 library
re2.search(pattern, user_input)  # Guaranteed linear time
Limit input length before regex processing:
python
if len(user_input) > 1000:
    raise ValueError("Input too long")
Use static analysis tools to detect vulnerable patterns:

recheck (JavaScript)
safe-regex
rxxr2
Consider using string operations instead of regex where possible
"""

    def _get_pagination_remediation(self) -> str:
        """Get pagination limit remediation advice."""
        return """

Enforce maximum page size limits:

python
MAX_PAGE_SIZE = 100

@app.route('/api/items')
def get_items():
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 20, type=int)
    
    # Enforce limits
    page_size = min(page_size, MAX_PAGE_SIZE)
    page = max(page, 1)
    
    items = Item.query.paginate(page=page, per_page=page_size)
    return jsonify(items)
Use cursor-based pagination for large datasets:
python
@app.route('/api/items')
def get_items():
    cursor = request.args.get('cursor')
    limit = min(request.args.get('limit', 20, type=int), 100)
    
    query = Item.query.order_by(Item.id)
    if cursor:
        query = query.filter(Item.id > cursor)
    
    items = query.limit(limit + 1).all()
    
    next_cursor = items[-1].id if len(items) > limit else None
    return jsonify({
        'items': items[:limit],
        'next_cursor': next_cursor
    })
Default to reasonable page sizes (10-50 items)

Document maximum limits in API documentation

Return metadata with pagination info:

json
{
    "data": [...],
    "pagination": {
        "page": 1,
        "page_size": 20,
        "total_pages": 50,
        "total_items": 1000,
        "max_page_size": 100
    }
}
Implement query timeouts for database operations
"""

    def _get_bomb_remediation(self) -> str:
        """Get data bomb protection remediation advice."""
        return """

Limit JSON parsing depth:

Python:

python
import json
from functools import partial

def parse_json_safe(data, max_depth=20):
    depth = [0]
    
    def object_hook(obj):
        depth[0] += 1
        if depth[0] > max_depth:
            raise ValueError("JSON too deeply nested")
        return obj
    
    return json.loads(data, object_hook=object_hook)
JavaScript:

javascript
const parseJsonSafe = (str, maxDepth = 20) => {
    let depth = 0;
    return JSON.parse(str, (key, value) => {
        if (typeof value === 'object' && value !== null) {
            depth++;
            if (depth > maxDepth) {
                throw new Error('JSON too deeply nested');
            }
        }
        return value;
    });
};
Limit total object/array size:
python
MAX_ITEMS = 10000

def count_items(obj, count=0):
    if count > MAX_ITEMS:
        raise ValueError("Too many items in JSON")
    if isinstance(obj, dict):
        count += len(obj)
        for v in obj.values():
            count = count_items(v, count)
    elif isinstance(obj, list):
        count += len(obj)
        for v in obj:
            count = count_items(v, count)
    return count
Use streaming parsers for large documents

Set request body size limits (see size limit remediation)

Implement parsing timeouts
"""

    def _get_xml_remediation(self) -> str:
        """Get XML bomb protection remediation advice."""
        return """

Disable XML external entities and DTD processing:

Python (defusedxml):

python
import defusedxml.ElementTree as ET

# Safe by default - entities disabled
tree = ET.parse(xml_file)
Python (lxml):

python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False
)
tree = etree.parse(xml_file, parser)
Java:

java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
.NET:

csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
Use defusedxml library in Python (drop-in replacement)

Limit entity expansion count and depth

Consider using JSON instead of XML where possible

Validate XML against schema before processing

Set parsing timeouts and memory limits
"""