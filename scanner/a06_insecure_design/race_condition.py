# scanner/insecure_design/race_condition.py
"""
Race Condition Scanner

Detects potential race condition vulnerabilities:
- TOCTOU (Time-of-check to time-of-use)
- Concurrent request handling issues
- Double-submit vulnerabilities
- Limit bypass through parallel requests

OWASP: A06:2025 - Insecure Design
CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
"""

import asyncio
import time
from typing import List, Dict, Optional, Tuple
import aiohttp

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class RaceConditionScanner(BaseScanner):
    """Scanner for Race Condition vulnerabilities"""
    
    name = "Race Condition Scanner"
    description = "Detects race condition and TOCTOU vulnerabilities"
    owasp_category = OWASPCategory.A06_INSECURE_DESIGN
    
    # Endpoints likely to have race conditions
    SENSITIVE_ENDPOINTS = [
        '/api/transfer', '/api/payment', '/api/withdraw',
        '/api/balance', '/api/order', '/api/checkout',
        '/api/voucher', '/api/coupon', '/api/redeem',
        '/api/vote', '/api/like', '/api/follow',
        '/api/register', '/api/signup',
        '/redeem', '/checkout', '/payment',
        '/transfer', '/withdraw', '/deposit',
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for race condition vulnerabilities"""
        vulnerabilities = []
        
        # Check if URL looks like a sensitive endpoint
        if not self._is_sensitive_endpoint(url):
            return vulnerabilities
        
        # Test 1: Double-submit detection
        double_vuln = await self._test_double_submit(session, url, params)
        if double_vuln:
            vulnerabilities.append(double_vuln)
        
        # Test 2: Parallel request race condition
        parallel_vuln = await self._test_parallel_requests(session, url, params)
        if parallel_vuln:
            vulnerabilities.append(parallel_vuln)
        
        # Test 3: Response consistency check
        consistency_vuln = await self._test_response_consistency(session, url, params)
        if consistency_vuln:
            vulnerabilities.append(consistency_vuln)
        
        return vulnerabilities
    
    def _is_sensitive_endpoint(self, url: str) -> bool:
        """Check if URL is a sensitive endpoint"""
        url_lower = url.lower()
        return any(endpoint in url_lower for endpoint in self.SENSITIVE_ENDPOINTS)
    
    async def _test_double_submit(self, session: aiohttp.ClientSession,
                                   url: str, params: Dict[str, str]) -> Optional[Vulnerability]:
        """Test for double-submit vulnerabilities"""
        
        if not params:
            return None
        
        try:
            # Send two identical requests nearly simultaneously
            async def make_request():
                return await self.make_request(session, "POST", url, data=params)
            
            # Execute both requests concurrently
            results = await asyncio.gather(
                make_request(),
                make_request(),
                return_exceptions=True
            )
            
            # Check if both succeeded (potential vulnerability)
            success_count = sum(1 for r in results 
                               if r and not isinstance(r, Exception) 
                               and r.status in [200, 201])
            
            if success_count == 2:
                # Both requests succeeded - potential race condition
                return self.create_vulnerability(
                    vuln_type="Potential Double-Submit Race Condition",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="Request Body",
                    payload="Concurrent identical POST requests",
                    evidence=f"Both concurrent requests returned success ({success_count}/2)",
                    description="The endpoint accepted two identical requests submitted simultaneously, which may indicate a race condition vulnerability allowing double-spending or duplicate actions.",
                    cwe_id="CWE-362",
                    cvss_score=6.5,
                    remediation=self._get_remediation(),
                    references=[
                        "https://cwe.mitre.org/data/definitions/362.html",
                        "https://portswigger.net/research/smashing-the-state-machine"
                    ]
                )
        except Exception:
            pass
        
        return None
    
    async def _test_parallel_requests(self, session: aiohttp.ClientSession,
                                       url: str, params: Dict[str, str]) -> Optional[Vulnerability]:
        """Test race condition with multiple parallel requests"""
        
        if not params:
            return None
        
        # Number of concurrent requests
        num_requests = 10
        
        try:
            async def make_request(req_id: int) -> Tuple[int, Optional[int], Optional[str]]:
                response = await self.make_request(session, "POST", url, data=params)
                if response:
                    body = await response.text()
                    return (req_id, response.status, body[:200])
                return (req_id, None, None)
            
            # Send many requests in parallel
            start_time = time.time()
            results = await asyncio.gather(
                *[make_request(i) for i in range(num_requests)],
                return_exceptions=True
            )
            elapsed = time.time() - start_time
            
            # Analyze results
            successful = [r for r in results if not isinstance(r, Exception) and r[1] in [200, 201]]
            
            # If many requests succeed when only one should
            if len(successful) > 1:
                # Check for response variations (indicating state changes)
                response_bodies = set(r[2] for r in successful if r[2])
                
                if len(response_bodies) > 1:
                    return self.create_vulnerability(
                        vuln_type="Race Condition - State Inconsistency",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="Concurrent Requests",
                        payload=f"{num_requests} parallel requests",
                        evidence=f"{len(successful)} successful, {len(response_bodies)} different responses in {elapsed:.2f}s",
                        description="Multiple parallel requests produced different responses, indicating potential race condition affecting shared state.",
                        cwe_id="CWE-362",
                        cvss_score=7.5,
                        remediation=self._get_remediation(),
                        references=[
                            "https://cwe.mitre.org/data/definitions/362.html"
                        ]
                    )
        except Exception:
            pass
        
        return None
    
    async def _test_response_consistency(self, session: aiohttp.ClientSession,
                                          url: str, params: Dict[str, str]) -> Optional[Vulnerability]:
        """Test for response consistency under load"""
        
        try:
            # Make several sequential requests
            responses = []
            for _ in range(5):
                response = await self.make_request(session, "GET", url, params=params)
                if response:
                    body = await response.text()
                    responses.append((response.status, len(body), body[:100]))
                await asyncio.sleep(0.1)
            
            if len(responses) >= 3:
                # Check for variations in response length (might indicate shared state issues)
                lengths = [r[1] for r in responses]
                statuses = [r[0] for r in responses]
                
                # Calculate variance in response lengths
                avg_length = sum(lengths) / len(lengths)
                variance = sum((l - avg_length) ** 2 for l in lengths) / len(lengths)
                
                # High variance might indicate race condition
                if variance > 1000 and len(set(statuses)) > 1:
                    return self.create_vulnerability(
                        vuln_type="Potential Race Condition - Response Inconsistency",
                        severity=Severity.LOW,
                        url=url,
                        parameter="Sequential Requests",
                        payload="5 sequential GET requests",
                        evidence=f"Response lengths varied significantly: {lengths}, variance: {variance:.2f}",
                        description="Sequential requests produced inconsistent responses, which may indicate shared state issues.",
                        cwe_id="CWE-362",
                        cvss_score=4.0,
                        remediation=self._get_remediation(),
                        references=[
                            "https://cwe.mitre.org/data/definitions/362.html"
                        ]
                    )
        except Exception:
            pass
        
        return None
    
    def _get_remediation(self) -> str:
        """Get remediation advice for race conditions"""
        return """
Race Condition Prevention:

1. **Use Database-Level Locking**
   ```sql
   -- Pessimistic locking
   SELECT * FROM accounts WHERE id = ? FOR UPDATE;
   
   -- Optimistic locking with version
   UPDATE accounts 
   SET balance = balance - 100, version = version + 1 
   WHERE id = ? AND version = ?;
   ```

2. Implement Idempotency Keys
    ```python
@app.route('/api/payment', methods=['POST'])
def process_payment():
    idempotency_key = request.headers.get('Idempotency-Key')
    
    # Check if request already processed
    existing = db.get_by_idempotency_key(idempotency_key)
    if existing:
        return existing.response
    
    # Process and store result
    result = process_transaction()
    db.store_idempotency(idempotency_key, result)
    return result
    ```

3. Use Atomic Operations

```python
# Instead of:
balance = get_balance(user_id)
if balance >= amount:
    set_balance(user_id, balance - amount)

# Use atomic operation:
result = db.execute(
    "UPDATE accounts SET balance = balance - %s "
    "WHERE user_id = %s AND balance >= %s",
    (amount, user_id, amount)
)
if result.rowcount == 0:
    raise InsufficientFunds()
```

4. Implement Request Deduplication

- Use unique transaction IDs
- Implement request queuing
- Use distributed locks (Redis, etc.)

5. Use Mutex/Semaphores for Critical Sections
```python
import threading

lock = threading.Lock()

def critical_operation():
    with lock:
        # Only one thread can execute this at a time
        perform_sensitive_action()
```

6. Rate Limiting

- Limit requests per user/IP
- Add delays between sensitive operations
"""
