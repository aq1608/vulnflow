"""Insufficient Logging Scanner (CWE-778)"""

from typing import List, Dict, Optional, Tuple
import aiohttp
import asyncio
import time

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class InsufficientLoggingScanner(BaseScanner):
    """
    Scanner for Insufficient Logging (CWE-778).
    
    Tests for indicators that security events are not being logged:
    1. No account lockout after failed logins (suggests no monitoring)
    2. No rate limiting on sensitive endpoints
    3. No evidence of attack detection
    4. Lack of audit trail indicators
    """
    
    name = "Insufficient Logging Scanner"
    description = "Detects indicators of insufficient security event logging"
    owasp_category = OWASPCategory.A09_LOGGING_ALERTING_FAILURES
    
    # Endpoints that should have logging/monitoring
    SENSITIVE_ENDPOINTS = [
        '/login',
        '/signin',
        '/auth',
        '/authenticate',
        '/api/login',
        '/api/auth',
        '/admin',
        '/admin/login',
        '/user/login',
        '/account/login',
    ]
    
    # Malicious payloads that should trigger logging
    MALICIOUS_PAYLOADS = [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "; cat /etc/passwd",
        "${7*7}",
        "{{7*7}}",
    ]

    async def scan(self, session: aiohttp.ClientSession,
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for insufficient logging indicators"""
        vulnerabilities = []
        
        # Test for failed login handling (indicates logging/monitoring)
        login_vulns = await self._test_failed_login_handling(session, url)
        vulnerabilities.extend(login_vulns)
        
        # Test for malicious payload detection
        detection_vulns = await self._test_attack_detection(session, url, params)
        vulnerabilities.extend(detection_vulns)
        
        # Check for audit trail indicators
        audit_vulns = await self._check_audit_indicators(session, url)
        vulnerabilities.extend(audit_vulns)
        
        return vulnerabilities
    
    async def _test_failed_login_handling(self, session: aiohttp.ClientSession,
                                           url: str) -> List[Vulnerability]:
        """Test how the application handles multiple failed logins"""
        vulnerabilities = []
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Find login endpoint
        login_url = None
        for endpoint in self.SENSITIVE_ENDPOINTS:
            test_url = base_url + endpoint
            response = await self.make_request(session, "GET", test_url)
            if response and response.status == 200:
                try:
                    body = await response.text()
                    if any(x in body.lower() for x in ['password', 'login', 'sign in', 'username']):
                        login_url = test_url
                        break
                except Exception:
                    continue
        
        if not login_url:
            return vulnerabilities
        
        # Test multiple failed logins
        failed_attempts = 0
        blocked = False
        response_times = []
        
        for i in range(10):  # Try 10 failed logins
            start_time = time.time()
            
            response = await self.make_request(
                session, "POST", login_url,
                data={
                    'username': f'testuser{i}@nonexistent.com',
                    'password': 'WrongPassword123!',
                    'email': f'testuser{i}@nonexistent.com',
                }
            )
            
            elapsed = time.time() - start_time
            response_times.append(elapsed)
            
            if not response:
                continue
            
            # Check for blocking indicators
            if response.status in [429, 403]:
                blocked = True
                break
            
            try:
                body = await response.text()
                if any(x in body.lower() for x in ['blocked', 'locked', 'too many', 'rate limit', 'captcha']):
                    blocked = True
                    break
            except Exception:
                pass
            
            failed_attempts += 1
            await asyncio.sleep(0.2)  # Small delay
        
        # Analyze results
        if not blocked and failed_attempts >= 8:
            # Check if response times increased (could indicate logging/processing)
            avg_time = sum(response_times) / len(response_times) if response_times else 0
            
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Insufficient Login Monitoring",
                severity=Severity.MEDIUM,
                url=login_url,
                evidence=f"Completed {failed_attempts} failed login attempts without lockout or rate limiting. Avg response time: {avg_time:.2f}s",
                description=(
                    "The application allowed multiple failed login attempts without any apparent "
                    "protective measures such as:\n"
                    "- Account lockout\n"
                    "- Rate limiting\n"
                    "- CAPTCHA challenges\n"
                    "- Progressive delays\n\n"
                    "This suggests insufficient logging and alerting for authentication failures, "
                    "which is critical for detecting brute force attacks and credential stuffing."
                ),
                cwe_id="CWE-778",
                cvss_score=5.3,
                remediation=(
                    "1. Implement failed login attempt logging with user context\n"
                    "2. Set up alerts for abnormal login failure rates\n"
                    "3. Implement account lockout after N failed attempts\n"
                    "4. Add rate limiting on authentication endpoints\n"
                    "5. Consider CAPTCHA after several failed attempts\n"
                    "6. Monitor and alert on login attempts from unusual locations/IPs"
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism",
                    "https://cwe.mitre.org/data/definitions/778.html",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
                ]
            ))
        
        return vulnerabilities
    
    async def _test_attack_detection(self, session: aiohttp.ClientSession,
                                      url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Test if obvious attacks are detected"""
        vulnerabilities = []
        
        if not params:
            params = {'test': 'value'}
        
        # Send obviously malicious requests
        detected = False
        total_payloads = len(self.MALICIOUS_PAYLOADS)
        
        for payload in self.MALICIOUS_PAYLOADS:
            test_params = params.copy()
            for param in test_params:
                test_params[param] = payload
            
            response = await self.make_request(session, "GET", url, params=test_params)
            if response:
                # Check for WAF/detection indicators
                if response.status in [403, 406, 418, 429, 503]:
                    detected = True
                    break
                
                try:
                    body = await response.text()
                    detection_indicators = [
                        'blocked', 'forbidden', 'attack detected',
                        'malicious', 'suspicious', 'security',
                        'waf', 'firewall', 'protection'
                    ]
                    if any(ind in body.lower() for ind in detection_indicators):
                        detected = True
                        break
                except Exception:
                    pass
            
            await asyncio.sleep(0.1)
        
        if not detected:
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="No Attack Detection Observed",
                severity=Severity.LOW,
                url=url,
                evidence=f"Sent {total_payloads} malicious payloads without triggering any visible security response",
                description=(
                    "The application did not show any visible indication of detecting or blocking "
                    "obviously malicious input (SQL injection, XSS, path traversal, etc.). "
                    "While this doesn't confirm vulnerabilities exist, it suggests:\n"
                    "- No Web Application Firewall (WAF) or it's not properly configured\n"
                    "- Insufficient logging of suspicious input patterns\n"
                    "- Lack of real-time attack detection and alerting"
                ),
                cwe_id="CWE-778",
                cvss_score=3.7,
                remediation=(
                    "1. Implement input validation logging for suspicious patterns\n"
                    "2. Consider deploying a Web Application Firewall (WAF)\n"
                    "3. Set up alerting for common attack signatures\n"
                    "4. Integrate with SIEM for centralized security monitoring\n"
                    "5. Implement the OWASP ModSecurity Core Rule Set"
                ),
                references=[
                    "https://owasp.org/www-project-modsecurity-core-rule-set/",
                    "https://cwe.mitre.org/data/definitions/778.html"
                ]
            ))
        
        return vulnerabilities
    
    async def _check_audit_indicators(self, session: aiohttp.ClientSession,
                                       url: str) -> List[Vulnerability]:
        """Check for audit trail indicators"""
        vulnerabilities = []
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check response headers for security monitoring indicators
        response = await self.make_request(session, "GET", url)
        if response:
            headers = response.headers
            
            # Check for request ID headers (indicates logging infrastructure)
            request_id_headers = [
                'X-Request-ID', 'X-Request-Id', 'X-Correlation-ID',
                'X-Trace-ID', 'X-Amzn-RequestId', 'Request-Id'
            ]
            
            has_request_id = any(h in headers for h in request_id_headers)
            
            if not has_request_id:
                # This is informational - absence doesn't confirm vulnerability
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Missing Request Correlation Headers",
                    severity=Severity.INFO,
                    url=url,
                    evidence="No X-Request-ID or similar correlation headers found in response",
                    description=(
                        "The application does not return request correlation headers "
                        "(X-Request-ID, X-Correlation-ID, etc.). While not a vulnerability itself, "
                        "these headers are a best practice that:\n"
                        "- Enable request tracing across distributed systems\n"
                        "- Help correlate logs for incident investigation\n"
                        "- Aid in debugging and performance monitoring"
                    ),
                    cwe_id="CWE-778",
                    cvss_score=0.0,
                    remediation=(
                        "1. Generate unique request IDs for each request\n"
                        "2. Include request ID in all log entries\n"
                        "3. Return request ID in response headers\n"
                        "4. Propagate IDs across microservices"
                    ),
                    references=[
                        "https://devcenter.heroku.com/articles/http-request-id",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
                    ]
                ))
        
        return vulnerabilities