# tests/test_detection_accuracy.py
import pytest
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class TestCase:
    name: str
    url: str
    expected_vulns: List[str]
    should_not_find: List[str]

class TestDetectionAccuracy:
    """Test detection accuracy against known vulnerable endpoints"""
    
    TEST_CASES = [
        TestCase(
            name="Error-based SQLi",
            url="http://localhost:5000/sqli/error-based?id=1'",
            expected_vulns=["SQL Injection"],
            should_not_find=["XSS"]
        ),
        TestCase(
            name="Reflected XSS",
            url="http://localhost:5000/xss/reflected?name=<script>alert(1)</script>",
            expected_vulns=["Cross-Site Scripting"],
            should_not_find=["SQL Injection"]
        ),
        TestCase(
            name="Secure SQLi endpoint",
            url="http://localhost:5000/sqli/secure?id=1",
            expected_vulns=[],
            should_not_find=["SQL Injection"]
        ),
        TestCase(
            name="Missing security headers",
            url="http://localhost:5000/headers/missing",
            expected_vulns=["Missing Security Headers"],
            should_not_find=[]
        ),
    ]
    
    @pytest.mark.asyncio
    @pytest.mark.parametrize("test_case", TEST_CASES, ids=lambda tc: tc.name)
    async def test_detection(self, test_case: TestCase):
        from scanner.vuln_scanner import VulnerabilityScanner
        
        scanner = VulnerabilityScanner()
        target = {"url": test_case.url.split("?")[0], "params": {}}
        
        # Parse params from URL
        if "?" in test_case.url:
            params_str = test_case.url.split("?")[1]
            for param in params_str.split("&"):
                key, value = param.split("=", 1)
                target["params"][key] = value
        
        vulns = await scanner.scan_target({"urls": {test_case.url: {}}, "forms": []})
        vuln_types = [v.vuln_type for v in vulns]
        
        # Check expected vulnerabilities found
        for expected in test_case.expected_vulns:
            assert any(expected in vt for vt in vuln_types), \
                f"Should find {expected} in {test_case.name}"
        
        # Check false positives not present
        for should_not in test_case.should_not_find:
            assert not any(should_not in vt for vt in vuln_types), \
                f"Should not find {should_not} in {test_case.name}"


class TestFalsePositiveRate:
    """Measure false positive rates"""
    
    CLEAN_SITES = [
        "http://localhost:5000/sqli/secure",
        "http://localhost:5000/xss/secure",
        "http://localhost:5000/headers/secure",
    ]
    
    @pytest.mark.asyncio
    async def test_false_positive_rate(self):
        from scanner.vuln_scanner import VulnerabilityScanner
        
        scanner = VulnerabilityScanner()
        total_false_positives = 0
        
        for url in self.CLEAN_SITES:
            target = {"url": url, "params": {"id": "1", "name": "test"}}
            vulns = await scanner.scan_target({"urls": {url: {}}, "forms": []})
            
            if vulns:
                total_false_positives += len(vulns)
                print(f"False positives on {url}: {[v.vuln_type for v in vulns]}")
        
        false_positive_rate = total_false_positives / len(self.CLEAN_SITES)
        
        # Target: less than 5% false positive rate
        assert false_positive_rate < 0.05, \
            f"False positive rate {false_positive_rate:.2%} exceeds 5%"