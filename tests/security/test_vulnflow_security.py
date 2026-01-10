# tests/security/test_vulnflow_security.py
import pytest
import requests
from urllib.parse import quote

class TestVulnFlowAPISecurity:
    """Security tests for VulnFlow's own API"""
    
    BASE_URL = "http://localhost:8000"
    
    def test_api_rate_limiting(self):
        """API should have rate limiting"""
        responses = []
        for _ in range(100):
            resp = requests.post(f"{self.BASE_URL}/api/v1/scans", 
                               json={"target_url": "http://example.com"})
            responses.append(resp.status_code)
        
        # Should see 429 Too Many Requests at some point
        assert 429 in responses, "API should implement rate limiting"
    
    def test_input_validation_target_url(self):
        """Should validate target URL input"""
        malicious_inputs = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "http://localhost/admin",  # Should block localhost
            "http://169.254.169.254/",  # AWS metadata
            "http://127.0.0.1:22",
            "gopher://evil.com",
        ]
        
        for payload in malicious_inputs:
            resp = requests.post(f"{self.BASE_URL}/api/v1/scans",
                               json={"target_url": payload})
            assert resp.status_code in [400, 422], \
                f"Should reject malicious URL: {payload}"
    
    def test_ssrf_prevention(self):
        """Should prevent SSRF attacks"""
        # Try to scan internal networks
        internal_targets = [
            "http://127.0.0.1:8000",
            "http://localhost:8000",
            "http://0.0.0.0:8000",
            "http://[::1]:8000",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
        ]
        
        for target in internal_targets:
            resp = requests.post(f"{self.BASE_URL}/api/v1/scans",
                               json={"target_url": target})
            assert resp.status_code in [400, 403], \
                f"Should block internal target: {target}"
    
    def test_authentication_required(self):
        """Critical endpoints should require authentication"""
        protected_endpoints = [
            "/api/v1/scans",
            "/api/v1/scans/123/results",
            "/api/v1/admin/config",
        ]
        
        for endpoint in protected_endpoints:
            resp = requests.get(f"{self.BASE_URL}{endpoint}")
            assert resp.status_code in [401, 403], \
                f"Endpoint {endpoint} should require auth"
    
    def test_sql_injection_in_api(self):
        """API should be immune to SQL injection"""
        payloads = [
            "'; DROP TABLE scans;--",
            "1 OR 1=1",
            "1' UNION SELECT * FROM users--",
        ]
        
        for payload in payloads:
            resp = requests.get(f"{self.BASE_URL}/api/v1/scans/{quote(payload)}")
            # Should return 404 or 400, not 500 (which might indicate SQLi)
            assert resp.status_code != 500, \
                f"Possible SQLi with payload: {payload}"
    
    def test_xss_in_reports(self):
        """Report generation should escape user input"""
        # Create a scan with malicious target name
        resp = requests.post(f"{self.BASE_URL}/api/v1/scans", json={
            "target_url": "http://example.com/<script>alert('xss')</script>"
        })
        
        if resp.status_code == 200:
            scan_id = resp.json()["scan_id"]
            
            # Wait for completion and get HTML report
            import time
            time.sleep(5)
            
            report_resp = requests.get(
                f"{self.BASE_URL}/api/v1/scans/{scan_id}/results?format=html"
            )
            
            # Check that script tags are escaped
            assert "<script>" not in report_resp.text, \
                "Report should escape script tags"
            assert "&lt;script&gt;" in report_resp.text or \
                   "script" not in report_resp.text.lower(), \
                "Report should HTML-encode malicious content"
    
    def test_path_traversal(self):
        """Should prevent path traversal attacks"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        
        for payload in payloads:
            resp = requests.get(
                f"{self.BASE_URL}/api/v1/reports/{quote(payload, safe='')}"
            )
            assert resp.status_code in [400, 404], \
                f"Should block path traversal: {payload}"
            assert "root:" not in resp.text, \
                "Path traversal successful!"
    
    def test_security_headers_present(self):
        """API responses should include security headers"""
        resp = requests.get(f"{self.BASE_URL}/api/v1/health")
        
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
        ]
        
        for header in required_headers:
            assert header in resp.headers, f"Missing header: {header}"