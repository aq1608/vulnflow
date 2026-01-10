# tests/test_scanners.py
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from scanner.vuln_scanner import (
    SQLInjectionScanner, 
    XSSScanner, 
    Vulnerability,
    Severity
)

class TestSQLInjectionScanner:
    """Unit tests for SQL injection detection"""
    
    @pytest.fixture
    def scanner(self):
        return SQLInjectionScanner()
    
    @pytest.mark.asyncio
    async def test_detects_error_based_sqli(self, scanner):
        """Should detect SQL error messages in response"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="""
            <html>
            <body>
            Error: You have an error in your SQL syntax; 
            check the manual that corresponds to your MySQL server version
            </body>
            </html>
        """)
        
        with patch('aiohttp.ClientSession.get', return_value=mock_response):
            target = {
                "url": "http://test.com/search",
                "params": {"q": "test"}
            }
            vulns = await scanner.scan(target)
            
            assert len(vulns) > 0
            assert vulns[0].vuln_type == "SQL Injection (Error-based)"
            assert vulns[0].severity == Severity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_detects_time_based_sqli(self, scanner):
        """Should detect time-based SQL injection"""
        async def slow_response(*args, **kwargs):
            await asyncio.sleep(5)  # Simulate delay
            mock = AsyncMock()
            mock.status = 200
            mock.text = AsyncMock(return_value="OK")
            return mock
        
        with patch('aiohttp.ClientSession.get', side_effect=slow_response):
            target = {
                "url": "http://test.com/user",
                "params": {"id": "1"}
            }
            vulns = await scanner.scan(target)
            
            # Should detect if response took > 4.5 seconds
            time_based = [v for v in vulns if "Time-based" in v.vuln_type]
            assert len(time_based) > 0
    
    @pytest.mark.asyncio
    async def test_no_false_positive_on_clean_response(self, scanner):
        """Should not report SQLi on clean responses"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="""
            <html><body>Welcome to our website!</body></html>
        """)
        
        with patch('aiohttp.ClientSession.get', return_value=mock_response):
            target = {
                "url": "http://clean-site.com/page",
                "params": {"id": "1"}
            }
            vulns = await scanner.scan(target)
            
            assert len(vulns) == 0


class TestXSSScanner:
    """Unit tests for XSS detection"""
    
    @pytest.fixture
    def scanner(self):
        return XSSScanner()
    
    @pytest.mark.asyncio
    async def test_detects_reflected_xss(self, scanner):
        """Should detect reflected XSS"""
        payload = '<script>alert("XSS")</script>'
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value=f"""
            <html>
            <body>
            <h1>Search results for: {payload}</h1>
            </body>
            </html>
        """)
        
        with patch('aiohttp.ClientSession.get', return_value=mock_response):
            target = {
                "url": "http://test.com/search",
                "params": {"q": "test"}
            }
            vulns = await scanner.scan(target)
            
            assert len(vulns) > 0
            assert "Cross-Site Scripting" in vulns[0].vuln_type
    
    @pytest.mark.asyncio
    async def test_no_xss_when_encoded(self, scanner):
        """Should not report XSS when payload is properly encoded"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="""
            <html>
            <body>
            <h1>Search results for: &lt;script&gt;alert("XSS")&lt;/script&gt;</h1>
            </body>
            </html>
        """)
        
        with patch('aiohttp.ClientSession.get', return_value=mock_response):
            target = {
                "url": "http://test.com/search",
                "params": {"q": "test"}
            }
            vulns = await scanner.scan(target)
            
            assert len(vulns) == 0