# tests/conftest.py
import sys
import os
import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


@pytest.fixture
def sample_crawl_results():
    """Sample crawl results for testing"""
    return {
        "urls": {
            "http://test.com/": {
                "status": 200,
                "content_type": "text/html",
                "headers": {"Server": "nginx"}
            },
            "http://test.com/login": {
                "status": 200,
                "content_type": "text/html",
                "headers": {}
            },
            "http://test.com/search?q=test": {
                "status": 200,
                "content_type": "text/html",
                "headers": {}
            },
        },
        "forms": [
            {
                "action": "http://test.com/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""}
                ]
            },
            {
                "action": "http://test.com/search",
                "method": "GET",
                "inputs": [
                    {"name": "q", "type": "text", "value": ""}
                ]
            }
        ],
        "endpoints": [],
        "total_pages": 3
    }


@pytest.fixture
def sample_response_data():
    """Sample HTTP response data for tech detection"""
    return {
        "headers": "Server: nginx\nX-Powered-By: PHP/8.1",
        "cookies": "PHPSESSID=abc123; laravel_session=xyz",
        "body": """
        <html>
        <head>
            <meta name="csrf-token" content="abc123">
        </head>
        <body>
            <form>
                <input type="hidden" name="csrfmiddlewaretoken" value="xyz">
            </form>
        </body>
        </html>
        """
    }


@pytest.fixture
def mock_aiohttp_session():
    """Create a mock aiohttp session"""
    from unittest.mock import AsyncMock, MagicMock
    
    session = AsyncMock()
    response = AsyncMock()
    response.status = 200
    response.headers = {"Content-Type": "text/html"}
    response.text = AsyncMock(return_value="<html><body>Test</body></html>")
    
    # Make session.get return an async context manager
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.return_value.__aexit__ = AsyncMock(return_value=None)
    
    return session