# websec/crawler/spider.py
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set, Dict, List
import re


class AsyncWebCrawler:
    """Asynchronous web crawler for discovering pages and forms"""
    
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.discovered_urls: Dict[str, dict] = {}
        self.forms: List[dict] = []
        self.endpoints: List[str] = []
        
    async def crawl(self) -> Dict:
        """Main crawl entry point"""
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            await self._crawl_url(session, self.base_url, 0)
        
        return {
            "urls": self.discovered_urls,
            "forms": self.forms,
            "endpoints": self.endpoints,
            "total_pages": len(self.visited)
        }
    
    async def _crawl_url(self, session: aiohttp.ClientSession, 
                         url: str, depth: int):
        """Recursively crawl URLs"""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        if not self._is_same_domain(url):
            return
            
        self.visited.add(url)
        
        try:
            async with session.get(url, allow_redirects=True) as response:
                content_type = response.headers.get('Content-Type', '')
                
                self.discovered_urls[url] = {
                    "status": response.status,
                    "content_type": content_type,
                    "headers": dict(response.headers)
                }
                
                if response.status == 200 and 'text/html' in content_type:
                    html = await response.text()
                    await self._parse_page(session, url, html, depth)
                        
        except Exception as e:
            self.discovered_urls[url] = {"error": str(e)}
    
    async def _parse_page(self, session: aiohttp.ClientSession, 
                          base_url: str, html: str, depth: int):
        """Parse HTML page to extract links and forms"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract links
        tasks = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('#') or href.startswith('javascript:'):
                continue
            full_url = urljoin(base_url, href).split('#')[0]
            if full_url not in self.visited:
                tasks.append(self._crawl_url(session, full_url, depth + 1))
        
        # Extract forms
        for form in soup.find_all('form'):
            form_data = self._parse_form(base_url, form)
            if form_data not in self.forms:
                self.forms.append(form_data)
        
        # Extract potential API endpoints from scripts
        for script in soup.find_all('script'):
            if script.string:
                self._extract_endpoints(script.string)
        
        # Run crawl tasks with limit
        if tasks:
            await asyncio.gather(*tasks[:10])
    
    def _parse_form(self, base_url: str, form) -> dict:
        """Parse HTML form element"""
        action = form.get('action', '')
        return {
            "action": urljoin(base_url, action) if action else base_url,
            "method": form.get('method', 'GET').upper(),
            "inputs": [
                {
                    "name": inp.get('name'),
                    "type": inp.get('type', 'text'),
                    "value": inp.get('value', '')
                }
                for inp in form.find_all(['input', 'textarea', 'select'])
                if inp.get('name')
            ]
        }
    
    def _extract_endpoints(self, script_content: str):
        """Extract API endpoints from JavaScript"""
        patterns = [
            r'["\']/(api|v\d)/[^"\']+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, script_content)
            for match in matches:
                if isinstance(match, tuple):
                    self.endpoints.extend(match)
                else:
                    self.endpoints.append(match)
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain"""
        try:
            return urlparse(url).netloc == urlparse(self.base_url).netloc
        except:
            return False