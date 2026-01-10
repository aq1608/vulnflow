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
        self._lock = asyncio.Lock()  # For thread-safe operations
        
    async def crawl(self) -> Dict:
        """Main crawl entry point"""
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                await self._crawl_url(session, self.base_url, 0)
        except Exception as e:
            print(f"    [!] Crawl error: {e}")
        
        return {
            "urls": self.discovered_urls,
            "forms": self.forms,
            "endpoints": self.endpoints,
            "total_pages": len(self.visited)
        }
    
    async def _crawl_url(self, session: aiohttp.ClientSession, 
                         url: str, depth: int):
        """Recursively crawl URLs"""
        # Check limits
        if depth > self.max_depth:
            return
        
        async with self._lock:
            if len(self.visited) >= self.max_pages:
                return
            if url in self.visited:
                return
            if not self._is_same_domain(url):
                return
            # Mark as visited
            self.visited.add(url)
        
        try:
            async with session.get(url, allow_redirects=True) as response:
                content_type = response.headers.get('Content-Type', '')
                
                async with self._lock:
                    self.discovered_urls[url] = {
                        "status": response.status,
                        "content_type": content_type,
                        "headers": dict(response.headers)
                    }
                
                if response.status == 200 and 'text/html' in content_type:
                    html = await response.text()
                    await self._parse_page(session, url, html, depth)
                        
        except asyncio.TimeoutError:
            async with self._lock:
                self.discovered_urls[url] = {"error": "Timeout"}
        except aiohttp.ClientError as e:
            async with self._lock:
                self.discovered_urls[url] = {"error": str(e)}
        except Exception as e:
            async with self._lock:
                self.discovered_urls[url] = {"error": str(e)}
    
    async def _parse_page(self, session: aiohttp.ClientSession, 
                          base_url: str, html: str, depth: int):
        """Parse HTML page to extract links and forms"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return
        
        # Collect URLs to crawl
        urls_to_crawl = []
        
        # Extract links
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Skip non-HTTP links
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            
            # Build full URL
            full_url = urljoin(base_url, href)
            
            # Remove fragments
            full_url = full_url.split('#')[0]
            
            # Check if we should crawl this URL
            async with self._lock:
                if full_url not in self.visited and self._is_same_domain(full_url):
                    if len(self.visited) < self.max_pages:
                        urls_to_crawl.append(full_url)
        
        # Extract forms
        for form in soup.find_all('form'):
            form_data = self._parse_form(base_url, form)
            async with self._lock:
                if form_data not in self.forms:
                    self.forms.append(form_data)
        
        # Extract potential API endpoints from scripts
        for script in soup.find_all('script'):
            if script.string:
                self._extract_endpoints(script.string)
        
        # Crawl discovered URLs concurrently (limit concurrency)
        if urls_to_crawl and depth < self.max_depth:
            # Limit to 5 concurrent requests per page
            batch_size = 5
            for i in range(0, len(urls_to_crawl), batch_size):
                batch = urls_to_crawl[i:i + batch_size]
                tasks = [
                    self._crawl_url(session, url, depth + 1) 
                    for url in batch
                ]
                # Use gather with return_exceptions to prevent one failure from stopping all
                await asyncio.gather(*tasks, return_exceptions=True)
    
    def _parse_form(self, base_url: str, form) -> dict:
        """Parse HTML form element"""
        action = form.get('action', '')
        if action:
            action_url = urljoin(base_url, action)
        else:
            action_url = base_url
            
        return {
            "action": action_url,
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
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        for m in match:
                            if m and m.startswith('/'):
                                self.endpoints.append(m)
                    elif match and match.startswith('/'):
                        self.endpoints.append(match)
            except re.error:
                pass
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain"""
        try:
            base_domain = urlparse(self.base_url).netloc.lower()
            url_domain = urlparse(url).netloc.lower()
            return base_domain == url_domain
        except Exception:
            return False