# crawler/spa_spider.py
"""
SPA-aware web crawler using Playwright for JavaScript rendering
"""

import asyncio
import re
import os
import json
from pathlib import Path
from typing import Set, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext, Route
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from crawler.spider import AuthConfig


class SPAWebCrawler:
    """SPA-aware web crawler using Playwright for JavaScript rendering"""

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        save_pages: bool = False,
        output_dir: str = "./crawled_pages",
        auth_config: Optional[AuthConfig] = None,
        headless: bool = True,
        wait_time: int = 2000,
        discover_api: bool = True,
    ):
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright required. Install: pip install playwright && playwright install chromium"
            )
        
        # Clean base URL
        self.base_url = re.sub(r'/#.*$', '', base_url).rstrip('/')
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.save_pages = save_pages
        self.output_dir = output_dir
        self.auth_config = auth_config
        self.headless = headless
        self.wait_time = wait_time
        self.discover_api = discover_api
        
        self.visited: Set[str] = set()
        self.discovered_urls: Dict[str, dict] = {}
        self.forms: List[dict] = []
        self.endpoints: List[str] = []
        self.api_endpoints: List[dict] = []
        
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._auth_token: Optional[str] = None
        
        if self.save_pages:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    async def _add_auth_header(self, route: Route):
        """Add authorization header to API requests"""
        request = route.request
        url = request.url
        
        if self._auth_token and ('/api/' in url or '/rest/' in url):
            headers = {**request.headers, 'Authorization': f'Bearer {self._auth_token}'}
            await route.continue_(headers=headers)
        else:
            await route.continue_()

    async def crawl(self) -> Dict:
        """Main crawl entry point"""
        async with async_playwright() as p:
            self._browser = await p.chromium.launch(headless=self.headless)
            self._context = await self._browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
            
            try:
                # Authenticate first
                if self.auth_config:
                    await self._authenticate()
                
                # Set up auth header injection for all API requests
                if self._auth_token:
                    await self._context.route('**/*', self._add_auth_header)
                
                # Start crawling
                await self._crawl_url(self.base_url, 0)
                
                # Discover additional API endpoints
                if self.discover_api:
                    await self._discover_api_endpoints()
                    
            except Exception as e:
                print(f"    [!] Crawl error: {e}")
            finally:
                await self._browser.close()
        
        # Deduplicate
        self.endpoints = list(set(self.endpoints))
        
        return {
            "urls": self.discovered_urls,
            "forms": self.forms,
            "endpoints": self.endpoints,
            "api_endpoints": self.api_endpoints,
            "total_pages": len(self.visited)
        }

    async def _authenticate(self):
        """Perform authentication"""
        if not self.auth_config:
            return
        
        page = await self._context.new_page()
        
        try:
            if self.auth_config.bearer_token:
                self._auth_token = self.auth_config.bearer_token
                print(f"    [+] Using provided bearer token")
                
            elif self.auth_config.cookies:
                domain = urlparse(self.base_url).netloc
                cookies = [
                    {'name': k, 'value': v, 'domain': domain, 'path': '/'}
                    for k, v in self.auth_config.cookies.items()
                ]
                await self._context.add_cookies(cookies)
                print(f"    [+] Set {len(cookies)} cookies")
                
            elif self.auth_config.login_url and self.auth_config.username:
                await self._perform_login(page)
                
        except Exception as e:
            print(f"    [!] Authentication error: {e}")
        finally:
            await page.close()

    async def _perform_login(self, page: Page):
        """Perform login"""
        login_url = self.auth_config.login_url
        
        # Auto-fix frontend URLs
        if '/#/' in login_url or '/#' in login_url:
            print(f"    [*] Frontend URL detected, searching for API endpoint...")
            api_url = await self._find_login_api(page)
            if api_url:
                login_url = api_url
            else:
                print(f"    [!] Could not find API endpoint")
                print(f"    [!] Try: --login-url {self.base_url}/rest/user/login")
                return
        
        print(f"    [*] Logging in at {login_url}")
        
        if self.auth_config.login_method == 'JSON':
            await self._api_login(page, login_url)
        else:
            await self._form_login(page)

    async def _find_login_api(self, page: Page) -> Optional[str]:
        """Auto-discover login API endpoint"""
        common_paths = [
            '/rest/user/login',
            '/api/auth/login',
            '/api/login',
            '/api/v1/auth/login',
            '/auth/login',
            '/api/users/login',
        ]
        
        for path in common_paths:
            test_url = f"{self.base_url}{path}"
            try:
                response = await page.request.post(
                    test_url,
                    headers={"Content-Type": "application/json"},
                    data="{}"
                )
                if response.status not in [404, 405]:
                    print(f"    [+] Found: {path}")
                    return test_url
            except:
                continue
        return None

    async def _api_login(self, page: Page, login_url: str):
        """Perform API-based login"""
        login_data = {
            self.auth_config.username_field: self.auth_config.username,
            self.auth_config.password_field: self.auth_config.password
        }
        
        try:
            response = await page.request.post(
                login_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(login_data)
            )
            
            status = response.status
            body = await response.text()
            
            if status in [200, 201]:
                data = json.loads(body)
                
                # Extract token
                token = None
                if 'authentication' in data:
                    token = data['authentication'].get('token')
                if not token:
                    token = data.get('token') or data.get('access_token')
                
                if token:
                    self._auth_token = token
                    print(f"    [+] Login successful! Token: {token[:40]}...")
                else:
                    print(f"    [+] Login succeeded (no token in response)")
            else:
                print(f"    [!] Login failed: HTTP {status}")
                
        except Exception as e:
            print(f"    [!] Login error: {e}")

    async def _form_login(self, page: Page):
        """Handle form-based login"""
        try:
            await page.goto(self.auth_config.login_url, wait_until='networkidle')
            await page.wait_for_timeout(1000)
            
            # Fill form
            await page.fill(f'input[name="{self.auth_config.username_field}"], input[type="email"], #email', 
                          self.auth_config.username)
            await page.fill('input[type="password"], #password', 
                          self.auth_config.password)
            await page.click('button[type="submit"], input[type="submit"]')
            
            await page.wait_for_timeout(2000)
            print(f"    [+] Form login submitted")
            
        except Exception as e:
            print(f"    [!] Form login error: {e}")

    async def _crawl_url(self, url: str, depth: int):
        """Crawl a URL with JavaScript rendering"""
        # Clean URL
        clean_url = re.sub(r'/#/?$', '', url)
        if not clean_url or clean_url == '':
            clean_url = self.base_url
        
        normalized = clean_url.split('#')[0].rstrip('/')
        
        # Checks
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        if normalized in self.visited:
            return
        if not self._is_same_domain(normalized):
            return
        if self._should_skip_url(normalized):
            return
        
        self.visited.add(normalized)
        print(f"    [Crawling] {clean_url} (depth={depth})")
        
        page = await self._context.new_page()
        
        try:
            # Capture API calls
            api_calls = []
            page.on('request', lambda req: api_calls.append({
                'url': req.url, 'method': req.method
            }) if '/api/' in req.url or '/rest/' in req.url else None)
            
            # Navigate
            response = await page.goto(clean_url, wait_until='domcontentloaded', timeout=30000)
            
            # Wait for JS to render
            try:
                await page.wait_for_load_state('networkidle', timeout=10000)
            except:
                pass
            
            await page.wait_for_timeout(self.wait_time)
            
            # Get content
            html = await page.content()
            status = response.status if response else 0
            title = await page.title()
            
            self.discovered_urls[clean_url] = {
                "status": status,
                "content_type": "text/html",
                "title": title,
                "js_rendered": True
            }
            
            if self.save_pages:
                self._save_page(clean_url, html, status)
            
            # Store API calls
            for call in api_calls:
                if call not in self.api_endpoints:
                    self.api_endpoints.append(call)
                    self.endpoints.append(call['url'])
            
            # Parse for more links
            await self._parse_page(page, clean_url, html, depth)
            
        except Exception as e:
            print(f"    [!] Error: {str(e)[:80]}")
            self.discovered_urls[clean_url] = {"error": str(e)}
        finally:
            await page.close()

    async def _parse_page(self, page: Page, base_url: str, html: str, depth: int):
        """Parse rendered page"""
        soup = BeautifulSoup(html, 'html.parser')
        urls_to_crawl = set()
        
        # Standard links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('javascript:', 'mailto:', 'tel:')):
                continue
            if href.startswith('#') and not href.startswith('#/'):
                continue
            
            if href.startswith('#/'):
                full_url = f"{self.base_url}/{href}"
            else:
                full_url = urljoin(base_url, href)
            
            full_url = re.sub(r'/#/?$', '', full_url)
            if self._is_same_domain(full_url) and not self._should_skip_url(full_url):
                urls_to_crawl.add(full_url)
        
        # Angular routerLink
        for elem in soup.find_all(attrs={"routerlink": True}):
            route = elem.get("routerlink")
            if route and route.startswith('/'):
                urls_to_crawl.add(f"{self.base_url}{route}")
        
        # Extract forms
        for form in soup.find_all('form'):
            form_data = self._parse_form(base_url, form)
            if form_data and form_data not in self.forms:
                self.forms.append(form_data)
        
        # Crawl found URLs
        for url in list(urls_to_crawl)[:15]:
            if len(self.visited) < self.max_pages:
                await self._crawl_url(url, depth + 1)

    async def _discover_api_endpoints(self):
        """Probe common API endpoints"""
        page = await self._context.new_page()
        
        api_paths = [
            '/rest/user/whoami',
            '/rest/user/login',
            '/rest/products/search',
            '/rest/basket',
            '/rest/admin/application-version',
            '/rest/admin/application-configuration',
            '/rest/languages',
            '/rest/memories',
            '/rest/chatbot/status',
            '/rest/deluxe-membership',
            '/rest/wallet/balance',
            '/rest/track-order',
            '/api/Users',
            '/api/Products',
            '/api/Feedbacks',
            '/api/Complaints',
            '/api/Recycles',
            '/api/SecurityQuestions',
            '/api/Challenges',
            '/api/Quantitys',
            '/api/Cards',
            '/api/Addresss',
            '/api/SecurityAnswers',
            '/metrics',           # Prometheus
            '/actuator',          # Spring Boot
            '/actuator/health',
            '/actuator/metrics',
            '/actuator/env',
            '/health',
            '/healthz',
            '/ready',
            '/status',
            '/_status',
            '/debug',
            '/debug/vars',        # Go expvar
            '/server-status',     # Apache
            '/nginx_status', 
            '/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility',
            '/encryptionkeys/premium.key',
        ]
        
        found = 0
        for path in api_paths:
            url = f"{self.base_url}{path}"
            try:
                headers = {'Authorization': f'Bearer {self._auth_token}'} if self._auth_token else {}
                response = await page.request.get(url, headers=headers, timeout=5000)
                if response.status not in [404, 405]:
                    self.endpoints.append(path)
                    self.api_endpoints.append({'url': url, 'method': 'GET', 'status': response.status})
                    found += 1
            except:
                continue
        
        print(f"    [+] Found {found} API endpoints")
        await page.close()

    def _parse_form(self, base_url: str, form) -> Optional[dict]:
        """Parse HTML form"""
        inputs = [
            {"name": inp.get('name') or inp.get('formcontrolname'),
             "type": inp.get('type', 'text'),
             "value": inp.get('value', '')}
            for inp in form.find_all(['input', 'textarea', 'select'])
            if inp.get('name') or inp.get('formcontrolname')
        ]
        
        if not inputs:
            return None
        
        action = form.get('action', '')
        return {
            "action": urljoin(base_url, action) if action else base_url,
            "method": form.get('method', 'POST').upper(),
            "inputs": inputs
        }

    def _save_page(self, url: str, html: str, status: int):
        """Save page to file"""
        try:
            filename = re.sub(r'[^\w\-.]', '_', url.replace('http://', '').replace('https://', ''))[:200]
            if not filename.endswith('.html'):
                filename += '.html'
            
            with open(os.path.join(self.output_dir, filename), 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"    [Saved] {filename}")
        except Exception as e:
            print(f"    [!] Save error: {e}")

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is same domain"""
        try:
            return urlparse(self.base_url).netloc.lower() == urlparse(url).netloc.lower()
        except:
            return False

    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped"""
        skip = [r'/logout', r'/signout', r'\.pdf$', r'\.zip$', r'\.png$', 
                r'\.jpg$', r'\.gif$', r'\.css$', r'\.js$', r'\.map$', r'\.woff']
        return any(re.search(p, url, re.I) for p in skip)