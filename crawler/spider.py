# crawler/spider.py
import asyncio
import aiohttp
from aiohttp import BasicAuth
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set, Dict, List, Optional
import re
import os
from pathlib import Path
import json


class AuthConfig:
    """Authentication configuration container"""
    
    def __init__(
        self,
        # Form-based login
        login_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        username_field: str = "email",      # Field name for username input
        password_field: str = "password",   # Field name for password input
        login_method: str = "POST",         # POST or JSON (for API login)
        additional_form_data: Optional[Dict] = None,
        
        # Token-based auth
        bearer_token: Optional[str] = None,
        
        # Cookie-based auth
        cookies: Optional[Dict[str, str]] = None,
        
        # Basic HTTP auth
        basic_auth_user: Optional[str] = None,
        basic_auth_pass: Optional[str] = None,
        
        # Custom headers (API keys, etc.)
        custom_headers: Optional[Dict[str, str]] = None,
        
        # Session management
        logout_pattern: Optional[str] = None,  # URL pattern to avoid (logout links)
        auth_check_url: Optional[str] = None,  # URL to verify authentication
        auth_success_pattern: Optional[str] = None,  # Pattern in response indicating auth success
    ):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.login_method = login_method
        self.additional_form_data = additional_form_data or {}
        
        self.bearer_token = bearer_token
        self.cookies = cookies or {}
        
        self.basic_auth_user = basic_auth_user
        self.basic_auth_pass = basic_auth_pass
        
        self.custom_headers = custom_headers or {}
        
        self.logout_pattern = logout_pattern
        self.auth_check_url = auth_check_url
        self.auth_success_pattern = auth_success_pattern


class AsyncWebCrawler:
    """Asynchronous web crawler for discovering pages and forms with authentication support"""

    def __init__(
        self, 
        base_url: str, 
        max_depth: int = 3, 
        max_pages: int = 100, 
        save_pages: bool = False, 
        output_dir: str = "./crawled_pages",
        auth_config: Optional[AuthConfig] = None,  # NEW: Authentication config
        respect_robots: bool = False,               # NEW: Robots.txt compliance
        request_delay: float = 0.1,                 # NEW: Delay between requests
    ):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.discovered_urls: Dict[str, dict] = {}
        self.forms: List[dict] = []
        self.endpoints: List[str] = []
        self._lock = asyncio.Lock()

        # Page saving options
        self.save_pages = save_pages
        self.output_dir = output_dir

        # NEW: Authentication
        self.auth_config = auth_config
        self._auth_token: Optional[str] = None
        self._session_cookies: Dict[str, str] = {}
        self._is_authenticated: bool = False
        
        # NEW: Rate limiting
        self.request_delay = request_delay
        
        # Create output directory if saving is enabled
        if self.save_pages:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def _get_request_headers(self) -> Dict[str, str]:
        """Build request headers including authentication"""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        
        if self.auth_config:
            # Add bearer token
            if self._auth_token:
                headers["Authorization"] = f"Bearer {self._auth_token}"
            elif self.auth_config.bearer_token:
                headers["Authorization"] = f"Bearer {self.auth_config.bearer_token}"
            
            # Add custom headers
            headers.update(self.auth_config.custom_headers)
        
        return headers

    def _get_basic_auth(self) -> Optional[BasicAuth]:
        """Get basic auth if configured"""
        if self.auth_config and self.auth_config.basic_auth_user:
            return BasicAuth(
                self.auth_config.basic_auth_user,
                self.auth_config.basic_auth_pass or ""
            )
        return None

    async def _authenticate(self, session: aiohttp.ClientSession) -> bool:
        """Perform authentication before crawling"""
        if not self.auth_config:
            return True
        
        # If cookies are provided, add them directly
        if self.auth_config.cookies:
            self._session_cookies.update(self.auth_config.cookies)
            print(f"    [+] Using provided cookies")
        
        # If bearer token is provided, no login needed
        if self.auth_config.bearer_token:
            self._auth_token = self.auth_config.bearer_token
            print(f"    [+] Using provided bearer token")
            return True
        
        # If login credentials are provided, perform login
        if self.auth_config.login_url and self.auth_config.username:
            return await self._perform_login(session)
        
        return True

    async def _perform_login(self, session: aiohttp.ClientSession) -> bool:
        """Perform form or API-based login"""
        try:
            login_url = self.auth_config.login_url
            
            # Build login data
            login_data = {
                self.auth_config.username_field: self.auth_config.username,
                self.auth_config.password_field: self.auth_config.password,
            }
            login_data.update(self.auth_config.additional_form_data)
            
            headers = self._get_request_headers()
            
            print(f"    [*] Attempting login at {login_url}")
            
            if self.auth_config.login_method.upper() == "JSON":
                # JSON API login (common for SPAs like Juice Shop)
                headers["Content-Type"] = "application/json"
                async with session.post(
                    login_url, 
                    json=login_data, 
                    headers=headers,
                    allow_redirects=True
                ) as response:
                    return await self._process_login_response(response)
            else:
                # Standard form POST login
                async with session.post(
                    login_url, 
                    data=login_data, 
                    headers=headers,
                    allow_redirects=True
                ) as response:
                    return await self._process_login_response(response)
                    
        except Exception as e:
            print(f"    [!] Login failed: {e}")
            return False

    async def _process_login_response(self, response: aiohttp.ClientResponse) -> bool:
        """Process login response and extract tokens/cookies"""
        try:
            # Check for successful status codes
            if response.status not in [200, 201, 302, 303]:
                print(f"    [!] Login returned status {response.status}")
                return False
            
            # Extract cookies from response
            for cookie in response.cookies.values():
                self._session_cookies[cookie.key] = cookie.value
            
            # Try to extract token from JSON response
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    json_response = await response.json()
                    
                    # Common token field names
                    token_fields = ['token', 'access_token', 'accessToken', 'jwt', 
                                   'auth_token', 'authToken', 'id_token']
                    
                    # Check top level
                    for field in token_fields:
                        if field in json_response:
                            self._auth_token = json_response[field]
                            print(f"    [+] Extracted token from '{field}' field")
                            break
                    
                    # Check nested 'authentication' object (Juice Shop pattern)
                    if not self._auth_token and 'authentication' in json_response:
                        auth_obj = json_response['authentication']
                        for field in token_fields:
                            if field in auth_obj:
                                self._auth_token = auth_obj[field]
                                print(f"    [+] Extracted token from 'authentication.{field}'")
                                break
                                
                except json.JSONDecodeError:
                    pass
            
            # Check for auth token in response headers
            auth_header = response.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                self._auth_token = auth_header[7:]
                print(f"    [+] Extracted token from Authorization header")
            
            # Check for token in Set-Cookie
            for cookie_name, cookie_value in self._session_cookies.items():
                if 'token' in cookie_name.lower() or 'session' in cookie_name.lower():
                    print(f"    [+] Found session cookie: {cookie_name}")
            
            self._is_authenticated = True
            print(f"    [+] Authentication successful")
            return True
            
        except Exception as e:
            print(f"    [!] Error processing login response: {e}")
            return False

    async def _verify_authentication(self, session: aiohttp.ClientSession) -> bool:
        """Verify that authentication is still valid"""
        if not self.auth_config or not self.auth_config.auth_check_url:
            return True
        
        try:
            headers = self._get_request_headers()
            async with session.get(
                self.auth_config.auth_check_url,
                headers=headers,
                cookies=self._session_cookies
            ) as response:
                if response.status == 401 or response.status == 403:
                    print(f"    [!] Authentication expired, re-authenticating...")
                    return await self._authenticate(session)
                
                # Check for success pattern in response
                if self.auth_config.auth_success_pattern:
                    text = await response.text()
                    if self.auth_config.auth_success_pattern not in text:
                        return await self._authenticate(session)
                
                return True
        except Exception:
            return True

    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped (logout links, etc.)"""
        if not self.auth_config:
            return False
        
        # Skip logout URLs
        if self.auth_config.logout_pattern:
            if re.search(self.auth_config.logout_pattern, url, re.IGNORECASE):
                return True
        
        # Common logout patterns
        logout_patterns = [
            r'/logout', r'/signout', r'/sign-out', r'/log-out',
            r'/disconnect', r'/exit', r'\?logout', r'\?signout'
        ]
        
        for pattern in logout_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False

    async def crawl(self) -> Dict:
        """Main crawl entry point"""
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        # Prepare cookies for session
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        
        try:
            async with aiohttp.ClientSession(
                connector=connector, 
                timeout=timeout,
                cookie_jar=cookie_jar
            ) as session:
                # NEW: Authenticate before crawling
                if self.auth_config:
                    auth_success = await self._authenticate(session)
                    if not auth_success:
                        print(f"    [!] Authentication failed, crawling as unauthenticated user")
                
                await self._crawl_url(session, self.base_url, 0)
                
        except Exception as e:
            print(f"    [!] Crawl error: {e}")

        # Return format unchanged
        return {
            "urls": self.discovered_urls,
            "forms": self.forms,
            "endpoints": self.endpoints,
            "total_pages": len(self.visited)
        }

    def _save_page(self, url: str, html: str, status_code: int):
        """Save webpage content to file"""
        if not self.save_pages:
            return

        try:
            filename = url.replace('http://', '').replace('https://', '')
            filename = re.sub(r'[^\w\-.]', '_', filename)

            if not filename.endswith('.html'):
                filename += '.html'

            if len(filename) > 200:
                filename = filename[:200] + '.html'

            filepath = os.path.join(self.output_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)

            metadata_file = filepath.replace('.html', '_metadata.txt')
            with open(metadata_file, 'w', encoding='utf-8') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Status: {status_code}\n")
                f.write(f"Authenticated: {self._is_authenticated}\n")

            print(f"    [Saved] {filename}")

        except Exception as e:
            print(f"    [!] Error saving {url}: {e}")

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
            if self._should_skip_url(url):  # NEW: Skip logout URLs
                return
            self.visited.add(url)

        # NEW: Rate limiting
        if self.request_delay > 0:
            await asyncio.sleep(self.request_delay)

        try:
            # NEW: Use authentication headers and cookies
            headers = self._get_request_headers()
            basic_auth = self._get_basic_auth()
            
            async with session.get(
                url, 
                allow_redirects=True,
                headers=headers,
                cookies=self._session_cookies,
                auth=basic_auth
            ) as response:
                content_type = response.headers.get('Content-Type', '')

                async with self._lock:
                    self.discovered_urls[url] = {
                        "status": response.status,
                        "content_type": content_type,
                        "headers": dict(response.headers)
                    }

                if response.status == 200 and 'text/html' in content_type:
                    html = await response.text()
                    self._save_page(url, html, response.status)
                    await self._parse_page(session, url, html, depth)
                
                # NEW: Handle JSON responses (for SPAs)
                elif response.status == 200 and 'application/json' in content_type:
                    json_text = await response.text()
                    self._extract_urls_from_json(json_text)

        except asyncio.TimeoutError:
            async with self._lock:
                self.discovered_urls[url] = {"error": "Timeout"}
        except aiohttp.ClientError as e:
            async with self._lock:
                self.discovered_urls[url] = {"error": str(e)}
        except Exception as e:
            async with self._lock:
                self.discovered_urls[url] = {"error": str(e)}

    def _extract_urls_from_json(self, json_text: str):
        """Extract URLs from JSON responses (useful for SPAs)"""
        try:
            # Find URL patterns in JSON
            url_pattern = r'["\']((?:https?://[^\s"\']+)|(?:/[^\s"\']+))["\']'
            matches = re.findall(url_pattern, json_text)
            
            for match in matches:
                if match.startswith('/'):
                    full_url = urljoin(self.base_url, match)
                    if self._is_same_domain(full_url):
                        self.endpoints.append(match)
        except Exception:
            pass

    async def _parse_page(self, session: aiohttp.ClientSession,
                          base_url: str, html: str, depth: int):
        """Parse HTML page to extract links and forms"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return

        urls_to_crawl = []

        # Extract links
        for link in soup.find_all('a', href=True):
            href = link['href']

            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue

            full_url = urljoin(base_url, href)
            full_url = full_url.split('#')[0]

            # NEW: Skip logout URLs
            if self._should_skip_url(full_url):
                continue

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
            # NEW: Also check src attributes for JS files
            if script.get('src'):
                src = script['src']
                if not src.startswith(('http://', 'https://')):
                    src = urljoin(base_url, src)
                if self._is_same_domain(src):
                    self.endpoints.append(src)

        # NEW: Extract data from Angular/React/Vue attributes
        self._extract_spa_data(soup)

        if urls_to_crawl and depth < self.max_depth:
            batch_size = 5
            for i in range(0, len(urls_to_crawl), batch_size):
                batch = urls_to_crawl[i:i + batch_size]
                tasks = [
                    self._crawl_url(session, url, depth + 1)
                    for url in batch
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_spa_data(self, soup: BeautifulSoup):
        """Extract data from SPA frameworks (Angular, React, Vue)"""
        # Angular routes
        for elem in soup.find_all(attrs={"ng-href": True}):
            href = elem.get("ng-href")
            if href:
                full_url = urljoin(self.base_url, href)
                self.endpoints.append(href)
        
        # React router links
        for elem in soup.find_all(attrs={"to": True}):
            href = elem.get("to")
            if href and href.startswith('/'):
                self.endpoints.append(href)
        
        # Vue router links
        for elem in soup.find_all("router-link"):
            href = elem.get("to")
            if href and href.startswith('/'):
                self.endpoints.append(href)
        
        # Data attributes that might contain URLs
        for elem in soup.find_all(attrs={"data-url": True}):
            url = elem.get("data-url")
            if url:
                self.endpoints.append(url)

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
            r'\$http\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',  # Angular
            r'\.request\s*\(\s*["\']([^"\']+)["\']',
            r'["\']/(rest|api|graphql)/[^"\']+["\']',  # Common API patterns
        ]

        for pattern in patterns:
            try:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        for m in match:
                            if m and (m.startswith('/') or m.startswith('http')):
                                self.endpoints.append(m)
                    elif match and (match.startswith('/') or match.startswith('http')):
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