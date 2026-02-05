# scanner/insecure_design/file_upload.py
"""
File Upload Security Scanner

Detects insecure file upload vulnerabilities:
- Unrestricted file type uploads
- Bypass of file extension checks
- Missing content-type validation
- Path traversal in filenames
- Executable uploads

OWASP: A06:2025 - Insecure Design
CWE-434: Unrestricted Upload of File with Dangerous Type
CWE-646: Reliance on File Name or Extension of Externally-Supplied File
"""

import re
import asyncio
import io
from typing import List, Dict, Optional, Tuple
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class FileUploadScanner(BaseScanner):
    """Scanner for insecure file upload vulnerabilities"""
    
    name = "File Upload Scanner"
    description = "Detects insecure file upload configurations and bypasses"
    owasp_category = OWASPCategory.A06_INSECURE_DESIGN
    
    # Dangerous file extensions by category
    DANGEROUS_EXTENSIONS = {
        'executable': ['.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.phar',
                      '.asp', '.aspx', '.ashx', '.asmx', '.cer', '.asa',
                      '.jsp', '.jspx', '.jsf', '.jsw', '.jsv',
                      '.exe', '.dll', '.bat', '.cmd', '.com', '.ps1', '.vbs',
                      '.pl', '.cgi', '.py', '.rb', '.sh'],
        'config': ['.htaccess', '.htpasswd', 'web.config', '.env', '.ini', '.conf'],
        'script': ['.js', '.html', '.htm', '.svg', '.xml', '.xhtml'],
        'ssi': ['.shtml', '.stm', '.shtm'],
    }
    
    # Extension bypass techniques
    BYPASS_TECHNIQUES = [
        # Null byte injection
        ('.php%00.jpg', 'Null byte bypass'),
        ('.php\x00.jpg', 'Null byte (raw)'),
        
        # Double extension
        ('.php.jpg', 'Double extension'),
        ('.php.png', 'Double extension PNG'),
        ('.jpg.php', 'Reverse double extension'),
        
        # Case manipulation
        ('.pHp', 'Case variation'),
        ('.PhP', 'Mixed case'),
        ('.PHP', 'Uppercase'),
        
        # Special characters
        ('.php.', 'Trailing dot'),
        ('.php ', 'Trailing space'),
        ('.php::$DATA', 'NTFS ADS'),
        ('.php....', 'Multiple dots'),
        ('.php%20', 'URL encoded space'),
        ('.php%0a', 'Newline injection'),
        
        # Alternative extensions
        ('.phtml', 'Alternative PHP'),
        ('.phar', 'PHP Archive'),
        ('.inc', 'PHP include'),
        ('.module', 'PHP module'),
        
        # Content-type tricks
        ('.php;.jpg', 'Semicolon bypass'),
        ('.php#.jpg', 'Hash bypass'),
        
        # Polyglot files
        ('polyglot.php.gif', 'Polyglot GIF'),
    ]
    
    # Common upload endpoints
    UPLOAD_ENDPOINTS = [
        '/upload', '/upload.php', '/upload.asp', '/upload.aspx',
        '/file/upload', '/files/upload', '/api/upload', '/api/v1/upload',
        '/image/upload', '/images/upload', '/img/upload',
        '/media/upload', '/document/upload', '/documents/upload',
        '/attachment/upload', '/attachments',
        '/admin/upload', '/cms/upload',
        '/profile/upload', '/avatar/upload',
        '/import', '/data/import',
    ]
    
    # Content-type mappings for bypass
    CONTENT_TYPES = {
        'image': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
        'document': ['application/pdf', 'application/msword', 
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        'text': ['text/plain', 'text/csv'],
    }
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for file upload vulnerabilities"""
        vulnerabilities = []
        
        # Find upload endpoints
        upload_endpoints = await self._discover_upload_endpoints(session, url)
        
        for endpoint in upload_endpoints:
            # Test each endpoint for vulnerabilities
            endpoint_vulns = await self._test_upload_endpoint(session, endpoint)
            vulnerabilities.extend(endpoint_vulns)
        
        # Also test provided URL if it looks like an upload endpoint
        if any(pattern in url.lower() for pattern in ['upload', 'file', 'import', 'attach']):
            direct_vulns = await self._test_upload_endpoint(session, url)
            vulnerabilities.extend(direct_vulns)
        
        return vulnerabilities
    
    async def _discover_upload_endpoints(self, session: aiohttp.ClientSession,
                                          base_url: str) -> List[str]:
        """Discover potential upload endpoints"""
        discovered = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check common upload paths
        for endpoint in self.UPLOAD_ENDPOINTS[:10]:  # Limit for speed
            test_url = urljoin(base, endpoint)
            try:
                response = await self.make_request(session, "GET", test_url)
                if response and response.status not in [404, 403, 500]:
                    discovered.append(test_url)
                
                # Also check OPTIONS for POST support
                response = await self.make_request(session, "OPTIONS", test_url)
                if response and 'POST' in response.headers.get('Allow', ''):
                    if test_url not in discovered:
                        discovered.append(test_url)
                        
            except Exception:
                continue
        
        return discovered[:5]  # Limit endpoints to test
    
    async def _test_upload_endpoint(self, session: aiohttp.ClientSession,
                                     url: str) -> List[Vulnerability]:
        """Test a specific upload endpoint"""
        vulnerabilities = []
        
        # Test 1: Check if dangerous extensions are allowed
        ext_vuln = await self._test_dangerous_extensions(session, url)
        if ext_vuln:
            vulnerabilities.append(ext_vuln)
        
        # Test 2: Check extension bypass techniques
        bypass_vuln = await self._test_extension_bypass(session, url)
        if bypass_vuln:
            vulnerabilities.append(bypass_vuln)
        
        # Test 3: Check content-type bypass
        content_vuln = await self._test_content_type_bypass(session, url)
        if content_vuln:
            vulnerabilities.append(content_vuln)
        
        # Test 4: Check for path traversal in filename
        traversal_vuln = await self._test_filename_traversal(session, url)
        if traversal_vuln:
            vulnerabilities.append(traversal_vuln)
        
        # Test 5: Check for missing validation indicators
        validation_vuln = await self._test_upload_validation(session, url)
        if validation_vuln:
            vulnerabilities.append(validation_vuln)
        
        return vulnerabilities
    
    async def _test_dangerous_extensions(self, session: aiohttp.ClientSession,
                                          url: str) -> Optional[Vulnerability]:
        """Test if dangerous file extensions are accepted"""
        
        for ext in ['.php', '.jsp', '.asp', '.aspx']:
            # Create a minimal test file
            filename = f"test{ext}"
            content = b"<?php echo 'test'; ?>" if 'php' in ext else b"test"
            
            try:
                form_data = aiohttp.FormData()
                form_data.add_field('file', content, 
                                   filename=filename,
                                   content_type='application/octet-stream')
                
                async with session.post(
                    url,
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    # Check for success indicators
                    if response.status in [200, 201]:
                        # Look for uploaded file path or success message
                        success_indicators = [
                            'success', 'uploaded', 'complete', 
                            filename, ext, 'file_path', 'url'
                        ]
                        
                        if any(ind.lower() in body.lower() for ind in success_indicators):
                            return self.create_vulnerability(
                                vuln_type="Unrestricted File Upload",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter="file",
                                payload=filename,
                                evidence=f"Server accepted {ext} file upload",
                                description=f"The application allows uploading of dangerous file types ({ext}). This can lead to remote code execution.",
                                cwe_id="CWE-434",
                                cvss_score=9.8,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                    "https://cwe.mitre.org/data/definitions/434.html"
                                ]
                            )
            except Exception:
                continue
        
        return None
    
    async def _test_extension_bypass(self, session: aiohttp.ClientSession,
                                      url: str) -> Optional[Vulnerability]:
        """Test extension bypass techniques"""
        
        for bypass_ext, description in self.BYPASS_TECHNIQUES[:8]:  # Limit for speed
            filename = f"test{bypass_ext}"
            content = b"<?php echo 'test'; ?>"
            
            try:
                form_data = aiohttp.FormData()
                form_data.add_field('file', content, 
                                   filename=filename,
                                   content_type='image/jpeg')  # Misleading content-type
                
                async with session.post(
                    url,
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    if response.status in [200, 201]:
                        success_indicators = ['success', 'uploaded', 'complete', 'url', 'path']
                        
                        if any(ind.lower() in body.lower() for ind in success_indicators):
                            return self.create_vulnerability(
                                vuln_type="File Upload Extension Bypass",
                                severity=Severity.HIGH,
                                url=url,
                                parameter="file",
                                payload=filename,
                                evidence=f"Bypass technique accepted: {description}",
                                description=f"File extension validation can be bypassed using {description}.",
                                cwe_id="CWE-646",
                                cvss_score=8.8,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                                ]
                            )
            except Exception:
                continue
        
        return None
    
    async def _test_content_type_bypass(self, session: aiohttp.ClientSession,
                                         url: str) -> Optional[Vulnerability]:
        """Test if content-type validation can be bypassed"""
        
        filename = "malicious.php"
        content = b"<?php echo 'test'; ?>"
        
        for content_type in ['image/jpeg', 'image/gif', 'image/png']:
            try:
                form_data = aiohttp.FormData()
                form_data.add_field('file', content, 
                                   filename=filename,
                                   content_type=content_type)
                
                async with session.post(
                    url,
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    if response.status in [200, 201]:
                        if 'success' in body.lower() or 'uploaded' in body.lower():
                            return self.create_vulnerability(
                                vuln_type="Content-Type Validation Bypass",
                                severity=Severity.HIGH,
                                url=url,
                                parameter="file",
                                payload=f"{filename} with Content-Type: {content_type}",
                                evidence="PHP file accepted with image content-type",
                                description="The application relies only on Content-Type header for file validation, which can be easily spoofed.",
                                cwe_id="CWE-434",
                                cvss_score=8.0,
                                remediation=self._get_remediation(),
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                                ]
                            )
            except Exception:
                continue
        
        return None
    
    async def _test_filename_traversal(self, session: aiohttp.ClientSession,
                                        url: str) -> Optional[Vulnerability]:
        """Test for path traversal in filename"""
        
        traversal_names = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc/passwd',
            '..%252f..%252f..%252fetc/passwd',
        ]
        
        for filename in traversal_names:
            try:
                form_data = aiohttp.FormData()
                form_data.add_field('file', b'test content', 
                                   filename=filename,
                                   content_type='text/plain')
                
                async with session.post(
                    url,
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    # Check for path traversal indicators
                    if response.status in [200, 201]:
                        # Look for original traversal path in response (might indicate it's being used)
                        if '../' in body or '..\\' in body:
                            return self.create_vulnerability(
                                vuln_type="File Upload Path Traversal",
                                severity=Severity.HIGH,
                                url=url,
                                parameter="filename",
                                payload=filename,
                                evidence="Path traversal characters in filename accepted",
                                description="The application may be vulnerable to path traversal via the uploaded filename.",
                                cwe_id="CWE-73",
                                cvss_score=7.5,
                                remediation="Sanitize filenames by removing path separators and using a safe basename.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/73.html"
                                ]
                            )
            except Exception:
                continue
        
        return None
    
    async def _test_upload_validation(self, session: aiohttp.ClientSession,
                                       url: str) -> Optional[Vulnerability]:
        """Test for weak or missing upload validation"""
        
        # Send empty file
        try:
            form_data = aiohttp.FormData()
            form_data.add_field('file', b'', filename='empty.txt', content_type='text/plain')
            
            async with session.post(
                url,
                data=form_data,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                body = await response.text()
                
                if response.status in [200, 201]:
                    if 'success' in body.lower():
                        return self.create_vulnerability(
                            vuln_type="Missing File Upload Validation",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="file",
                            payload="empty file",
                            evidence="Empty file accepted",
                            description="The application accepts empty files, indicating weak validation.",
                            cwe_id="CWE-434",
                            cvss_score=5.0,
                            remediation="Implement proper file size and content validation.",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                            ]
                        )
        except Exception:
            pass
        
        return None
    
    def _get_remediation(self) -> str:
        """Get comprehensive remediation advice"""
        return """
File Upload Security Best Practices:

1. **Validate File Extension (Server-side)**
   - Use allowlist of permitted extensions
   - Check extension after lowercase conversion
   - Don't rely on Content-Type header

2. **Validate File Content (Magic Bytes)**
   - Check file signatures/magic bytes
   - Use libraries like python-magic, fileinfo

3. **Rename Uploaded Files**
   - Generate random filenames
   - Don't preserve user-supplied names

4. **Store Outside Web Root**
   - Upload to non-executable directory
   - Serve through a controller/proxy

5. **Set Proper Permissions**
   - Remove execute permissions
   - Use restrictive file permissions

6. **Limit File Size**
   - Implement max file size limits
   - Check before and during upload

7. **Scan for Malware**
   - Use antivirus scanning
   - Check for embedded scripts

Example (Python/Flask):
```python
import os
import uuid
import magic

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_MIMES = {'image/png', 'image/jpeg', 'image/gif'}
UPLOAD_FOLDER = '/var/uploads'  # Outside web root

def allowed_file(file):
    # Check extension
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    
    # Check magic bytes
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIMES:
        return False
    
    return True

def secure_upload(file):
    if not allowed_file(file):
        raise ValueError("Invalid file type")
    
    # Generate random filename
    ext = file.filename.rsplit('.', 1)[-1].lower()
    filename = f"{uuid.uuid4()}.{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    file.save(filepath)
    os.chmod(filepath, 0o644)  # Read-only
    
    return filename
```
"""