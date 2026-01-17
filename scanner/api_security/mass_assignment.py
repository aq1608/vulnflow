# scanner/api_security/mass_assignment.py
"""
Mass Assignment Scanner

Detects mass assignment vulnerabilities where:
- API accepts unexpected parameters
- User can modify restricted fields
- Role/privilege escalation via parameter injection

OWASP API Security: API6:2019 - Mass Assignment
CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
"""

import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class MassAssignmentScanner(BaseScanner):
    """Scanner for mass assignment vulnerabilities"""
    
    name="Mass Assignment Scanner",
    description="Detects mass assignment vulnerabilities in APIs",
    owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL

    def __init__(self):
        
        # Dangerous fields that shouldn't be user-controllable
        self.dangerous_fields = {
            # Role/permission fields
            "role": ["admin", "administrator", "superuser", "root"],
            "roles": ["admin", "administrator"],
            "is_admin": [True, "true", "1", 1],
            "isAdmin": [True, "true", "1", 1],
            "admin": [True, "true", "1", 1],
            "is_superuser": [True, "true", "1", 1],
            "is_staff": [True, "true", "1", 1],
            "permissions": ["all", "*", "admin"],
            "privilege": ["admin", "elevated"],
            "access_level": ["admin", "10", "999"],
            "user_type": ["admin", "administrator"],
            "account_type": ["premium", "admin"],
            
            # Verification/status fields
            "verified": [True, "true", "1", 1],
            "is_verified": [True, "true", "1", 1],
            "email_verified": [True, "true", "1", 1],
            "active": [True, "true", "1", 1],
            "is_active": [True, "true", "1", 1],
            "approved": [True, "true", "1", 1],
            "status": ["active", "approved", "verified"],
            
            # Financial fields
            "balance": [1000000, "1000000"],
            "credits": [1000000, "1000000"],
            "points": [1000000, "1000000"],
            "discount": [100, "100"],
            "price": [0, "0", 0.01],
            
            # ID fields (IDOR via mass assignment)
            "user_id": [1, "1"],
            "userId": [1, "1"],
            "owner_id": [1, "1"],
            "account_id": [1, "1"],
            "organization_id": [1, "1"],
            
            # Timestamp manipulation
            "created_at": ["2020-01-01T00:00:00Z"],
            "updated_at": ["2020-01-01T00:00:00Z"],
            "expires_at": ["2099-12-31T23:59:59Z"],
            "subscription_end": ["2099-12-31"],
        }
        
        # API endpoints that commonly accept updates
        self.target_endpoints = [
            "/api/user",
            "/api/users/me",
            "/api/profile",
            "/api/account",
            "/api/settings",
            "/api/v1/user",
            "/api/v1/users/me",
            "/api/v1/profile",
            "/user/update",
            "/profile/update",
            "/account/settings",
        ]
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """
        Scan for mass assignment vulnerabilities.
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test target endpoints
        for endpoint in self.target_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            # Test with PUT/PATCH
            put_vulns = await self._test_mass_assignment(session, test_url, "PUT")
            vulnerabilities.extend(put_vulns)
            
            patch_vulns = await self._test_mass_assignment(session, test_url, "PATCH")
            vulnerabilities.extend(patch_vulns)
            
            # Also test POST for create endpoints
            if 'create' in endpoint or 'register' in endpoint:
                post_vulns = await self._test_mass_assignment(session, test_url, "POST")
                vulnerabilities.extend(post_vulns)
            
            if vulnerabilities:
                break  # Found issues, stop testing
        
        # Test the original URL
        if not vulnerabilities:
            url_vulns = await self._test_mass_assignment(session, url, "POST")
            vulnerabilities.extend(url_vulns)
        
        return vulnerabilities
    
    async def _test_mass_assignment(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str
    ) -> List[Vulnerability]:
        """Test endpoint for mass assignment"""
        vulnerabilities = []
        
        # First, check if endpoint exists and accepts the method
        try:
            async with session.request(
                method,
                url,
                json={},
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False
            ) as response:
                if response.status == 404:
                    return vulnerabilities
                if response.status == 405:  # Method not allowed
                    return vulnerabilities
        except:
            return vulnerabilities
        
        # Test each dangerous field
        for field_name, test_values in self.dangerous_fields.items():
            for test_value in test_values[:1]:  # Test first value only
                vuln = await self._test_field(
                    session, url, method, field_name, test_value
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Found issue with this field
        
        return vulnerabilities
    
    async def _test_field(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        field_name: str,
        test_value: Any
    ) -> Optional[Vulnerability]:
        """Test a specific field for mass assignment"""
        try:
            # Build payload with dangerous field
            payload = {
                field_name: test_value,
                "dummy_field": "dummy_value",  # Legitimate-looking field
            }
            
            # Add common expected fields
            if "user" in url.lower() or "profile" in url.lower():
                payload.update({
                    "name": "Test User",
                    "email": "test@test.com",
                })
            
            async with session.request(
                method,
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                response_text = await response.text()
                
                # Check for success indicators
                if response.status in [200, 201]:
                    try:
                        response_json = json.loads(response_text)
                        
                        # Check if our dangerous field was accepted
                        if self._field_accepted(response_json, field_name, test_value):
                            severity = self._get_field_severity(field_name)
                            
                            return Vulnerability(
                                vuln_type="Mass Assignment",
                                severity=severity,
                                url=url,
                                parameter=field_name,
                                payload=json.dumps({field_name: test_value}),
                                evidence=f"Field '{field_name}' accepted in response",
                                description=f"API accepts restricted field: {field_name}",
                                cwe_id="CWE-915",
                                remediation=self._get_remediation()
                            )
                    except json.JSONDecodeError:
                        pass
                    
                    # Check if field appears in response text
                    if str(test_value).lower() in response_text.lower():
                        field_pattern = rf'["\']?{re.escape(field_name)}["\']?\s*[:=]\s*["\']?{re.escape(str(test_value))}["\']?'
                        
                        # scanner/api_security/mass_assignment.py (continued)

                        if re.search(field_pattern, response_text, re.IGNORECASE):
                            severity = self._get_field_severity(field_name)
                            
                            return Vulnerability(
                                vuln_type="Mass Assignment",
                                severity=severity,
                                url=url,
                                parameter=field_name,
                                payload=json.dumps({field_name: test_value}),
                                evidence=f"Field '{field_name}={test_value}' reflected in response",
                                description=f"API may accept restricted field: {field_name}",
                                cwe_id="CWE-915",
                                remediation=self._get_remediation()
                            )
                
                # Check for specific error messages that confirm field existence
                error_patterns = [
                    rf"{field_name}.*(?:cannot|not allowed|forbidden|restricted)",
                    rf"(?:cannot|not allowed).*{field_name}",
                    rf"{field_name}.*(?:permission|unauthorized)",
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        # Field exists but is protected - this is good, but note it
                        return None
        
        except Exception:
            pass
        
        return None
    
    def _field_accepted(
        self,
        response_json: Any,
        field_name: str,
        test_value: Any
    ) -> bool:
        """Check if field was accepted in JSON response"""
        if isinstance(response_json, dict):
            # Direct match
            if field_name in response_json:
                return str(response_json[field_name]).lower() == str(test_value).lower()
            
            # Check nested objects
            for key, value in response_json.items():
                if isinstance(value, dict):
                    if self._field_accepted(value, field_name, test_value):
                        return True
                        
            # Check in 'data' wrapper
            if 'data' in response_json and isinstance(response_json['data'], dict):
                return self._field_accepted(response_json['data'], field_name, test_value)
            
            # Check in 'user' wrapper
            if 'user' in response_json and isinstance(response_json['user'], dict):
                return self._field_accepted(response_json['user'], field_name, test_value)
        
        return False
    
    def _get_field_severity(self, field_name: str) -> Severity:
        """Determine severity based on field type"""
        critical_fields = [
            'role', 'roles', 'is_admin', 'isAdmin', 'admin', 
            'is_superuser', 'permissions', 'privilege', 'access_level'
        ]
        
        high_fields = [
            'user_id', 'userId', 'owner_id', 'account_id',
            'verified', 'is_verified', 'email_verified',
            'balance', 'credits', 'price'
        ]
        
        field_lower = field_name.lower()
        
        if any(f.lower() == field_lower for f in critical_fields):
            return Severity.CRITICAL
        
        if any(f.lower() == field_lower for f in high_fields):
            return Severity.HIGH
        
        return Severity.MEDIUM
    
    def _get_remediation(self) -> str:
        """Get remediation advice"""
        return """
1. Implement allowlisting for acceptable fields in each endpoint
2. Use DTOs (Data Transfer Objects) to control accepted properties
3. Never directly bind user input to internal objects
4. Use separate models for input validation and database entities
5. Implement proper authorization checks for sensitive field updates

Example (Node.js/Express):
```javascript
// BAD - accepts any field
app.put('/user', (req, res) => {
    User.update(req.body);
});

// GOOD - allowlist fields
app.put('/user', (req, res) => {
    const allowed = ['name', 'email', 'bio'];
    const updates = {};
    allowed.forEach(field => {
        if (req.body[field]) updates[field] = req.body[field];
    });
    User.update(updates);
});
"""