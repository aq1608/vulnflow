# scanner/misconfig/debug.py
"""Debug Mode Detection Scanner"""

import re
from typing import List, Dict, Optional
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class DebugModeScanner(BaseScanner):
    """Scanner for Debug Mode and Development Configuration issues"""
    
    name = "Debug Mode Scanner"
    description = "Detects debug mode and development configurations exposed in production"
    owasp_category = OWASPCategory.A02_SECURITY_MISCONFIGURATION
    
    # Minimum content length to consider valid
    MIN_CONTENT_LENGTH = 20
    
    # Debug endpoints to check
    DEBUG_ENDPOINTS = [
        # Django
        ('/__debug__/', 'Django Debug Toolbar'),
        
        # Laravel
        ('/_debugbar', 'Laravel Debugbar'),
        ('/_debugbar/open', 'Laravel Debugbar Open'),
        
        # Symfony
        ('/_profiler/', 'Symfony Profiler'),
        ('/_profiler/latest', 'Symfony Profiler Latest'),
        ('/_wdt/', 'Symfony Web Debug Toolbar'),
        
        # ASP.NET
        ('/elmah.axd', 'ELMAH Error Log'),
        ('/trace.axd', 'ASP.NET Trace'),
        
        # Spring Boot Actuator
        ('/actuator', 'Spring Boot Actuator'),
        ('/actuator/health', 'Spring Actuator Health'),
        ('/actuator/info', 'Spring Actuator Info'),
        ('/actuator/env', 'Spring Actuator Environment'),
        ('/actuator/mappings', 'Spring Actuator Mappings'),
        ('/actuator/configprops', 'Spring Actuator Config Properties'),
        ('/actuator/beans', 'Spring Actuator Beans'),
        ('/actuator/metrics', 'Spring Actuator Metrics'),
        ('/actuator/threaddump', 'Spring Actuator Thread Dump'),
        ('/actuator/heapdump', 'Spring Actuator Heap Dump'),
        
        # Generic debug
        ('/api/debug', 'Debug API'),
        ('/debug', 'Debug Page'),
        ('/debug/vars', 'Go Debug Variables'),
        ('/debug/pprof/', 'Go pprof'),
        ('/console', 'Console'),
        ('/admin/console', 'Admin Console'),
        
        # GraphQL
        ('/graphql', 'GraphQL Endpoint'),
        ('/graphiql', 'GraphiQL Interface'),
        ('/__graphql', 'GraphQL Debug'),
        ('/playground', 'GraphQL Playground'),
        ('/altair', 'Altair GraphQL Client'),
        
        # Metrics & Monitoring (Prometheus, etc.)
        ('/metrics', 'Prometheus Metrics'),
        ('/prometheus', 'Prometheus Endpoint'),
        ('/prometheus/metrics', 'Prometheus Metrics'),
        ('/-/metrics', 'Prometheus Metrics Alt'),
        ('/federate', 'Prometheus Federation'),
        
        # Health & Status
        ('/health', 'Health Check'),
        ('/healthz', 'Kubernetes Health'),
        ('/readyz', 'Kubernetes Ready'),
        ('/livez', 'Kubernetes Liveness'),
        ('/ready', 'Ready Check'),
        ('/status', 'Status Page'),
        ('/server-status', 'Apache Server Status'),
        ('/server-info', 'Apache Server Info'),
        ('/nginx_status', 'Nginx Status'),
        ('/info', 'Info Endpoint'),
        ('/version', 'Version Info'),
        ('/build-info', 'Build Info'),
        
        # Swagger/OpenAPI
        ('/swagger', 'Swagger UI'),
        ('/swagger-ui', 'Swagger UI'),
        ('/swagger-ui.html', 'Swagger UI'),
        ('/swagger.json', 'Swagger JSON'),
        ('/swagger.yaml', 'Swagger YAML'),
        ('/api-docs', 'API Documentation'),
        ('/v2/api-docs', 'Swagger v2 API Docs'),
        ('/v3/api-docs', 'OpenAPI v3 Docs'),
        ('/openapi.json', 'OpenAPI JSON'),
        
        # PHP
        ('/phpinfo.php', 'PHP Info'),
        ('/info.php', 'PHP Info'),
        ('/test.php', 'PHP Test'),
        ('/php-info.php', 'PHP Info'),
        
        # Other
        ('/stats', 'Statistics'),
        ('/statistics', 'Statistics'),
        ('/monitoring', 'Monitoring'),
        ('/jmx', 'JMX Console'),
    ]
    
    # Patterns indicating debug mode
    DEBUG_PATTERNS = [
        (r'DEBUG\s*=\s*True', 'Django DEBUG=True'),
        (r'APP_DEBUG\s*=\s*true', 'Laravel APP_DEBUG'),
        (r'FLASK_DEBUG\s*=\s*1', 'Flask Debug Mode'),
        (r'development\s*mode', 'Development Mode'),
        (r'debug\s*mode\s*(is\s*)?(enabled|on|active)', 'Debug Mode Enabled'),
        (r'stack\s*trace', 'Stack Trace Exposed'),
        (r'Traceback\s*\(most\s*recent', 'Python Traceback'),
        (r'at\s+[\w\.]+\([\w\.]+:\d+\)', 'Java Stack Trace'),
        (r'Exception\s+in\s+thread', 'Java Exception'),
        (r'<b>Warning</b>:\s+\w+\(\)', 'PHP Warning'),
        (r'<b>Fatal\s+error</b>', 'PHP Fatal Error'),
        (r'Call\s+Stack', 'Debug Call Stack'),
        (r'mysqli?_connect\(', 'Database Connection Info'),
        (r'pg_connect\(', 'PostgreSQL Connection Info'),
        (r'Werkzeug\s+Debugger', 'Werkzeug Debugger'),
        (r'Laravel.*Exception', 'Laravel Exception'),
        (r'Symfony.*Exception', 'Symfony Exception'),
        (r'ExceptionHandler', 'Exception Handler'),
        (r'vendor/laravel', 'Laravel Vendor Path'),
        (r'node_modules', 'Node Modules Path'),
        (r'DOCUMENT_ROOT', 'Document Root Exposed'),
        (r'__FILE__', 'File Path Exposed'),
    ]
    
    # Prometheus-specific patterns
    PROMETHEUS_PATTERNS = [
        r'^# HELP \w+',           # Help text
        r'^# TYPE \w+ \w+',       # Type declaration
        r'^\w+\{[^}]*\}\s+[\d.]+', # Metric with labels
        r'^\w+_total\s+[\d.]+',   # Counter metric
        r'^\w+_seconds\s+[\d.]+', # Duration metric
        r'^\w+_bytes\s+[\d.]+',   # Bytes metric
        r'^process_\w+\s+[\d.]+', # Process metrics
        r'^go_\w+\s+[\d.]+',      # Go runtime metrics
        r'^node_\w+',             # Node exporter metrics
        r'^http_\w+',             # HTTP metrics
    ]
    
    # Error trigger payloads
    ERROR_TRIGGERS = [
        ("'", "SQL/Syntax Error"),
        ("{{", "Template Error"),
        ("<script>", "XSS/Parse Error"),
        ("[]", "Type Error"),
        ("null", "Null Reference"),
        ("%s%s%s%s%s", "Format String"),
        ("../../../", "Path Error"),
        ("-1", "Numeric Error"),
        ("9999999999999999", "Integer Overflow"),
    ]
    
    async def scan(self, session: aiohttp.ClientSession, 
                   url: str, params: Dict[str, str] = None) -> List[Vulnerability]:
        """Scan for debug mode and development configurations"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check debug endpoints
        for endpoint, name in self.DEBUG_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            vuln = await self._check_debug_endpoint(session, test_url, name, endpoint)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Check for debug info in error responses
        if params:
            vuln = await self._trigger_errors(session, url, params)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Check main page for debug indicators
        vuln = await self._check_page_debug(session, url)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _check_debug_endpoint(self, session: aiohttp.ClientSession,
                                     url: str, name: str, endpoint: str) -> Optional[Vulnerability]:
        """Check if a debug endpoint is accessible"""
        
        response = await self.make_request(session, "GET", url)
        if not response:
            return None
        
        if response.status == 200:
            body = await response.text()
            content_type = response.headers.get('Content-Type', '')
            
            # ══════════════════════════════════════════════════════════════
            # FIX 1: Skip empty responses
            # ══════════════════════════════════════════════════════════════
            if not body or len(body.strip()) < self.MIN_CONTENT_LENGTH:
                return None
            
            # ══════════════════════════════════════════════════════════════
            # FIX 2: Skip SPA shells and error pages
            # ══════════════════════════════════════════════════════════════
            if self._is_error_or_spa_page(body, content_type):
                return None
            
            # ══════════════════════════════════════════════════════════════
            # FIX 3: Validate content matches the expected debug type
            # ══════════════════════════════════════════════════════════════
            if not self._is_valid_debug_content(body, name, endpoint, content_type):
                return None
            
            # Determine severity based on endpoint type
            severity = self._determine_endpoint_severity(endpoint, name, body)
            
            # Create evidence with content preview
            content_preview = body[:500] + '...' if len(body) > 500 else body
            
            return self.create_vulnerability(
                vuln_type=f"Debug Endpoint Exposed: {name}",
                severity=severity,
                url=url,
                evidence=f"{name} is accessible.\n\nContent preview:\n{content_preview}",
                description=self._get_endpoint_description(name, endpoint),
                cwe_id="CWE-489",
                cvss_score=self._severity_to_cvss(severity),
                remediation=self._get_endpoint_remediation(name, endpoint),
                references=self._get_endpoint_references(name, endpoint)
            )
        
        return None
    
    def _is_valid_debug_content(self, body: str, name: str, endpoint: str, content_type: str) -> bool:
        """Validate the content matches expected debug endpoint type"""
        
        body_lower = body.lower()
        endpoint_lower = endpoint.lower()
        
        # ══════════════════════════════════════════════════════════════
        # FIX 4: Special handling for Prometheus metrics
        # ══════════════════════════════════════════════════════════════
        if 'metric' in endpoint_lower or 'prometheus' in endpoint_lower:
            return self._is_prometheus_metrics(body)
        
        # GraphQL endpoints
        if 'graphql' in endpoint_lower or 'graphiql' in endpoint_lower or 'playground' in endpoint_lower:
            return self._is_graphql_content(body, content_type)
        
        # Spring Actuator
        if 'actuator' in endpoint_lower:
            return self._is_actuator_content(body, endpoint)
        
        # Health/Status endpoints
        if any(x in endpoint_lower for x in ['/health', '/status', '/ready', '/live']):
            return self._is_health_content(body, content_type)
        
        # PHP Info
        if 'phpinfo' in endpoint_lower or 'info.php' in endpoint_lower:
            return 'php version' in body_lower or 'configuration' in body_lower
        
        # Swagger/OpenAPI
        if 'swagger' in endpoint_lower or 'api-docs' in endpoint_lower or 'openapi' in endpoint_lower:
            return self._is_swagger_content(body, content_type)
        
        # Server status pages
        if 'server-status' in endpoint_lower or 'server-info' in endpoint_lower:
            return 'apache' in body_lower or 'server' in body_lower
        
        if 'nginx_status' in endpoint_lower:
            return 'active connections' in body_lower or 'nginx' in body_lower
        
        # Debug toolbars
        if 'debug' in endpoint_lower or 'profiler' in endpoint_lower or 'debugbar' in endpoint_lower:
            return self._is_debug_toolbar_content(body)
        
        # Default: Check for general debug keywords
        debug_keywords = [
            'debug', 'profiler', 'stack', 'trace', 'exception',
            'error', 'dump', 'variable', 'environment', 'config',
            'database', 'query', 'request', 'session', 'version',
            'build', 'status', 'health', 'info'
        ]
        
        return any(kw in body_lower for kw in debug_keywords)
    
    def _is_prometheus_metrics(self, body: str) -> bool:
        """Check if body contains Prometheus metrics format"""
        
        # Prometheus metrics have a specific format
        # Lines starting with # HELP, # TYPE, or metric_name{labels} value
        
        lines = body.strip().split('\n')
        metric_line_count = 0
        
        for line in lines[:50]:  # Check first 50 lines
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Comment lines (HELP, TYPE)
            if line.startswith('# HELP ') or line.startswith('# TYPE '):
                metric_line_count += 1
                continue
            
            # Skip other comments
            if line.startswith('#'):
                continue
            
            # Metric line: metric_name{labels} value or metric_name value
            # Pattern: word characters, optionally {labels}, then space and number
            for pattern in self.PROMETHEUS_PATTERNS:
                if re.match(pattern, line, re.MULTILINE):
                    metric_line_count += 1
                    break
            else:
                # Also check simple format: metric_name value
                if re.match(r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})?\s+[\d.eE+-]+', line):
                    metric_line_count += 1
        
        # If we found several metric-like lines, it's likely Prometheus format
        return metric_line_count >= 3
    
    def _is_graphql_content(self, body: str, content_type: str) -> bool:
        """Check if content is GraphQL related"""
        body_lower = body.lower()
        
        # GraphiQL/Playground HTML
        if 'text/html' in content_type:
            graphql_indicators = [
                'graphiql', 'graphql playground', 'graphql-playground',
                'altair', 'graphql ide', 'graphql.js', 'react-graphql'
            ]
            return any(ind in body_lower for ind in graphql_indicators)
        
        # GraphQL JSON response
        if 'application/json' in content_type:
            return '"__schema"' in body or '"queryType"' in body or '"data"' in body
        
        return 'graphql' in body_lower
    
    def _is_actuator_content(self, body: str, endpoint: str) -> bool:
        """Check if content is Spring Actuator format"""
        body_lower = body.lower()
        
        # Health endpoint
        if '/health' in endpoint:
            return '"status"' in body_lower and ('up' in body_lower or 'down' in body_lower)
        
        # Env endpoint
        if '/env' in endpoint:
            return '"propertysources"' in body_lower or '"property"' in body_lower
        
        # Mappings endpoint
        if '/mappings' in endpoint:
            return '"dispatcherservlets"' in body_lower or '"mappings"' in body_lower
        
        # Generic actuator response (JSON with _links)
        if '"_links"' in body_lower:
            return True
        
        return 'actuator' in body_lower or 'springframework' in body_lower
    
    def _is_health_content(self, body: str, content_type: str) -> bool:
        """Check if content is health check response"""
        body_lower = body.lower()
        
        # JSON health response
        health_indicators = [
            '"status"', '"health"', '"alive"', '"ready"',
            '"ok"', '"up"', '"down"', '"healthy"', '"unhealthy"'
        ]
        
        if any(ind in body_lower for ind in health_indicators):
            return True
        
        # Simple text response
        simple_responses = ['ok', 'healthy', 'alive', 'ready', 'up']
        body_stripped = body.strip().lower()
        if body_stripped in simple_responses:
            return True
        
        return False
    
    def _is_swagger_content(self, body: str, content_type: str) -> bool:
        """Check if content is Swagger/OpenAPI"""
        body_lower = body.lower()
        
        # Swagger UI HTML
        if 'text/html' in content_type:
            return 'swagger' in body_lower or 'openapi' in body_lower
        
        # OpenAPI JSON/YAML
        swagger_indicators = [
            '"swagger"', '"openapi"', '"paths"', '"info"',
            'swagger:', 'openapi:', 'paths:'
        ]
        
        return any(ind in body_lower for ind in swagger_indicators)
    
    def _is_debug_toolbar_content(self, body: str) -> bool:
        """Check if content is from a debug toolbar"""
        body_lower = body.lower()
        
        debug_indicators = [
            'debug toolbar', 'debugbar', 'profiler',
            'queries', 'timeline', 'request', 'response',
            'memory', 'time', 'dump', 'variables',
            'django debug', 'laravel debugbar', 'symfony profiler'
        ]
        
        return any(ind in body_lower for ind in debug_indicators)
    
    def _is_error_or_spa_page(self, body: str, content_type: str) -> bool:
        """Check if response is an error page or SPA shell"""
        if not body:
            return True
        
        body_lower = body.lower().strip()
        
        # Too short
        if len(body_lower) < self.MIN_CONTENT_LENGTH:
            return True
        
        # SPA shell detection
        spa_indicators = [
            '<app-root></app-root>',
            '<div id="root"></div>',
            '<div id="app"></div>',
        ]
        
        for indicator in spa_indicators:
            if indicator.lower() in body_lower:
                # Check if there's actual content
                text_without_tags = re.sub(r'<[^>]+>', '', body)
                if len(text_without_tags.strip()) < 100:
                    return True
        
        # Error page detection (only for HTML)
        if 'text/html' in content_type.lower():
            error_indicators = [
                '<title>404', '<title>error', '<title>not found',
                'page not found', 'file not found', '404 not found'
            ]
            if any(err in body_lower for err in error_indicators):
                return True
        
        return False
    
    def _determine_endpoint_severity(self, endpoint: str, name: str, body: str) -> Severity:
        """Determine severity based on endpoint type and content"""
        endpoint_lower = endpoint.lower()
        body_lower = body.lower()
        
        # Critical: Sensitive actuator endpoints, heap dumps, env vars
        critical_endpoints = [
            '/actuator/env', '/actuator/heapdump', '/actuator/threaddump',
            '/actuator/configprops', '/debug/pprof', '/trace.axd'
        ]
        if any(ep in endpoint_lower for ep in critical_endpoints):
            return Severity.CRITICAL
        
        # Critical if contains sensitive data
        sensitive_patterns = ['password', 'secret', 'api_key', 'apikey', 'token', 'credential']
        if any(pat in body_lower for pat in sensitive_patterns):
            return Severity.CRITICAL
        
        # High: Metrics, GraphQL with introspection, PHP info
        high_endpoints = [
            '/metrics', '/prometheus', '/graphql', '/graphiql',
            '/phpinfo', '/actuator', '/elmah.axd', '/__debug__'
        ]
        if any(ep in endpoint_lower for ep in high_endpoints):
            return Severity.HIGH
        
        # Medium: Health, status, swagger
        medium_endpoints = [
            '/health', '/status', '/swagger', '/api-docs', '/server-status'
        ]
        if any(ep in endpoint_lower for ep in medium_endpoints):
            return Severity.MEDIUM
        
        # Default
        return Severity.MEDIUM
    
    def _get_endpoint_description(self, name: str, endpoint: str) -> str:
        """Get description based on endpoint type"""
        descriptions = {
            'Prometheus': "Prometheus metrics endpoint is exposed, revealing detailed application metrics, performance data, and potentially sensitive operational information.",
            'Actuator': "Spring Boot Actuator endpoint is exposed, which may reveal sensitive application configuration, environment variables, and internal state.",
            'GraphQL': "GraphQL endpoint is exposed. If introspection is enabled, attackers can discover the entire API schema.",
            'PHP Info': "PHP info page is exposed, revealing detailed server configuration, installed modules, and environment variables.",
            'Swagger': "Swagger/OpenAPI documentation is exposed, revealing the complete API structure and endpoints.",
            'Debug': "Debug endpoint is exposed, which may reveal sensitive application internals and aid attackers.",
        }
        
        for key, desc in descriptions.items():
            if key.lower() in name.lower() or key.lower() in endpoint.lower():
                return desc
        
        return f"The debug/monitoring endpoint '{name}' is exposed and accessible. This may leak sensitive information about the application."
    
    def _get_endpoint_remediation(self, name: str, endpoint: str) -> str:
        """Get remediation advice based on endpoint type"""
        
        if 'metric' in endpoint.lower() or 'prometheus' in endpoint.lower():
            return """1. Restrict access to /metrics endpoint using authentication
2. Use network-level controls (firewall, internal network only)
3. Configure Prometheus to scrape from internal endpoints only
4. Consider using Prometheus push gateway for external access
5. Filter sensitive metrics before exposure"""
        
        if 'actuator' in endpoint.lower():
            return """1. Disable unnecessary actuator endpoints in production:
   management.endpoints.web.exposure.exclude=env,heapdump,threaddump
2. Require authentication for actuator endpoints:
   management.endpoint.health.show-details=when_authorized
3. Use a separate management port accessible only internally
4. Configure Spring Security to protect actuator endpoints"""
        
        if 'graphql' in endpoint.lower():
            return """1. Disable GraphQL introspection in production:
   graphql.introspection.enabled=false
2. Implement authentication and authorization
3. Use query complexity analysis to prevent DoS
4. Implement rate limiting
5. Remove GraphiQL/Playground in production"""
        
        return """1. Disable debug endpoints in production
2. Implement authentication for administrative endpoints
3. Use network segmentation to restrict access
4. Configure web server to block debug paths
5. Monitor access to these endpoints"""
    
    def _get_endpoint_references(self, name: str, endpoint: str) -> List[str]:
        """Get references based on endpoint type"""
        
        refs = [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
        ]
        
        if 'metric' in endpoint.lower() or 'prometheus' in endpoint.lower():
            refs.append("https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config")
        
        if 'actuator' in endpoint.lower():
            refs.append("https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security")
        
        if 'graphql' in endpoint.lower():
            refs.append("https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html")
        
        return refs
    
    def _severity_to_cvss(self, severity: Severity) -> float:
        """Convert severity to CVSS score"""
        mapping = {
            Severity.CRITICAL: 9.1,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 3.1,
            Severity.INFO: 0.0
        }
        return mapping.get(severity, 5.0)
    
    async def _trigger_errors(self, session: aiohttp.ClientSession,
                               url: str, params: Dict[str, str]) -> Optional[Vulnerability]:
        """Try to trigger error messages"""
        
        for trigger, trigger_name in self.ERROR_TRIGGERS:
            for param_name in params:
                test_params = params.copy()
                test_params[param_name] = trigger
                
                response = await self.make_request(session, "GET", url, params=test_params)
                if not response:
                    continue
                
                body = await response.text()
                
                # Skip empty responses
                if not body or len(body.strip()) < self.MIN_CONTENT_LENGTH:
                    continue
                
                for pattern, debug_name in self.DEBUG_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        return self.create_vulnerability(
                            vuln_type=f"Debug Information Disclosure: {debug_name}",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param_name,
                            payload=trigger,
                            evidence=f"Debug pattern '{debug_name}' found in error response",
                            description="The application exposes detailed debug information in error responses, which may help attackers understand the system.",
                            cwe_id="CWE-209",
                            cvss_score=5.3,
                            remediation="Disable debug mode in production. Implement custom error pages that don't expose technical details.",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"
                            ]
                        )
        
        return None
    
    async def _check_page_debug(self, session: aiohttp.ClientSession,
                                 url: str) -> Optional[Vulnerability]:
        """Check the main page for debug indicators"""
        
        response = await self.make_request(session, "GET", url)
        if not response:
            return None
        
        body = await response.text()
        
        # Skip empty responses
        if not body or len(body.strip()) < self.MIN_CONTENT_LENGTH:
            return None
        
        for pattern, debug_name in self.DEBUG_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return self.create_vulnerability(
                    vuln_type=f"Debug Mode Indicator: {debug_name}",
                    severity=Severity.LOW,
                    url=url,
                    evidence=f"Debug indicator '{debug_name}' found on page",
                    description="The page contains debug mode indicators, suggesting the application may be running in development mode.",
                    cwe_id="CWE-489",
                    cvss_score=3.1,
                    remediation="Ensure the application is running in production mode with debug features disabled.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
                    ]
                )
        
        return None