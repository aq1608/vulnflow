# scanner/api_security/graphql.py
"""
GraphQL Security Scanner

Detects GraphQL-specific vulnerabilities:
- Introspection enabled
- Query depth/complexity attacks
- Batching attacks
- Field suggestions (information disclosure)
- Authorization bypass

OWASP API Security Top 10
"""

import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class GraphQLScanner(BaseScanner):
    """Scanner for GraphQL-specific vulnerabilities"""

    name="GraphQL Security Scanner",
    description="Detects GraphQL API security vulnerabilities",
    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION

    def __init__(self):
        
        # Common GraphQL endpoints
        self.graphql_endpoints = [
            "/graphql",
            "/graphiql",
            "/api/graphql",
            "/api/v1/graphql",
            "/v1/graphql",
            "/gql",
            "/query",
            "/api/query",
        ]
        
        # Introspection query
        self.introspection_query = """
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
                queryType { name }
                mutationType { name }
            }
        }
        """
        
        # Simpler introspection
        self.simple_introspection = """
        query { __schema { types { name } } }
        """
        
        # Query for field suggestions
        self.field_suggestion_query = """
        query { __type(name: "Query") { fields { name } } }
        """
    
    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None
    ) -> List[Vulnerability]:
        """Scan for GraphQL vulnerabilities"""
        vulnerabilities = []
        
        # Find GraphQL endpoint
        graphql_url = await self._find_graphql_endpoint(session, url)
        
        if not graphql_url:
            return vulnerabilities
        
        # Test introspection
        intro_vuln = await self._test_introspection(session, graphql_url)
        if intro_vuln:
            vulnerabilities.append(intro_vuln)
        
        # Test query depth attack
        depth_vuln = await self._test_query_depth(session, graphql_url)
        if depth_vuln:
            vulnerabilities.append(depth_vuln)
        
        # Test batching attack
        batch_vuln = await self._test_batching(session, graphql_url)
        if batch_vuln:
            vulnerabilities.append(batch_vuln)
        
        # Test field suggestions
        suggestion_vuln = await self._test_field_suggestions(session, graphql_url)
        if suggestion_vuln:
            vulnerabilities.append(suggestion_vuln)
        
        # Test debug mode
        debug_vuln = await self._test_debug_mode(session, graphql_url)
        if debug_vuln:
            vulnerabilities.append(debug_vuln)
        
        return vulnerabilities
# scanner/api_security/graphql.py (continued)
    
    async def _find_graphql_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[str]:
        """Find the GraphQL endpoint"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in self.graphql_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            try:
                # Test with simple query
                test_query = {"query": "{ __typename }"}
                
                async with session.post(
                    test_url,
                    json=test_query,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            # Valid GraphQL response
                            if "data" in data or "errors" in data:
                                return test_url
                        except:
                            pass
                
                # Also try GET method
                async with session.get(
                    test_url,
                    params={"query": "{ __typename }"},
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            if "data" in data or "errors" in data:
                                return test_url
                        except:
                            pass
            
            except Exception:
                continue
        
        return None
    
    async def _test_introspection(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test if introspection is enabled"""
        try:
            query = {"query": self.introspection_query}
            
            async with session.post(
                url,
                json=query,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                data = await response.json()
                
                if "data" in data and data["data"].get("__schema"):
                    schema = data["data"]["__schema"]
                    types_count = len(schema.get("types", []))
                    
                    # Extract some type names as evidence
                    type_names = [t["name"] for t in schema.get("types", [])[:10]]
                    
                    return Vulnerability(
                        vuln_type="GraphQL Introspection Enabled",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="GraphQL Query",
                        payload="Introspection Query",
                        evidence=f"Schema exposed with {types_count} types: {', '.join(type_names[:5])}...",
                        description="GraphQL introspection is enabled, exposing the entire API schema",
                        cwe_id="CWE-200",
                        remediation="Disable introspection in production. Use allowlisting for permitted queries."
                    )
        
        except Exception:
            pass
        
        return None
    
    async def _test_query_depth(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test for query depth attack vulnerability"""
        # Create a deeply nested query
        deep_query = "{ __typename "
        for i in range(20):
            deep_query += "... on Query { __typename "
        deep_query += "}" * 21
        
        # Alternative: nested fragments
        nested_query = """
        query DeepQuery {
            __schema {
                types {
                    fields {
                        type {
                            fields {
                                type {
                                    fields {
                                        type {
                                            name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        try:
            async with session.post(
                url,
                json={"query": nested_query},
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as response:
                data = await response.json()
                
                # If query succeeds without depth limiting
                if "data" in data and not data.get("errors"):
                    return Vulnerability(
                        vuln_type="GraphQL Query Depth Attack",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="GraphQL Query",
                        payload="Deeply nested query (20+ levels)",
                        evidence="Server accepted deeply nested query without limits",
                        description="GraphQL endpoint lacks query depth limiting, enabling DoS attacks",
                        cwe_id="CWE-770",
                        remediation="Implement query depth limiting. Use graphql-depth-limit or similar."
                    )
                
                # Check if errors mention depth but still processed
                errors = data.get("errors", [])
                for error in errors:
                    msg = error.get("message", "").lower()
                    if "depth" not in msg and "complexity" not in msg:
                        # Query failed but not due to depth limits
                        pass
        
        except asyncio.TimeoutError:
            # Timeout might indicate DoS vulnerability
            return Vulnerability(
                vuln_type="GraphQL Query Complexity DoS",
                severity=Severity.HIGH,
                url=url,
                parameter="GraphQL Query",
                payload="Complex nested query",
                evidence="Server timed out processing complex query",
                description="GraphQL endpoint vulnerable to complexity-based DoS attacks",
                cwe_id="CWE-400",
                remediation="Implement query complexity analysis and limits."
            )
        except Exception:
            pass
        
        return None
    
    async def _test_batching(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test for query batching attacks"""
        # Batch multiple queries
        batch_queries = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ] * 20  # 100 queries
        
        try:
            async with session.post(
                url,
                json=batch_queries,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if isinstance(data, list) and len(data) >= 50:
                        return Vulnerability(
                            vuln_type="GraphQL Batching Attack",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="GraphQL Query Batch",
                            payload=f"Batch of {len(batch_queries)} queries",
                            evidence=f"Server processed {len(data)} batched queries",
                            description="GraphQL endpoint allows unlimited query batching, enabling brute force and DoS",
                            cwe_id="CWE-770",
                            remediation="Limit the number of queries per batch. Implement rate limiting per operation."
                        )
        
        except Exception:
            pass
        
        return None
    
    async def _test_field_suggestions(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test for field suggestion information disclosure"""
        # Query with intentional typo
        typo_queries = [
            '{ usrs { id } }',      # users typo
            '{ pasword }',           # password typo
            '{ admn }',              # admin typo
            '{ secrt }',             # secret typo
        ]
        
        for query in typo_queries:
            try:
                async with session.post(
                    url,
                    json={"query": query},
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    data = await response.json()
                    
                    errors = data.get("errors", [])
                    for error in errors:
                        msg = error.get("message", "")
                        
                        # Check for "Did you mean" suggestions
                        if "did you mean" in msg.lower() or "perhaps you meant" in msg.lower():
                            return Vulnerability(
                                vuln_type="GraphQL Field Suggestions",
                                severity=Severity.LOW,
                                url=url,
                                parameter="GraphQL Query",
                                payload=query,
                                evidence=msg[:200],
                                description="GraphQL provides field suggestions, leaking schema information",
                                cwe_id="CWE-200",
                                remediation="Disable field suggestions in production or use custom error messages."
                            )
            
            except Exception:
                continue
        
        return None
    
    async def _test_debug_mode(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Vulnerability]:
        """Test for debug mode / stack traces"""
        # Send malformed query to trigger error
        bad_queries = [
            '{ __typename { }',  # Syntax error
            'query { undefined_field_xyz }',
            '{ ... on NonExistentType { id } }',
        ]
        
        for query in bad_queries:
            try:
                async with session.post(
                    url,
                    json={"query": query},
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    text = await response.text()
                    
                    # Check for stack traces or debug info
                    debug_indicators = [
                        r"at\s+[\w.]+\s*\(",        # Stack trace
                        r"File\s+\"[^\"]+\",\s+line\s+\d+",  # Python traceback
                        r"\.js:\d+:\d+",             # JavaScript stack
                        r"node_modules",
                        r"internal/",
                        r"DEBUG",
                        r"stack.*trace",
                    ]
                    
                    for pattern in debug_indicators:
                        if re.search(pattern, text, re.IGNORECASE):
                            return Vulnerability(
                                vuln_type="GraphQL Debug Mode Enabled",
                                severity=Severity.LOW,
                                url=url,
                                parameter="GraphQL Query",
                                payload=query[:50],
                                evidence=text[:200],
                                description="GraphQL endpoint exposes debug information or stack traces",
                                cwe_id="CWE-209",
                                remediation="Disable debug mode in production. Use custom error handlers."
                            )
            
            except Exception:
                continue
        
        return None