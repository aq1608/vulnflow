# reports/generator.py
"""
VulnFlow Report Generator

Generates security scan reports in HTML, JSON, and SARIF formats.
Updated for OWASP Top 10 2025 with HTTP Traffic Capture (ZAP-style).
"""

from typing import List, Dict, Optional
from datetime import datetime
import json
import html
import re
from enum import Enum


# OWASP 2025 Category Information for Reports - ENHANCED WITH CWE MAPPINGS
OWASP_2025_CATEGORIES = {
    "A01:2025 - Broken Access Control": {
        "id": "A01",
        "name": "Broken Access Control",
        "short": "Access Control",
        "color": "#dc3545",
        "description": "Failures in access control enforcement, allowing users to act outside intended permissions. Now includes SSRF.",
        "url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
        "key_cwes": ["CWE-200", "CWE-201", "CWE-352", "CWE-639", "CWE-862", "CWE-863", "CWE-918"],
        "total_cwes": 40,
        "key_changes": "Absorbs SSRF (previously A10:2021). Highest occurrence in data."
    },
    "A02:2025 - Security Misconfiguration": {
        "id": "A02",
        "name": "Security Misconfiguration",
        "short": "Misconfiguration",
        "color": "#fd7e14",
        "description": "Missing security hardening, default credentials, overly permissive cloud settings, verbose errors.",
        "url": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
        "key_cwes": ["CWE-16", "CWE-611", "CWE-489", "CWE-942", "CWE-1004"],
        "total_cwes": 16,
        "key_changes": "Moved UP from #5. Now covers cloud/infrastructure misconfigurations. XXE (CWE-611) included here."
    },
    "A03:2025 - Software Supply Chain Failures": {
        "id": "A03",
        "name": "Software Supply Chain Failures",
        "short": "Supply Chain",
        "color": "#e83e8c",
        "description": "Vulnerabilities in dependencies, CI/CD pipelines, and software components. Expanded beyond just outdated components.",
        "url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
        "key_cwes": ["CWE-1104", "CWE-1395", "CWE-1329", "CWE-477"],
        "total_cwes": 6,
        "key_changes": "RENAMED from 'Vulnerable and Outdated Components'. Now covers entire supply chain including CI/CD, SBOM, build pipelines."
    },
    "A04:2025 - Cryptographic Failures": {
        "id": "A04",
        "name": "Cryptographic Failures",
        "short": "Crypto Failures",
        "color": "#6f42c1",
        "description": "Weak cryptography, missing encryption, poor key management, deprecated algorithms.",
        "url": "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
        "key_cwes": ["CWE-327", "CWE-331", "CWE-338", "CWE-326", "CWE-916"],
        "total_cwes": 32,
        "key_changes": "Moved DOWN from #2. Focus on weak PRNG, broken algorithms, post-quantum readiness."
    },
    "A05:2025 - Injection": {
        "id": "A05",
        "name": "Injection",
        "short": "Injection",
        "color": "#d63384",
        "description": "SQL, NoSQL, OS command, LDAP, XPath injection and XSS. Untrusted data sent to interpreters.",
        "url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
        "key_cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-917"],
        "total_cwes": 37,
        "key_changes": "Moved DOWN from #3. XSS now explicitly included. Highest CVE count (62,445). LLM prompt injection mentioned separately."
    },
    "A06:2025 - Insecure Design": {
        "id": "A06",
        "name": "Insecure Design",
        "short": "Insecure Design",
        "color": "#20c997",
        "description": "Missing or ineffective security controls, architectural flaws, business logic vulnerabilities.",
        "url": "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
        "key_cwes": ["CWE-256", "CWE-269", "CWE-434", "CWE-501", "CWE-522"],
        "total_cwes": 39,
        "key_changes": "Moved DOWN from #4. Focus on threat modeling, secure design patterns, SDLC."
    },
    "A07:2025 - Authentication Failures": {
        "id": "A07",
        "name": "Authentication Failures",
        "short": "Auth Failures",
        "color": "#0dcaf0",
        "description": "Weaknesses in authentication, session management, credential handling, and identity verification.",
        "url": "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
        "key_cwes": ["CWE-259", "CWE-287", "CWE-384", "CWE-798", "CWE-1392"],
        "total_cwes": 36,
        "key_changes": "Slight name change. Now includes hybrid password spray attacks, MFA bypass, breached credential checks."
    },
    "A08:2025 - Software or Data Integrity Failures": {
        "id": "A08",
        "name": "Software or Data Integrity Failures",
        "short": "Integrity Failures",
        "color": "#198754",
        "description": "Code and infrastructure without integrity verification, insecure deserialization, unsigned updates.",
        "url": "https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/",
        "key_cwes": ["CWE-502", "CWE-829", "CWE-915", "CWE-494", "CWE-345"],
        "total_cwes": 14,
        "key_changes": "Clarifying name change. Focuses on trust boundaries, unsigned code, CDN integrity (SRI)."
    },
    "A09:2025 - Security Logging and Alerting Failures": {
        "id": "A09",
        "name": "Security Logging and Alerting Failures",
        "short": "Logging Failures",
        "color": "#6c757d",
        "description": "Insufficient logging, monitoring, and alerting. Failure to detect and respond to attacks.",
        "url": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
        "key_cwes": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "total_cwes": 5,
        "key_changes": "RENAMED to emphasize 'Alerting'. Focus on actionable alerts, not just logging."
    },
    "A10:2025 - Mishandling of Exceptional Conditions": {
        "id": "A10",
        "name": "Mishandling of Exceptional Conditions",
        "short": "Exceptional Conditions",
        "color": "#ffc107",
        "description": "Systems that fail open, improper error handling, resource exhaustion, unhandled exceptions.",
        "url": "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
        "key_cwes": ["CWE-209", "CWE-476", "CWE-636", "CWE-754", "CWE-755"],
        "total_cwes": 24,
        "key_changes": "🆕 NEW CATEGORY replacing SSRF. Focuses on fail-open, error handling, resource limits, state corruption."
    },
    "Other": {
        "id": "Other",
        "name": "Other",
        "short": "Other",
        "color": "#adb5bd",
        "description": "Vulnerabilities not directly mapped to OWASP Top 10 2025",
        "url": "https://owasp.org/Top10/",
        "key_cwes": [],
        "total_cwes": 0,
        "key_changes": ""
    }
}

# Legacy OWASP 2021 to 2025 mapping for backward compatibility
OWASP_2021_TO_2025_MAPPING = {
    "A01:2021 - Broken Access Control": "A01:2025 - Broken Access Control",
    "A02:2021 - Cryptographic Failures": "A04:2025 - Cryptographic Failures",
    "A03:2021 - Injection": "A05:2025 - Injection",
    "A04:2021 - Insecure Design": "A06:2025 - Insecure Design",
    "A05:2021 - Security Misconfiguration": "A02:2025 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components": "A03:2025 - Software Supply Chain Failures",
    "A07:2021 - Identification and Authentication Failures": "A07:2025 - Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures": "A08:2025 - Software or Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures": "A09:2025 - Security Logging and Alerting Failures",
    "A10:2021 - Server-Side Request Forgery": "A01:2025 - Broken Access Control",
}

# CWE to OWASP 2025 mapping for accurate categorization
CWE_TO_OWASP_2025 = {
    # A01 - Broken Access Control
    "CWE-22": "A01:2025 - Broken Access Control",
    "CWE-23": "A01:2025 - Broken Access Control",
    "CWE-200": "A01:2025 - Broken Access Control",
    "CWE-201": "A01:2025 - Broken Access Control",
    "CWE-352": "A01:2025 - Broken Access Control",
    "CWE-425": "A01:2025 - Broken Access Control",
    "CWE-601": "A01:2025 - Broken Access Control",
    "CWE-639": "A01:2025 - Broken Access Control",
    "CWE-862": "A01:2025 - Broken Access Control",
    "CWE-863": "A01:2025 - Broken Access Control",
    "CWE-918": "A01:2025 - Broken Access Control",
    
    # A02 - Security Misconfiguration
    "CWE-16": "A02:2025 - Security Misconfiguration",
    "CWE-489": "A02:2025 - Security Misconfiguration",
    "CWE-611": "A02:2025 - Security Misconfiguration",
    "CWE-614": "A02:2025 - Security Misconfiguration",
    "CWE-942": "A02:2025 - Security Misconfiguration",
    "CWE-1004": "A02:2025 - Security Misconfiguration",
    
    # A03 - Software Supply Chain Failures
    "CWE-477": "A03:2025 - Software Supply Chain Failures",
    "CWE-1104": "A03:2025 - Software Supply Chain Failures",
    "CWE-1329": "A03:2025 - Software Supply Chain Failures",
    "CWE-1395": "A03:2025 - Software Supply Chain Failures",
    
    # A04 - Cryptographic Failures
    "CWE-261": "A04:2025 - Cryptographic Failures",
    "CWE-319": "A04:2025 - Cryptographic Failures",
    "CWE-326": "A04:2025 - Cryptographic Failures",
    "CWE-327": "A04:2025 - Cryptographic Failures",
    "CWE-328": "A04:2025 - Cryptographic Failures",
    "CWE-330": "A04:2025 - Cryptographic Failures",
    "CWE-331": "A04:2025 - Cryptographic Failures",
    "CWE-338": "A04:2025 - Cryptographic Failures",
    "CWE-916": "A04:2025 - Cryptographic Failures",
    
    # A05 - Injection
    "CWE-77": "A05:2025 - Injection",
    "CWE-78": "A05:2025 - Injection",
    "CWE-79": "A05:2025 - Injection",
    "CWE-89": "A05:2025 - Injection",
    "CWE-90": "A05:2025 - Injection",
    "CWE-94": "A05:2025 - Injection",
    "CWE-643": "A05:2025 - Injection",
    "CWE-917": "A05:2025 - Injection",
    
    # A06 - Insecure Design
    "CWE-256": "A06:2025 - Insecure Design",
    "CWE-269": "A06:2025 - Insecure Design",
    "CWE-434": "A06:2025 - Insecure Design",
    "CWE-501": "A06:2025 - Insecure Design",
    "CWE-522": "A06:2025 - Insecure Design",
    "CWE-799": "A06:2025 - Insecure Design",
    
    # A07 - Authentication Failures
    "CWE-259": "A07:2025 - Authentication Failures",
    "CWE-287": "A07:2025 - Authentication Failures",
    "CWE-307": "A07:2025 - Authentication Failures",
    "CWE-384": "A07:2025 - Authentication Failures",
    "CWE-613": "A07:2025 - Authentication Failures",
    "CWE-798": "A07:2025 - Authentication Failures",
    "CWE-1392": "A07:2025 - Authentication Failures",
    
    # A08 - Software or Data Integrity Failures
    "CWE-345": "A08:2025 - Software or Data Integrity Failures",
    "CWE-494": "A08:2025 - Software or Data Integrity Failures",
    "CWE-502": "A08:2025 - Software or Data Integrity Failures",
    "CWE-829": "A08:2025 - Software or Data Integrity Failures",
    "CWE-915": "A08:2025 - Software or Data Integrity Failures",
    
    # A09 - Security Logging and Alerting Failures
    "CWE-117": "A09:2025 - Security Logging and Alerting Failures",
    "CWE-223": "A09:2025 - Security Logging and Alerting Failures",
    "CWE-532": "A09:2025 - Security Logging and Alerting Failures",
    "CWE-778": "A09:2025 - Security Logging and Alerting Failures",
    
    # A10 - Mishandling of Exceptional Conditions
    "CWE-209": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-248": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-252": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-391": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-476": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-636": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-754": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-755": "A10:2025 - Mishandling of Exceptional Conditions",
    "CWE-756": "A10:2025 - Mishandling of Exceptional Conditions",
}


class ReportGenerator:
    """Generate security scan reports in various formats with HTTP traffic capture"""
    
    def __init__(self):
        self.owasp_categories = OWASP_2025_CATEGORIES
        self.legacy_mapping = OWASP_2021_TO_2025_MAPPING
        self.cwe_mapping = CWE_TO_OWASP_2025
    
    def _normalize_owasp_category(self, category_value: str) -> str:
        """Normalize OWASP category to 2025 format."""
        if not category_value:
            return "Other"
        
        if "2025" in category_value:
            return category_value
        
        if "2021" in category_value:
            return self.legacy_mapping.get(category_value, "Other")
        
        category_lower = category_value.lower()
        for cat_key in self.owasp_categories:
            if self.owasp_categories[cat_key]["name"].lower() in category_lower:
                return cat_key
        
        return "Other"
    
    def _get_owasp_from_cwe(self, cwe_id: str) -> str:
        """Get OWASP 2025 category from CWE ID."""
        if not cwe_id:
            return "Other"
        
        cwe_normalized = cwe_id.upper()
        if not cwe_normalized.startswith("CWE-"):
            cwe_normalized = f"CWE-{cwe_normalized}"
        
        return self.cwe_mapping.get(cwe_normalized, "Other")
    
    def _get_owasp_category_info(self, category_value: str) -> Dict:
        """Get OWASP category information."""
        normalized = self._normalize_owasp_category(category_value)
        return self.owasp_categories.get(normalized, self.owasp_categories["Other"])
    
    def _generate_owasp_summary(self, scan_results: Dict) -> Dict:
        """Generate summary by OWASP category."""
        vulns = scan_results.get("vulnerabilities", [])
        owasp_summary = {}
        
        for cat_key in self.owasp_categories:
            owasp_summary[cat_key] = {
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                **self.owasp_categories[cat_key]
            }
        
        for vuln in vulns:
            owasp_cat = getattr(vuln, 'owasp_category', None)
            
            if owasp_cat:
                cat_value = owasp_cat.value if hasattr(owasp_cat, 'value') else str(owasp_cat)
            else:
                cwe_id = getattr(vuln, 'cwe_id', None)
                if cwe_id:
                    cat_value = self._get_owasp_from_cwe(cwe_id)
                else:
                    cat_value = "Other"
            
            normalized_cat = self._normalize_owasp_category(cat_value)
            
            if normalized_cat in owasp_summary:
                owasp_summary[normalized_cat]["count"] += 1
                
                severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                if severity in owasp_summary[normalized_cat]:
                    owasp_summary[normalized_cat][severity] += 1
        
        return {k: v for k, v in owasp_summary.items() if v["count"] > 0}
    
    def _get_css_styles(self) -> str:
        """Get all CSS styles including HTTP traffic display"""
        return '''
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
                   color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .owasp-badge { display: inline-block; background: rgba(255,255,255,0.2); 
                               padding: 5px 12px; border-radius: 15px; font-size: 0.85em; 
                               margin-top: 10px; }
        
        /* Severity Summary */
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
                    gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; 
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center;
                        cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        .summary-card:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.15); }
        .summary-card.critical { border-left: 4px solid #dc3545; }
        .summary-card.high { border-left: 4px solid #fd7e14; }
        .summary-card.medium { border-left: 4px solid #ffc107; }
        .summary-card.low { border-left: 4px solid #17a2b8; }
        .summary-card .count { font-size: 2.5em; font-weight: bold; }
        
        /* OWASP Summary Section */
        .owasp-summary { background: white; padding: 25px; border-radius: 10px; 
                         box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .owasp-summary h2 { margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
        .owasp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; }
        .owasp-card { background: #f8f9fa; padding: 15px; border-radius: 8px; 
                      border-left: 4px solid var(--owasp-color, #6c757d);
                      cursor: pointer; transition: all 0.2s; }
        .owasp-card:hover { background: #e9ecef; transform: translateX(5px); }
        .owasp-card-header { display: flex; justify-content: space-between; align-items: center; }
        .owasp-card-id { font-weight: bold; font-size: 1.1em; color: var(--owasp-color, #333); }
        .owasp-card-count { background: var(--owasp-color, #6c757d); color: white; 
                            padding: 3px 10px; border-radius: 12px; font-size: 0.9em; font-weight: bold; }
        .owasp-card-name { font-size: 0.9em; color: #666; margin-top: 5px; }
        .owasp-card-breakdown { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
        .owasp-card-breakdown span { font-size: 0.75em; padding: 2px 8px; border-radius: 10px; }
        .owasp-card-breakdown .critical { background: #dc3545; color: white; }
        .owasp-card-breakdown .high { background: #fd7e14; color: white; }
        .owasp-card-breakdown .medium { background: #ffc107; color: #333; }
        .owasp-card-breakdown .low { background: #17a2b8; color: white; }
        
        /* Controls Section */
        .controls { background: white; padding: 20px; border-radius: 10px; 
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px;
                     display: flex; flex-wrap: wrap; gap: 15px; align-items: center; }
        .search-box { flex: 1; min-width: 250px; }
        .search-box input { width: 100%; padding: 10px 15px; border: 2px solid #e0e0e0;
                            border-radius: 8px; font-size: 14px; transition: border-color 0.2s; }
        .search-box input:focus { outline: none; border-color: #1a1a2e; }
        .filter-group { display: flex; flex-direction: column; gap: 8px; }
        .filter-label { font-size: 12px; color: #666; font-weight: 600; text-transform: uppercase; }
        .filter-buttons { display: flex; gap: 8px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 16px; border: 2px solid #e0e0e0; background: white;
                      border-radius: 20px; cursor: pointer; font-size: 13px; font-weight: 500;
                      transition: all 0.2s; }
        .filter-btn:hover { background: #f0f0f0; }
        .filter-btn.active { background: #1a1a2e; color: white; border-color: #1a1a2e; }
        .filter-btn.critical.active { background: #dc3545; border-color: #dc3545; }
        .filter-btn.high.active { background: #fd7e14; border-color: #fd7e14; }
        .filter-btn.medium.active { background: #ffc107; border-color: #ffc107; color: #333; }
        .filter-btn.low.active { background: #17a2b8; border-color: #17a2b8; }
        
        /* OWASP Filter Dropdown */
        .owasp-filter { position: relative; }
        .owasp-filter-btn { padding: 8px 16px; border: 2px solid #e0e0e0; background: white;
                            border-radius: 20px; cursor: pointer; font-size: 13px; font-weight: 500;
                            display: flex; align-items: center; gap: 5px; }
        .owasp-filter-btn:hover { background: #f0f0f0; }
        .owasp-dropdown { display: none; position: absolute; top: 100%; left: 0; 
                          background: white; border: 1px solid #e0e0e0; border-radius: 8px;
                          box-shadow: 0 4px 15px rgba(0,0,0,0.15); z-index: 100; min-width: 250px;
                          margin-top: 5px; max-height: 300px; overflow-y: auto; }
        .owasp-dropdown.show { display: block; }
        .owasp-dropdown-item { padding: 10px 15px; cursor: pointer; border-left: 3px solid transparent;
                               display: flex; justify-content: space-between; align-items: center; }
        .owasp-dropdown-item:hover { background: #f8f9fa; }
        .owasp-dropdown-item.selected { background: #e3f2fd; border-left-color: #1a1a2e; }
        
        /* Bulk Actions */
        .bulk-actions { display: flex; gap: 10px; margin-left: auto; }
        .bulk-btn { padding: 8px 12px; background: #f8f9fa; border: 1px solid #dee2e6;
                    border-radius: 6px; cursor: pointer; font-size: 13px; transition: all 0.2s; }
        .bulk-btn:hover { background: #e9ecef; }
        
        /* Vulnerability Cards */
        .vuln-card { background: white; border-radius: 10px; 
                      margin-bottom: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                      overflow: hidden; transition: all 0.3s ease; }
        .vuln-card.hidden { display: none; }
        .vuln-card-header { display: flex; justify-content: space-between; align-items: center; 
                            padding: 20px; cursor: pointer; user-select: none;
                            transition: background 0.2s; }
        .vuln-card-header:hover { background: #f8f9fa; }
        .vuln-card-header h3 { display: flex; align-items: center; gap: 10px; font-size: 1em; 
                               flex: 1; flex-wrap: wrap; }
        .vuln-card-header .toggle-icon { transition: transform 0.3s; color: #666; }
        .vuln-card.expanded .toggle-icon { transform: rotate(180deg); }
        .vuln-card-body { max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out;
                          padding: 0 20px; }
        .vuln-card.expanded .vuln-card-body { max-height: 5000px; padding: 0 20px 20px; }
        
        .severity { padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; 
                    text-transform: uppercase; font-size: 0.75em; white-space: nowrap; }
        .severity.critical { background: #dc3545; }
        .severity.high { background: #fd7e14; }
        .severity.medium { background: #ffc107; color: #333; }
        .severity.low { background: #17a2b8; }
        .severity.info { background: #6c757d; }
        
        /* OWASP Badge */
        .owasp-badge-small { padding: 3px 10px; border-radius: 12px; font-size: 0.7em; 
                       font-weight: 600; white-space: nowrap; background: #f0f0f0; 
                       color: #333; border: 1px solid #ddd; }
        .owasp-badge-small a { color: inherit; text-decoration: none; }
        .owasp-badge-small a:hover { text-decoration: underline; }
        
        .detail { margin: 12px 0; }
        .detail-label { font-weight: bold; color: #666; font-size: 0.9em; }
        .code { background: #f8f9fa; padding: 15px; border-radius: 5px; 
                 font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; 
                 overflow-x: auto; margin: 8px 0; font-size: 13px;
                 border: 1px solid #e9ecef; white-space: pre-wrap; word-wrap: break-word; }
        
        /* Payload Box */
        .payload-box { background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px;
                       padding: 10px 15px; font-family: monospace; font-size: 13px;
                       margin: 8px 0; white-space: pre-wrap; word-wrap: break-word; }
        
        /* OWASP Detail Box */
        .owasp-detail-box { background: #f0f7ff; border: 1px solid #cce5ff; 
                            border-radius: 8px; padding: 12px; margin: 12px 0;
                            display: flex; align-items: flex-start; gap: 12px; }
        .owasp-detail-box .owasp-icon { font-size: 1.5em; }
        .owasp-detail-box .owasp-info { flex: 1; }
        .owasp-detail-box .owasp-title { font-weight: bold; color: #004085; }
        .owasp-detail-box .owasp-desc { font-size: 0.85em; color: #666; margin-top: 3px; }
        .owasp-detail-box a { color: #004085; }
        
        /* ============================================ */
        /* HTTP TRAFFIC SECTION - ZAP STYLE            */
        /* ============================================ */
        .http-traffic-section { margin-top: 15px; border: 1px solid #ddd; border-radius: 8px;
                                overflow: hidden; }
        .http-toggle { background: #f8f9fa; padding: 12px 15px; cursor: pointer;
                       display: flex; align-items: center; gap: 10px;
                       border-bottom: 1px solid #ddd; user-select: none;
                       transition: background 0.2s; }
        .http-toggle:hover { background: #e9ecef; }
        .http-toggle .toggle-icon { font-size: 12px; transition: transform 0.2s; }
        .http-toggle .toggle-icon.expanded { transform: rotate(90deg); }
        .http-toggle-hint { color: #6c757d; font-size: 12px; margin-left: auto; }
        .http-toggle-title { font-weight: 600; color: #333; }
        .http-content { display: none; background: #1e1e1e; }
        .http-content.show { display: block; }
        .http-panels { display: flex; flex-direction: column; }
        
        /* Request/Response Panels */
        .http-panel { border-bottom: 1px solid #333; }
        .http-panel:last-child { border-bottom: none; }
        .http-panel-header { background: #2d2d2d; padding: 10px 15px;
                             border-bottom: 1px solid #404040;
                             display: flex; justify-content: space-between; align-items: center; }
        .http-label { color: #fff; font-weight: 600; font-size: 13px;
                      display: flex; align-items: center; gap: 8px; }
        .http-label .icon { font-size: 14px; }
        .http-label.request { color: #61afef; }
        .http-label.response { color: #98c379; }
        .http-meta { color: #666; font-size: 11px; }
        
        .http-code { margin: 0; padding: 15px; font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                     font-size: 12px; line-height: 1.6; color: #d4d4d4; white-space: pre-wrap;
                     word-wrap: break-word; background: #1e1e1e; max-height: 400px; overflow: auto; }
        
        /* HTTP Syntax Highlighting */
        .http-method { color: #c678dd; font-weight: bold; }
        .http-url { color: #61afef; }
        .http-version { color: #56b6c2; }
        .http-status-ok { color: #98c379; font-weight: bold; }
        .http-status-redirect { color: #e5c07b; font-weight: bold; }
        .http-status-error { color: #e06c75; font-weight: bold; }
        .http-header-name { color: #e5c07b; }
        .http-header-value { color: #98c379; }
        .http-header-colon { color: #abb2bf; }
        
        /* Payload Highlighting */
        .payload-highlight { background: #e6db74; color: #1e1e1e; padding: 1px 4px;
                            border-radius: 3px; font-weight: bold; }
        .payload-marker { background: #ff6b6b; color: #fff; padding: 1px 4px;
                          border-radius: 3px; font-weight: bold; font-size: 10px; }
        
        /* Evidence Context */
        .evidence-context-section { margin-top: 15px; }
        .evidence-context-header { font-weight: bold; color: #666; font-size: 0.9em; margin-bottom: 8px;
                                   display: flex; align-items: center; gap: 8px; }
        .evidence-context-header .icon { color: #ffc107; }
        .evidence-context { background: #2d2d2d; color: #d4d4d4; border-radius: 6px;
                           padding: 15px; font-family: monospace; font-size: 12px;
                           white-space: pre-wrap; word-wrap: break-word;
                           max-height: 300px; overflow: auto; border: 1px solid #404040; }
        .evidence-context .line-number { color: #666; margin-right: 10px; user-select: none;
                                         display: inline-block; min-width: 30px; text-align: right; }
        .evidence-context .match-line { background: rgba(255, 255, 0, 0.15); display: block;
                                        margin: 0 -15px; padding: 2px 15px; }
        
        /* Remediation Section */
        .remediation-section { margin-top: 15px; border-top: 1px solid #e9ecef; padding-top: 15px; }
        .remediation-header { display: flex; align-items: center; justify-content: space-between;
                              cursor: pointer; padding: 10px; background: #e8f5e9; 
                              border-radius: 8px; margin-bottom: 10px; }
        .remediation-header:hover { background: #c8e6c9; }
        .remediation-header h4 { color: #2e7d32; display: flex; align-items: center; gap: 8px; 
                                 font-size: 0.95em; }
        .remediation-content { max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }
        .remediation-section.expanded .remediation-content { max-height: 2000px; }
        .remediation-text { background: #f1f8e9; padding: 15px; border-radius: 8px;
                            font-size: 0.9em; line-height: 1.7; }
        .remediation-text pre { background: #263238; color: #aed581; padding: 15px;
                                border-radius: 6px; overflow-x: auto; margin: 10px 0;
                                font-size: 12px; }
        .remediation-text code { font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
                                 background: rgba(0,0,0,0.1); padding: 2px 6px; border-radius: 3px; }
        .remediation-text ol, .remediation-text ul { margin-left: 20px; margin-top: 10px; }
        .remediation-text li { margin: 5px 0; }
        
        .no-vulns { text-align: center; padding: 60px; background: white; 
                     border-radius: 10px; color: #28a745; }
        .no-vulns h2 { font-size: 2em; }
        
        .results-info { padding: 10px 0; color: #666; font-size: 14px; }
        
        /* Copy Button */
        .copy-btn { background: #404040; color: #aaa; border: none; padding: 4px 8px;
                    border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s; }
        .copy-btn:hover { background: #505050; color: #fff; }
        .copy-btn.copied { background: #28a745; color: #fff; }
        
        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .vuln-card { animation: fadeIn 0.3s ease-out; }
        
        /* Print styles */
        @media print {
            .controls, .bulk-actions, .toggle-icon, .owasp-summary, .http-toggle,
            .copy-btn { display: none !important; }
            .vuln-card-body { max-height: none !important; padding: 20px !important; }
            .remediation-content { max-height: none !important; }
            .http-content { display: block !important; max-height: none !important; }
            .header { background: #1a1a2e !important; -webkit-print-color-adjust: exact; }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .controls { flex-direction: column; }
            .filter-group { width: 100%; }
            .bulk-actions { width: 100%; justify-content: center; }
            .http-panels { flex-direction: column; }
        }
        '''
    
    def _get_javascript(self) -> str:
        """Get all JavaScript for interactivity"""
        return '''
        let currentFilter = 'all';
        let currentOWASPFilter = 'all';
        
        function toggleCard(card) {
            card.classList.toggle('expanded');
        }
        
        function toggleRemediation(id) {
            const section = document.getElementById(id);
            section.classList.toggle('expanded');
            event.stopPropagation();
        }
        
        function toggleHttpTraffic(element) {
            event.stopPropagation();
            const content = element.nextElementSibling;
            const icon = element.querySelector('.toggle-icon');
            
            if (content.classList.contains('show')) {
                content.classList.remove('show');
                icon.classList.remove('expanded');
            } else {
                content.classList.add('show');
                icon.classList.add('expanded');
            }
        }
        
        function expandAll() {
            document.querySelectorAll('.vuln-card:not(.hidden)').forEach(card => {
                card.classList.add('expanded');
            });
        }
        
        function collapseAll() {
            document.querySelectorAll('.vuln-card').forEach(card => {
                card.classList.remove('expanded');
            });
            document.querySelectorAll('.remediation-section').forEach(section => {
                section.classList.remove('expanded');
            });
            document.querySelectorAll('.http-content').forEach(content => {
                content.classList.remove('show');
            });
            document.querySelectorAll('.http-toggle .toggle-icon').forEach(icon => {
                icon.classList.remove('expanded');
            });
        }
        
        function setFilter(severity) {
            currentFilter = severity;
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
                if (btn.dataset.filter === severity) {
                    btn.classList.add('active');
                }
            });
            filterVulnerabilities();
        }
        
        function filterBySeverity(severity) {
            setFilter(severity);
        }
        
        function toggleOWASPDropdown(event) {
            event.stopPropagation();
            const dropdown = document.getElementById('owaspDropdown');
            dropdown.classList.toggle('show');
        }
        
        function setOWASPFilter(category) {
            currentOWASPFilter = category;
            document.querySelectorAll('.owasp-dropdown-item').forEach(item => {
                item.classList.remove('selected');
                if (item.dataset.owasp === category) {
                    item.classList.add('selected');
                }
            });
            
            const btn = document.getElementById('owaspFilterText');
            if (category === 'all') {
                btn.textContent = 'All Categories';
            } else {
                const parts = category.split(' - ');
                btn.textContent = parts.length > 1 ? parts[0] : category;
            }
            
            document.getElementById('owaspDropdown').classList.remove('show');
            filterVulnerabilities();
        }
        
        function filterByOWASP(category) {
            setOWASPFilter(category);
        }
        
        function filterVulnerabilities() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.vuln-card');
            let visibleCount = 0;
            
            cards.forEach(card => {
                const cardSeverity = card.dataset.severity;
                const cardOWASP = card.dataset.owasp;
                const searchable = card.dataset.searchable;
                
                const matchesSeverity = currentFilter === 'all' || cardSeverity === currentFilter;
                const matchesOWASP = currentOWASPFilter === 'all' || cardOWASP === currentOWASPFilter;
                const matchesSearch = searchTerm === '' || searchable.includes(searchTerm);
                
                if (matchesSeverity && matchesOWASP && matchesSearch) {
                    card.classList.remove('hidden');
                    visibleCount++;
                } else {
                    card.classList.add('hidden');
                }
            });
            
            const totalCount = cards.length;
            const resultsText = visibleCount === totalCount 
                ? `Showing all ${totalCount} vulnerabilities`
                : `Showing ${visibleCount} of ${totalCount} vulnerabilities`;
            document.getElementById('resultsCount').textContent = resultsText;
        }
        
        function copyToClipboard(elementId, buttonElement) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            navigator.clipboard.writeText(text).then(() => {
                buttonElement.textContent = '✓ Copied';
                buttonElement.classList.add('copied');
                setTimeout(() => {
                    buttonElement.textContent = '📋 Copy';
                    buttonElement.classList.remove('copied');
                }, 2000);
            });
        }
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.owasp-filter')) {
                document.getElementById('owaspDropdown')?.classList.remove('show');
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.key === 'e' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT') {
                expandAll();
            }
            if (e.key === 'c' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT') {
                collapseAll();
            }
            if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
                e.preventDefault();
                document.getElementById('searchInput').focus();
            }
            if (e.key === 'Escape') {
                document.getElementById('searchInput').value = '';
                setFilter('all');
                setOWASPFilter('all');
            }
        });
        '''
    
    def _format_http_with_highlighting(self, http_text: str, payload: str = None) -> str:
        """Format HTTP text with syntax highlighting and payload marking"""
        if not http_text:
            return ""
        
        # Escape HTML first
        escaped = html.escape(http_text)
        
        # Highlight HTTP method and URL (request line)
        escaped = re.sub(
            r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+([^\s]+)\s+(HTTP/[\d.]+)',
            r'<span class="http-method">\1</span> <span class="http-url">\2</span> <span class="http-version">\3</span>',
            escaped,
            flags=re.MULTILINE
        )
        
        # Highlight HTTP response status line
        def highlight_status(match):
            version = match.group(1)
            status = match.group(2)
            reason = match.group(3)
            status_int = int(status)
            
            if status_int < 300:
                status_class = "http-status-ok"
            elif status_int < 400:
                status_class = "http-status-redirect"
            else:
                status_class = "http-status-error"
            
            return f'<span class="http-version">{version}</span> <span class="{status_class}">{status}</span> {reason}'
        
        escaped = re.sub(
            r'^(HTTP/[\d.]+)\s+(\d{3})\s+(.*)$',
            highlight_status,
            escaped,
            flags=re.MULTILINE
        )
        
        # Highlight headers
        escaped = re.sub(
            r'^([A-Za-z][A-Za-z0-9\-]*):\s*(.*)$',
            r'<span class="http-header-name">\1</span><span class="http-header-colon">:</span> <span class="http-header-value">\2</span>',
            escaped,
            flags=re.MULTILINE
        )
        
        # Highlight the payload if provided
        if payload:
            escaped_payload = html.escape(payload)
            if escaped_payload in escaped:
                escaped = escaped.replace(
                    escaped_payload,
                    f'<span class="payload-highlight">{escaped_payload}</span>'
                )
        
        return escaped
    
    def _build_http_section(self, vuln, vuln_id: int) -> str:
        """Build the HTTP request/response section like ZAP"""
        request = getattr(vuln, 'request', None)
        response = getattr(vuln, 'response', None)
        
        if not request and not response:
            return ""
        
        payload = getattr(vuln, 'payload', None)
        
        section_html = f'''
        <div class="http-traffic-section">
            <div class="http-toggle" onclick="toggleHttpTraffic(this)">
                <span class="toggle-icon">▶</span>
                <span class="http-toggle-title">🔍 HTTP Traffic</span>
                <span class="http-toggle-hint">Click to view request/response</span>
            </div>
            <div class="http-content">
                <div class="http-panels">
        '''
        
        if request:
            request_id = f"request-{vuln_id}"
            formatted_request = self._format_http_with_highlighting(request, payload)
            section_html += f'''
                    <div class="http-panel">
                        <div class="http-panel-header">
                            <span class="http-label request"><span class="icon">📤</span> Request</span>
                            <button class="copy-btn" onclick="copyToClipboard('{request_id}', this)">📋 Copy</button>
                        </div>
                        <pre class="http-code" id="{request_id}">{formatted_request}</pre>
                    </div>
            '''
        
        if response:
            response_id = f"response-{vuln_id}"
            formatted_response = self._format_http_with_highlighting(response, payload)
            
            # Calculate response size
            response_size = len(response)
            size_display = f"{response_size} bytes" if response_size < 1024 else f"{response_size/1024:.1f} KB"
            
            section_html += f'''
                    <div class="http-panel">
                        <div class="http-panel-header">
                            <span class="http-label response"><span class="icon">📥</span> Response</span>
                            <span class="http-meta">{size_display}</span>
                            <button class="copy-btn" onclick="copyToClipboard('{response_id}', this)">📋 Copy</button>
                        </div>
                        <pre class="http-code" id="{response_id}">{formatted_response}</pre>
                    </div>
            '''
        
        section_html += '''
                </div>
            </div>
        </div>
        '''
        
        return section_html
    
    def _build_evidence_context_section(self, vuln) -> str:
        """Build evidence context section with payload highlighting"""
        evidence_context = getattr(vuln, 'evidence_context', None)
        
        if not evidence_context:
            return ""
        
        # Process the context to highlight payload markers
        context_html = html.escape(evidence_context)
        
        # Replace our markers with HTML highlighting
        context_html = context_html.replace(
            '&gt;&gt;&gt;PAYLOAD_START&gt;&gt;&gt;',
            '<span class="payload-highlight">'
        )
        context_html = context_html.replace(
            '&lt;&lt;&lt;PAYLOAD_END&lt;&lt;&lt;',
            '</span>'
        )
        
        # Also highlight 【】markers
        payload = getattr(vuln, 'payload', None)
        if payload:
            escaped_payload = html.escape(payload)
            context_html = context_html.replace(
                f'【{escaped_payload}】',
                f'<span class="payload-highlight">{escaped_payload}</span>'
            )
        
        # Highlight [SOURCE: ...] and [SINK: ...] markers
        context_html = re.sub(
            r'\[SOURCE:\s*([^\]]+)\]',
            r'<span class="payload-marker">SOURCE</span> <span class="payload-highlight">\1</span>',
            context_html
        )
        context_html = re.sub(
            r'\[SINK:\s*([^\]]+)\]',
            r'<span class="payload-marker">SINK</span> <span class="payload-highlight">\1</span>',
            context_html
        )
        
        return f'''
        <div class="evidence-context-section">
            <div class="evidence-context-header">
                <span class="icon">🎯</span> Evidence Context
            </div>
            <div class="evidence-context">{context_html}</div>
        </div>
        '''
    
    def generate_html_report(self, scan_results: Dict) -> str:
        """Generate HTML report with HTTP traffic capture"""
        summary = self._generate_summary(scan_results)
        owasp_summary = self._generate_owasp_summary(scan_results)
        vulns = scan_results.get("vulnerabilities", [])
        
        target = html.escape(str(scan_results.get("target", "Unknown")))
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnFlow Security Report</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VulnFlow Security Report</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Pages Crawled:</strong> {scan_results.get("pages_scanned", 0)} | 
               <strong>Forms Tested:</strong> {scan_results.get("forms_tested", 0)}</p>
            <span class="owasp-badge">📋 OWASP Top 10 2025</span>
        </div>
        
        <div class="summary">
            <div class="summary-card critical" onclick="filterBySeverity('critical')" title="Click to filter">
                <div class="count">{summary["critical"]}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high" onclick="filterBySeverity('high')" title="Click to filter">
                <div class="count">{summary["high"]}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium" onclick="filterBySeverity('medium')" title="Click to filter">
                <div class="count">{summary["medium"]}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low" onclick="filterBySeverity('low')" title="Click to filter">
                <div class="count">{summary["low"]}</div>
                <div>Low</div>
            </div>
        </div>
'''
        
        # OWASP Summary Section
        if owasp_summary:
            html_content += '''
        <div class="owasp-summary">
            <h2>📊 OWASP Top 10 2025 Breakdown</h2>
            <div class="owasp-grid">
'''
            for cat_key, cat_data in sorted(owasp_summary.items(), key=lambda x: x[1]["count"], reverse=True):
                breakdown_html = ""
                if cat_data["critical"] > 0:
                    breakdown_html += f'<span class="critical">{cat_data["critical"]} Critical</span>'
                if cat_data["high"] > 0:
                    breakdown_html += f'<span class="high">{cat_data["high"]} High</span>'
                if cat_data["medium"] > 0:
                    breakdown_html += f'<span class="medium">{cat_data["medium"]} Medium</span>'
                if cat_data["low"] > 0:
                    breakdown_html += f'<span class="low">{cat_data["low"]} Low</span>'
                
                html_content += f'''
                <div class="owasp-card" onclick="filterByOWASP('{cat_key}')" 
                     style="--owasp-color: {cat_data['color']}">
                    <div class="owasp-card-header">
                        <span class="owasp-card-id">{cat_data['id']}</span>
                        <span class="owasp-card-count">{cat_data['count']}</span>
                    </div>
                    <div class="owasp-card-name">{html.escape(cat_data['name'])}</div>
                    <div class="owasp-card-breakdown">{breakdown_html}</div>
                </div>
'''
            html_content += '''
            </div>
        </div>
'''
        
        if vulns:
            # OWASP filter dropdown options
            owasp_options = '<div class="owasp-dropdown-item" data-owasp="all" onclick="setOWASPFilter(\'all\')">All Categories</div>'
            for cat_key in sorted(owasp_summary.keys()):
                cat_info = self.owasp_categories.get(cat_key, {})
                owasp_options += f'''
                <div class="owasp-dropdown-item" data-owasp="{html.escape(cat_key)}" 
                     onclick="setOWASPFilter('{html.escape(cat_key)}')"
                     style="border-left-color: {cat_info.get('color', '#6c757d')}">
                    <span>{cat_info.get('id', '')} - {cat_info.get('short', '')}</span>
                    <span style="color: #666; font-size: 0.85em;">{owasp_summary[cat_key]['count']}</span>
                </div>
'''
            
            html_content += f'''
        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Search vulnerabilities..." onkeyup="filterVulnerabilities()">
            </div>
            <div class="filter-group">
                <span class="filter-label">Severity</span>
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="setFilter('all')" data-filter="all">All</button>
                    <button class="filter-btn critical" onclick="setFilter('critical')" data-filter="critical">Critical</button>
                    <button class="filter-btn high" onclick="setFilter('high')" data-filter="high">High</button>
                    <button class="filter-btn medium" onclick="setFilter('medium')" data-filter="medium">Medium</button>
                    <button class="filter-btn low" onclick="setFilter('low')" data-filter="low">Low</button>
                </div>
            </div>
            <div class="filter-group">
                <span class="filter-label">OWASP Category</span>
                <div class="owasp-filter">
                    <button class="owasp-filter-btn" onclick="toggleOWASPDropdown(event)">
                        <span id="owaspFilterText">All Categories</span>
                        <span>▼</span>
                    </button>
                    <div class="owasp-dropdown" id="owaspDropdown">
                        {owasp_options}
                    </div>
                </div>
            </div>
            <div class="bulk-actions">
                <button class="bulk-btn" onclick="expandAll()">📂 Expand All</button>
                <button class="bulk-btn" onclick="collapseAll()">📁 Collapse All</button>
            </div>
        </div>
        
        <div class="results-info">
            <span id="resultsCount">Showing all {len(vulns)} vulnerabilities</span>
        </div>
        
        <h2 style="margin-bottom: 20px;">Vulnerability Details</h2>
        <div id="vulnContainer">
'''
        else:
            html_content += '''
        <h2 style="margin-bottom: 20px;">Vulnerability Details</h2>
'''
        
        if not vulns:
            html_content += '''
        <div class="no-vulns">
            <h2>✅ No Vulnerabilities Found</h2>
            <p>Great job! No security issues were detected during this scan.</p>
        </div>
'''
        else:
            for i, vuln in enumerate(vulns, 1):
                severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                remediation = getattr(vuln, 'remediation', None)
                
                # Get OWASP category info
                owasp_cat = getattr(vuln, 'owasp_category', None)
                if owasp_cat:
                    owasp_cat_value = owasp_cat.value if hasattr(owasp_cat, 'value') else str(owasp_cat)
                else:
                    owasp_cat_value = "Other"
                
                owasp_info = self._get_owasp_category_info(owasp_cat_value)
                normalized_owasp = self._normalize_owasp_category(owasp_cat_value)
                
                # Build HTTP traffic section
                http_section = self._build_http_section(vuln, i)
                
                # Build evidence context section
                evidence_context_section = self._build_evidence_context_section(vuln)
                
                html_content += f'''
        <div class="vuln-card" data-severity="{severity}" data-owasp="{html.escape(normalized_owasp)}" 
             data-searchable="{html.escape(vuln.vuln_type.lower())} {html.escape(vuln.url.lower())} {html.escape(vuln.parameter.lower() if vuln.parameter else '')} {html.escape(owasp_info['name'].lower())}">
            <div class="vuln-card-header" onclick="toggleCard(this.parentElement)">
                <h3>
                    <span>#{i} {html.escape(vuln.vuln_type)}</span>
                    <span class="owasp-badge-small" style="background: {owasp_info['color']}20; border-color: {owasp_info['color']}; color: {owasp_info['color']}">
                        {owasp_info['id']}
                    </span>
                </h3>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <span class="severity {severity}">{severity}</span>
                    <span class="toggle-icon">▼</span>
                </div>
            </div>
            <div class="vuln-card-body">
                <div class="owasp-detail-box">
                    <span class="owasp-icon">🔖</span>
                    <div class="owasp-info">
                        <div class="owasp-title">
                            <a href="{owasp_info['url']}" target="_blank">{owasp_info['id']}: {html.escape(owasp_info['name'])}</a>
                        </div>
                        <div class="owasp-desc">{html.escape(owasp_info['description'])}</div>
                    </div>
                </div>
                
                <div class="detail">
                    <span class="detail-label">URL:</span> 
                    <a href="{html.escape(vuln.url)}" target="_blank" style="color: #1976d2; word-break: break-all;">{html.escape(vuln.url)}</a>
                </div>
'''
                if vuln.parameter:
                    html_content += f'''
                <div class="detail">
                    <span class="detail-label">Parameter:</span> <code>{html.escape(vuln.parameter)}</code>
                </div>
'''
                if vuln.payload:
                    html_content += f'''
                <div class="detail">
                    <span class="detail-label">Payload:</span>
                    <div class="payload-box">{html.escape(vuln.payload)}</div>
                </div>
'''
                html_content += f'''
                <div class="detail">
                    <span class="detail-label">Evidence:</span>
                    <div class="code">{html.escape(vuln.evidence)}</div>
                </div>
'''
                
                # Add evidence context if available
                if evidence_context_section:
                    html_content += evidence_context_section
                
                # Add HTTP traffic section
                if http_section:
                    html_content += http_section
                
                html_content += f'''
                <div class="detail">
                    <span class="detail-label">Description:</span>
                    <p style="margin-top: 5px;">{self._format_description_html(vuln.description)}</p>
                </div>
'''
                if vuln.cwe_id:
                    cwe_num = vuln.cwe_id.replace('CWE-', '')
                    html_content += f'''
                <div class="detail">
                    <span class="detail-label">CWE:</span> 
                    <a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html" 
                       target="_blank" style="color: #1976d2;">{html.escape(vuln.cwe_id)}</a>
                </div>
'''
                
                cvss_score = getattr(vuln, 'cvss_score', None)
                if cvss_score:
                    cvss_color = self._get_cvss_color(cvss_score)
                    html_content += f'''
                <div class="detail">
                    <span class="detail-label">CVSS Score:</span> 
                    <span style="color: {cvss_color}; font-weight: bold;">{cvss_score}</span>
                </div>
'''
                
                # Remediation section
                if remediation:
                    formatted_remediation = self._format_remediation_html(remediation)
                    html_content += f'''
                <div class="remediation-section" id="remediation-{i}">
                    <div class="remediation-header" onclick="toggleRemediation('remediation-{i}')">
                        <h4>💡 Remediation</h4>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="remediation-content">
                        <div class="remediation-text">
                            {formatted_remediation}
                        </div>
                    </div>
                </div>
'''
                
                # References section
                references = getattr(vuln, 'references', None)
                if references and len(references) > 0:
                    html_content += '''
                <div class="detail" style="margin-top: 15px;">
                    <span class="detail-label">References:</span>
                    <ul style="margin-top: 5px; margin-left: 20px;">
'''
                    for ref in references[:5]:  # Limit to 5 references
                        html_content += f'''
                        <li><a href="{html.escape(ref)}" target="_blank" style="color: #1976d2; font-size: 0.9em;">{html.escape(ref[:80])}{'...' if len(ref) > 80 else ''}</a></li>
'''
                    html_content += '''
                    </ul>
                </div>
'''
                
                html_content += '''
            </div>
        </div>
'''
        
        if vulns:
            html_content += '''
        </div>
'''
        
        # Add JavaScript
        html_content += f'''
    </div>
    
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>'''
        
        return html_content
    
    def _format_description_html(self, description: str) -> str:
        """Format description with basic markdown support"""
        if not description:
            return ""
        
        text = html.escape(description)
        
        # Convert **bold** to <strong>
        text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
        
        # Convert `code` to <code>
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        
        # Convert newlines to <br>
        text = text.replace('\n', '<br>')
        
        return text
    
    def _get_cvss_color(self, cvss_score: float) -> str:
        """Get color based on CVSS score"""
        if cvss_score >= 9.0:
            return "#dc3545"  # Critical - Red
        elif cvss_score >= 7.0:
            return "#fd7e14"  # High - Orange
        elif cvss_score >= 4.0:
            return "#ffc107"  # Medium - Yellow
        elif cvss_score >= 0.1:
            return "#17a2b8"  # Low - Blue
        else:
            return "#6c757d"  # Info - Gray
    
    def _format_remediation_html(self, remediation: str) -> str:
        """Format remediation text as HTML with proper code highlighting"""
        if not remediation:
            return ""
        
        # Escape HTML first
        text = html.escape(remediation.strip())
        
        # Handle code blocks (```language ... ```)
        def replace_code_block(match):
            lang = match.group(1) or ''
            code = match.group(2)
            return f'<pre><code class="language-{lang}">{code}</code></pre>'
        
        text = re.sub(r'```(\w*)\n(.*?)```', replace_code_block, text, flags=re.DOTALL)
        
        # Handle inline code (`code`)
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        
        # Handle **bold**
        text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
        
        # Convert numbered lists
        lines = text.split('\n')
        in_list = False
        in_ul = False
        result = []
        
        for line in lines:
            stripped = line.strip()
            
            # Check for numbered list item
            numbered_match = re.match(r'^(\d+)\.\s+(.+)$', stripped)
            bullet_match = re.match(r'^[-*]\s+(.+)$', stripped)
            
            if numbered_match:
                if in_ul:
                    result.append('</ul>')
                    in_ul = False
                if not in_list:
                    result.append('<ol>')
                    in_list = True
                result.append(f'<li>{numbered_match.group(2)}</li>')
            elif bullet_match:
                if in_list:
                    result.append('</ol>')
                    in_list = False
                if not in_ul:
                    result.append('<ul>')
                    in_ul = True
                result.append(f'<li>{bullet_match.group(1)}</li>')
            else:
                if in_list:
                    result.append('</ol>')
                    in_list = False
                if in_ul:
                    result.append('</ul>')
                    in_ul = False
                result.append(line)
        
        if in_list:
            result.append('</ol>')
        if in_ul:
            result.append('</ul>')
        
        text = '\n'.join(result)
        
        # Convert line breaks to <br> (but not inside pre tags)
        parts = re.split(r'(<pre>.*?</pre>)', text, flags=re.DOTALL)
        for i, part in enumerate(parts):
            if not part.startswith('<pre>'):
                parts[i] = part.replace('\n', '<br>\n')
        text = ''.join(parts)
        
        return text
    
    def generate_json_report(self, scan_results: Dict) -> str:
        """Generate JSON report for CI/CD integration with HTTP capture"""
        summary = self._generate_summary(scan_results)
        owasp_summary = self._generate_owasp_summary(scan_results)
        
        report = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "target": scan_results.get("target", "Unknown"),
                "scanner_version": "2.0.0",
                "owasp_version": "2025",
                "pages_scanned": scan_results.get("pages_scanned", 0),
                "forms_tested": scan_results.get("forms_tested", 0)
            },
            "summary": summary,
            "owasp_summary": {
                cat_key: {
                    "id": data["id"],
                    "name": data["name"],
                    "count": data["count"],
                    "critical": data["critical"],
                    "high": data["high"],
                    "medium": data["medium"],
                    "low": data["low"]
                }
                for cat_key, data in owasp_summary.items()
            },
            "findings": []
        }
        
        for vuln in scan_results.get("vulnerabilities", []):
            severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            
            owasp_cat = getattr(vuln, 'owasp_category', None)
            if owasp_cat:
                owasp_cat_value = owasp_cat.value if hasattr(owasp_cat, 'value') else str(owasp_cat)
            else:
                owasp_cat_value = "Other"
            
            normalized_owasp = self._normalize_owasp_category(owasp_cat_value)
            owasp_info = self._get_owasp_category_info(owasp_cat_value)
            
            finding = {
                "type": vuln.vuln_type,
                "severity": severity,
                "url": vuln.url,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "evidence": vuln.evidence,
                "description": vuln.description,
                "cwe_id": vuln.cwe_id,
                "cvss_score": getattr(vuln, 'cvss_score', None),
                "owasp": {
                    "category": normalized_owasp,
                    "id": owasp_info["id"],
                    "name": owasp_info["name"],
                    "url": owasp_info["url"]
                },
                "remediation": getattr(vuln, 'remediation', None),
                "references": getattr(vuln, 'references', [])
            }
            
            # Add HTTP capture if available
            request = getattr(vuln, 'request', None)
            response = getattr(vuln, 'response', None)
            
            if request or response:
                finding["http_traffic"] = {
                    "request": request,
                    "response": response[:10000] if response and len(response) > 10000 else response  # Limit response size
                }
            
            # Add evidence context if available
            evidence_context = getattr(vuln, 'evidence_context', None)
            if evidence_context:
                finding["evidence_context"] = evidence_context
            
            report["findings"].append(finding)
        
        report["exit_code"] = self._determine_exit_code(scan_results)
        
        return json.dumps(report, indent=2)
    
    def generate_sarif_report(self, scan_results: Dict) -> str:
        """Generate SARIF format for GitHub/IDE integration"""
        rules = []
        results = []
        
        rule_ids = {}
        
        for vuln in scan_results.get("vulnerabilities", []):
            rule_id = vuln.vuln_type.replace(" ", "_").lower()
            rule_id = re.sub(r'[^a-z0-9_]', '', rule_id)
            
            if rule_id not in rule_ids:
                rule_ids[rule_id] = len(rules)
                severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                
                owasp_cat = getattr(vuln, 'owasp_category', None)
                if owasp_cat:
                    owasp_cat_value = owasp_cat.value if hasattr(owasp_cat, 'value') else str(owasp_cat)
                else:
                    owasp_cat_value = "Other"
                
                normalized_owasp = self._normalize_owasp_category(owasp_cat_value)
                owasp_info = self._get_owasp_category_info(owasp_cat_value)
                
                rule_def = {
                    "id": rule_id,
                    "name": vuln.vuln_type,
                    "shortDescription": {"text": vuln.vuln_type},
                    "fullDescription": {"text": vuln.description[:500] if len(vuln.description) > 500 else vuln.description},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(severity)
                    },
                    "properties": {
                        "security-severity": self._severity_to_cvss(severity),
                        "owasp": owasp_info["id"],
                        "owasp-category": owasp_info["name"],
                        "owasp-url": owasp_info["url"],
                        "tags": [
                            "security",
                            f"owasp-{owasp_info['id'].lower()}",
                        ]
                    }
                }
                
                if vuln.cwe_id:
                    rule_def["helpUri"] = f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html"
                    rule_def["properties"]["cwe"] = vuln.cwe_id
                    rule_def["properties"]["tags"].append(f"cwe-{vuln.cwe_id.lower()}")
                
                remediation = getattr(vuln, 'remediation', None)
                if remediation:
                    rule_def["help"] = {
                        "text": f"OWASP: {owasp_info['id']} - {owasp_info['name']}\n\n{remediation}",
                        "markdown": f"**OWASP:** [{owasp_info['id']} - {owasp_info['name']}]({owasp_info['url']})\n\n{remediation}"
                    }
                
                rules.append(rule_def)
            
            # Create result
            result_entry = {
                "ruleId": rule_id,
                "ruleIndex": rule_ids[rule_id],
                "message": {"text": f"{vuln.vuln_type} found at {vuln.url}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln.url}
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": str(hash(f"{vuln.url}{vuln.parameter}{vuln.payload}") % (10 ** 10))
                }
            }
            
            # Add snippet if payload available
            if vuln.payload:
                result_entry["locations"][0]["physicalLocation"]["region"] = {
                    "snippet": {"text": vuln.payload}
                }
            
            results.append(result_entry)
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnFlow",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/your-org/vulnflow",
                        "rules": rules,
                        "properties": {
                            "owasp-version": "2025"
                        }
                    }
                },
                "results": results
            }]
        }
        
        return json.dumps(sarif, indent=2)
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Generate vulnerability summary"""
        vulns = scan_results.get("vulnerabilities", [])
        summary = {
            "total_findings": len(vulns),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in vulns:
            severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _determine_exit_code(self, scan_results: Dict) -> int:
        """Determine CI/CD exit code"""
        summary = self._generate_summary(scan_results)
        
        if summary["critical"] > 0:
            return 2
        if summary["high"] > 0:
            return 1
        return 0
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return mapping.get(severity.lower(), "warning")
    
    def _severity_to_cvss(self, severity: str) -> str:
        """Convert severity to approximate CVSS score for SARIF"""
        mapping = {
            "critical": "9.5",
            "high": "7.5",
            "medium": "5.0",
            "low": "2.5",
            "info": "0.0"
        }
        return mapping.get(severity.lower(), "5.0")