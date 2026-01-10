# websec/reports/generator.py
from typing import List, Dict
from datetime import datetime
import json
import html


class ReportGenerator:
    """Generate security scan reports in various formats"""
    
    def generate_html_report(self, scan_results: Dict) -> str:
        """Generate HTML report"""
        summary = self._generate_summary(scan_results)
        vulns = scan_results.get("vulnerabilities", [])
        
        # Escape HTML in user-provided data
        target = html.escape(str(scan_results.get("target", "Unknown")))
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnFlow Security Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
                   color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
                    gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 10px; 
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card.critical {{ border-left: 4px solid #dc3545; }}
        .summary-card.high {{ border-left: 4px solid #fd7e14; }}
        .summary-card.medium {{ border-left: 4px solid #ffc107; }}
        .summary-card.low {{ border-left: 4px solid #17a2b8; }}
        .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
        .vuln-card {{ background: white; border-radius: 10px; padding: 20px; 
                      margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; 
                        margin-bottom: 15px; }}
        .severity {{ padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; 
                    text-transform: uppercase; font-size: 0.8em; }}
        .severity.critical {{ background: #dc3545; }}
        .severity.high {{ background: #fd7e14; }}
        .severity.medium {{ background: #ffc107; color: #333; }}
        .severity.low {{ background: #17a2b8; }}
        .severity.info {{ background: #6c757d; }}
        .detail {{ margin: 10px 0; }}
        .detail-label {{ font-weight: bold; color: #666; }}
        .code {{ background: #f8f9fa; padding: 15px; border-radius: 5px; 
                 font-family: monospace; overflow-x: auto; margin: 10px 0; }}
        .no-vulns {{ text-align: center; padding: 60px; background: white; 
                     border-radius: 10px; color: #28a745; }}
        .no-vulns h2 {{ font-size: 2em; }}
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
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <div class="count">{summary["critical"]}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{summary["high"]}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{summary["medium"]}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{summary["low"]}</div>
                <div>Low</div>
            </div>
        </div>
        
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
                html_content += f'''
        <div class="vuln-card">
            <div class="vuln-header">
                <h3>#{i} {html.escape(vuln.vuln_type)}</h3>
                <span class="severity {severity}">{severity}</span>
            </div>
            <div class="detail">
                <span class="detail-label">URL:</span> {html.escape(vuln.url)}
            </div>
'''
                if vuln.parameter:
                    html_content += f'''
            <div class="detail">
                <span class="detail-label">Parameter:</span> {html.escape(vuln.parameter)}
            </div>
'''
                if vuln.payload:
                    html_content += f'''
            <div class="detail">
                <span class="detail-label">Payload:</span>
                <div class="code">{html.escape(vuln.payload)}</div>
            </div>
'''
                html_content += f'''
            <div class="detail">
                <span class="detail-label">Evidence:</span>
                <div class="code">{html.escape(vuln.evidence)}</div>
            </div>
            <div class="detail">
                <span class="detail-label">Description:</span> {html.escape(vuln.description)}
            </div>
'''
                if vuln.cwe_id:
                    html_content += f'''
            <div class="detail">
                <span class="detail-label">CWE:</span> 
                <a href="https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html" 
                   target="_blank">{html.escape(vuln.cwe_id)}</a>
            </div>
'''
                html_content += '''
        </div>
'''
        
        html_content += '''
    </div>
</body>
</html>'''
        
        return html_content
    
    def generate_json_report(self, scan_results: Dict) -> str:
        """Generate JSON report for CI/CD integration"""
        summary = self._generate_summary(scan_results)
        
        report = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "target": scan_results.get("target", "Unknown"),
                "scanner_version": "1.0.0"
            },
            "summary": summary,
            "findings": []
        }
        
        for vuln in scan_results.get("vulnerabilities", []):
            severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            report["findings"].append({
                "type": vuln.vuln_type,
                "severity": severity,
                "url": vuln.url,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "evidence": vuln.evidence,
                "description": vuln.description,
                "cwe_id": vuln.cwe_id,
                "cvss_score": vuln.cvss_score
            })
        
        report["exit_code"] = self._determine_exit_code(scan_results)
        
        return json.dumps(report, indent=2)
    
    def generate_sarif_report(self, scan_results: Dict) -> str:
        """Generate SARIF format for GitHub/IDE integration"""
        rules = []
        results = []
        
        rule_ids = {}
        
        for vuln in scan_results.get("vulnerabilities", []):
            # Create rule if not exists
            rule_id = vuln.vuln_type.replace(" ", "_").lower()
            if rule_id not in rule_ids:
                rule_ids[rule_id] = len(rules)
                severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                rules.append({
                    "id": rule_id,
                    "name": vuln.vuln_type,
                    "shortDescription": {"text": vuln.vuln_type},
                    "fullDescription": {"text": vuln.description},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(severity)
                    },
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html" if vuln.cwe_id else None
                })
            
            # Create result
            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_ids[rule_id],
                "message": {"text": f"{vuln.vuln_type} found at {vuln.url}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln.url}
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": hash(f"{vuln.url}{vuln.parameter}")
                }
            })
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnFlow",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-org/vulnflow",
                        "rules": rules
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