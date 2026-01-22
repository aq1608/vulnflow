# reports/generator.py
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
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center;
                        cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }}
        .summary-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.15); }}
        .summary-card.active {{ ring: 2px solid currentColor; }}
        .summary-card.critical {{ border-left: 4px solid #dc3545; }}
        .summary-card.high {{ border-left: 4px solid #fd7e14; }}
        .summary-card.medium {{ border-left: 4px solid #ffc107; }}
        .summary-card.low {{ border-left: 4px solid #17a2b8; }}
        .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
        
        /* Controls Section */
        .controls {{ background: white; padding: 20px; border-radius: 10px; 
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px;
                     display: flex; flex-wrap: wrap; gap: 15px; align-items: center; }}
        .search-box {{ flex: 1; min-width: 250px; }}
        .search-box input {{ width: 100%; padding: 10px 15px; border: 2px solid #e0e0e0;
                            border-radius: 8px; font-size: 14px; transition: border-color 0.2s; }}
        .search-box input:focus {{ outline: none; border-color: #1a1a2e; }}
        .filter-buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{ padding: 8px 16px; border: 2px solid #e0e0e0; background: white;
                      border-radius: 20px; cursor: pointer; font-size: 13px; font-weight: 500;
                      transition: all 0.2s; }}
        .filter-btn:hover {{ background: #f0f0f0; }}
        .filter-btn.active {{ background: #1a1a2e; color: white; border-color: #1a1a2e; }}
        .filter-btn.critical.active {{ background: #dc3545; border-color: #dc3545; }}
        .filter-btn.high.active {{ background: #fd7e14; border-color: #fd7e14; }}
        .filter-btn.medium.active {{ background: #ffc107; border-color: #ffc107; color: #333; }}
        .filter-btn.low.active {{ background: #17a2b8; border-color: #17a2b8; }}
        
        /* Expand/Collapse All */
        .bulk-actions {{ display: flex; gap: 10px; margin-left: auto; }}
        .bulk-btn {{ padding: 8px 12px; background: #f8f9fa; border: 1px solid #dee2e6;
                    border-radius: 6px; cursor: pointer; font-size: 13px; transition: all 0.2s; }}
        .bulk-btn:hover {{ background: #e9ecef; }}
        
        /* Vulnerability Cards */
        .vuln-card {{ background: white; border-radius: 10px; 
                      margin-bottom: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                      overflow: hidden; transition: all 0.3s ease; }}
        .vuln-card.hidden {{ display: none; }}
        .vuln-card-header {{ display: flex; justify-content: space-between; align-items: center; 
                            padding: 20px; cursor: pointer; user-select: none;
                            transition: background 0.2s; }}
        .vuln-card-header:hover {{ background: #f8f9fa; }}
        .vuln-card-header h3 {{ display: flex; align-items: center; gap: 10px; font-size: 1em; }}
        .vuln-card-header .toggle-icon {{ transition: transform 0.3s; color: #666; }}
        .vuln-card.expanded .toggle-icon {{ transform: rotate(180deg); }}
        .vuln-card-body {{ max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out;
                          padding: 0 20px; }}
        .vuln-card.expanded .vuln-card-body {{ max-height: 2000px; padding: 0 20px 20px; }}
        
        .severity {{ padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; 
                    text-transform: uppercase; font-size: 0.75em; white-space: nowrap; }}
        .severity.critical {{ background: #dc3545; }}
        .severity.high {{ background: #fd7e14; }}
        .severity.medium {{ background: #ffc107; color: #333; }}
        .severity.low {{ background: #17a2b8; }}
        .severity.info {{ background: #6c757d; }}
        
        .detail {{ margin: 12px 0; }}
        .detail-label {{ font-weight: bold; color: #666; font-size: 0.9em; }}
        .code {{ background: #f8f9fa; padding: 15px; border-radius: 5px; 
                 font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; 
                 overflow-x: auto; margin: 8px 0; font-size: 13px;
                 border: 1px solid #e9ecef; }}
        
        /* Remediation Section */
        .remediation-section {{ margin-top: 15px; border-top: 1px solid #e9ecef; padding-top: 15px; }}
        .remediation-header {{ display: flex; align-items: center; justify-content: space-between;
                              cursor: pointer; padding: 10px; background: #e8f5e9; 
                              border-radius: 8px; margin-bottom: 10px; }}
        .remediation-header:hover {{ background: #c8e6c9; }}
        .remediation-header h4 {{ color: #2e7d32; display: flex; align-items: center; gap: 8px; 
                                 font-size: 0.95em; }}
        .remediation-content {{ max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }}
        .remediation-section.expanded .remediation-content {{ max-height: 2000px; }}
        .remediation-text {{ background: #f1f8e9; padding: 15px; border-radius: 8px;
                            font-size: 0.9em; line-height: 1.7; }}
        .remediation-text pre {{ background: #263238; color: #aed581; padding: 15px;
                                border-radius: 6px; overflow-x: auto; margin: 10px 0;
                                font-size: 12px; }}
        .remediation-text code {{ font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; }}
        .remediation-text ol, .remediation-text ul {{ margin-left: 20px; margin-top: 10px; }}
        .remediation-text li {{ margin: 5px 0; }}
        
        .no-vulns {{ text-align: center; padding: 60px; background: white; 
                     border-radius: 10px; color: #28a745; }}
        .no-vulns h2 {{ font-size: 2em; }}
        
        /* Results count */
        .results-info {{ padding: 10px 0; color: #666; font-size: 14px; }}
        
        /* Animations */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .vuln-card {{ animation: fadeIn 0.3s ease-out; }}
        
        /* Print styles */
        @media print {{
            .controls, .bulk-actions, .toggle-icon {{ display: none !important; }}
            .vuln-card-body {{ max-height: none !important; padding: 20px !important; }}
            .remediation-content {{ max-height: none !important; }}
        }}
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
        
        if vulns:
            html_content += '''
        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Search vulnerabilities..." onkeyup="filterVulnerabilities()">
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="setFilter('all')" data-filter="all">All</button>
                <button class="filter-btn critical" onclick="setFilter('critical')" data-filter="critical">Critical</button>
                <button class="filter-btn high" onclick="setFilter('high')" data-filter="high">High</button>
                <button class="filter-btn medium" onclick="setFilter('medium')" data-filter="medium">Medium</button>
                <button class="filter-btn low" onclick="setFilter('low')" data-filter="low">Low</button>
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
                
                html_content += f'''
        <div class="vuln-card" data-severity="{severity}" data-searchable="{html.escape(vuln.vuln_type.lower())} {html.escape(vuln.url.lower())} {html.escape(vuln.parameter.lower() if vuln.parameter else '')}">
            <div class="vuln-card-header" onclick="toggleCard(this.parentElement)">
                <h3>
                    <span>#{i} {html.escape(vuln.vuln_type)}</span>
                </h3>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <span class="severity {severity}">{severity}</span>
                    <span class="toggle-icon">▼</span>
                </div>
            </div>
            <div class="vuln-card-body">
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
                       target="_blank" style="color: #1976d2;">{html.escape(vuln.cwe_id)}</a>
                </div>
'''
                # Add remediation section if available
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
                html_content += '''
            </div>
        </div>
'''
        
        if vulns:
            html_content += '''
        </div>
'''
        
        # Add JavaScript for interactivity
        html_content += '''
    </div>
    
    <script>
        let currentFilter = 'all';
        
        function toggleCard(card) {
            card.classList.toggle('expanded');
        }
        
        function toggleRemediation(id) {
            const section = document.getElementById(id);
            section.classList.toggle('expanded');
            event.stopPropagation();
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
        }
        
        function setFilter(severity) {
            currentFilter = severity;
            
            // Update button states
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
        
        function filterVulnerabilities() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.vuln-card');
            let visibleCount = 0;
            
            cards.forEach(card => {
                const cardSeverity = card.dataset.severity;
                const searchable = card.dataset.searchable;
                
                const matchesSeverity = currentFilter === 'all' || cardSeverity === currentFilter;
                const matchesSearch = searchTerm === '' || searchable.includes(searchTerm);
                
                if (matchesSeverity && matchesSearch) {
                    card.classList.remove('hidden');
                    visibleCount++;
                } else {
                    card.classList.add('hidden');
                }
            });
            
            // Update results count
            const totalCount = cards.length;
            const resultsText = visibleCount === totalCount 
                ? `Showing all ${totalCount} vulnerabilities`
                : `Showing ${visibleCount} of ${totalCount} vulnerabilities`;
            document.getElementById('resultsCount').textContent = resultsText;
        }
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Press 'e' to expand all
            if (e.key === 'e' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT') {
                expandAll();
            }
            // Press 'c' to collapse all
            if (e.key === 'c' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT') {
                collapseAll();
            }
            // Press '/' to focus search
            if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
                e.preventDefault();
                document.getElementById('searchInput').focus();
            }
            // Press Escape to clear search and filters
            if (e.key === 'Escape') {
                document.getElementById('searchInput').value = '';
                setFilter('all');
            }
        });
    </script>
</body>
</html>'''
        
        return html_content
    
    def _format_remediation_html(self, remediation: str) -> str:
        """Format remediation text as HTML with proper code highlighting"""
        if not remediation:
            return ""
        
        # Escape HTML first
        text = html.escape(remediation.strip())
        
        # Handle code blocks (```python ... ```)
        import re
        
        def replace_code_block(match):
            lang = match.group(1) or ''
            code = match.group(2)
            return f'<pre><code class="language-{lang}">{code}</code></pre>'
        
        text = re.sub(r'```(\w*)\n(.*?)```', replace_code_block, text, flags=re.DOTALL)
        
        # Handle inline code (`code`)
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        
        # Convert numbered lists
        lines = text.split('\n')
        in_list = False
        result = []
        
        for line in lines:
            # Check for numbered list item
            numbered_match = re.match(r'^(\d+)\.\s+(.+)$', line.strip())
            if numbered_match:
                if not in_list:
                    result.append('<ol>')
                    in_list = True
                result.append(f'<li>{numbered_match.group(2)}</li>')
            else:
                if in_list and line.strip() == '':
                    result.append('</ol>')
                    in_list = False
                elif in_list and not line.strip().startswith('<pre>'):
                    result.append('</ol>')
                    in_list = False
                    result.append(line)
                else:
                    result.append(line)
        
        if in_list:
            result.append('</ol>')
        
        text = '\n'.join(result)
        
        # Convert line breaks to <br> (but not inside pre tags)
        parts = re.split(r'(<pre>.*?</pre>)', text, flags=re.DOTALL)
        for i, part in enumerate(parts):
            if not part.startswith('<pre>'):
                parts[i] = part.replace('\n', '<br>\n')
        text = ''.join(parts)
        
        return text
    
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
                "cvss_score": vuln.cvss_score,
                "remediation": getattr(vuln, 'remediation', None)
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
                
                rule_def = {
                    "id": rule_id,
                    "name": vuln.vuln_type,
                    "shortDescription": {"text": vuln.vuln_type},
                    "fullDescription": {"text": vuln.description},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(severity)
                    }
                }
                
                # Add help text with remediation if available
                remediation = getattr(vuln, 'remediation', None)
                if remediation:
                    rule_def["help"] = {"text": remediation, "markdown": remediation}
                
                if vuln.cwe_id:
                    rule_def["helpUri"] = f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html"
                
                rules.append(rule_def)
            
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