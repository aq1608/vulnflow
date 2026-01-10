# VulnFlow

Web Vulnerability Scanner with Contextual Remediation

## Installation

```bash
pip install -e .
```

## Usage
### CLI
```bash
# Basic scan
vulnflow scan http://example.com

# Scan with options
vulnflow scan http://example.com -d 3 -m 100 -o report.html -f html

# Start API server
vulnflow server --port 8000
```

### API

```bash
# Start server
vulnflow server

# Create scan
curl -X POST "http://localhost:8000/api/v1/scans" \
     -H "Content-Type: application/json" \
     -d '{"target_url": "http://example.com"}'
```
## Features
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Security header analysis
- CSRF vulnerability detection
- Technology stack fingerprinting
- Contextual remediation advice
- Multiple report formats (JSON, HTML, SARIF)

## License
MIT License