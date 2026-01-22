# VulnFlow

<div align="center">

```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗      ██████╗ ██╗    ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║     ██╔═══██╗██║    ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║     ██║   ██║██║ █╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║     ██║   ██║██║███╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ███████╗╚██████╔╝╚███╔███╔╝
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝
```

**AI-Enhanced Web Vulnerability Scanner with Contextual Remediation**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-orange.svg)](https://owasp.org/Top10/)
[![AI Powered](https://img.shields.io/badge/AI-Groq%20LLM-purple.svg)](https://groq.com/)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [AI Features](#-ai-powered-scanning) • [Documentation](#-documentation) • [API](#-api-server)

</div>

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **🤖 AI-Powered Analysis** | Groq LLM integration for smart payload generation and false positive reduction |
| **⚡ Parallel Scanning Engine** | Concurrent vulnerability testing with configurable workers for maximum speed |
| **🛡️ OWASP Top 10 Coverage** | Complete coverage of OWASP Top 10 2021 vulnerabilities |
| **🔍 33+ Security Modules** | SQLi, XSS, SSRF, IDOR, Command Injection, SSTI, Privilege Escalation, and more |
| **🕷️ Smart Crawling** | Async web crawler with depth control and form detection |
| **🔧 Technology Detection** | Automatic fingerprinting of web technologies |
| **💡 Contextual Remediation** | Framework-specific fix recommendations with code examples |
| **📊 Interactive HTML Reports** | Collapsible findings, search, filtering, and expandable remediation sections |
| **📄 Multiple Report Formats** | JSON, HTML, and SARIF output |
| **🔄 CI/CD Integration** | Exit codes and SARIF for pipeline integration |
| **📈 Performance Metrics** | Detailed timing and throughput statistics |
| **🚦 Rate Limiting** | Configurable rate limiting to avoid detection/blocking |
| **🔐 Authentication Support** | Bearer tokens and proxy support |

---

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnflow.git
cd vulnflow

# Install in development mode
pip install -e .

# Or install with all dependencies
pip install -e ".[dev]"
```

### Requirements

- Python 3.8+
- pip

### Optional Dependencies

```bash
# For enhanced terminal output
pip install rich

# For API server
pip install uvicorn fastapi

# For AI features (recommended)
pip install groq
```

### AI Setup (Recommended)

To enable AI-powered scanning features:

1. Get a free API key from [Groq Console](https://console.groq.com)
2. Set the environment variable:

```bash
# Linux/macOS
export GROQ_API_KEY="your-api-key-here"

# Windows (PowerShell)
$env:GROQ_API_KEY="your-api-key-here"

# Windows (CMD)
set GROQ_API_KEY=your-api-key-here
```

---

## ⚡ Quick Start

### Basic Scan

```bash
# Simple scan with defaults (AI enabled if GROQ_API_KEY is set)
vulnflow scan http://example.com

# Verbose output with timing
vulnflow scan http://example.com -v --timing
```

### AI-Powered Scanning

```bash
# Full AI-enhanced scan (requires GROQ_API_KEY)
vulnflow scan http://example.com --mode full

# Adjust AI confidence threshold
vulnflow scan http://example.com --confidence-threshold 0.8

# Disable AI for faster scanning
vulnflow scan http://example.com --no-ai
```

### Generate Reports

```bash
# Interactive HTML report with remediation
vulnflow scan http://example.com -o report.html -f html

# JSON report for programmatic access
vulnflow scan http://example.com -o report.json --remediation

# SARIF format for CI/CD
vulnflow scan http://example.com -o report.sarif -f sarif
```

### Fast Parallel Scanning

```bash
# High-speed scan with 20 workers
vulnflow scan http://example.com --workers 20

# Maximum performance
vulnflow scan http://example.com -w 30 -c 50 --rate-limit 100
```

---

## 🤖 AI-Powered Scanning

VulnFlow integrates with Groq's LLM (Llama 3.3 70B) to provide intelligent vulnerability analysis.

### AI Features

| Feature | Description |
|---------|-------------|
| **Smart Payload Generation** | Context-aware payloads based on detected technologies |
| **False Positive Reduction** | AI validates findings to reduce noise |
| **Confidence Scoring** | Each finding includes an AI confidence score |
| **Enhanced Analysis** | Deeper vulnerability analysis with AI assistance |

### AI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--no-ai` | `False` | Disable AI-powered analysis |
| `--api-key` | env var | Groq API key (overrides GROQ_API_KEY) |
| `--smart-payloads/--no-smart-payloads` | `True` | Enable/disable AI-generated payloads |
| `--confidence-threshold` | `0.6` | Minimum confidence score (0.0-1.0) |
| `--mode` | `full` | Scan mode: `quick`, `standard`, `owasp`, `full` |

### Scan Modes

| Mode | Description | Speed |
|------|-------------|-------|
| `quick` | Fast scan with common vulnerabilities | ⚡⚡⚡ |
| `standard` | Balanced scan coverage | ⚡⚡ |
| `owasp` | OWASP Top 10 focused scan | ⚡⚡ |
| `full` | Comprehensive scan with all modules | ⚡ |

### Example AI Workflows

```bash
# High-confidence findings only
vulnflow scan http://example.com --confidence-threshold 0.9

# OWASP-focused scan with AI
vulnflow scan http://example.com --mode owasp

# Quick scan without AI (maximum speed)
vulnflow scan http://example.com --mode quick --no-ai

# Full AI scan with custom API key
vulnflow scan http://example.com --api-key "gsk_..." --mode full
```

---

## 📊 Interactive HTML Reports

VulnFlow generates feature-rich, interactive HTML reports with modern UI/UX.

### Report Features

| Feature | Description |
|---------|-------------|
| **🔍 Search** | Real-time search across all vulnerabilities |
| **🏷️ Severity Filtering** | Filter by Critical, High, Medium, Low |
| **📂 Collapsible Cards** | Expand/collapse individual findings |
| **💡 Remediation Sections** | Expandable fix recommendations with code examples |
| **⌨️ Keyboard Shortcuts** | Quick navigation with hotkeys |
| **🖨️ Print-Friendly** | Optimized layout for printing/PDF export |
| **📱 Responsive Design** | Works on desktop, tablet, and mobile |

### Keyboard Shortcuts (HTML Report)

| Key | Action |
|-----|--------|
| `e` | Expand all vulnerability cards |
| `c` | Collapse all cards |
| `/` | Focus search box |
| `Escape` | Clear search and filters |

### Generate Interactive Report

```bash
# Generate interactive HTML report
vulnflow scan http://example.com -o report.html -f html

# With verbose scan and remediation details
vulnflow scan http://example.com -o report.html -f html -v --remediation
```

### Report Screenshot

The HTML report includes:
- **Summary Cards**: Click to filter by severity
- **Search Bar**: Filter vulnerabilities in real-time
- **Vulnerability Cards**: Expandable with full details
- **Remediation Sections**: Collapsible code examples and fix recommendations
- **CWE Links**: Direct links to MITRE CWE database

---

## 📋 Command Reference

### Command Overview

```bash
vulnflow --help
```

| Command | Description |
|---------|-------------|
| `scan` | Scan target URL for vulnerabilities |
| `server` | Start the API server |
| `version` | Show version info and AI status |
| `benchmark` | Run performance benchmark |

---

## 🔍 SCAN Command

```bash
vulnflow scan [OPTIONS] TARGET_URL
```

### Scan Configuration Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--depth` | `-d` | `2` | Maximum crawl depth |
| `--max-pages` | `-m` | `50` | Maximum pages to crawl |

### AI Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--no-ai` | | `False` | Disable AI-powered analysis |
| `--api-key` | | None | Groq API key (overrides env var) |
| `--smart-payloads/--no-smart-payloads` | | `True` | Use AI-generated payloads |
| `--confidence-threshold` | | `0.6` | Minimum confidence score (0.0-1.0) |
| `--mode` | | `full` | Scan mode: `quick`, `standard`, `owasp`, `full` |

### Parallel Execution Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--workers` | `-w` | `8` | Number of concurrent scanner workers |
| `--concurrent-targets` | `-c` | `15` | Number of concurrent targets |

### Performance & Timing Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--timeout` | `-t` | `30` | Request timeout in seconds |
| `--rate-limit` | | `75` | Max requests per second |
| `--timing` | | `False` | Show detailed timing breakdown |
| `--stats` | | `False` | Show execution statistics |
| `--no-timing` | | `False` | Hide timing information |

### Output Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | None | Output file path |
| `--format` | `-f` | `json` | Report format: `json`, `html`, or `sarif` |
| `--verbose` | `-v` | `False` | Enable verbose output |
| `--remediation` | `-r` | `False` | Show remediation advice in terminal |

### CI/CD Integration

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--fail-on` | | `critical` | Exit with error code on severity: `critical`, `high`, `medium`, `any`, `none` |

---

## 🔒 Available Security Modules

VulnFlow includes **32 security scanning modules** organized by vulnerability category:

### Injection Scanners

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `sqli` | A03:2021-Injection | SQL Injection (Union, Blind, Error-based) |
| `nosqli` | A03:2021-Injection | NoSQL Injection (MongoDB, CouchDB) |
| `cmdi` | A03:2021-Injection | OS Command Injection |
| `ssti` | A03:2021-Injection | Server-Side Template Injection |
| `ldapi` | A03:2021-Injection | LDAP Injection |
| `xpath` | A03:2021-Injection | XPath Injection |
| `hhi` | A03:2021-Injection | Host Header Injection |

### Cross-Site Scripting (XSS)

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `xss` | A03:2021-Injection | Reflected & Stored XSS |
| `dom_xss` | A03:2021-Injection | DOM-based XSS |

### Access Control

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `idor` | A01:2021-Broken Access Control | Insecure Direct Object Reference |
| `path_traversal` | A01:2021-Broken Access Control | Path/Directory Traversal |
| `forced_browsing` | A01:2021-Broken Access Control | Forced Browsing / Authorization Bypass |
| `privilege_escalation` | A01:2021-Broken Access Control | Vertical & Horizontal Privilege Escalation |
| `jwt_vulnerabilities` | A01:2021-Broken Access Control | JWT Algorithm Confusion, Weak Secrets |

### Security Misconfiguration

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `headers` | A05:2021-Security Misconfiguration | Missing Security Headers |
| `cors` | A05:2021-Security Misconfiguration | CORS Misconfiguration |
| `debug` | A05:2021-Security Misconfiguration | Debug Mode / Stack Traces Exposed |
| `backup` | A05:2021-Security Misconfiguration | Backup & Config File Exposure |
| `ssl_tls` | A05:2021-Security Misconfiguration | SSL/TLS Vulnerabilities |
| `cookie_security` | A05:2021-Security Misconfiguration | Insecure Cookie Attributes |
| `information_disclosure` | A05:2021-Security Misconfiguration | Sensitive Information Disclosure |

### Server-Side Request Forgery (SSRF)

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `ssrf` | A10:2021-SSRF | Server-Side Request Forgery |

### XML External Entity (XXE)

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `xxe` | A05:2021-Security Misconfiguration | XML External Entity Injection |

### Insecure Deserialization

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `insecure_deserialization` | A08:2021-Software and Data Integrity Failures | Insecure Deserialization |

### API Security

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `rate_limiting` | A04:2021-Insecure Design | Missing/Weak Rate Limiting |
| `mass_assignment` | A04:2021-Insecure Design | Mass Assignment / Parameter Pollution |
| `graphql` | A04:2021-Insecure Design | GraphQL Introspection & Injection |

### Authentication

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `brute_force` | A07:2021-Identification and Authentication Failures | Brute Force Attack Susceptibility |
| `session_fixation` | A07:2021-Identification and Authentication Failures | Session Fixation |
| `weak_password` | A07:2021-Identification and Authentication Failures | Weak Password Policy |

### Cryptographic Failures

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `weak_crypto` | A02:2021-Cryptographic Failures | Weak Encryption Algorithms |
| `sensitive_data_exposure` | A02:2021-Cryptographic Failures | Sensitive Data Exposure |

### Known Vulnerabilities

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `known_cve` | A06:2021-Vulnerable and Outdated Components | Known CVE Detection |

---

## 📚 Usage Examples

### Basic Scans

```bash
# Simple scan with defaults (AI enabled)
vulnflow scan http://example.com

# Verbose with timing breakdown
vulnflow scan http://example.com -v --timing

# Check version and AI status
vulnflow version
```

### AI-Powered Scanning

```bash
# Full AI-enhanced scan
vulnflow scan http://example.com --mode full

# High-confidence findings only
vulnflow scan http://example.com --confidence-threshold 0.85

# OWASP Top 10 focused with AI
vulnflow scan http://example.com --mode owasp

# Disable AI for speed
vulnflow scan http://example.com --no-ai --workers 20
```

### Performance Tuning

```bash
# High concurrency parallel scan
vulnflow scan http://example.com -w 20 -c 30

# Maximum speed with rate limiting
vulnflow scan http://example.com -w 50 -c 100 --rate-limit 200

# Large site scan with timing
vulnflow scan http://example.com -d 4 -m 500 -w 30 --timing --stats
```

### Report Generation

```bash
# Interactive HTML report
vulnflow scan http://example.com -o report.html -f html

# JSON report with remediation
vulnflow scan http://example.com -o report.json --remediation

# SARIF format (for GitHub/GitLab integration)
vulnflow scan http://example.com -o report.sarif -f sarif

# Full verbose scan with HTML report
vulnflow scan http://example.com -v --remediation --timing -o report.html -f html
```

### CI/CD Pipeline Integration

```bash
# Fail pipeline if critical vulnerabilities found (exit code 2)
vulnflow scan http://example.com --fail-on critical

# Fail on high or critical (exit code 1)
vulnflow scan http://example.com --fail-on high

# Full CI/CD example with SARIF output
vulnflow scan http://staging.example.com \
    -w 30 \
    -o scan-results.sarif \
    -f sarif \
    --fail-on high \
    --no-timing
```

### Complete Production Scan

```bash
vulnflow scan https://target.com \
    --mode full \
    --confidence-threshold 0.7 \
    --workers 25 \
    --concurrent-targets 50 \
    --timeout 20 \
    --rate-limit 100 \
    --depth 3 \
    --max-pages 100 \
    --output full-report.html \
    --format html \
    --verbose \
    --remediation \
    --timing \
    --stats \
    --fail-on high
```

---

## 📈 Performance Metrics & Timing

VulnFlow includes detailed performance tracking:

### Basic Timing (Default)

```
⏱️  Total scan time: 12.45s
```

### Detailed Timing (`--timing` flag)

```
╭──────────────────── ⚡ Scan Performance ────────────────────╮
│                                                              │
│ ⏱️  Total Scan Time: 12.45s                                  │
│                                                              │
│ Performance Metrics:                                         │
│   • Pages scanned: 47 (3.8 pages/sec)                       │
│   • Forms tested: 12 (1.0 forms/sec)                        │
│   • Vulnerabilities found: 5                                 │
│                                                              │
╰──────────────────────────────────────────────────────────────╯

              📊 Phase Breakdown
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Phase                      ┃   Duration ┃ % of Total ┃ Progress           ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ AI-Enhanced Scanning       │     8.23s  │     66.1%  │ ██████████░░░░░    │
│ Crawling                   │     3.12s  │     25.1%  │ ████░░░░░░░░░░░    │
│ Technology Detection       │     0.87s  │      7.0%  │ █░░░░░░░░░░░░░░    │
│ Remediation Generation     │     0.23s  │      1.8%  │ ░░░░░░░░░░░░░░░    │
└────────────────────────────┴────────────┴────────────┴────────────────────┘
```

### AI Statistics (`--stats` flag with AI enabled)

```
              ⚡ Execution Statistics
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Metric                    ┃        Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ AI Enhanced Findings      │           12 │
│ False Positives Filtered  │            3 │
│ Total Duration            │        8.23s │
│ Throughput                │ 18.7 tasks/s │
└───────────────────────────┴──────────────┘
```

---

## 🌐 API Server

### Start Server

```bash
# Default (0.0.0.0:8000)
vulnflow server

# Custom port
vulnflow server -p 8080

# Localhost only
vulnflow server -h 127.0.0.1 -p 3000
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Create new scan |
| `GET` | `/api/v1/scans/{id}` | Get scan status |
| `GET` | `/api/v1/scans/{id}/results` | Get scan results |
| `GET` | `/api/v1/scans` | List all scans |
| `DELETE` | `/api/v1/scans/{id}` | Cancel scan |

### API Usage Examples

```bash
# Create a new AI-enhanced scan
curl -X POST "http://localhost:8000/api/v1/scans" \
     -H "Content-Type: application/json" \
     -d '{
       "target_url": "http://example.com",
       "config": {
         "depth": 2,
         "max_pages": 50,
         "workers": 10,
         "ai_enabled": true,
         "confidence_threshold": 0.6
       }
     }'

# Get scan status
curl "http://localhost:8000/api/v1/scans/{scan_id}"

# Get scan results
curl "http://localhost:8000/api/v1/scans/{scan_id}/results"
```

### API Documentation

When the server is running, interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key for AI features | None |
| `VULNFLOW_WORKERS` | Default number of workers | `8` |
| `VULNFLOW_TIMEOUT` | Default timeout (seconds) | `30` |
| `VULNFLOW_RATE_LIMIT` | Default rate limit (req/s) | `75` |
| `VULNFLOW_LOG_LEVEL` | Logging level | `INFO` |

### Configuration File

Create `vulnflow.yaml` in your project root:

```yaml
scan:
  depth: 3
  max_pages: 100
  timeout: 30
  mode: full
  
ai:
  enabled: true
  confidence_threshold: 0.6
  smart_payloads: true
  
parallel:
  enabled: true
  workers: 10
  concurrent_targets: 20
  rate_limit: 75

output:
  format: html
  include_remediation: true
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install VulnFlow
        run: pip install vulnflow
      
      - name: Run Security Scan
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
        run: |
          vulnflow scan ${{ secrets.TARGET_URL }} \
            --mode owasp \
            --workers 20 \
            --output results.sarif \
            --format sarif \
            --fail-on high
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.10
  variables:
    GROQ_API_KEY: $GROQ_API_KEY
  script:
    - pip install vulnflow
    - vulnflow scan $TARGET_URL -o report.sarif -f sarif --fail-on high
  artifacts:
    reports:
      sast: report.sarif
  only:
    - main
    - merge_requests
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    environment {
        GROQ_API_KEY = credentials('groq-api-key')
    }
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    pip install vulnflow
                    vulnflow scan ${TARGET_URL} \
                        --mode full \
                        --workers 20 \
                        --output report.html \
                        --format html \
                        --fail-on high
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'report.html'
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'report.html',
                        reportName: 'VulnFlow Security Report'
                    ])
                }
            }
        }
    }
}
```

---

## 🚪 Exit Codes

| Code | Description |
|------|-------------|
| `0` | Scan completed, no issues above threshold |
| `1` | Scan completed, high severity issues found |
| `2` | Scan completed, critical severity issues found |
| `130` | Scan interrupted by user (Ctrl+C) |

---

## 📋 Quick Reference Card

```bash
# Essential Commands
vulnflow scan <URL>                              # Full AI-enhanced scan
vulnflow scan <URL> --no-ai -w 20                # Fast scan without AI
vulnflow scan <URL> --mode owasp                 # OWASP Top 10 focused
vulnflow scan <URL> -o report.html -f html       # Interactive HTML report
vulnflow scan <URL> --fail-on high               # CI/CD mode
vulnflow scan <URL> -v --timing --stats          # Full metrics
vulnflow scan <URL> --remediation                # Show fix advice
vulnflow server                                  # Start API
vulnflow version                                 # Check AI status

# AI Configuration
vulnflow scan <URL> --confidence-threshold 0.8   # High confidence only
vulnflow scan <URL> --no-smart-payloads          # Disable AI payloads
vulnflow scan <URL> --api-key "gsk_..."          # Custom API key

# Performance Comparison
vulnflow scan <URL> --no-ai -w 30 --timing       # Maximum speed
vulnflow scan <URL> --mode quick --timing        # Quick AI scan
vulnflow scan <URL> --mode full --timing         # Comprehensive scan
```

---

## ⚠️ Disclaimer

VulnFlow is designed for authorized security testing only. Always obtain proper authorization before scanning any systems you do not own. The developers are not responsible for any misuse of this tool.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.