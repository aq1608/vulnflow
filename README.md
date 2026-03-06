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

**AI-Enhanced Web Vulnerability Scanner with Browser-Based Detection & Contextual Remediation**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202025-orange.svg)](https://owasp.org/Top10/)
[![AI Powered](https://img.shields.io/badge/AI-Groq%20LLM-purple.svg)](https://groq.com/)
[![Playwright](https://img.shields.io/badge/Browser-Playwright-green.svg)](https://playwright.dev/)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Playwright Scanning](#-playwright-browser-based-scanning) • [Authentication](#-authentication) • [AI Features](#-ai-powered-scanning) • [Documentation](#-documentation) • [API](#-api-server)

</div>

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **🎭 Playwright Browser Scanning** | Real browser-based XSS and SQLi detection — catches DOM XSS in Angular/React/Vue SPAs |
| **🤖 AI-Powered Analysis** | Groq LLM integration for smart payload generation and false positive reduction |
| **⚡ Parallel Scanning Engine** | Concurrent vulnerability testing with configurable workers and auto-tuning |
| **🛡️ OWASP Top 10 2025** | Complete coverage of all 10 categories in the OWASP Top 10 2025 standard |
| **🔍 35+ Security Modules** | SQLi, XSS, SSRF, IDOR, SSTI, XXE, CRLF, EL Injection, and many more |
| **🕷️ SPA-Aware Crawling** | Playwright-powered crawler that handles Angular, React, and Vue hash routing |
| **🔐 Full Authentication** | Login forms, JSON API auth, bearer tokens, cookies, basic auth, custom headers |
| **💉 Database Enumeration** | Automatic database type detection, table extraction, and data exfiltration via SQLi |
| **🔧 Technology Detection** | Automatic fingerprinting of web technologies and frameworks |
| **💡 Contextual Remediation** | Framework-specific fix recommendations with code examples |
| **📊 Interactive HTML Reports** | Collapsible findings, search, filtering, and expandable remediation sections |
| **📄 Multiple Report Formats** | JSON, HTML, and SARIF output |
| **🔄 CI/CD Integration** | Exit codes and SARIF for pipeline integration |
| **📈 Performance Metrics** | Detailed timing, throughput statistics, and OWASP coverage display |
| **🎯 Auto-Tuning** | Automatic concurrency reduction for lab / CTF targets to prevent DoS |
| **⏱️ Global Timeouts** | Phase-level timeouts and early termination on high failure rates |

---

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/aq1608/vulnflow.git
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
# For browser-based scanning (XSS, SQLi, SPA crawling) — HIGHLY RECOMMENDED
pip install playwright
playwright install chromium

# For enhanced terminal output
pip install rich

# For API server
pip install uvicorn fastapi

# For AI features
pip install groq
```

### AI Setup (Optional)

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
# Simple scan with defaults
vulnflow scan http://example.com

# SPA-aware scan with Playwright crawler + browser-based detection
vulnflow scan http://example.com --spa

# Verbose output with timing
vulnflow scan http://example.com --spa -v --timing
```

### Scan a Lab / CTF Target (Juice Shop, DVWA, etc.)

```bash
# Recommended settings for Juice Shop or similar targets
vulnflow scan http://localhost:3000 \
    --spa \
    --mode standard \
    --login-url http://localhost:3000/rest/user/login \
    --username admin@juice-sh.op \
    --password admin123 \
    -v --timing

# Full scan with lower concurrency (prevents overwhelming the target)
vulnflow scan http://192.168.1.100:42000 \
    --spa \
    --mode full \
    --workers 4 \
    --concurrent-targets 5 \
    --rate-limit 15 \
    --timeout 10 \
    -v
```

### Generate Reports

```bash
# Interactive HTML report with remediation
vulnflow scan http://example.com --spa -o report.html -f html

# JSON report for programmatic access
vulnflow scan http://example.com -o report.json --remediation

# SARIF format for CI/CD
vulnflow scan http://example.com -o report.sarif -f sarif
```

---

## 🎭 Playwright Browser-Based Scanning

VulnFlow uses real Chromium browsers via Playwright to detect vulnerabilities that traditional HTTP scanners miss — especially in modern SPAs.

### What It Catches

| Detection | How It Works |
|-----------|-------------|
| **DOM XSS in Angular/React/Vue** | Injects payloads into hash-routed URLs, waits for the SPA to render, detects `alert()` dialogs |
| **SQL Injection via Login Forms** | Fills login forms with SQLi payloads, detects authentication bypass |
| **SQL Injection via Search** | Tests search endpoints that use dynamic queries |
| **Database Enumeration** | Extracts database type, table names, and data via confirmed SQLi |
| **Authentication Bypass** | Detects admin access via `' OR 1=1--` and similar payloads |

### Playwright Features

| Feature | Description |
|---------|-------------|
| **Popup Dismissal** | Automatically dismisses welcome dialogs, cookie consent banners |
| **Hash Navigation** | Uses `window.location.hash` to avoid URL encoding issues in SPAs |
| **API Response Waiting** | Waits for Angular/React API calls to complete before checking DOM |
| **Sequential Execution** | SQLi scanner runs first, then XSS — prevents overwhelming single-threaded targets |
| **Auth Token Injection** | Sets bearer tokens in `localStorage` for authenticated scanning |
| **Dialog Detection** | Catches `alert()`, `confirm()`, `prompt()` dialogs as XSS proof |

### Playwright Options

| Option | Default | Description |
|--------|---------|-------------|
| `--spa` | `False` | Enable SPA-aware Playwright crawler |
| `--headless/--no-headless` | `True` | Run browser in headless mode (use `--no-headless` for debugging) |

### Example: Debugging XSS with Visible Browser

```bash
# Run with visible browser to see what Playwright is doing
vulnflow scan http://localhost:3000 --spa --no-headless -v
```

---

## 🔐 Authentication

VulnFlow supports multiple authentication methods for scanning protected areas.

### JSON API Login (Recommended for SPAs)

```bash
vulnflow scan http://localhost:3000 --spa \
    --login-url http://localhost:3000/rest/user/login \
    --username admin@juice-sh.op \
    --password admin123 \
    --auth-method json \
    --username-field email \
    --password-field password
```

### Form-Based Login

```bash
vulnflow scan http://example.com --spa \
    --login-url http://example.com/login \
    --username admin \
    --password password123 \
    --auth-method form
```

### Bearer Token

```bash
vulnflow scan http://example.com \
    --bearer-token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Cookie-Based Authentication

```bash
vulnflow scan http://example.com \
    --cookies '{"session": "abc123", "csrf_token": "xyz789"}'
```

### Basic Auth

```bash
vulnflow scan http://example.com \
    --basic-auth "admin:password123"
```

### Custom Headers

```bash
vulnflow scan http://example.com \
    --auth-header "X-API-Key: abc123" \
    --auth-header "X-Custom-Token: xyz789"
```

### Authentication Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--login-url` | None | Login URL for form/API authentication |
| `--username` / `-u` | None | Username or email |
| `--password` / `-p` | None | Password |
| `--username-field` | `email` | Form field name for username |
| `--password-field` | `password` | Form field name for password |
| `--auth-method` | `json` | Method: `form`, `json`, `basic`, `bearer`, `cookie` |
| `--bearer-token` | None | Bearer token for API auth |
| `--cookies` | None | Cookies as JSON string |
| `--basic-auth` | None | Basic auth as `username:password` |
| `--auth-header` | None | Custom header (repeatable) |

---

## 🤖 AI-Powered Scanning

VulnFlow optionally integrates with Groq's LLM (Llama 3.3 70B) for intelligent vulnerability analysis. AI features are **optional** — the scanner works fully without them.

### AI Features

| Feature | Description |
|---------|-------------|
| **Smart Payload Generation** | Context-aware payloads based on detected technologies |
| **False Positive Reduction** | AI validates findings to reduce noise |
| **Confidence Scoring** | Each finding includes an AI confidence score |
| **Severity Adjustment** | AI can upgrade/downgrade severity based on context |
| **Business Impact Analysis** | AI assesses real-world exploitation risk |

### AI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--no-ai` | `False` | Disable AI-powered analysis |
| `--api-key` | env var | Groq API key (overrides `GROQ_API_KEY`) |
| `--smart-payloads/--no-smart-payloads` | `True` | Enable/disable AI-generated payloads |
| `--confidence-threshold` | `0.6` | Minimum confidence score (0.0–1.0) |

### AI Workflows

```bash
# High-confidence findings only
vulnflow scan http://example.com --confidence-threshold 0.9

# Disable AI for maximum speed
vulnflow scan http://example.com --no-ai --workers 20

# Full AI scan with custom API key
vulnflow scan http://example.com --api-key "gsk_..." --mode full
```

---

## 🛡️ OWASP Top 10 2025 Coverage

VulnFlow's 35+ scanners are organized by the **OWASP Top 10 2025** standard:

### A01:2025 — Broken Access Control

| Module | Description |
|--------|-------------|
| `idor` | Insecure Direct Object Reference |
| `path_traversal` | Path / Directory Traversal |
| `forced_browsing` | Forced Browsing / Authorisation Bypass |
| `privilege_escalation` | Vertical & Horizontal Privilege Escalation |
| `jwt` | JWT Algorithm Confusion, Weak Secrets, None Algorithm |
| `ssrf` | Server-Side Request Forgery *(moved from A10:2021)* |
| `csrf` | Cross-Site Request Forgery |
| `open_redirect` | Open Redirect |

### A02:2025 — Security Misconfiguration

| Module | Description |
|--------|-------------|
| `headers` | Missing Security Headers (CSP, HSTS, X-Frame-Options, etc.) |
| `cors` | CORS Misconfiguration |
| `debug` | Debug Mode / Stack Traces Exposed |
| `backup` | Backup & Config File Exposure |
| `ssl_tls` | SSL/TLS Vulnerabilities |
| `cookie_security` | Insecure Cookie Attributes |
| `information_disclosure` | Sensitive Information Disclosure |
| `config_exposure` | Configuration File Exposure |

### A03:2025 — Software Supply Chain Failures

| Module | Description |
|--------|-------------|
| `known_cve` | Known CVE Detection |
| `dependency_check` | Dependency Vulnerability Check |
| `integrity_check` | Subresource / Script Integrity |
| `outdated_components` | Outdated Framework / Library Detection |

### A04:2025 — Cryptographic Failures

| Module | Description |
|--------|-------------|
| `weak_crypto` | Weak Encryption Algorithms |
| `sensitive_data_exposure` | Sensitive Data in Transit / Storage |

### A05:2025 — Injection

| Module | Description |
|--------|-------------|
| `sqli` | SQL Injection (Union, Blind, Error-based) |
| `nosqli` | NoSQL Injection (MongoDB, CouchDB) |
| `xss` | Reflected & Stored XSS |
| `dom_xss` | DOM-based XSS |
| `cmdi` | OS Command Injection |
| `ssti` | Server-Side Template Injection |
| `ldapi` | LDAP Injection |
| `xpath` | XPath Injection |
| `hhi` | Host Header Injection |
| `xxe` | XML External Entity Injection |
| `code_injection` | Code Injection |
| `crlf` | CRLF Injection |
| `el_injection` | Expression Language Injection |
| **🎭 Playwright XSS** | Browser-based DOM XSS detection (Angular, React, Vue) |
| **🎭 Playwright SQLi** | Browser-based SQL Injection + Database Enumeration |

### A06:2025 — Insecure Design

| Module | Description |
|--------|-------------|
| `rate_limiting` | Missing / Weak Rate Limiting |
| `business_logic` | Business Logic Flaws |
| `clickjacking` | Clickjacking |
| `file_upload` | Unrestricted File Upload |
| `http_smuggling` | HTTP Request Smuggling |
| `race_condition` | Race Condition / TOCTOU |
| `trust_boundary` | Trust Boundary Violation |

### A07:2025 — Authentication Failures

| Module | Description |
|--------|-------------|
| `auth_bypass` | Authentication Bypass |
| `brute_force` | Brute Force Susceptibility |
| `mfa_check` | Missing MFA |
| `session_fixation` | Session Fixation |
| `session_management` | Weak Session Management |
| `weak_password` | Weak Password Policy |

### A08:2025 — Software or Data Integrity Failures

| Module | Description |
|--------|-------------|
| `deserialization` | Insecure Deserialisation |
| `code_integrity` | Code Integrity Verification |
| `cookie_integrity` | Cookie Integrity / Tampering |

### A09:2025 — Security Logging and Alerting Failures

| Module | Description |
|--------|-------------|
| `log_injection` | Log Injection |
| `sensitive_log_data` | Sensitive Data in Logs |
| `log_file_exposure` | Log File Exposure |
| `insufficient_logging` | Insufficient Logging |
| `alert_detection` | Missing Security Alerting |

### A10:2025 — Mishandling of Exceptional Conditions 🆕

| Module | Description |
|--------|-------------|
| `error_handling` | Improper Error Handling |
| `fail_open` | Fail-Open Conditions |
| `resource_limits` | Resource Limit Enforcement |

### API Security (Additional)

| Module | Description |
|--------|-------------|
| `graphql` | GraphQL Introspection & Injection |
| `mass_assignment` | Mass Assignment / Parameter Pollution |

---

## 📋 Scan Modes

| Mode | Scanners | Use Case | Speed |
|------|----------|----------|-------|
| `quick` | 5 | Fast check for critical issues | ⚡⚡⚡ |
| `standard` | 17 | Balanced coverage for most targets | ⚡⚡ |
| `owasp` | 25 | OWASP Top 10 focused | ⚡⚡ |
| `full` | 35+ | Every scanner — comprehensive audit | ⚡ |
| `api` | 14 | API-focused (REST, GraphQL) | ⚡⚡ |
| `injection` | 13 | Injection-only (SQLi, XSS, SSTI, etc.) | ⚡⚡ |
| `auth` | 9 | Authentication & session focused | ⚡⚡ |

```bash
# Use a specific mode
vulnflow scan http://example.com --mode owasp

# Quick check
vulnflow scan http://example.com --mode quick

# API security audit
vulnflow scan http://api.example.com --mode api
```

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

### Scan Configuration

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--depth` | `-d` | `2` | Maximum crawl depth |
| `--max-pages` | `-m` | `50` | Maximum pages to crawl |
| `--mode` | | `full` | Scan mode: `quick`, `standard`, `owasp`, `full`, `api`, `injection`, `auth` |
| `--spa` | | `False` | Enable SPA / Playwright crawler |
| `--headless/--no-headless` | | `True` | Browser headless mode |

### Parallel Execution

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--workers` | `-w` | `8` | Concurrent scanner workers |
| `--concurrent-targets` | `-c` | `15` | Concurrent targets |
| `--timeout` | `-t` | `30` | Timeout per scan (seconds) |
| `--rate-limit` | | `75` | Max requests per second |

> **Auto-tuning**: When scanning lab targets (localhost, 192.168.x.x, :3000, etc.), VulnFlow automatically reduces concurrency and timeouts to prevent overwhelming the target.

### Output

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | None | Output file path |
| `--format` | `-f` | `json` | Report format: `json`, `html`, `sarif` |
| `--verbose` | `-v` | `False` | Verbose output |
| `--remediation` | `-r` | `False` | Show remediation advice |
| `--timing` | | `False` | Detailed timing breakdown |
| `--stats` | | `False` | Execution statistics |
| `--no-timing` | | `False` | Hide timing info |

### CI/CD

| Option | Default | Description |
|--------|---------|-------------|
| `--fail-on` | `critical` | Exit threshold: `critical`, `high`, `medium`, `any`, `none` |

---

## 📚 Usage Examples

### SPA / Modern Web Application

```bash
# Angular / React / Vue app with SPA crawling
vulnflow scan http://localhost:3000 --spa -v

# With authentication
vulnflow scan http://localhost:3000 --spa \
    --login-url http://localhost:3000/rest/user/login \
    --username admin@juice-sh.op \
    --password admin123

# Debug mode — see the browser
vulnflow scan http://localhost:3000 --spa --no-headless -v
```

### Traditional Web Application

```bash
# Standard server-rendered app
vulnflow scan http://example.com --mode full -v --timing

# With basic auth
vulnflow scan http://example.com --basic-auth "admin:secret"
```

### Performance Tuning

```bash
# High concurrency for robust targets
vulnflow scan http://example.com -w 20 -c 30 --rate-limit 100

# Low concurrency for fragile targets
vulnflow scan http://192.168.1.100:3000 --spa \
    --workers 3 --concurrent-targets 5 --rate-limit 15 --timeout 10

# Maximum speed, no AI
vulnflow scan http://example.com --no-ai --workers 30 --mode quick
```

### Reports

```bash
# Interactive HTML report
vulnflow scan http://example.com -o report.html -f html

# JSON report with remediation
vulnflow scan http://example.com -o report.json --remediation

# SARIF for GitHub Advanced Security
vulnflow scan http://example.com -o report.sarif -f sarif

# Full verbose report
vulnflow scan http://example.com -v --remediation --timing -o report.html -f html
```

### Complete Production Scan

```bash
vulnflow scan https://target.com \
    --spa \
    --mode full \
    --login-url https://target.com/api/auth/login \
    --username scanner@company.com \
    --password "$SCANNER_PASSWORD" \
    --auth-method json \
    --confidence-threshold 0.7 \
    --workers 20 \
    --concurrent-targets 30 \
    --timeout 20 \
    --rate-limit 80 \
    --depth 3 \
    --max-pages 200 \
    --output full-report.html \
    --format html \
    --verbose \
    --remediation \
    --timing \
    --stats \
    --fail-on high
```

---

## 📊 Interactive HTML Reports

### Report Features

| Feature | Description |
|---------|-------------|
| **🔍 Search** | Real-time search across all vulnerabilities |
| **🏷️ Severity Filtering** | Filter by Critical, High, Medium, Low |
| **📂 Collapsible Cards** | Expand/collapse individual findings |
| **💡 Remediation Sections** | Expandable fix recommendations with code examples |
| **⌨️ Keyboard Shortcuts** | Quick navigation with hotkeys |
| **🖨️ Print-Friendly** | Optimised layout for printing / PDF export |
| **📱 Responsive Design** | Works on desktop, tablet, and mobile |

### Keyboard Shortcuts (HTML Report)

| Key | Action |
|-----|--------|
| `e` | Expand all vulnerability cards |
| `c` | Collapse all cards |
| `/` | Focus search box |
| `Escape` | Clear search and filters |

---

## 📈 Performance Metrics & Timing

### OWASP Coverage Display

```
[*] OWASP 2025 Coverage:
  ✓ A01: Broken Access Control  [████████░░] 80%
  ✓ A02: Security Misconfig     [███████░░░] 70%
  ✓ A03: Supply Chain Failures  [██████████] 100%
  ✓ A04: Cryptographic Failures [██████████] 100%
  ✓ A05: Injection              [██████████] 100%
  ✓ A06: Insecure Design        [█████████░] 90%
  ✓ A07: Auth Failures          [████████░░] 80%
  ✓ A08: Data Integrity         [██████████] 100%
  ✓ A09: Logging Failures       [██████████] 100%
  ✓ A10: Exceptional Conditions [██████████] 100%
```

### Scan Summary

```
══════════════════════════════════════════════════════
  Scan Complete in 47.23s
  Validated Vulnerabilities: 14
  Playwright XSS Findings: 2
  Playwright SQLi Findings: 6
  Auth Bypass Findings: 3
  Database Enumerated: Yes
    Tables Found: 12
    Data Extracted: Yes

  Findings by OWASP 2025 Category:
    A01: 3 findings (🟠2 🟡1)
    A02: 4 findings (🟡3 🔵1)
    A05: 7 findings (🔴1 🟠4 🟡2)
══════════════════════════════════════════════════════
```

### Detailed Timing (`--timing` flag)

```
╭──────────────────── ⚡ Scan Performance ────────────────────╮
│ ⏱️  Total Scan Time: 47.23s                                  │
│                                                              │
│ Performance Metrics:                                         │
│   • Pages scanned: 47 (3.8 pages/sec)                       │
│   • Forms tested: 12 (1.0 forms/sec)                        │
│   • Vulnerabilities found: 14                                │
╰──────────────────────────────────────────────────────────────╯

              📊 Phase Breakdown
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Phase                      ┃   Duration ┃ % of Total ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Crawling                   │     5.12s  │     10.8%  │
│ Technology Detection       │     0.87s  │      1.8%  │
│ Vulnerability Scanning     │    40.01s  │     84.7%  │
│ Remediation Generation     │     1.23s  │      2.6%  │
└────────────────────────────┴────────────┴────────────┘
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

### API Usage

```bash
# Create scan
curl -X POST "http://localhost:8000/api/v1/scans" \
     -H "Content-Type: application/json" \
     -d '{
       "target_url": "http://example.com",
       "config": {
         "depth": 2,
         "max_pages": 50,
         "workers": 10,
         "mode": "full",
         "playwright_xss": true,
         "playwright_sqli": true
       }
     }'

# Get results
curl "http://localhost:8000/api/v1/scans/{scan_id}/results"
```

### API Documentation

When the server is running:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key for AI features | None |
| `VULNFLOW_WORKERS` | Default number of workers | `8` |
| `VULNFLOW_TIMEOUT` | Default timeout (seconds) | `20` |
| `VULNFLOW_RATE_LIMIT` | Default rate limit (req/s) | `75` |
| `VULNFLOW_LOG_LEVEL` | Logging level | `INFO` |

### Configuration File

Create `vulnflow.yaml` in your project root:

```yaml
scan:
  depth: 3
  max_pages: 100
  timeout: 20
  mode: full

playwright:
  xss: true
  sqli: true
  enumerate_db: true
  headless: true

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
          python-version: '3.11'

      - name: Install VulnFlow
        run: |
          pip install vulnflow
          pip install playwright
          playwright install chromium

      - name: Run Security Scan
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
        run: |
          vulnflow scan ${{ secrets.TARGET_URL }} \
            --spa \
            --mode owasp \
            --workers 10 \
            --output results.sarif \
            --format sarif \
            --fail-on high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.11
  variables:
    GROQ_API_KEY: $GROQ_API_KEY
  before_script:
    - pip install vulnflow playwright
    - playwright install chromium --with-deps
  script:
    - vulnflow scan $TARGET_URL --spa -o report.sarif -f sarif --fail-on high
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
                    pip install vulnflow playwright
                    playwright install chromium
                    vulnflow scan ${TARGET_URL} \
                        --spa \
                        --mode full \
                        --workers 15 \
                        --output report.html \
                        --format html \
                        --fail-on high
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'report.html'
                    publishHTML([
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
# ── Essential Commands ─────────────────────────────────
vulnflow scan <URL>                                 # Default scan
vulnflow scan <URL> --spa                           # SPA-aware scan
vulnflow scan <URL> --spa --no-headless -v          # Debug with visible browser
vulnflow scan <URL> --no-ai --mode quick            # Fastest possible
vulnflow scan <URL> -o report.html -f html          # HTML report
vulnflow scan <URL> --fail-on high                  # CI/CD mode
vulnflow server                                     # Start API
vulnflow version                                    # Check status

# ── Authentication ─────────────────────────────────────
vulnflow scan <URL> --spa \
    --login-url <URL>/api/login \
    --username admin --password pass                # JSON login

vulnflow scan <URL> --bearer-token "eyJ..."         # Bearer token
vulnflow scan <URL> --basic-auth "user:pass"        # Basic auth
vulnflow scan <URL> --cookies '{"sid":"abc"}'       # Cookies

# ── Scan Modes ─────────────────────────────────────────
vulnflow scan <URL> --mode quick                    # 5 scanners
vulnflow scan <URL> --mode standard                 # 17 scanners
vulnflow scan <URL> --mode owasp                    # 25 scanners
vulnflow scan <URL> --mode full                     # All 35+
vulnflow scan <URL> --mode api                      # API-focused
vulnflow scan <URL> --mode injection                # Injection-only
vulnflow scan <URL> --mode auth                     # Auth-focused

# ── Performance ────────────────────────────────────────
vulnflow scan <URL> -w 3 -c 5 --rate-limit 15      # Lab target
vulnflow scan <URL> -w 20 -c 30 --rate-limit 100   # Robust target
vulnflow scan <URL> -v --timing --stats             # Full metrics

# ── AI ─────────────────────────────────────────────────
vulnflow scan <URL> --confidence-threshold 0.9      # High confidence
vulnflow scan <URL> --no-ai                         # Disable AI
vulnflow scan <URL> --api-key "gsk_..."             # Custom key
```

---

## 🏗️ Architecture

```
vulnflow/
├── cli/                    # CLI entry point (Click)
│   └── main.py
├── crawler/                # Web crawlers
│   ├── spider.py           # Traditional async HTTP crawler
│   └── spa_spider.py       # Playwright SPA-aware crawler
├── detector/               # Technology fingerprinting
├── scanner/                # Vulnerability scanners
│   ├── base.py             # Base classes (Vulnerability, Severity, etc.)
│   ├── vuln_scanner.py     # Main orchestrator (no AI)
│   ├── enhanced_vuln_scanner.py  # AI-enhanced orchestrator
│   ├── parallel_executor.py      # Parallel execution engine
│   ├── a01_access_control/ # OWASP A01 scanners
│   ├── a02_misconfig/      # OWASP A02 scanners
│   ├── a03_supply_chain/   # OWASP A03 scanners
│   ├── a04_cryptographic/  # OWASP A04 scanners
│   ├── a05_injection/      # OWASP A05 scanners (incl. Playwright XSS/SQLi)
│   ├── a06_insecure_design/
│   ├── a07_authentication/
│   ├── a08_deserialization/
│   ├── a09_logging/
│   ├── a10_exceptional_conditions/  # 🆕 New in 2025
│   ├── api_security/
│   ├── cve/
│   └── xxe/
├── remediation/            # Remediation advice engine
├── reports/                # Report generators (JSON, HTML, SARIF)
└── api/                    # FastAPI REST server
```

---

## ⚠️ Disclaimer

VulnFlow is designed for **authorised security testing only**. Always obtain proper written authorisation before scanning any systems you do not own. The developers are not responsible for any misuse of this tool.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.