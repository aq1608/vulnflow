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

**Web Vulnerability Scanner with Contextual Remediation**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-orange.svg)](https://owasp.org/Top10/)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [API](#-api-server)

</div>

---

## Features

| Feature | Description |
|---------|-------------|
| **Parallel Scanning Engine** | Concurrent vulnerability testing with configurable workers for maximum speed |
| **OWASP Top 10 Coverage** | Complete coverage of OWASP Top 10 2021 vulnerabilities |
| **12 Security Modules** | SQLi, XSS, SSRF, IDOR, Command Injection, SSTI, and more |
| **Smart Crawling** | Async web crawler with depth control and form detection |
| **Technology Detection** | Automatic fingerprinting of web technologies |
| **Contextual Remediation** | Framework-specific fix recommendations |
| **Multiple Report Formats** | JSON, HTML, and SARIF output |
| **CI/CD Integration** | Exit codes and SARIF for pipeline integration |
| **Performance Metrics** | Detailed timing and throughput statistics |
| **Rate Limiting** | Configurable rate limiting to avoid detection/blocking |
| **Authentication Support** | Bearer tokens and proxy support |

---

## Installation

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
```

---

## Quick Start

### Basic Scan

```bash
# Simple scan with defaults
vulnflow scan http://example.com

# Verbose output with timing
vulnflow scan http://example.com -v --timing
```

### Generate Reports

```bash
# HTML report
vulnflow scan http://example.com -o report.html -f html

# JSON report with remediation advice
vulnflow scan http://example.com -o report.json --remediation

# SARIF format for CI/CD
vulnflow scan http://example.com -o report.sarif -f sarif
```

### Fast Parallel Scanning

```bash
# High-speed scan with 20 workers
vulnflow scan http://example.com --workers 20 --fast

# Maximum performance
vulnflow scan http://example.com -w 30 -c 50 --fast --rate-limit 100
```

---

## Command Reference

### Command Overview

```bash
vulnflow --help
```

| Command | Description |
|---------|-------------|
| `scan` | Scan target URL for vulnerabilities |
| `server` | Start the API server |
| `version` | Show version info |
| `benchmark` | Run performance benchmark |

---

## SCAN Command

```bash
vulnflow scan [OPTIONS] TARGET_URL
```

### Scan Configuration Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--depth` | `-d` | `2` | Maximum crawl depth |
| `--max-pages` | `-m` | `50` | Maximum pages to crawl |

### Parallel Execution Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--parallel/--no-parallel` | | `True` | Enable/disable parallel scanning |
| `--workers` | `-w` | `5` | Number of concurrent scanner workers |
| `--concurrent-targets` | `-c` | `10` | Number of concurrent targets |
| `--fast` | | `False` | Use fast worker pool mode for maximum speed |

### Performance & Timing Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--timeout` | `-t` | `30` | Request timeout in seconds |
| `--rate-limit` | | `50` | Max requests per second |
| `--timing` | | `False` | Show detailed timing breakdown |
| `--stats` | | `False` | Show execution statistics |
| `--no-timing` | | `False` | Hide timing information |

### Authentication & Network Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--auth-token` | | None | Bearer token for authenticated scanning |
| `--proxy` | | None | Proxy URL (e.g., `http://127.0.0.1:8080`) |
| `--callback-url` | | None | Callback URL for blind vulnerability detection |

### Output Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | None | Output file path |
| `--format` | `-f` | `json` | Report format: `json`, `html`, or `sarif` |
| `--verbose` | `-v` | `False` | Enable verbose output |
| `--remediation` | `-r` | `False` | Show remediation advice in results |

### CI/CD Integration

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--fail-on` | | `critical` | Exit with error code on severity: `critical`, `high`, `medium`, `any`, `none` |

---

## Available Security Modules

| Module | OWASP Category | Description |
|--------|----------------|-------------|
| `sqli` | A03:2021-Injection | SQL Injection |
| `nosqli` | A03:2021-Injection | NoSQL Injection |
| `cmdi` | A03:2021-Injection | Command Injection |
| `ssti` | A03:2021-Injection | Server-Side Template Injection |
| `xss` | A03:2021-Injection | Cross-Site Scripting |
| `ssrf` | A10:2021-SSRF | Server-Side Request Forgery |
| `idor` | A01:2021-Broken Access Control | Insecure Direct Object Reference |
| `path_traversal` | A01:2021-Broken Access Control | Path Traversal |
| `forced_browsing` | A01:2021-Broken Access Control | Forced Browsing |
| `cors` | A05:2021-Security Misconfiguration | CORS Misconfiguration |
| `headers` | A05:2021-Security Misconfiguration | Security Headers Check |
| `backup` | A05:2021-Security Misconfiguration | Backup Files Detection |
| `debug` | A05:2021-Security Misconfiguration | Debug Endpoints Detection |

---

## Usage Examples

### Basic Scans

```bash
# Simple scan with defaults
vulnflow scan http://example.com

# Verbose with timing breakdown
vulnflow scan http://example.com -v --timing
```

### Performance Tuning

```bash
# High concurrency parallel scan
vulnflow scan http://example.com -w 20 -c 30 --fast

# Maximum speed with rate limiting
vulnflow scan http://example.com -w 50 -c 100 --fast --rate-limit 200

# Slower, more thorough scan
vulnflow scan http://example.com --no-parallel -d 5 -m 200

# Large site scan with timing
vulnflow scan http://example.com -d 4 -m 500 -w 30 --timing --stats
```

### Sequential vs Parallel Comparison

```bash
# Sequential scanning (disable parallel)
vulnflow scan http://example.com --no-parallel --timing

# Parallel scanning with 10 workers
vulnflow scan http://example.com --workers 10 --timing

# Fast mode with maximum parallelism
vulnflow scan http://example.com --workers 20 --concurrent-targets 40 --fast --timing
```

### Authenticated Scanning

```bash
# With Bearer token
vulnflow scan http://example.com --auth-token "eyJhbGciOiJIUzI1NiIs..."

# Through proxy (e.g., Burp Suite)
vulnflow scan http://example.com --proxy http://127.0.0.1:8080

# With both
vulnflow scan http://example.com --auth-token "eyJ..." --proxy http://127.0.0.1:8080
```

### Report Generation

```bash
# JSON report (default)
vulnflow scan http://example.com -o report.json

# HTML report with remediation
vulnflow scan http://example.com -o report.html -f html --remediation

# SARIF format (for GitHub/GitLab integration)
vulnflow scan http://example.com -o report.sarif -f sarif

# Verbose with full details
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
    --workers 25 \
    --concurrent-targets 50 \
    --timeout 20 \
    --rate-limit 100 \
    --depth 3 \
    --max-pages 100 \
    --auth-token "Bearer eyJ..." \
    --output full-report.html \
    --format html \
    --verbose \
    --remediation \
    --timing \
    --stats \
    --fail-on high
```

---

##  Performance Metrics & Timing

VulnFlow includes detailed performance tracking:

### Basic Timing (Default)

```
✓ Scan complete!

  Total scan time: 12.45s
```

### Detailed Timing (`--timing` flag)

```
╭──────────────────── ⚡ Scan Performance ────────────────────╮
│                                                              │
│   Total Scan Time: 12.45s                                    │
│                                                              │
│ Performance Metrics:                                         │
│   • Pages scanned: 47 (3.8 pages/sec)                       │
│   • Forms tested: 12 (1.0 forms/sec)                        │
│   • Vulnerabilities found: 5                                 │
│                                                              │
╰──────────────────────────────────────────────────────────────╯

           Phase Breakdown
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Phase                    ┃   Duration ┃ % of Total ┃ Progress           ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ Vulnerability Scanning   │     8.23s  │     66.1%  │ ██████████░░░░░    │
│ Crawling                 │     3.12s  │     25.1%  │ ████░░░░░░░░░░░    │
│ Technology Detection     │     0.87s  │      7.0%  │ █░░░░░░░░░░░░░░    │
│ Remediation Generation   │     0.23s  │      1.8%  │ ░░░░░░░░░░░░░░░    │
└──────────────────────────┴────────────┴────────────┴────────────────────┘
```

### Execution Statistics (`--stats` flag)

```
           Execution Statistics
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Metric            ┃        Value ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ Total Tasks       │          156 │
│ Completed Tasks   │          154 │
│ Failed Tasks      │            2 │
│ Total Duration    │        8.23s │
│ Throughput        │ 18.7 tasks/s │
└───────────────────┴──────────────┘
```

---

## API Server

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
# Create a new scan
curl -X POST "http://localhost:8000/api/v1/scans" \
     -H "Content-Type: application/json" \
     -d '{
       "target_url": "http://example.com",
       "config": {
         "depth": 2,
         "max_pages": 50,
         "parallel": true,
         "workers": 10
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

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNFLOW_WORKERS` | Default number of workers | `5` |
| `VULNFLOW_TIMEOUT` | Default timeout (seconds) | `30` |
| `VULNFLOW_RATE_LIMIT` | Default rate limit (req/s) | `50` |
| `VULNFLOW_LOG_LEVEL` | Logging level | `INFO` |

### Configuration File

Create `vulnflow.yaml` in your project root:

```yaml
scan:
  depth: 3
  max_pages: 100
  timeout: 30
  
parallel:
  enabled: true
  workers: 10
  concurrent_targets: 20
  rate_limit: 50

output:
  format: html
  include_remediation: true
  
modules:
  enabled:
    - sqli
    - xss
    - ssrf
    - headers
```

---

## CI/CD Integration

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
        run: |
          vulnflow scan ${{ secrets.TARGET_URL }} \
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
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    pip install vulnflow
                    vulnflow scan ${TARGET_URL} \
                        --workers 20 \
                        --output report.html \
                        --format html \
                        --fail-on high
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'report.html'
                }
            }
        }
    }
}
```

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Scan completed, no issues above threshold |
| `1` | Scan completed, high severity issues found |
| `2` | Scan completed, critical severity issues found |
| `130` | Scan interrupted by user (Ctrl+C) |

---

## Quick Reference Card

```bash
# Essential Commands
vulnflow scan <URL>                              # Full scan
vulnflow scan <URL> -w 20 --fast                 # High-speed parallel
vulnflow scan <URL> --modules sqli --modules xss # Specific modules
vulnflow scan <URL> -o report.html -f html       # HTML report
vulnflow scan <URL> --fail-on high               # CI/CD mode
vulnflow scan <URL> -v --timing --stats          # Full metrics
vulnflow scan <URL> --remediation                # With fix advice
vulnflow server                                  # Start API

# Performance Comparison
vulnflow scan <URL> --no-parallel --timing       # Sequential (baseline)
vulnflow scan <URL> -w 10 --timing               # Parallel (faster)
vulnflow scan <URL> -w 20 --fast --timing        # Fast mode (fastest)
```

---

## ⚠️ Disclaimer

VulnFlow is designed for authorized security testing only. Always obtain proper authorization before scanning any systems you do not own. The developers are not responsible for any misuse of this tool.
