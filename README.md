# ReconStrike

**Advanced Web & Network Vulnerability Assessment Framework**

ReconStrike is a professional-grade vulnerability scanner built in Python that performs comprehensive security assessments against web applications and network endpoints. Designed for penetration testers, security auditors, and DevSecOps teams.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Modules](https://img.shields.io/badge/scan%20modules-21-green.svg)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-orange.svg)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-v4.0-red.svg)
![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)

---

## Features

### Core Scanning Engine
- **21 vulnerability scan modules** covering OWASP Top 10 and beyond
- **Zero false positive architecture** — baseline comparison, double-verification, structural validation
- **Concurrent crawler** — multi-threaded discovery (5-10x faster than sequential)
- **WAF detection** — identifies 10+ WAF/CDN products before scanning
- **Technology stack fingerprinting** — frameworks, servers, CMS, CDN, analytics

### Scan Modules

| Category | Modules |
|----------|---------|
| **Injection** | SQL Injection, XSS, SSTI, Command Injection, XXE, LFI/Path Traversal |
| **Authentication** | Auth bypass, Default credentials, JWT vulnerabilities, CSRF |
| **Configuration** | Security headers, SSL/TLS, Misconfigurations, CORS |
| **Discovery** | Port scanning, Subdomain enumeration, Directory bruteforce, Information disclosure |
| **Access Control** | IDOR, SSRF, File upload vulnerabilities |
| **Fingerprinting** | Technology detection, WAF identification |
| **API Security** | Endpoint discovery, Auth bypass, Rate limiting, CORS, Method testing |

### Advanced Features
- **7 scan profiles** — quick, standard, deep, aggressive, passive, api, owasp
- **OWASP Top 10 & PCI DSS v4.0 compliance mapping** with pass/fail scoring
- **Scan diffing** — compare current results against previous scans to track remediation
- **API endpoint security** — auto-discovers and tests REST API endpoints
- **WAF detection** — Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, Sucuri, and more
- **Rate limiting** — configurable requests per second
- **Proxy support** — HTTP and SOCKS5 proxy routing (Tor-compatible)
- **Scope control** — include/exclude URL patterns via regex
- **JSON output** — machine-readable output for automation pipelines
- **CI/CD integration** — exit codes based on severity thresholds
- **Authenticated scanning** — auto-detect login forms and maintain sessions
- **Progress tracking** — real-time progress bar with ETA
- **HTML reports** — professional dark-themed reports with risk scoring and executive summary

---

## Installation

```bash
git clone https://github.com/cyphersec-404/ReconStrike.git
cd ReconStrike
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python3 reconstrike.py -t https://target.com
```

### Scan Profiles
```bash
# Quick recon (5 modules, depth 2)
python3 reconstrike.py -t https://target.com --profile quick

# Deep scan (all modules, depth 5)
python3 reconstrike.py -t https://target.com --profile deep

# Aggressive (all modules, depth 7)
python3 reconstrike.py -t https://target.com --profile aggressive

# API-focused
python3 reconstrike.py -t https://api.target.com --profile api --api-scan

# OWASP compliance check
python3 reconstrike.py -t https://target.com --profile owasp --compliance

# Passive recon only (no injection tests)
python3 reconstrike.py -t https://target.com --profile passive
```

### Authenticated Scanning
```bash
python3 reconstrike.py -t https://target.com \
  --auth-url https://target.com/login \
  -u admin -p password123
```

### Selective Modules
```bash
# Run specific modules
python3 reconstrike.py -t https://target.com --modules sqli,xss,headers,ssl

# Run all except slow ones
python3 reconstrike.py -t https://target.com --exclude-modules portscan,subdomain
```

### Advanced Options
```bash
# With proxy (Tor, Burp, etc.)
python3 reconstrike.py -t https://target.com --proxy socks5://127.0.0.1:9050

# Rate-limited scan
python3 reconstrike.py -t https://target.com --rate-limit 10

# JSON output for automation
python3 reconstrike.py -t https://target.com --json --json-file results.json

# Compare with previous scan
python3 reconstrike.py -t https://target.com --diff

# Compliance report
python3 reconstrike.py -t https://target.com --compliance

# CI/CD pipeline (exit 1 on critical, 2 on high)
python3 reconstrike.py -t https://target.com --ci --severity-threshold HIGH -q
```

### Custom Headers & Cookies
```bash
python3 reconstrike.py -t https://target.com \
  --cookie "session=abc123; token=xyz" \
  --header "Authorization: Bearer eyJ..." \
  --header "X-Custom: value"
```

---

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| **HTML Report** | `-o report.html` | Professional dark-themed report with risk scoring |
| **JSON** | `--json` | Machine-readable output to stdout |
| **JSON File** | `--json-file out.json` | Save JSON to file |
| **CLI Summary** | (default) | Color-coded terminal output |
| **Quiet Mode** | `-q` | Minimal output for CI/CD |

---

## Compliance

ReconStrike maps findings to industry frameworks:

- **OWASP Top 10 (2021)** — A01 through A10 category mapping with pass/fail
- **PCI DSS v4.0** — Requirements 6.5.1 through 6.5.10

Use `--compliance` to generate the compliance report section in both CLI and HTML output.

---

## Architecture

```
reconstrike.py              # CLI entry point
scanner/
  core.py                   # ScanSession, ScanConfig, Finding, Severity
  concurrent.py             # Multi-threaded crawler
  crawler.py                # URL/form extraction
  reporter.py               # HTML report generation
  compliance.py             # OWASP/PCI DSS mapping
  diff_scan.py              # Scan history & comparison
  api_scanner.py            # REST API security testing
  waf_detect.py             # WAF/CDN detection
  tech_stack.py             # Technology fingerprinting
  modules/
    sqli.py                 # SQL Injection (error + blind)
    xss.py                  # Reflected XSS
    ssti.py                 # Server-Side Template Injection
    lfi.py                  # Path Traversal / LFI
    cmd_injection.py        # OS Command Injection
    xxe.py                  # XML External Entity
    ssrf.py                 # Server-Side Request Forgery
    csrf.py                 # Cross-Site Request Forgery
    idor.py                 # Insecure Direct Object Reference
    jwt.py                  # JWT Vulnerabilities
    auth.py                 # Authentication Security
    headers.py              # Security Headers
    ssl_check.py            # SSL/TLS Configuration
    misconfig.py            # Security Misconfigurations
    directory.py            # Sensitive Files & Directories
    info_disclosure.py      # Information Disclosure
    file_upload.py          # File Upload Vulnerabilities
    portscan.py             # TCP Port Scanning
    subdomain.py            # Subdomain Enumeration
    fingerprint.py          # Technology Detection
```

---

## Disclaimer

This tool is intended for **authorized security testing only**. Only use ReconStrike against systems you own or have explicit written permission to test. Unauthorized scanning is illegal. The authors are not responsible for misuse.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
