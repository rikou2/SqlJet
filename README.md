# SqlJet Ai V1 - Advanced SQL Injection Discovery & Testing Tool

SqlJet Ai V1 is a comprehensive SQL injection detection and exploitation tool that automates the process of discovering SQL injection vulnerabilities across various endpoints including subdomains, APIs, and login forms.

## Features

- **Single-Command Operation**: Run complete scans with just one command
- **Fully Automated**: No user interaction required during scanning
- **Advanced Detection**: Identifies SQL injections in various contexts:
  - Website parameters
  - API endpoints
  - Login forms
  - POST requests
- **WAF Detection & Bypass**: Automatically detects WAFs and selects optimal tamper scripts
- **Database Enumeration**: Automatically extracts database information from vulnerable endpoints
- **Comprehensive Scanning**: Subdomain enumeration, URL discovery, and endpoint detection

## Usage

```bash
# Basic scan with full automation
python3 sqlsc.py -u testphp.vulnweb.com

# Direct scan from file with custom options
python3 sqlsc.py --vulnerable-file vulnerable_urls.txt --auto-waf --level 2 --risk 2
```

## Implementation Plan

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the full roadmap of current and planned features.

## Requirements

- Python 3.6+
- SQLMap
- Subfinder (for subdomain enumeration)
- HTTPx (for live URL checking)

## License

This project is available under the MIT license.
