# SQL Injection Scanner - Quick Start Guide

This guide helps you get up and running with the enhanced SQL Injection Scanner quickly.

## Installation

1. Make sure all scripts are executable:
   ```bash
   chmod +x sqli_*.sh run-sqliscanner.sh
   ```

2. Install required dependencies:
   ```bash
   # For Debian/Ubuntu
   sudo apt-get install curl jq bc parallel python3 sqlmap
   
   # For macOS with Homebrew
   brew install curl jq bc parallel python3 sqlmap
   
   # Install required Go tools
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install -v github.com/lc/gau/v2/cmd/gau@latest
   go install -v github.com/s0md3v/uro@latest
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   ```

## Basic Usage

The easiest way to use the scanner is with the launcher script:

```bash
./run-sqliscanner.sh example.com
```

This will prompt you for options and automatically use the best settings.

## Common Scenarios

### 1. Full Scan with WAF Bypass and DB Detection

For a thorough scan that automatically detects WAFs and database types:

```bash
./sqli_scanner.sh example.com --auto-waf --db-detect --report-format all
```

### 2. Generate Custom Payloads for All Databases

Generate comprehensive payload files:

```bash
./sqli_scanner.sh example.com --generate-payloads
```

### 3. Scan with Automatic SQLmap Exploitation

If you want the scanner to automatically exploit vulnerabilities with SQLmap:

```bash
./sqli_scanner.sh example.com --auto-sqlmap --auto-waf
```

### 4. Scan with Specific Tamper Techniques

If you know which WAF is in place and want to use specific tamper techniques:

```bash
./sqli_scanner.sh example.com --tamper "space2comment,between,randomcase" --encode-level 3
```

### 5. Scan with Higher Concurrency

For faster scanning on powerful systems:

```bash
./sqli_scanner.sh example.com --threads 20 --auto-waf
```

### 6. Authenticated Scanning

To scan pages that require authentication:

```bash
./sqli_scanner.sh example.com --cookie "session=abc123; user=admin" --auto-waf
```

## Advanced Features

### Module Architecture

The scanner is divided into specialized modules:

- **sqli_core.sh**: Core utility functions
- **sqli_waf.sh**: Advanced WAF detection and bypass
- **sqli_payloads.sh**: Sophisticated payload management
- **sqli_detect.sh**: SQL injection detection logic
- **sqli_exploit.sh**: SQLmap integration for exploitation
- **sqli_report.sh**: Report generation in multiple formats

### Vulnerability IDs

Each detected vulnerability is assigned a unique ID in the format:

```
VULN_YYYYMMDDHHMMSS_XXXXXXXX
```

Where:
- `YYYYMMDDHHMMSS` is the timestamp
- `XXXXXXXX` is a hash derived from the URL, parameter, and vulnerability type

These IDs help track vulnerabilities across different scans and reports.

### Database Detection

The scanner can attempt to identify the database type (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) and use database-specific payloads for improved detection.

### WAF Bypass

The enhanced WAF module can detect 14+ WAF types and automatically select the most effective bypass techniques for each.

## Output Files

After scanning, you'll find detailed results in the `results/[domain]/[timestamp]/` directory:

- `vulnerabilities.txt`: List of all detected vulnerabilities
- `vulns/`: Directory containing detailed information about each vulnerability
- `report.*`: Reports in various formats (txt, html, json, csv, xml)
- `detailed_report.md`: Markdown report with vulnerability IDs and details
- `summary.txt`: Overview of the scan results
- `db_types.txt`: Detected database types for each URL
- `waf_bypass_payloads.txt`: Custom WAF bypass payloads if generated

## Need Help?

For more details, see the full README.md file or run:

```bash
./sqli_scanner.sh --help
``` 