# Advanced SQL Injection Scanner

An advanced SQL injection vulnerability scanner with WAF bypass capabilities and automatic exploitation.

## Features

- Subdomain enumeration and comprehensive URL discovery
- Multiple SQL injection detection techniques:
  - Error-based detection
  - Time-based detection
  - Boolean-based detection
  - Union-based detection
- WAF (Web Application Firewall) detection and bypass
- Advanced payload handling with encoding and tamper techniques
- SQLmap integration for exploitation
- Detailed reporting in multiple formats
- Proxy support with rotation

## Installation

### Prerequisites

The scanner requires the following tools to be installed:

- subfinder - Subdomain discovery tool
- gau - URL discovery tool
- uro - URL optimization
- httpx - HTTP toolkit
- sqlmap - SQL injection exploitation
- curl - HTTP requests
- jq - JSON processing
- parallel (recommended) - Parallel processing

### Install dependencies

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/s0md3v/uro@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install other tools
sudo apt-get install -y sqlmap curl jq parallel
```

## Usage

Basic usage:

```bash
./sqli_scanner.sh example.com
```

Advanced usage with options:

```bash
./sqli_scanner.sh example.com --threads 20 --auto-waf --auto-sqlmap --report-format all
```

### Options

- `--auto-sqlmap`: Automatically run sqlmap on found vulnerabilities
- `--threads <num>`: Set number of concurrent threads (default: 10)
- `--proxy <proxy>`: Use proxy (format: http://proxy:port)
- `--proxy-list <file>`: Rotate through proxies in the specified file
- `--auth <method>`: Authentication method: basic, digest, ntlm
- `--user <username>`: Username for authentication
- `--pass <password>`: Password for authentication
- `--cookie <cookie>`: Cookie string for authenticated scanning
- `--headers <file>`: File containing custom headers
- `--verbose`: Enable verbose output
- `--report-format <fmt>`: Report format (options: txt,html,json,csv,xml,all)
- `--timeout <sec>`: Request timeout in seconds (default: 10)
- `--user-agent <ua>`: Custom User-Agent string
- `--encode-level <lvl>`: Payload encoding level (1-3)
- `--tamper <techniques>`: Comma-separated tamper techniques
- `--auto-waf`: Auto-detect WAF and use appropriate bypass techniques
- `--list-tampers`: List available tamper techniques
- `--payload-types <type>`: Comma-separated payload types (default: all)

## Examples

### Basic scan

```bash
./sqli_scanner.sh example.com
```

### Scan with WAF bypass and automatic exploitation

```bash
./sqli_scanner.sh example.com --auto-waf --auto-sqlmap
```

### Scan with specific tamper techniques

```bash
./sqli_scanner.sh example.com --tamper space2comment,between,randomcase
```

### List all available tamper techniques

```bash
./sqli_scanner.sh --list-tampers
```

### Scan with proxy and custom timeout

```bash
./sqli_scanner.sh example.com --proxy http://127.0.0.1:8080 --timeout 15
```

## How It Works

1. **Subdomain Discovery**: Uses subfinder to discover all subdomains of the target domain
2. **URL Collection**: Uses gau and uro to find and deduplicate URLs
3. **URL Filtering**: Filters URLs that have parameters which could be vulnerable
4. **WAF Detection**: Detects if the target has a WAF and selects appropriate bypass techniques
5. **Vulnerability Testing**: Tests each URL for SQL injection vulnerabilities
6. **Exploitation**: Optionally uses sqlmap to exploit found vulnerabilities
7. **Reporting**: Generates detailed reports in various formats

## File Structure

- `sqli_scanner.sh`: Main script that coordinates all functionality
- `sqli_core.sh`: Core functions and utilities
- `sqli_detect.sh`: SQL injection detection logic
- `sqli_exploit.sh`: Integration with sqlmap for exploitation
- `sqli_report.sh`: Report generation in various formats
- `Payloads/`: Directory containing SQL injection payloads
- `tamper/`: Directory containing tamper scripts for WAF bypass

## Disclaimer

This tool is for legitimate security testing only. Always obtain proper authorization before testing any system.

## License

This project is licensed under the MIT License. 