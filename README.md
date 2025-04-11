# SqlJet Ai V1 - Advanced SQL Injection Discovery & Testing Tool

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.1-blue">
  <img src="https://img.shields.io/badge/Python-3.8+-orange">
  <img src="https://img.shields.io/badge/License-MIT-green">
</p>

<p align="center"><i>Copyright (c) 2024-2025 SqlJet Ai developers by R13</i></p>

SqlJet Ai is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities across various endpoints including subdomains, APIs, and login forms. This tool is for educational purposes only - the developer is not responsible for any illegal use.

## ✨ Features

- **Single-Command Operation**: Run complete scans with just one command
- **Fully Automated**: Zero user interaction required during scanning
- **Advanced Detection**: Identifies SQL injections in various contexts:
  - Website parameters
  - API endpoints
  - Login forms
  - POST requests
- **Intelligent Crawling**: Uses Katana to discover hidden injection points
- **WAF Detection & Bypass**: Automatically detects WAFs and selects optimal tamper scripts
- **Database Enumeration**: Automatically extracts database information from vulnerable endpoints
- **Comprehensive Reporting**: Generates detailed reports of discovered vulnerabilities

## 🔧 Installation

### Prerequisites for All Platforms

- Python 3.8+
- Go 1.17+ (for Katana and other tools)

### Quick Installation (All Platforms)

```bash
# Clone the repository
git clone https://github.com/rikou2/SqlJet.git
cd SqlJet

# Install Python dependencies
pip install -r requirements.txt
```

### Kali Linux

```bash
# Clone the repository
git clone https://github.com/rikou2/SqlJet.git
cd SqlJet

# Install Python dependencies
pip3 install -r requirements.txt

# Install required Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Add Go binaries to your PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Install SQLMap if not already installed
apt update && apt install -y sqlmap
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Go
brew install python3 go

# Clone the repository
git clone https://github.com/rikou2/SqlJet.git
cd SqlJet

# Install Python dependencies
pip3 install -r requirements.txt

# Install required Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Add Go binaries to your PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Install SQLMap
brew install sqlmap
```

### Windows

1. Install Python 3.8+ from [python.org](https://www.python.org/downloads/windows/)
2. Install Go from [golang.org](https://golang.org/dl/)
3. Install Git from [git-scm.com](https://git-scm.com/downloads)

```powershell
# Clone the repository
git clone https://github.com/rikou2/SqlJet.git
cd SqlJet

# Install Python dependencies
pip install -r requirements.txt

# Install required Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Add Go binaries to your PATH
$env:Path += ";$($env:USERPROFILE)\go\bin"

# Install SQLMap (via pip or download from SQLMap repository)
pip install sqlmap
```

## 🚀 Usage

### Basic Commands

```bash
# Run a basic scan against a domain
python sqlsc.py -u example.com

# Specify output directory
python sqlsc.py -u example.com -o /path/to/output

# Skip reconnaissance phase
python sqlsc.py -u example.com --skip-recon

# Scan using a file of pre-discovered vulnerable URLs
python sqlsc.py --vulnerable-file vulnerable_urls.txt
```

### Advanced Options

```bash
# Set SQLMap risk and level parameters
python sqlsc.py -u example.com --risk 3 --level 5

# Enable automatic WAF detection and bypass
python sqlsc.py -u example.com --auto-waf

# Customize SQLMap tamper scripts
python sqlsc.py -u example.com --tamper "between,charencode,space2comment"

# Set a custom timeout
python sqlsc.py -u example.com --timeout 300

# Limit maximum number of URLs to scan
python sqlsc.py -u example.com --max-urls 500
```

### Katana Crawler Options

```bash
# Enable Katana crawler (enabled by default)
python sqlsc.py -u example.com --katana

# Set Katana crawler depth
python sqlsc.py -u example.com --katana-depth 5

# Set Katana crawler timeout
python sqlsc.py -u example.com --katana-timeout 600
```

### Feature-Specific Scanning

```bash
# Run only JavaScript endpoint discovery
python sqlsc.py -u example.com --js-scan

# Run only login form detection
python sqlsc.py -u example.com --login-scan

# Run only POST request generation
python sqlsc.py -u example.com --post-scan

# Run only API endpoint discovery
python sqlsc.py -u example.com --api-scan

# Run all enhanced scans
python sqlsc.py -u example.com --full
```

### Database Enumeration

```bash
# Enumerate databases
python sqlsc.py -u example.com --get-dbs

# Enumerate tables from specific database
python sqlsc.py -u example.com --get-tables --db-name users

# Enumerate columns from specific table
python sqlsc.py -u example.com --get-columns --db-name users --tbl-name accounts

# Dump table data
python sqlsc.py -u example.com --dump --db-name users --tbl-name accounts
```

### Authentication and Proxy Options

```bash
# Use HTTP authentication
python sqlsc.py -u example.com --auth-type basic --auth-cred "username:password"

# Use a proxy
python sqlsc.py -u example.com --proxy "http://proxy.example.com:8080"

# Use a proxy file (multiple proxies)
python sqlsc.py -u example.com --proxy-file proxies.txt

# Set a custom cookie
python sqlsc.py -u example.com --cookie "session=123456"
```

## 📋 Full Command Reference

```
Usage: sqlsc.py [options]

Options:
  -h, --help            Show help message and exit
  -u, --url DOMAIN      Target domain to scan
  -l, --list DOMAIN_LIST
                        File containing list of domains
  -o, --output OUTPUT   Output directory for results
  --skip-recon          Skip reconnaissance phase
  --max-urls MAX_URLS   Maximum number of URLs to scan
  --vulnerable-file VULNERABLE_FILE
                        File containing already discovered vulnerable URLs
  --threads THREADS     Number of concurrent threads (default: 10)
  --verbose             Enable verbose output

SQL Injection Options:
  --level LEVEL         SQLMap detection level (1-5)
  --risk RISK           SQLMap risk level (1-3)
  --tamper TAMPER       SQLMap tamper script(s)
  --prefix PREFIX       Injection payload prefix
  --suffix SUFFIX       Injection payload suffix
  --auto-waf            Auto-detect WAF and recommend tamper scripts

Crawler Options:
  --katana              Use Katana crawler to find potential SQL injection points
  --katana-depth DEPTH  Katana crawler depth (default: 3)
  --katana-timeout TIME Katana crawler timeout in seconds (default: 300)

Enhanced Scanning Options:
  --full                Run all enhanced scanning options
  --js-scan             Extract endpoints from JavaScript files
  --login-scan          Find and test login forms
  --post-scan           Generate and test POST requests
  --api-scan            Extract and test API endpoints

Database Enumeration Options:
  --get-dbs             Get list of databases
  --get-tables          Get tables from database
  --get-columns         Get columns from table
  --db-name DB_NAME     Database name to enumerate
  --tbl-name TBL_NAME   Table name to enumerate
  --col-name COL_NAME   Column name to enumerate
  --dump                Dump table contents

Authentication and Proxy Options:
  --auth-type AUTH_TYPE Authentication type (Basic, Digest, NTLM)
  --auth-cred AUTH_CRED Authentication credentials (username:password)
  --cookie COOKIE       HTTP cookie header
  --proxy PROXY         Use a proxy for requests
  --proxy-file PROXY_FILE
                        File containing proxies
  --timeout TIMEOUT     Timeout for requests (seconds)
```

## 🔄 Recent Updates

### Version 1.1 (April 2025)
- Added comprehensive dependency management with requirements.txt
- Improved WAF detection algorithm with enhanced bypass techniques
- Fixed bugs related to parameter handling in nested URLs
- Added support for more database types
- Enhanced reporting with detailed CSV output
- Performance improvements for large-scale scans

## 📜 License

This project is available under the MIT license.

## ⚠️ Disclaimer

SqlJet Ai is designed for educational purposes and legal penetration testing activities only. The developer is not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before scanning any target that is not owned by you.
