# SqlJet Ai V1 - Advanced SQL Injection Discovery & Testing Tool

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue">
  <img src="https://img.shields.io/badge/Python-3.6+-orange">
  <img src="https://img.shields.io/badge/License-MIT-green">
</p>

<p align="center"><i>Copyright (c) 2024-2025 SqlJet Ai developers by R13</i></p>

SqlJet Ai is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities across various endpoints including subdomains, APIs, and login forms. This tool is for educational purposes only - the developer is not responsible for any illegal use.

## Features

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

## Installation

### Prerequisites for All Platforms

- Python 3.6+
- Go 1.17+ (for Katana and other tools)

### Kali Linux

```bash
# Clone the repository
git clone https://github.com/rikou2/sqljet.git
cd sqljet

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
git clone https://github.com/rikou2/sqljet.git
cd sqljet

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

1. Install Python 3.6+ from [python.org](https://www.python.org/downloads/windows/)
2. Install Go from [golang.org](https://golang.org/dl/)
3. Install Git from [git-scm.com](https://git-scm.com/downloads)

```powershell
# Clone the repository
git clone https://github.com/rikou2/sqljet.git
cd sqljet

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

## Usage

### New CLI Interface

Starting with the latest version, SqlJet Ai provides a more user-friendly command-line interface:

```bash
# Make the CLI executable (one-time setup)
chmod +x run_sqljet.py
ln -sf run_sqljet.py sqljet
chmod +x sqljet

# Run a basic scan against a domain
./sqljet -u example.com

# Show help and all available options
./sqljet --help
```

The new CLI interface offers the same functionality as the original command but with improved usability and help documentation.

### Basic Commands

```bash
# Run a basic scan against a domain
./sqljet -u example.com

# Specify output directory
./sqljet -u example.com -o /path/to/output

# Skip reconnaissance phase
./sqljet -u example.com --skip-recon

# Scan using a file of pre-discovered vulnerable URLs
./sqljet --vulnerable-file vulnerable_urls.txt
```

### Advanced Options

```bash
# Set SQLMap risk and level parameters
./sqljet -u example.com --risk 3 --level 5

# Enable automatic WAF detection and bypass
./sqljet -u example.com --auto-waf

# Customize SQLMap tamper scripts
./sqljet -u example.com --tamper "between,charencode,space2comment"

# Set a custom timeout
./sqljet -u example.com --timeout 300

# Limit maximum number of URLs to scan
./sqljet -u example.com --max-urls 500
```

### Katana Crawler Options

```bash
# Enable Katana crawler (enabled by default)
./sqljet -u example.com --katana

# Set Katana crawler depth
./sqljet -u example.com --katana-depth 5

# Set Katana crawler timeout
./sqljet -u example.com --katana-timeout 600
```

### Tool Management

```bash
# Update all required tools (subfinder, httpx, katana, gau, nuclei) and Python dependencies
./sqljet -up

# Same as above with long-form argument
./sqljet --update
```

### Feature-Specific Scanning

```bash
# Run only JavaScript endpoint discovery
./sqljet -u example.com --js-scan

# Run only login form detection
./sqljet -u example.com --login-scan

# Run only POST request generation
./sqljet -u example.com --post-scan

# Run only API endpoint discovery
./sqljet -u example.com --api-scan

# Run all enhanced scans
./sqljet -u example.com --full
```

### Database Enumeration

```bash
# Enumerate databases
./sqljet -u example.com --get-dbs

# Enumerate tables from specific database
./sqljet -u example.com --get-tables --db-name users

# Enumerate columns from specific table
./sqljet -u example.com --get-columns --db-name users --tbl-name accounts

# Dump table data
./sqljet -u example.com --dump --db-name users --tbl-name accounts
```

### Authentication and Proxy Options

```bash
# Use HTTP authentication
./sqljet -u example.com --auth-type basic --auth-cred "username:password"

# Use a proxy
./sqljet -u example.com --proxy "http://proxy.example.com:8080"

# Use a proxy file (multiple proxies)
./sqljet -u example.com --proxy-file proxies.txt

# Set a custom cookie
./sqljet -u example.com --cookie "session=123456"
```

## Full Command Reference

```
Usage: ./sqljet [options]

Options:
  -h, --help            Show help message and exit
  -u, --url URL         Target domain or URL
  -l, --list LIST       File containing list of URLs
  -o, --output OUTPUT   Output directory for results
  -up, --update         Update all required tools and dependencies
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
  --dbs                 Get list of databases
  --tables              Get tables from database
  --columns             Get columns from table
  --dump                Dump table contents

Authentication and Proxy Options:
  --auth-type AUTH_TYPE Authentication type (Basic, Digest, NTLM)
  --auth-cred AUTH_CRED Authentication credentials (username:password)
  --cookie COOKIE       HTTP cookie header
  --proxy PROXY         Use a proxy for requests
  --proxy-file PROXY_FILE
                        File containing proxies
  --timeout TIMEOUT     Timeout for requests (seconds)
  
AI Integration Options:
  --ai                  Enable AI-enhanced scanning 
  --ai-model MODEL      AI model to use (gpt-4, gpt-3.5-turbo)
  --ai-key KEY          OpenAI API key
  --nuclei              Use Nuclei with AI-powered detection
```

## License

This project is available under the MIT license.

## Disclaimer

SqlJet Ai is designed for educational purposes and legal penetration testing activities only. The developer is not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before scanning any target that is not owned by you.
