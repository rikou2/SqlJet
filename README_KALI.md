# SQL Injection Scanner - Kali Linux Installation Guide

This guide provides step-by-step instructions for installing and using the Advanced SQL Injection Scanner on Kali Linux.

## Quick Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/SqlQ.git
   cd SqlQ
   ```

2. Run the installer script as root:
   ```bash
   sudo bash install.sh
   ```

3. Start using the scanner:
   ```bash
   sqliq scan example.com
   ```

## What Gets Installed

The installer sets up:

- Shell-based scanner components
- Python-based detection and WAF bypass modules
- Machine learning detection module
- Integration with SQLmap for exploitation
- Comprehensive payload collections
- Tamper scripts for WAF bypass

## Directory Structure

After installation, files are organized as follows:

- `/usr/share/sqlq/` - Main installation directory
  - Shell scripts (sqli_*.sh) - Core scanner functionality
  - Python scripts (*.py) - Advanced detection modules
  - Tamper scripts in the tamper/ directory
  - Payloads in the Payloads/ directory
  - ML models in the models/ directory

- `/usr/local/bin/sqliq` - Main command-line interface

## Basic Usage

The `sqliq` command provides a unified interface to all scanner features:

```bash
# Basic scan
sqliq scan example.com

# Quick scan with automatic WAF bypass
sqliq quick example.com

# Full scan with all detection methods
sqliq full example.com

# Test WAF detection
sqliq waf https://example.com

# Use Python-based scanner (more advanced)
sqliq python example.com

# Use machine learning enhanced detection
sqliq ml-scan example.com
```

## Advanced Features

### WAF Detection and Bypass

The scanner can automatically detect and bypass Web Application Firewalls:

```bash
# Test WAF detection
sqliq waf https://example.com

# List available tamper techniques
sqliq tampers

# Scan with automatic WAF bypass
sqliq scan example.com --auto-waf
```

### Machine Learning Detection

The scanner includes a machine learning module that can detect SQL injections more accurately:

```bash
# Use machine learning module
sqliq ml-scan example.com
```

### Integration with SQLmap

For confirmed vulnerabilities, the scanner can automatically exploit them using SQLmap:

```bash
# Scan and exploit with SQLmap
sqliq scan example.com --auto-sqlmap
```

### Generating Custom Payloads

Generate comprehensive payload collections for different database types:

```bash
# Generate payloads
sqliq payloads
```

## Scan Results

Scan results are stored in the `/usr/share/sqlq/results/` directory, organized by domain and timestamp. Reports are available in multiple formats:

- Text (.txt)
- HTML (.html)
- JSON (.json)
- CSV (.csv)
- XML (.xml)

## Troubleshooting

### Common Issues

1. **Command not found**
   - Check if `/usr/local/bin` is in your PATH
   - Verify installation: `ls -la /usr/share/sqlq`

2. **Missing dependencies**
   - Run `sqliq update` to install all required dependencies

3. **Missing Go tools**
   - Ensure Go is installed: `go version`
   - Add Go binaries to your PATH: `export PATH=$PATH:/usr/local/go/bin:~/go/bin`

### Reinstalling

If you need to reinstall or update:

```bash
cd SqlQ
git pull
sudo bash install.sh
```

## Uninstallation

To completely remove the scanner:

```bash
sudo rm -rf /usr/share/sqlq
sudo rm /usr/local/bin/sqliq /usr/local/bin/sqliscanner
```

## Security Considerations

Always ensure you have legal authorization to scan the target. Unauthorized scanning may be illegal and unethical. The scanner provides significant capabilities for both legitimate security testing and potential misuse.

## Advanced Command-Line Options

For a full list of options:

```bash
sqliq scan --help
```

Common options include:

- `--threads <num>` - Set number of concurrent threads
- `--proxy <proxy>` - Use proxy (format: http://proxy:port)
- `--cookie <cookie>` - Cookie string for authenticated scanning
- `--timeout <sec>` - Request timeout in seconds
- `--report-format <fmt>` - Report format (txt,html,json,csv,xml,all)
- `--encode-level <lvl>` - Payload encoding level (1-3)
- `--tamper <techniques>` - Comma-separated tamper techniques
- `--auto-waf` - Auto-detect WAF and use appropriate bypass techniques
- `--db-detect` - Automatically detect database type for better payloads 