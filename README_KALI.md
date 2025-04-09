# SQL Injection Scanner - Kali Linux Installation Guide

This guide provides step-by-step instructions for installing and using the Advanced SQL Injection Scanner on Kali Linux.

## System Requirements

- Kali Linux (recommended) or other Linux distributions
- Bash 4.0+ (required for associative arrays)
- Python 3.6 or higher
- Required libraries (installed automatically by the installer)

> **Note:** This tool uses Bash 4.0+ features (associative arrays) and will not work on systems with older Bash versions (like macOS which comes with Bash 3.2). See the "Alternative Setup Methods" section if you're not using Kali Linux.

## Quick Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rikou2/SqlQ.git
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
```

## Alternative Setup Methods

### Option 1: Using Docker

If you're not running Kali Linux or don't have Bash 4.0+, you can use Docker to run the tool in a Kali Linux container:

1. **Install Docker for your platform**:
   - [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/)
   - [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
   - On Linux: `sudo apt install docker.io docker-compose`

2. **Pull and run the Kali Linux container with the tool**:
   ```bash
   # Pull the Kali Linux image
   docker pull kalilinux/kali-rolling
   
   # Run a Kali Linux container with shared access to your local SqlQ directory
   docker run -it --name kali-sqlq -v /path/to/SqlQ:/SqlQ kalilinux/kali-rolling
   ```

3. **Set up the environment in the container**:
   ```bash
   # Update package lists
   apt update
   
   # Install required dependencies
   apt install -y git python3 python3-pip curl wget netcat
   
   # Navigate to your shared folder
   cd /SqlQ
   
   # Install the tool
   bash install.sh
   
   # Run the SQL injection scanner
   sqliq scan example.com
   ```

### Option 2: Using a Virtual Machine

For a more isolated and complete Kali Linux experience:

1. **Download and install VirtualBox or VMware**
2. **Download Kali Linux VM image** from [Kali Linux Downloads](https://www.kali.org/get-kali/#kali-virtual-machines)
3. **Import and run the VM**
4. **Clone your repository in the VM**:
   ```bash
   git clone https://github.com/rikou2/SqlQ.git
   cd SqlQ
   sudo bash install.sh
   ```

# GitHub Repository Management

Here's how to manage your project on GitHub:

1. **Create a GitHub account** at https://github.com/signup if you don't have one

2. **Create a new repository on GitHub**
   - Go to https://github.com/new
   - Name it "SqlQ" or your preferred name
   - Add a description like "Advanced SQL Injection Scanner Tool"
   - Choose Public or Private visibility
   - Click "Create repository"

3. **Initialize and push your local repository**
   ```bash
   # Navigate to your project directory
   cd SqlQ

   # Initialize git repository
   git init

   # Add all your files
   git add .

   # Commit your files
   git commit -m "Initial commit - SQL Injection Scanner"

   # Set your remote repository
   git remote add origin https://github.com/YourUsername/SqlQ.git

   # Push to GitHub
   git push -u origin main
   ```

4. **If your default branch is 'master' instead of 'main':**
   ```bash
   git push -u origin master
   ```

5. **Verify** your code appears on your GitHub repository page

You may need to authenticate with your GitHub credentials during the push process.
</rewritten_file>