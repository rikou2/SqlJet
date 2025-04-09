#!/bin/bash
# SQL Injection Scanner Installer for Kali Linux
# This script installs and configures the Advanced SQL Injection Scanner

echo "====================================================="
echo "  Advanced SQL Injection Scanner Installer for Kali  "
echo "====================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root"
  exit 1
fi

# Installation directory
INSTALL_DIR="/usr/share/sqlq"
BIN_DIR="/usr/local/bin"

echo "[+] Installing dependencies..."

# Install system dependencies
apt-get update
apt-get install -y curl jq bc parallel python3 python3-pip sqlmap libxml2-utils

# Install Python dependencies
pip3 install requests argparse user_agents urllib3

# Install Go if not already installed
if ! command -v go &> /dev/null; then
    echo "[+] Installing Go..."
    wget -q https://go.dev/dl/go1.21.3.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> /etc/profile
    source /etc/profile
    rm /tmp/go.tar.gz
fi

# Make sure Go binaries are in the path
export PATH=$PATH:/usr/local/go/bin:~/go/bin

# Create installation directory
echo "[+] Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Install Go tools
echo "[+] Installing required Go tools..."
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
GO111MODULE=on go install -v github.com/lc/gau/v2/cmd/gau@latest
GO111MODULE=on go install -v github.com/s0md3v/uro@latest
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Copy shell scripts to installation directory
echo "[+] Copying shell scripts to installation directory..."
cp sqli_*.sh "$INSTALL_DIR/"
cp run-sqliscanner.sh "$INSTALL_DIR/"
cp README.md QUICKSTART.md README_KALI.md "$INSTALL_DIR/" 2>/dev/null || true

# Copy Python scripts to installation directory
echo "[+] Copying Python scripts to installation directory..."
cp *.py "$INSTALL_DIR/" 2>/dev/null || true
cp sqliq "$INSTALL_DIR/"
cp waf_integration.sh "$INSTALL_DIR/"

# Create results directory
mkdir -p "$INSTALL_DIR/results"

# Make scripts executable
echo "[+] Making scripts executable..."
chmod +x "$INSTALL_DIR/"*.sh "$INSTALL_DIR/sqliq" "$INSTALL_DIR/"*.py 2>/dev/null || true

# Create the sqliq command in BIN_DIR
echo "[+] Creating main executable..."
cat > "$BIN_DIR/sqliq" << 'EOF'
#!/bin/bash
# SQLiQ - Unified SQL Injection Scanner Command

# Installation directory
INSTALL_DIR="/usr/share/sqlq"

# Check if script directory exists
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Error: Installation directory not found at $INSTALL_DIR"
    echo "Please run the installer again: sudo bash install.sh"
    exit 1
fi

# Forward all commands to the main sqliq script
cd "$INSTALL_DIR" && ./sqliq "$@"
EOF

# Make the binary executable
chmod +x "$BIN_DIR/sqliq"

# Create symlinks for backward compatibility
ln -sf "$BIN_DIR/sqliq" "$BIN_DIR/sqliscanner"

# Create tamper directory if it doesn't exist
if [ ! -d "$INSTALL_DIR/tamper" ]; then
    mkdir -p "$INSTALL_DIR/tamper"
    touch "$INSTALL_DIR/tamper/__init__.py"
    # Copy tamper scripts from sqlmap if available
    if [ -d "/usr/share/sqlmap/tamper" ]; then
        cp /usr/share/sqlmap/tamper/*.py "$INSTALL_DIR/tamper/"
    fi
fi

# Create payloads directory if it doesn't exist
if [ ! -d "$INSTALL_DIR/Payloads" ]; then
    mkdir -p "$INSTALL_DIR/Payloads"
    
    # Create empty payload files if they don't exist
    for type in "Error_Based" "Time_Based" "Boolean_Based" "Union_Based" "Stacked_Queries" "Stored_Procedure" "Second_Order" "DNS_Exfiltration" "OOB" "Comment_Based" "Hybrid" "WAF_Bypass"; do
        touch "$INSTALL_DIR/Payloads/${type}_SQLi_Payloads.txt"
    done
    
    # Download some sample payloads
    echo "[+] Downloading sample payloads..."
    curl -s "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/time-based.txt" > "$INSTALL_DIR/Payloads/Time_Based_SQLi_Payloads.txt"
    curl -s "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/error-based.txt" > "$INSTALL_DIR/Payloads/Error_Based_SQLi_Payloads.txt"
    curl -s "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/union-based.txt" > "$INSTALL_DIR/Payloads/Union_Based_SQLi_Payloads.txt"
fi

# Create models and data directories for ML module
if [[ -f "$INSTALL_DIR/ml_detection.py" ]]; then
    mkdir -p "$INSTALL_DIR/models" "$INSTALL_DIR/data"
    touch "$INSTALL_DIR/data/ml_training_data.json"
fi

echo "====================================================="
echo "  Installation Completed Successfully!  "
echo "====================================================="
echo ""
echo "Usage:"
echo "  sqliq scan example.com        - Basic scan"
echo "  sqliq quick example.com       - Quick scan with default options"
echo "  sqliq full example.com        - Full scan with WAF bypass"
echo "  sqliq waf https://example.com - Test WAF detection"
echo "  sqliq update                  - Update dependencies"
echo "  sqliq help                    - Show help"
echo ""
echo "Results will be stored in: $INSTALL_DIR/results/"
echo "=====================================================" 