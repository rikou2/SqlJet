#!/bin/bash
# SqlJet Ai Installation Script
# This script automates the installation of SqlJet Ai and its dependencies

set -e # Exit on error

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << "EOF"
   ______     _ ___      _      _     ___ 
  /  ___/ __ | |   \    | |    / \   |_ _|
  \___ \ / _` | |) |_  | |   / _ \   | | 
   ___) | (_| |  __/ |_| |  / ___ \  | | 
  |____/ \__, |_|  \___/  /_/   \_\ |___|
         |___/  Ai V1           

         ~ Installation Script ~
EOF
echo -e "${NC}"

echo -e "${GREEN}[+] Starting SqlJet Ai installation...${NC}"

# Check if we're running as root (needed for some package installations)
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}[!] Running as root. This may cause permission issues with Go installations.${NC}"
    echo -e "${YELLOW}[!] Consider running without sudo and using sudo for apt commands only.${NC}"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}[!] Installation aborted.${NC}"
        exit 1
    fi
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    echo -e "${GREEN}[+] Detected OS: $OS${NC}"
elif [ "$(uname)" == "Darwin" ]; then
    OS="macOS"
    echo -e "${GREEN}[+] Detected OS: macOS${NC}"
else
    OS="Unknown"
    echo -e "${YELLOW}[!] Unknown OS, will attempt generic installation${NC}"
fi

# Install system dependencies
echo -e "${GREEN}[+] Installing system dependencies...${NC}"

if [[ "$OS" == *"Kali"* ]] || [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv git curl wget golang
    
    # Install SQLMap if not already installed
    if ! command -v sqlmap &> /dev/null; then
        echo -e "${GREEN}[+] Installing SQLMap...${NC}"
        sudo apt install -y sqlmap
    else
        echo -e "${GREEN}[+] SQLMap already installed${NC}"
    fi
    
elif [[ "$OS" == "macOS" ]]; then
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo -e "${GREEN}[+] Installing Homebrew...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
        echo -e "${GREEN}[+] Homebrew already installed${NC}"
    fi
    
    brew install python3 go git
    
    # Install SQLMap if not already installed
    if ! command -v sqlmap &> /dev/null; then
        echo -e "${GREEN}[+] Installing SQLMap...${NC}"
        brew install sqlmap
    else
        echo -e "${GREEN}[+] SQLMap already installed${NC}"
    fi
    
else
    echo -e "${YELLOW}[!] Unsupported OS for automatic system dependency installation${NC}"
    echo -e "${YELLOW}[!] Please install Python 3.6+, pip, Go 1.17+, git, and sqlmap manually${NC}"
    read -p "Continue with the rest of the installation? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}[!] Installation aborted.${NC}"
        exit 1
    fi
fi

# Create virtual environment
echo -e "${GREEN}[+] Creating Python virtual environment...${NC}"
python3 -m venv .venv
source .venv/bin/activate

# Clone WAFW00F if not already present
if [ ! -d "wafw00f" ]; then
    echo -e "${GREEN}[+] Cloning WAFW00F repository...${NC}"
    git clone https://github.com/EnableSecurity/wafw00f.git
else
    echo -e "${GREEN}[+] WAFW00F directory already exists${NC}"
fi

# Install Python dependencies
echo -e "${GREEN}[+] Installing Python dependencies...${NC}"
pip install -r requirements.txt
pip install -e wafw00f

# Install Go tools
echo -e "${GREEN}[+] Installing Go tools...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Make the CLI executable
echo -e "${GREEN}[+] Setting up SqlJet CLI...${NC}"
chmod +x run_sqljet.py
ln -sf run_sqljet.py sqljet
chmod +x sqljet

# Create activation script
echo -e "${GREEN}[+] Creating activation script...${NC}"
cat > activate_sqljet.sh << 'EOF'
#!/bin/bash
# SqlJet Ai Activation Script
# This script activates the virtual environment and sets up PATH

# Activate virtual environment
source .venv/bin/activate

# Add Go binaries to PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Display banner
echo -e "\033[0;36m"
cat << "BANNER"
   ______     _ ___      _      _     ___ 
  /  ___/ __ | |   \    | |    / \   |_ _|
  \___ \ / _` | |) |_  | |   / _ \   | | 
   ___) | (_| |  __/ |_| |  / ___ \  | | 
  |____/ \__, |_|  \___/  /_/   \_\ |___|
         |___/  Ai V1           

       ~ Environment Activated ~
BANNER
echo -e "\033[0m"

echo -e "\033[0;32m[+] SqlJet Ai environment activated\033[0m"
echo -e "\033[0;32m[+] Use ./sqljet to run the tool\033[0m"
echo -e "\033[0;32m[+] Example: ./sqljet -u example.com --auto-waf\033[0m"
EOF

chmod +x activate_sqljet.sh

echo -e "${GREEN}[+] SqlJet Ai installation completed!${NC}"
echo -e "${GREEN}[+] To activate the environment, run: source activate_sqljet.sh${NC}"
echo -e "${GREEN}[+] After activation, run: ./sqljet --help${NC}" 