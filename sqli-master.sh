#!/bin/bash
# SQLi-Master - Unified command for SQL Injection toolkit
# Combines shell scripts and Python modules into a single entry point

# ANSI color codes for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ASCII Art banner
print_banner() {
    echo -e "${CYAN}"
    echo '███████╗ ██████╗ ██╗     ██╗     ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ '
    echo '██╔════╝██╔═══██╗██║     ██║     ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗'
    echo '███████╗██║   ██║██║     ██║     ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝'
    echo '╚════██║██║▄▄ ██║██║     ██║     ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗'
    echo '███████║╚██████╔╝███████╗███████╗██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║'
    echo '╚══════╝ ╚══▀▀═╝ ╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝'
    echo -e "${GREEN}Unified SQL Injection Testing Toolkit ${YELLOW}v2.0${NC}"
    echo -e "${PURPLE}Enhanced WAF Bypass | Smart Payload Generation | Advanced Detection | Multi-Engine${NC}\n"
}

# Check which components are available
check_components() {
    PYTHON_AVAILABLE=false
    SHELL_AVAILABLE=false
    
    if [[ -f "sqli_scanner.py" && -f "waf_identify.py" && -f "db_detector.py" && -f "payload_generator.py" && -f "sqli_detector.py" ]]; then
        if command -v python3 &>/dev/null; then
            PYTHON_AVAILABLE=true
            echo -e "${GREEN}[✓] Python components available${NC}"
        else
            echo -e "${YELLOW}[!] Python components found but python3 is not installed${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Python components not found${NC}"
    fi
    
    if [[ -f "sqli_scanner.sh" && -f "sqli_core.sh" && -f "sqli_detect.sh" ]]; then
        SHELL_AVAILABLE=true
        echo -e "${GREEN}[✓] Shell components available${NC}"
    else
        echo -e "${YELLOW}[!] Shell components not found${NC}"
    fi
    
    if [[ "$PYTHON_AVAILABLE" == "false" && "$SHELL_AVAILABLE" == "false" ]]; then
        echo -e "${RED}[✗] No components found. Please make sure you're in the right directory.${NC}"
        exit 1
    fi
}

# Check for required tools
check_requirements() {
    MISSING_TOOLS=()
    
    for tool in subfinder gau uro httpx sqlmap curl jq bc; do
        if ! command -v "$tool" &>/dev/null; then
            MISSING_TOOLS+=("$tool")
        fi
    done
    
    if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[!] Missing required tools: ${MISSING_TOOLS[*]}${NC}"
        echo -e "${YELLOW}[!] Some functionality may be limited${NC}"
    else
        echo -e "${GREEN}[✓] All required tools available${NC}"
    fi
    
    # Make Python modules executable
    if [[ "$PYTHON_AVAILABLE" == "true" ]]; then
        chmod +x *.py 2>/dev/null
    fi
    
    # Make shell scripts executable
    if [[ "$SHELL_AVAILABLE" == "true" ]]; then
        chmod +x *.sh 2>/dev/null
    fi
}

# Process command-line arguments
process_arguments() {
    # Default values
    MODE="auto"
    TARGET=""
    ARGS=()
    
    # Process arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mode=*)
                MODE="${1#*=}"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                show_version
                exit 0
                ;;
            *)
                if [[ -z "$TARGET" && "$1" != -* ]]; then
                    TARGET="$1"
                else
                    ARGS+=("$1")
                fi
                shift
                ;;
        esac
    done
    
    # Check if target is provided
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[✗] Target domain is required${NC}"
        show_help
        exit 1
    fi
}

# Show help information
show_help() {
    echo -e "${BLUE}Usage:${NC} $0 <target-domain> [options]"
    echo -e "${BLUE}Options:${NC}"
    echo "  --mode=<python|shell|auto>  Select engine mode (default: auto)"
    echo "  --threads <num>             Set number of concurrent threads (default: 10)"
    echo "  --proxy <proxy>             Use proxy (format: http://proxy:port)"
    echo "  --proxy-list <file>         Rotate through proxies in the specified file"
    echo "  --auth <method>             Authentication method: basic, digest, ntlm"
    echo "  --user <username>           Username for authentication"
    echo "  --pass <password>           Password for authentication"
    echo "  --cookie <cookie>           Cookie string for authenticated scanning"
    echo "  --headers <file>            File containing custom headers"
    echo "  --verbose                   Enable verbose output"
    echo "  --report-format <fmt>       Report format (options: txt,html,json,csv,xml,all)"
    echo "  --timeout <sec>             Request timeout in seconds (default: 10)"
    echo "  --user-agent <ua>           Custom User-Agent string"
    echo "  --encode-level <lvl>        Payload encoding level (1-3)"
    echo "  --tamper <techniques>       Comma-separated tamper techniques"
    echo "  --auto-waf                  Auto-detect WAF and use appropriate bypass techniques"
    echo "  --list-tampers              List available tamper techniques"
    echo "  --payload-types <type>      Comma-separated payload types to use (default: all)"
    echo "  --db-detect                 Automatically detect database type for better payloads"
    echo "  --auto-sqlmap               Automatically run sqlmap on found vulnerabilities"
    echo "  --help, -h                  Show this help message"
    echo "  --version, -v               Show version information"
}

# Show version information
show_version() {
    echo -e "${GREEN}SQLi-Master v2.0${NC}"
    echo "Enhanced SQL Injection Testing Toolkit"
    echo "Supports Python and Shell engines"
    echo "Copyright (c) 2025"
}

# Main entry point
main() {
    print_banner
    check_components
    check_requirements
    process_arguments "$@"
    
    echo -e "\n${BLUE}[*] Target: ${GREEN}$TARGET${NC}"
    
    # Select mode based on available components and user preference
    if [[ "$MODE" == "auto" ]]; then
        if [[ "$PYTHON_AVAILABLE" == "true" ]]; then
            MODE="python"
        elif [[ "$SHELL_AVAILABLE" == "true" ]]; then
            MODE="shell"
        else
            echo -e "${RED}[✗] No components available to run in auto mode${NC}"
            exit 1
        fi
    fi
    
    # Run in selected mode
    if [[ "$MODE" == "python" ]]; then
        if [[ "$PYTHON_AVAILABLE" == "true" ]]; then
            echo -e "${BLUE}[*] Running in Python mode${NC}"
            echo -e "${YELLOW}[!] Starting scan...${NC}\n"
            python3 sqli_scanner.py "$TARGET" "${ARGS[@]}"
        else
            echo -e "${RED}[✗] Python components not available${NC}"
            exit 1
        fi
    elif [[ "$MODE" == "shell" ]]; then
        if [[ "$SHELL_AVAILABLE" == "true" ]]; then
            echo -e "${BLUE}[*] Running in Shell mode${NC}"
            echo -e "${YELLOW}[!] Starting scan...${NC}\n"
            ./sqli_scanner.sh "$TARGET" "${ARGS[@]}"
        else
            echo -e "${RED}[✗] Shell components not available${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[✗] Invalid mode: $MODE${NC}"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
