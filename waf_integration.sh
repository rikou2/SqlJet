#!/bin/bash
# WAF Integration for SQL Injection Scanner
# This script acts as a bridge between the Python WAF detection and the shell scripts

# Directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if the Python script exists
if [ ! -f "$SCRIPT_DIR/waf_integration.py" ]; then
    echo "Error: waf_integration.py not found in $SCRIPT_DIR"
    exit 1
fi

# Make sure the Python script is executable
chmod +x "$SCRIPT_DIR/waf_integration.py"

# Function to detect WAF and get bypass techniques
detect_waf() {
    local url="$1"
    local user_agent="$2"
    
    if [ -z "$user_agent" ]; then
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
    fi
    
    # Call the Python script with shell output flag
    if [ -n "$url" ]; then
        "$SCRIPT_DIR/waf_integration.py" "$url" --user-agent "$user_agent" --shell-output
    else
        echo "none:none"
    fi
}

# Function to list available tamper techniques
list_tamper_techniques() {
    "$SCRIPT_DIR/waf_integration.py" --list-tampers
}

# If the script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Check if we're listing tamper techniques
    if [[ "$1" == "--list-tampers" ]]; then
        list_tamper_techniques
        exit 0
    fi
    
    # Otherwise, detect WAF for the given URL
    if [ -z "$1" ]; then
        echo "Usage: $0 <URL> [user-agent]"
        exit 1
    fi
    
    detect_waf "$1" "$2"
fi 