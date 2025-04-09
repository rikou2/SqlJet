#!/bin/bash
# Enhanced SQL Injection Scanner Launcher
# This script automatically selects the best options for the SQL injection scanner

# Check if target is provided
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target-domain> [additional-options]"
  echo "Example: $0 example.com --verbose"
  exit 1
fi

TARGET="$1"
shift

# Default best options
OPTIONS=(
  "--auto-waf"          # Automatically detect and bypass WAF
  "--threads 15"        # Good balance for most systems
  "--report-format all" # Generate all report formats
  "--encode-level 3"    # Use advanced encoding
  "--timeout 15"        # Reasonable timeout
)

# Check if user wants SQLmap integration
read -r -p "Do you want to automatically run SQLmap on found vulnerabilities? (y/N): " sqlmap_choice
if [[ "$sqlmap_choice" == "y" || "$sqlmap_choice" == "Y" ]]; then
  OPTIONS+=("--auto-sqlmap")
fi

# Check if user wants to use a proxy
read -r -p "Do you want to use a proxy? (y/N): " proxy_choice
if [[ "$proxy_choice" == "y" || "$proxy_choice" == "Y" ]]; then
  read -r -p "Enter proxy URL (e.g., http://127.0.0.1:8080): " proxy_url
  OPTIONS+=("--proxy $proxy_url")
fi

# Check if user wants to use cookies (e.g., for authenticated scanning)
read -r -p "Do you need to provide cookies for authenticated scanning? (y/N): " cookie_choice
if [[ "$cookie_choice" == "y" || "$cookie_choice" == "Y" ]]; then
  read -r -p "Enter cookie string: " cookie_string
  OPTIONS+=("--cookie \"$cookie_string\"")
fi

# Build the final command
CMD="./sqli_scanner.sh $TARGET ${OPTIONS[*]} $*"

# Print the command that will be executed
echo "Executing: $CMD"
echo "Press Ctrl+C to cancel or Enter to continue..."
read -r

# Execute the command
eval "$CMD" 