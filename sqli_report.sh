#!/bin/bash
# SQLInjectionScanner Report Module - Generate reports for SQL injection findings
# This file contains functions for generating reports in different formats

# Source the core module
# shellcheck source=sqli_core.sh
. "./sqli_core.sh"

# ---------------------------- Reporting Functions ----------------------------

# Generate reports in different formats
generate_report() {
  local format="$1"
  local output_file="${OUTPUT_DIR}/report"
  local vuln_file="${OUTPUT_DIR}/vulnerabilities.txt"
  
  if [[ ! -f "$vuln_file" ]]; then
    log "ERROR" "Vulnerability file not found. No report to generate."
    return
  fi
  
  case "$format" in
    "txt")
      # Already have the txt format
      cp "$vuln_file" "${output_file}.txt"
      log "INFO" "Text report generated: ${output_file}.txt"
      ;;
    "html")
      # Create HTML report
      {
        echo "<html><head><title>SQL Injection Scan Report: $TARGET_DOMAIN</title>"
        echo "<style>body{font-family:Arial,sans-serif;margin:20px}h1{color:#003366}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px;border:1px solid #ddd}th{background-color:#003366;color:white}tr:nth-child(even){background-color:#f2f2f2}</style>"
        echo "</head><body>"
        echo "<h1>SQL Injection Scan Report</h1>"
        echo "<p><strong>Target Domain:</strong> $TARGET_DOMAIN</p>"
        echo "<p><strong>Scan Date:</strong> $(date)</p>"
        echo "<p><strong>Scan ID:</strong> $SCAN_ID</p>"
        echo "<h2>Vulnerabilities Found: $VULN_COUNT</h2>"
        
        if [[ $VULN_COUNT -gt 0 ]]; then
          echo "<table><tr><th>URL</th><th>Parameter</th><th>Type</th><th>Details</th></tr>"
          while IFS= read -r vuln_entry; do
            url=$(echo "$vuln_entry" | cut -d ' ' -f1)
            param=$(echo "$vuln_entry" | grep -o '\[.*\]' | tr -d '[]')
            type=$(echo "$vuln_entry" | grep -o '\- .*:' | sed 's/\- \(.*\):/\1/' || echo "Unknown")
            details=$(echo "$vuln_entry" | grep -o ':.*$' | sed 's/: //' || echo "")
            echo "<tr><td>$url</td><td>$param</td><td>$type</td><td>$details</td></tr>"
          done < "$vuln_file"
          echo "</table>"
        else
          echo "<p>No SQL injection vulnerabilities were found.</p>"
        fi
        
        echo "<h2>WAF Bypass Methods</h2>"
        echo "<p>Tamper techniques used: $TAMPER_TECHNIQUES</p>"
        
        echo "<h2>Scan Configuration</h2>"
        echo "<ul>"
        echo "<li>Threads: $THREADS</li>"
        echo "<li>Timeout: $TIMEOUT seconds</li>"
        echo "<li>Encoding Level: $ENCODE_LEVEL</li>"
        echo "<li>Auto-detect WAF: $AUTO_WAF_DETECT</li>"
        echo "</ul>"
        
        echo "</body></html>"
      } > "${output_file}.html"
      log "INFO" "HTML report generated: ${output_file}.html"
      ;;
    "json")
      # Create JSON report
      {
        echo "{"
        echo "  \"scan_info\": {"
        echo "    \"target\": \"$TARGET_DOMAIN\","
        echo "    \"date\": \"$(date)\","
        echo "    \"scan_id\": \"$SCAN_ID\","
        echo "    \"vulnerabilities_count\": $VULN_COUNT,"
        echo "    \"configuration\": {"
        echo "      \"threads\": $THREADS,"
        echo "      \"timeout\": $TIMEOUT,"
        echo "      \"encoding_level\": $ENCODE_LEVEL,"
        echo "      \"auto_waf_detect\": $AUTO_WAF_DETECT,"
        echo "      \"tamper_techniques\": \"$TAMPER_TECHNIQUES\""
        echo "    }"
        echo "  },"
        echo "  \"vulnerabilities\": ["
        
        if [[ $VULN_COUNT -gt 0 ]]; then
          first=true
          while IFS= read -r vuln_entry; do
            if ! $first; then
              echo ","
            else
              first=false
            fi
            url=$(echo "$vuln_entry" | cut -d ' ' -f1)
            param=$(echo "$vuln_entry" | grep -o '\[.*\]' | tr -d '[]')
            type=$(echo "$vuln_entry" | grep -o '\- .*:' | sed 's/\- \(.*\):/\1/' || echo "Unknown")
            details=$(echo "$vuln_entry" | grep -o ':.*$' | sed 's/: //' || echo "")
            
            echo -n "    {"
            echo -n "\"url\": \"$url\", "
            echo -n "\"parameter\": \"$param\", "
            echo -n "\"type\": \"$type\", "
            echo -n "\"details\": \"$details\""
            echo -n "}"
          done < "$vuln_file"
        fi
        
        echo ""
        echo "  ]"
        echo "}"
      } > "${output_file}.json"
      log "INFO" "JSON report generated: ${output_file}.json"
      ;;
    "csv")
      # Create CSV report
      {
        echo "URL,Parameter,Type,Details"
        if [[ $VULN_COUNT -gt 0 ]]; then
          while IFS= read -r vuln_entry; do
            url=$(echo "$vuln_entry" | cut -d ' ' -f1)
            param=$(echo "$vuln_entry" | grep -o '\[.*\]' | tr -d '[]')
            type=$(echo "$vuln_entry" | grep -o '\- .*:' | sed 's/\- \(.*\):/\1/' || echo "Unknown")
            details=$(echo "$vuln_entry" | grep -o ':.*$' | sed 's/: //' || echo "")
            echo "\"$url\",\"$param\",\"$type\",\"$details\""
          done < "$vuln_file"
        fi
      } > "${output_file}.csv"
      log "INFO" "CSV report generated: ${output_file}.csv"
      ;;
    "xml")
      # Create XML report
      {
        echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        echo "<scan>"
        echo "  <scan_info>"
        echo "    <target>$TARGET_DOMAIN</target>"
        echo "    <date>$(date)</date>"
        echo "    <scan_id>$SCAN_ID</scan_id>"
        echo "    <vulnerabilities_count>$VULN_COUNT</vulnerabilities_count>"
        echo "    <configuration>"
        echo "      <threads>$THREADS</threads>"
        echo "      <timeout>$TIMEOUT</timeout>"
        echo "      <encoding_level>$ENCODE_LEVEL</encoding_level>"
        echo "      <auto_waf_detect>$AUTO_WAF_DETECT</auto_waf_detect>"
        echo "      <tamper_techniques>$TAMPER_TECHNIQUES</tamper_techniques>"
        echo "    </configuration>"
        echo "  </scan_info>"
        echo "  <vulnerabilities>"
        
        if [[ $VULN_COUNT -gt 0 ]]; then
          while IFS= read -r vuln_entry; do
            url=$(echo "$vuln_entry" | cut -d ' ' -f1)
            param=$(echo "$vuln_entry" | grep -o '\[.*\]' | tr -d '[]')
            type=$(echo "$vuln_entry" | grep -o '\- .*:' | sed 's/\- \(.*\):/\1/' || echo "Unknown")
            details=$(echo "$vuln_entry" | grep -o ':.*$' | sed 's/: //' || echo "")
            
            echo "    <vulnerability>"
            echo "      <url>$url</url>"
            echo "      <parameter>$param</parameter>"
            echo "      <type>$type</type>"
            echo "      <details>$details</details>"
            echo "    </vulnerability>"
          done < "$vuln_file"
        fi
        
        echo "  </vulnerabilities>"
        echo "</scan>"
      } > "${output_file}.xml"
      log "INFO" "XML report generated: ${output_file}.xml"
      ;;
    "all")
      generate_report "txt"
      generate_report "html"
      generate_report "json" 
      generate_report "csv"
      generate_report "xml"
      ;;
    *)
      log "ERROR" "Unknown report format: $format"
      ;;
  esac
}

# Create a summary of the scan
create_scan_summary() {
  local output_file="${OUTPUT_DIR}/summary.txt"
  
  {
    echo "===== SQL Injection Scan Summary ====="
    echo "Target Domain: $TARGET_DOMAIN"
    echo "Scan Date: $(date)"
    echo "Scan ID: $SCAN_ID"
    echo ""
    echo "Statistics:"
    echo "  - Subdomains found: $SUBCOUNT"
    echo "  - URLs collected: $URLCOUNT"
    echo "  - Parameterized URLs: $PARAM_URL_COUNT"
    echo "  - Live URLs: $LIVE_URL_COUNT"
    echo "  - Vulnerabilities found: $VULN_COUNT"
    echo ""
    echo "Configuration:"
    echo "  - Threads: $THREADS"
    echo "  - Timeout: $TIMEOUT seconds"
    echo "  - Encoding Level: $ENCODE_LEVEL"
    echo "  - Auto-detect WAF: $AUTO_WAF_DETECT"
    echo "  - Tamper techniques: $TAMPER_TECHNIQUES"
    echo ""
    echo "Report files:"
    
    if [[ "$REPORT_FORMAT" == "all" ]]; then
      echo "  - ${OUTPUT_DIR}/report.txt"
      echo "  - ${OUTPUT_DIR}/report.html"
      echo "  - ${OUTPUT_DIR}/report.json"
      echo "  - ${OUTPUT_DIR}/report.csv"
      echo "  - ${OUTPUT_DIR}/report.xml"
    else
      echo "  - ${OUTPUT_DIR}/report.${REPORT_FORMAT}"
    fi
    
    echo ""
    if [[ $VULN_COUNT -gt 0 ]]; then
      echo "Vulnerable URLs:"
      cat "${OUTPUT_DIR}/vulnerabilities.txt"
    else
      echo "No SQL injection vulnerabilities found."
    fi
  } > "$output_file"
  
  log "INFO" "Scan summary created: $output_file"
}

# Export functions
export -f generate_report
export -f create_scan_summary 