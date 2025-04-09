#!/usr/bin/env python3
# SQLi Detector - Advanced SQL injection detection with WAF bypass
# Integrates with waf_identify.py, db_detector.py, and payload_generator.py

import sys
import os
import re
import time
import json
import random
import urllib.parse
import requests
import concurrent.futures
from datetime import datetime

# Import our custom modules
import waf_identify
import db_detector
import payload_generator

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SQLiDetector:
    def __init__(self, threads=10, timeout=10, verbose=False):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_dir = "results"
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        self.payload_generator = payload_generator.SQLiPayloadGenerator()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        
    def set_output_dir(self, output_dir):
        """Set the output directory for results"""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def log(self, level, message):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if level.upper() == "VERBOSE" and not self.verbose:
            return
            
        prefix = {
            "INFO": "[*]",
            "ERROR": "[!]",
            "SUCCESS": "[+]",
            "VERBOSE": "[V]"
        }.get(level.upper(), "[?]")
        
        print(f"{prefix} {timestamp} - {message}")
        
        # Write to log file if output directory is set
        if self.output_dir:
            log_file = os.path.join(self.output_dir, "sqli_scan.log")
            with open(log_file, "a") as f:
                f.write(f"{timestamp} {prefix} {message}\n")
                
    def detect_waf(self, url):
        """Detect WAF and get bypass strategy"""
        self.log("INFO", f"Detecting WAF for {url}")
        waf_result = waf_identify.get_waf_bypass_strategy(url)
        
        # Parse waf_result which is in format "waf_type:tamper_techniques"
        parts = waf_result.split(":", 1)
        waf_type = parts[0]
        tamper = parts[1] if len(parts) > 1 else ""
        
        if waf_type != "none":
            self.log("SUCCESS", f"WAF detected: {waf_type}")
            self.log("INFO", f"Using tamper techniques: {tamper}")
        else:
            self.log("INFO", "No WAF detected")
            
        return waf_type, tamper
        
    def detect_db_type(self, url, param_name):
        """Detect database type"""
        self.log("INFO", f"Detecting database type for {url}, param: {param_name}")
        db_type = db_detector.detect_database(url, param_name)
        self.log("SUCCESS", f"Detected database type: {db_type}")
        return db_type
        
    def parse_url_params(self, url):
        """Parse URL and extract parameter names and values"""
        if "?" not in url:
            return url, []
            
        base_url = url.split("?")[0]
        query_string = url.split("?")[1]
        
        params = []
        for param_pair in query_string.split("&"):
            if "=" in param_pair:
                name, value = param_pair.split("=", 1)
                params.append((name, value))
                
        return base_url, params
        
    def inject_payload(self, url, param_name, orig_value, payload):
        """Create a URL with the payload injected into the specified parameter"""
        base_url, params = self.parse_url_params(url)
        
        # Replace the value of the target parameter
        new_params = []
        for name, value in params:
            if name == param_name:
                new_params.append(f"{name}={urllib.parse.quote_plus(payload)}")
            else:
                new_params.append(f"{name}={value}")
                
        # Reconstruct the URL
        if new_params:
            return f"{base_url}?{'&'.join(new_params)}"
        else:
            # If no params were in the original URL, add our injected param
            return f"{base_url}?{param_name}={urllib.parse.quote_plus(payload)}"
            
    def test_payload(self, url, param_name, payload, tamper=None):
        """Test a single payload for SQL injection vulnerability"""
        # Apply tamper techniques if provided
        if tamper:
            tampered_payload = self.payload_generator.apply_tamper(payload, tamper)
        else:
            tampered_payload = payload
            
        # Create the injected URL
        injected_url = self.inject_payload(url, param_name, "", tampered_payload)
        
        if self.verbose:
            self.log("VERBOSE", f"Testing: {injected_url}")
            
        try:
            # First get a baseline response
            base_url, _ = self.parse_url_params(url)
            baseline = self.session.get(f"{base_url}", timeout=self.timeout, verify=False)
            
            # Now test the injected URL
            start_time = time.time()
            response = self.session.get(injected_url, timeout=self.timeout, verify=False)
            elapsed_time = time.time() - start_time
            
            # Check for evidence of SQL injection
            result = self.analyze_response(response, baseline, elapsed_time, payload)
            
            if result["vulnerable"]:
                self.log("SUCCESS", f"Found {result['type']} SQLi at {url} [param: {param_name}]: {result['details']}")
                
                # Save the vulnerability details
                vuln_file = os.path.join(self.output_dir, "vulnerabilities.txt")
                with open(vuln_file, "a") as f:
                    f.write(f"{url} [{param_name}] - {result['type']}: {result['details']}\n")
                    
                # Save to structured format
                self.save_vuln_details(url, param_name, payload, result)
                
                return True, result
                
        except requests.exceptions.Timeout:
            # For time-based SQLi, a timeout might be a positive result
            if "SLEEP" in payload.upper() or "BENCHMARK" in payload.upper() or "WAITFOR" in payload.upper() or "PG_SLEEP" in payload.upper():
                self.log("SUCCESS", f"Possible Time-Based SQLi at {url} [param: {param_name}]: timeout triggered")
                
                result = {
                    "vulnerable": True,
                    "type": "Time_Based",
                    "details": "Request timeout - possible time-based SQLi",
                    "payload": payload
                }
                
                # Save the vulnerability
                vuln_file = os.path.join(self.output_dir, "vulnerabilities.txt")
                with open(vuln_file, "a") as f:
                    f.write(f"{url} [{param_name}] - Time_Based: timeout triggered\n")
                    
                # Save to structured format
                self.save_vuln_details(url, param_name, payload, result)
                
                return True, result
                
        except Exception as e:
            if self.verbose:
                self.log("VERBOSE", f"Error testing {injected_url}: {str(e)}")
                
        return False, None
        
    def analyze_response(self, response, baseline, elapsed_time, payload):
        """Analyze the response for signs of SQL injection"""
        # Initialize result
        result = {
            "vulnerable": False,
            "type": "",
            "details": "",
            "payload": payload
        }
        
        # Check for SQL errors
        error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
            # PostgreSQL
            r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result",
            # Microsoft SQL
            r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"Unclosed quotation mark",
            # Oracle
            r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"quoted string not properly terminated",
            # SQLite
            r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
            # Generic
            r"SQL syntax.*", r"syntax error\s*at", r"incorrect syntax near", r"unexpected end of SQL",
            r"Warning.*SQL", r"[0-9]+\s*Syntax\s*Error", r"SQL syntax error"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                error_match = re.search(pattern, response.text, re.IGNORECASE).group(0)
                result["vulnerable"] = True
                result["type"] = "Error_Based"
                result["details"] = f"SQL error: {error_match[:50]}..."
                return result
                
        # Time-based detection
        if elapsed_time > 5.0 and "SLEEP" in payload.upper():
            result["vulnerable"] = True
            result["type"] = "Time_Based"
            result["details"] = f"Time delay: {elapsed_time:.2f}s"
            return result
            
        # Boolean-based detection
        if "1=1" in payload or "'1'='1" in payload:
            # Create a false condition payload
            false_payload = payload.replace("1=1", "1=2").replace("'1'='1", "'1'='2")
            
            try:
                # Test the false condition
                false_url = response.url.replace(payload, false_payload)
                false_response = self.session.get(false_url, timeout=self.timeout, verify=False)
                
                # Compare responses
                if (len(response.text) != len(false_response.text) and 
                    abs(len(response.text) - len(false_response.text)) > 100):
                    result["vulnerable"] = True
                    result["type"] = "Boolean_Based"
                    result["details"] = f"Response difference: {abs(len(response.text) - len(false_response.text))} chars"
                    return result
            except:
                pass
                
        # UNION-based detection
        if "UNION SELECT" in payload.upper():
            # Look for evidence of successful UNION query
            union_pattern = r"\b(1,2,3|2,3,4|NULL,NULL|[0-9]+\s*,\s*[0-9]+)"
            if re.search(union_pattern, response.text):
                result["vulnerable"] = True
                result["type"] = "Union_Based"
                result["details"] = f"UNION query outputs visible in response"
                return result
                
        return result
        
    def save_vuln_details(self, url, param_name, payload, result):
        """Save vulnerability details to structured format"""
        vuln_id = f"SQLI-{int(time.time())}-{random.randint(1000, 9999)}"
        
        details = {
            "id": vuln_id,
            "url": url,
            "param": param_name,
            "type": result["type"],
            "details": result["details"],
            "payload": payload,
            "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save to JSON file
        details_file = os.path.join(self.output_dir, "vuln_details.json")
        
        try:
            # Read existing vulnerabilities if file exists
            if os.path.exists(details_file):
                with open(details_file, "r") as f:
                    vulns = json.load(f)
            else:
                vulns = []
                
            # Add new vulnerability
            vulns.append(details)
            
            # Write back to file
            with open(details_file, "w") as f:
                json.dump(vulns, f, indent=2)
                
        except Exception as e:
            self.log("ERROR", f"Error saving vulnerability details: {str(e)}")
            
    def test_url(self, url, tamper=None, db_type=None):
        """Test a URL for SQL injection vulnerabilities"""
        self.log("INFO", f"Testing {url} for SQL injection")
        
        # Parse URL to get parameters
        base_url, params = self.parse_url_params(url)
        
        if not params:
            self.log("INFO", f"No parameters found in {url}")
            return False
            
        # Detect WAF if not already provided
        waf_type, waf_tamper = None, None
        if not tamper:
            waf_type, waf_tamper = self.detect_waf(url)
            tamper = waf_tamper
            
        # Test each parameter
        for param_name, orig_value in params:
            self.log("INFO", f"Testing parameter '{param_name}' in {url}")
            
            # Detect database type if not already provided
            param_db_type = db_type
            if not param_db_type:
                try:
                    param_db_type = self.detect_db_type(url, param_name)
                except Exception as e:
                    self.log("ERROR", f"Error detecting DB type: {str(e)}")
                    param_db_type = "Generic"
                    
            # Generate payloads based on database type
            payloads = self.payload_generator.generate_for_db(param_db_type or "Generic", count=20)
            
            # Add some specialized payloads
            specialized = self.payload_generator.create_specialized_payloads(param_db_type or "Generic", param_name, waf_type)
            payloads.extend(specialized)
            
            # Deduplicate payloads
            payloads = list(set(payloads))
            
            # Test each payload
            for payload in payloads:
                vulnerable, result = self.test_payload(url, param_name, payload, tamper)
                if vulnerable:
                    self.log("SUCCESS", f"Found SQL injection in {url}, parameter: {param_name}")
                    return True
                    
        return False
        
    def scan_urls(self, urls, tamper=None):
        """Scan multiple URLs for SQL injection, using threads"""
        self.log("INFO", f"Scanning {len(urls)} URLs with {self.threads} threads")
        
        # Create results directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = os.path.join(self.output_dir, f"scan_{timestamp}")
        os.makedirs(scan_dir, exist_ok=True)
        self.set_output_dir(scan_dir)
        
        vulnerabilities = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all URLs for testing
            future_to_url = {executor.submit(self.test_url, url, tamper): url for url in urls}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulnerable = future.result()
                    if vulnerable:
                        vulnerabilities.append(url)
                except Exception as e:
                    self.log("ERROR", f"Error scanning {url}: {str(e)}")
                    
        self.log("INFO", f"Scan complete. Found {len(vulnerabilities)} vulnerable URLs")
        return vulnerabilities
        
def main():
    """Main function when script is run directly"""
    if len(sys.argv) < 2:
        print("Usage: python3 sqli_detector.py <url_or_file> [options]")
        print("Options:")
        print("  --threads <num>     Number of threads (default: 10)")
        print("  --timeout <sec>     Request timeout (default: 10)")
        print("  --tamper <techs>    Tamper techniques (comma-separated)")
        print("  --verbose           Enable verbose output")
        print("  --output <dir>      Output directory (default: results)")
        sys.exit(1)
        
    target = sys.argv[1]
    threads = 10
    timeout = 10
    tamper = None
    verbose = False
    output_dir = "results"
    
    # Parse command line arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--threads" and i+1 < len(sys.argv):
            threads = int(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == "--timeout" and i+1 < len(sys.argv):
            timeout = int(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == "--tamper" and i+1 < len(sys.argv):
            tamper = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == "--verbose":
            verbose = True
            i += 1
        elif sys.argv[i] == "--output" and i+1 < len(sys.argv):
            output_dir = sys.argv[i+1]
            i += 2
        else:
            i += 1
            
    # Create detector
    detector = SQLiDetector(threads=threads, timeout=timeout, verbose=verbose)
    detector.set_output_dir(output_dir)
    
    # Check if target is a file or URL
    if os.path.isfile(target):
        # Read URLs from file
        with open(target, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        detector.scan_urls(urls, tamper)
    else:
        # Single URL
        detector.test_url(target, tamper)
        
if __name__ == "__main__":
    main()
