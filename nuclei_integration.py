#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
import re
import time
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

class NucleiIntegration:
    """Integration with ProjectDiscovery's Nuclei AI-powered vulnerability scanner for SQL injection detection."""

    def __init__(self, api_key=None, output_dir=None, verify_ssl=True, debug=False, nuclei_path=None, katana_path=None):
        """
        Initialize the Nuclei integration module.
        
        Args:
            api_key (str): ProjectDiscovery API key (optional, can be set via env var PDCP_API_KEY)
            output_dir (str): Directory to save results
            verify_ssl (bool): Whether to verify SSL certificates
            debug (bool): Enable debug output
            nuclei_path (str): Absolute path to nuclei executable (defaults to "nuclei" in PATH)
            katana_path (str): Absolute path to katana executable (defaults to "katana" in PATH)
        """
        self.api_key = api_key or os.environ.get("PDCP_API_KEY")
        self.output_dir = output_dir
        self.verify_ssl = verify_ssl
        self.debug = debug
        
        # Use absolute paths if provided, otherwise rely on PATH
        self.nuclei_path = nuclei_path or "nuclei"
        self.katana_path = katana_path or "katana"
        self.environment = os.environ.copy()
        
        # Add API key to environment if provided
        if self.api_key:
            self.environment["PDCP_API_KEY"] = self.api_key
        
        # Create results directory if it doesn't exist
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def log_info(self, message):
        """Log an informational message."""
        print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
    
    def log_success(self, message):
        """Log a success message."""
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
    
    def log_warning(self, message):
        """Log a warning message."""
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
    
    def log_error(self, message):
        """Log an error message."""
        print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
    
    def log_debug(self, message):
        """Log a debug message if debug mode is enabled."""
        if self.debug:
            print(f"{Fore.MAGENTA}[DEBUG] {message}{Style.RESET_ALL}")
    
    def check_nuclei_installation(self):
        """
        Check if Nuclei is installed and available in the PATH.
        
        Returns:
            bool: True if Nuclei is installed, False otherwise
        """
        try:
            # Use the configured nuclei_path instead of hardcoded "nuclei"
            proc = subprocess.run([self.nuclei_path, "-version"], 
                                 capture_output=True, 
                                 text=True, 
                                 env=self.environment)
            
            if proc.returncode == 0:
                version = proc.stdout.strip()
                self.log_success(f"Nuclei is installed: {version}")
                return True
            else:
                self.log_error("Nuclei is installed but returned an error.")
                return False
        except FileNotFoundError:
            self.log_error("Nuclei is not installed or not in PATH. Please install it first.")
            self.log_info("You can install nuclei using: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return False
    
    def check_api_key(self):
        """
        Check if the ProjectDiscovery API key is configured.
        
        Returns:
            bool: True if API key is configured, False otherwise
        """
        if self.api_key:
            self.log_success("ProjectDiscovery API key is configured.")
            return True
        else:
            self.log_error("ProjectDiscovery API key is not configured.")
            self.log_info("Please set your API key using: export PDCP_API_KEY=your_api_key")
            self.log_info("You can get an API key from: cloud.projectdiscovery.io")
            return False
    
    def run_nuclei_scan(self, target, ai_prompt, output_file=None, verbose=False, rate_limit=150, timeout=15):
        """
        Run a Nuclei scan with an AI prompt.
        
        Args:
            target (str): Target URL or file with targets
            ai_prompt (str): AI prompt for Nuclei scan
            output_file (str): Output file for scan results
            verbose (bool): Enable verbose output
            rate_limit (int): Rate limit for requests
            timeout (int): Timeout for requests
            
        Returns:
            dict: Scan results with status and findings
        """
        if not self.check_nuclei_installation():
            return {"status": "error", "message": "Nuclei not installed"}
        
        if not self.check_api_key():
            return {"status": "error", "message": "API key not configured"}
        
        if not output_file and self.output_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"nuclei_scan_{timestamp}.json"
            output_file = os.path.join(self.output_dir, output_name)
        
        # Build Nuclei command with absolute path
        command = [self.nuclei_path]
        
        # Handle target
        if os.path.isfile(target):
            command.extend(["-list", target])
            # More robust detection of jsonl format
            if target.endswith(".jsonl") or target.endswith(".json"):
                command.extend(["-im", "jsonl"])
                # Increase timeout for jsonl scanning, as these typically need more time
                timeout = max(timeout, 20)  # Ensure minimum 20s timeout for jsonl scanning
                self.log_info(f"Detected jsonl format, increased timeout to {timeout}s")
        else:
            command.extend(["-target", target])
        
        # Add AI prompt
        command.extend(["-ai", ai_prompt])
        
        # Add output file
        if output_file:
            command.extend(["-o", output_file, "-j"])
        
        # Add options for verbosity
        if verbose:
            command.append("-v")
        
        # Set rate limit
        command.extend(["-rate-limit", str(rate_limit)])
        
        # Set timeout
        command.extend(["-timeout", str(timeout)])
        
        # Skip SSL verification if requested
        if not self.verify_ssl:
            command.append("-no-verify")
        
        # Execute the command
        self.log_info(f"Running Nuclei scan: {' '.join(command)}")
        start_time = time.time()
        
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.environment
            )
            
            vulnerabilities = []
            sql_injection_found = False
            
            # Process output in real-time
            for line in process.stdout:
                if "SQL" in line and "injection" in line.lower():
                    sql_injection_found = True
                    self.log_success(f"SQL Injection vulnerability found!")
                    print(f"{Fore.RED}{Style.BRIGHT}[VULNERABLE] {line.strip()}{Style.RESET_ALL}")
                    vulnerabilities.append(line.strip())
                elif "time-based" in line.lower() or "time delay" in line.lower():
                    # Highlight time-based detection attempts
                    print(f"{Fore.YELLOW}[TIME-BASED] {line.strip()}{Style.RESET_ALL}")
                elif "executing" in line.lower() and "payload" in line.lower():
                    # Show when nuclei is executing payloads
                    print(f"{Fore.BLUE}[PAYLOAD] {line.strip()}{Style.RESET_ALL}")
                elif verbose:
                    print(line.strip())
            
            process.wait()
            end_time = time.time()
            duration = round(end_time - start_time, 2)
            
            if process.returncode == 0:
                self.log_success(f"Nuclei scan completed in {duration} seconds.")
                if sql_injection_found:
                    self.log_success(f"SQL Injection vulnerabilities were found! Check {output_file} for details.")
                else:
                    self.log_info("No SQL Injection vulnerabilities were found.")
                
                return {
                    "status": "success",
                    "duration": duration,
                    "output_file": output_file,
                    "sql_injection_found": sql_injection_found,
                    "vulnerabilities": vulnerabilities
                }
            else:
                stderr = process.stderr.read()
                self.log_error(f"Nuclei scan failed: {stderr}")
                return {
                    "status": "error", 
                    "message": stderr,
                    "duration": duration
                }
                
        except Exception as e:
            self.log_error(f"Error running Nuclei scan: {str(e)}")
            return {"status": "error", "message": str(e)}

    def find_sql_injections(self, target, output_file=None):
        """
        Run a comprehensive SQL injection scan using multiple Nuclei AI prompts.
        
        Args:
            target (str): Target URL, domain, or file with targets
            output_file (str): Output file for scan results
            
        Returns:
            dict: Scan results with status, findings and vulnerabilities
        """
        self.log_info(f"Starting comprehensive SQL injection scan on {target}")
        
        # Comprehensive SQL injection detection prompts (user-provided)
        ai_prompts = [
            # Basic SQL injection techniques
            "Identify SQL injection vulnerabilities using boolean-based conditions.",
            "Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data.",
            "Check for error messages revealing SQL queries.",
            
            # Time-based techniques
            "Use time-based techniques to find blind SQL injection.",
            "Detect SQL injection vulnerabilities using time delay techniques.",
            "Scan for time based SQL injection in all parameters",
            "Fuzz all parameters with sql injection detection payloads for mysql, mssql, postgresql, etc. Use time base detection payloads",
            
            # Parameter-specific scanning
            "Find SQL injection in 'id', 'user', 'product', 'category', 'page' parameters",
            "Scan for blind SQL injection in 's', 'search', 'query', 'sort', 'filter' GET/POST parameters",
            
            # Advanced techniques
            "Identify second-order SQL injection vulnerabilities where input is stored and executed later.",
            "Identify SQL injection in API endpoints using JSON payloads",
            "Check for SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host)"
        ]
        
        # Storage for results
        consolidated_results = {
            "status": "success", 
            "vulnerabilities": [],
            "sql_injection_found": False,
            "scans_completed": 0,
            "scans_total": len(ai_prompts)
        }
        
        for idx, prompt in enumerate(ai_prompts, 1):
            self.log_info(f"Running SQL injection scan {idx}/{len(ai_prompts)}: {prompt}")
            
            # Generate output filename for this specific scan
            if self.output_dir:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                prompt_slug = prompt.split()[0].lower()
                scan_output = os.path.join(
                    self.output_dir, 
                    f"nuclei_sqli_{prompt_slug}_{timestamp}.json"
                )
            else:
                scan_output = None
            
            # Run the scan with this prompt
            result = self.run_nuclei_scan(
                target=target,
                ai_prompt=prompt,
                output_file=scan_output,
                verbose=self.debug,
                timeout=10  # Longer timeout for SQL injection
            )
            
            # Update consolidated results
            consolidated_results["scans_completed"] += 1
            
            if result["status"] == "success" and result.get("sql_injection_found", False):
                consolidated_results["sql_injection_found"] = True
                consolidated_results["vulnerabilities"].extend(result.get("vulnerabilities", []))
            
            # Short delay between scans to avoid rate limiting
            time.sleep(2)
        
        # Remove duplicate findings
        consolidated_results["vulnerabilities"] = list(set(consolidated_results["vulnerabilities"]))
        
        # Write final consolidated output if requested
        if output_file and consolidated_results["vulnerabilities"]:
            try:
                with open(output_file, 'w') as f:
                    json.dump(consolidated_results, f, indent=2)
                self.log_success(f"Consolidated results saved to {output_file}")
            except Exception as e:
                self.log_error(f"Error saving consolidated results: {str(e)}")
        
        return consolidated_results

    def scan_katana_output(self, katana_file, output_file=None):
        """
        Scan targets found by Katana crawler.
        
        Args:
            katana_file (str): Path to Katana output file (JSONL format)
            output_file (str): Output file for scan results
            
        Returns:
            dict: Scan results with status and findings
        """
        if not os.path.exists(katana_file):
            self.log_error(f"Katana output file not found: {katana_file}")
            return {"status": "error", "message": "Katana file not found"}
        
        self.log_info(f"Scanning targets from Katana output: {katana_file}")
        
        # Comprehensive SQL injection detection prompts for Katana output (user-provided)
        ai_prompts = [
            # From user's prompt list specifically for Katana jsonl format
            "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting SQL Injection vulnerabilities with pre-conditions.",
            "Detect SQL error messages indicating SQL injection vulnerabilities",
            "Find SQL injection in 'id', 'user', 'product', 'category', 'page' parameters",
            "Scan for blind SQL injection in 's', 'search', 'query', 'sort', 'filter' GET/POST parameters",
            "Scan for time based SQL injection in all parameters",
            "Identify SQL injection in API endpoints using JSON payloads",
            "Check for SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host)"
        ]
        
        # Storage for results
        consolidated_results = {
            "status": "success", 
            "vulnerabilities": [],
            "sql_injection_found": False,
            "scans_completed": 0,
            "scans_total": len(ai_prompts)
        }
        
        for idx, prompt in enumerate(ai_prompts, 1):
            self.log_info(f"Running scan {idx}/{len(ai_prompts)} on Katana output: {prompt}")
            
            # Generate output filename for this specific scan
            if self.output_dir:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                prompt_slug = prompt.split()[0].lower()
                scan_output = os.path.join(
                    self.output_dir, 
                    f"nuclei_katana_{prompt_slug}_{timestamp}.json"
                )
            else:
                scan_output = None
            
            # Run the scan with this prompt
            result = self.run_nuclei_scan(
                target=katana_file,
                ai_prompt=prompt,
                output_file=scan_output,
                verbose=self.debug,
                rate_limit=100,
                timeout=15  # Increased timeout for more thorough scanning
            )
            
            # Update consolidated results
            consolidated_results["scans_completed"] += 1
            
            if result["status"] == "success" and result.get("sql_injection_found", False):
                consolidated_results["sql_injection_found"] = True
                consolidated_results["vulnerabilities"].extend(result.get("vulnerabilities", []))
            
            # Short delay between scans to avoid rate limiting
            time.sleep(2)
        
        # Remove duplicate findings
        consolidated_results["vulnerabilities"] = list(set(consolidated_results["vulnerabilities"]))
        
        # Write final consolidated output if requested
        if output_file and consolidated_results["vulnerabilities"]:
            try:
                with open(output_file, 'w') as f:
                    json.dump(consolidated_results, f, indent=2)
                self.log_success(f"Consolidated results saved to {output_file}")
            except Exception as e:
                self.log_error(f"Error saving consolidated results: {str(e)}")
        
        return consolidated_results

# Example usage
if __name__ == "__main__":
    # This will only run when the script is executed directly, not when imported
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [--api-key KEY] [--output-dir DIR] [--disable-ssl-verify]")
        sys.exit(1)
    
    target = sys.argv[1]
    api_key = None
    output_dir = "./results"
    verify_ssl = True
    
    # Parse command line arguments
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == "--api-key" and i + 1 < len(sys.argv):
            api_key = sys.argv[i + 1]
        elif sys.argv[i] == "--output-dir" and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
        elif sys.argv[i] == "--disable-ssl-verify":
            verify_ssl = False
    
    # Create the integration instance
    nuclei = NucleiIntegration(
        api_key=api_key,
        output_dir=output_dir,
        debug=True
    )
    
    # Run a comprehensive SQL injection scan
    results = nuclei.find_sql_injections(
        target=target,
        output_file=os.path.join(output_dir, "nuclei_sqli_results.json")
    )
    
    # Print scan summary
    if results["sql_injection_found"]:
        print(f"\n{Fore.RED}{Style.BRIGHT}SQL INJECTION VULNERABILITIES DETECTED:{Style.RESET_ALL}")
        for vuln in results["vulnerabilities"]:
            print(f"{Fore.RED}[VULNERABLE] {vuln}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}{Style.BRIGHT}Total: {len(results['vulnerabilities'])} SQL injection points found{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}No SQL injection vulnerabilities were found.{Style.RESET_ALL}")
