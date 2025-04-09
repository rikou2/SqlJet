#!/usr/bin/env python3
# SQLi Scanner - Main entry point for the improved SQL injection scanner
# Integrates shell scripts with Python modules for advanced detection and exploitation

import os
import sys
import json
import argparse
import subprocess
import concurrent.futures
from datetime import datetime
import random
import string
import urllib.parse

# Import our custom modules
import waf_identify
import db_detector
import payload_generator
import sqli_detector

# ASCII art banner
BANNER = """
███████╗ ██████╗ ██╗     ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔═══██╗██║     ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║   ██║██║     ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║▄▄ ██║██║     ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╔╝███████╗██║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                        v2.0 - Advanced Edition
"""

class SQLiScanner:
    def __init__(self, args):
        self.args = args
        self.scan_id = self.generate_scan_id()
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.output_dir = f"results/{args.target}/{self.timestamp}"
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize logger
        self.setup_logging()
        
        # Initialize sub-modules
        self.detector = sqli_detector.SQLiDetector(
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose
        )
        self.detector.set_output_dir(self.output_dir)
        
        self.payload_generator = payload_generator.SQLiPayloadGenerator()
        
    def generate_scan_id(self):
        """Generate a unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"SCAN_{timestamp}_{random_str}"
        
    def setup_logging(self):
        """Set up logging"""
        self.log_file = os.path.join(self.output_dir, "scan.log")
        
        # Write initial scan info
        with open(self.log_file, "w") as f:
            f.write(f"SQL Injection Scanner v2.0\n")
            f.write(f"Scan started at: {datetime.now()}\n")
            f.write(f"Scan ID: {self.scan_id}\n")
            f.write(f"Target: {self.args.target}\n")
            f.write(f"Output directory: {self.output_dir}\n")
            f.write("-" * 80 + "\n")
    
    def log(self, level, message):
        """Log a message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        prefix = {
            "INFO": "[*]",
            "ERROR": "[!]",
            "SUCCESS": "[+]",
            "VERBOSE": "[V]",
            "WARNING": "[W]"
        }.get(level.upper(), "[?]")
        
        log_message = f"{timestamp} {prefix} {message}"
        
        # Print to console
        if level.upper() != "VERBOSE" or self.args.verbose:
            print(log_message)
            
        # Write to log file
        with open(self.log_file, "a") as f:
            f.write(log_message + "\n")
            
    def enumerate_subdomains(self):
        """Enumerate subdomains using subfinder"""
        self.log("INFO", f"Enumerating subdomains for {self.args.target}...")
        
        subfinder_output = os.path.join(self.output_dir, "subdomains.txt")
        
        try:
            # Run subfinder
            cmd = ["subfinder", "-d", self.args.target, "-silent", "-o", subfinder_output]
            if self.args.threads:
                cmd.extend(["-t", str(self.args.threads)])
                
            subprocess.run(cmd, check=True)
            
            # Ensure main domain is included
            with open(subfinder_output, "r") as f:
                subdomains = [line.strip() for line in f]
                
            if self.args.target not in subdomains:
                with open(subfinder_output, "a") as f:
                    f.write(f"{self.args.target}\n")
                    
            # Count subdomains
            with open(subfinder_output, "r") as f:
                count = sum(1 for _ in f)
                
            self.log("SUCCESS", f"Found {count} subdomains (including root domain)")
            return subfinder_output
            
        except subprocess.SubprocessError as e:
            self.log("ERROR", f"Error running subfinder: {e}")
            
            # Create file with just the main domain
            with open(subfinder_output, "w") as f:
                f.write(f"{self.args.target}\n")
                
            self.log("WARNING", "Using only the root domain")
            return subfinder_output
            
    def gather_urls(self, subdomains_file):
        """Gather URLs using gau and uro"""
        self.log("INFO", "Gathering URLs from various sources...")
        
        raw_urls = os.path.join(self.output_dir, "urls_raw.txt")
        urls_file = os.path.join(self.output_dir, "urls.txt")
        
        try:
            # Run gau to fetch URLs
            with open(subdomains_file, "r") as f, open(raw_urls, "w") as out:
                cmd = ["gau", "--threads", str(self.args.threads)]
                gau = subprocess.Popen(cmd, stdin=f, stdout=out)
                gau.wait()
                
            # Deduplicate with uro
            subprocess.run(["uro", "-i", raw_urls, "-o", urls_file], check=True)
            
            # Count URLs
            with open(urls_file, "r") as f:
                count = sum(1 for _ in f)
                
            self.log("SUCCESS", f"Collected {count} unique URLs after deduplication")
            return urls_file
            
        except subprocess.SubprocessError as e:
            self.log("ERROR", f"Error gathering URLs: {e}")
            return None
            
    def filter_parameterized_urls(self, urls_file):
        """Filter URLs with parameters"""
        self.log("INFO", "Filtering URLs with parameters...")
        
        param_urls = os.path.join(self.output_dir, "param_urls.txt")
        
        try:
            # Filter URLs with "?"
            with open(urls_file, "r") as f, open(param_urls, "w") as out:
                for line in f:
                    if "?" in line:
                        out.write(line)
                        
            # Count parameterized URLs
            with open(param_urls, "r") as f:
                count = sum(1 for _ in f)
                
            if count == 0:
                self.log("ERROR", "No parameterized URLs found. SQLi scan will not proceed.")
                return None
                
            self.log("SUCCESS", f"Found {count} URLs with parameters")
            return param_urls
            
        except Exception as e:
            self.log("ERROR", f"Error filtering parameterized URLs: {e}")
            return None
            
    def check_live_urls(self, param_urls_file):
        """Check which URLs are live using httpx"""
        self.log("INFO", "Checking which parameterized URLs are live...")
        
        live_urls = os.path.join(self.output_dir, "live_urls.txt")
        
        try:
            # Run httpx to check live URLs
            cmd = ["httpx", "-silent", "-l", param_urls_file, "-mc", "200", "-o", live_urls]
            if self.args.threads:
                cmd.extend(["-threads", str(self.args.threads)])
                
            subprocess.run(cmd, check=True)
            
            # Count live URLs
            with open(live_urls, "r") as f:
                count = sum(1 for _ in f)
                
            if count == 0:
                self.log("ERROR", "No live parameterized URLs found. Exiting.")
                return None
                
            self.log("SUCCESS", f"Found {count} live parameterized URLs")
            return live_urls
            
        except subprocess.SubprocessError as e:
            self.log("ERROR", f"Error checking live URLs: {e}")
            return None
            
    def scan_urls(self, live_urls_file):
        """Scan URLs for SQL injection vulnerabilities"""
        self.log("INFO", "Scanning URLs for SQL injection vulnerabilities...")
        
        try:
            # Read live URLs
            with open(live_urls_file, "r") as f:
                urls = [line.strip() for line in f]
                
            # Scan URLs using the detector
            vulnerabilities = self.detector.scan_urls(urls, self.args.tamper)
            
            # Count vulnerabilities
            count = len(vulnerabilities)
            
            if count > 0:
                self.log("SUCCESS", f"Found {count} vulnerable URLs")
            else:
                self.log("INFO", "No SQL injection vulnerabilities found")
                
            return vulnerabilities
            
        except Exception as e:
            self.log("ERROR", f"Error scanning URLs: {e}")
            return []
            
    def save_report(self, vulnerabilities):
        """Save scan report"""
        self.log("INFO", "Generating scan report...")
        
        report_file = os.path.join(self.output_dir, "report.md")
        json_report = os.path.join(self.output_dir, "report.json")
        
        try:
            # Read vulnerability details
            vuln_details = []
            vuln_details_file = os.path.join(self.output_dir, "vuln_details.json")
            if os.path.exists(vuln_details_file):
                with open(vuln_details_file, "r") as f:
                    vuln_details = json.load(f)
                    
            # Create JSON report
            report = {
                "scan_id": self.scan_id,
                "target": self.args.target,
                "timestamp": self.timestamp,
                "vulnerabilities": vuln_details,
                "settings": {
                    "threads": self.args.threads,
                    "timeout": self.args.timeout,
                    "tamper": self.args.tamper,
                    "auto_waf": self.args.auto_waf
                }
            }
            
            with open(json_report, "w") as f:
                json.dump(report, f, indent=2)
                
            # Create markdown report
            with open(report_file, "w") as f:
                f.write(f"# SQL Injection Scan Report\n\n")
                f.write(f"## Scan Details\n\n")
                f.write(f"- **Target:** {self.args.target}\n")
                f.write(f"- **Scan ID:** {self.scan_id}\n")
                f.write(f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"- **Vulnerabilities Found:** {len(vuln_details)}\n\n")
                
                if vuln_details:
                    f.write(f"## Vulnerabilities\n\n")
                    f.write(f"| ID | URL | Parameter | Type | Details |\n")
                    f.write(f"|---|---|---|---|---|\n")
                    
                    for vuln in vuln_details:
                        f.write(f"| {vuln['id']} | {vuln['url']} | {vuln['param']} | {vuln['type']} | {vuln['details']} |\n")
                        
                else:
                    f.write(f"## No vulnerabilities found\n\n")
                    
                f.write(f"\n## Scan Settings\n\n")
                f.write(f"- **Threads:** {self.args.threads}\n")
                f.write(f"- **Timeout:** {self.args.timeout} seconds\n")
                f.write(f"- **Tamper:** {self.args.tamper or 'Auto-detected'}\n")
                f.write(f"- **Auto WAF:** {self.args.auto_waf}\n")
                
            self.log("SUCCESS", f"Report saved to {report_file} and {json_report}")
            
        except Exception as e:
            self.log("ERROR", f"Error generating report: {e}")
            
    def run_sqlmap(self, vulnerabilities):
        """Run sqlmap on found vulnerabilities"""
        if not self.args.auto_sqlmap or not vulnerabilities:
            return
            
        self.log("INFO", "Running sqlmap on found vulnerabilities...")
        
        sqlmap_dir = os.path.join(self.output_dir, "sqlmap")
        os.makedirs(sqlmap_dir, exist_ok=True)
        
        for url in vulnerabilities:
            try:
                # Extract parameter name
                param_name = None
                if "?" in url:
                    query = url.split("?")[1]
                    if "=" in query:
                        param_name = query.split("=")[0]
                        
                if not param_name:
                    self.log("WARNING", f"Could not extract parameter name from {url}")
                    continue
                    
                # Run sqlmap
                self.log("INFO", f"Running sqlmap on {url} (parameter: {param_name})")
                
                output_dir = os.path.join(sqlmap_dir, param_name)
                cmd = [
                    "sqlmap", "-u", url, 
                    "-p", param_name,
                    "--batch",
                    "--output-dir", output_dir
                ]
                
                # Add tamper if specified
                if self.args.tamper:
                    cmd.extend(["--tamper", self.args.tamper])
                    
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                # Log the result
                output = stdout.decode() + stderr.decode()
                result_file = os.path.join(output_dir, "sqlmap_output.txt")
                with open(result_file, "w") as f:
                    f.write(output)
                    
                self.log("SUCCESS", f"sqlmap output saved to {result_file}")
                
            except Exception as e:
                self.log("ERROR", f"Error running sqlmap on {url}: {e}")
                
    def run_scan(self):
        """Run the complete scan process"""
        self.log("INFO", f"Starting SQL injection scan for {self.args.target}")
        self.log("INFO", f"Scan ID: {self.scan_id}")
        
        # 1. Enumerate subdomains
        subdomains = self.enumerate_subdomains()
        if not subdomains:
            self.log("ERROR", "Subdomain enumeration failed")
            return False
            
        # 2. Gather URLs
        urls = self.gather_urls(subdomains)
        if not urls:
            self.log("ERROR", "URL gathering failed")
            return False
            
        # 3. Filter parameterized URLs
        param_urls = self.filter_parameterized_urls(urls)
        if not param_urls:
            self.log("ERROR", "No parameterized URLs found")
            return False
            
        # 4. Check live URLs
        live_urls = self.check_live_urls(param_urls)
        if not live_urls:
            self.log("ERROR", "No live URLs found")
            return False
            
        # 5. Detect WAF if auto_waf is enabled
        if self.args.auto_waf and not self.args.tamper:
            self.log("INFO", "Auto WAF detection enabled")
            
            # Get first live URL for WAF testing
            with open(live_urls, "r") as f:
                sample_url = f.readline().strip()
                
            if sample_url:
                waf_type, tamper = waf_identify.get_waf_bypass_strategy(sample_url).split(":", 1)
                
                if waf_type != "none":
                    self.log("SUCCESS", f"WAF detected: {waf_type}")
                    self.log("INFO", f"Using tamper techniques: {tamper}")
                    self.args.tamper = tamper
                else:
                    self.log("INFO", "No WAF detected")
                    
        # 6. Scan URLs for SQL injection
        vulnerabilities = self.scan_urls(live_urls)
        
        # 7. Save report
        self.save_report(vulnerabilities)
        
        # 8. Run sqlmap if enabled
        if self.args.auto_sqlmap:
            self.run_sqlmap(vulnerabilities)
            
        self.log("INFO", f"Scan completed. Results are in {self.output_dir}")
        return True

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    
    parser.add_argument("target", help="Target domain to scan")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--auto-sqlmap", action="store_true", help="Automatically run sqlmap on found vulnerabilities")
    parser.add_argument("--proxy", help="Use proxy (format: http://proxy:port)")
    parser.add_argument("--proxy-list", help="Rotate through proxies in the specified file")
    parser.add_argument("--cookie", help="Cookie string for authenticated scanning")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--tamper", help="Comma-separated tamper techniques")
    parser.add_argument("--auto-waf", action="store_true", help="Auto-detect WAF and use appropriate bypass techniques")
    parser.add_argument("--db-detect", action="store_true", help="Automatically detect database type for better payloads")
    
    return parser.parse_args()

def main():
    """Main entry point"""
    print(BANNER)
    
    args = parse_arguments()
    
    # Create scanner and run scan
    scanner = SQLiScanner(args)
    
    print("=" * 80)
    print(f" Target Domain: {args.target}")
    print(f" Scan ID: {scanner.scan_id}")
    print(" This script will perform SQL Injection tests on the target.")
    print(f" Ensure you have legal permission to test {args.target}!")
    print(" Unauthorized attacks are illegal. Proceed at your own risk.")
    print("=" * 80)
    
    confirm = input("Do you want to continue? (y/N): ")
    if confirm.lower() not in ("y", "yes"):
        print("Scan aborted by user.")
        return
        
    scanner.run_scan()
    
if __name__ == "__main__":
    main()
