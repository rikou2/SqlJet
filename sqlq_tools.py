#!/usr/bin/env python3
# SQLi Advanced Toolkit
# Integrates external tools: subfinder, gau, uro, httpx, sqlmap, curl

import os
import sys
import subprocess
import argparse
import json
import logging
import threading
import queue
import time
import re
from datetime import datetime
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sqlq_tools.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('sqlq_tools')

class SQLQToolIntegrator:
    """
    SQL Injection toolkit that integrates popular security tools
    """
    def __init__(self, config=None):
        """Initialize the tool integrator"""
        self.config = config or {}
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.results_dir = os.path.join(self.base_dir, 'results')
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Create temp directory
        self.temp_dir = os.path.join(self.base_dir, 'temp')
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Session ID
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Results storage
        self.target_domain = None
        self.subdomains = []
        self.urls = []
        self.filtered_urls = []
        self.alive_urls = []
        self.vulnerable_urls = []
        
        # Thread control
        self.threads = self.config.get('threads', 10)
        self.lock = threading.Lock()
        
        # Check required tools
        self.check_tools()
        
        logger.info("SQL Injection Tool Integrator initialized")
        
    def check_tools(self):
        """Check if required tools are installed and in PATH"""
        required_tools = ['subfinder', 'gau', 'uro', 'httpx', 'sqlmap', 'curl']
        missing_tools = []
        
        for tool in required_tools:
            try:
                subprocess.run(['which', tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"Found required tool: {tool}")
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
                logger.error(f"Required tool not found: {tool}")
                
        if missing_tools:
            print(f"ERROR: The following required tools are missing: {', '.join(missing_tools)}")
            print("Please install them before running this script.")
            print("Installation instructions:")
            print("  subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            print("  gau: go install github.com/lc/gau/v2/cmd/gau@latest")
            print("  uro: pip install uro")
            print("  httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            print("  sqlmap: apt-get install sqlmap")
            print("  curl: apt-get install curl")
            sys.exit(1)
            
    def scan_domain(self, domain, options=None):
        """
        Perform comprehensive SQL injection scan using external tools
        
        Args:
            domain: The target domain to scan
            options: Scan options
            
        Returns:
            Dictionary with scan results
        """
        self.target_domain = domain
        
        # Default options
        default_options = {
            "threads": 10,
            "timeout": 30,
            "subfinder_timeout": 2,
            "httpx_timeout": 5,
            "sqlmap_risk": 1,
            "sqlmap_level": 1,
            "output_file": os.path.join(self.results_dir, f"scan_{self.session_id}_{domain}_results.json"),
            "verbose": False
        }
        
        # Update with user options
        if options:
            default_options.update(options)
            
        self.options = default_options
        
        # Start scan
        start_time = time.time()
        print(f"\n[+] Starting comprehensive scan of domain: {domain}")
        print(f"[+] Session ID: {self.session_id}")
        print(f"[+] Using external tools: subfinder, gau, uro, httpx, sqlmap, curl\n")
        
        try:
            # Step 1: Discover subdomains using subfinder
            self._discover_subdomains()
            
            # Step 2: Find URLs using gau
            self._find_urls()
            
            # Step 3: Filter and normalize URLs using uro
            self._filter_urls()
            
            # Step 4: Check for alive URLs using httpx
            self._check_alive_urls()
            
            # Step 5: Scan for SQL injection vulnerabilities using sqlmap
            self._scan_for_sqli()
            
            # Step 6: Generate report
            self._generate_report()
            
            # Completed
            duration = time.time() - start_time
            print(f"\n[+] Scan completed in {duration:.2f} seconds")
            print(f"[+] Results saved to: {self.options['output_file']}")
            
            return {
                "session_id": self.session_id,
                "target_domain": domain,
                "duration": duration,
                "subdomains": len(self.subdomains),
                "urls": len(self.urls),
                "filtered_urls": len(self.filtered_urls),
                "alive_urls": len(self.alive_urls),
                "vulnerable_urls": len(self.vulnerable_urls),
                "output_file": self.options['output_file']
            }
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            print(f"[!] Error during scan: {e}")
            return None
            
    def _discover_subdomains(self):
        """Discover subdomains using subfinder"""
        print(f"[*] Step 1: Discovering subdomains with subfinder...")
        
        output_file = os.path.join(self.temp_dir, f"{self.session_id}_subdomains.txt")
        
        # Run subfinder
        cmd = [
            "subfinder", 
            "-d", self.target_domain, 
            "-o", output_file,
            "-t", str(self.options["threads"]),
            "-timeout", str(self.options["subfinder_timeout"])
        ]
        
        if self.options["verbose"]:
            cmd.append("-v")
            
        try:
            subprocess.run(cmd, check=True)
            
            # Read discovered subdomains
            with open(output_file, 'r') as f:
                self.subdomains = [line.strip() for line in f if line.strip()]
                
            print(f"[+] Discovered {len(self.subdomains)} subdomains")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running subfinder: {e}")
            print(f"[!] Error running subfinder: {e}")
            # Continue with just the main domain
            self.subdomains = [self.target_domain]
            
    def _find_urls(self):
        """Find URLs using gau"""
        print(f"[*] Step 2: Finding URLs with gau...")
        
        output_file = os.path.join(self.temp_dir, f"{self.session_id}_urls.txt")
        
        # Create a file with all domains (main domain + subdomains)
        domains_file = os.path.join(self.temp_dir, f"{self.session_id}_domains.txt")
        with open(domains_file, 'w') as f:
            f.write(self.target_domain + '\n')
            for subdomain in self.subdomains:
                f.write(subdomain + '\n')
                
        # Run gau
        try:
            with open(output_file, 'w') as outf:
                subprocess.run(
                    ["gau", "--threads", str(self.options["threads"]), "--fp", domains_file],
                    stdout=outf,
                    check=True
                )
                
            # Read discovered URLs
            with open(output_file, 'r') as f:
                self.urls = [line.strip() for line in f if line.strip()]
                
            print(f"[+] Found {len(self.urls)} URLs")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running gau: {e}")
            print(f"[!] Error running gau: {e}")
            # Try alternate method using curl
            self._find_urls_alternate()
            
    def _find_urls_alternate(self):
        """Alternate method to find URLs using curl and Wayback Machine API"""
        print(f"[*] Using alternate method to find URLs...")
        
        all_urls = []
        
        # Process each domain (main domain + subdomains)
        for domain in [self.target_domain] + self.subdomains:
            try:
                # Query Wayback Machine API
                cmd = [
                    "curl", "-s",
                    f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                
                # Parse JSON output
                try:
                    urls = json.loads(result.stdout)
                    # Skip the header row
                    if urls and len(urls) > 1:
                        for url_entry in urls[1:]:
                            all_urls.append(url_entry[0])
                except json.JSONDecodeError:
                    pass
                    
            except subprocess.CalledProcessError:
                logger.warning(f"Error fetching URLs for {domain} from Wayback Machine")
                
        # Remove duplicates
        self.urls = list(set(all_urls))
        print(f"[+] Found {len(self.urls)} URLs with alternate method")
        
    def _filter_urls(self):
        """Filter and normalize URLs using uro"""
        print(f"[*] Step 3: Filtering URLs with uro...")
        
        if not self.urls:
            print(f"[!] No URLs to filter")
            return
            
        input_file = os.path.join(self.temp_dir, f"{self.session_id}_urls_to_filter.txt")
        output_file = os.path.join(self.temp_dir, f"{self.session_id}_filtered_urls.txt")
        
        # Write URLs to file
        with open(input_file, 'w') as f:
            for url in self.urls:
                f.write(url + '\n')
                
        # Run uro
        try:
            with open(output_file, 'w') as outf:
                subprocess.run(
                    ["uro", "-i", input_file],
                    stdout=outf,
                    check=True
                )
                
            # Read filtered URLs
            with open(output_file, 'r') as f:
                self.filtered_urls = [line.strip() for line in f if line.strip()]
                
            print(f"[+] Filtered down to {len(self.filtered_urls)} unique URLs")
            
            # Further filter to keep only URLs with parameters
            param_urls = [url for url in self.filtered_urls if '?' in url and '=' in url]
            self.filtered_urls = param_urls
            
            print(f"[+] Found {len(self.filtered_urls)} URLs with parameters")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running uro: {e}")
            print(f"[!] Error running uro: {e}")
            # Manual filtering as fallback
            self._filter_urls_manual()
            
    def _filter_urls_manual(self):
        """Manual URL filtering as fallback"""
        print(f"[*] Using manual URL filtering...")
        
        filtered = set()
        
        for url in self.urls:
            # Keep only URLs with parameters
            if '?' in url and '=' in url:
                # Basic URL normalization
                parsed = urlparse(url)
                # Convert to lowercase
                normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path.lower()}?{parsed.query}"
                filtered.add(normalized)
                
        self.filtered_urls = list(filtered)
        print(f"[+] Filtered down to {len(self.filtered_urls)} URLs with parameters")
        
    def _check_alive_urls(self):
        """Check for alive URLs using httpx"""
        print(f"[*] Step 4: Checking for alive URLs with httpx...")
        
        if not self.filtered_urls:
            print(f"[!] No URLs to check")
            return
            
        input_file = os.path.join(self.temp_dir, f"{self.session_id}_urls_to_check.txt")
        output_file = os.path.join(self.temp_dir, f"{self.session_id}_alive_urls.txt")
        
        # Write URLs to file
        with open(input_file, 'w') as f:
            for url in self.filtered_urls:
                f.write(url + '\n')
                
        # Run httpx
        try:
            subprocess.run(
                [
                    "httpx", 
                    "-l", input_file, 
                    "-o", output_file,
                    "-timeout", str(self.options["httpx_timeout"]),
                    "-threads", str(self.options["threads"]),
                    "-silent"
                ],
                check=True
            )
            
            # Read alive URLs
            with open(output_file, 'r') as f:
                self.alive_urls = [line.strip() for line in f if line.strip()]
                
            print(f"[+] Found {len(self.alive_urls)} alive URLs")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running httpx: {e}")
            print(f"[!] Error running httpx: {e}")
            # Use curl as fallback
            self._check_alive_urls_fallback()
            
    def _check_alive_urls_fallback(self):
        """Fallback method to check alive URLs using curl"""
        print(f"[*] Using curl to check alive URLs...")
        
        alive_urls = []
        
        # Set up thread queue
        url_queue = queue.Queue()
        for url in self.filtered_urls:
            url_queue.put(url)
            
        # Define worker function
        def check_url_worker():
            while not url_queue.empty():
                try:
                    url = url_queue.get(block=False)
                    
                    # Check URL with curl
                    try:
                        result = subprocess.run(
                            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "3", url],
                            capture_output=True,
                            text=True,
                            check=False
                        )
                        
                        if result.stdout.strip() and int(result.stdout.strip()) < 500:
                            with self.lock:
                                alive_urls.append(url)
                                
                    except Exception:
                        pass
                        
                    url_queue.task_done()
                    
                except queue.Empty:
                    break
                    
        # Start worker threads
        threads = []
        for _ in range(min(self.options["threads"], len(self.filtered_urls))):
            t = threading.Thread(target=check_url_worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Wait for completion
        for t in threads:
            t.join()
            
        self.alive_urls = alive_urls
        print(f"[+] Found {len(self.alive_urls)} alive URLs with curl")
        
    def _scan_for_sqli(self):
        """Scan for SQL injection vulnerabilities using sqlmap"""
        print(f"[*] Step 5: Scanning for SQL injection vulnerabilities with sqlmap...")
        
        if not self.alive_urls:
            print(f"[!] No alive URLs to scan")
            return
            
        # Limit number of URLs to scan if too many
        urls_to_scan = self.alive_urls
        if len(urls_to_scan) > 500:
            print(f"[!] Limiting scan to 500 URLs out of {len(urls_to_scan)}")
            urls_to_scan = urls_to_scan[:500]
            
        # Set up thread queue
        url_queue = queue.Queue()
        for url in urls_to_scan:
            url_queue.put(url)
            
        # Shared results
        vulnerable_urls = []
        scan_results = []
        
        # Define worker function
        def sqlmap_worker():
            while not url_queue.empty():
                try:
                    url = url_queue.get(block=False)
                    
                    # Create output directory for this URL
                    url_hash = str(hash(url))[:10]
                    output_dir = os.path.join(self.temp_dir, f"{self.session_id}_sqlmap_{url_hash}")
                    
                    print(f"[*] Scanning URL: {url}")
                    
                    # Run sqlmap
                    cmd = [
                        "sqlmap", 
                        "-u", url,
                        "--batch",
                        "--risk", str(self.options["sqlmap_risk"]),
                        "--level", str(self.options["sqlmap_level"]),
                        "--timeout", str(self.options["timeout"]),
                        "--threads", str(min(5, self.options["threads"])),
                        "--output-dir", output_dir,
                        "--disable-coloring"
                    ]
                    
                    if not self.options["verbose"]:
                        cmd.append("--silent")
                        
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                        
                        # Check if vulnerable
                        if "is vulnerable" in result.stdout or "is vulnerable" in result.stderr:
                            with self.lock:
                                vulnerable_urls.append(url)
                                scan_results.append({
                                    "url": url,
                                    "vulnerable": True,
                                    "details": self._extract_sqlmap_details(result.stdout, result.stderr)
                                })
                            print(f"[!] Found SQL injection vulnerability in {url}")
                        else:
                            with self.lock:
                                scan_results.append({
                                    "url": url,
                                    "vulnerable": False
                                })
                            print(f"[-] No SQL injection vulnerability found in {url}")
                            
                    except Exception as e:
                        logger.error(f"Error running sqlmap on {url}: {e}")
                        with self.lock:
                            scan_results.append({
                                "url": url,
                                "vulnerable": False,
                                "error": str(e)
                            })
                            
                    url_queue.task_done()
                    
                except queue.Empty:
                    break
                    
        # Start worker threads
        threads = []
        for _ in range(min(5, self.options["threads"])):
            t = threading.Thread(target=sqlmap_worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Wait for completion with progress updates
        total_urls = len(urls_to_scan)
        while not url_queue.empty():
            remaining = url_queue.qsize()
            completed = total_urls - remaining
            print(f"[*] Progress: {completed}/{total_urls} URLs scanned, {len(vulnerable_urls)} vulnerabilities found", end="\r")
            time.sleep(5)
            
        # Final wait for threads to complete
        for t in threads:
            t.join()
            
        self.vulnerable_urls = vulnerable_urls
        self.scan_results = scan_results
        
        print(f"\n[+] SQL injection scan complete. Found {len(self.vulnerable_urls)} vulnerable URLs")
        
    def _extract_sqlmap_details(self, stdout, stderr):
        """Extract details from sqlmap output"""
        details = {}
        
        # Extract parameter
        param_match = re.search(r"Parameter: ([^\s]+)", stdout)
        if param_match:
            details["parameter"] = param_match.group(1)
            
        # Extract type
        type_match = re.search(r"Type: ([^\s]+)", stdout)
        if type_match:
            details["type"] = type_match.group(1)
            
        # Extract title
        title_match = re.search(r"Title: ([^\n]+)", stdout)
        if title_match:
            details["title"] = title_match.group(1)
            
        # Extract payload
        payload_match = re.search(r"Payload: ([^\n]+)", stdout)
        if payload_match:
            details["payload"] = payload_match.group(1)
            
        return details
        
    def _generate_report(self):
        """Generate scan report"""
        print(f"[*] Step 6: Generating report...")
        
        # Create report structure
        report = {
            "scan_id": self.session_id,
            "target_domain": self.target_domain,
            "scan_date": datetime.now().isoformat(),
            "statistics": {
                "subdomains_count": len(self.subdomains),
                "total_urls_found": len(self.urls),
                "filtered_urls_count": len(self.filtered_urls),
                "alive_urls_count": len(self.alive_urls),
                "vulnerable_urls_count": len(self.vulnerable_urls)
            },
            "subdomains": self.subdomains,
            "vulnerable_urls": [],
            "scan_results": self.scan_results if hasattr(self, 'scan_results') else []
        }
        
        # Add detailed information for vulnerable URLs
        for url in self.vulnerable_urls:
            # Find details in scan results
            details = {}
            for result in report["scan_results"]:
                if result["url"] == url:
                    details = result.get("details", {})
                    break
                    
            report["vulnerable_urls"].append({
                "url": url,
                "parameter": details.get("parameter", "unknown"),
                "type": details.get("type", "unknown"),
                "title": details.get("title", "SQL Injection"),
                "payload": details.get("payload", "unknown")
            })
            
        # Write report to file
        try:
            with open(self.options["output_file"], 'w') as f:
                json.dump(report, f, indent=2)
                
            # Generate text report as well
            text_file = os.path.splitext(self.options["output_file"])[0] + ".txt"
            self._generate_text_report(report, text_file)
            
            print(f"[+] Report saved to {self.options['output_file']}")
            print(f"[+] Text report saved to {text_file}")
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            print(f"[!] Error generating report: {e}")
            
    def _generate_text_report(self, report, output_file):
        """Generate a text version of the report"""
        try:
            with open(output_file, 'w') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("SQL INJECTION SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Basic information
                f.write(f"Target Domain: {report['target_domain']}\n")
                f.write(f"Scan Date: {report['scan_date']}\n")
                f.write(f"Scan ID: {report['scan_id']}\n\n")
                
                # Statistics
                f.write("SCAN STATISTICS\n")
                f.write("-" * 15 + "\n")
                f.write(f"Subdomains Found: {report['statistics']['subdomains_count']}\n")
                f.write(f"Total URLs Found: {report['statistics']['total_urls_found']}\n")
                f.write(f"Filtered URLs: {report['statistics']['filtered_urls_count']}\n")
                f.write(f"Alive URLs: {report['statistics']['alive_urls_count']}\n")
                f.write(f"Vulnerable URLs: {report['statistics']['vulnerable_urls_count']}\n\n")
                
                # Subdomains
                if report['subdomains']:
                    f.write("DISCOVERED SUBDOMAINS\n")
                    f.write("-" * 21 + "\n")
                    for subdomain in report['subdomains']:
                        f.write(f"- {subdomain}\n")
                    f.write("\n")
                
                # Vulnerable URLs
                if report['vulnerable_urls']:
                    f.write("SQL INJECTION VULNERABILITIES\n")
                    f.write("-" * 28 + "\n\n")
                    
                    for i, vuln in enumerate(report['vulnerable_urls'], 1):
                        f.write(f"{i}. URL: {vuln['url']}\n")
                        f.write(f"   Parameter: {vuln['parameter']}\n")
                        f.write(f"   Type: {vuln['type']}\n")
                        f.write(f"   Title: {vuln['title']}\n")
                        f.write(f"   Payload: {vuln['payload']}\n\n")
                else:
                    f.write("No SQL Injection vulnerabilities were found.\n\n")
                
                # Footer
                f.write("=" * 80 + "\n")
                f.write("End of Report\n")
                f.write("=" * 80 + "\n")
                
        except Exception as e:
            logger.error(f"Error generating text report: {e}")

def main():
    """Main entry point for the SQL Injection Tool Integrator"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="SQL Injection Comprehensive Scanner - Integrates subfinder, gau, uro, httpx, sqlmap, curl"
    )
    
    # Target specification
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    
    # Scan options
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--risk", type=int, choices=[1, 2, 3], default=1, help="SQLMap risk level (default: 1)")
    parser.add_argument("--level", type=int, choices=[1, 2, 3, 4, 5], default=1, help="SQLMap level (default: 1)")
    parser.add_argument("-o", "--output", help="Output file for results (default: auto-generated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure options
    options = {
        "threads": args.threads,
        "timeout": args.timeout,
        "sqlmap_risk": args.risk,
        "sqlmap_level": args.level,
        "verbose": args.verbose
    }
    
    if args.output:
        options["output_file"] = args.output
        
    # Initialize and run the tool integrator
    integrator = SQLQToolIntegrator()
    integrator.scan_domain(args.domain, options)

if __name__ == "__main__":
    main()
