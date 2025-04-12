#!/usr/bin/env python3
"""
SqlJet Ai V1 - Command Line Entry Point
This script provides a clean entry point for the SqlJet Ai V1 tool
"""

import sys
import argparse
from datetime import datetime
import os

def main():
    """Main entry point for SqlJet Ai V1 tool"""
    
    parser = argparse.ArgumentParser(description='SqlJet Ai V1 - Advanced SQL Injection Discovery & Testing Tool')
    
    # Basic options
    parser.add_argument("-u", "--url", help="Target domain or URL")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-up", "--update", action="store_true", help="Update all required tools")
    parser.add_argument('--katana', action='store_true', default=True, help='Use Katana crawler to find potential SQL injection points')
    parser.add_argument('--katana-depth', type=int, default=3, help='Katana crawler depth (default: 3)')
    parser.add_argument('--katana-timeout', type=int, default=300, help='Katana crawler timeout in seconds (default: 300)')
    parser.add_argument('--skip-recon', action='store_true', help='Skip reconnaissance phase')
    parser.add_argument('--max-urls', type=int, help='Maximum number of URLs to scan')
    parser.add_argument('--vulnerable-file', help='File containing already discovered vulnerable URLs')
    
    # Enhanced scanning options
    parser.add_argument('--full', action='store_true', help='Run full scan with all enhanced features')
    parser.add_argument('--api-scan', action='store_true', help='Scan for API endpoints')
    parser.add_argument('--login-scan', action='store_true', help='Scan for login forms')
    parser.add_argument('--post-scan', action='store_true', help='Generate and test POST requests')
    parser.add_argument('--js-scan', action='store_true', help='Extract endpoints from JavaScript files')
    
    # SQLMap options
    parser.add_argument('--level', type=int, default=1, help='SQLMap detection level (1-5)')
    
    # AI integration options
    parser.add_argument('--ai', action='store_true', help='Enable AI-enhanced scanning for better SQL injection detection')
    parser.add_argument('--ai-model', default='gpt-4', choices=['gpt-4', 'gpt-3.5-turbo'], help='AI model to use for analysis')
    parser.add_argument('--ai-key', help='OpenAI API key (can also be set via OPENAI_API_KEY environment variable)')
    parser.add_argument('--store-ai-key', action='store_true', help='Securely store the provided API key for future use')
    parser.add_argument('--ai-analyze-only', action='store_true', help='Only analyze target without performing actual injection tests')
    parser.add_argument('--disable-ssl-verify', action='store_true', help='Disable SSL certificate verification (useful for sites with invalid/expired certificates)')
    parser.add_argument('--nuclei', action='store_true', help='Use Nuclei with AI-powered detection for enhanced SQL injection scanning')
    parser.add_argument('--pdcp-api-key', help='ProjectDiscovery API key for Nuclei AI scanning (can also be set via PDCP_API_KEY env var)')
    parser.add_argument('--nuclei-katana', action='store_true', help='Run Nuclei AI scans on Katana crawler output for deeper vulnerability detection')
    parser.add_argument('--risk', type=int, default=1, help='SQLMap risk level (1-3)')
    parser.add_argument('--tamper', help='SQLMap tamper script(s)')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--prefix', help='Injection payload prefix')
    parser.add_argument('--suffix', help='Injection payload suffix')
    parser.add_argument('--auto-waf', action='store_true', help='Auto-detect WAF and use appropriate tamper scripts')
    
    # Authentication options
    parser.add_argument('--auth-type', help='HTTP authentication type (Basic, Digest, NTLM)')
    parser.add_argument('--auth-cred', help='HTTP authentication credentials (user:pass)')
    parser.add_argument('--cookie', help='HTTP Cookie header')
    
    # Proxy options
    parser.add_argument('--proxy', help='Proxy URL (http(s)://host:port)')
    parser.add_argument('--proxy-file', help='File containing a list of proxies')
    parser.add_argument('--headers', help='Extra headers')
    
    # Data extraction options
    parser.add_argument('--dbs', action='store_true', help='Enumerate databases')
    parser.add_argument('--tables', action='store_true', help='Enumerate tables')
    parser.add_argument('--columns', action='store_true', help='Enumerate columns')
    parser.add_argument('--dump', action='store_true', help='Dump table contents')
    
    # Output options
    parser.add_argument('--report', help='Output report format (csv, html, etc.)')
    parser.add_argument('--timeout', type=int, help='Timeout for requests (seconds)')
    
    # If no arguments, show help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Import the main module only after parsing args to prevent unwanted early execution
    from sqlsc import run_sql_scan, update_tools, RESULTS_BASE_DIR
    
    # Handle tool updates if requested
    if args.update:
        update_tools()
        sys.exit(0)
    
    # Validate arguments
    if not args.url and not args.vulnerable_file:
        print("[ERROR] You must specify either a target domain/URL (-u/--url) or a file with vulnerable URLs (--vulnerable-file)")
        sys.exit(1)
    
    # Set up output directory
    if args.url:
        domain_clean = args.url.replace('https://', '').replace('http://', '').split('/')[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = args.output or os.path.join(RESULTS_BASE_DIR, f"{domain_clean}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Starting Scan for: {domain_clean}")
        print(f"[*] Results directory: {output_dir}")
    else:
        # Direct scan mode from vulnerable file - use a generic name
        domain_clean = "direct-scan"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = args.output or os.path.join(RESULTS_BASE_DIR, f"{domain_clean}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Starting Scan for: {domain_clean}")
        print(f"[*] Results directory: {output_dir}")
    
    # Run the scan with the provided arguments
    run_sql_scan(args, output_dir)

if __name__ == "__main__":
    main() 