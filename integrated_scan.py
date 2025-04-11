#!/usr/bin/env python3
"""
SqlQ Integrated Scan Module
Provides a single automated workflow for comprehensive SQL injection scanning
"""

import os
import sys
import time
import json
import shutil
from datetime import datetime
from katana_crawler import crawl_with_katana, filter_potential_sqli_urls

# Import enhancer features
from enhancer import extract_js_endpoints, find_login_forms, detect_content_types, generate_post_requests, enhance_scan

# --- Color formatting ---
def header(msg):
    """Print section header"""
    print(f"\n{'=' * 60}")
    print(f"   {msg}")
    print(f"{'=' * 60}")

def display_signature():
    """Display SqlJet Ai V1 signature"""
    from colorama import Fore, Style
    print(f"\n{Fore.CYAN}{Style.BRIGHT}SqlJet{Fore.RED} Ai{Fore.CYAN} V1{Style.RESET_ALL} - {Fore.GREEN}by electrounice{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Copyright (c) 2024-2025 SqlJet Ai developers by r13{Style.RESET_ALL}")

def info(msg):
    """Print info message"""
    print(f"[*] {msg}")

def success(msg):
    """Print success message"""
    print(f"[+] {msg}")

def warning(msg):
    """Print warning message"""
    print(f"[!] {msg}")

def error(msg):
    """Print error message"""
    print(f"[ERROR] {msg}")

# --- Main Integration Function ---
def run_integrated_scan(args, output_dir):
    """Run the integrated scanning workflow
    
    This function orchestrates the entire scanning process from reconnaissance to SQLMap scanning
    including Katana crawling for automatic SQL injection point discovery
    
    SqlJet Ai V1 - Advanced SQL Injection Discovery & Testing Tool
    Copyright (c) 2024-2025 SqlJet Ai developers by r13
    
    Args:
        args: The command line arguments
        output_dir: The output directory for results
        
    Returns:
        dict: Results of the scan
    """
    domain = args.domain.replace('http://', '').replace('https://', '').split('/')[0]
    scan_start_time = time.time()
    
    # Create results directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Log file for tracking progress
    log_file = os.path.join(output_dir, "integrated_scan.log")
    with open(log_file, 'w') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting integrated scan for {domain}\n")
    
    # Track discovered URLs
    all_discovered_urls = set()
    
    header("STARTING COMPREHENSIVE SQL INJECTION SCAN")
    display_signature()
    info(f"Target: {domain}")
    info(f"Output directory: {output_dir}")
    info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # --- PHASE 1: SUBDOMAIN ENUMERATION ---
    if not args.skip_recon:
        header("PHASE 1: SUBDOMAIN ENUMERATION")
        subdomains_file = os.path.join(output_dir, "subdomains.txt")
        
        # Import the collect_subdomains function from sqlsc
        from sqlsc import collect_subdomains
        
        print(f"[+] Starting subdomain enumeration for {domain}")
        subdomains_count = collect_subdomains(domain, subdomains_file)
        
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Found {subdomains_count} subdomains\n")
    
    # --- PHASE 2: URL COLLECTION ---
    header("PHASE 2: URL DISCOVERY")
    all_urls_file = os.path.join(output_dir, "all_urls.txt")
    
    # Import the necessary function from sqlsc
    from sqlsc import collect_urls, filter_urls, check_live_urls
    
    if not args.skip_recon and os.path.exists(subdomains_file):
        print(f"[+] Collecting URLs from subdomains")
        collect_urls(subdomains_file, all_urls_file)
    else:
        # If skipping subdomain recon, just collect for main domain
        collect_urls(domain, all_urls_file)
    
    # Filter for URLs with parameters and check which are live
    filtered_params_urls_file = os.path.join(output_dir, "filtered_params_urls.txt")
    filter_urls(all_urls_file, filtered_params_urls_file)
    
    live_params_urls_file = os.path.join(output_dir, "live_params_urls.txt")
    live_count = check_live_urls(filtered_params_urls_file, live_params_urls_file)
    
    with open(log_file, 'a') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Found {live_count} live URLs with parameters\n")
    
    # --- PHASE 3: ENHANCED SCANNING ---
    header("PHASE 3: ENHANCED ATTACK SURFACE DISCOVERY")
    
    js_endpoints = 0
    login_forms = 0
    post_requests = 0
    
    if args.full or args.js_scan:
        # Extract API endpoints from JavaScript
        js_endpoints_file = os.path.join(output_dir, "js_endpoints.txt")
        js_endpoints = extract_js_endpoints(f"http://{domain}", js_endpoints_file)
        
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Found {js_endpoints} JavaScript endpoints\n")
        
        # Add these endpoints to our list of URLs to test
        if os.path.exists(js_endpoints_file) and js_endpoints > 0:
            with open(js_endpoints_file, 'r') as f:
                js_endpoints = [line.strip() for line in f.readlines()]
                all_discovered_urls.update(js_endpoints)
    
    if args.full or args.login_scan:
        # Find login forms
        login_forms_file = os.path.join(output_dir, "login_forms.txt")
        login_forms = find_login_forms(f"http://{domain}", login_forms_file)
        
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Found {login_forms} login forms\n")
        
        # Add these login forms to our list of URLs to test
        if os.path.exists(login_forms_file) and login_forms > 0:
            with open(login_forms_file, 'r') as f:
                login_forms = [line.strip() for line in f.readlines()]
                all_discovered_urls.update(login_forms)
    
    if args.full or args.post_scan:
        # Generate POST request templates
        html_form_urls_file = os.path.join(output_dir, "html_form_urls.txt")
        post_templates_file = os.path.join(output_dir, "post_templates.json")
        
        # First detect content types to identify HTML forms
        content_types = detect_content_types(all_urls_file, output_dir)
        
        # Then generate POST templates for those forms
        if os.path.exists(html_form_urls_file):
            post_requests = generate_post_requests(html_form_urls_file, post_templates_file)
            
            with open(log_file, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Generated {post_requests} POST request templates\n")
    
    # Run Katana crawler to find potential SQL injection points if enabled
    katana_urls = 0
    if args.katana:
        katana_start = time.time()
        print(f"\n{'-'*60}\n[*] PHASE 4: KATANA CRAWLING - DISCOVERING POTENTIAL SQL INJECTION POINTS\n{'-'*60}")
        
        # Define output files for Katana results
        katana_output = os.path.join(output_dir, "katana_urls.txt")
        katana_filtered = os.path.join(output_dir, "katana_filtered.txt")
        
        # Run Katana crawler
        domain = args.domain
        if not domain.startswith('http'):
            domain = f"http://{domain}"
            
        print(f"[*] Crawling {domain} with Katana to find potential SQL injection points...")
        success, count = crawl_with_katana(
            target=domain,
            output_file=katana_output,
            depth=args.katana_depth,
            timeout=args.katana_timeout,
            max_urls=args.max_urls or 1000
        )
        
        if success and count > 0:
            # Filter the results to find high-potential SQL injection points
            katana_urls = filter_potential_sqli_urls(katana_output, katana_filtered)
            
            # If we found potential injection points, use the filtered file for scanning
            if katana_urls > 0:
                shutil.copy(katana_filtered, live_params_urls_file)
                print(f"[+] Added {katana_urls} potential SQL injection points discovered by Katana")
            
        katana_end = time.time()
        print(f"[*] Katana crawling completed in {int(katana_end - katana_start)} seconds")
    
    # Combine all discovered URLs
    if all_discovered_urls:
        combined_urls_file = os.path.join(output_dir, "combined_urls.txt")
        
        # Read existing URLs from live_params_urls_file
        existing_urls = set()
        if os.path.exists(live_params_urls_file):
            with open(live_params_urls_file, 'r') as f:
                existing_urls = set([line.strip() for line in f.readlines()])
                all_discovered_urls.update(existing_urls)
        
        # Add Katana URLs if they exist
        if katana_urls > 0 and os.path.exists(katana_filtered):
            with open(katana_filtered, 'r') as f:
                katana_discovered = set([line.strip() for line in f.readlines()])
                all_discovered_urls.update(katana_discovered)
        
        # Write combined URLs to file
        with open(combined_urls_file, 'w') as f:
            for url in all_discovered_urls:
                f.write(f"{url}\n")
        
        # Use this as our target for SQLMap testing
        live_params_urls_file = combined_urls_file
    
    # --- PHASE 4: SQLMAP SCANNING ---
    header("PHASE 4: SQL INJECTION TESTING")
    
    # Import the scan_with_sqlmap function from sqlsc
    from sqlsc import scan_with_sqlmap, run_dbs_enum
    
    sqlmap_start_time = time.time()
    
    # Run SQLMap scan
    info(f"Starting SQLMap scan on {live_params_urls_file}")
    scan_results = scan_with_sqlmap(
        live_params_urls_file,
        output_dir,
        tamper_scripts=args.tamper,
        level=args.level,
        risk=args.risk,
        prefix=args.prefix,
        suffix=args.suffix,
        auth_type=args.auth_type,
        auth_cred=args.auth_cred,
        cookie=args.cookie,
        proxy=args.proxy,
        proxy_file=args.proxy_file,
        headers=args.headers,
        get_dbs=args.dbs,
        get_tables=args.tables,
        get_columns=args.columns,
        dump_data=args.dump,
        threads=args.threads,
        verbose=args.verbose,
        auto_waf=args.auto_waf,
        report_format=args.report,
        timeout=args.timeout,
        auto_enum_dbs=True
    )
    
    sqlmap_end_time = time.time()
    sqlmap_duration = sqlmap_end_time - sqlmap_start_time
    
    with open(log_file, 'a') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SQLMap scan completed in {sqlmap_duration/60:.2f} minutes\n")
    
    # --- PHASE 5: DATABASE ENUMERATION ---
    if scan_results.get('vulnerable_found', False) and args.dbs:
        header("PHASE 5: DATABASE ENUMERATION")
        
        if 'vulnerable_urls' in scan_results and scan_results['vulnerable_urls']:
            # Write vulnerable URLs to a file
            vulnerable_urls_file = os.path.join(output_dir, "vulnerable_urls.txt")
            with open(vulnerable_urls_file, 'w') as f:
                for url in scan_results['vulnerable_urls']:
                    f.write(f"{url}\n")
            
            # Run database enumeration
            info(f"Enumerating databases for {len(scan_results['vulnerable_urls'])} vulnerable URLs")
            db_enum_results = run_dbs_enum(
                vulnerable_urls_file,
                output_dir,
                tamper_scripts=args.tamper,
                level=args.level,
                risk=args.risk,
                prefix=args.prefix,
                suffix=args.suffix,
                auth_type=args.auth_type,
                auth_cred=args.auth_cred,
                cookie=args.cookie,
                proxy=args.proxy,
                proxy_file=args.proxy_file,
                threads=args.threads,
                verbose=args.verbose,
                return_dbs=True
            )
            
            if db_enum_results:
                print(f"[+] Found {len(db_enum_results)} databases")
                for db in db_enum_results:
                    info(f"Database found: {db}")
    
    # --- GENERATE SUMMARY ---
    header("SCAN SUMMARY")
    
    scan_end_time = time.time()
    total_duration = scan_end_time - scan_start_time
    
    # Create summary file
    summary_file = os.path.join(output_dir, "scan_summary.txt")
    with open(summary_file, 'w') as f:
        f.write(f"SqlQ Comprehensive Scan Summary for {domain}\n")
        f.write(f"{'='*50}\n")
        f.write(f"Scan started at: {datetime.fromtimestamp(scan_start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan completed at: {datetime.fromtimestamp(scan_end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total scan duration: {total_duration/60:.2f} minutes\n\n")
        
        f.write("RECONNAISSANCE RESULTS:\n")
        f.write(f"- Subdomain enumeration: {sum(1 for _ in open(subdomains_file)) if os.path.exists(subdomains_file) else 0} subdomains found\n")
        f.write(f"- URL discovery: {sum(1 for _ in open(all_urls_file)) if os.path.exists(all_urls_file) else 0} total URLs\n")
        f.write(f"- Parameter URLs: {sum(1 for _ in open(filtered_params_urls_file)) if os.path.exists(filtered_params_urls_file) else 0} URLs with parameters\n")
        f.write(f"- Live URLs: {sum(1 for _ in open(live_params_urls_file)) if os.path.exists(live_params_urls_file) else 0} live URLs tested\n\n")
        
        f.write("ENHANCED SCANNING RESULTS:\n")
        f.write(f"- JavaScript endpoints: {sum(1 for _ in open(js_endpoints_file)) if os.path.exists(js_endpoints_file) else 0} endpoints found\n")
        f.write(f"- Login forms: {sum(1 for _ in open(login_forms_file)) if os.path.exists(login_forms_file) else 0} forms found\n")
        if os.path.exists(post_templates_file):
            with open(post_templates_file, 'r') as ptf:
                try:
                    post_templates = json.load(ptf)
                    f.write(f"- POST templates: {len(post_templates)} templates generated\n\n")
                except:
                    f.write(f"- POST templates: Error parsing file\n\n")
        else:
            f.write(f"- POST templates: None generated\n\n")
        
        f.write("SQL INJECTION RESULTS:\n")
        f.write(f"- SQLMap scan duration: {sqlmap_duration/60:.2f} minutes\n")
        f.write(f"- Vulnerable URLs found: {len(scan_results.get('vulnerable_urls', []))}\n")
        if scan_results.get('vulnerable_urls', []):
            f.write("\nVulnerable URLs:\n")
            for url in scan_results.get('vulnerable_urls', []):
                f.write(f"  - {url}\n")
        
        f.write(f"\nResults saved to: {output_dir}\n")
    
    info(f"Scan completed in {total_duration/60:.2f} minutes")
    print(f"[+] Results saved to {output_dir}")
    print(f"[+] Summary saved to {summary_file}")
    
    return {
        'domain': domain,
        'duration': total_duration,
        'vulnerable_count': len(scan_results.get('vulnerable_urls', [])),
        'output_dir': output_dir
    }

if __name__ == "__main__":
    # Simple test when run directly
    pass
