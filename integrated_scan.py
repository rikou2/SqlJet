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
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from katana_crawler import crawl_with_katana, filter_potential_sqli_urls

# Import enhancer features
from enhancer import extract_js_endpoints, find_login_forms, detect_content_types, generate_post_requests, enhance_scan

# Try to import AI integration
try:
    from ai_integration import SqlJetAiIntegration, load_api_key
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# --- Color formatting ---
def header(msg):
    """Print section header"""
    print(f"\n{'=' * 60}")
    print(f"   {msg}")
    print(f"{'=' * 60}")

def display_signature():
    """Display SqlJet Ai V1 signature"""
    from colorama import Fore, Style
    print(f"\n{Fore.CYAN}{Style.BRIGHT}SqlJet{Fore.RED} Ai{Fore.CYAN} V1{Style.RESET_ALL} - {Fore.GREEN}by R13{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Copyright (c) 2024-2025 SqlJet Ai developers by R13{Style.RESET_ALL}")

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
    including Katana crawling for automatic SQL injection point discovery and AI-powered analysis
    
    SqlJet Ai V1 - Advanced SQL Injection Discovery & Testing Tool
    Copyright (c) 2024-2025 SqlJet Ai developers by r13
    
    Args:
        args: The command line arguments
        output_dir: The output directory for results
        
    Returns:
        dict: Results of the scan
    """
    
    # Initialize AI integration if requested
    ai_integration = None
    if getattr(args, 'ai', False) and AI_AVAILABLE:
        try:
            # Get API key from argument or environment
            api_key = getattr(args, 'ai_key', None) or load_api_key()
            if not api_key:
                warning("AI scanning enabled but no API key provided. Set with --ai-key or OPENAI_API_KEY environment variable.")
            else:
                # Initialize AI integration
                ai_model = getattr(args, 'ai_model', 'gpt-4')
                # Check if SSL verification should be disabled
                verify_ssl = not getattr(args, 'disable_ssl_verify', False)
                ai_integration = SqlJetAiIntegration(api_key=api_key, model=ai_model, output_dir=output_dir, verify_ssl=verify_ssl)
                success(f"AI-enhanced scanning enabled using {ai_model}")
                if not verify_ssl:
                    info("SSL certificate verification disabled for this scan")
        except Exception as e:
            error(f"Failed to initialize AI integration: {e}")
            warning("Continuing scan without AI capabilities")
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
    
    # --- PHASE 3: AI-POWERED ANALYSIS (if enabled) ---
    if ai_integration is not None:
        header("PHASE 3: AI-POWERED VULNERABILITY ANALYSIS")
        
        # Analyze the target domain for SQL injection vulnerabilities
        target_url = f"http://{domain}" if not domain.startswith('http') else domain
        info(f"Performing AI analysis of target: {target_url}")
        
        # Analyze the target domain
        target_analysis = ai_integration.analyze_target(target_url)
        
        if 'error' not in target_analysis:
            # Display vulnerability likelihood for parameters
            if 'vulnerable_params' in target_analysis and target_analysis['vulnerable_params']:
                success(f"AI analysis identified {len(target_analysis['vulnerable_params'])} potentially vulnerable parameters")
                for param, score in target_analysis['vulnerable_params'].items():
                    if score >= 7:
                        print(f"  {Fore.RED if 'Fore' in globals() else ''}[HIGH] Parameter '{param}' - Score: {score}/10{Style.RESET_ALL if 'Style' in globals() else ''}")
                    elif score >= 4:
                        print(f"  {Fore.YELLOW if 'Fore' in globals() else ''}[MEDIUM] Parameter '{param}' - Score: {score}/10{Style.RESET_ALL if 'Style' in globals() else ''}")
                    else:
                        print(f"  {Fore.GREEN if 'Fore' in globals() else ''}[LOW] Parameter '{param}' - Score: {score}/10{Style.RESET_ALL if 'Style' in globals() else ''}")
            
            # Display recommended payloads
            if 'recommended_payloads' in target_analysis and target_analysis['recommended_payloads']:
                info("AI-recommended SQL injection payloads:")
                for i, payload in enumerate(target_analysis['recommended_payloads'], 1):
                    print(f"  {i}. {payload}")
            
            # Display WAF evasion techniques
            if 'waf_evasion_techniques' in target_analysis and target_analysis['waf_evasion_techniques']:
                info("AI-recommended WAF evasion techniques:")
                for i, technique in enumerate(target_analysis['waf_evasion_techniques'], 1):
                    print(f"  {i}. {technique}")
            
            with open(log_file, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] AI analysis completed for {target_url}\n")
        else:
            warning(f"AI analysis error: {target_analysis.get('error', 'Unknown error')}")
    
    # --- PHASE 4: ENHANCED SCANNING ---
    header("PHASE 4: ENHANCED ATTACK SURFACE DISCOVERY")
    
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
    
    # --- PHASE 5: SQLMAP SCANNING ---
    header("PHASE 5: SQL INJECTION TESTING")
    
    # Import the scan_with_sqlmap function from sqlsc
    from sqlsc import scan_with_sqlmap, run_dbs_enum
    
    sqlmap_start_time = time.time()
    
    # Prioritize URLs using AI if available
    if ai_integration is not None and live_params_urls_file and os.path.exists(live_params_urls_file):
        info("Using AI to prioritize discovered endpoints for SQL injection testing")
        
        # Read the discovered URLs
        with open(live_params_urls_file, 'r') as f:
            discovered_urls = [line.strip() for line in f.readlines()]
        
        if discovered_urls:
            # Get base target URL
            target_url = f"http://{domain}" if not domain.startswith('http') else domain
            
            # Use AI to prioritize endpoints
            prioritized_urls = ai_integration.prioritize_endpoints(target_url, discovered_urls)
            
            # Create a new file with prioritized URLs
            prioritized_urls_file = os.path.join(output_dir, "prioritized_urls.txt")
            with open(prioritized_urls_file, 'w') as f:
                for url in prioritized_urls:
                    f.write(f"{url}\n")
            
            success(f"AI prioritized {len(prioritized_urls)} endpoints for testing")
            info(f"Top 5 prioritized endpoints:")
            for i, url in enumerate(prioritized_urls[:5], 1):
                print(f"  {i}. {url}")
            
            # Use the prioritized URLs file for testing
            live_params_urls_file = prioritized_urls_file
            
            with open(log_file, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] AI prioritized {len(prioritized_urls)} endpoints for testing\n")
    
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
        
        # Run database enumeration for each vulnerable URL
        for url in scan_results.get('vulnerable_urls', []):
            info(f"Enumerating database for: {url}")
            run_dbs_enum(
                url,
                output_dir,
                get_dbs=args.dbs,
                db_name=args.db_name,
                get_tables=args.tables,
                get_columns=args.columns,
                tbl_name=args.tbl_name,
                dump_data=args.dump,
                tamper_scripts=args.tamper
            )
    
    # --- PHASE 7: AI ANALYSIS OF RESULTS (if enabled) ---
    if ai_integration is not None and scan_results:
        header("PHASE 7: AI ANALYSIS OF SCAN RESULTS")
        
        # Get the summary of vulnerable URLs
        vulnerable_urls = scan_results.get('vulnerable_urls', [])
        
        if vulnerable_urls:
            info(f"Performing AI analysis of {len(vulnerable_urls)} vulnerable endpoints")
            
            # Analyze each vulnerable endpoint in detail
            for url in vulnerable_urls:
                try:
                    # Extract parameters from URL
                    parsed_url = urlparse(url)
                    parameters = parse_qs(parsed_url.query)
                    flat_params = {k: v[0] if len(v) == 1 else v for k, v in parameters.items()}
                    
                    # Get custom payloads for this specific endpoint
                    param_names = list(flat_params.keys())
                    if param_names:
                        # Choose the first parameter for demonstration
                        target_param = param_names[0]
                        custom_payloads = ai_integration.generate_custom_payloads(
                            url, 
                            target_param, 
                            db_type=scan_results.get('db_type'),
                            waf_detected=scan_results.get('waf_detected', False)
                        )
                        
                        if custom_payloads:
                            success(f"AI generated {len(custom_payloads)} custom payloads for {url}")
                            info("Top 3 custom payloads:")
                            for i, payload in enumerate(custom_payloads[:3], 1):
                                print(f"  {i}. {payload}")
                except Exception as e:
                    warning(f"Error during AI analysis of {url}: {e}")
            
            with open(log_file, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] AI analysis of vulnerable endpoints completed\n")
        else:
            info("No vulnerable endpoints found for AI analysis")
    
    # --- GENERATE SUMMARY ---
    header("SCAN SUMMARY")
    
    # Ensure all file paths are defined before generating summary
    # These might not be defined in all code paths
    if 'js_endpoints_file' not in locals():
        js_endpoints_file = os.path.join(output_dir, "js_endpoints.txt")
    if 'login_forms_file' not in locals():
        login_forms_file = os.path.join(output_dir, "login_forms.txt")
    if 'post_templates_file' not in locals():
        post_templates_file = os.path.join(output_dir, "post_templates.json")
    
    scan_end_time = time.time()
    total_duration = scan_end_time - scan_start_time
    
    # Create summary file
    summary_file = os.path.join(output_dir, "scan_summary.txt")
    with open(summary_file, 'w') as f:
        f.write(f"SqlJet Ai V1 Comprehensive Scan Summary for {domain}\n")
        f.write(f"{'='*60}\n")
        f.write(f"Scan started at: {datetime.fromtimestamp(scan_start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan completed at: {datetime.fromtimestamp(scan_end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total scan duration: {total_duration/60:.2f} minutes\n\n")
        
        # Include AI enhancement information if used
        if ai_integration is not None:
            f.write(f"AI-ENHANCED SCANNING INFORMATION\n")
            f.write(f"{'='*60}\n")
            f.write(f"AI Model used: {getattr(args, 'ai_model', 'gpt-4')}\n")
            if ai_integration:
                f.write(f"AI Capabilities: Parameter analysis, Endpoint prioritization, Response interpretation\n")
                if getattr(args, 'ai_analyze_only', False):
                    f.write(f"AI Mode: Analysis only (no automatic exploitation)\n")
                else:
                    f.write(f"AI Mode: Full integration (analysis and exploitation)\n")
            f.write("\n")
        
        f.write("RECONNAISSANCE RESULTS:\n")
        # Only try to read files if they exist and are defined
        if 'subdomains_file' in locals():
            f.write(f"- Subdomain enumeration: {sum(1 for _ in open(subdomains_file)) if os.path.exists(subdomains_file) else 0} subdomains found\n")
        else:
            f.write(f"- Subdomain enumeration: Skipped\n")
            
        if 'all_urls_file' in locals():
            f.write(f"- URL discovery: {sum(1 for _ in open(all_urls_file)) if os.path.exists(all_urls_file) else 0} total URLs\n")
        else:
            f.write(f"- URL discovery: Skipped\n")
            
        if 'filtered_params_urls_file' in locals():
            f.write(f"- Parameter URLs: {sum(1 for _ in open(filtered_params_urls_file)) if os.path.exists(filtered_params_urls_file) else 0} URLs with parameters\n")
        else:
            f.write(f"- Parameter URLs: Skipped\n")
            
        if 'live_params_urls_file' in locals():
            f.write(f"- Live URLs: {sum(1 for _ in open(live_params_urls_file)) if os.path.exists(live_params_urls_file) else 0} live URLs tested\n\n")
        else:
            f.write(f"- Live URLs: Skipped\n\n")
        
        f.write("ENHANCED SCANNING RESULTS:\n")
        # JS endpoints
        if 'js_endpoints_file' in locals():
            f.write(f"- JavaScript endpoints: {sum(1 for _ in open(js_endpoints_file)) if os.path.exists(js_endpoints_file) else 0} endpoints found\n")
        else:
            f.write(f"- JavaScript endpoints: Skipped\n")
        
        # Login forms
        if 'login_forms_file' in locals():
            f.write(f"- Login forms: {sum(1 for _ in open(login_forms_file)) if os.path.exists(login_forms_file) else 0} forms found\n")
        else:
            f.write(f"- Login forms: Skipped\n")
        
        # POST templates
        if 'post_templates_file' in locals() and os.path.exists(post_templates_file):
            with open(post_templates_file, 'r') as ptf:
                try:
                    post_templates = json.load(ptf)
                    f.write(f"- POST templates: {len(post_templates)} templates generated\n\n")
                except:
                    f.write(f"- POST templates: Error parsing file\n\n")
        else:
            f.write(f"- POST templates: Skipped\n\n")
        
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
