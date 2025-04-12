#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

# Path to Nuclei (use absolute path to ensure it works)
HOME_DIR = os.path.expanduser("~")
NUCLEI_PATH = os.path.join(HOME_DIR, "go", "bin", "nuclei")

# SQL injection detection prompts exactly as provided
AI_PROMPTS = [
    # Basic prompts
    "Fuzz all parameters with sql injection detection payloads for mysql, mssql, postgresql, etc Use time base detection payloads",
    "Detect SQL injection vulnerabilities using time delay techniques.",
    "Identify second-order SQL injection vulnerabilities where input is stored and executed later.",
    "Identify SQL injection vulnerabilities using boolean-based conditions.",
    "Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data.",
    "Check for error messages revealing SQL queries.",
    "Use time-based techniques to find blind SQL injection.",
]

# Katana-specific prompts
KATANA_PROMPTS = [
    "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting SQL Injection vulnerabilities with pre-conditions.",
    "Detect SQL error messages indicating SQL injection vulnerabilities",
    "Find SQL injection in 'id', 'user', 'product', 'category', 'page' parameters",
    "Scan for blind SQL injection in 's', 'search', 'query', 'sort', 'filter' GET/POST parameters",
    "Scan for time based SQL injection in all parameters",
    "Identify SQL injection in API endpoints using JSON payloads",
    "Check for SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host)"
]

def print_header(text):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*80)
    print(f"{Fore.CYAN}{Style.BRIGHT} {text}")
    print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*80)

def print_info(text):
    print(f"{Fore.BLUE}[*] {text}")

def print_success(text):
    print(f"{Fore.GREEN}[+] {text}")

def print_error(text):
    print(f"{Fore.RED}[-] {text}")

def print_warning(text):
    print(f"{Fore.YELLOW}[!] {text}")

def print_vulnerable(text):
    print(f"{Fore.RED}{Style.BRIGHT}[VULNERABLE] {text}")

def check_nuclei_installed():
    """Check if Nuclei is installed and available."""
    global NUCLEI_PATH
    if not os.path.exists(NUCLEI_PATH):
        print_error(f"Nuclei not found at {NUCLEI_PATH}")
        alt_path = subprocess.run(["which", "nuclei"], capture_output=True, text=True).stdout.strip()
        if alt_path:
            print_info(f"Found Nuclei at alternate path: {alt_path}")
            NUCLEI_PATH = alt_path
            return True
        else:
            print_error("Nuclei not installed. Please install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return False
    return True

def run_nuclei_with_prompt(target, prompt, output_file=None, katana_mode=False, scan_id=0, total_scans=0, api_key=None):
    """Run Nuclei with a specific AI prompt."""
    command = [NUCLEI_PATH, "-target", target, "-ai", prompt]
    
    # If we're in Katana mode, adjust command
    if katana_mode:
        if not target.endswith('.jsonl'):
            print_warning("Target should be a Katana JSONL file for Katana-specific prompts. Continuing anyway.")
        command = [NUCLEI_PATH, "-list", target, "-im", "jsonl", "-ai", prompt]
    
    # Add API key if provided
    if api_key:
        command.extend(["-auth", api_key])
    elif os.environ.get("PDCP_API_KEY"):
        print_info("Using PDCP_API_KEY from environment")
    
    # Add output file if specified
    if output_file:
        command.extend(["-o", output_file, "-j"])
    
    # Add options for better scanning
    command.extend(["-silent", "-no-interactsh", "-timeout", "30"])
    
    # Display progress
    progress = f"[{scan_id}/{total_scans}]" if total_scans > 0 else ""
    print_info(f"{progress} Running Nuclei scan with prompt: {prompt}")
    print_info(f"Command: {' '.join(command)}")
    
    # Run the command
    start_time = time.time()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        vulnerabilities = []
        sql_injection_found = False
        
        # Process output in real-time
        for line in process.stdout:
            if "SQL" in line and "injection" in line.lower():
                sql_injection_found = True
                print_vulnerable(line.strip())
                vulnerabilities.append(line.strip())
            elif "time-based" in line.lower() or "time delay" in line.lower():
                # Highlight time-based detection attempts
                print(f"{Fore.YELLOW}[TIME-BASED] {line.strip()}")
            elif "executing" in line.lower() and "payload" in line.lower():
                # Show when nuclei is executing payloads
                print(f"{Fore.BLUE}[PAYLOAD] {line.strip()}")
            else:
                print(line.strip())
        
        process.wait()
        end_time = time.time()
        duration = round(end_time - start_time, 2)
        
        if process.returncode == 0:
            if sql_injection_found:
                print_success(f"Scan completed in {duration}s. SQL Injection vulnerabilities found!")
            else:
                print_info(f"Scan completed in {duration}s. No SQL Injection vulnerabilities found.")
            return True
        else:
            stderr = process.stderr.read()
            print_error(f"Nuclei scan failed: {stderr}")
            return False
            
    except Exception as e:
        print_error(f"Error running Nuclei scan: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run Nuclei AI prompts for SQL injection detection")
    parser.add_argument("target", help="Target URL, domain, or Katana JSONL file")
    parser.add_argument("--katana", action="store_true", help="Run Katana-specific prompts on a JSONL file")
    parser.add_argument("--output-dir", default="./nuclei_results", help="Directory to store results")
    parser.add_argument("--prompt-id", type=int, help="Run only a specific prompt ID")
    parser.add_argument("--api-key", help="ProjectDiscovery API key for Nuclei AI")
    args = parser.parse_args()
    
    if not check_nuclei_installed():
        sys.exit(1)
    
    # Create output directory
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    print_header("NUCLEI AI SQL INJECTION DETECTION")
    print_info(f"Target: {args.target}")
    print_info(f"Output directory: {args.output_dir}")
    
    # Run standard prompts
    if not args.katana:
        prompts = AI_PROMPTS
        print_header("RUNNING STANDARD SQL INJECTION PROMPTS")
    else:
        prompts = KATANA_PROMPTS
        print_header("RUNNING KATANA-SPECIFIC SQL INJECTION PROMPTS")
    
    # If prompt_id is specified, run only that prompt
    if args.prompt_id is not None:
        if 1 <= args.prompt_id <= len(prompts):
            prompt = prompts[args.prompt_id - 1]
            output_file = os.path.join(args.output_dir, f"prompt_{args.prompt_id}.json")
            run_nuclei_with_prompt(
                args.target, 
                prompt, 
                output_file=output_file,
                katana_mode=args.katana,
                scan_id=args.prompt_id,
                total_scans=1,
                api_key=args.api_key
            )
        else:
            print_error(f"Invalid prompt ID. Must be between 1 and {len(prompts)}")
        return
    
    # Run all prompts
    for idx, prompt in enumerate(prompts, 1):
        output_file = os.path.join(args.output_dir, f"prompt_{idx}.json")
        run_nuclei_with_prompt(
            args.target, 
            prompt, 
            output_file=output_file,
            katana_mode=args.katana,
            scan_id=idx,
            total_scans=len(prompts),
            api_key=args.api_key
        )
        
        # Short delay between scans
        if idx < len(prompts):
            print_info("Waiting 2 seconds before next scan...")
            time.sleep(2)
    
    print_header("ALL NUCLEI AI SCANS COMPLETED")
    print_info(f"Results saved to {args.output_dir}")

if __name__ == "__main__":
    main()
