#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
import tempfile
from datetime import datetime
from urllib.parse import urlparse, parse_qs

def check_katana_installed():
    """
    Check if Katana crawler is installed
    """
    try:
        process = subprocess.run(["katana", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            return True
        return False
    except FileNotFoundError:
        return False

def install_katana():
    """
    Provide instructions to install Katana
    """
    print("[!] Katana is not installed. Install it with:")
    print("   GO111MODULE=on go install github.com/projectdiscovery/katana/cmd/katana@latest")
    print("[!] Make sure Go is installed and $GOPATH/bin is in your PATH")
    return False

def crawl_with_katana(target, output_file, depth=3, timeout=300, max_urls=1000, extra_args=None):
    """
    Crawl a target using Katana and extract parameters that might be vulnerable to SQL injection
    
    Args:
        target: Target URL or domain to crawl
        output_file: File to save results
        depth: Crawling depth
        timeout: Maximum time to run in seconds
        max_urls: Maximum number of URLs to crawl
        extra_args: Additional Katana arguments
        
    Returns:
        tuple: (success, count_of_potential_injection_points)
    """
    if not check_katana_installed():
        return install_katana(), 0
    
    print(f"[*] Crawling {target} with Katana to find potential SQL injection points...")
    
    # Create a temporary file for raw Katana output
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_file:
        temp_output = tmp_file.name
    
    # Build Katana command
    cmd = [
        "katana", 
        "-u", target,
        "-jc",  # JSON output
        "-d", str(depth),
        "-timeout", str(timeout),
        "-mr", str(max_urls),
        "-o", temp_output,
        "-fs", "kr",  # Disable known extensions crawler
    ]
    
    # Add extra arguments if provided
    if extra_args:
        cmd.extend(extra_args)
    
    try:
        print(f"[*] Running command: {' '.join(cmd)}")
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        
        if process.returncode != 0:
            print(f"[ERROR] Katana failed: {process.stderr}")
            return False, 0
            
        # Process the Katana output to find potential SQL injection points
        sql_injectable_params = []
        processed_urls = set()
        
        if not os.path.exists(temp_output):
            print("[ERROR] Katana did not generate any output")
            return False, 0
            
        # Process the results
        with open(temp_output, 'r') as f:
            with open(output_file, 'w') as out_f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        url = data.get('url', '')
                        
                        # Skip if we've seen this URL before
                        parsed_url = urlparse(url)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        
                        # Extract GET parameters
                        params = parse_qs(parsed_url.query)
                        if params:
                            for param in params:
                                # Construct a URL with the parameter that might be injectable
                                injectable_url = f"{base_url}?{param}=1"
                                if injectable_url not in processed_urls:
                                    sql_injectable_params.append(injectable_url)
                                    out_f.write(f"{injectable_url}\n")
                                    processed_urls.add(injectable_url)
                        
                        # Extract form parameters from body
                        if data.get('method') == 'POST' and data.get('body'):
                            body_params = parse_qs(data.get('body', ''))
                            if body_params:
                                for param in body_params:
                                    # Generate a POST request template for SQLMap
                                    post_template = f"{base_url} -d \"{param}=1\""
                                    if post_template not in processed_urls:
                                        sql_injectable_params.append(post_template)
                                        out_f.write(f"{post_template}\n")
                                        processed_urls.add(post_template)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        print(f"[ERROR] Error processing Katana result: {e}")
                        continue
        
        # Clean up temporary file
        if os.path.exists(temp_output):
            os.unlink(temp_output)
            
        print(f"[+] Found {len(sql_injectable_params)} potential SQL injection points")
        return True, len(sql_injectable_params)
        
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Katana crawl timed out after {timeout} seconds")
        return False, 0
    except Exception as e:
        print(f"[ERROR] Failed to run Katana: {e}")
        return False, 0

def filter_potential_sqli_urls(katana_output, filtered_output):
    """
    Filter URLs from Katana output that are more likely to be SQL injectable
    
    Args:
        katana_output: File containing Katana crawled URLs
        filtered_output: File to save filtered URLs
        
    Returns:
        int: Number of potential SQL injection URLs
    """
    sql_keywords = ['id', 'uid', 'user', 'account', 'number', 'order', 'no', 'doc',
                    'key', 'email', 'group', 'profile', 'edit', 'report', 'view', 'user',
                    'process', 'cart', 'item', 'page', 'cat', 'product', 'article',
                    'member', 'note', 'field', 'filter', 'query', 'search', 'keyword']
    
    count = 0
    seen_urls = set()
    
    try:
        with open(katana_output, 'r') as infile, open(filtered_output, 'w') as outfile:
            for line in infile:
                line = line.strip()
                if not line:
                    continue
                
                # Skip duplicate URLs
                if line in seen_urls:
                    continue
                seen_urls.add(line)
                
                # Parse the URL to get parameters
                parsed_url = urlparse(line.split(' ')[0])  # Split for POST requests with -d param
                query_params = parse_qs(parsed_url.query)
                
                # Check if URL has parameters that might be SQL injectable
                is_potential_sqli = False
                
                # Check if any parameter name contains SQL injectable keywords
                if query_params:
                    for param in query_params:
                        if any(keyword in param.lower() for keyword in sql_keywords):
                            is_potential_sqli = True
                            break
                
                # If URL contains POST data
                if ' -d ' in line:
                    post_data = line.split(' -d ')[1].strip('"\'')
                    post_params = parse_qs(post_data)
                    if post_params:
                        for param in post_params:
                            if any(keyword in param.lower() for keyword in sql_keywords):
                                is_potential_sqli = True
                                break
                
                # If no parameters but path contains potential ID pattern
                path = parsed_url.path
                path_parts = path.split('/')
                for part in path_parts:
                    # Look for numeric IDs in the path
                    if part.isdigit() or (part and part[0].isdigit()):
                        is_potential_sqli = True
                        break
                
                # If it's a potential SQL injection point, write to output
                if is_potential_sqli:
                    outfile.write(f"{line}\n")
                    count += 1
                
        print(f"[+] Filtered down to {count} high-potential SQL injection points")
        return count
    except Exception as e:
        print(f"[ERROR] Error filtering potential SQLi URLs: {e}")
        return 0

def main():
    """
    Main function when script is run directly
    """
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <output_file>")
        sys.exit(1)
        
    target = sys.argv[1]
    output_file = sys.argv[2]
    
    success, count = crawl_with_katana(target, output_file)
    if success and count > 0:
        filtered_file = output_file.replace('.txt', '_filtered.txt')
        filter_count = filter_potential_sqli_urls(output_file, filtered_file)
        print(f"[+] Completed crawling. Found {count} potential injection points, filtered to {filter_count} high-potential points.")
    else:
        print("[!] Katana crawl failed or found no potential injection points")

if __name__ == "__main__":
    main()
