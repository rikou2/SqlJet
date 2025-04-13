#!/usr/bin/env python3
"""
WAFW00F Integrator for SqlJet Ai
This module provides integration with WAFW00F for WAF detection and tamper script selection
"""

import os
import sys
import logging
import json
from urllib.parse import urlparse
import requests
from colorama import Fore, Style

# Ensure WAFW00F is in the path
wafw00f_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wafw00f')
if wafw00f_dir not in sys.path:
    sys.path.append(wafw00f_dir)

try:
    from wafw00f.main import WAFW00F, buildResultRecord
    WAFW00F_AVAILABLE = True
except ImportError:
    WAFW00F_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] WAFW00F not found. WAF detection will be limited.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Clone WAFW00F repository to the current directory for better WAF detection.{Style.RESET_ALL}")

# Mapping of WAF names to recommended tamper scripts
# These mappings are based on experience and may need to be updated
WAF_TAMPER_SCRIPTS = {
    # Cloudflare
    'Cloudflare': ['space2comment', 'apostrophemask', 'randomcase'],
    # Akamai
    'Kona SiteDefender': ['space2comment', 'apostrophemask', 'randomcase', 'charencode'],
    # AWS WAF
    'AWS': ['space2randomblank', 'base64encode', 'charencode'],
    # ModSecurity
    'ModSecurity': ['apostrophemask', 'lowercase', 'space2comment'],
    # F5 WAF
    'F5 BIG-IP ASM': ['space2morehash', 'apostrophemask', 'randomcase'],
    # Imperva
    'Imperva': ['apostrophemask', 'space2comment', 'chardoubleencode'],
    # Sucuri
    'Sucuri': ['space2randomblank', 'apostrophemask', 'htmlencode'],
    # Fortinet
    'FortiWeb': ['apostrophemask', 'lowercase', 'space2randomblank'],
    # Barracuda
    'Barracuda': ['apostrophemask', 'space2comment', 'equaltolike'],
    # Citrix
    'NetScaler AppFirewall': ['apostrophemask', 'randomcase', 'space2comment'],
    # Generic WAF (fallback)
    'Generic': ['space2comment', 'apostrophemask', 'charencode']
}

# Add common variations of WAF names to ensure match
WAF_NAME_VARIATIONS = {
    'Cloudflare WAF': 'Cloudflare',
    'Akamai Kona': 'Kona SiteDefender',
    'Amazon WAF': 'AWS',
    'AWS WAF': 'AWS',
    'Amazon Web Services': 'AWS',
    'ModSecurity WAF': 'ModSecurity',
    'ModSec': 'ModSecurity',
    'F5 WAF': 'F5 BIG-IP ASM',
    'F5 Networks': 'F5 BIG-IP ASM',
    'BIG-IP': 'F5 BIG-IP ASM',
    'Imperva SecureSphere': 'Imperva',
    'Incapsula': 'Imperva',
    'Sucuri WAF': 'Sucuri',
    'Sucuri CloudProxy': 'Sucuri',
    'FortiGate': 'FortiWeb',
    'FortiADC': 'FortiWeb',
    'Barracuda WAF': 'Barracuda',
    'Citrix WAF': 'NetScaler AppFirewall',
    'AppWall': 'NetScaler AppFirewall'
}

def detect_waf(url, proxy=None, timeout=10, verbose=False):
    """
    Detect WAF using WAFW00F
    
    Args:
        url (str): Target URL to check
        proxy (str): Optional proxy to use (e.g., http://127.0.0.1:8080)
        timeout (int): Timeout for requests in seconds
        verbose (bool): Enable verbose output
    
    Returns:
        tuple: (WAF name, WAF manufacturer)
    """
    if not WAFW00F_AVAILABLE:
        print(f"{Fore.YELLOW}[!] WAFW00F not available. Using basic WAF detection.{Style.RESET_ALL}")
        return basic_waf_detection(url, proxy, timeout)
    
    # Configure logging
    log_level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=log_level)
    
    # Parse URL
    parsed_url = urlparse(url)
    target = parsed_url.netloc
    path = parsed_url.path if parsed_url.path else "/"
    ssl = parsed_url.scheme == "https"
    
    # Configure proxy
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}
    
    try:
        print(f"{Fore.BLUE}[*] Detecting WAF on {url}{Style.RESET_ALL}")
        wafw00f = WAFW00F(target=target, debuglevel=verbose, path=path, followredirect=True, proxies=proxies, timeout=timeout)
        wafs, evil_url = wafw00f.identwaf(findall=True)
        
        if wafs:
            for waf in wafs:
                print(f"{Fore.GREEN}[+] WAF detected: {waf}{Style.RESET_ALL}")
            
            # Get manufacturer from first WAF found
            result = buildResultRecord(url, wafs[0] if wafs else None)
            return wafs[0], result.get("manufacturer", "Unknown")
        else:
            print(f"{Fore.YELLOW}[!] No WAF detected on {url}{Style.RESET_ALL}")
            return None, None
    except Exception as e:
        print(f"{Fore.RED}[ERROR] WAF detection error: {str(e)}{Style.RESET_ALL}")
        return None, None

def basic_waf_detection(url, proxy=None, timeout=10):
    """
    Basic WAF detection when WAFW00F is not available
    
    Args:
        url (str): Target URL to check
        proxy (str): Optional proxy to use
        timeout (int): Timeout for requests
    
    Returns:
        tuple: (WAF name, WAF manufacturer)
    """
    print(f"{Fore.BLUE}[*] Performing basic WAF detection on {url}{Style.RESET_ALL}")
    
    # Prepare headers and proxies
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    }
    
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}
    
    try:
        # First, make a normal request
        normal_resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
        
        # Payload to trigger WAF
        attack_url = url
        if "?" not in url:
            attack_url = f"{url}?id='OR 1=1--"
        else:
            attack_url = f"{url}&id='OR 1=1--"
        
        # Make attack request
        attack_resp = requests.get(attack_url, headers=headers, proxies=proxies, timeout=timeout)
        
        # Check for common WAF signatures in headers
        waf_detected = None
        manufacturer = None
        
        # Check for status code changes
        if normal_resp.status_code != attack_resp.status_code:
            waf_detected = "Generic"
            manufacturer = "Unknown"
            print(f"{Fore.GREEN}[+] WAF detected: Different status codes between normal and attack requests{Style.RESET_ALL}")
        
        # Look for common WAF headers
        for resp in [normal_resp, attack_resp]:
            server = resp.headers.get("Server", "")
            if "cloudflare" in server.lower():
                waf_detected = "Cloudflare"
                manufacturer = "Cloudflare, Inc."
                break
            elif "sucuri" in server.lower():
                waf_detected = "Sucuri"
                manufacturer = "Sucuri Inc."
                break
            elif "nginx" in server.lower() and attack_resp.status_code == 403:
                waf_detected = "NGINX WAF"
                manufacturer = "NGINX"
                break
            
            # Check cookies
            for cookie in resp.cookies:
                if "__cfduid" in cookie.name:
                    waf_detected = "Cloudflare"
                    manufacturer = "Cloudflare, Inc."
                    break
        
        if waf_detected:
            print(f"{Fore.GREEN}[+] WAF detected: {waf_detected} ({manufacturer}){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No WAF detected on {url}{Style.RESET_ALL}")
            
        return waf_detected, manufacturer
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Basic WAF detection error: {str(e)}{Style.RESET_ALL}")
        return None, None

def get_tamper_scripts_for_waf(waf_name, default_tampers=None):
    """
    Get appropriate tamper scripts for the detected WAF
    
    Args:
        waf_name (str): Name of the detected WAF
        default_tampers (list): Default tamper scripts to use if no match
    
    Returns:
        list: List of recommended tamper scripts
    """
    if not waf_name:
        return default_tampers or ["space2comment", "apostrophemask"]
    
    # Normalize WAF name
    waf_normalized = WAF_NAME_VARIATIONS.get(waf_name, waf_name)
    
    # Get tamper scripts for the WAF
    tamper_scripts = WAF_TAMPER_SCRIPTS.get(waf_normalized, None)
    
    # If no specific tamper scripts for this WAF, try generic ones
    if not tamper_scripts:
        for key, value in WAF_NAME_VARIATIONS.items():
            if waf_name.lower() in key.lower() or key.lower() in waf_name.lower():
                tamper_scripts = WAF_TAMPER_SCRIPTS.get(value, None)
                if tamper_scripts:
                    break
    
    # Still no tamper scripts? Use generic ones
    if not tamper_scripts:
        tamper_scripts = WAF_TAMPER_SCRIPTS.get("Generic", ["space2comment", "apostrophemask"])
    
    # If default_tampers provided, merge them with recommended ones
    if default_tampers:
        return list(set(tamper_scripts + default_tampers))
        
    return tamper_scripts

def detect_and_select_tampers(url, proxy=None, default_tampers=None, verbose=False):
    """
    Detect WAF and select appropriate tamper scripts
    
    Args:
        url (str): Target URL to check
        proxy (str): Optional proxy to use
        default_tampers (list): Default tamper scripts to use
        verbose (bool): Enable verbose output
    
    Returns:
        dict: Result containing WAF info and tamper scripts
    """
    waf_name, manufacturer = detect_waf(url, proxy, verbose=verbose)
    
    tamper_scripts = get_tamper_scripts_for_waf(waf_name, default_tampers)
    
    result = {
        "waf_detected": waf_name is not None,
        "waf_name": waf_name or "None",
        "waf_manufacturer": manufacturer or "None",
        "tamper_scripts": tamper_scripts
    }
    
    if waf_name:
        print(f"{Fore.GREEN}[+] Selected tamper scripts for {waf_name}: {', '.join(tamper_scripts)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Using generic tamper scripts: {', '.join(tamper_scripts)}{Style.RESET_ALL}")
    
    return result

if __name__ == "__main__":
    # Test function when run directly
    if len(sys.argv) > 1:
        url = sys.argv[1]
        proxy = sys.argv[2] if len(sys.argv) > 2 else None
        result = detect_and_select_tampers(url, proxy, verbose=True)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python wafw00f_integrator.py <url> [proxy]")
        print("Example: python wafw00f_integrator.py https://example.com http://127.0.0.1:8080") 