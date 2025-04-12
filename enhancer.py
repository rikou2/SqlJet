#!/usr/bin/env python3
"""
SqlQ Enhancer - Advanced SQL Injection Detection Framework
This module expands SqlQ with advanced capabilities for comprehensive scanning
"""

import os
import re
import sys
import json
import time
import random
import tldextract
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# User-Agent handling
def load_user_agents(user_agent_file="useragents/user-agents.txt"):
    """Load user agents from file"""
    user_agents = []
    try:
        # Get full path if not absolute
        if not os.path.isabs(user_agent_file):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            user_agent_file = os.path.join(base_dir, user_agent_file)
            
        if os.path.exists(user_agent_file):
            with open(user_agent_file, 'r') as f:
                user_agents = [line.strip() for line in f if line.strip()]
                print(f"[+] Loaded {len(user_agents)} user agents")
        else:
            print(f"[!] User agent file not found: {user_agent_file}")
            # Fallback to some common user agents
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
            ]
    except Exception as e:
        print(f"[!] Error loading user agents: {str(e)}")
        # Fallback
        user_agents = ["Mozilla/5.0 (compatible; SqlJet/1.0; +http://example.com)"]
        
    return user_agents

# Get a random user agent
def get_random_user_agent(user_agents=None):
    """Get a random user agent from the loaded list"""
    if not user_agents:
        user_agents = load_user_agents()
    return random.choice(user_agents) if user_agents else "Mozilla/5.0 (compatible; SqlJet/1.0)"

# Replace the immediate loading of user agents with a lazy-loading approach
USER_AGENTS = None

def get_user_agents():
    global USER_AGENTS
    if USER_AGENTS is None:
        USER_AGENTS = load_user_agents()
    return USER_AGENTS

# --- API Endpoint Discovery ---

def extract_js_endpoints(url, output_file):
    """
    Extract API endpoints from JavaScript files on a website
    
    Args:
        url: The base URL to scan
        output_file: File to write discovered endpoints
    
    Returns:
        int: Number of endpoints found
    """
    try:
        # Get the main page
        headers = {'User-Agent': get_random_user_agent(get_user_agents())}
        response = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
        if response.status_code != 200:
            print(f"[!] Failed to fetch {url}, status code: {response.status_code}")
            return 0
            
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract all JavaScript files
        js_files = []
        for script in soup.find_all('script'):
            if script.get('src'):
                js_url = script.get('src')
                # Handle relative URLs
                if not js_url.startswith(('http://', 'https://')):
                    js_url = urljoin(url, js_url)
                js_files.append(js_url)
        
        print(f"[*] Found {len(js_files)} JavaScript files")
        
        # Extract API endpoints from JS files
        endpoints = set()
        api_patterns = [
            r'url:\s*[\'"]([^\'"]+)[\'"]',
            r'fetch\([\'"]([^\'"]+)[\'"]',
            r'axios\.(?:get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            r'\.ajax\(\{[^}]*url:\s*[\'"]([^\'"]+)[\'"]',
            r'path:\s*[\'"]([^\'"]+)[\'"]',
            r'endpoint[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]',
            r'route[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]',
            r'href=[\'"](/api[^\'"]+)[\'"]',
            r'(/api/[a-zA-Z0-9/\-_]+)',
            r'(/v[0-9]+/[a-zA-Z0-9/\-_]+)'
        ]
        
        for js_url in js_files:
            try:
                headers = {'User-Agent': get_random_user_agent(get_user_agents())}
                js_response = requests.get(js_url, headers=headers, timeout=20, allow_redirects=True)
                if js_response.status_code == 200:
                    js_content = js_response.text
                    
                    # Apply patterns to find API endpoints
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_content)
                        for match in matches:
                            # Skip if it's a placeholder like {id}
                            if '{' in match or '}' in match:
                                continue
                                
                            # Skip common non-API URLs
                            if match.startswith(('http://', 'https://')):
                                parsed = urlparse(match)
                                if parsed.netloc == urlparse(url).netloc:
                                    endpoints.add(match)
                            elif match.startswith('/'):
                                endpoints.add(urljoin(url, match))
            except Exception as e:
                print(f"[!] Error processing JavaScript file {js_url}: {e}")
                continue
        
        # Save discovered endpoints
        with open(output_file, 'w') as f:
            for endpoint in sorted(endpoints):
                f.write(f"{endpoint}\n")
                
        print(f"[+] Discovered {len(endpoints)} potential API endpoints from JavaScript files")
        return len(endpoints)
        
    except Exception as e:
        print(f"[!] Error extracting JavaScript endpoints: {e}")
        return 0

# --- Login Form Detection ---

def find_login_forms(url, output_file):
    """
    Find login forms on a website for testing SQL injection in auth forms
    
    Args:
        url: The URL to scan
        output_file: File to write discovered login pages
    
    Returns:
        int: Number of forms found
    """
    try:
        # Get the main page
        headers = {'User-Agent': get_random_user_agent(get_user_agents())}
        response = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
        if response.status_code != 200:
            print(f"[!] Failed to fetch {url}, status code: {response.status_code}")
            return 0
            
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Login-related keywords
        login_keywords = ['login', 'signin', 'log-in', 'sign-in', 'auth', 'authenticate', 'account']
        
        # List to store login form URLs
        login_urls = set()
        
        # Method 1: Find forms with login-related action or ID
        for form in soup.find_all('form'):
            form_action = form.get('action', '').lower()
            form_id = form.get('id', '').lower()
            form_class = ' '.join(form.get('class', [])).lower()
            
            # Check if form has login-related attributes
            is_login_form = any(keyword in form_action or keyword in form_id or keyword in form_class 
                               for keyword in login_keywords)
            
            # Check if form has password field
            has_password = bool(form.find('input', {'type': 'password'}))
            
            if is_login_form or has_password:
                # Handle relative URLs
                if form_action:
                    if not form_action.startswith(('http://', 'https://')):
                        form_action = urljoin(url, form_action)
                    login_urls.add(form_action)
                else:
                    # If no action, use current URL
                    login_urls.add(url)
        
        # Method 2: Find links to login pages
        for a in soup.find_all('a'):
            href = a.get('href', '').lower()
            text = a.text.lower()
            
            if any(keyword in href or keyword in text for keyword in login_keywords):
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(url, href)
                login_urls.add(href)
        
        # Method 3: Common login paths
        base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url))
        common_paths = ['/login', '/signin', '/sign-in', '/auth', '/authentication', 
                         '/user/login', '/account/login', '/members/login']
        
        for path in common_paths:
            login_urls.add(urljoin(base_url, path))
        
        # Filter out empty URLs and write to file
        login_urls = [u for u in login_urls if u and not u.endswith(('#', '?', '/'))]
        
        with open(output_file, 'w') as f:
            for login_url in sorted(login_urls):
                f.write(f"{login_url}\n")
        
        print(f"[+] Discovered {len(login_urls)} potential login pages")
        return len(login_urls)
        
    except Exception as e:
        print(f"[!] Error finding login forms: {e}")
        return 0

# --- Content Type Detection ---

def detect_content_types(urls_file, output_dir):
    """
    Analyze URLs to detect content types (JSON, XML, HTML forms, etc.)
    
    Args:
        urls_file: File containing URLs to analyze
        output_dir: Directory to store categorized URLs
    
    Returns:
        dict: Dictionary with counts of different content types
    """
    if not os.path.exists(urls_file):
        print(f"[!] URLs file not found: {urls_file}")
        return {}
        
    # Create output files
    json_urls_file = os.path.join(output_dir, "json_endpoints.txt")
    xml_urls_file = os.path.join(output_dir, "xml_endpoints.txt")
    html_form_urls_file = os.path.join(output_dir, "html_form_urls.txt")
    
    # Initialize counters
    content_types = {
        'json': 0,
        'xml': 0,
        'html_form': 0,
        'other': 0
    }
    
    # Open output files
    with open(json_urls_file, 'w') as json_f, \
         open(xml_urls_file, 'w') as xml_f, \
         open(html_form_urls_file, 'w') as html_f:
        
        # Read URLs
        with open(urls_file, 'r') as f:
            urls = [line.strip() for line in f.readlines()]
        
        print(f"[*] Analyzing content types for {len(urls)} URLs")
        
        # Function to check a single URL
        def check_url(url):
            result = {'url': url, 'type': 'other'}
            try:
                # Send HEAD request first to check content type
                headers = {'User-Agent': get_random_user_agent(get_user_agents())}
                head_response = requests.head(url, headers=headers, timeout=20, allow_redirects=True)
                content_type = head_response.headers.get('Content-Type', '').lower()
                
                # Check for JSON
                if 'json' in content_type or url.endswith(('.json', '/json')):
                    result['type'] = 'json'
                # Check for XML
                elif 'xml' in content_type or url.endswith(('.xml', '/xml')):
                    result['type'] = 'xml'
                else:
                    # If not determined by header, try GET request
                    response = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
                    content = response.text
                    
                    # Check for JSON response
                    if response.headers.get('Content-Type', '').lower().startswith('application/json'):
                        result['type'] = 'json'
                    # Check if content looks like JSON
                    elif content.strip().startswith('{') and content.strip().endswith('}'):
                        try:
                            json.loads(content)
                            result['type'] = 'json'
                        except:
                            pass
                    # Check for XML
                    elif content.strip().startswith('<') and '?xml' in content[:100]:
                        result['type'] = 'xml'
                    # Check for HTML forms
                    elif '<form' in content.lower():
                        soup = BeautifulSoup(content, 'html.parser')
                        if soup.find('form'):
                            result['type'] = 'html_form'
            except Exception as e:
                print(f"[!] Error analyzing {url}: {e}")
            return result
        
        # Process URLs in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_url, urls))
        
        # Process results
        for result in results:
            content_type = result['type']
            url = result['url']
            
            content_types[content_type] = content_types.get(content_type, 0) + 1
            
            if content_type == 'json':
                json_f.write(f"{url}\n")
            elif content_type == 'xml':
                xml_f.write(f"{url}\n")
            elif content_type == 'html_form':
                html_f.write(f"{url}\n")
    
    print(f"[+] Content type analysis complete:")
    print(f"    - JSON endpoints: {content_types['json']}")
    print(f"    - XML endpoints: {content_types['xml']}")
    print(f"    - HTML forms: {content_types['html_form']}")
    print(f"    - Other: {content_types['other']}")
    
    return content_types

# --- POST Request Generation ---

def generate_post_requests(urls_file, output_file):
    """
    Generate POST request templates for URLs with forms
    
    Args:
        urls_file: File containing URLs to analyze
        output_file: File to write POST request templates
    
    Returns:
        int: Number of POST templates generated
    """
    if not os.path.exists(urls_file):
        print(f"[!] URLs file not found: {urls_file}")
        return 0
    
    post_templates = []
    
    # Read URLs
    with open(urls_file, 'r') as f:
        urls = [line.strip() for line in f.readlines()]
    
    print(f"[*] Generating POST request templates for {len(urls)} URLs")
    
    # Function to analyze a single URL
    def analyze_url(url):
        templates = []
        try:
            headers = {'User-Agent': get_random_user_agent(get_user_agents())}
            response = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Process each form
                for form in soup.find_all('form'):
                    form_method = form.get('method', 'get').lower()
                    form_action = form.get('action', '')
                    
                    # Focus on POST forms
                    if form_method == 'post':
                        # Handle relative URLs
                        if form_action:
                            if not form_action.startswith(('http://', 'https://')):
                                form_action = urljoin(url, form_action)
                        else:
                            form_action = url
                        
                        # Extract form fields
                        fields = {}
                        for input_field in form.find_all(['input', 'textarea', 'select']):
                            field_name = input_field.get('name')
                            field_type = input_field.get('type', '')
                            
                            if field_name and field_type not in ['submit', 'button', 'reset', 'image', 'file']:
                                # Use dummy values based on field type
                                if field_type == 'password':
                                    fields[field_name] = 'password123'
                                elif 'user' in field_name.lower() or 'email' in field_name.lower():
                                    fields[field_name] = 'testuser@example.com'
                                else:
                                    fields[field_name] = '1'
                        
                        if fields:
                            templates.append({
                                'url': form_action,
                                'method': 'POST',
                                'data': fields
                            })
        except Exception as e:
            print(f"[!] Error analyzing {url} for POST templates: {e}")
        
        return templates
    
    # Process URLs in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(analyze_url, urls))
    
    # Flatten results
    for result in results:
        post_templates.extend(result)
    
    # Write templates to file
    with open(output_file, 'w') as f:
        json.dump(post_templates, f, indent=4)
    
    print(f"[+] Generated {len(post_templates)} POST request templates")
    return len(post_templates)

# --- Main Integration Function ---

def enhance_scan(domain, output_dir):
    """
    Run enhanced scanning features
    
    Args:
        domain: Target domain
        output_dir: Directory to store results
    
    Returns:
        dict: Summary of enhancement results
    """
    results = {
        'api_endpoints': 0,
        'login_forms': 0,
        'content_types': {},
        'post_templates': 0
    }
    
    # Make sure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Base URL
    base_url = f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain
    
    print(f"\n[*] Starting enhanced scanning for {domain}")
    
    # 1. Extract API endpoints from JavaScript
    js_endpoints_file = os.path.join(output_dir, "js_endpoints.txt")
    results['api_endpoints'] = extract_js_endpoints(base_url, js_endpoints_file)
    
    # 2. Find login forms
    login_forms_file = os.path.join(output_dir, "login_forms.txt")
    results['login_forms'] = find_login_forms(base_url, login_forms_file)
    
    # 3. Detect content types for URLs
    urls_file = os.path.join(output_dir, "all_urls.txt")
    # If all_urls.txt doesn't exist yet, create a basic one for this test
    if not os.path.exists(urls_file):
        with open(urls_file, 'w') as f:
            f.write(f"{base_url}\n")
    
    results['content_types'] = detect_content_types(urls_file, output_dir)
    
    # 4. Generate POST request templates
    html_form_urls_file = os.path.join(output_dir, "html_form_urls.txt")
    post_templates_file = os.path.join(output_dir, "post_templates.json")
    
    if os.path.exists(html_form_urls_file):
        results['post_templates'] = generate_post_requests(html_form_urls_file, post_templates_file)
    
    print(f"\n[+] Enhanced scanning complete for {domain}")
    return results

if __name__ == "__main__":
    # Simple test code when run directly
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        output_dir = os.path.join("results", domain)
        enhance_scan(domain, output_dir)
    else:
        print("Usage: python3 enhancer.py domain.com")
