#!/usr/bin/env python3
# Domain Scanner Module
# Discovers subdomains, URLs, and endpoints for comprehensive SQL injection testing

import os
import re
import json
import logging
import dns.resolver
import requests
import threading
import queue
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('domain_scanner')

class DomainScanner:
    """
    Comprehensive domain scanner to discover subdomains, URLs, and endpoints
    for SQL injection testing
    """
    def __init__(self, config=None):
        """Initialize domain scanner with configuration"""
        self.config = config or {}
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize scan properties
        self.target_domain = None
        self.discovered_subdomains = set()
        self.discovered_urls = set()
        self.discovered_endpoints = set()
        self.injectable_params = {}
        
        # Thread control
        self.threads = self.config.get('threads', 10)
        self.scan_queue = queue.Queue()
        self.lock = threading.Lock()
        
        # User agent for requests
        self.user_agent = self.config.get('user_agent', 'SQLi Toolkit/1.0')
        
        # Maximum scan depth
        self.max_depth = self.config.get('max_depth', 3)
        
        # Maximum pages to scan
        self.max_pages = self.config.get('max_pages', 500)
        
        # Timeout for requests
        self.timeout = self.config.get('timeout', 10)
        
        # Set of already processed URLs to avoid duplicates
        self.processed_urls = set()
        
        logger.info("Domain Scanner module initialized")
        
    def scan_domain(self, domain):
        """
        Perform comprehensive scan of a domain:
        1. Find subdomains
        2. Discover URLs on each subdomain
        3. Extract endpoints and parameters
        
        Args:
            domain: The target domain to scan
            
        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting comprehensive scan of domain: {domain}")
        
        # Clean up domain if needed
        self.target_domain = self._clean_domain(domain)
        
        # Step 1: Find subdomains
        self._discover_subdomains()
        
        # Step 2: Discover URLs on each subdomain
        self._discover_urls()
        
        # Step 3: Extract endpoints with potential injectable parameters
        self._extract_endpoints()
        
        # Prepare results
        results = {
            "target_domain": self.target_domain,
            "subdomains_count": len(self.discovered_subdomains),
            "subdomains": list(self.discovered_subdomains),
            "urls_count": len(self.discovered_urls),
            "urls": list(self.discovered_urls),
            "endpoints_count": len(self.discovered_endpoints),
            "endpoints": list(self.discovered_endpoints),
            "injectable_params_count": sum(len(params) for params in self.injectable_params.values()),
            "injectable_params": self.injectable_params
        }
        
        # Save results to file
        self._save_results(results)
        
        logger.info(f"Scan completed for {domain}: Found {results['subdomains_count']} subdomains, {results['urls_count']} URLs, {results['endpoints_count']} endpoints, and {results['injectable_params_count']} potential injectable parameters")
        
        return results
        
    def _clean_domain(self, domain):
        """Clean domain name by removing protocol and path"""
        domain = domain.strip().lower()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
            
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
            
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':', 1)[0]
            
        return domain
        
    def _discover_subdomains(self):
        """Discover subdomains using various techniques"""
        logger.info(f"Discovering subdomains for {self.target_domain}")
        
        # Always add the main domain
        self.discovered_subdomains.add(self.target_domain)
        
        # Method 1: DNS enumeration
        self._dns_enumeration()
        
        # Method 2: Certificate transparency logs
        self._cert_transparency_enumeration()
        
        # Method 3: Web scraping for common subdomains
        self._common_subdomains_enumeration()
        
        # Add www. subdomain if not already discovered
        www_domain = f"www.{self.target_domain}"
        if www_domain not in self.discovered_subdomains:
            self.discovered_subdomains.add(www_domain)
            
        logger.info(f"Discovered {len(self.discovered_subdomains)} subdomains")
        
    def _dns_enumeration(self):
        """Discover subdomains using DNS enumeration"""
        try:
            # Load common subdomain dictionary
            common_subdomains = [
                "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
                "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "admin", "web",
                "dev", "test", "portal", "beta", "staging", "app", "docs", "support",
                "status", "static", "media", "images", "auth", "login"
            ]
            
            for subdomain in common_subdomains:
                try:
                    domain_to_check = f"{subdomain}.{self.target_domain}"
                    dns.resolver.resolve(domain_to_check, 'A')
                    self.discovered_subdomains.add(domain_to_check)
                    logger.debug(f"DNS enumeration found: {domain_to_check}")
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"Error in DNS enumeration: {e}")
            
    def _cert_transparency_enumeration(self):
        """Discover subdomains using certificate transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for item in data:
                        domain = item.get('name_value', '').lower()
                        
                        # Remove wildcard and cleanup
                        domain = domain.replace('*.', '')
                        
                        # Ensure it's a subdomain of the target
                        if domain.endswith(f".{self.target_domain}") or domain == self.target_domain:
                            self.discovered_subdomains.add(domain)
                            logger.debug(f"Certificate transparency found: {domain}")
                except:
                    logger.debug("Error parsing crt.sh response")
                    
        except Exception as e:
            logger.error(f"Error in certificate transparency enumeration: {e}")
            
    def _common_subdomains_enumeration(self):
        """
        Try common subdomains by directly checking their existence
        """
        # Load or create a wordlist of common subdomains
        wordlist_path = os.path.join(self.data_dir, 'common_subdomains.txt')
        
        # Create default wordlist if it doesn't exist
        if not os.path.exists(wordlist_path):
            common_subdomains = [
                "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
                "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "admin", "web",
                "dev", "test", "portal", "beta", "staging", "app", "docs", "support",
                "status", "static", "media", "images", "auth", "login", "mobile",
                "dashboard", "api-docs", "backend", "frontend", "internal", "extranet"
            ]
            
            with open(wordlist_path, 'w') as f:
                for subdomain in common_subdomains:
                    f.write(f"{subdomain}\n")
        
        # Read wordlist
        with open(wordlist_path, 'r') as f:
            subdomain_list = [line.strip() for line in f if line.strip()]
            
        # Set up threading
        threads = []
        subdomain_queue = queue.Queue()
        
        # Add subdomains to queue
        for subdomain in subdomain_list:
            subdomain_queue.put(subdomain)
            
        # Define worker function
        def worker():
            while not subdomain_queue.empty():
                try:
                    subdomain = subdomain_queue.get(block=False)
                    domain_to_check = f"{subdomain}.{self.target_domain}"
                    
                    try:
                        # Try HTTPS first
                        response = requests.head(
                            f"https://{domain_to_check}", 
                            timeout=self.timeout,
                            headers={"User-Agent": self.user_agent},
                            allow_redirects=True
                        )
                        
                        if response.status_code < 500:  # Consider any non-server-error as potentially valid
                            with self.lock:
                                self.discovered_subdomains.add(domain_to_check)
                                logger.debug(f"Found subdomain via HTTPS: {domain_to_check}")
                    except:
                        try:
                            # Fall back to HTTP
                            response = requests.head(
                                f"http://{domain_to_check}", 
                                timeout=self.timeout,
                                headers={"User-Agent": self.user_agent},
                                allow_redirects=True
                            )
                            
                            if response.status_code < 500:  # Consider any non-server-error as potentially valid
                                with self.lock:
                                    self.discovered_subdomains.add(domain_to_check)
                                    logger.debug(f"Found subdomain via HTTP: {domain_to_check}")
                        except:
                            pass
                            
                    subdomain_queue.task_done()
                except queue.Empty:
                    break
                except Exception as e:
                    logger.debug(f"Error checking subdomain: {e}")
                    subdomain_queue.task_done()
        
        # Start worker threads
        for _ in range(min(self.threads, len(subdomain_list))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Wait for all threads to complete
        for t in threads:
            t.join()
            
    def _discover_urls(self):
        """Discover URLs on each subdomain using web crawling"""
        logger.info(f"Discovering URLs on {len(self.discovered_subdomains)} subdomains")
        
        # Initialize URL discovery
        self.processed_urls = set()
        self.discovered_urls = set()
        
        # Create queue for URLs to process
        url_queue = queue.Queue()
        
        # Add initial URLs to queue
        for subdomain in self.discovered_subdomains:
            # Try HTTPS first, then HTTP
            https_url = f"https://{subdomain}"
            http_url = f"http://{subdomain}"
            
            url_queue.put((https_url, 0))  # (url, depth)
            url_queue.put((http_url, 0))   # (url, depth)
            
        # Set up threading
        threads = []
            
        # Define worker function
        def worker():
            while not url_queue.empty() and len(self.discovered_urls) < self.max_pages:
                try:
                    url, depth = url_queue.get(block=False)
                    
                    # Skip if URL has already been processed
                    with self.lock:
                        if url in self.processed_urls:
                            url_queue.task_done()
                            continue
                        
                        self.processed_urls.add(url)
                    
                    try:
                        # Fetch URL content
                        response = requests.get(
                            url, 
                            timeout=self.timeout,
                            headers={"User-Agent": self.user_agent},
                            allow_redirects=True
                        )
                        
                        # Skip if not HTML
                        content_type = response.headers.get('Content-Type', '')
                        if 'text/html' not in content_type:
                            url_queue.task_done()
                            continue
                            
                        # Add URL to discovered list
                        with self.lock:
                            self.discovered_urls.add(url)
                            logger.debug(f"Discovered URL: {url}")
                            
                        # Extract linked URLs if not at max depth
                        if depth < self.max_depth and len(self.discovered_urls) < self.max_pages:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            # Find all links
                            for a_tag in soup.find_all('a', href=True):
                                href = a_tag['href']
                                
                                # Skip empty links, anchors, javascript, and mailto
                                if not href or href.startswith(('#', 'javascript:', 'mailto:')):
                                    continue
                                    
                                # Convert relative URL to absolute
                                if not href.startswith(('http://', 'https://')):
                                    href = urljoin(url, href)
                                    
                                # Ensure it's a subdomain of our target
                                parsed_href = urlparse(href)
                                href_domain = parsed_href.netloc.lower()
                                
                                if href_domain and (href_domain == self.target_domain or href_domain.endswith(f".{self.target_domain}")):
                                    # Add new URL to queue
                                    url_queue.put((href, depth + 1))
                                    
                    except Exception as e:
                        logger.debug(f"Error fetching URL {url}: {e}")
                        
                    url_queue.task_done()
                    
                except queue.Empty:
                    break
                except Exception as e:
                    logger.debug(f"Error in URL discovery worker: {e}")
                    try:
                        url_queue.task_done()
                    except:
                        pass
        
        # Start worker threads
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Wait for completion or timeout
        start_time = time.time()
        max_runtime = 600  # 10 minutes max
        
        while not url_queue.empty() and len(self.discovered_urls) < self.max_pages:
            if time.time() - start_time > max_runtime:
                logger.warning(f"URL discovery timed out after {max_runtime} seconds")
                break
            time.sleep(1)
            
        logger.info(f"Discovered {len(self.discovered_urls)} URLs")
        
    def _extract_endpoints(self):
        """
        Extract endpoints and potential injectable parameters from discovered URLs
        """
        logger.info("Extracting endpoints with potential injectable parameters")
        
        # Regular expressions for common parameter patterns that might be injectable
        injectable_param_patterns = [
            r'id=\d+',
            r'user(id|name)=[^&]+',
            r'category=[^&]+',
            r'search=[^&]+',
            r'query=[^&]+',
            r'item(id)?=\d+',
            r'product(id)?=\d+',
            r'page(id)?=\d+',
            r'view=[^&]+',
            r'file=[^&]+',
            r'key=[^&]+',
            r'p=[^&]+',
            r'pid=[^&]+',
            r'sid=[^&]+',
            r'uid=[^&]+',
            r'edit=\d+'
        ]
        
        # Compile regex patterns
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in injectable_param_patterns]
        
        for url in self.discovered_urls:
            parsed_url = urlparse(url)
            
            # Skip URLs without query parameters
            if not parsed_url.query:
                continue
                
            # Extract the endpoint (path without query)
            endpoint = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            self.discovered_endpoints.add(endpoint)
            
            # Initialize params for this endpoint
            if endpoint not in self.injectable_params:
                self.injectable_params[endpoint] = []
                
            # Extract parameters that match injectable patterns
            for pattern in compiled_patterns:
                matches = pattern.findall(parsed_url.query)
                
                if matches:
                    for match in matches:
                        # Extract parameter name and value
                        if '=' in match:
                            param_name, param_value = match.split('=', 1)
                            
                            # Add to injectable parameters if not already present
                            param_info = {
                                "name": param_name,
                                "example_value": param_value,
                                "url": url
                            }
                            
                            # Check if parameter already exists
                            if not any(p.get('name') == param_name for p in self.injectable_params[endpoint]):
                                self.injectable_params[endpoint].append(param_info)
                                logger.debug(f"Found potentially injectable parameter: {param_name} in {url}")
        
        logger.info(f"Extracted {len(self.discovered_endpoints)} endpoints with {sum(len(params) for params in self.injectable_params.values())} potentially injectable parameters")
        
    def _save_results(self, results):
        """Save scan results to file"""
        output_file = os.path.join(self.data_dir, f"domain_scan_{self.target_domain}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Scan results saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving scan results: {e}")
            
    def generate_targets_file(self):
        """
        Generate a targets file with all discovered endpoints and parameters
        for SQL injection testing
        """
        if not self.discovered_endpoints:
            logger.warning("No endpoints discovered, cannot generate targets file")
            return None
            
        targets_file = os.path.join(self.data_dir, f"sqli_targets_{self.target_domain}.txt")
        
        try:
            with open(targets_file, 'w') as f:
                # Add all endpoints with injectable parameters
                for endpoint, params in self.injectable_params.items():
                    for param in params:
                        # Create test URL with parameter
                        test_url = f"{endpoint}?{param['name']}={param['example_value']}"
                        f.write(f"{test_url}\n")
                
            logger.info(f"Generated SQL injection targets file: {targets_file}")
            return targets_file
            
        except Exception as e:
            logger.error(f"Error generating targets file: {e}")
            return None

if __name__ == "__main__":
    # Simple test/demo
    scanner = DomainScanner({
        'threads': 5,
        'max_depth': 2,
        'max_pages': 50,
        'timeout': 5
    })
    
    results = scanner.scan_domain("example.com")
    
    print(f"\nDomain Scanner Results:")
    print(f"Discovered {results['subdomains_count']} subdomains")
    print(f"Discovered {results['urls_count']} URLs")
    print(f"Discovered {results['endpoints_count']} endpoints")
    print(f"Found {results['injectable_params_count']} potential injectable parameters")
    
    # Generate targets file
    targets_file = scanner.generate_targets_file()
    if targets_file:
        print(f"\nGenerated targets file: {targets_file}")
        print("Use this file with SQLi Toolkit for comprehensive testing:")
