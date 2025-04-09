#!/usr/bin/env python3
# Fingerprint Module - Advanced fingerprinting for targets and vulnerabilities
# Creates unique fingerprints based on various characteristics

import re
import json
import hashlib
import requests
import socket
import urllib.parse
from datetime import datetime
import ssl
import random
from user_agents import parse as ua_parse

# Import our ID generator
from id_generator import IDGenerator

class TargetFingerprinter:
    def __init__(self, id_generator=None):
        """Initialize fingerprinter with optional ID generator"""
        self.id_generator = id_generator or IDGenerator()
        self.fingerprints = {}
        
    def fingerprint_server(self, url):
        """Create a fingerprint of the server technology"""
        try:
            response = requests.head(url, timeout=10, verify=False, 
                                     headers={"User-Agent": "Mozilla/5.0 (compatible; SQLi-Scanner/2.0)"})
            
            # Extract server information
            server = response.headers.get("Server", "")
            x_powered_by = response.headers.get("X-Powered-By", "")
            technologies = []
            
            # Check for common technologies
            if "Apache" in server:
                technologies.append("Apache")
            if "nginx" in server:
                technologies.append("nginx")
            if "IIS" in server:
                technologies.append("IIS")
            if "PHP" in x_powered_by:
                technologies.append("PHP")
            if "ASP.NET" in x_powered_by:
                technologies.append("ASP.NET")
            
            # Create a hash of the technology fingerprint
            tech_string = f"{server}|{x_powered_by}|{'|'.join(technologies)}"
            tech_hash = hashlib.md5(tech_string.encode()).hexdigest()[:12]
            
            # Generate a tech ID
            tech_id = f"TECH-{tech_hash}"
            
            # Store fingerprint
            self.fingerprints[tech_id] = {
                "url": url,
                "server": server,
                "x_powered_by": x_powered_by,
                "technologies": technologies,
                "timestamp": datetime.now().isoformat(),
                "headers": dict(response.headers)
            }
            
            return tech_id, self.fingerprints[tech_id]
            
        except Exception as e:
            return None, {"error": str(e)}
            
    def fingerprint_domain(self, domain):
        """Create a fingerprint of the domain infrastructure"""
        try:
            # Get IP address
            ip = socket.gethostbyname(domain)
            
            # Try to get SSL/TLS information
            ssl_info = {}
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info = {
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "subject": dict(x[0] for x in cert['subject']),
                            "version": cert['version'],
                            "valid_from": cert['notBefore'],
                            "valid_to": cert['notAfter']
                        }
            except:
                # SSL/TLS info not available
                pass
                
            # Create a hash of the domain fingerprint
            domain_string = f"{domain}|{ip}|{json.dumps(ssl_info)}"
            domain_hash = hashlib.md5(domain_string.encode()).hexdigest()[:12]
            
            # Generate a domain ID
            domain_id = f"DOMAIN-{domain_hash}"
            
            # Store fingerprint
            self.fingerprints[domain_id] = {
                "domain": domain,
                "ip": ip,
                "ssl_info": ssl_info,
                "timestamp": datetime.now().isoformat()
            }
            
            return domain_id, self.fingerprints[domain_id]
            
        except Exception as e:
            return None, {"error": str(e)}
            
    def fingerprint_parameter(self, url, param_name, param_value="1"):
        """Create a fingerprint of how a parameter behaves"""
        try:
            # We'll test different types of input to see how the parameter responds
            test_values = [
                "1", # numeric
                "string", # text
                "1'", # SQL quote
                "<script>", # XSS
                "../", # path traversal
                "1 AND 1=1", # SQL logic
                str(random.randint(1000000, 9999999)) # random number
            ]
            
            responses = {}
            parsed_url = urllib.parse.urlparse(url)
            
            # Build base URL without the parameter we're testing
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Store original param value if it exists
            original_value = query_params.get(param_name, [""])[0]
            
            base_params = {}
            for p, v in query_params.items():
                if p != param_name:
                    base_params[p] = v[0]
            
            for test_value in test_values:
                # Construct test URL
                test_params = base_params.copy()
                test_params[param_name] = test_value
                
                query_string = urllib.parse.urlencode(test_params)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query_string,
                    parsed_url.fragment
                ))
                
                # Make request
                try:
                    response = requests.get(test_url, timeout=10, verify=False,
                                           headers={"User-Agent": "Mozilla/5.0 (compatible; SQLi-Scanner/2.0)"})
                    
                    responses[test_value] = {
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "response_time": response.elapsed.total_seconds(),
                        "is_error": any(err in response.text.lower() for err in ["error", "exception", "invalid", "failed"]),
                    }
                except:
                    responses[test_value] = {"error": "Request failed"}
            
            # Analyze responses to determine parameter behavior
            behavior = {
                "numeric_sensitive": responses["1"]["content_length"] != responses["string"]["content_length"],
                "sql_injectable": responses["1"]["content_length"] != responses["1'"]["content_length"] or 
                                  responses["1'"].get("is_error", False),
                "xss_sensitive": responses["string"]["content_length"] != responses["<script>"]["content_length"] or
                                 "<script>" in responses["<script>"].get("headers", {}).get("Content-Type", ""),
                "path_sensitive": "../" in url or responses["../"].get("status_code") == 404,
                "original_value": original_value,
                "response_variance": max(r.get("content_length", 0) for r in responses.values() if isinstance(r, dict)) - 
                                    min(r.get("content_length", 0) for r in responses.values() if isinstance(r, dict))
            }
            
            # Create parameter fingerprint ID
            param_string = f"{url}|{param_name}|{json.dumps(behavior)}"
            param_hash = hashlib.md5(param_string.encode()).hexdigest()[:12]
            param_id = f"PARAM-{param_hash}"
            
            # Store fingerprint
            self.fingerprints[param_id] = {
                "url": url,
                "param_name": param_name,
                "behavior": behavior,
                "responses": responses,
                "timestamp": datetime.now().isoformat()
            }
            
            return param_id, self.fingerprints[param_id]
            
        except Exception as e:
            return None, {"error": str(e)}
    
    def fingerprint_vulnerability(self, url, param_name, payload, response_text, response_time):
        """Create a fingerprint of a detected vulnerability"""
        try:
            # Extract error patterns or unique identifiers from the response
            error_patterns = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"PostgreSQL.*ERROR",
                r"Driver.* SQL[\-\_\ ]*Server",
                r"ORA-[0-9][0-9][0-9][0-9]",
                r"SQL syntax.*",
                r"syntax error\s*at"
            ]
            
            matched_patterns = []
            for pattern in error_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    matched_patterns.append(match.group(0))
            
            # Create vulnerability fingerprint
            vuln_details = {
                "url": url,
                "param": param_name,
                "payload": payload,
                "response_time": response_time,
                "matched_patterns": matched_patterns,
                "response_hash": hashlib.md5(response_text.encode()).hexdigest(),
                "timestamp": datetime.now().isoformat()
            }
            
            # Generate vulnerability ID using the ID Generator
            vuln_id = self.id_generator.generate_vuln_id(url, param_name)
            
            # Store the fingerprint
            self.fingerprints[vuln_id] = vuln_details
            
            return vuln_id, vuln_details
            
        except Exception as e:
            return None, {"error": str(e)}
            
    def save_fingerprints(self, output_file):
        """Save all fingerprints to a file"""
        try:
            with open(output_file, "w") as f:
                json.dump({
                    "generated_at": datetime.now().isoformat(),
                    "fingerprints": self.fingerprints
                }, f, indent=2)
                
            return True
        except Exception as e:
            print(f"Error saving fingerprints: {e}")
            return False
            
    def load_fingerprints(self, input_file):
        """Load fingerprints from a file"""
        try:
            with open(input_file, "r") as f:
                data = json.load(f)
                
            self.fingerprints = data.get("fingerprints", {})
            return True
        except Exception as e:
            print(f"Error loading fingerprints: {e}")
            return False
            
    def get_fingerprint(self, fingerprint_id):
        """Get a specific fingerprint by ID"""
        return self.fingerprints.get(fingerprint_id, {})

# Main function for standalone usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python fingerprint.py <url> <param_name>")
        sys.exit(1)
        
    url = sys.argv[1]
    param_name = sys.argv[2]
    
    id_gen = IDGenerator()
    fingerprinter = TargetFingerprinter(id_gen)
    
    print(f"Fingerprinting server: {url}")
    tech_id, tech_details = fingerprinter.fingerprint_server(url)
    
    domain = urllib.parse.urlparse(url).netloc
    print(f"Fingerprinting domain: {domain}")
    domain_id, domain_details = fingerprinter.fingerprint_domain(domain)
    
    print(f"Fingerprinting parameter: {param_name}")
    param_id, param_details = fingerprinter.fingerprint_parameter(url, param_name)
    
    print("\nResults:")
    print(f"Technology ID: {tech_id}")
    print(f"Domain ID: {domain_id}")
    print(f"Parameter ID: {param_id}")
    
    # Save results
    output_file = "fingerprints.json"
    if fingerprinter.save_fingerprints(output_file):
        print(f"Fingerprints saved to {output_file}")
