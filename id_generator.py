#!/usr/bin/env python3
# ID Generator Module - Advanced identification and tracking for SQL injection attacks
# Provides unique IDs and tracking for vulnerabilities, payloads, and scan sessions

import os
import re
import time
import uuid
import random
import string
import hashlib
import json
from datetime import datetime

class IDGenerator:
    def __init__(self, scan_id=None):
        """Initialize ID Generator with optional scan ID"""
        self.scan_id = scan_id or self._generate_scan_id()
        self.id_map = {}
        self.id_counters = {
            "VULN": 0,
            "PAY": 0,
            "TEST": 0,
            "WAF": 0,
            "DB": 0
        }
        
    def _generate_scan_id(self):
        """Generate a unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"SCAN_{timestamp}_{random_str}"
        
    def generate_vuln_id(self, url, param, vuln_type="SQLI"):
        """Generate a unique vulnerability ID"""
        self.id_counters["VULN"] += 1
        
        # Create a hash based on URL and parameter to ensure consistency
        url_param_hash = hashlib.md5(f"{url}:{param}".encode()).hexdigest()[:8]
        
        # Format: VULN-[SCAN_ID]-[COUNTER]-[URL_PARAM_HASH]
        vuln_id = f"VULN-{self.id_counters['VULN']}-{url_param_hash}"
        
        # Store details
        self.id_map[vuln_id] = {
            "type": "vulnerability",
            "url": url,
            "param": param,
            "vuln_type": vuln_type,
            "timestamp": datetime.now().isoformat()
        }
        
        return vuln_id
        
    def generate_payload_id(self, payload, db_type="generic", tamper=None):
        """Generate a unique payload ID"""
        self.id_counters["PAY"] += 1
        
        # Create a hash based on the payload
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
        
        # Format: PAY-[COUNTER]-[DB_TYPE]-[PAYLOAD_HASH]
        payload_id = f"PAY-{self.id_counters['PAY']}-{db_type[:3].upper()}-{payload_hash}"
        
        # Store details
        self.id_map[payload_id] = {
            "type": "payload",
            "payload": payload,
            "db_type": db_type,
            "tamper": tamper,
            "timestamp": datetime.now().isoformat()
        }
        
        return payload_id
        
    def generate_test_id(self, url, param, payload_id):
        """Generate a unique test ID for tracking injection tests"""
        self.id_counters["TEST"] += 1
        
        # Create a hash based on the test parameters
        test_hash = hashlib.md5(f"{url}:{param}:{payload_id}".encode()).hexdigest()[:8]
        
        # Format: TEST-[COUNTER]-[TEST_HASH]
        test_id = f"TEST-{self.id_counters['TEST']}-{test_hash}"
        
        # Store details
        self.id_map[test_id] = {
            "type": "test",
            "url": url,
            "param": param,
            "payload_id": payload_id,
            "timestamp": datetime.now().isoformat()
        }
        
        return test_id
        
    def generate_waf_id(self, url, waf_type):
        """Generate a unique WAF identification ID"""
        self.id_counters["WAF"] += 1
        
        # Create a hash based on the URL
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        
        # Format: WAF-[WAF_TYPE]-[URL_HASH]
        waf_id = f"WAF-{waf_type.upper()}-{url_hash}"
        
        # Store details
        self.id_map[waf_id] = {
            "type": "waf",
            "url": url,
            "waf_type": waf_type,
            "timestamp": datetime.now().isoformat()
        }
        
        return waf_id
        
    def generate_db_id(self, url, db_type):
        """Generate a unique database identification ID"""
        self.id_counters["DB"] += 1
        
        # Create a hash based on the URL
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        
        # Format: DB-[DB_TYPE]-[URL_HASH]
        db_id = f"DB-{db_type.upper()}-{url_hash}"
        
        # Store details
        self.id_map[db_id] = {
            "type": "db",
            "url": url,
            "db_type": db_type,
            "timestamp": datetime.now().isoformat()
        }
        
        return db_id
        
    def get_id_details(self, id_str):
        """Get details for an ID"""
        return self.id_map.get(id_str, {})
        
    def save_id_map(self, output_dir):
        """Save ID map to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        output_file = os.path.join(output_dir, "id_map.json")
        
        with open(output_file, "w") as f:
            json.dump({
                "scan_id": self.scan_id,
                "generated_at": datetime.now().isoformat(),
                "id_counters": self.id_counters,
                "id_map": self.id_map
            }, f, indent=2)
            
        return output_file
        
    def load_id_map(self, input_file):
        """Load ID map from file"""
        if not os.path.exists(input_file):
            return False
            
        with open(input_file, "r") as f:
            data = json.load(f)
            
        self.scan_id = data.get("scan_id", self.scan_id)
        self.id_counters = data.get("id_counters", self.id_counters)
        self.id_map = data.get("id_map", self.id_map)
        
        return True
        
    def generate_request_id(self, url, method="GET"):
        """Generate a unique HTTP request ID"""
        timestamp = int(time.time())
        url_hash = hashlib.md5(url.encode()).hexdigest()[:6]
        return f"REQ-{method[:1]}-{timestamp}-{url_hash}"
        
    def generate_response_id(self, request_id):
        """Generate a unique HTTP response ID based on request ID"""
        return f"RESP-{request_id[4:]}"
        
    def generate_session_id(self):
        """Generate a unique session ID"""
        return f"SESSION-{uuid.uuid4().hex[:12]}"
        
    def categorize_id(self, id_str):
        """Determine the type of ID from its format"""
        if id_str.startswith("VULN-"):
            return "vulnerability"
        elif id_str.startswith("PAY-"):
            return "payload"
        elif id_str.startswith("TEST-"):
            return "test"
        elif id_str.startswith("WAF-"):
            return "waf"
        elif id_str.startswith("DB-"):
            return "database"
        elif id_str.startswith("REQ-"):
            return "request"
        elif id_str.startswith("RESP-"):
            return "response"
        elif id_str.startswith("SESSION-"):
            return "session"
        elif id_str.startswith("SCAN_"):
            return "scan"
        else:
            return "unknown"
            
    def print_id_stats(self):
        """Print statistics about generated IDs"""
        print(f"Scan ID: {self.scan_id}")
        print(f"Vulnerability IDs: {self.id_counters['VULN']}")
        print(f"Payload IDs: {self.id_counters['PAY']}")
        print(f"Test IDs: {self.id_counters['TEST']}")
        print(f"WAF IDs: {self.id_counters['WAF']}")
        print(f"Database IDs: {self.id_counters['DB']}")
        print(f"Total IDs in map: {len(self.id_map)}")

if __name__ == "__main__":
    # Simple demo
    id_gen = IDGenerator()
    
    vuln_id = id_gen.generate_vuln_id("http://example.com/page.php?id=1", "id")
    payload_id = id_gen.generate_payload_id("' OR 1=1--", "mysql")
    test_id = id_gen.generate_test_id("http://example.com/page.php?id=1", "id", payload_id)
    waf_id = id_gen.generate_waf_id("http://example.com", "cloudflare")
    db_id = id_gen.generate_db_id("http://example.com", "mysql")
    
    print(f"Generated IDs:")
    print(f"Scan ID: {id_gen.scan_id}")
    print(f"Vulnerability ID: {vuln_id}")
    print(f"Payload ID: {payload_id}")
    print(f"Test ID: {test_id}")
    print(f"WAF ID: {waf_id}")
    print(f"Database ID: {db_id}")
    
    # Save to file
    output_file = id_gen.save_id_map("./results")
    print(f"ID map saved to {output_file}")
