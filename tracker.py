#!/usr/bin/env python3
# Tracker Module - Central tracking system for SQL injection testing
# Integrates ID generation, fingerprinting, and result tracking

import os
import sys
import json
import time
import uuid
import logging
from datetime import datetime
import sqlite3
import threading
import hashlib

# Import our custom modules
from id_generator import IDGenerator
from fingerprint import TargetFingerprinter

class SQLiTracker:
    def __init__(self, output_dir="results", db_file=None):
        """Initialize the SQL injection tracker"""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize ID generator
        self.id_generator = IDGenerator()
        
        # Initialize fingerprinter
        self.fingerprinter = TargetFingerprinter(self.id_generator)
        
        # Initialize database
        self.db_file = db_file or os.path.join(output_dir, "sqli_tracker.db")
        self.init_database()
        
        # Thread-local storage for session IDs
        self.thread_local = threading.local()
        
        # Set up logging
        self.setup_logging()
        
    def setup_logging(self):
        """Set up logging for the tracker"""
        log_file = os.path.join(self.output_dir, "tracker.log")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("SQLiTracker")
        
    def init_database(self):
        """Initialize the SQLite database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_sessions (
            scan_id TEXT PRIMARY KEY,
            target TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT,
            options TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_id TEXT PRIMARY KEY,
            scan_id TEXT,
            url TEXT,
            param TEXT,
            vuln_type TEXT,
            payload TEXT,
            details TEXT,
            discovery_time TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS tests (
            test_id TEXT PRIMARY KEY,
            scan_id TEXT,
            url TEXT,
            param TEXT,
            payload TEXT,
            result TEXT,
            test_time TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS fingerprints (
            fp_id TEXT PRIMARY KEY,
            type TEXT,
            target TEXT,
            details TEXT,
            creation_time TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
        
    def start_scan_session(self, target, options=None):
        """Start a new scan session"""
        scan_id = self.id_generator.scan_id
        start_time = datetime.now().isoformat()
        
        # Store in database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO scan_sessions VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, target, start_time, None, "running", json.dumps(options or {}))
        )
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Started scan session {scan_id} for {target}")
        return scan_id
        
    def end_scan_session(self, scan_id=None):
        """End a scan session"""
        if not scan_id:
            scan_id = self.id_generator.scan_id
            
        end_time = datetime.now().isoformat()
        
        # Update database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE scan_sessions SET end_time = ?, status = ? WHERE scan_id = ?",
            (end_time, "completed", scan_id)
        )
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Completed scan session {scan_id}")
        return scan_id
        
    def start_test(self, url, param, payload):
        """Start a new test and return a test ID"""
        scan_id = getattr(self.thread_local, 'scan_id', self.id_generator.scan_id)
        
        # Generate a payload ID
        payload_id = self.id_generator.generate_payload_id(payload)
        
        # Generate a test ID
        test_id = self.id_generator.generate_test_id(url, param, payload_id)
        
        # Store test start in database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO tests VALUES (?, ?, ?, ?, ?, ?, ?)",
            (test_id, scan_id, url, param, payload, "running", datetime.now().isoformat())
        )
        
        conn.commit()
        conn.close()
        
        if getattr(self.logger, 'isEnabledFor', lambda x: True)(logging.DEBUG):
            self.logger.debug(f"Started test {test_id} for {url} [{param}]")
            
        return test_id
        
    def end_test(self, test_id, result):
        """End a test with result"""
        # Update database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE tests SET result = ? WHERE test_id = ?",
            (json.dumps(result), test_id)
        )
        
        conn.commit()
        conn.close()
        
        if getattr(self.logger, 'isEnabledFor', lambda x: True)(logging.DEBUG):
            self.logger.debug(f"Completed test {test_id} with result: {result.get('vulnerable', False)}")
            
        return test_id
        
    def record_vulnerability(self, url, param, payload, details, vuln_type="SQLI"):
        """Record a vulnerability"""
        scan_id = getattr(self.thread_local, 'scan_id', self.id_generator.scan_id)
        
        # Generate vulnerability ID
        vuln_id = self.id_generator.generate_vuln_id(url, param, vuln_type)
        
        # Create fingerprint
        response_text = details.get("response_text", "")
        response_time = details.get("response_time", 0)
        fp_id, _ = self.fingerprinter.fingerprint_vulnerability(url, param, payload, response_text, response_time)
        
        # Store in database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (vuln_id, scan_id, url, param, vuln_type, payload, json.dumps(details), datetime.now().isoformat())
        )
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Recorded vulnerability {vuln_id} in {url} [{param}]: {vuln_type}")
        return vuln_id, fp_id
        
    def fingerprint_target(self, url):
        """Create fingerprints for the target"""
        # Extract domain
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # Fingerprint server
        tech_id, _ = self.fingerprinter.fingerprint_server(url)
        
        # Fingerprint domain
        domain_id, _ = self.fingerprinter.fingerprint_domain(domain)
        
        # Store fingerprints in database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        for fp_id, details in self.fingerprinter.fingerprints.items():
            fp_type = "server" if fp_id.startswith("TECH-") else "domain"
            cursor.execute(
                "INSERT OR REPLACE INTO fingerprints VALUES (?, ?, ?, ?, ?)",
                (fp_id, fp_type, url if fp_type == "server" else domain, 
                 json.dumps(details), datetime.now().isoformat())
            )
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Created fingerprints for {url}: {tech_id}, {domain_id}")
        return tech_id, domain_id
        
    def fingerprint_parameter(self, url, param):
        """Fingerprint a parameter"""
        param_id, details = self.fingerprinter.fingerprint_parameter(url, param)
        
        # Store in database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT OR REPLACE INTO fingerprints VALUES (?, ?, ?, ?, ?)",
            (param_id, "parameter", f"{url}:{param}", json.dumps(details), datetime.now().isoformat())
        )
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Created parameter fingerprint for {url} [{param}]: {param_id}")
        return param_id
        
    def set_session_for_thread(self, scan_id):
        """Set the scan session ID for the current thread"""
        self.thread_local.scan_id = scan_id
        
    def generate_report(self, scan_id=None, format="json"):
        """Generate a report of scan results"""
        if not scan_id:
            scan_id = self.id_generator.scan_id
            
        # Query database
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get scan session info
        cursor.execute("SELECT * FROM scan_sessions WHERE scan_id = ?", (scan_id,))
        session = cursor.fetchone()
        
        if not session:
            self.logger.error(f"Scan session {scan_id} not found")
            conn.close()
            return None
            
        # Get vulnerabilities
        cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        vulnerabilities = [dict(row) for row in cursor.fetchall()]
        
        # Get test counts
        cursor.execute("SELECT COUNT(*) FROM tests WHERE scan_id = ?", (scan_id,))
        test_count = cursor.fetchone()[0]
        
        # Get successful tests
        cursor.execute("SELECT COUNT(*) FROM tests WHERE scan_id = ? AND json_extract(result, '$.vulnerable') = 1", (scan_id,))
        successful_tests = cursor.fetchone()[0]
        
        conn.close()
        
        # Create report
        report = {
            "scan_id": scan_id,
            "target": session["target"],
            "start_time": session["start_time"],
            "end_time": session["end_time"],
            "status": session["status"],
            "statistics": {
                "total_tests": test_count,
                "successful_tests": successful_tests,
                "vulnerability_count": len(vulnerabilities)
            },
            "vulnerabilities": vulnerabilities,
            "generated_at": datetime.now().isoformat()
        }
        
        # Save report
        report_file = os.path.join(self.output_dir, f"report_{scan_id}.{format}")
        
        if format == "json":
            with open(report_file, "w") as f:
                json.dump(report, f, indent=2)
        else:
            # Default to text format
            with open(report_file, "w") as f:
                f.write(f"SQL Injection Scan Report\n")
                f.write(f"=======================\n\n")
                f.write(f"Scan ID: {scan_id}\n")
                f.write(f"Target: {session['target']}\n")
                f.write(f"Start Time: {session['start_time']}\n")
                f.write(f"End Time: {session['end_time']}\n")
                f.write(f"Status: {session['status']}\n\n")
                
                f.write(f"Statistics:\n")
                f.write(f"  Total Tests: {test_count}\n")
                f.write(f"  Successful Tests: {successful_tests}\n")
                f.write(f"  Vulnerabilities Found: {len(vulnerabilities)}\n\n")
                
                if vulnerabilities:
                    f.write(f"Vulnerabilities:\n")
                    f.write(f"---------------\n\n")
                    
                    for vuln in vulnerabilities:
                        f.write(f"ID: {vuln['vuln_id']}\n")
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"Parameter: {vuln['param']}\n")
                        f.write(f"Type: {vuln['vuln_type']}\n")
                        f.write(f"Payload: {vuln['payload']}\n")
                        f.write(f"Discovery Time: {vuln['discovery_time']}\n\n")
        
        self.logger.info(f"Generated report: {report_file}")
        return report_file
        
    def export_ids(self):
        """Export all generated IDs"""
        return self.id_generator.save_id_map(self.output_dir)
        
    def get_vulnerability_count(self, scan_id=None):
        """Get the number of vulnerabilities found"""
        if not scan_id:
            scan_id = self.id_generator.scan_id
            
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
        
    def get_fingerprint_count(self):
        """Get the number of fingerprints created"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM fingerprints")
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
        
    def get_test_count(self, scan_id=None):
        """Get the number of tests performed"""
        if not scan_id:
            scan_id = self.id_generator.scan_id
            
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM tests WHERE scan_id = ?", (scan_id,))
        count = cursor.fetchone()[0]
        
        conn.close()
        return count

# Main function for standalone usage
if __name__ == "__main__":
    tracker = SQLiTracker()
    print(f"SQL Injection Tracker initialized")
    print(f"Scan ID: {tracker.id_generator.scan_id}")
    print(f"Database: {tracker.db_file}")
    print(f"Output directory: {tracker.output_dir}")
