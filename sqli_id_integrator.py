#!/usr/bin/env python3
# SQLi ID Integrator - Integrates ID tracking with existing scanner components
# Provides enhanced tracking, fingerprinting, and reporting capabilities

import os
import sys
import json
import argparse
from datetime import datetime

# Import our custom modules
from id_generator import IDGenerator
from fingerprint import TargetFingerprinter
from tracker import SQLiTracker
import sqli_detector

class SQLiIDIntegrator:
    def __init__(self, output_dir="results"):
        """Initialize the ID integrator with tracking capabilities"""
        # Set up output directory
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize tracker
        self.tracker = SQLiTracker(output_dir)
        
        # Reference to the SQLi detector
        self.detector = None
        
    def setup_detector(self, args):
        """Setup and wrap the SQLi detector with ID tracking"""
        # Create detector with standard parameters
        self.detector = sqli_detector.SQLiDetector(
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose
        )
        
        # Set custom output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = os.path.join(self.output_dir, f"scan_{timestamp}")
        self.detector.set_output_dir(scan_dir)
        
        # Store scan options
        options = {
            "threads": args.threads,
            "timeout": args.timeout,
            "verbose": args.verbose,
            "tamper": args.tamper,
            "proxy": args.proxy,
            "auto_waf": args.auto_waf,
            "db_detect": args.db_detect,
            "scan_time": timestamp
        }
        
        # Start a scan session with the tracker
        self.scan_id = self.tracker.start_scan_session(args.target, options)
        
        # Patch detector methods to add ID tracking
        self._patch_detector_methods()
        
        return self.detector
        
    def _patch_detector_methods(self):
        """Patch detector methods to add ID tracking"""
        # Store original method references
        original_test_url = self.detector.test_url
        original_test_payload = self.detector.test_payload
        original_analyze_response = self.detector.analyze_response
        
        # Patch test_url method
        def patched_test_url(url, tamper=None, db_type=None):
            """Patched test_url with ID tracking"""
            # Fingerprint target before testing
            self.tracker.fingerprint_target(url)
            
            # Parse URL for parameters
            base_url, params = self.detector.parse_url_params(url)
            
            # Fingerprint each parameter
            for param_name, _ in params:
                self.tracker.fingerprint_parameter(url, param_name)
            
            # Call original method
            return original_test_url(url, tamper, db_type)
            
        # Patch test_payload method
        def patched_test_payload(url, param_name, payload, tamper=None):
            """Patched test_payload with ID tracking"""
            # Start test tracking
            test_id = self.tracker.start_test(url, param_name, payload)
            
            # Call original method
            vulnerable, result = original_test_payload(url, param_name, payload, tamper)
            
            # End test tracking
            self.tracker.end_test(test_id, result or {"vulnerable": vulnerable})
            
            # If vulnerable, record the vulnerability
            if vulnerable and result:
                details = {
                    "response_text": result.get("details", ""),
                    "response_time": 0,
                    "type": result.get("type", "SQLI"),
                    "test_id": test_id
                }
                self.tracker.record_vulnerability(url, param_name, payload, details, result.get("type", "SQLI"))
            
            return vulnerable, result
            
        # Patch analyze_response method
        def patched_analyze_response(response, baseline, elapsed_time, payload):
            """Patched analyze_response with enhanced details"""
            # Call original method
            result = original_analyze_response(response, baseline, elapsed_time, payload)
            
            # Add additional details for better tracking
            if result["vulnerable"]:
                result["response_time"] = elapsed_time
                result["response_size"] = len(response.text)
                result["status_code"] = response.status_code
            
            return result
        
        # Apply patches
        self.detector.test_url = patched_test_url
        self.detector.test_payload = patched_test_payload
        self.detector.analyze_response = patched_analyze_response
        
    def scan_and_track(self, args):
        """Run a complete scan with tracking"""
        # Setup detector
        detector = self.setup_detector(args)
        
        # Set scan ID for tracking
        self.tracker.set_session_for_thread(self.scan_id)
        
        # Run the scan
        if args.url_file and os.path.isfile(args.url_file):
            # Read URLs from file
            with open(args.url_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
                
            print(f"[-] Scanning {len(urls)} URLs from {args.url_file}...")
            results = detector.scan_urls(urls, args.tamper)
        else:
            # Single URL
            print(f"[-] Scanning target: {args.target}")
            result = detector.test_url(args.target, args.tamper)
            results = [args.target] if result else []
        
        # End scan session
        self.tracker.end_scan_session(self.scan_id)
        
        # Generate reports
        self._generate_reports(args.target, args.report_format)
        
        return results
        
    def _generate_reports(self, target, report_format="all"):
        """Generate comprehensive reports"""
        formats = ["json", "txt"]
        if report_format != "all":
            formats = [report_format]
            
        report_files = []
        for fmt in formats:
            report_file = self.tracker.generate_report(self.scan_id, fmt)
            if report_file:
                report_files.append(report_file)
        
        # Export ID map
        id_map_file = self.tracker.export_ids()
        
        print(f"[+] Reports generated:")
        for report in report_files:
            print(f"    - {report}")
        print(f"    - {id_map_file}")
        
        # Print statistics
        vuln_count = self.tracker.get_vulnerability_count(self.scan_id)
        test_count = self.tracker.get_test_count(self.scan_id)
        fp_count = self.tracker.get_fingerprint_count()
        
        print(f"\n[+] Scan Summary:")
        print(f"    - Target: {target}")
        print(f"    - Scan ID: {self.scan_id}")
        print(f"    - Tests performed: {test_count}")
        print(f"    - Vulnerabilities found: {vuln_count}")
        print(f"    - Fingerprints created: {fp_count}")
        
        return report_files

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="SQLi Scanner with Enhanced ID Tracking")
    
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("--url-file", help="File containing URLs to scan")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--tamper", help="Comma-separated tamper techniques")
    parser.add_argument("--proxy", help="Use proxy (format: http://proxy:port)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--report-format", default="all", help="Report format (json, txt, all)")
    parser.add_argument("--auto-waf", action="store_true", help="Auto-detect WAF and bypass")
    parser.add_argument("--db-detect", action="store_true", help="Detect database type")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    
    return parser.parse_args()

def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════╗
    ║  SQLi Scanner with Enhanced ID Tracking   ║
    ║  Generates comprehensive IDs and tracks   ║
    ║  all aspects of SQL injection testing     ║
    ╚═══════════════════════════════════════════╝
    """)
    
    args = parse_args()
    
    # Create integrator
    integrator = SQLiIDIntegrator(args.output_dir)
    
    # Run scan with tracking
    results = integrator.scan_and_track(args)
    
    if results:
        print(f"\n[+] Found {len(results)} vulnerable URLs")
    else:
        print(f"\n[-] No vulnerabilities found")
    
    print(f"\n[+] Done! All IDs and tracking information saved to {args.output_dir}")

if __name__ == "__main__":
    main()
