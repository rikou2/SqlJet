#!/usr/bin/env python3
"""
Test script for automatic database enumeration
This simulates finding vulnerable URLs and tests the database enumeration functionality
"""

import os
import sys
from sqlsc import run_dbs_enum, vulnerable, success, info, header

# Configuration for test
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
VULNERABLE_URLS_FILE = os.path.join(TEST_DIR, "test_vulnerable_urls.txt")
OUTPUT_DIR = os.path.join(TEST_DIR, "test_results")

def main():
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Display colorful banner
    header("SQL INJECTION TEST - DATABASE ENUMERATION")
    info(f"Testing automatic database enumeration with {VULNERABLE_URLS_FILE}")
    info(f"Results will be saved to {OUTPUT_DIR}")
    
    # Simulate finding vulnerabilities
    vulnerable("Simulated SQL injection vulnerabilities found!")
    success(f"Found {sum(1 for _ in open(VULNERABLE_URLS_FILE))} vulnerable URLs")
    
    # Run the database enumeration function
    print("\n")
    run_dbs_enum(
        vulnerable_urls_file=VULNERABLE_URLS_FILE,
        output_dir=OUTPUT_DIR,
        tamper_scripts="between,charencode",
        level=3,
        risk=2,
        threads=5,
        verbose=True
    )
    
    print("\n")
    info("Test completed! Check results directory for database enumeration output.")

if __name__ == "__main__":
    main()
