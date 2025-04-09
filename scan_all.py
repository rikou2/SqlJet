#!/usr/bin/env python3
# SQL Injection Comprehensive Scanner
# Automatically finds subdomains, URLs, endpoints and scans for SQL injection vulnerabilities

import sys
import os
import argparse
import logging
import json
import importlib.util
import datetime
import subprocess

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sql_scan_all.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('scan_all')

def load_module(module_name, module_path):
    """
    Dynamically load a Python module from path
    """
    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        logger.error(f"Error loading module {module_name} from {module_path}: {e}")
        return None

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="SQL Injection Comprehensive Scanner - Automatically finds subdomains, URLs, endpoints and scans for SQL injection vulnerabilities")
    
    # Target specification
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    
    # Scan options
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=500, help="Maximum pages to scan per domain (default: 500)")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain discovery")
    
    # Advanced options
    parser.add_argument("--impact", action="store_true", help="Perform business impact assessment")
    parser.add_argument("--vaccine", action="store_true", help="Generate SQL injection vaccine for vulnerabilities")
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text", help="Report format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Current directory for module imports
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)
    
    # Start scan process
    logger.info(f"Starting comprehensive scan of domain: {args.domain}")
    print(f"\n[+] Starting comprehensive scan of domain: {args.domain}")
    print(f"[+] This will automatically discover subdomains, URLs, and endpoints before testing for SQL injection vulnerabilities\n")
    
    start_time = datetime.datetime.now()
    
    # Create results dictionary
    scan_results = {
        "scan_id": f"scan_{start_time.strftime('%Y%m%d_%H%M%S')}",
        "target_domain": args.domain,
        "start_time": start_time.isoformat(),
        "end_time": None,
        "status": "running",
        "options": vars(args),
        "subdomains": [],
        "urls": [],
        "endpoints": [],
        "injectable_parameters": {},
        "vulnerabilities": [],
        "recommendations": []
    }
    
    try:
        # Step 1: Load domain scanner module
        domain_scanner_path = os.path.join(base_dir, 'domain_scanner.py')
        domain_scanner_module = load_module('domain_scanner', domain_scanner_path)
        
        if not domain_scanner_module:
            logger.error("Failed to load domain scanner module")
            print("[!] Error: Failed to load domain scanner module")
            return
        
        # Step 2: Configure and run domain scanner
        scanner_config = {
            'threads': args.threads,
            'timeout': args.timeout,
            'max_depth': args.depth,
            'max_pages': args.max_pages
        }
        
        domain_scanner = domain_scanner_module.DomainScanner(scanner_config)
        
        print(f"[*] Step 1: Discovering subdomains, URLs, and endpoints...")
        domain_scan_results = domain_scanner.scan_domain(args.domain)
        
        if domain_scan_results:
            scan_results["subdomains"] = domain_scan_results.get("subdomains", [])
            scan_results["urls"] = domain_scan_results.get("urls", [])
            scan_results["endpoints"] = domain_scan_results.get("endpoints", [])
            scan_results["injectable_parameters"] = domain_scan_results.get("injectable_params", {})
            
            print(f"[+] Discovered {len(scan_results['subdomains'])} subdomains")
            print(f"[+] Found {len(scan_results['urls'])} URLs")
            print(f"[+] Identified {len(scan_results['endpoints'])} endpoints")
            print(f"[+] Detected {sum(len(params) for params in scan_results['injectable_parameters'].values())} potential injectable parameters")
            
            # Generate targets file for SQLi scanning
            targets_file = domain_scanner.generate_targets_file()
            scan_results["targets_file"] = targets_file
            
            # Step 3: Load SQLi detector module
            sqli_detector_path = os.path.join(base_dir, 'sqli_detector.py')
            sqli_detector_module = load_module('sqli_detector', sqli_detector_path)
            
            if not sqli_detector_module:
                logger.error("Failed to load SQLi detector module")
                print("[!] Error: Failed to load SQLi detector module")
            else:
                # Step 4: Scan each endpoint with injectable parameters
                print(f"\n[*] Step 2: Testing endpoints for SQL injection vulnerabilities...")
                
                sqli_detector = sqli_detector_module.SQLiDetector(
                    threads=args.threads,
                    timeout=args.timeout,
                    verbose=args.verbose
                )
                
                # Track number of vulnerabilities found
                vuln_count = 0
                
                # Process each endpoint with injectable parameters
                for endpoint, params in scan_results["injectable_parameters"].items():
                    for param in params:
                        # Create test URL with parameter
                        test_url = f"{endpoint}?{param['name']}={param['example_value']}"
                        print(f"[*] Testing: {test_url}")
                        
                        # Scan this endpoint for SQL injection
                        scan_result = sqli_detector.scan_url(test_url, max_depth=1)
                        
                        # Add vulnerabilities to results
                        if scan_result and "vulnerabilities" in scan_result:
                            vulns = scan_result["vulnerabilities"]
                            if vulns:
                                print(f"[!] Found {len(vulns)} vulnerabilities in {test_url}")
                                scan_results["vulnerabilities"].extend(vulns)
                                vuln_count += len(vulns)
                
                print(f"\n[+] SQL injection testing complete. Found {vuln_count} vulnerabilities across all endpoints.")
                
                # Step 5: Run business impact assessment if requested
                if args.impact and vuln_count > 0:
                    print(f"\n[*] Step 3: Performing business impact assessment...")
                    
                    # Load business impact module
                    impact_path = os.path.join(base_dir, 'business_impact.py')
                    impact_module = load_module('business_impact', impact_path)
                    
                    if impact_module:
                        assessor = impact_module.BusinessImpactAssessment()
                        assessor.load_vulnerabilities(scan_results["vulnerabilities"])
                        
                        # Default organization info
                        org_info = {
                            "industry": "other",
                            "size": "medium",
                            "data_records": 10000,
                            "annual_revenue": 1000000,
                            "compliance": ["none"]
                        }
                        
                        assessments = assessor.assess_all_vulnerabilities(org_info)
                        
                        if assessments:
                            # Get risk categories
                            risk_categories = assessor.generate_risk_categories()
                            scan_results["risk_assessment"] = {
                                "critical_risk_count": len(risk_categories.get("critical_risk", [])),
                                "high_risk_count": len(risk_categories.get("high_risk", [])),
                                "medium_risk_count": len(risk_categories.get("medium_risk", [])),
                                "low_risk_count": len(risk_categories.get("low_risk", []))
                            }
                            
                            # Get financial impact
                            financial_summary = assessor.generate_financial_summary()
                            scan_results["financial_impact"] = financial_summary
                            
                            # Compile recommendations
                            recommendations = assessor._compile_recommendations()
                            scan_results["recommendations"] = recommendations
                            
                            print(f"[+] Business impact assessment complete")
                            print(f"    Critical risks: {scan_results['risk_assessment']['critical_risk_count']}")
                            print(f"    High risks: {scan_results['risk_assessment']['high_risk_count']}")
                            print(f"    Medium risks: {scan_results['risk_assessment']['medium_risk_count']}")
                            print(f"    Low risks: {scan_results['risk_assessment']['low_risk_count']}")
                            
                            if "total_financial_impact" in financial_summary:
                                print(f"    Estimated financial impact: ${financial_summary['total_financial_impact']:.2f}")
                    else:
                        print("[!] Error: Failed to load business impact module")
                
                # Step 6: Generate SQL injection vaccine if requested
                if args.vaccine and vuln_count > 0:
                    print(f"\n[*] Step 4: Generating SQL injection vaccines...")
                    # This would integrate with the sqli_vaccine module
        else:
            print("[!] Domain scan failed to return results")
    
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        print(f"[!] Error during scan: {e}")
        scan_results["status"] = "error"
        scan_results["error"] = str(e)
    
    # Update scan status
    scan_results["status"] = "completed"
    scan_results["end_time"] = datetime.datetime.now().isoformat()
    
    # Calculate scan duration
    end_time = datetime.datetime.now()
    duration = (end_time - start_time).total_seconds()
    scan_results["duration_seconds"] = duration
    
    # Save results to file
    output_file = os.path.join(results_dir, f"{scan_results['scan_id']}_results.json")
    
    try:
        with open(output_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        print(f"\n[+] Scan results saved to: {output_file}")
    except Exception as e:
        logger.error(f"Error saving scan results: {e}")
        print(f"[!] Error saving scan results: {e}")
    
    # Generate text report if requested
    if args.output == "text":
        report_file = os.path.join(results_dir, f"{scan_results['scan_id']}_report.txt")
        
        try:
            with open(report_file, 'w') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("SQL INJECTION COMPREHENSIVE SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Domain info
                f.write(f"Target Domain: {args.domain}\n")
                f.write(f"Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {duration:.2f} seconds\n\n")
                
                # Summary of findings
                f.write(f"SUMMARY OF FINDINGS\n")
                f.write(f"------------------\n")
                f.write(f"Subdomains Discovered: {len(scan_results['subdomains'])}\n")
                f.write(f"URLs Found: {len(scan_results['urls'])}\n")
                f.write(f"Endpoints Identified: {len(scan_results['endpoints'])}\n")
                f.write(f"Potentially Injectable Parameters: {sum(len(params) for params in scan_results['injectable_parameters'].values())}\n")
                f.write(f"Total Vulnerabilities Found: {len(scan_results['vulnerabilities'])}\n\n")
                
                # Risk breakdown if available
                if "risk_assessment" in scan_results:
                    f.write(f"Risk Breakdown:\n")
                    f.write(f"  Critical Risk: {scan_results['risk_assessment']['critical_risk_count']}\n")
                    f.write(f"  High Risk: {scan_results['risk_assessment']['high_risk_count']}\n")
                    f.write(f"  Medium Risk: {scan_results['risk_assessment']['medium_risk_count']}\n")
                    f.write(f"  Low Risk: {scan_results['risk_assessment']['low_risk_count']}\n\n")
                
                # Financial impact if available
                if "financial_impact" in scan_results:
                    f.write(f"Estimated Financial Impact: ${scan_results['financial_impact'].get('total_financial_impact', 0):.2f}\n\n")
                
                # Subdomains list
                if scan_results['subdomains']:
                    f.write(f"DISCOVERED SUBDOMAINS\n")
                    f.write(f"---------------------\n")
                    for subdomain in scan_results['subdomains']:
                        f.write(f"- {subdomain}\n")
                    f.write("\n")
                
                # Vulnerabilities
                if scan_results['vulnerabilities']:
                    f.write(f"SQL INJECTION VULNERABILITIES\n")
                    f.write(f"----------------------------\n\n")
                    
                    for i, vuln in enumerate(scan_results['vulnerabilities'], 1):
                        f.write(f"{i}. {vuln.get('type', 'SQL Injection')}\n")
                        f.write(f"   URL: {vuln.get('url', 'N/A')}\n")
                        f.write(f"   Parameter: {vuln.get('parameter', 'N/A')}\n")
                        f.write(f"   Severity: {vuln.get('severity', 'Medium')}\n")
                        if "payload" in vuln:
                            f.write(f"   Payload: {vuln.get('payload', 'N/A')}\n")
                        if "details" in vuln:
                            f.write(f"   Details: {vuln.get('details', 'N/A')}\n")
                        f.write("\n")
                
                # Recommendations
                if scan_results.get('recommendations'):
                    f.write(f"REMEDIATION RECOMMENDATIONS\n")
                    f.write(f"--------------------------\n\n")
                    
                    for i, rec in enumerate(scan_results['recommendations'][:10], 1):
                        f.write(f"{i}. {rec.get('title', 'N/A')}\n")
                        f.write(f"   {rec.get('description', 'N/A')}\n")
                        f.write(f"   Priority: {rec.get('priority', 'Medium')}\n")
                        f.write(f"   Effort: {rec.get('effort', 'Medium')}\n")
                        f.write(f"   Affected Vulnerabilities: {rec.get('count', 0)}\n\n")
                
                # Footer
                f.write("\n")
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            print(f"[+] Text report generated: {report_file}")
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            print(f"[!] Error generating text report: {e}")
    
    # Print summary
    print(f"\n[+] Scan completed in {duration:.2f} seconds")
    print(f"[+] Found {len(scan_results['vulnerabilities'])} SQL injection vulnerabilities")
    print(f"[+] Results saved to: {output_file}")

if __name__ == "__main__":
    main()
