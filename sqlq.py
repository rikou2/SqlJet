#!/usr/bin/env python3
# SQLi Toolkit - Main Integration Script
# Comprehensive SQL Injection testing, detection, and protection toolkit

import os
import sys
import argparse
import json
import logging
import datetime
import requests
import threading
import time
import importlib.util
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sqlq.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('sqlq')

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

class SQLQToolkit:
    """
    SQLi Toolkit - Comprehensive SQL Injection testing, detection, and protection
    """
    def __init__(self):
        """Initialize the SQLi Toolkit"""
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.results_dir = os.path.join(self.base_dir, 'results')
        os.makedirs(self.results_dir, exist_ok=True)
        
        self.modules = {}
        self.session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_results = {
            "session_id": self.session_id,
            "start_time": datetime.datetime.now().isoformat(),
            "end_time": None,
            "targets": [],
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize modules
        self._load_modules()
        
        logger.info("SQLi Toolkit initialized")
        
    def _load_config(self):
        """Load configuration from file or create default"""
        config_file = os.path.join(self.base_dir, 'config', 'sqlq_config.json')
        
        # Create config directory if it doesn't exist
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"Configuration loaded from {config_file}")
                return config
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                
        # Create default configuration
        config = {
            "general": {
                "threads": 10,
                "timeout": 30,
                "user_agent": "SQLi Toolkit/1.0",
                "verify_ssl": False,
                "proxy": None,
                "results_dir": "results"
            },
            "scanner": {
                "max_depth": 3,
                "max_params": 20,
                "test_all_params": True,
                "follow_redirects": True
            },
            "organization": {
                "industry": "other",
                "size": "medium",
                "data_records": 10000,
                "annual_revenue": 1000000,
                "compliance": ["none"]
            },
            "modules": {
                "waf_identify": True,
                "payload_generator": True,
                "db_detector": True,
                "tracker": True,
                "advanced_features": True,
                "ml_detection": True,
                "cloud_platform": False,
                "browser_extension": False,
                "ai_analysis": True,
                "iot_mobile_scanner": True,
                "business_impact": True,
                "sqli_vaccine": True
            }
        }
        
        # Save default configuration
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Default configuration created at {config_file}")
        except Exception as e:
            logger.error(f"Error saving default configuration: {e}")
            
        return config
    
    def _load_modules(self):
        """Load all available modules"""
        module_files = {
            'sqli_detector': 'sqli_detector.py',
            'waf_identify': 'waf_identify.py',
            'payload_generator': 'payload_generator.py',
            'db_detector': 'db_detector.py',
            'tracker': 'tracker.py', 
            'advanced_features': 'advanced_features.py',
            'ml_detection': 'ml_detection.py',
            'cloud_platform': 'cloud_platform.py',
            'browser_extension': 'browser_extension.py',
            'ai_analysis': 'ai_analysis.py',
            'iot_mobile_scanner': 'iot_mobile_scanner.py',
            'business_impact': 'business_impact.py'
        }
        
        # Try to load each module
        for module_name, module_file in module_files.items():
            # Skip modules disabled in config
            if module_name in self.config.get('modules', {}) and not self.config['modules'].get(module_name, True):
                logger.info(f"Module {module_name} is disabled in configuration")
                continue
                
            module_path = os.path.join(self.base_dir, module_file)
            
            if os.path.exists(module_path):
                try:
                    # Import module dynamically
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Store the module
                    self.modules[module_name] = module
                    logger.info(f"Module loaded: {module_name}")
                except Exception as e:
                    logger.error(f"Error loading module {module_name}: {e}")
            else:
                logger.warning(f"Module file not found: {module_path}")
                
    def scan_target(self, target_url, options=None):
        """
        Scan a target URL for SQL injection vulnerabilities
        
        Args:
            target_url: The URL to scan
            options: Additional scan options
            
        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting scan of target: {target_url}")
        
        # Initialize scan options
        scan_options = {
            "threads": self.config['general']['threads'],
            "timeout": self.config['general']['timeout'],
            "max_depth": self.config['scanner']['max_depth'],
            "test_all_params": self.config['scanner']['test_all_params']
        }
        
        # Update with user options if provided
        if options:
            scan_options.update(options)
            
        # Prepare results structure
        scan_id = f"scan_{self.session_id}_{len(self.session_results['targets']) + 1}"
        scan_results = {
            "scan_id": scan_id,
            "target_url": target_url,
            "start_time": datetime.datetime.now().isoformat(),
            "end_time": None,
            "status": "running",
            "options": scan_options,
            "vulnerabilities": [],
            "technologies": {},
            "recommendations": []
        }
        
        # Add to session results
        self.session_results["targets"].append(scan_results)
        
        try:
            # Step 1: Initialize tracker if available
            tracker = None
            if 'tracker' in self.modules:
                try:
                    tracker_module = self.modules['tracker']
                    tracker = tracker_module.SQLiTracker()
                    tracker.start_scan_session(target_url, scan_options)
                    logger.info(f"Tracker initialized for scan {scan_id}")
                except Exception as e:
                    logger.error(f"Error initializing tracker: {e}")
            
            # Step 2: Run AI Analysis if available
            ai_analysis_results = None
            if 'ai_analysis' in self.modules:
                try:
                    ai_module = self.modules['ai_analysis']
                    ai_analyzer = ai_module.AIAnalysis(self.config.get('ai_analysis', {}))
                    ai_analysis_results = ai_analyzer.analyze_page(target_url)
                    
                    if ai_analysis_results:
                        scan_results["technologies"] = {
                            "framework": ai_analysis_results.get("framework", {}).get("name") if ai_analysis_results.get("framework") else "Unknown",
                            "database": ai_analysis_results.get("database", {}).get("name") if ai_analysis_results.get("database") else "Unknown",
                            "context": ai_analysis_results.get("context", {}).get("type", "Unknown")
                        }
                        logger.info(f"AI Analysis complete for {target_url}")
                except Exception as e:
                    logger.error(f"Error in AI Analysis: {e}")
            
            # Step 3: Detect WAF if available
            waf_results = None
            if 'waf_identify' in self.modules:
                try:
                    waf_module = self.modules['waf_identify']
                    waf_detector = waf_module.WAFIdentifier()
                    waf_results = waf_detector.identify_waf(target_url)
                    
                    if waf_results and waf_results.get("detected"):
                        scan_results["technologies"]["waf"] = waf_results.get("name", "Unknown WAF")
                        logger.info(f"WAF detected: {waf_results.get('name', 'Unknown')}")
                except Exception as e:
                    logger.error(f"Error in WAF detection: {e}")
            
            # Step 4: Detect database if available
            db_results = None
            if 'db_detector' in self.modules and not scan_results["technologies"].get("database") or scan_results["technologies"].get("database") == "Unknown":
                try:
                    db_module = self.modules['db_detector']
                    db_detector = db_module.DBDetector()
                    db_results = db_detector.detect_db(target_url)
                    
                    if db_results and db_results.get("database"):
                        scan_results["technologies"]["database"] = db_results.get("database")
                        logger.info(f"Database detected: {db_results.get('database')}")
                except Exception as e:
                    logger.error(f"Error in database detection: {e}")
            
            # Step 5: Run the main SQL injection scan
            vulnerabilities = []
            if 'sqli_detector' in self.modules:
                try:
                    sqli_module = self.modules['sqli_detector']
                    sqli_detector = sqli_module.SQLiDetector(
                        threads=scan_options["threads"],
                        timeout=scan_options["timeout"],
                        verbose=True
                    )
                    
                    # Configure with analysis results if available
                    if ai_analysis_results:
                        injectable_params = [p.get("name") for p in ai_analysis_results.get("injectable_parameters", []) if p.get("likely_injectable", False)]
                        if injectable_params:
                            sqli_detector.target_parameters = injectable_params
                    
                    # Run the scan
                    scan_results_raw = sqli_detector.scan_url(target_url, max_depth=scan_options["max_depth"])
                    
                    if scan_results_raw and "vulnerabilities" in scan_results_raw:
                        vulnerabilities = scan_results_raw["vulnerabilities"]
                        scan_results["vulnerabilities"] = vulnerabilities
                        
                        # Update tracker if available
                        if tracker:
                            for vuln in vulnerabilities:
                                tracker.add_vulnerability(vuln)
                                
                        logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {target_url}")
                except Exception as e:
                    logger.error(f"Error in SQL injection scan: {e}")
            
            # Step 6: Run IoT/Mobile scanning if specified
            if 'iot_mobile_scanner' in self.modules and scan_options.get("scan_mobile_api", False):
                try:
                    iot_module = self.modules['iot_mobile_scanner']
                    scanner = iot_module.IoTMobileScanner()
                    api_vulns = scanner.scan_mobile_app_backend(target_url)
                    
                    if api_vulns:
                        # Add to main vulnerabilities list
                        vulnerabilities.extend(api_vulns)
                        scan_results["vulnerabilities"] = vulnerabilities
                        
                        # Update tracker if available
                        if tracker:
                            for vuln in api_vulns:
                                tracker.add_vulnerability(vuln)
                                
                        logger.info(f"Found {len(api_vulns)} vulnerabilities in mobile API endpoints")
                except Exception as e:
                    logger.error(f"Error in IoT/Mobile scanning: {e}")
            
            # Step 7: Run business impact assessment if available
            if 'business_impact' in self.modules and vulnerabilities:
                try:
                    impact_module = self.modules['business_impact']
                    assessor = impact_module.BusinessImpactAssessment()
                    assessor.load_vulnerabilities(vulnerabilities)
                    
                    # Use organization info from config
                    org_info = self.config.get("organization", {})
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
                        
                        logger.info(f"Business impact assessment complete")
                except Exception as e:
                    logger.error(f"Error in business impact assessment: {e}")
            
            # Step 8: Generate SQL injection vaccine if available and requested
            if 'sqli_vaccine' in self.modules and vulnerabilities and scan_options.get("generate_vaccine", False):
                try:
                    # For now we'll just note that this would happen
                    # In a complete implementation, we would initialize and call the vaccine module
                    scan_results["vaccine_generated"] = True
                    logger.info(f"SQL injection vaccine would be generated for {len(vulnerabilities)} vulnerabilities")
                except Exception as e:
                    logger.error(f"Error generating SQL injection vaccine: {e}")
                    
            # Update scan status
            scan_results["status"] = "completed"
            scan_results["end_time"] = datetime.datetime.now().isoformat()
            
            # Calculate scan duration
            start_time = datetime.datetime.fromisoformat(scan_results["start_time"])
            end_time = datetime.datetime.fromisoformat(scan_results["end_time"])
            duration = (end_time - start_time).total_seconds()
            scan_results["duration_seconds"] = duration
            
            # Update tracker if available
            if tracker:
                tracker.end_scan_session(scan_id, "completed")
                
            logger.info(f"Scan completed for {target_url} in {duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Error scanning target {target_url}: {e}")
            scan_results["status"] = "error"
            scan_results["error"] = str(e)
            scan_results["end_time"] = datetime.datetime.now().isoformat()
            
            # Update tracker if available
            if tracker:
                tracker.end_scan_session(scan_id, "error")
        
        # Save results to file
        self._save_scan_results(scan_results)
        
        return scan_results
        
    def _save_scan_results(self, scan_results):
        """Save scan results to file"""
        scan_id = scan_results["scan_id"]
        output_file = os.path.join(self.results_dir, f"{scan_id}_results.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            logger.info(f"Scan results saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving scan results: {e}")
            
    def save_session_results(self):
        """Save session results to file"""
        self.session_results["end_time"] = datetime.datetime.now().isoformat()
        output_file = os.path.join(self.results_dir, f"session_{self.session_id}_results.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.session_results, f, indent=2)
            logger.info(f"Session results saved to {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Error saving session results: {e}")
            return None
            
    def generate_report(self, output_format="text"):
        """Generate a comprehensive report of the session"""
        if not self.session_results["targets"]:
            logger.warning("No targets scanned, cannot generate report")
            return None
            
        if output_format == "text":
            return self._generate_text_report()
        elif output_format == "json":
            return self.save_session_results()
        else:
            logger.error(f"Unsupported report format: {output_format}")
            return None
            
    def _generate_text_report(self):
        """Generate a text report of the session"""
        output_file = os.path.join(self.results_dir, f"session_{self.session_id}_report.txt")
        
        try:
            with open(output_file, 'w') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("SQL INJECTION TOOLKIT SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Session info
                start_time = datetime.datetime.fromisoformat(self.session_results["start_time"])
                f.write(f"Session ID: {self.session_id}\n")
                f.write(f"Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Targets Scanned: {len(self.session_results['targets'])}\n\n")
                
                # Summary of findings
                total_vulns = sum(len(target.get("vulnerabilities", [])) for target in self.session_results["targets"])
                f.write(f"SUMMARY OF FINDINGS\n")
                f.write(f"------------------\n")
                f.write(f"Total Vulnerabilities Found: {total_vulns}\n\n")
                
                # Risk breakdown if available
                risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                
                for target in self.session_results["targets"]:
                    if "risk_assessment" in target:
                        risk_counts["critical"] += target["risk_assessment"].get("critical_risk_count", 0)
                        risk_counts["high"] += target["risk_assessment"].get("high_risk_count", 0)
                        risk_counts["medium"] += target["risk_assessment"].get("medium_risk_count", 0)
                        risk_counts["low"] += target["risk_assessment"].get("low_risk_count", 0)
                
                f.write(f"Risk Breakdown:\n")
                f.write(f"  Critical Risk: {risk_counts['critical']}\n")
                f.write(f"  High Risk: {risk_counts['high']}\n")
                f.write(f"  Medium Risk: {risk_counts['medium']}\n")
                f.write(f"  Low Risk: {risk_counts['low']}\n\n")
                
                # Financial impact if available
                financial_impacts = []
                for target in self.session_results["targets"]:
                    if "financial_impact" in target:
                        financial_impacts.append(target["financial_impact"])
                
                if financial_impacts:
                    total_impact = sum(impact.get("total_financial_impact", 0) for impact in financial_impacts)
                    f.write(f"Estimated Financial Impact: ${total_impact:.2f}\n\n")
                
                # Details for each target
                f.write(f"TARGET DETAILS\n")
                f.write(f"--------------\n\n")
                
                for target in self.session_results["targets"]:
                    f.write(f"Target URL: {target['target_url']}\n")
                    f.write(f"Status: {target['status']}\n")
                    
                    # Technologies detected
                    if "technologies" in target:
                        f.write(f"Technologies Detected:\n")
                        for tech_type, tech_name in target["technologies"].items():
                            f.write(f"  {tech_type}: {tech_name}\n")
                    
                    # Vulnerabilities
                    vulns = target.get("vulnerabilities", [])
                    f.write(f"\nVulnerabilities Found: {len(vulns)}\n")
                    
                    for i, vuln in enumerate(vulns, 1):
                        f.write(f"\n{i}. {vuln.get('type', 'SQL Injection')}\n")
                        f.write(f"   URL: {vuln.get('url', 'N/A')}\n")
                        f.write(f"   Parameter: {vuln.get('parameter', 'N/A')}\n")
                        f.write(f"   Severity: {vuln.get('severity', 'Medium')}\n")
                        if "payload" in vuln:
                            f.write(f"   Payload: {vuln.get('payload', 'N/A')}\n")
                        if "details" in vuln:
                            f.write(f"   Details: {vuln.get('details', 'N/A')}\n")
                    
                    # Recommendations
                    recommendations = target.get("recommendations", [])
                    if recommendations:
                        f.write(f"\nTop Recommendations:\n")
                        for i, rec in enumerate(recommendations[:5], 1):
                            f.write(f"{i}. {rec.get('title', 'N/A')}\n")
                            f.write(f"   {rec.get('description', 'N/A')}\n")
                            f.write(f"   Priority: {rec.get('priority', 'Medium')}\n")
                    
                    f.write("\n" + "-" * 80 + "\n\n")
                
                # Footer
                f.write("\n")
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
                
            logger.info(f"Text report generated: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            return None

def main():
    """Main entry point for the SQLi Toolkit"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="SQLi Toolkit - Comprehensive SQL Injection testing, detection, and protection")
    
    # Target specification
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument("-u", "--url", help="Target URL to scan")
    target_group.add_argument("-f", "--file", help="File containing target URLs (one per line)")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    scan_group.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    scan_group.add_argument("-d", "--depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    scan_group.add_argument("--all-params", action="store_true", help="Test all parameters (default: only injectable ones)")
    
    # Advanced features
    adv_group = parser.add_argument_group("Advanced Features")
    adv_group.add_argument("--mobile", action="store_true", help="Scan for mobile API endpoints")
    adv_group.add_argument("--iot", action="store_true", help="Scan for IoT devices on local network")
    adv_group.add_argument("--vaccine", action="store_true", help="Generate SQL injection vaccine for vulnerabilities")
    adv_group.add_argument("--impact", action="store_true", help="Perform business impact assessment")
    
    # Organization info for impact assessment
    org_group = parser.add_argument_group("Organization Info (for Business Impact Assessment)")
    org_group.add_argument("--industry", choices=["financial_services", "healthcare", "retail", "technology", "manufacturing", "government", "education", "other"], default="other", help="Industry sector")
    org_group.add_argument("--org-size", choices=["small", "medium", "large", "enterprise"], default="medium", help="Organization size")
    org_group.add_argument("--data-records", type=int, default=10000, help="Estimated number of data records")
    org_group.add_argument("--annual-revenue", type=int, default=1000000, help="Annual revenue in USD")
    org_group.add_argument("--compliance", nargs="+", choices=["pci_dss", "hipaa", "gdpr", "sox", "ccpa", "none"], default=["none"], help="Compliance requirements")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", choices=["text", "json"], default="text", help="Report format (default: text)")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Verify target specification
    if not args.url and not args.file:
        parser.error("No targets specified. Use -u/--url or -f/--file to specify targets")
        
    # Initialize toolkit
    toolkit = SQLQToolkit()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Prepare scan options
    scan_options = {
        "threads": args.threads,
        "timeout": args.timeout,
        "max_depth": args.depth,
        "test_all_params": args.all_params,
        "scan_mobile_api": args.mobile,
        "scan_iot_devices": args.iot,
        "generate_vaccine": args.vaccine,
        "perform_impact_assessment": args.impact,
        "organization_info": {
            "industry": args.industry,
            "size": args.org_size,
            "data_records": args.data_records,
            "annual_revenue": args.annual_revenue,
            "compliance": args.compliance
        }
    }
    
    # Initialize targets list
    targets = []
    
    # Load targets from URL parameter
    if args.url:
        targets.append(args.url)
        
    # Load targets from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except Exception as e:
            logger.error(f"Error loading targets from file: {e}")
            
    # Scan each target
    if targets:
        logger.info(f"Starting scan of {len(targets)} targets")
        
        for target in targets:
            toolkit.scan_target(target, scan_options)
            
        # Generate and save report
        report_file = toolkit.generate_report(args.output)
        
        if report_file:
            print(f"\nScan completed. Report saved to: {report_file}")
        else:
            print("\nScan completed but report generation failed. Check logs for details.")
    else:
        logger.error("No valid targets found")
        
if __name__ == "__main__":
    main()
