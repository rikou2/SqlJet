#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# SqlJet Ai V1 - AI Integration Module
# Copyright (c) 2024-2025 SqlJet Ai developers by R13
#
# This module integrates the AI analyzer with the main SqlJet tool

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# Import utility functions for colorized output
try:
    from integrated_scan import success, warning, info, error
except ImportError:
    # Fallback functions if the import fails
    def success(msg): print(f"[+] {msg}")
    def warning(msg): print(f"[!] {msg}")
    def info(msg): print(f"[*] {msg}")
    def error(msg): print(f"[ERROR] {msg}")

# Import the AI analyzer
from ai_analyzer import AiInjectionAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("sqljet_ai_integration")

class SqlJetAiIntegration:
    """
    Integrates AI capabilities into the SqlJet scanning workflow.
    """
    
    def __init__(self, api_key=None, model="gpt-4", output_dir=None, verify_ssl=True):
        """
        Initialize the AI integration module.
        
        Args:
            api_key (str, optional): OpenAI API key. If not provided, will use environment variable.
            model (str, optional): OpenAI model to use. Default is "gpt-4".
            output_dir (str, optional): Directory to save AI analysis results.
        """
        # Initialize the AI analyzer
        try:
            self.ai_analyzer = AiInjectionAnalyzer(api_key=api_key, model=model, verify_ssl=verify_ssl)
            self.ai_enabled = True
            logger.info("AI integration successfully initialized")
        except Exception as e:
            logger.error(f"Failed to initialize AI integration: {e}")
            self.ai_enabled = False
        
        # Set up output directory for AI analysis results
        self.output_dir = output_dir
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def analyze_target(self, target_url):
        """
        Perform initial AI analysis of the target URL to determine scanning approach.
        
        Args:
            target_url (str): The target URL to analyze
            
        Returns:
            dict: Analysis results and recommendations
        """
        if not self.ai_enabled:
            logger.warning("AI analysis skipped: AI integration not enabled")
            return {"error": "AI integration not enabled"}
        
        try:
            # Parse URL to extract parameters
            parsed_url = urlparse(target_url)
            parameters = parse_qs(parsed_url.query)
            
            # Flatten parameters (parse_qs returns lists for each parameter)
            flat_params = {k: v[0] if len(v) == 1 else v for k, v in parameters.items()}
            
            # Perform AI analysis
            logger.info(f"Performing AI analysis of target URL: {target_url}")
            analysis = self.ai_analyzer.analyze_url_parameters(target_url, flat_params)
            
            # Save analysis results if output directory is specified
            if self.output_dir:
                self._save_analysis_results(
                    target_url, 
                    "target_analysis", 
                    analysis
                )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing target URL: {e}")
            return {"error": str(e)}
    
    def prioritize_endpoints(self, target_url, discovered_endpoints):
        """
        Use AI to prioritize discovered endpoints for SQL injection testing.
        
        Args:
            target_url (str): The base target URL
            discovered_endpoints (list): List of discovered endpoints
            
        Returns:
            list: Prioritized list of endpoints to test
        """
        if not self.ai_enabled:
            logger.warning("Endpoint prioritization skipped: AI integration not enabled")
            return discovered_endpoints
        
        try:
            # Perform AI analysis of attack vectors
            logger.info(f"Using AI to prioritize {len(discovered_endpoints)} discovered endpoints")
            analysis = self.ai_analyzer.analyze_attack_vectors(target_url, discovered_endpoints)
            
            # Extract prioritized endpoints
            prioritized = analysis.get("prioritized_endpoints", [])
            
            # Save analysis results if output directory is specified
            if self.output_dir:
                self._save_analysis_results(
                    target_url, 
                    "endpoint_prioritization", 
                    analysis
                )
            
            # Return prioritized endpoints in order
            return [ep["endpoint"] for ep in prioritized]
            
        except Exception as e:
            logger.error(f"Error prioritizing endpoints: {e}")
            return discovered_endpoints  # Fall back to original order
    
    def generate_custom_payloads(self, target_url, parameter, db_type=None, waf_detected=False):
        """
        Generate custom SQL injection payloads optimized for the specific target.
        
        Args:
            target_url (str): The target URL
            parameter (str): The parameter to inject into
            db_type (str, optional): Database type if known
            waf_detected (bool): Whether a WAF has been detected
            
        Returns:
            list: List of custom SQL injection payloads
        """
        if not self.ai_enabled:
            logger.warning("Custom payload generation skipped: AI integration not enabled")
            return []
        
        try:
            # Create target info dictionary
            target_info = {
                "url": target_url,
                "parameter": parameter
            }
            
            # Generate custom payloads
            logger.info(f"Generating AI-optimized payloads for {target_url} parameter '{parameter}'")
            payloads = self.ai_analyzer.generate_custom_payloads(
                target_info,
                db_type=db_type,
                waf_detected=waf_detected
            )
            
            # Save generated payloads if output directory is specified
            if self.output_dir:
                self._save_analysis_results(
                    target_url,
                    f"custom_payloads_{parameter}",
                    {"payloads": payloads}
                )
            
            return payloads
            
        except Exception as e:
            logger.error(f"Error generating custom payloads: {e}")
            return []
    
    def analyze_injection_response(self, target_url, payload, response_body, status_code, headers):
        """
        Analyze a server response to determine if an SQL injection attempt was successful.
        
        Args:
            target_url (str): The URL that was tested
            payload (str): The SQL injection payload used
            response_body (str): The response body content
            status_code (int): HTTP status code
            headers (dict): Response headers
            
        Returns:
            dict: Analysis of the response indicating success or failure
        """
        if not self.ai_enabled:
            logger.warning("Response analysis skipped: AI integration not enabled")
            return {"success_likelihood": 0, "confidence": 0}
        
        try:
            # Analyze the response
            logger.info(f"Analyzing response from {target_url} for SQL injection success")
            analysis = self.ai_analyzer.analyze_response(
                target_url,
                payload,
                response_body,
                status_code,
                headers
            )
            
            # Save analysis results if output directory is specified
            if self.output_dir:
                self._save_analysis_results(
                    target_url,
                    "response_analysis",
                    analysis
                )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing injection response: {e}")
            return {"success_likelihood": 0, "confidence": 0, "error": str(e)}
    
    def _save_analysis_results(self, target_url, analysis_type, results):
        """
        Save AI analysis results to a file.
        
        Args:
            target_url (str): The target URL
            analysis_type (str): Type of analysis performed
            results (dict): Analysis results to save
        """
        try:
            # Format timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create a sanitized filename
            parsed_url = urlparse(target_url)
            host = parsed_url.netloc.replace(":", "_")
            
            # Create filename
            filename = f"ai_{analysis_type}_{host}_{timestamp}.json"
            filepath = os.path.join(self.output_dir, filename)
            
            # Save results to file
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
                
            logger.info(f"Saved AI analysis results to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving analysis results: {e}")

# Function to securely store API key
def store_api_key(api_key):
    """
    Securely store OpenAI API key in a configuration file.
    
    Args:
        api_key (str): The OpenAI API key to store
    """
    try:
        # Create config directory if it doesn't exist
        config_dir = os.path.expanduser("~/.sqljet")
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        
        # Create config file
        config_file = os.path.join(config_dir, "config.json")
        
        # Read existing config if it exists
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
            except:
                config = {}
        else:
            config = {}
        
        # Update config with API key
        config["openai_api_key"] = api_key
        
        # Write config to file
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Set appropriate permissions
        os.chmod(config_file, 0o600)  # Only owner can read/write
        
        logger.info(f"API key securely stored in {config_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error storing API key: {e}")
        return False

# Function to load API key
def load_api_key():
    """
    Load OpenAI API key from environment variable or configuration file.
    
    Returns:
        str: The OpenAI API key, or None if not found
    """
    # First check environment variable
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        return api_key
    
    # Then check configuration file
    try:
        config_file = os.path.expanduser("~/.sqljet/config.json")
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                return config.get("openai_api_key")
    except Exception as e:
        logger.error(f"Error loading API key from config file: {e}")
    
    return None

# Command-line handler for testing the AI integration
def main():
    parser = argparse.ArgumentParser(description="SqlJet AI Integration Test Utility")
    parser.add_argument("-u", "--url", help="Target URL to analyze")
    parser.add_argument("-k", "--api-key", help="OpenAI API key")
    parser.add_argument("-s", "--store-key", action="store_true", help="Store API key for future use")
    parser.add_argument("-m", "--model", default="gpt-4", help="OpenAI model to use")
    parser.add_argument("-o", "--output-dir", help="Directory to save AI analysis results")
    parser.add_argument("--disable-ssl-verify", action="store_true", help="Disable SSL certificate verification for targets with invalid certificates")
    
    args = parser.parse_args()
    
    # Store API key if requested
    if args.store_key and args.api_key:
        if store_api_key(args.api_key):
            print("API key stored successfully")
        else:
            print("Failed to store API key")
    
    # Load API key if not provided
    api_key = args.api_key or load_api_key()
    if not api_key:
        print("Error: OpenAI API key not provided. Use --api-key or set OPENAI_API_KEY environment variable")
        return 1
    
    # Initialize AI integration
    ai_integration = SqlJetAiIntegration(
        api_key=api_key,
        model=args.model,
        output_dir=args.output_dir,
        verify_ssl=not args.disable_ssl_verify
    )
    
    # Test target analysis if URL is provided
    if args.url:
        print(f"Analyzing target URL: {args.url}")
        analysis = ai_integration.analyze_target(args.url)
        print(json.dumps(analysis, indent=2))
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
