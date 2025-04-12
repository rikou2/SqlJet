#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# SqlJet Ai V1 - AI SQL Injection Analyzer Module
# Copyright (c) 2024-2025 SqlJet Ai developers by R13
#
# This module integrates OpenAI capabilities into SqlJet for enhanced SQL injection detection

import os
import re
import json
import time
import logging
import requests
from requests.exceptions import SSLError
from dotenv import load_dotenv
import openai

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("sqljet_ai")

class AiInjectionAnalyzer:
    """
    AI-powered SQL injection vulnerability analyzer using OpenAI API.
    """
    
    def __init__(self, api_key=None, model="gpt-4", temperature=0.1, verify_ssl=True):
        """
        Initialize the AI analyzer with OpenAI API credentials.
        
        Args:
            api_key (str, optional): OpenAI API key. If not provided, will look for OPENAI_API_KEY env variable.
            model (str, optional): OpenAI model to use. Defaults to "gpt-4".
            temperature (float, optional): Model temperature. Lower values for more deterministic outputs.
        """
        # Load environment variables from .env file if it exists
        load_dotenv()
        
        # Use provided API key or get from environment
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY environment variable or pass api_key parameter.")
        
        self.model = model
        self.temperature = temperature
        self.verify_ssl = verify_ssl
        # Set the API key directly in the openai module instead of using client object
        openai.api_key = self.api_key
        # Set SSL verification
        openai.verify_ssl_certs = verify_ssl
        logger.info(f"AI Analyzer initialized with model: {model}, SSL verification: {verify_ssl}")
        
        # Store analysis results for continuous learning
        self.analysis_history = []
    
    def analyze_url_parameters(self, url, parameters):
        """
        Analyze URL and parameters to determine SQL injection vulnerability likelihood.
        
        Args:
            url (str): The URL to analyze
            parameters (dict): Dictionary of parameter names and values
            
        Returns:
            dict: Analysis results with vulnerability score and recommendations
        """
        try:
            # Make a safe request to test if the URL is accessible
            try:
                requests.get(url, verify=self.verify_ssl, timeout=10)
            except SSLError as ssl_err:
                if self.verify_ssl:
                    logger.warning(f"SSL certificate verification failed for {url}: {ssl_err}")
                    logger.warning("Consider using the --disable-ssl-verify option if this is expected")
                    return {
                        "error": f"SSL certificate verification failed: {ssl_err}",
                        "vulnerable_params": {},
                        "vulnerability_indicators": [],
                        "recommended_payloads": [],
                        "waf_evasion_techniques": []
                    }
            except requests.exceptions.RequestException as req_err:
                logger.warning(f"Request error when accessing URL: {req_err}")
                # Continue with analysis despite connection issues
            prompt = f"""
            As a specialized SQL injection vulnerability analyzer, assess this URL and its parameters:
            
            URL: {url}
            Parameters: {json.dumps(parameters, indent=2)}
            
            Answer the following questions:
            1. Which parameters, if any, are likely vulnerable to SQL injection? Rate each from 0-10.
            2. What specific characteristics suggest vulnerability?
            3. Recommend 3 precise SQL injection payloads to test, tailored to these parameters.
            4. What WAF evasion techniques would be most effective?
            
            Structure your response as valid JSON with these keys: 
            - vulnerable_params (object with parameter names as keys and scores as values)
            - vulnerability_indicators (array of strings)
            - recommended_payloads (array of strings)
            - waf_evasion_techniques (array of strings)
            """
            
            response = self._make_openai_request(prompt, "sql_injection_url_analyzer")
            
            # Parse the JSON response
            try:
                # Extract JSON from response (it might be wrapped in markdown code blocks)
                json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    json_str = response
                
                analysis = json.loads(json_str)
                
                # Add logging about the results
                vulnerable_count = sum(1 for score in analysis.get("vulnerable_params", {}).values() if score > 7)
                logger.info(f"AI analysis found {vulnerable_count} likely vulnerable parameters in {url}")
                
                return analysis
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI response as JSON: {e}")
                return {
                    "error": "Failed to parse AI response",
                    "raw_response": response,
                    "vulnerable_params": {},
                    "vulnerability_indicators": [],
                    "recommended_payloads": [],
                    "waf_evasion_techniques": []
                }
        
        except Exception as e:
            logger.error(f"Error analyzing URL parameters: {e}")
            return {
                "error": str(e),
                "vulnerable_params": {},
                "vulnerability_indicators": [],
                "recommended_payloads": [],
                "waf_evasion_techniques": []
            }
    
    def analyze_response(self, url, payload, response_body, status_code, headers):
        """
        Analyze a server response to determine if an SQL injection attempt was successful.
        
        Args:
            url (str): The URL that was tested
            payload (str): The SQL injection payload used
            response_body (str): The response body content
            status_code (int): HTTP status code
            headers (dict): Response headers
            
        Returns:
            dict: Analysis of the response indicating success or failure
        """
        try:
            # Truncate response body if too large
            truncated_body = response_body[:3000] + "..." if len(response_body) > 3000 else response_body
            
            prompt = f"""
            As a specialized SQL injection success analyzer, determine if this SQL injection attempt was successful:
            
            URL: {url}
            Payload: {payload}
            Status Code: {status_code}
            Response Headers: {json.dumps(dict(headers), indent=2)}
            Response Body (truncated): {truncated_body}
            
            Analyze the response carefully for signs of:
            1. SQL error messages
            2. Modified data output
            3. Timing differences
            4. Successful authentication bypass
            5. Database content exposure
            
            Structure your response as valid JSON with these keys:
            - success_likelihood (float between 0-1)
            - confidence (float between 0-1)
            - indicators (array of strings explaining why you believe the injection succeeded or failed)
            - next_steps (array of strings with recommended follow-up payloads or techniques)
            """
            
            response = self._make_openai_request(prompt, "sql_injection_response_analyzer")
            
            # Parse the JSON response
            try:
                # Extract JSON from response (it might be wrapped in markdown code blocks)
                json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    json_str = response
                
                analysis = json.loads(json_str)
                
                # Log the results
                success_likelihood = analysis.get("success_likelihood", 0)
                if success_likelihood > 0.7:
                    logger.info(f"AI analysis indicates HIGH likelihood of successful injection: {url}")
                elif success_likelihood > 0.3:
                    logger.info(f"AI analysis indicates MEDIUM likelihood of successful injection: {url}")
                else:
                    logger.info(f"AI analysis indicates LOW likelihood of successful injection: {url}")
                
                return analysis
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI response as JSON: {e}")
                return {
                    "error": "Failed to parse AI response",
                    "raw_response": response,
                    "success_likelihood": 0,
                    "confidence": 0,
                    "indicators": [],
                    "next_steps": []
                }
                
        except Exception as e:
            logger.error(f"Error analyzing response: {e}")
            return {
                "error": str(e),
                "success_likelihood": 0,
                "confidence": 0,
                "indicators": [],
                "next_steps": []
            }
    
    def generate_custom_payloads(self, target_info, db_type=None, waf_detected=False, previous_attempts=None):
        """
        Generate custom SQL injection payloads optimized for the specific target.
        
        Args:
            target_info (dict): Information about the target
            db_type (str, optional): Database type if known (mysql, mssql, oracle, etc.)
            waf_detected (bool): Whether a WAF has been detected
            previous_attempts (list, optional): List of previously attempted payloads
            
        Returns:
            list: List of custom-generated payloads
        """
        try:
            previous = previous_attempts or []
            prev_attempts_str = "\n".join([f"- {p}" for p in previous[:5]])
            
            prompt = f"""
            As an SQL injection payload generator, create 5 highly optimized SQL injection payloads for this target:
            
            Target URL: {target_info.get('url', 'Unknown')}
            Parameter: {target_info.get('parameter', 'Unknown')}
            Database Type: {db_type or 'Unknown'}
            WAF Detected: {"Yes" if waf_detected else "No"}
            
            Previous attempted payloads:
            {prev_attempts_str}
            
            For each payload:
            1. Generate a payload that is likely to bypass security controls
            2. Explain how it works
            3. Rate its evasion potential from 1-10
            
            Create diverse payloads including: boolean-based, time-based, error-based, and UNION-based techniques.
            
            Format your response as valid JSON with this structure:
            ```json
            {{
              "payloads": [
                {{
                  "payload": "payload string here",
                  "explanation": "how this works",
                  "evasion_score": 7,
                  "technique": "boolean|time|error|union"
                }}
              ]
            }}
            ```
            """
            
            response = self._make_openai_request(prompt, "sql_injection_payload_generator")
            
            # Parse the JSON response
            try:
                # Extract JSON from response (it might be wrapped in markdown code blocks)
                json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    json_str = response
                
                payload_data = json.loads(json_str)
                payloads = [item["payload"] for item in payload_data.get("payloads", [])]
                
                logger.info(f"Generated {len(payloads)} custom SQL injection payloads")
                return payloads
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI response as JSON: {e}")
                return []
                
        except Exception as e:
            logger.error(f"Error generating custom payloads: {e}")
            return []
    
    def analyze_attack_vectors(self, target_url, discovered_endpoints):
        """
        Analyze discovered endpoints to prioritize SQL injection testing.
        
        Args:
            target_url (str): The base target URL
            discovered_endpoints (list): List of discovered endpoints
            
        Returns:
            dict: Prioritized attack vectors with recommendations
        """
        try:
            # Make a safe request to test if the target is accessible
            try:
                requests.get(target_url, verify=self.verify_ssl, timeout=10)
            except SSLError as ssl_err:
                if self.verify_ssl:
                    logger.warning(f"SSL certificate verification failed for {target_url}: {ssl_err}")
                    logger.warning("Consider using the --disable-ssl-verify option if this is expected")
                    return {
                        "error": f"SSL certificate verification failed: {ssl_err}",
                        "prioritized_endpoints": [],
                        "patterns_identified": [],
                        "overall_recommendation": "Use --disable-ssl-verify option to bypass SSL verification"
                    }
            except requests.exceptions.RequestException as req_err:
                logger.warning(f"Request error when testing target: {req_err}")
                # Continue with analysis despite connection issues
            endpoints_str = "\n".join([f"- {e}" for e in discovered_endpoints[:30]])
            
            prompt = f"""
            As an SQL injection attack vector analyzer, examine these discovered endpoints and prioritize them for testing:
            
            Base Target: {target_url}
            
            Discovered Endpoints:
            {endpoints_str}
            
            {"..." if len(discovered_endpoints) > 30 else ""}
            
            Analyze these endpoints and:
            1. Rank them by SQL injection vulnerability likelihood (high to low)
            2. Identify patterns suggesting database interaction
            3. Recommend specific parameters to target
            4. Suggest testing strategies for each high-priority endpoint
            
            Format your response as valid JSON with this structure:
            {{
              "prioritized_endpoints": [
                {{
                  "endpoint": "string",
                  "priority": "high|medium|low",
                  "reasoning": "string",
                  "target_parameters": ["param1", "param2"],
                  "testing_strategy": "string"
                }}
              ],
              "patterns_identified": ["pattern1", "pattern2"],
              "overall_recommendation": "string"
            }}
            """
            
            response = self._make_openai_request(prompt, "sql_injection_vector_analyzer")
            
            # Parse the JSON response
            try:
                # Extract JSON from response (it might be wrapped in markdown code blocks)
                json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    json_str = response
                
                analysis = json.loads(json_str)
                
                # Log the results
                high_priority = sum(1 for ep in analysis.get("prioritized_endpoints", []) if ep.get("priority") == "high")
                logger.info(f"AI analysis prioritized {high_priority} high-priority endpoints out of {len(discovered_endpoints)}")
                
                return analysis
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI response as JSON: {e}")
                return {
                    "error": "Failed to parse AI response",
                    "raw_response": response,
                    "prioritized_endpoints": [],
                    "patterns_identified": [],
                    "overall_recommendation": "Error in analysis"
                }
                
        except Exception as e:
            logger.error(f"Error analyzing attack vectors: {e}")
            return {
                "error": str(e),
                "prioritized_endpoints": [],
                "patterns_identified": [],
                "overall_recommendation": "Error in analysis"
            }
    
    def _make_openai_request(self, prompt, system_role):
        """
        Make a request to the OpenAI API with appropriate error handling and retries.
        
        Args:
            prompt (str): The user prompt to send
            system_role (str): The system role identifier
            
        Returns:
            str: The response content
        """
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                response = openai.ChatCompletion.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": f"You are a specialized security AI assistant focused on {system_role}."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.temperature
                )
                return response.choices[0].message.content
                
            except openai.RateLimitError:
                if attempt < max_retries - 1:
                    logger.warning(f"Rate limit exceeded. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error("Rate limit exceeded and max retries reached.")
                    raise
                    
            except openai.APIError as e:
                logger.error(f"OpenAI API error: {e}")
                if attempt < max_retries - 1 and hasattr(e, 'status_code') and (500 <= e.status_code < 600):
                    logger.warning(f"API server error. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    raise
                    
            except Exception as e:
                logger.error(f"Error making OpenAI request: {e}")
                raise

# Example usage
if __name__ == "__main__":
    try:
        analyzer = AiInjectionAnalyzer()
        
        # Example analysis
        url = "https://example.com/search.php"
        params = {"q": "test", "id": "123", "page": "1"}
        
        print("Analyzing URL parameters...")
        result = analyzer.analyze_url_parameters(url, params)
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error: {e}")
