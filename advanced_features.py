#!/usr/bin/env python3
# Advanced Features for SQL Injection Toolkit
# Integrates AI, ML, Cloud, IoT, and other advanced capabilities

import os
import sys
import json
import logging
import importlib.util
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('advanced_features.log')
    ]
)
logger = logging.getLogger('sqli_advanced')

class AdvancedFeatures:
    """
    Main controller for advanced SQL injection features
    """
    def __init__(self, base_dir=None):
        """Initialize the advanced features manager"""
        self.base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
        self.config_dir = os.path.join(self.base_dir, 'config')
        self.data_dir = os.path.join(self.base_dir, 'data')
        self.models_dir = os.path.join(self.base_dir, 'models')
        
        # Create necessary directories
        for directory in [self.config_dir, self.data_dir, self.models_dir]:
            os.makedirs(directory, exist_ok=True)
            
        # Initialize configuration
        self.config = self._load_config()
        
        # Initialize feature modules
        self.modules = {}
        self._load_modules()
        
        logger.info("Advanced Features initialized")
        
    def _load_config(self):
        """Load configuration from file or create default"""
        config_file = os.path.join(self.config_dir, 'advanced_config.json')
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    logger.info(f"Configuration loaded from {config_file}")
                    return config
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                
        # Default configuration
        config = {
            'features': {
                'ml_detection': {
                    'enabled': True,
                    'model_path': os.path.join(self.models_dir, 'ml_model.pkl'),
                    'training_data': os.path.join(self.data_dir, 'ml_training_data.json'),
                    'threshold': 0.75
                },
                'cloud_platform': {
                    'enabled': False,
                    'api_endpoint': 'https://api.example.com/sqli-cloud',
                    'api_key': '',
                    'share_anonymous_data': True
                },
                'browser_extension': {
                    'enabled': False,
                    'port': 8765,
                    'allow_remote': False
                },
                'ai_analysis': {
                    'enabled': True,
                    'model': 'local',  # or 'openai', 'huggingface', etc.
                    'api_key': '',
                    'max_tokens': 1000
                },
                'iot_mobile': {
                    'enabled': True,
                    'scan_api_endpoints': True,
                    'scan_mobile_apps': True,
                    'scan_iot_devices': True
                },
                'business_impact': {
                    'enabled': True,
                    'data_classification': {
                        'pii': 'high',
                        'financial': 'high',
                        'health': 'high',
                        'credentials': 'critical'
                    }
                },
                'zero_day': {
                    'enabled': True,
                    'fuzz_depth': 'medium',  # low, medium, high
                    'timeout': 30
                },
                'sql_vaccine': {
                    'enabled': False,
                    'auto_patch': False,
                    'patch_templates': os.path.join(self.data_dir, 'vaccine_templates')
                }
            },
            'version': '1.0.0',
            'last_updated': datetime.now().isoformat()
        }
        
        # Save default configuration
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
                logger.info(f"Default configuration created at {config_file}")
        except Exception as e:
            logger.error(f"Error saving default configuration: {e}")
            
        return config
        
    def _load_modules(self):
        """Load all enabled feature modules"""
        try:
            # Machine Learning Detection
            if self.config['features']['ml_detection']['enabled']:
                spec = importlib.util.spec_from_file_location(
                    "ml_detection", 
                    os.path.join(self.base_dir, "ml_detection.py")
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.modules['ml_detection'] = module.MLDetection(self.config['features']['ml_detection'])
                    logger.info("Machine Learning Detection module loaded")
                else:
                    logger.warning("ML Detection module not found")
                    
            # Collaborative Cloud Platform
            if self.config['features']['cloud_platform']['enabled']:
                spec = importlib.util.spec_from_file_location(
                    "cloud_platform", 
                    os.path.join(self.base_dir, "cloud_platform.py")
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.modules['cloud_platform'] = module.CloudPlatform(self.config['features']['cloud_platform'])
                    logger.info("Cloud Platform module loaded")
                else:
                    logger.warning("Cloud Platform module not found")
                    
            # Similar imports for other modules...
            # For brevity, I'm not repeating the same pattern for all modules
            
            # Load remaining modules dynamically
            for module_name in ['browser_extension', 'ai_analysis', 'iot_mobile', 
                             'business_impact', 'zero_day', 'sql_vaccine']:
                if self.config['features'][module_name]['enabled']:
                    try:
                        spec = importlib.util.spec_from_file_location(
                            module_name, 
                            os.path.join(self.base_dir, f"{module_name}.py")
                        )
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            # Get the class name by converting snake_case to CamelCase
                            class_name = ''.join(word.title() for word in module_name.split('_'))
                            module_class = getattr(module, class_name)
                            self.modules[module_name] = module_class(self.config['features'][module_name])
                            logger.info(f"{class_name} module loaded")
                        else:
                            logger.warning(f"{module_name} module not found")
                    except Exception as e:
                        logger.error(f"Error loading {module_name}: {e}")
                        
        except Exception as e:
            logger.error(f"Error loading modules: {e}")
            
    def get_module(self, module_name):
        """Get a specific module by name"""
        return self.modules.get(module_name)
    
    def save_config(self):
        """Save current configuration to file"""
        config_file = os.path.join(self.config_dir, 'advanced_config.json')
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
                logger.info(f"Configuration saved to {config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
            
    def update_feature_config(self, feature_name, config_updates):
        """Update configuration for a specific feature"""
        if feature_name in self.config['features']:
            for key, value in config_updates.items():
                if key in self.config['features'][feature_name]:
                    self.config['features'][feature_name][key] = value
            self.config['last_updated'] = datetime.now().isoformat()
            return self.save_config()
        return False

    def enable_feature(self, feature_name, enable=True):
        """Enable or disable a feature"""
        if feature_name in self.config['features']:
            self.config['features'][feature_name]['enabled'] = enable
            self.config['last_updated'] = datetime.now().isoformat()
            result = self.save_config()
            
            # If enabling, try to load the module
            if enable and result:
                self._load_modules()
            # If disabling, remove from loaded modules
            elif not enable and feature_name in self.modules:
                del self.modules[feature_name]
                
            return result
        return False
        
# Create a singleton instance
_instance = None

def get_instance(base_dir=None):
    """Get or create the AdvancedFeatures singleton"""
    global _instance
    if _instance is None:
        _instance = AdvancedFeatures(base_dir)
    return _instance

if __name__ == "__main__":
    # Simple test/demo
    manager = get_instance()
    print("Advanced SQL Injection Features:")
    for feature, config in manager.config['features'].items():
        status = "ENABLED" if config['enabled'] else "DISABLED"
        print(f"- {feature.replace('_', ' ').title()}: {status}")
