#!/usr/bin/env python3
# Browser Extension Integration Module
# Creates a websocket server to interact with browser extensions for real-time testing

import os
import sys
import json
import logging
import asyncio
import websockets
import threading
import webbrowser
import http.server
import socketserver
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('browser_extension')

class BrowserExtension:
    """
    Browser extension integration for real-time SQL injection testing
    """
    def __init__(self, config, payload_generator=None, detector=None):
        """Initialize browser extension with configuration"""
        self.config = config
        self.port = config.get('port', 8765)
        self.allow_remote = config.get('allow_remote', False)
        self.static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'browser_extension')
        self.debug_mode = config.get('debug_mode', False)
        
        # Reference to other modules
        self.payload_generator = payload_generator
        self.detector = detector
        
        # Store connected clients
        self.clients = set()
        
        # Create static directory if it doesn't exist
        os.makedirs(self.static_dir, exist_ok=True)
        
        # Create extension files if they don't exist
        self._create_extension_files()
        
        # Initialize the server
        self.server = None
        self.server_thread = None
        self.websocket_server = None
        self.websocket_thread = None
        
        logger.info("Browser Extension module initialized")
        
    def _create_extension_files(self):
        """Create extension files if they don't exist"""
        # Create manifest.json
        manifest_path = os.path.join(self.static_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            manifest = {
                "manifest_version": 3,
                "name": "SQLi Scanner Extension",
                "version": "1.0",
                "description": "Helps identify and test SQL injection vulnerabilities",
                "permissions": ["activeTab", "storage", "tabs", "webRequest"],
                "host_permissions": ["<all_urls>"],
                "action": {
                    "default_popup": "popup.html",
                    "default_icon": {
                        "16": "icons/icon16.png",
                        "48": "icons/icon48.png",
                        "128": "icons/icon128.png"
                    }
                },
                "icons": {
                    "16": "icons/icon16.png",
                    "48": "icons/icon48.png",
                    "128": "icons/icon128.png"
                },
                "background": {
                    "service_worker": "background.js"
                },
                "content_scripts": [
                    {
                        "matches": ["<all_urls>"],
                        "js": ["content.js"]
                    }
                ]
            }
            
            os.makedirs(os.path.join(self.static_dir, "icons"), exist_ok=True)
            
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
                
        # Create popup.html
        popup_path = os.path.join(self.static_dir, "popup.html")
        if not os.path.exists(popup_path):
            popup_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SQLi Scanner</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      width: 320px;
      margin: 0;
      padding: 10px;
    }
    
    h1 {
      font-size: 18px;
      color: #333;
      margin-bottom: 15px;
    }
    
    .controls {
      margin-bottom: 15px;
    }
    
    button {
      background-color: #4CAF50;
      color: white;
      border: none;
      padding: 8px 16px;
      text-align: center;
      text-decoration: none;
      display: inline-block;
      font-size: 14px;
      margin: 4px 2px;
      cursor: pointer;
      border-radius: 4px;
    }
    
    button:disabled {
      background-color: #cccccc;
      color: #666666;
      cursor: not-allowed;
    }
    
    button.danger {
      background-color: #f44336;
    }
    
    .results {
      max-height: 300px;
      overflow-y: auto;
      border: 1px solid #ddd;
      padding: 10px;
      margin-top: 10px;
    }
    
    .form-param {
      border-bottom: 1px solid #eee;
      padding: 5px 0;
    }
    
    .vulnerable {
      color: #f44336;
      font-weight: bold;
    }
    
    .status {
      color: #555;
      font-size: 12px;
      font-style: italic;
    }
  </style>
</head>
<body>
  <h1>SQLi Scanner</h1>
  
  <div class="controls">
    <button id="scanPage">Scan Current Page</button>
    <button id="scanForms">Scan Forms</button>
    <button id="clearResults">Clear Results</button>
  </div>
  
  <div class="status" id="status">Ready to scan</div>
  
  <div class="results" id="results">
    <p>No results yet. Click "Scan" to begin.</p>
  </div>
  
  <script src="popup.js"></script>
</body>
</html>
"""
            with open(popup_path, 'w') as f:
                f.write(popup_html)
                
        # Create popup.js
        popup_js_path = os.path.join(self.static_dir, "popup.js")
        if not os.path.exists(popup_js_path):
            popup_js = """document.addEventListener('DOMContentLoaded', function() {
  const scanPageButton = document.getElementById('scanPage');
  const scanFormsButton = document.getElementById('scanForms');
  const clearResultsButton = document.getElementById('clearResults');
  const statusElement = document.getElementById('status');
  const resultsElement = document.getElementById('results');
  
  // Connect to the WebSocket server
  let socket;
  let isConnected = false;
  
  function connectWebSocket() {
    socket = new WebSocket('ws://localhost:8765');
    
    socket.onopen = function(e) {
      isConnected = true;
      statusElement.textContent = 'Connected to SQLi Scanner';
      scanPageButton.disabled = false;
      scanFormsButton.disabled = false;
    };
    
    socket.onmessage = function(event) {
      const data = JSON.parse(event.data);
      
      if (data.type === 'scan_result') {
        displayResult(data);
      } else if (data.type === 'status') {
        statusElement.textContent = data.message;
      }
    };
    
    socket.onclose = function(event) {
      isConnected = false;
      statusElement.textContent = 'Disconnected from SQLi Scanner';
      scanPageButton.disabled = true;
      scanFormsButton.disabled = true;
      
      // Try to reconnect after 5 seconds
      setTimeout(connectWebSocket, 5000);
    };
    
    socket.onerror = function(error) {
      isConnected = false;
      statusElement.textContent = 'WebSocket Error';
      scanPageButton.disabled = true;
      scanFormsButton.disabled = true;
    };
  }
  
  function displayResult(data) {
    const resultItem = document.createElement('div');
    resultItem.className = 'result-item';
    
    if (data.vulnerable) {
      resultItem.innerHTML = `<p class="vulnerable">Vulnerable: ${data.url}</p>`;
      resultItem.innerHTML += `<p>Parameter: ${data.param}</p>`;
      resultItem.innerHTML += `<p>Payload: ${data.payload}</p>`;
    } else {
      resultItem.innerHTML = `<p>Tested: ${data.url}</p>`;
      resultItem.innerHTML += `<p>Parameter: ${data.param}</p>`;
      resultItem.innerHTML += `<p>Status: Not vulnerable</p>`;
    }
    
    resultsElement.appendChild(resultItem);
    resultsElement.scrollTop = resultsElement.scrollHeight;
  }
  
  // Initialize connection
  connectWebSocket();
  
  // Set up button handlers
  scanPageButton.addEventListener('click', function() {
    if (!isConnected) {
      statusElement.textContent = 'Not connected to server';
      return;
    }
    
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const activeTab = tabs[0];
      statusElement.textContent = 'Scanning page...';
      
      socket.send(JSON.stringify({
        type: 'scan_request',
        action: 'scan_page',
        url: activeTab.url
      }));
      
      chrome.tabs.sendMessage(activeTab.id, {action: "scan_page"}, function(response) {
        if (response && response.params) {
          socket.send(JSON.stringify({
            type: 'params_found',
            url: activeTab.url,
            params: response.params
          }));
        }
      });
    });
  });
  
  scanFormsButton.addEventListener('click', function() {
    if (!isConnected) {
      statusElement.textContent = 'Not connected to server';
      return;
    }
    
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const activeTab = tabs[0];
      statusElement.textContent = 'Scanning forms...';
      
      socket.send(JSON.stringify({
        type: 'scan_request',
        action: 'scan_forms',
        url: activeTab.url
      }));
      
      chrome.tabs.sendMessage(activeTab.id, {action: "scan_forms"}, function(response) {
        if (response && response.forms) {
          socket.send(JSON.stringify({
            type: 'forms_found',
            url: activeTab.url,
            forms: response.forms
          }));
        }
      });
    });
  });
  
  clearResultsButton.addEventListener('click', function() {
    resultsElement.innerHTML = '<p>Results cleared.</p>';
  });
});
"""
            with open(popup_js_path, 'w') as f:
                f.write(popup_js)
                
        # Create content.js
        content_js_path = os.path.join(self.static_dir, "content.js")
        if not os.path.exists(content_js_path):
            content_js = """// Content script to interact with the current page

// Listen for messages from the popup
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "scan_page") {
    // Find all URL parameters
    const params = findUrlParameters();
    sendResponse({params: params});
  } else if (request.action === "scan_forms") {
    // Find all forms and their inputs
    const forms = findForms();
    sendResponse({forms: forms});
  }
  return true;
});

// Function to find URL parameters in the current page
function findUrlParameters() {
  const url = window.location.href;
  const paramString = url.split('?')[1];
  const paramList = [];
  
  if (paramString) {
    const params = paramString.split('&');
    
    params.forEach(param => {
      const [name, value] = param.split('=');
      if (name && value) {
        paramList.push({
          name: decodeURIComponent(name),
          value: decodeURIComponent(value),
          url: url
        });
      }
    });
  }
  
  return paramList;
}

// Function to find forms and their inputs
function findForms() {
  const forms = document.querySelectorAll('form');
  const formList = [];
  
  forms.forEach((form, formIndex) => {
    const formData = {
      action: form.action || window.location.href,
      method: form.method || 'GET',
      id: form.id || `form_${formIndex}`,
      inputs: []
    };
    
    const inputs = form.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
      if (input.name) {
        formData.inputs.push({
          name: input.name,
          type: input.type || 'text',
          value: input.value || ''
        });
      }
    });
    
    if (formData.inputs.length > 0) {
      formList.push(formData);
    }
  });
  
  return formList;
}

// Function to highlight vulnerable elements
function highlightElement(element) {
  const originalBackground = element.style.backgroundColor;
  const originalBorder = element.style.border;
  
  element.style.backgroundColor = '#ffcccc';
  element.style.border = '2px solid #ff0000';
  
  setTimeout(() => {
    element.style.backgroundColor = originalBackground;
    element.style.border = originalBorder;
  }, 3000);
}
"""
            with open(content_js_path, 'w') as f:
                f.write(content_js)
                
        # Create background.js
        background_js_path = os.path.join(self.static_dir, "background.js")
        if not os.path.exists(background_js_path):
            background_js = """// Background script for the SQLi Scanner extension

// Listen for installation
chrome.runtime.onInstalled.addListener(function() {
  console.log('SQLi Scanner Extension installed');
  
  // Initialize storage
  chrome.storage.local.set({
    'scanHistory': [],
    'vulnerabilities': [],
    'settings': {
      'autoScan': false,
      'notifyVulnerabilities': true,
      'serverUrl': 'ws://localhost:8765'
    }
  });
});

// Monitor all web requests for possible parameters
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Only process main frame navigations with query parameters
    if (details.type === 'main_frame' && details.url.includes('?')) {
      try {
        const url = new URL(details.url);
        if (url.search) {
          // Store the URL for possible future scanning
          chrome.storage.local.get('scanHistory', function(data) {
            const history = data.scanHistory || [];
            const entry = {
              url: details.url,
              timestamp: Date.now(),
              scanned: false
            };
            
            // Add to history if it doesn't exist
            if (!history.some(h => h.url === details.url)) {
              history.unshift(entry);
              // Keep history at a reasonable size
              if (history.length > 100) {
                history.pop();
              }
              chrome.storage.local.set({scanHistory: history});
            }
          });
        }
      } catch (e) {
        console.error('Error processing URL:', e);
      }
    }
    return {cancel: false};
  },
  {urls: ["<all_urls>"]},
  ["requestBody"]
);
"""
            with open(background_js_path, 'w') as f:
                f.write(background_js)
                
        logger.info("Browser extension files created")
        
    async def _websocket_handler(self, websocket, path):
        """Handle WebSocket connections"""
        # Register new client
        self.clients.add(websocket)
        logger.info(f"New client connected. Total clients: {len(self.clients)}")
        
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self._process_message(websocket, data)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON message: {message}")
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Invalid JSON format"
                    }))
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            # Unregister client
            self.clients.remove(websocket)
            logger.info(f"Client disconnected. Total clients: {len(self.clients)}")
            
    async def _process_message(self, websocket, data):
        """Process messages from clients"""
        message_type = data.get('type')
        
        if message_type == 'scan_request':
            action = data.get('action')
            url = data.get('url')
            
            if action == 'scan_page':
                await websocket.send(json.dumps({
                    "type": "status",
                    "message": f"Scanning page: {url}"
                }))
                
                # Extract parameters from URL
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                
                for param_name, param_values in query_params.items():
                    # Test each parameter
                    await self._test_parameter(websocket, url, param_name, param_values[0])
                    
            elif action == 'scan_forms':
                await websocket.send(json.dumps({
                    "type": "status",
                    "message": f"Scanning forms on: {url}"
                }))
                
        elif message_type == 'params_found':
            url = data.get('url')
            params = data.get('params', [])
            
            await websocket.send(json.dumps({
                "type": "status",
                "message": f"Found {len(params)} parameters to test"
            }))
            
            for param in params:
                await self._test_parameter(websocket, param.get('url'), param.get('name'), param.get('value'))
                
        elif message_type == 'forms_found':
            url = data.get('url')
            forms = data.get('forms', [])
            
            await websocket.send(json.dumps({
                "type": "status",
                "message": f"Found {len(forms)} forms to test"
            }))
            
            for form in forms:
                form_action = form.get('action')
                form_method = form.get('method')
                inputs = form.get('inputs', [])
                
                await websocket.send(json.dumps({
                    "type": "status",
                    "message": f"Testing form: {form.get('id')} ({len(inputs)} inputs)"
                }))
                
                for input_data in inputs:
                    await self._test_parameter(
                        websocket, 
                        form_action, 
                        input_data.get('name'),
                        input_data.get('value'),
                        form_method
                    )
                    
    async def _test_parameter(self, websocket, url, param_name, param_value, method="GET"):
        """Test a parameter for SQL injection"""
        # Use the detector module if available
        if self.detector:
            # Generate test payloads
            payloads = []
            if self.payload_generator:
                payloads = self.payload_generator.generate_for_db("generic", count=3)
            else:
                # Default payloads if no generator available
                payloads = ["' OR 1=1--", "1' OR '1'='1", "' UNION SELECT 1,2,3--"]
                
            # Test each payload
            for payload in payloads:
                try:
                    # Create the test URL
                    if method == "GET":
                        # Parse the URL and replace the parameter
                        parsed_url = urlparse(url)
                        query_params = parse_qs(parsed_url.query)
                        query_params[param_name] = [payload]
                        
                        # Rebuild the query string
                        query_string = "&".join([f"{k}={v[0]}" for k, v in query_params.items()])
                        
                        # Rebuild the URL
                        test_url = parsed_url._replace(query=query_string).geturl()
                    else:
                        # For POST, we just note the original URL
                        test_url = url
                        
                    # Send status update
                    await websocket.send(json.dumps({
                        "type": "status",
                        "message": f"Testing {param_name} with payload: {payload}"
                    }))
                    
                    # In a real implementation, we'd test this payload with the detector
                    # For demo, simulate some results
                    import random
                    is_vulnerable = random.random() < 0.2  # 20% chance of being vulnerable
                    
                    # Send the result
                    await websocket.send(json.dumps({
                        "type": "scan_result",
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "method": method,
                        "vulnerable": is_vulnerable,
                        "details": "Simulated test result" if not self.detector else "Actual test result"
                    }))
                    
                    if is_vulnerable:
                        # If vulnerable, stop testing this parameter
                        break
                        
                except Exception as e:
                    logger.error(f"Error testing parameter: {e}")
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"Error testing parameter {param_name}: {str(e)}"
                    }))
                    
    def _run_http_server(self):
        """Run HTTP server to serve extension files"""
        handler = http.server.SimpleHTTPRequestHandler
        
        class CustomHandler(handler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=self.static_dir, **kwargs)
                
            def log_message(self, format, *args):
                if self.debug_mode:
                    logger.debug(format % args)
                    
        with socketserver.TCPServer(("", self.port + 1), CustomHandler) as httpd:
            logger.info(f"HTTP server started at http://localhost:{self.port + 1}")
            httpd.serve_forever()
            
    async def _start_websocket_server(self):
        """Start WebSocket server"""
        host = "0.0.0.0" if self.allow_remote else "localhost"
        self.websocket_server = await websockets.serve(
            self._websocket_handler, host, self.port
        )
        logger.info(f"WebSocket server started at ws://{host}:{self.port}")
        await self.websocket_server.wait_closed()
        
    def start(self):
        """Start the browser extension integration servers"""
        # Start HTTP server in a separate thread
        self.server_thread = threading.Thread(target=self._run_http_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Start WebSocket server in a separate thread
        async def run_websocket_server():
            await self._start_websocket_server()
            
        self.websocket_thread = threading.Thread(
            target=lambda: asyncio.run(run_websocket_server())
        )
        self.websocket_thread.daemon = True
        self.websocket_thread.start()
        
        logger.info("Browser extension integration started")
        
        # Print installation instructions
        print("\nBrowser Extension Installation Instructions:")
        print("1. Open Chrome and go to chrome://extensions/")
        print("2. Enable 'Developer mode' (toggle in top right)")
        print("3. Click 'Load unpacked' and select this folder:")
        print(f"   {os.path.abspath(self.static_dir)}")
        print("\nThe extension API server is running at:")
        print(f"WebSocket: ws://localhost:{self.port}")
        print(f"HTTP: http://localhost:{self.port + 1}")
        
        return True
        
    def stop(self):
        """Stop the browser extension integration servers"""
        if self.websocket_server:
            self.websocket_server.close()
            
        logger.info("Browser extension integration stopped")
        return True
        
    def open_extension_page(self):
        """Open the extension folder in the browser"""
        url = f"http://localhost:{self.port + 1}"
        webbrowser.open(url)
        
        logger.info(f"Opened extension page: {url}")
        return True

if __name__ == "__main__":
    # Simple test/demo
    config = {
        'port': 8765,
        'allow_remote': False,
        'debug_mode': True
    }
    
    extension = BrowserExtension(config)
    extension.start()
    
    print("\nPress Enter to exit...")
    input()
    
    extension.stop()
