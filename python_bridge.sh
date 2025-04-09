#!/bin/bash
# Python to Shell Bridge Script
# Enables seamless usage of both Python modules and shell scripts together

# Source the core shell modules
. "./sqli_core.sh"

# Function to call the Python WAF detector from shell scripts
get_waf_bypass_strategy() {
    local url="$1"
    python3 waf_identify.py "$url"
}

# Function to call the Python database detector from shell scripts
detect_db_type() {
    local url="$1"
    local param_name="$2"
    python3 -c "import db_detector; print(db_detector.detect_database('$url', '$param_name'))"
}

# Function to generate smart payloads from shell scripts
generate_smart_payloads() {
    local db_type="$1"
    local tamper="$2"
    local count="$3"
    python3 -c "import payload_generator; gen = payload_generator.SQLiPayloadGenerator(); payloads = gen.generate_smart_payloads('$db_type', '$tamper', $count); print('\n'.join(payloads))"
}

# Function to test SQLi using Python from shell scripts
test_sqli_python() {
    local url="$1"
    local tamper="$2"
    python3 -c "import sqli_detector; detector = sqli_detector.SQLiDetector(); result = detector.test_url('$url', '$tamper'); print('VULNERABLE' if result else 'NOT_VULNERABLE')"
}

# Export the functions for use in other shell scripts
export -f get_waf_bypass_strategy
export -f detect_db_type
export -f generate_smart_payloads
export -f test_sqli_python
