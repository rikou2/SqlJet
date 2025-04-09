#!/usr/bin/env python3
# Business Impact Assessment Module
# Evaluates and quantifies the business impact of SQL injection vulnerabilities

import os
import json
import logging
import datetime
import csv
import re
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('business_impact')

class BusinessImpactAssessment:
    """
    Evaluates the business impact of discovered SQL injection vulnerabilities
    """
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.config = config or {}
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize impact parameters
        self.impact_factors = self._load_impact_factors()
        self.industry_factors = self._load_industry_factors()
        
        # Initialize report data
        self.vulnerabilities = []
        self.assessed_vulns = []
        
        logger.info("Business Impact Assessment module initialized")
        
    def _load_impact_factors(self):
        """Load impact factors from config or use defaults"""
        factors_file = os.path.join(self.data_dir, 'impact_factors.json')
        
        # Create default factors if file doesn't exist
        if not os.path.exists(factors_file):
            factors = {
                "data_sensitivity": {
                    "personal_identifiable_information": 0.9,
                    "payment_card_data": 1.0,
                    "health_information": 0.95,
                    "credentials": 0.8,
                    "internal_business_data": 0.7,
                    "public_data": 0.3
                },
                "data_exposure": {
                    "full_database_dump": 1.0,
                    "targeted_data_extraction": 0.8,
                    "limited_information_disclosure": 0.6,
                    "error_based_inference": 0.4
                },
                "attack_complexity": {
                    "trivial": 1.0,
                    "low": 0.8,
                    "moderate": 0.6,
                    "high": 0.4
                },
                "exploitability": {
                    "public_facing_no_auth": 1.0,
                    "public_facing_with_auth": 0.8,
                    "internal_network": 0.6,
                    "internal_authenticated": 0.4
                },
                "business_criticality": {
                    "revenue_generating": 1.0,
                    "customer_facing": 0.9,
                    "business_operations": 0.8,
                    "internal_tools": 0.6,
                    "development_systems": 0.4
                },
                "regulatory_compliance": {
                    "pci_dss": 1.0,
                    "hipaa": 0.95,
                    "gdpr": 0.9,
                    "sox": 0.85,
                    "ccpa": 0.8,
                    "none": 0.3
                }
            }
            
            # Save default factors
            with open(factors_file, 'w') as f:
                json.dump(factors, f, indent=2)
            
        else:
            # Load existing factors
            with open(factors_file, 'r') as f:
                factors = json.load(f)
                
        return factors
        
    def _load_industry_factors(self):
        """Load industry-specific impact factors"""
        industry_file = os.path.join(self.data_dir, 'industry_factors.json')
        
        # Create default factors if file doesn't exist
        if not os.path.exists(industry_file):
            factors = {
                "financial_services": {
                    "base_multiplier": 1.0,
                    "breach_cost_per_record": 388,
                    "reputation_impact": 0.9,
                    "regulatory_penalties": 0.95
                },
                "healthcare": {
                    "base_multiplier": 0.95,
                    "breach_cost_per_record": 429,
                    "reputation_impact": 0.85,
                    "regulatory_penalties": 1.0
                },
                "retail": {
                    "base_multiplier": 0.8,
                    "breach_cost_per_record": 312,
                    "reputation_impact": 0.8,
                    "regulatory_penalties": 0.7
                },
                "technology": {
                    "base_multiplier": 0.85,
                    "breach_cost_per_record": 346,
                    "reputation_impact": 0.8,
                    "regulatory_penalties": 0.75
                },
                "manufacturing": {
                    "base_multiplier": 0.7,
                    "breach_cost_per_record": 285,
                    "reputation_impact": 0.6,
                    "regulatory_penalties": 0.65
                },
                "government": {
                    "base_multiplier": 0.9,
                    "breach_cost_per_record": 310,
                    "reputation_impact": 0.85,
                    "regulatory_penalties": 0.7
                },
                "education": {
                    "base_multiplier": 0.75,
                    "breach_cost_per_record": 291,
                    "reputation_impact": 0.7,
                    "regulatory_penalties": 0.6
                },
                "other": {
                    "base_multiplier": 0.8,
                    "breach_cost_per_record": 320,
                    "reputation_impact": 0.75,
                    "regulatory_penalties": 0.7
                }
            }
            
            # Save default factors
            with open(industry_file, 'w') as f:
                json.dump(factors, f, indent=2)
            
        else:
            # Load existing factors
            with open(industry_file, 'r') as f:
                factors = json.load(f)
                
        return factors
        
    def load_vulnerabilities(self, vulnerabilities):
        """Load vulnerabilities for assessment"""
        self.vulnerabilities = vulnerabilities
        logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities for assessment")
        return len(vulnerabilities)
        
    def load_vulnerabilities_from_file(self, file_path):
        """Load vulnerabilities from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Check if the file contains a list of vulnerabilities directly
            if isinstance(data, list):
                self.vulnerabilities = data
            # Or if it's a report format with vulnerabilities nested
            elif isinstance(data, dict) and "vulnerabilities" in data:
                self.vulnerabilities = data["vulnerabilities"]
            elif isinstance(data, dict) and "results" in data:
                # Extract vulnerabilities from nested structure
                all_vulns = []
                for device, device_data in data["results"].items():
                    if "vulnerabilities" in device_data:
                        all_vulns.extend(device_data["vulnerabilities"])
                self.vulnerabilities = all_vulns
            else:
                logger.error("Unknown vulnerability file format")
                return 0
                
            logger.info(f"Loaded {len(self.vulnerabilities)} vulnerabilities from {file_path}")
            return len(self.vulnerabilities)
            
        except Exception as e:
            logger.error(f"Error loading vulnerabilities from file: {e}")
            return 0
            
    def assess_vulnerability(self, vulnerability, organization_info=None):
        """
        Assess business impact of a single vulnerability
        
        Args:
            vulnerability: The vulnerability data dictionary
            organization_info: Dictionary with organization details:
                - industry: Industry sector (financial_services, healthcare, etc.)
                - size: Organization size (small, medium, large, enterprise)
                - data_records: Estimated number of data records
                - annual_revenue: Annual revenue in USD
                - compliance: List of compliance requirements
        
        Returns:
            Assessment dictionary with impact scores and details
        """
        # Use default organization info if not provided
        if not organization_info:
            organization_info = {
                "industry": "other",
                "size": "medium",
                "data_records": 100000,
                "annual_revenue": 10000000,
                "compliance": ["none"]
            }
            
        # Get industry factors
        industry = organization_info.get("industry", "other")
        industry_data = self.industry_factors.get(industry, self.industry_factors["other"])
        
        # Initialize assessment
        assessment = {
            "vulnerability": vulnerability,
            "timestamp": datetime.datetime.now().isoformat(),
            "scores": {},
            "financial_impact": {},
            "recommendations": []
        }
        
        # Calculate technical severity score (0-10)
        severity = vulnerability.get("severity", "Medium")
        severity_map = {"Low": 3, "Medium": 6, "High": 8, "Critical": 10}
        tech_severity = severity_map.get(severity, 5)
        
        # Calculate data sensitivity score
        data_type = self._determine_data_type(vulnerability)
        data_sensitivity = self.impact_factors["data_sensitivity"].get(data_type, 0.5)
        
        # Calculate exploitability score
        attack_vector = self._determine_attack_vector(vulnerability)
        exploitability = self.impact_factors["exploitability"].get(attack_vector, 0.7)
        
        # Calculate attack complexity
        complexity = self._determine_attack_complexity(vulnerability)
        attack_complexity = self.impact_factors["attack_complexity"].get(complexity, 0.6)
        
        # Calculate business criticality
        app_type = self._determine_app_type(vulnerability)
        business_criticality = self.impact_factors["business_criticality"].get(app_type, 0.7)
        
        # Calculate regulatory impact
        compliance_impact = 0
        for requirement in organization_info.get("compliance", ["none"]):
            compliance_score = self.impact_factors["regulatory_compliance"].get(requirement, 0.3)
            compliance_impact = max(compliance_impact, compliance_score)
            
        # Calculate combined impact score (0-10)
        impact_score = (
            (data_sensitivity * 2.5) +
            (exploitability * 2.0) +
            (attack_complexity * 1.5) +
            (business_criticality * 2.0) +
            (compliance_impact * 2.0)
        ) / 10.0 * 10
        
        # Calculate financial impact
        data_records = organization_info.get("data_records", 10000)
        annual_revenue = organization_info.get("annual_revenue", 1000000)
        
        # Cost of breach (per record)
        breach_cost_per_record = industry_data.get("breach_cost_per_record", 330)
        
        # Estimated data exposure percentage
        exposure_type = self._determine_data_exposure(vulnerability)
        exposure_percentage = self.impact_factors["data_exposure"].get(exposure_type, 0.5)
        
        # Financial impacts
        direct_breach_cost = data_records * exposure_percentage * breach_cost_per_record
        
        # Reputation impact (% of annual revenue)
        reputation_factor = industry_data.get("reputation_impact", 0.75)
        reputation_impact = annual_revenue * reputation_factor * exposure_percentage * 0.05
        
        # Regulatory penalties
        regulatory_factor = industry_data.get("regulatory_penalties", 0.7)
        regulatory_penalties = 0
        
        # Different compliance penalties
        if "gdpr" in organization_info.get("compliance", []):
            # GDPR: Up to 4% of global annual revenue or €20 million
            regulatory_penalties += min(annual_revenue * 0.04, 20000000) * regulatory_factor * exposure_percentage
            
        if "pci_dss" in organization_info.get("compliance", []):
            # PCI-DSS: $5,000 to $100,000 per month
            regulatory_penalties += 50000 * regulatory_factor * exposure_percentage
            
        if "hipaa" in organization_info.get("compliance", []):
            # HIPAA: $100 to $50,000 per violation
            regulatory_penalties += 25000 * data_sensitivity * regulatory_factor * exposure_percentage
            
        # Total financial impact
        total_financial_impact = direct_breach_cost + reputation_impact + regulatory_penalties
        
        # Store scores
        assessment["scores"] = {
            "technical_severity": round(tech_severity, 1),
            "data_sensitivity": round(data_sensitivity * 10, 1),
            "exploitability": round(exploitability * 10, 1),
            "attack_complexity": round(attack_complexity * 10, 1),
            "business_criticality": round(business_criticality * 10, 1),
            "regulatory_impact": round(compliance_impact * 10, 1),
            "overall_impact": round(impact_score, 1)
        }
        
        # Store financial impact
        assessment["financial_impact"] = {
            "direct_breach_cost": round(direct_breach_cost, 2),
            "reputation_impact": round(reputation_impact, 2),
            "regulatory_penalties": round(regulatory_penalties, 2),
            "total_financial_impact": round(total_financial_impact, 2)
        }
        
        # Generate recommendations
        assessment["recommendations"] = self._generate_recommendations(vulnerability, assessment)
        
        return assessment
        
    def _determine_data_type(self, vulnerability):
        """Determine type of data potentially exposed by this vulnerability"""
        url = vulnerability.get("url", "")
        details = vulnerability.get("details", "")
        parameter = vulnerability.get("parameter", "")
        
        # Check URL and details for indicators
        indicators = {
            "personal_identifiable_information": ["user", "profile", "account", "member", "customer", "personal", "name", "address", "phone", "email"],
            "payment_card_data": ["payment", "card", "credit", "transaction", "purchase", "order", "checkout", "billing"],
            "health_information": ["health", "medical", "patient", "doctor", "hospital", "clinic", "treatment", "diagnosis"],
            "credentials": ["login", "password", "credential", "auth", "session", "token"],
            "internal_business_data": ["admin", "report", "internal", "revenue", "sales", "employee", "hr", "finance"],
            "public_data": ["public", "info", "news", "article", "post", "comment", "blog"]
        }
        
        scores = {data_type: 0 for data_type in indicators.keys()}
        
        # Score each data type based on indicators present
        for data_type, terms in indicators.items():
            for term in terms:
                if term in url.lower() or term in details.lower() or term in parameter.lower():
                    scores[data_type] += 1
                    
        # Return data type with highest score, or default to internal_business_data
        if not scores or max(scores.values()) == 0:
            return "internal_business_data"
            
        return max(scores.items(), key=lambda x: x[1])[0]
        
    def _determine_attack_vector(self, vulnerability):
        """Determine attack vector based on vulnerability details"""
        url = vulnerability.get("url", "")
        details = vulnerability.get("details", "")
        
        # Check if URL is public-facing or internal
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Check for internal hostnames/IPs
        internal_patterns = [
            r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}',
            r'^192\.168\.\d{1,3}\.\d{1,3}',
            r'localhost',
            r'\.internal\.',
            r'\.local$'
        ]
        
        is_internal = any(re.search(pattern, hostname) for pattern in internal_patterns)
        
        # Check for authentication indicators
        auth_indicators = ["login", "auth", "session", "token", "authenticated", "username", "password"]
        requires_auth = any(indicator in url.lower() or indicator in details.lower() for indicator in auth_indicators)
        
        if is_internal and requires_auth:
            return "internal_authenticated"
        elif is_internal:
            return "internal_network"
        elif requires_auth:
            return "public_facing_with_auth"
        else:
            return "public_facing_no_auth"
            
    def _determine_attack_complexity(self, vulnerability):
        """Determine complexity of exploiting this vulnerability"""
        payload = vulnerability.get("payload", "")
        vuln_type = vulnerability.get("type", "")
        details = vulnerability.get("details", "")
        
        # Simple payloads indicate trivial complexity
        simple_payloads = ["'", "1'", "' OR '1'='1", "1 OR 1=1"]
        if payload in simple_payloads:
            return "trivial"
            
        # Time-based and UNION-based injections are more complex
        if "Time-based" in vuln_type or "sleep" in payload.lower() or "waitfor" in payload.lower():
            return "moderate"
            
        if "UNION" in payload:
            return "moderate"
            
        # Blind SQLi typically requires more effort
        if "Blind" in vuln_type or "blind" in details.lower():
            return "high"
            
        # Default to low complexity
        return "low"
        
    def _determine_app_type(self, vulnerability):
        """Determine application type and business criticality"""
        url = vulnerability.get("url", "")
        details = vulnerability.get("details", "")
        
        # Check URL and details for indicators
        indicators = {
            "revenue_generating": ["shop", "store", "checkout", "payment", "subscription", "order", "cart", "purchase"],
            "customer_facing": ["account", "profile", "customer", "user", "client", "member", "public"],
            "business_operations": ["admin", "dashboard", "report", "manage", "operations", "analytics"],
            "internal_tools": ["internal", "tool", "utility", "staff", "employee"],
            "development_systems": ["dev", "test", "staging", "uat", "sandbox"]
        }
        
        for app_type, terms in indicators.items():
            for term in terms:
                if term in url.lower() or term in details.lower():
                    return app_type
                    
        # Default to business_operations
        return "business_operations"
        
    def _determine_data_exposure(self, vulnerability):
        """Determine potential data exposure level"""
        payload = vulnerability.get("payload", "")
        vuln_type = vulnerability.get("type", "")
        details = vulnerability.get("details", "")
        
        # Check for indicators of full database access
        if "UNION SELECT" in payload and "information_schema" in payload:
            return "full_database_dump"
            
        # Check for targeted data extraction
        if "UNION SELECT" in payload:
            return "targeted_data_extraction"
            
        # Check for error-based attacks
        if "Error-based" in vuln_type or "error" in details.lower():
            return "error_based_inference"
            
        # Default to limited information disclosure
        return "limited_information_disclosure"
        
    def _generate_recommendations(self, vulnerability, assessment):
        """Generate mitigation recommendations based on assessment"""
        recommendations = []
        
        # Basic recommendations
        recommendations.append({
            "title": "Implement Parameterized Queries",
            "description": "Replace dynamic SQL construction with parameterized queries to eliminate injection risks.",
            "priority": "High",
            "effort": "Medium"
        })
        
        recommendations.append({
            "title": "Input Validation",
            "description": "Implement strict input validation for all parameters.",
            "priority": "High",
            "effort": "Medium"
        })
        
        # Based on vulnerability type
        if "Time-based" in vulnerability.get("type", ""):
            recommendations.append({
                "title": "Limit Query Execution Time",
                "description": "Set database query timeout limits to mitigate time-based attacks.",
                "priority": "Medium",
                "effort": "Low"
            })
            
        # Based on data sensitivity
        data_sensitivity = assessment["scores"]["data_sensitivity"]
        if data_sensitivity > 7:
            recommendations.append({
                "title": "Data Encryption",
                "description": "Encrypt sensitive data in the database to reduce impact of successful attacks.",
                "priority": "High",
                "effort": "High"
            })
            
            recommendations.append({
                "title": "Data Access Monitoring",
                "description": "Implement monitoring for suspicious database access patterns.",
                "priority": "High",
                "effort": "Medium"
            })
            
        # Based on attack vector
        attack_vector = self._determine_attack_vector(vulnerability)
        if attack_vector == "public_facing_no_auth":
            recommendations.append({
                "title": "Implement Web Application Firewall (WAF)",
                "description": "Deploy a WAF configured to block SQL injection attempts.",
                "priority": "High",
                "effort": "Medium"
            })
            
        # Based on business criticality
        business_criticality = assessment["scores"]["business_criticality"]
        if business_criticality > 8:
            recommendations.append({
                "title": "Regular Security Testing",
                "description": "Implement regular automated and manual security testing for critical applications.",
                "priority": "High",
                "effort": "Medium"
            })
            
        return recommendations
        
    def assess_all_vulnerabilities(self, organization_info=None):
        """Assess business impact of all loaded vulnerabilities"""
        self.assessed_vulns = []
        
        for vuln in self.vulnerabilities:
            assessment = self.assess_vulnerability(vuln, organization_info)
            self.assessed_vulns.append(assessment)
            
        logger.info(f"Assessed business impact for {len(self.assessed_vulns)} vulnerabilities")
        return self.assessed_vulns
        
    def prioritize_vulnerabilities(self):
        """Prioritize vulnerabilities based on business impact"""
        if not self.assessed_vulns:
            logger.warning("No assessed vulnerabilities to prioritize")
            return []
            
        # Sort by overall impact score (descending)
        prioritized = sorted(
            self.assessed_vulns,
            key=lambda x: x["scores"]["overall_impact"],
            reverse=True
        )
        
        return prioritized
        
    def generate_risk_categories(self):
        """Categorize vulnerabilities into risk categories"""
        if not self.assessed_vulns:
            logger.warning("No assessed vulnerabilities to categorize")
            return {}
            
        categories = {
            "critical_risk": [],
            "high_risk": [],
            "medium_risk": [],
            "low_risk": []
        }
        
        for assessment in self.assessed_vulns:
            impact_score = assessment["scores"]["overall_impact"]
            
            if impact_score >= 8.0:
                categories["critical_risk"].append(assessment)
            elif impact_score >= 6.0:
                categories["high_risk"].append(assessment)
            elif impact_score >= 4.0:
                categories["medium_risk"].append(assessment)
            else:
                categories["low_risk"].append(assessment)
                
        return categories
        
    def generate_financial_summary(self):
        """Generate financial impact summary across all vulnerabilities"""
        if not self.assessed_vulns:
            logger.warning("No assessed vulnerabilities for financial summary")
            return {}
            
        total_impacts = {
            "direct_breach_cost": 0,
            "reputation_impact": 0,
            "regulatory_penalties": 0,
            "total_financial_impact": 0
        }
        
        for assessment in self.assessed_vulns:
            for key in total_impacts:
                total_impacts[key] += assessment["financial_impact"].get(key, 0)
                
        # Calculate average per vulnerability
        avg_impacts = {
            f"avg_{key}": value / len(self.assessed_vulns)
            for key, value in total_impacts.items()
        }
        
        # Combine totals and averages
        summary = {**total_impacts, **avg_impacts}
        
        # Add max values
        max_impact = max(self.assessed_vulns, key=lambda x: x["financial_impact"]["total_financial_impact"])
        summary["max_impact_vulnerability"] = {
            "url": max_impact["vulnerability"].get("url", ""),
            "type": max_impact["vulnerability"].get("type", ""),
            "financial_impact": max_impact["financial_impact"]["total_financial_impact"]
        }
        
        return summary
        
    def generate_report(self, output_file=None, format="json"):
        """Generate a comprehensive business impact report"""
        if not self.assessed_vulns:
            logger.warning("No assessed vulnerabilities for report generation")
            return None
            
        # Create default output file if not specified
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.data_dir, f"business_impact_report_{timestamp}.{format}")
            
        # Generate risk categories
        risk_categories = self.generate_risk_categories()
        
        # Generate financial summary
        financial_summary = self.generate_financial_summary()
        
        # Prioritize vulnerabilities
        prioritized_vulns = self.prioritize_vulnerabilities()
        
        # Create report structure
        report = {
            "report_date": datetime.datetime.now().isoformat(),
            "vulnerabilities_assessed": len(self.assessed_vulns),
            "risk_summary": {
                "critical_risk_count": len(risk_categories["critical_risk"]),
                "high_risk_count": len(risk_categories["high_risk"]),
                "medium_risk_count": len(risk_categories["medium_risk"]),
                "low_risk_count": len(risk_categories["low_risk"])
            },
            "financial_summary": financial_summary,
            "top_vulnerabilities": [
                {
                    "url": v["vulnerability"].get("url", ""),
                    "type": v["vulnerability"].get("type", ""),
                    "impact_score": v["scores"]["overall_impact"],
                    "financial_impact": v["financial_impact"]["total_financial_impact"]
                }
                for v in prioritized_vulns[:5]  # Top 5 vulnerabilities
            ],
            "mitigation_recommendations": self._compile_recommendations(),
            "detailed_assessments": self.assessed_vulns if format == "json" else None
        }
        
        # Write report to file
        if format == "json":
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
                
        elif format == "csv":
            self._write_csv_report(output_file, report)
            
        logger.info(f"Business impact report saved to {output_file}")
        return output_file
        
    def _compile_recommendations(self):
        """Compile and prioritize unique recommendations"""
        if not self.assessed_vulns:
            return []
            
        # Collect all recommendations
        all_recommendations = []
        for assessment in self.assessed_vulns:
            all_recommendations.extend(assessment.get("recommendations", []))
            
        # Count frequency of each recommendation
        recommendation_counts = {}
        for rec in all_recommendations:
            rec_key = rec["title"]
            if rec_key not in recommendation_counts:
                recommendation_counts[rec_key] = {
                    "title": rec["title"],
                    "description": rec["description"],
                    "priority": rec["priority"],
                    "effort": rec["effort"],
                    "count": 0
                }
            recommendation_counts[rec_key]["count"] += 1
            
        # Convert to list and sort by count
        recommendations = list(recommendation_counts.values())
        recommendations.sort(key=lambda x: x["count"], reverse=True)
        
        return recommendations
        
    def _write_csv_report(self, output_file, report):
        """Write report in CSV format"""
        # Write risk summary
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(["Business Impact Assessment Report", report["report_date"]])
            writer.writerow([])
            
            # Risk summary
            writer.writerow(["Risk Summary", "Count"])
            for risk_level, count in report["risk_summary"].items():
                writer.writerow([risk_level.replace("_", " ").title(), count])
            writer.writerow([])
            
            # Financial summary
            writer.writerow(["Financial Impact Summary", "Amount ($)"])
            for impact_type, amount in report["financial_summary"].items():
                if not impact_type.startswith("max_"):
                    writer.writerow([impact_type.replace("_", " ").title(), f"${amount:.2f}"])
            writer.writerow([])
            
            # Top vulnerabilities
            writer.writerow(["Top Vulnerabilities by Impact"])
            writer.writerow(["URL", "Type", "Impact Score", "Financial Impact ($)"])
            for vuln in report["top_vulnerabilities"]:
                writer.writerow([
                    vuln["url"],
                    vuln["type"],
                    f"{vuln['impact_score']:.1f}",
                    f"${vuln['financial_impact']:.2f}"
                ])
            writer.writerow([])
            
            # Recommendations
            writer.writerow(["Top Mitigation Recommendations"])
            writer.writerow(["Title", "Description", "Priority", "Effort", "Affected Vulnerabilities"])
            for rec in report["mitigation_recommendations"]:
                writer.writerow([
                    rec["title"],
                    rec["description"],
                    rec["priority"],
                    rec["effort"],
                    rec["count"]
                ])

if __name__ == "__main__":
    # Simple test/demo
    assessor = BusinessImpactAssessment()
    
    # Sample vulnerability
    sample_vuln = {
        "type": "SQL Injection",
        "url": "https://example.com/shop/product?id=1",
        "parameter": "id",
        "payload": "1' UNION SELECT 1,2,3 FROM users--",
        "severity": "High",
        "details": "SQL error detected in response: MySQL syntax error"
    }
    
    # Sample organization info
    org_info = {
        "industry": "retail",
        "size": "medium",
        "data_records": 50000,
        "annual_revenue": 5000000,
        "compliance": ["pci_dss", "gdpr"]
    }
    
    # Assess vulnerability
    assessment = assessor.assess_vulnerability(sample_vuln, org_info)
    
    # Print results
    print(f"Overall Impact Score: {assessment['scores']['overall_impact']:.1f}/10")
    print(f"Financial Impact: ${assessment['financial_impact']['total_financial_impact']:.2f}")
    print("\nTop Recommendations:")
    for rec in assessment['recommendations']:
        print(f"- {rec['title']} ({rec['priority']} priority)")
