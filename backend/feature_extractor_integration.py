"""
Suraksha Kavach - Feature Extractor Integration Examples
========================================================

Integration examples for using the URL Feature Extractor with:
- Flask API endpoints
- XGBoost model training
- Rule-based scoring systems

Author: Suraksha Kavach Team
Purpose: Day 2 Task 2 - Integration examples for feature extractor
"""

import json
from url_feature_extractor import URLFeatureExtractor


class FeatureExtractorIntegration:
    """
    Integration layer for URL Feature Extractor with various systems.
    """
    
    def __init__(self):
        """Initialize the integration layer."""
        self.extractor = URLFeatureExtractor()
    
    def extract_for_flask_api(self, url: str) -> dict:
        """
        Extract features formatted for Flask API response.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Flask API formatted response
        """
        features = self.extractor.extract_features(url)
        
        # Format for Flask API
        api_response = {
            'success': True,
            'url': url,
            'features': features,
            'risk_indicators': {
                'has_suspicious_keywords': features['has_suspicious_keywords'],
                'suspicious_keyword_count': features['suspicious_keyword_count'],
                'has_ip_address': features['has_ip_address'],
                'has_unusual_port': features['has_unusual_port'],
                'has_suspicious_tld': features['has_suspicious_tld'],
                'is_http_only': features['has_http'] and not features['has_https']
            },
            'summary': {
                'url_length': features['url_length'],
                'hostname_length': features['hostname_length'],
                'num_subdomains': features['num_subdomains'],
                'num_query_params': features['num_query_params'],
                'security_score': self._calculate_security_score(features)
            }
        }
        
        return api_response
    
    def extract_for_xgboost(self, url: str) -> dict:
        """
        Extract features formatted for XGBoost model training/prediction.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: XGBoost formatted features
        """
        features = self.extractor.extract_features(url)
        
        # Convert boolean to int for ML models
        ml_features = {}
        
        # Numerical features
        numerical_features = [
            'url_length', 'hostname_length', 'path_length', 'query_length',
            'num_dots', 'num_hyphens', 'num_digits', 'num_slashes',
            'num_underscores', 'num_equals', 'num_question_marks',
            'num_ampersands', 'num_percent', 'num_subdomains',
            'suspicious_keyword_count', 'tld_length', 'num_query_params',
            'url_depth', 'ratio_digits_to_chars', 'domain_age_days'
        ]
        
        for feature in numerical_features:
            ml_features[feature] = float(features.get(feature, 0))
        
        # Boolean features (convert to 0/1)
        boolean_features = [
            'has_https', 'has_http', 'has_ftp', 'has_ip_address',
            'has_at_symbol', 'has_suspicious_keywords', 'has_encoded_chars',
            'has_long_query_string', 'has_unusual_port', 'has_double_slashes',
            'has_tilde', 'is_subdomain', 'has_www', 'has_suspicious_tld',
            'has_empty_query_params', 'has_ssl_in_url', 'has_secure_in_url',
            'has_login_in_url', 'has_bank_in_url', 'has_consecutive_slashes'
        ]
        
        for feature in boolean_features:
            ml_features[feature] = int(features.get(feature, False))
        
        # Feature vector for XGBoost
        feature_vector = {
            'features': ml_features,
            'feature_names': list(ml_features.keys()),
            'url': url,
            'timestamp': None  # Will be filled by the calling system
        }
        
        return feature_vector
    
    def extract_for_rule_based_scoring(self, url: str) -> dict:
        """
        Extract features formatted for rule-based phishing scoring.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Rule-based scoring features
        """
        features = self.extractor.extract_features(url)
        
        # Calculate risk scores based on rules
        risk_score = 0
        risk_factors = []
        
        # URL length risk
        if features['url_length'] > 75:
            risk_score += 15
            risk_factors.append("Long URL (>75 chars)")
        
        # HTTP risk
        if features['has_http'] and not features['has_https']:
            risk_score += 20
            risk_factors.append("HTTP instead of HTTPS")
        
        # IP address risk
        if features['has_ip_address']:
            risk_score += 30
            risk_factors.append("IP address in hostname")
        
        # Suspicious keywords risk
        if features['suspicious_keyword_count'] > 0:
            risk_score += features['suspicious_keyword_count'] * 10
            risk_factors.append(f"Suspicious keywords: {features['suspicious_keywords_found']}")
        
        # Hyphen risk
        if features['num_hyphens'] > 2:
            risk_score += 10
            risk_factors.append("Multiple hyphens in hostname")
        
        # Suspicious TLD risk
        if features['has_suspicious_tld']:
            risk_score += 25
            risk_factors.append("Suspicious top-level domain")
        
        # Unusual port risk
        if features['has_unusual_port']:
            risk_score += 15
            risk_factors.append("Unusual port number")
        
        # Subdomain risk
        if features['num_subdomains'] > 3:
            risk_score += 10
            risk_factors.append("Excessive subdomains")
        
        return {
            'url': url,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'risk_factors': risk_factors,
            'features': features,
            'recommendation': self._get_recommendation(risk_score)
        }
    
    def _calculate_security_score(self, features: dict) -> int:
        """
        Calculate a simple security score (0-100).
        
        Args:
            features (dict): Extracted features
            
        Returns:
            int: Security score (0=unsafe, 100=safe)
        """
        score = 100  # Start with perfect score
        
        # Deductions for suspicious features
        if features['has_http'] and not features['has_https']:
            score -= 20
        
        if features['has_ip_address']:
            score -= 30
        
        if features['suspicious_keyword_count'] > 0:
            score -= features['suspicious_keyword_count'] * 5
        
        if features['has_suspicious_tld']:
            score -= 25
        
        if features['has_unusual_port']:
            score -= 15
        
        if features['url_length'] > 75:
            score -= 10
        
        return max(0, score)
    
    def _get_risk_level(self, score: int) -> str:
        """
        Get risk level based on score.
        
        Args:
            score (int): Risk score
            
        Returns:
            str: Risk level
        """
        if score >= 50:
            return "High Risk"
        elif score >= 30:
            return "Medium Risk"
        elif score >= 10:
            return "Low Risk"
        else:
            return "Safe"
    
    def _get_recommendation(self, score: int) -> str:
        """
        Get recommendation based on risk score.
        
        Args:
            score (int): Risk score
            
        Returns:
            str: Recommendation
        """
        if score >= 50:
            return "Do not visit this website. High risk of phishing."
        elif score >= 30:
            return "Exercise extreme caution. Verify the website legitimacy."
        elif score >= 10:
            return "Be careful. Check the website carefully before proceeding."
        else:
            return "Appears safe. Normal precautions recommended."


def main():
    """
    Demonstration of integration examples.
    """
    print("=== Feature Extractor Integration Examples ===\n")
    
    integration = FeatureExtractorIntegration()
    
    # Test URL
    test_url = "http://verify-account-secure-bank-login-12345.ml/login.php?user=admin&pass=123&redirect=claim"
    
    print(f"Testing URL: {test_url}\n")
    
    # Flask API integration
    print("1. Flask API Integration:")
    flask_result = integration.extract_for_flask_api(test_url)
    print(json.dumps(flask_result, indent=2))
    print()
    
    # XGBoost integration
    print("2. XGBoost Integration:")
    xgb_result = integration.extract_for_xgboost(test_url)
    print(f"Feature vector length: {len(xgb_result['features'])}")
    print("Sample features:")
    for i, (key, value) in enumerate(list(xgb_result['features'].items())[:10]):
        print(f"  {key}: {value}")
    print()
    
    # Rule-based scoring
    print("3. Rule-based Scoring:")
    rule_result = integration.extract_for_rule_based_scoring(test_url)
    print(f"Risk Score: {rule_result['risk_score']}")
    print(f"Risk Level: {rule_result['risk_level']}")
    print(f"Risk Factors: {rule_result['risk_factors']}")
    print(f"Recommendation: {rule_result['recommendation']}")


if __name__ == "__main__":
    main()
