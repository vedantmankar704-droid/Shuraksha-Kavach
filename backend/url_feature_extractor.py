"""
Suraksha Kavach - URL Feature Extraction System
===============================================

A comprehensive feature extraction module for phishing detection and ML model training.
Converts URLs into structured numerical and boolean features for analysis.

Author: Suraksha Kavach Team
Purpose: Day 2 Task 2 - Feature extraction for XGBoost model training
"""

import re
import urllib.parse
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs


class URLFeatureExtractor:
    """
    URL Feature Extractor for Phishing Detection
    
    Extracts comprehensive features from URLs for:
    - Rule-based phishing detection
    - Machine learning model training (XGBoost)
    - Flask API integration
    """
    
    def __init__(self):
        """Initialize the feature extractor with suspicious keywords list."""
        self.suspicious_keywords = [
            'verify', 'login', 'secure', 'update', 'account', 
            'bank', 'otp', 'password', 'free', 'reward', 'claim'
        ]
        
        # Common ports that might be suspicious
        self.suspicious_ports = [8080, 8443, 3000, 5000, 8000, 9000, 1337, 2222, 3128, 1080]
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        Extract comprehensive features from a URL.
        
        Args:
            url (str): Input URL to analyze
            
        Returns:
            Dict[str, Any]: Structured feature object with numerical and boolean features
        """
        try:
            # Parse URL safely
            parsed_url = urlparse(url)
            
            # Initialize features dictionary
            features = {
                # Basic URL features
                'url_length': len(url),
                'hostname_length': len(parsed_url.hostname) if parsed_url.hostname else 0,
                'path_length': len(parsed_url.path) if parsed_url.path else 0,
                'query_length': len(parsed_url.query) if parsed_url.query else 0,
                
                # Character counting features
                'num_dots': url.count('.'),
                'num_hyphens': url.count('-'),
                'num_digits': sum(c.isdigit() for c in url),
                'num_slashes': url.count('/'),
                'num_underscores': url.count('_'),
                'num_equals': url.count('='),
                'num_question_marks': url.count('?'),
                'num_ampersands': url.count('&'),
                'num_percent': url.count('%'),
                
                # Protocol features
                'has_https': parsed_url.scheme == 'https',
                'has_http': parsed_url.scheme == 'http',
                'has_ftp': parsed_url.scheme == 'ftp',
                
                # Domain features
                'num_subdomains': self._count_subdomains(parsed_url.hostname),
                'has_ip_address': self._has_ip_address(parsed_url.hostname),
                'has_at_symbol': '@' in url,
                
                # Suspicious keyword features
                'has_suspicious_keywords': self._has_suspicious_keywords(url),
                'suspicious_keyword_count': self._count_suspicious_keywords(url),
                'suspicious_keywords_found': self._get_suspicious_keywords_found(url),
                
                # Special features
                'has_encoded_chars': self._has_encoded_characters(url),
                'has_long_query_string': len(parsed_url.query) > 100,
                'has_unusual_port': self._has_unusual_port(parsed_url.port),
                'has_double_slashes': '//' in url.replace('://', ''),
                'has_tilde': '~' in url,
                
                # Domain-specific features
                'domain_age_days': 0,  # Placeholder for future API integration
                'is_subdomain': self._is_subdomain(parsed_url.hostname),
                'has_www': parsed_url.hostname.startswith('www.') if parsed_url.hostname else False,
                
                # TLD features
                'tld_length': self._get_tld_length(parsed_url.hostname),
                'has_suspicious_tld': self._has_suspicious_tld(parsed_url.hostname),
                
                # Query string features
                'num_query_params': len(parse_qs(parsed_url.query)),
                'has_empty_query_params': self._has_empty_query_params(parsed_url.query),
                
                # Security features
                'has_ssl_in_url': 'ssl' in url.lower(),
                'has_secure_in_url': 'secure' in url.lower(),
                'has_login_in_url': 'login' in url.lower(),
                'has_bank_in_url': 'bank' in url.lower(),
                
                # Structural features
                'url_depth': self._calculate_url_depth(parsed_url.path),
                'has_consecutive_slashes': '//' in url.replace('://', '').replace('//', ''),
                'ratio_digits_to_chars': self._calculate_digit_ratio(url),
                
                # Original URL for reference
                'original_url': url
            }
            
            return features
            
        except Exception as e:
            # Return safe defaults if URL parsing fails
            return self._get_default_features(url, str(e))
    
    def _count_subdomains(self, hostname: str) -> int:
        """
        Count the number of subdomains in the hostname.
        
        Args:
            hostname (str): Hostname to analyze
            
        Returns:
            int: Number of subdomains
        """
        if not hostname:
            return 0
        
        # Remove 'www.' if present
        hostname = hostname.replace('www.', '')
        
        # Split by dots and count subdomains (excluding main domain)
        parts = hostname.split('.')
        
        # If we have more than 2 parts, the extra ones are subdomains
        return max(0, len(parts) - 2)
    
    def _has_ip_address(self, hostname: str) -> bool:
        """
        Check if hostname contains an IP address.
        
        Args:
            hostname (str): Hostname to check
            
        Returns:
            bool: True if IP address is detected
        """
        if not hostname:
            return False
        
        # IPv4 pattern
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        # Check for IPv4 pattern
        if re.match(ipv4_pattern, hostname):
            return True
        
        # Check for common IP patterns in hostname
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
            return True
        
        return False
    
    def _has_suspicious_keywords(self, url: str) -> bool:
        """
        Check if URL contains any suspicious keywords.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if suspicious keywords are found
        """
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in self.suspicious_keywords)
    
    def _count_suspicious_keywords(self, url: str) -> int:
        """
        Count the number of suspicious keywords in URL.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            int: Count of suspicious keywords
        """
        url_lower = url.lower()
        return sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
    
    def _get_suspicious_keywords_found(self, url: str) -> List[str]:
        """
        Get list of suspicious keywords found in URL.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            List[str]: List of found suspicious keywords
        """
        url_lower = url.lower()
        return [keyword for keyword in self.suspicious_keywords if keyword in url_lower]
    
    def _has_encoded_characters(self, url: str) -> bool:
        """
        Check if URL contains URL-encoded characters.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if encoded characters are found
        """
        # Look for URL encoding patterns (% followed by hex digits)
        return bool(re.search(r'%[0-9A-Fa-f]{2}', url))
    
    def _has_unusual_port(self, port: int) -> bool:
        """
        Check if URL uses an unusual port.
        
        Args:
            port (int): Port number to check
            
        Returns:
            bool: True if unusual port is detected
        """
        if not port:
            return False
        
        # Check if port is suspicious
        return port in self.suspicious_ports or port not in [80, 443, 8080]
    
    def _is_subdomain(self, hostname: str) -> bool:
        """
        Check if hostname is a subdomain.
        
        Args:
            hostname (str): Hostname to check
            
        Returns:
            bool: True if it's a subdomain
        """
        if not hostname:
            return False
        
        hostname = hostname.replace('www.', '')
        parts = hostname.split('.')
        
        return len(parts) > 2
    
    def _get_tld_length(self, hostname: str) -> int:
        """
        Get the length of the top-level domain.
        
        Args:
            hostname (str): Hostname to analyze
            
        Returns:
            int: Length of TLD
        """
        if not hostname:
            return 0
        
        parts = hostname.split('.')
        if len(parts) >= 2:
            return len(parts[-1])
        return 0
    
    def _has_suspicious_tld(self, hostname: str) -> bool:
        """
        Check if hostname has a suspicious TLD.
        
        Args:
            hostname (str): Hostname to check
            
        Returns:
            bool: True if suspicious TLD is found
        """
        if not hostname:
            return False
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.work', '.date']
        
        return any(hostname.lower().endswith(tld) for tld in suspicious_tlds)
    
    def _has_empty_query_params(self, query: str) -> bool:
        """
        Check if query string has empty parameters.
        
        Args:
            query (str): Query string to check
            
        Returns:
            bool: True if empty parameters are found
        """
        if not query:
            return False
        
        # Look for patterns like &= or &param=
        return bool(re.search(r'&=|&\w+=$|^\w+=$', query))
    
    def _calculate_url_depth(self, path: str) -> int:
        """
        Calculate the depth of URL path.
        
        Args:
            path (str): URL path to analyze
            
        Returns:
            int: Depth of the path
        """
        if not path:
            return 0
        
        # Count slashes, excluding leading slash
        return path.count('/')
    
    def _calculate_digit_ratio(self, url: str) -> float:
        """
        Calculate ratio of digits to total characters.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            float: Ratio of digits to characters
        """
        if not url:
            return 0.0
        
        digit_count = sum(c.isdigit() for c in url)
        return digit_count / len(url) if len(url) > 0 else 0.0
    
    def _get_default_features(self, url: str, error: str) -> Dict[str, Any]:
        """
        Return default features if URL parsing fails.
        
        Args:
            url (str): Original URL
            error (str): Error message
            
        Returns:
            Dict[str, Any]: Default feature dictionary
        """
        return {
            'url_length': len(url),
            'hostname_length': 0,
            'path_length': 0,
            'query_length': 0,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_digits': sum(c.isdigit() for c in url),
            'num_slashes': url.count('/'),
            'num_underscores': url.count('_'),
            'num_equals': url.count('='),
            'num_question_marks': url.count('?'),
            'num_ampersands': url.count('&'),
            'num_percent': url.count('%'),
            'has_https': url.startswith('https://'),
            'has_http': url.startswith('http://'),
            'has_ftp': url.startswith('ftp://'),
            'num_subdomains': 0,
            'has_ip_address': False,
            'has_at_symbol': '@' in url,
            'has_suspicious_keywords': self._has_suspicious_keywords(url),
            'suspicious_keyword_count': self._count_suspicious_keywords(url),
            'suspicious_keywords_found': self._get_suspicious_keywords_found(url),
            'has_encoded_chars': self._has_encoded_characters(url),
            'has_long_query_string': False,
            'has_unusual_port': False,
            'has_double_slashes': '//' in url.replace('://', ''),
            'has_tilde': '~' in url,
            'domain_age_days': 0,
            'is_subdomain': False,
            'has_www': False,
            'tld_length': 0,
            'has_suspicious_tld': False,
            'num_query_params': 0,
            'has_empty_query_params': False,
            'has_ssl_in_url': 'ssl' in url.lower(),
            'has_secure_in_url': 'secure' in url.lower(),
            'has_login_in_url': 'login' in url.lower(),
            'has_bank_in_url': 'bank' in url.lower(),
            'url_depth': 0,
            'has_consecutive_slashes': False,
            'ratio_digits_to_chars': self._calculate_digit_ratio(url),
            'original_url': url,
            'parsing_error': error
        }


def main():
    """
    Example usage and testing of the URL Feature Extractor.
    """
    print("=== Suraksha Kavach URL Feature Extractor ===\n")
    
    # Initialize the extractor
    extractor = URLFeatureExtractor()
    
    # Test URLs with different characteristics
    test_urls = [
        # Normal legitimate URL
        "https://www.github.com/vedantmankar704-droid/Suraksha-Kavach",
        
        # Suspicious phishing URL
        "http://verify-account-secure-bank-login-12345.ml/login.php?user=admin&pass=123&redirect=claim",
        
        # URL with IP address and unusual port
        "http://192.168.1.100:8080/secure-update-account?verify=true&otp=12345&reward=free"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"--- Test URL {i} ---")
        print(f"URL: {url}")
        print()
        
        # Extract features
        features = extractor.extract_features(url)
        
        # Display key features
        key_features = [
            'url_length', 'hostname_length', 'num_dots', 'num_hyphens', 
            'num_digits', 'has_https', 'has_ip_address', 'num_subdomains',
            'suspicious_keyword_count', 'has_suspicious_keywords', 'has_at_symbol',
            'has_encoded_chars', 'has_long_query_string', 'has_unusual_port',
            'has_suspicious_tld', 'num_query_params', 'url_depth'
        ]
        
        print("Key Features:")
        for feature in key_features:
            value = features[feature]
            print(f"  {feature}: {value}")
        
        if features.get('suspicious_keywords_found'):
            print(f"  Suspicious keywords found: {features['suspicious_keywords_found']}")
        
        print()
        print("Full Feature Dictionary:")
        for key, value in features.items():
            if key not in key_features and key != 'suspicious_keywords_found':
                print(f"  {key}: {value}")
        
        print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()
