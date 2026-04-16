from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

def analyze_url(url):
    """Analyze URL for phishing indicators"""
    score = 0
    reasons = []
    
    # Parse URL
    parsed = urlparse(url)
    
    # Check HTTPS
    if parsed.scheme != 'https':
        score += 20
        reasons.append("No HTTPS")
    
    # Check URL length
    if len(url) > 75:
        score += 15
        reasons.append("Long URL detected")
    
    # Check for hyphens in domain
    if '-' in parsed.netloc:
        score += 10
        reasons.append("Hyphenated domain")
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz']
    if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
        score += 25
        reasons.append("Suspicious top-level domain")
    
    # Check for IP address in domain
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.match(ip_pattern, parsed.netloc):
        score += 30
        reasons.append("IP address instead of domain name")
    
    return {
        'url': url,
        'score': score,
        'reasons': reasons,
        'is_safe': score < 30
    }

@app.route('/api/scan', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        result = analyze_url(url)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)