from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Expanded whitelist
KNOWN_SAFE_DOMAINS = {
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 
    'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com', 'netflix.com', 
    'paypal.com', 'leetcode.com', 'chatgpt.com', 'openai.com'
}

# Load the final, unified model
try:
    model = joblib.load('final_phishing_model.joblib')
    model_columns = joblib.load('final_model_columns.joblib')
    print("Final model loaded successfully.")
except FileNotFoundError:
    print("Model files not found. Please run the new model_training.py first.")
    model = None

def extract_features(content, content_type):
    """
    A single, robust function to extract features from any content type.
    This function MUST BE IDENTICAL in both training and app scripts.
    """
    features = {}
    content_lower = str(content).lower()
    
    # Basic Features
    features['length'] = len(content_lower)
    features['digit_count'] = sum(c.isdigit() for c in content_lower)

    if content_type == 'url':
        try:
            parsed_url = urlparse(content_lower if '://' in content_lower else 'http://' + content_lower)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            features['special_chars'] = content_lower.count('-') + content_lower.count('@') + content_lower.count('?') + content_lower.count('=') + content_lower.count('.')
            features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
            
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features['uses_ip'] = 1 if re.search(ip_pattern, domain) else 0
            
            # --- New, More Advanced Features ---
            features['subdomain_count'] = domain.count('.')
            features['path_length'] = len(path)
            tld = domain.split('.')[-1]
            features['tld_length'] = len(tld.split('/')[0]) # Get TLD length
            
        except Exception:
            # Fallback for malformed URLs
            features['special_chars'] = content_lower.count('.') + content_lower.count('-')
            features['has_httpshttps'] = 0
            features['uses_ip'] = 0
            features['subdomain_count'] = 0
            features['path_length'] = 0
            features['tld_length'] = 0
    else: # For email/sms
        features['special_chars'] = 0
        features['has_https'] = 0
        features['uses_ip'] = 0
        features['subdomain_count'] = 0
        features['path_length'] = 0
        features['tld_length'] = 0
    
    if content_type in ['sms', 'email']:
        features['has_link'] = 1 if 'http' in content_lower or 'www' in content_lower else 0
        phishing_keywords = ['verify', 'account', 'suspended', 'urgent', 'winner', 'claim', 'free', 'password', 'login']
        features['keyword_count'] = sum(content_lower.count(keyword) for keyword in phishing_keywords)
    else:
        features['has_link'] = 0
        features['keyword_count'] = 0

    return features

def get_detailed_reasons(features, content_type):
    """ Generates a list of human-readable reasons for a phishing classification. """
    reasons = []
    
    if content_type == 'url':
        if features.get('uses_ip') == 1:
            reasons.append("- Contains a numeric IP address instead of a domain name.")
        if features.get('has_https') == 0:
            reasons.append("- The connection is not secure (lacks HTTPS).")
        # --- Improved Reasons ---
        if features.get('subdomain_count', 0) > 3:
             reasons.append("- Uses an excessive number of subdomains, a common hiding tactic.")
        if features.get('path_length', 0) > 40:
             reasons.append("- Contains an unusually long path, potentially to hide the true destination.")

    if content_type in ['sms', 'email']:
        keyword_count = int(features.get('keyword_count', 0))
        if keyword_count > 0:
            reasons.append(f"- Contains {keyword_count} suspicious keyword(s) (e.g., 'urgent', 'verify', 'free').")
    
    if not reasons:
        reasons.append("- Its structure and patterns match examples of phishing the AI has learned from.")

    return reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    content = data.get('content')
    content_type = data.get('type')

    # Whitelist Check
    if content_type == 'url':
        try:
            domain = urlparse('http://' + content.replace('https://', '').replace('http://', '')).netloc.replace('www.', '')
            if domain in KNOWN_SAFE_DOMAINS:
                return jsonify({'status': 'Safe', 'content': content, 'reasons': [f"{domain} is a known and trusted domain."]})
        except Exception:
            pass

    if not model:
        return jsonify({'status': 'Error', 'content': content, 'reasons': ['AI model is not loaded.']})

    # AI Prediction
    try:
        features = extract_features(content, content_type)
        query_df = pd.DataFrame([features]).reindex(columns=model_columns, fill_value=0)
        
        prediction = model.predict(query_df)[0]
        result_status = "Phishing Warning" if prediction == 1 else "Safe"
        
        reasons = []
        if result_status == "Phishing Warning":
            reasons.extend(get_detailed_reasons(features, content_type))
        else:
            reasons.append("The model did not find common phishing patterns.")

        return jsonify({'status': result_status, 'content': content, 'reasons': reasons})
    
    except Exception as e:
        print(f"!!! PREDICTION ERROR: {e}")
        return jsonify({'status': 'Error', 'content': content, 'reasons': ['An error occurred during AI analysis.']})

if __name__ == '__main__':
    app.run(debug=True)