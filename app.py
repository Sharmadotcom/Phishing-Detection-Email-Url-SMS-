from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)

KNOWN_SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com', 
    'linkedin.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com', 
    'netflix.com', 'paypal.com', 'fleetcode.com'
}

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
    MUST BE IDENTICAL to the function in the training script.
    """
    features = {}
    content_lower = str(content).lower()

    features['length'] = len(content_lower)
    features['digit_count'] = sum(c.isdigit() for c in content_lower)

    if content_type == 'url':
        features['special_chars'] = content_lower.count('-') + content_lower.count('@') + content_lower.count('?') + content_lower.count('=')
        features['has_https'] = 1 if 'https' in content_lower else 0
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['uses_ip'] = 1 if re.search(ip_pattern, content_lower) else 0
    else:
        features['special_chars'] = 0
        features['has_https'] = 0
        features['uses_ip'] = 0
    
    if content_type in ['sms', 'email']:
        features['has_link'] = 1 if 'http' in content_lower or 'www' in content_lower else 0
        phishing_keywords = ['verify', 'account', 'suspended', 'urgent', 'winner', 'claim', 'free', 'password']
        features['keyword_count'] = sum(content_lower.count(keyword) for keyword in phishing_keywords)
    else:
        features['has_link'] = 0
        features['keyword_count'] = 0

    return features

def get_detailed_reasons(features, content_type):
    """
    Generates a list of human-readable reasons for a phishing classification based on features.
    """
    reasons = []
    
    if content_type == 'url':
        if features.get('uses_ip') == 1:
            reasons.append("- Contains a numeric IP address instead of a domain name.")
        if features.get('has_https') == 0:
            reasons.append("- The connection is not secure (lacks HTTPS).")
        if features.get('special_chars', 0) > 3:
            reasons.append("- High number of special characters, which can obscure the real domain.")
        if features.get('length', 0) > 75:
            reasons.append("- The URL is excessively long, a common tactic to hide the true destination.")

    if content_type in ['sms', 'email']:
        keyword_count = int(features.get('keyword_count', 0))
        if keyword_count > 0:
            reasons.append(f"- Contains {keyword_count} suspicious keyword(s) (e.g., 'urgent', 'verify', 'free').")
        if features.get('has_link') == 1:
            reasons.append("- Includes a link that requires careful inspection.")

    if not reasons:
         reasons.append("- The overall structure and patterns match examples of phishing the AI has learned from.")

    return reasons


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    content = data.get('content')
    content_type = data.get('type')

    if content_type == 'url':
        try:
            domain = urlparse('http://' + content.replace('https://', '').replace('http://', '')).netloc.replace('www.', '')
            if domain in KNOWN_SAFE_DOMAINS:
                return jsonify({'status': 'Safe', 'content': content, 'reasons': [f"{domain} is a known and trusted domain."]})
        except Exception:
            pass

    if not model:
        return jsonify({'status': 'Error', 'content': content, 'reasons': ['AI model is not loaded.']})

<<<<<<< HEAD
    # --- AI Prediction ---
    try:
        features = extract_features(content, content_type)
        query_df = pd.DataFrame([features], columns=model_columns).fillna(0)
        
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


from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)

# --- Whitelist of known safe domains ---
KNOWN_SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com', 
    'linkedin.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com', 
    'netflix.com', 'paypal.com', 'leetcode.com'
}

# --- Load the final, unified model ---
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
    MUST BE IDENTICAL to the function in the training script.
    """
    features = {}
    content_lower = str(content).lower()

    features['length'] = len(content_lower)
    features['digit_count'] = sum(c.isdigit() for c in content_lower)

    if content_type == 'url':
        features['special_chars'] = content_lower.count('-') + content_lower.count('@') + content_lower.count('?') + content_lower.count('=')
        features['has_https'] = 1 if 'https' in content_lower else 0
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['uses_ip'] = 1 if re.search(ip_pattern, content_lower) else 0
    else:
        features['special_chars'] = 0
        features['has_https'] = 0
        features['uses_ip'] = 0
    
    if content_type in ['sms', 'email']:
        features['has_link'] = 1 if 'http' in content_lower or 'www' in content_lower else 0
        phishing_keywords = ['verify', 'account', 'suspended', 'urgent', 'winner', 'claim', 'free', 'password']
        features['keyword_count'] = sum(content_lower.count(keyword) for keyword in phishing_keywords)
    else:
        features['has_link'] = 0
        features['keyword_count'] = 0

    return features

def get_detailed_reasons(features, content_type):
    """
    Generates a list of human-readable reasons for a phishing classification based on features.
    """
    reasons = []
    
    if content_type == 'url':
        if features.get('uses_ip') == 1:
            reasons.append("- Contains a numeric IP address instead of a domain name.")
        if features.get('has_https') == 0:
            reasons.append("- The connection is not secure (lacks HTTPS).")
        if features.get('special_chars', 0) > 3:
            reasons.append("- High number of special characters, which can obscure the real domain.")
        if features.get('length', 0) > 75:
            reasons.append("- The URL is excessively long, a common tactic to hide the true destination.")

    if content_type in ['sms', 'email']:
        keyword_count = int(features.get('keyword_count', 0))
        if keyword_count > 0:
            reasons.append(f"- Contains {keyword_count} suspicious keyword(s) (e.g., 'urgent', 'verify', 'free').")
        if features.get('has_link') == 1:
            reasons.append("- Includes a link that requires careful inspection.")

    # A fallback message if no specific rules were triggered but the model still flagged it
    if not reasons:
         reasons.append("- The overall structure and patterns match examples of phishing the AI has learned from.")

    return reasons


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    content = data.get('content')
    content_type = data.get('type')

    # --- Whitelist Check ---
    if content_type == 'url':
        try:
            domain = urlparse('http://' + content.replace('https://', '').replace('http://', '')).netloc.replace('www.', '')
            if domain in KNOWN_SAFE_DOMAINS:
                return jsonify({'status': 'Safe', 'content': content, 'reasons': [f"{domain} is a known and trusted domain."]})
        except Exception:
            pass

    if not model:
        return jsonify({'status': 'Error', 'content': content, 'reasons': ['AI model is not loaded.']})

    # --- AI Prediction ---
=======
>>>>>>> 991f396364eeb92dd1ccb9b79cbf00ecd8d95c74
    try:
        features = extract_features(content, content_type)
        query_df = pd.DataFrame([features], columns=model_columns).fillna(0)
        
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

