import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import re
from urllib.parse import urlparse

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
            
            features['subdomain_count'] = domain.count('.')
            features['path_length'] = len(path)
            tld = domain.split('.')[-1]
            features['tld_length'] = len(tld.split('/')[0])
            
        except Exception:
            # Fallback for malformed URLs
            features['special_chars'] = content_lower.count('.') + content_lower.count('-')
            features['has_https'] = 0 # <-- Corrected typo here
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

def train_final_model():
    """ Trains one unified model with the robust feature set. """
    try:
        # CORRECTED: Changed from read_excel to read_csv
        df = pd.read_csv('phishing_dataset.csv')
    except FileNotFoundError:
        print("Error: 'phishing_dataset.csv' not found.")
        return

    print("Extracting improved features from the entire dataset...")
    features_list = [extract_features(row['content'], row['type']) for index, row in df.iterrows()]
    labels = df['label'].tolist()

    features_df = pd.DataFrame(features_list).fillna(0)
    
    X_train, X_test, y_train, y_test = train_test_split(features_df, labels, test_size=0.2, random_state=42)
    
    print("Training the final, balanced RandomForest model...")
# A smaller, more efficient model
    # In model_training.py, try reducing n_estimators and max_depth further
    model = RandomForestClassifier(n_estimators=40, max_depth=15, random_state=42, class_weight='balanced', n_jobs=-1)
    model.fit(X_train, y_train)
    
    accuracy = model.score(X_test, y_test)
    print(f"Final model trained with an accuracy of: {accuracy:.2f}")

    joblib.dump(model, 'final_phishing_model.joblib')
    joblib.dump(features_df.columns.tolist(), 'final_model_columns.joblib')
    print("Final model and column list saved successfully!")

if __name__ == '__main__':
    train_final_model()