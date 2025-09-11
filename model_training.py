import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import re

def extract_features(content, content_type):
    """
    A single, robust function to extract features from any content type.
    """
    features = {}
    content_lower = str(content).lower()

    # General Features
    features['length'] = len(content_lower)
    features['digit_count'] = sum(c.isdigit() for c in content_lower)

    # URL-Specific Features
    if content_type == 'url':
        features['special_chars'] = content_lower.count('-') + content_lower.count('@') + content_lower.count('?') + content_lower.count('=')
        features['has_https'] = 1 if 'https' in content_lower else 0
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['uses_ip'] = 1 if re.search(ip_pattern, content_lower) else 0
    else:
        features['special_chars'] = 0
        features['has_https'] = 0
        features['uses_ip'] = 0
    
    # Text-Specific Features (SMS/Email)
    if content_type in ['sms', 'email']:
        features['has_link'] = 1 if 'http' in content_lower or 'www' in content_lower else 0
        phishing_keywords = ['verify', 'account', 'suspended', 'urgent', 'winner', 'claim', 'free', 'password']
        features['keyword_count'] = sum(content_lower.count(keyword) for keyword in phishing_keywords)
    else:
        features['has_link'] = 0
        features['keyword_count'] = 0

    return features

def train_final_model():
    """
    Trains one unified model with the robust feature set.
    """
    try:
        df = pd.read_csv('phishing_dataset.csv')
    except FileNotFoundError:
        print("Error: 'phishing_dataset.csv' not found. Please ensure it is in the correct folder.")
        return

    print("Extracting robust features from the entire dataset...")
    features_list = [extract_features(row['content'], row['type']) for index, row in df.iterrows()]
    labels = df['label'].tolist()

    features_df = pd.DataFrame(features_list).fillna(0)
    
    X_train, X_test, y_train, y_test = train_test_split(features_df, labels, test_size=0.2, random_state=42)
    
    print("Training the final, unified RandomForest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    accuracy = model.score(X_test, y_test)
    print(f"Final model trained with an accuracy of: {accuracy:.2f}")
    
    # Save the single model and its columns
    joblib.dump(model, 'final_phishing_model.joblib')
    joblib.dump(features_df.columns.tolist(), 'final_model_columns.joblib')
    print("Final model and column list saved successfully!")

if __name__ == '__main__':
    train_final_model()

