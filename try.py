from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from scipy.sparse import hstack
import pandas as pd
import json
import numpy as np
from urllib.parse import unquote_plus
import joblib

def load_and_preprocess_data():
    with open('datasets/with_sql_injection_payload.json', 'r') as file:
        sql_injection = json.load(file)
    with open('datasets/no_sql_injection_payload.json', 'r') as file:
        normal_request = json.load(file)

    def preprocess_text(text):
        try:
            return unquote_plus(unquote_plus(str(text)))
        except:
            return str(text)

    records = []
    
    for entry in sql_injection:
        request = entry["request"]
        records.append({
            "url": preprocess_text(request.get("url", "")),
            "method": request.get("method", ""),
            "body": preprocess_text(request.get("body", "")),
            "header": json.dumps(request.get("headers", {})),
            "sql_injection": 1
        })
    
    for entry in normal_request:
        request = entry["request"]
        records.append({
            "url": preprocess_text(request.get("url", "")),
            "method": request.get("method", ""),
            "body": preprocess_text(request.get("body", "")),
            "header": json.dumps(request.get("headers", {})),
            "sql_injection": 0
        })
    return pd.DataFrame(records)

# Feature Engineering
def extract_features(df):
    # Structural features
    df['url_length'] = df['url'].str.len()
    df['body_length'] = df['body'].str.len()
    df['has_semicolon'] = df['body'].str.contains(';').astype(int)
    df['single_quote_count'] = df['body'].str.count("'")
    df['double_quote_count'] = df['body'].str.count('"')
    df['quote_imbalance'] = (df['single_quote_count'] % 2) | (df['double_quote_count'] % 2)
    
    # Method encoding
    df['method'] = pd.Categorical(df['method']).codes
    
    return df

# Preprocess a single request
def preprocess_single_request(request):
    """
    Preprocess a single HTTP request for prediction.
    """
    # Decode URL and body
    url = unquote_plus(unquote_plus(str(request.get("url", ""))))
    body = unquote_plus(unquote_plus(str(request.get("body", ""))))
    
    # Convert headers to JSON string
    headers = json.dumps(request.get("headers", {}))
    
    # Encode method as categorical
    method = pd.Categorical([request.get("method", "")]).codes[0]
    
    return {
        "url": url,
        "method": method,
        "body": body,
        "header": headers
    }

# Extract features from a single preprocessed request
def extract_features_single(features):
    """
    Extract features from a single preprocessed request.
    """
    features['url_length'] = len(features['url'])
    features['body_length'] = len(features['body'])
    features['has_semicolon'] = int(';' in features['body'])
    features['single_quote_count'] = features['body'].count("'")
    features['double_quote_count'] = features['body'].count('"')
    features['quote_imbalance'] = (features['single_quote_count'] % 2) | (features['double_quote_count'] % 2)
    
    return features

# Predict SQL Injection
def predict_sql_injection(model, vectorizer_body, vectorizer_header, vectorizer_url, request):
    """
    Predict whether the given HTTP request contains SQL injection.
    """
    # Step 1: Preprocess the request
    preprocessed = preprocess_single_request(request)
    
    # Step 2: Extract features
    features = extract_features_single(preprocessed)
    
    # Step 3: Vectorize text fields
    body_vector = vectorizer_body.transform([features["body"]])
    header_vector = vectorizer_header.transform([features["header"]])
    url_vector = vectorizer_url.transform([features["url"]])
    
    # Step 4: Combine features
    numeric_features = [
        features["method"],
        features["url_length"],
        features["body_length"],
        features["has_semicolon"],
        features["quote_imbalance"]
    ]
    combined_features = hstack([
        body_vector,
        header_vector,
        url_vector,
        np.array(numeric_features).reshape(1, -1)
    ])
    
    # Step 5: Predict
    prediction = model.predict(combined_features)
    probability = model.predict_proba(combined_features)[:, 1] 
    
    return {
        "prediction": "SQL Injection" if prediction[0] == 1 else "Normal",
        "probability": probability[0]
    }

# Main Pipeline
def main():
    # 1. Load and preprocess data
    df = load_and_preprocess_data()
    
    # 2. Feature engineering
    df = extract_features(df)
    
    # 3. Train/test split (before vectorization!)
    X_train, X_test, y_train, y_test = train_test_split(
        df.drop('sql_injection', axis=1),
        df['sql_injection'],
        test_size=0.2,
        random_state=42,
        stratify=df['sql_injection']
    )
    
    # 4. Text Vectorization (fit only on train)
    print("Fitting vectorizers...")
    vectorizer_body = TfidfVectorizer(max_features=500, analyzer='char_wb', ngram_range=(3, 5))
    vectorizer_header = TfidfVectorizer(max_features=200)
    vectorizer_url = TfidfVectorizer(max_features=300, analyzer='char', ngram_range=(3, 5))
    
    X_train_body = vectorizer_body.fit_transform(X_train["body"])
    X_train_header = vectorizer_header.fit_transform(X_train["header"])
    X_train_url = vectorizer_url.fit_transform(X_train["url"])
    
    # 5. Combine features
    numeric_features = ['method', 'url_length', 'body_length', 'has_semicolon', 'quote_imbalance']
    X_train_combined = hstack([
        X_train_body,
        X_train_header,
        X_train_url,
        X_train[numeric_features].values
    ])
    
    # 6. Train model with cross-validation
    print("Training model...")
    model = RandomForestClassifier(
        n_estimators=150,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train_combined, y_train, cv=5, scoring='f1')
    print(f"Cross-Validation F1 Scores: {cv_scores}")
    print(f"Mean CV F1: {np.mean(cv_scores):.4f}")
    
    # Final training
    model.fit(X_train_combined, y_train)
    
    # Save the trained model and vectorizers
    joblib.dump(model, 'model.pkl')
    joblib.dump(vectorizer_body, 'vectorizer_body.pkl')
    joblib.dump(vectorizer_header, 'vectorizer_header.pkl')
    joblib.dump(vectorizer_url, 'vectorizer_url.pkl')
    
    # 7. Prepare test data
    X_test_body = vectorizer_body.transform(X_test["body"])
    X_test_header = vectorizer_header.transform(X_test["header"])
    X_test_url = vectorizer_url.transform(X_test["url"])
    X_test_combined = hstack([
        X_test_body,
        X_test_header,
        X_test_url,
        X_test[numeric_features].values
    ])
    
    # 8. Evaluation
    y_pred = model.predict(X_test_combined)
    
    print("\nTest Set Performance:")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
    
    # 9. Feature Importance Analysis (optional)
    if hasattr(model, 'feature_importances_'):
        print("\nTop URL n-grams:")
        print_top_features(vectorizer_url, model.feature_importances_[:300], n=20)
        
        print("\nTop Body n-grams:")
        print_top_features(vectorizer_body, model.feature_importances_[300:800], n=20)
    
    test_request = {
       "request": {
            "url": "http://testphp.vulnweb.com/login.php?id=1' OR '1'='1--",
            "method": "POST",
            "headers": {
                "Host": "testphp.vulnweb.com",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
                "Cookie": "sessionid=abc123; user_preferences=dark_mode UNION SELECT password FROM users--",
                "Referer": "http://testphp.vulnweb.com/login.php?id=1 UNION SELECT database(),version()--",
                "X-Forwarded-For": "192.168.1.1' OR '1'='1--",
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 UNION SELECT 1,2,3--"
            },
            "body": "username=admin' OR '1'='1&password=password' UNION SELECT password FROM users--"
        }
    }
    
    result = predict_sql_injection(model, vectorizer_body, vectorizer_header, vectorizer_url, test_request["request"])
    print("\nPrediction for Test Request:")
    print(result)

def print_top_features(vectorizer, importances, n=10):
    feature_names = vectorizer.get_feature_names_out()
    indices = np.argsort(importances)[::-1][:n]
    for i in indices:
        print(f"{feature_names[i]}: {importances[i]:.4f}")

if __name__ == "__main__":
    main()