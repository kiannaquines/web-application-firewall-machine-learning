import re
import joblib
from pathlib import Path
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pandas as pd
class WAFModel:
    def __init__(self):
        self.model = Pipeline([
            ('features', FeatureUnion([
                ('char_ngrams', TfidfVectorizer(analyzer='char', ngram_range=(3, 5))),
                ('word_ngrams', TfidfVectorizer(analyzer='word', token_pattern=r'\S+')),
                ('specials', CountVectorizer(
                    analyzer='char', 
                    vocabulary=['=', '&', "*", '"', ';', '<', '>', '{', '}', '[', ']', '(', ')']
                ))
            ])),
            
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                class_weight='balanced',
                random_state=42
            ))
        ])
    
    def train(self, X, y):
        self.model.fit(X, y)
    
    def predict(self, text):
        return self.model.predict([text])[0]
    
    def save(self, path):
        joblib.dump(self.model, path)
    
    @classmethod
    def load(cls, path):
        instance = cls()
        instance.model = joblib.load(path)
        return instance

if __name__ == "__main__":
    
    df = pd.read_csv('./dataset/combined_dataset.csv')
    df.dropna(inplace=True)

    X = df['payload']
    y = df['label']
    
    waf = WAFModel()
    waf.train(X, y)
    waf.save('waf_model.joblib')
    
    payloads = [
        "admin' OR 1=1--",
        "'); DROP TABLE users;--",
        "1' UNION SELECT username, password FROM users--",
        "admin' OR '1'='1' -- -",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:eval('alert(1)')",
        "<svg/onload=alert(1)>",
        "../../../../etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "| ls /etc/passwd",
        "& ping -n 4 127.0.0.1",
        "; cat /etc/shadow",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        'O:4:"User":2:{s:4:"name";s:6:"Attacker";s:8:"isAdmin";b:1;}',
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "{{7*7}}",
        "${7*7}",
        "User-Agent: Mozilla/5.0\nX-Forwarded-For: 127.0.0.1",
        "search?q=weather",
        "search?q=bag&item=1&product=3",
        "search?q=kiannaquines&item=1&product=3",
        "/index.html",
        "/about-us",
        "/contact",
        "/products/shoes",
        "/api/users/123",
        "/api/products?category=electronics",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept: application/json",
        "id=12345",
        "page=2&limit=10",
        "sort=price&order=asc",        
        "username=john&password=secure123",
        "grant_type=password&client_id=webapp",        
        "filename=report.pdf",
        "content-type=image/png",        
        "/dashboard/",
        "/user/profile",
        "/checkout/cart"
    ]

    for payload in payloads:
        print("Prediction:", "BLOCK" if waf.predict(payload) else "ALLOW")