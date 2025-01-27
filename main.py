import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.model_selection import cross_val_score

X = [
    "admin' OR 1=1--",                                
    "'; DROP TABLE users;--",                            
    "| ls /etc/passwd",                                  
    "& ping -n 4 127.0.0.1",                            
    "admin' OR '1'='1' -- -",                            
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "password=secret123",                               
    "Authorization: Bearer eyJ0eXAiOiJKV1Qi...",        
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "/api/user/1234/delete",                             
    "../../../../etc/passwd",                            
    "/wp-admin",                                         
    "/.git/config",                                      
    "/phpinfo.php",                                      
    "<script>alert('XSS')</script>",                     
    "<img src=x onerror=alert(1)>",                      
    "javascript:eval('alert(1)')",                       
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAAA=",
    'O:4:"User":2:{s:4:"name";s:6:"Attacker";s:8:"isAdmin";b:1;}',
    "curl -A 'Apache-HttpClient/4.2 (UNAVAILABLE)'", 
    "Struts2 exploit: %{(#_='multipart/form-data').(...)",
    "user=admin\n[CRITICAL] Failed login",
    "normal-request-123",
    "/index.html",
    "search?q=weather",
    "search?q=bag&item=1&product=3",
    "search?q=kiannaquines&item=1&product=3",
    "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
]

y = [
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0,
]

def preprocess_text(text):
    text = text.lower()
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[^\w\s]', '', text)
    return text

X_processed = [preprocess_text(payload) for payload in X]

vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
X_features = vectorizer.fit_transform(X_processed)

X_train, X_test, y_train, y_test = train_test_split(X_features, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)


y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
scores = cross_val_score(model, X_features, y, cv=5, scoring='f1')

print("F1 scores:", scores)
print("Mean F1 score:", scores.mean())
print("Accuracy Score:", accuracy)

new_request = 'search?q=kiannaquines&item_count=12&product=3'
new_request_processed = preprocess_text(new_request)
prediction = model.predict(vectorizer.transform([new_request_processed]))
print("Block Request" if prediction == 1 else "Allow Request")