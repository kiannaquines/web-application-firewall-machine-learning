import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

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
    "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
]

y = [
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0
]

vectorizer = TfidfVectorizer(ngram_range=(1, 2))
X_features = vectorizer.fit_transform(X)

model = LogisticRegression()
model.fit(X_features, y)

new_request = 'search?q=%kiannaquines%'
prediction = model.predict(vectorizer.transform([new_request]))
print("Block Request" if prediction == 1 else "Allow Request")