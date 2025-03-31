import re
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Embedding, SimpleRNN, Dense, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

class WAFModelRNN:
    def __init__(self, max_vocab_size=10000, max_sequence_length=100):
        self.max_vocab_size = max_vocab_size
        self.max_sequence_length = max_sequence_length
        self.tokenizer = Tokenizer(num_words=max_vocab_size, char_level=True)
        self.model = self._build_model()
    
    def _build_model(self):
        model = Sequential([
            Embedding(input_dim=self.max_vocab_size, output_dim=64, 
                     input_length=self.max_sequence_length),
            SimpleRNN(64, return_sequences=False),
            Dropout(0.5),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(optimizer='adam',
                     loss='binary_crossentropy',
                     metrics=['accuracy'])
        return model
    
    def preprocess_text(self, text):
        # Basic preprocessing - preserve special characters
        text = str(text).lower()
        text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
        return text
    
    def train(self, X, y, epochs=10, batch_size=32, validation_split=0.2):
        # Preprocess texts
        X_processed = [self.preprocess_text(text) for text in X]
        
        # Tokenize and pad sequences
        self.tokenizer.fit_on_texts(X_processed)
        X_seq = self.tokenizer.texts_to_sequences(X_processed)
        X_pad = pad_sequences(X_seq, maxlen=self.max_sequence_length)
        
        # Convert y to numpy array
        y = np.array(y)
        
        # Train the model
        self.model.fit(X_pad, y, 
                      epochs=epochs, 
                      batch_size=batch_size,
                      validation_split=validation_split)
    
    def predict(self, text):
        # Preprocess the text
        processed_text = self.preprocess_text(text)
        
        # Tokenize and pad
        seq = self.tokenizer.texts_to_sequences([processed_text])
        padded = pad_sequences(seq, maxlen=self.max_sequence_length)
        
        # Make prediction
        prediction = self.model.predict(padded)[0][0]
        return 1 if prediction > 0.5 else 0
    
    def save(self, model_path, tokenizer_path):
        # Save model and tokenizer
        self.model.save(model_path)
        joblib.dump(self.tokenizer, tokenizer_path)
    
    @classmethod
    def load(cls, model_path, tokenizer_path):
        # Create instance
        instance = cls()
        
        # Load model and tokenizer
        instance.model = load_model(model_path)
        instance.tokenizer = joblib.load(tokenizer_path)
        
        return instance

if __name__ == "__main__":
    # Load dataset
    df = pd.read_csv('./dataset/combined_dataset.csv')
    df.dropna(inplace=True)
    
    X = df['payload']
    y = df['label']
    
    # Initialize and train RNN model
    waf_rnn = WAFModelRNN(max_vocab_size=5000, max_sequence_length=200)
    waf_rnn.train(X, y, epochs=15, batch_size=64)
    
    # Save the model
    waf_rnn.save('waf_rnn_model.h5', 'waf_rnn_tokenizer.joblib')
    
    # Test payloads
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

    # Test predictions
    for payload in payloads:
        prediction = waf_rnn.predict(payload)
        print(f"Payload: {payload[:50]}... -> {'BLOCK' if prediction == 1 else 'ALLOW'}")