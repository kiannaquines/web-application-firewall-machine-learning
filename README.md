## Web Application Firewall
<p>This is my optimized version of web application firewall using support vector machine algorithm.</p>

## Runtime Stack
<p>The repository now includes a runnable demo stack for serving the model in front of a Flask application:</p>

1. <b>Flask + Gunicorn :</b> `app.py` exposes demo routes, a health endpoint, and an internal authorization endpoint for edge checks.
2. <b>Nginx :</b> `nginx/default.conf` performs `auth_request` checks on request line and headers before proxying traffic to Flask.
3. <b>Hybrid protection :</b> Nginx performs the edge check and Flask performs the final body-aware inspection using the trained `WAFDetector`.
4. <b>Validation replay :</b> `validate_traffic.py` safely replays labeled requests against the protected app and summarizes blocking behavior.

## Quick Start
```bash
cp .env.example .env
docker compose up --build
```

<p>Once the stack is up:</p>

```bash
curl http://127.0.0.1:8080/healthz
curl "http://127.0.0.1:8080/search?q=hello"
curl -X POST http://127.0.0.1:8080/submit \
  -H "Content-Type: application/json" \
  -d '{"input":"admin'\'' OR 1=1 --"}'
```

```bash
.venv/bin/python validate_traffic.py \
  --mode batch \
  --base-url http://127.0.0.1:8080 \
  --input-file samples/validation_requests.json
```

```bash
.venv/bin/python validate_traffic.py \
  --mode batch \
  --base-url http://127.0.0.1:8080 \
  --input-file samples/advanced_validation_requests.json \
  --stream \
  --concurrency 5
```

## Limitation
<p>This only check the body and its parameters <b>AS OF NOW</b></p>

![Image](https://github.com/user-attachments/assets/bcfc600e-2abf-4630-ab0d-92dda118fb1e)
![Image](https://github.com/user-attachments/assets/005f57dd-d967-472d-89ce-84eb43d8c58d)

## Model
The model is designed to classify input payloads (e.g., strings of text) into predefined categories, such as "malicious" or "benign." It leverages a machine learning pipeline consisting of the following components:

1. <b>Feature Extraction :</b>
    The model uses TfidfVectorizer with character-level n-grams (analyzer='char') to transform raw text data into numerical feature vectors. This approach captures patterns in sequences of characters, making it suitable for tasks like detecting malicious payloads in web applications.

2. <b>Classification :</b>
    A Support Vector Machine (SVM) classifier is employed to perform the classification task. The SVM is configured with a radial basis function (RBF) kernel and optimized hyperparameters (C=10, ngram_range=(1, 4)) to achieve high accuracy on the dataset.

3. <b>Training Process :</b>
    The model was trained on a labeled dataset containing various types of payloads. The dataset was preprocessed to ensure consistency, and a stratified train-test split was used to evaluate performance.
    Hyperparameter tuning was performed using GridSearchCV to optimize key parameters such as ngram_range, C, and kernel.

4. <b>Performance :</b>
    The trained model demonstrates strong generalization capabilities, achieving high precision, recall, and F1 scores on the test set. A confusion matrix and classification report are available for detailed performance analysis.

5. <b>Deployment :</b>
    The trained model is serialized and saved as request_predictor.joblib. It can be loaded and used for real-time predictions via the WafDetector class, which handles payload parsing and prediction.


![Image](https://github.com/user-attachments/assets/f3bf7245-59e6-4a33-b6a7-868d21ec32f6)

# Result

![Image](https://github.com/user-attachments/assets/66984891-c76f-431f-97ee-9cb92a493b3d)

![Image](https://github.com/user-attachments/assets/83e8ee14-1615-45be-821e-5eed33829f51)
