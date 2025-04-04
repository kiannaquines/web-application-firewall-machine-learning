## Web Application Firewall
<p>This is my own version of implementing a web application firewall using machine learning algorithm.</p>

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