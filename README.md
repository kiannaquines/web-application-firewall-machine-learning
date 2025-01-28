## Web Application Firewall
<p>This is my own version of implementing a wen application firewall using machine learning algorithms.</p>

![Image](https://github.com/user-attachments/assets/0f4e5ac3-c9bf-4524-ba1c-14a5cb99697f)
![Image](https://github.com/user-attachments/assets/cf4991c8-c930-4cf5-b198-533629cb175f)

## Model
<p>Fitting the model in each algorithm takes <b>4 hours</b> because of crappy specs of my laptop (CPU Based). It was so slow in fitting since the dataset that the model was trained has 100k+ records no GPU. 😅</p>
<p>The model was trained on both DecisionTreeClassifier & RandomForest, each algorithm got there own accuracy score.</p>

![Image](https://github.com/user-attachments/assets/167fe288-6674-47d1-a71e-427b866446e2)


# Result

![Image](https://github.com/user-attachments/assets/1b9ec1fa-a955-4597-b81e-fd03b3857a89)
<p>Out of 222 sql injection payload request 6 are missed to block the request.</p>

![Image](https://github.com/user-attachments/assets/d9e6cd97-8a1b-47e0-894e-986dbc387872)

<p>Out of 64 normal request 2 are missed to allow the request.</p>


![Image](https://github.com/user-attachments/assets/9109e76b-0cee-44c6-b9ac-5c33d53e7e4e)


## Take Aways

1. Since some of the payloads are missed in classifiying whether the request is Malicious or Not we must include the missed payload in the training and testing phase.

2. We can use RNN or CNN for this web application firewall.


## Future Plan


1. Integrate a Web Dashboard
2. Implement using Neural Network
