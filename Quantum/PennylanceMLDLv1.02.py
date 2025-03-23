import pennylane as qml
from pennylane import numpy as np
from scikit-learn import metrics
from scikit-learn.model_selection import train_test_split
from scikit-learn.svm import SVC
from scikit-learn.ensemble import RandomForestClassifier
from scikit-learn.linear_model import LogisticRegression
from scikit-learn.preprocessing import StandardScaler
from scikit-learn.datasets import fetch_kddcup99, fetch_covtype, fetch_20newsgroups
from keras.models import Sequential, load_model
from keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, LSTM, SimpleRNN
from keras.utils import to_categorical
import joblib
import os

# Function to save models
def save_model(model, filename):
    if isinstance(model, Sequential):
        model.save(filename)
    else:
        joblib.dump(model, filename)

# Function to load models
def load_model_custom(filename):
    if filename.endswith('.h5'):
        return load_model(filename)
    else:
        return joblib.load(filename)

# Load datasets
def load_datasets():
    print("Loading datasets...")
    # Intrusion detection dataset (KDD Cup 1999)
    kddcup99 = fetch_kddcup99(subset='SA', percent10=True, random_state=42)
    X_detection, y_detection = kddcup99.data, kddcup99.target

    # Intrusion prevention dataset (Covertype)
    covertype = fetch_covtype()
    X_prevention, y_prevention = covertype.data, covertype.target

    # Intrusion response dataset (20 Newsgroups, as a proxy for response actions)
    newsgroups = fetch_20newsgroups(subset='all', categories=['sci.crypt', 'comp.security'], remove=('headers', 'footers', 'quotes'))
    from sklearn.feature_extraction.text import TfidfVectorizer
    vectorizer = TfidfVectorizer()
    X_response = vectorizer.fit_transform(newsgroups.data)
    y_response = newsgroups.target

    return (X_prevention, y_prevention), (X_detection, y_detection), (X_response, y_response)

def train_and_evaluate_model(X, y, model_type, model_name):
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Standardize features
    scaler = StandardScaler(with_mean=False) if model_type in ['CNN', 'RNN', 'LSTM'] else StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Train the model
    if model_type == 'SVM':
        model = SVC(kernel='linear')
        model.fit(X_train, y_train)
    elif model_type == 'RandomForest':
        model = RandomForestClassifier(n_estimators=100)
        model.fit(X_train, y_train)
    elif model_type == 'LogisticRegression':
        model = LogisticRegression()
        model.fit(X_train, y_train)
    elif model_type == 'CNN':
        X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
        X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
        model = Sequential([
            Conv1D(64, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], 1)),
            MaxPooling1D(pool_size=2),
            Flatten(),
            Dense(100, activation='relu'),
            Dense(len(np.unique(y)), activation='softmax')
        ])
        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        model.fit(X_train, to_categorical(y_train), epochs=10, batch_size=32, verbose=1)
    elif model_type == 'RNN':
        X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
        X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
        model = Sequential([
            SimpleRNN(64, input_shape=(X_train.shape[1], 1)),
            Dense(len(np.unique(y)), activation='softmax')
        ])
        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        model.fit(X_train, to_categorical(y_train), epochs=10, batch_size=32, verbose=1)
    elif model_type == 'LSTM':
        X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
        X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
        model = Sequential([
            LSTM(64, input_shape=(X_train.shape[1], 1)),
            Dense(len(np.unique(y)), activation='softmax')
        ])
        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        model.fit(X_train, to_categorical(y_train), epochs=10, batch_size=32, verbose=1)
    else:
        raise ValueError("Unsupported model type")

    # Evaluate the model
    y_pred = model.predict(X_test)
    if model_type in ['CNN', 'RNN', 'LSTM']:
        y_pred = np.argmax(y_pred, axis=1)
    print(f"{model_name} Accuracy:", metrics.accuracy_score(y_test, y_pred))

    # Save the model
    save_model(model, f'{model_name}.h5' if model_type in ['CNN', 'RNN', 'LSTM'] else f'{model_name}.pkl')

# Load datasets
(X_prevention, y_prevention), (X_detection, y_detection), (X_response, y_response) = load_datasets()

# Train and evaluate models for intrusion prevention
print("Training and evaluating models for intrusion prevention")
train_and_evaluate_model(X_prevention, y_prevention, 'SVM', 'svm_prevention')
train_and_evaluate_model(X_prevention, y_prevention, 'RandomForest', 'rf_prevention')
train_and_evaluate_model(X_prevention, y_prevention, 'LogisticRegression', 'lr_prevention')
train_and_evaluate_model(X_prevention, y_prevention, 'CNN', 'cnn_prevention')
train_and_evaluate_model(X_prevention, y_prevention, 'RNN', 'rnn_prevention')
train_and_evaluate_model(X_prevention, y_prevention, 'LSTM', 'lstm_prevention')

# Train and evaluate models for intrusion detection
print("Training and evaluating models for intrusion detection")
train_and_evaluate_model(X_detection, y_detection, 'SVM', 'svm_detection')
train_and_evaluate_model(X_detection, y_detection, 'RandomForest', 'rf_detection')
train_and_evaluate_model(X_detection, y_detection, 'LogisticRegression', 'lr_detection')
train_and_evaluate_model(X_detection, y_detection, 'CNN', 'cnn_detection')
train_and_evaluate_model(X_detection, y_detection, 'RNN', 'rnn_detection')
train_and_evaluate_model(X_detection, y_detection, 'LSTM', 'lstm_detection')

# Train and evaluate models for intrusion response
print("Training and evaluating models for intrusion response")
train_and_evaluate_model(X_response, y_response, 'SVM', 'svm_response')
train_and_evaluate_model(X_response, y_response, 'RandomForest', 'rf_response')
train_and_evaluate_model(X_response, y_response, 'LogisticRegression', 'lr_response')
train_and_evaluate_model(X_response, y_response, 'CNN', 'cnn_response')
train_and_evaluate_model(X_response, y_response, 'RNN', 'rnn_response')
train_and_evaluate_model(X_response, y_response, 'LSTM', 'lstm_response')
