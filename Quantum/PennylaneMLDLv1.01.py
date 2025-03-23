import pennylane as qml
from pennylane import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
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

# Load your datasets
# Assuming X_prevention, y_prevention, X_detection, y_detection, X_response, y_response are your features and labels for each dataset
X_prevention, y_prevention = ...  # Load your prevention dataset here
X_detection, y_detection = ...  # Load your detection dataset here
X_response, y_response = ...  # Load your response dataset here

def train_and_evaluate_model(X, y, model_type, model_name):
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Standardize features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Train the model
    if model_type == 'SVM':
        model = SVC(kernel='linear')
    elif model_type == 'RandomForest':
        model = RandomForestClassifier(n_estimators=100)
    elif model_type == 'LogisticRegression':
        model = LogisticRegression()
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
