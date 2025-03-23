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

# Load your dataset
# Assuming X and y are your features and labels
X, y = ...  # Load your dataset here

# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Standardize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# SVM
svm = SVC(kernel='linear')
svm.fit(X_train, y_train)
y_pred_svm = svm.predict(X_test)
print("SVM Accuracy:", metrics.accuracy_score(y_test, y_pred_svm))
save_model(svm, 'svm_model.pkl')

# Random Forest
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)
print("Random Forest Accuracy:", metrics.accuracy_score(y_test, y_pred_rf))
save_model(rf, 'rf_model.pkl')

# Logistic Regression
lr = LogisticRegression()
lr.fit(X_train, y_train)
y_pred_lr = lr.predict(X_test)
print("Logistic Regression Accuracy:", metrics.accuracy_score(y_test, y_pred_lr))
save_model(lr, 'lr_model.pkl')

# CNN
X_train_cnn = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
X_test_cnn = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
cnn = Sequential([
    Conv1D(64, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], 1)),
    MaxPooling1D(pool_size=2),
    Flatten(),
    Dense(100, activation='relu'),
    Dense(len(np.unique(y)), activation='softmax')
])
cnn.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
cnn.fit(X_train_cnn, to_categorical(y_train), epochs=10, batch_size=32, verbose=1)
y_pred_cnn = cnn.predict(X_test_cnn)
print("CNN Accuracy:", metrics.accuracy_score(y_test, np.argmax(y_pred_cnn, axis=1)))
save_model(cnn, 'cnn_model.h5')

# RNN
rnn = Sequential([
    SimpleRNN(64, input_shape=(X_train.shape[1], 1)),
    Dense(len(np.unique(y)), activation='softmax')
])
rnn.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
rnn.fit(X_train_cnn, to_categorical(y_train), epochs=10, batch_size=32, verbose=1)
y_pred_rnn = rnn.predict(X_test_cnn)
print("RNN Accuracy:", metrics.accuracy_score(y_test, np.argmax(y_pred_rnn, axis=1)))
save_model(rnn, 'rnn_model.h5')

# LSTM
lstm = Sequential([
    LSTM(64, input_shape=(X_train.shape[1], 1)),
    Dense(len(np.unique(y)), activation='softmax')
])
lstm.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
lstm.fit(X_train_cnn, to_categorical(y_train), epochs=10, batch_size=32, verbose=1)
y_pred_lstm = lstm.predict(X_test_cnn)
print("LSTM Accuracy:", metrics.accuracy_score(y_test, np.argmax(y_pred_lstm, axis=1)))
save_model(lstm, 'lstm_model.h5')

# Quantum SVM with PennyLane
n_qubits = 4
dev = qml.device('default.qubit', wires=n_qubits)

@qml.qnode(dev)
def quantum_circuit(params, x):
    qml.templates.AngleEmbedding(x, wires=range(n_qubits))
    qml.templates.StronglyEntanglingLayers(params, wires=range(n_qubits))
    return [qml.expval(qml.PauliZ(i)) for i in range(n_qubits)]

def quantum_kernel(x1, x2, params):
    return np.dot(quantum_circuit(params, x1), quantum_circuit(params, x2))

params = np.random.randn(10, n_qubits, 3)

quantum_svm = SVC(kernel=lambda x1, x2: quantum_kernel(x1, x2, params))
quantum_svm.fit(X_train, y_train)
y_pred_qsvm = quantum_svm.predict(X_test)
print("Quantum SVM Accuracy:", metrics.accuracy_score(y_test, y_pred_qsvm))
save_model(quantum_svm, 'quantum_svm_model.pkl')
