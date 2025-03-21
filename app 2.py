import streamlit as st
import numpy as np
import time
from utils.data_generator import generate_network_data
from utils.quantum_simulation import quantum_analysis_simulation
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.datasets import make_classification
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifie
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression

class MachineLearningAI:
  
  def MLPCLassifier():
    if self.classifier=None 'param_grid=None", self.param_grid = p


        def generate_dataset(self, n_samples=100, n_features=20, test_size=0.25, random_state=42):
        X, y = make_classification(n_samples=n_samples, n_features=n_features, n_informative=2, n_classes=2, random_state=random_state)
        return train_test_split(X, y, test_size=test_size, random_state=random_state)

        def configure_pipeline(self, steps):
        self.pipeline = Pipeline(steps)

        def generate_and_train_classifier(self, X_train, y_train, cv=5):
        if self.pipeline is None:

            self.configure_pipeline([('scaler', StandardScaler()), ('poly', PolynomialFeatures()), ('classifier', self.classifier)])
        if self.param_grid is not None:
            self.grid_search = GridSearchCV(self.pipeline,
            self.param_grid, cv=cv, n_jobs=-1)
            self.grid_search.fit(X_train, y_train)
            print(f'Best parameters found: {self.grid_search.best_params_}')
            self.best_params = self.grid_search.best_params_
            self.pipeline = self.grid_search.best_estimator_
        else:
            scores = cross_val_score(self.pipeline, X_train, y_train, cv=cv, n_jobs=-1)
            self.pipeline.fit(X_train, y_train)
            return np.mean(scores)

    def evaluate_classifier(self, X_test, y_test):
        y_pred = self.pipeline.predict(X_test)
        print(classification_report(y_test, y_pred))
        print(confusion_matrix(y_test, y_pred))
        return accuracy_score(y_test, y_pred)

    def save_model(self, filename):
        joblib.dump(self.pipeline, filename)
        print(f'Model saved to {filename}')

    def load_model(self, filename):
        self.pipeline = joblib.load(filename)
        print(f'Model loaded from {filename}')

# Set up classifiers and parameter grids to use
        classifier_params = {
    'MLP': (MLPClassifier(), {
        'classifier__hidden_layer_sizes': [(50,), (100,)],
        'classifier__activation': ['tanh', 'relu', 'logistic',],
        'classifier__solver': ['sgd', 'adam', 'lbfgs'],
        'classifier__alpha': [0.0001, 0.05],
        'classifier__learning_rate': ['constant','adaptive', 'invscaling'],
        'classifier__learning_rate_init': [0.001, 0.01, 0.1],
        'classifier__max_iter': [100, 1000],
        'classifier__momentum': [0.9, 0.99],
        'classifier__nesterovs_momentum': [True, False],
        'classifier__early_stopping': [True, False],
        'classifier__validation_fraction': [0.1, 0.2],
        'classifier__beta_1': [0.9, 0.99],
        'classifier__beta_2': [0.9, 0.99],
        'classifier__epsilon': [1e-08, 1e-07],
        'classifier__n_iter_no_change': [10, 20, 30],
    }),
    'Decision Tree': (DecisionTreeClassifier(), {
        'classifier__max_depth': [None, 10, 20, 30],
        'classifier__min_samples_split': [2, 5, 10],
        'classifier__min_samples_leaf': [1, 2, 4],
        'classifier__min_weight_fraction_leaf': [0.0, 0.1, 0.2],
        'classifier__criterion': ['gini', 'entropy']
    }),
    'Random Forest': (RandomForestClassifier(), {
        'classifier__n_estimators': [50, 100, 200],
        'classifier__max_features': ['auto', 'sqrt', 'log2'],
        'classifier__max_depth': [None, 5, 10, 15, 20],
        'classifier__min_samples_split': [2, 5, 10],
    }),
    'SVM': (SVC(), {
        'classifier__C': [0.1, 1, 10],
        'classifier__gamma': ['scale', 'auto', 0.001, 0.01, 0.1, 1],
        'classifier__kernel': ['linear', 'rbf', 'poly', 'sigmoid'],
    }),
    'Logistic Regression': (LogisticRegression(), {
        'classifier__C': [0.1, 1, 10, 100],
        'classifier__penalty': ['l1', 'l2'],
        'classifier__solver': ['adam', 'newton-cg', 'lbfgs', 'liblinear' 'sag', 'saga'],
    })}

    def save_best_models(classifier_params):
    for name, (clf, params) in classifier_params.items():
        print(f'\nTraining and evaluating {name}')
        ai = MachineLearningAI(classifier=clf, param_grid=params)
        X_train, X_test, y_train, y_test = ai.generate_dataset()

        ai.generate_and_train_classifier(X_train, y_train)
        accuracy = ai.evaluate_classifier(X_test, y_test)
        print(f'{name} Model Accuracy: {accuracy}')

        # Save the best model
        model_file = f'best_{name.lower().replace(" ", "_")}_model.joblib'
        ai.save_model(model_file)


# Call the function to save the best models
save_best_models(classifier_params)

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping


class DeepLearningAI(MachineLearningAI):

    def __init__(self, classifier=None, param_grid=None):
        super().__init__(classifier, param_grid)

    def configure_deep_learning_model(self, input_dim):
        self.classifier = Sequential([
            Dense(128, input_dim=input_dim, activation='relu'),
            Dense(64, activation='relu'),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid'),
        ])
        self.classifier.compile(optimizer=Adam(), loss='binary_crossentropy', metrics=['accuracy'])

    def train_deep_learning_model(self, X_train, y_train, epochs=10240, batch_size=10):
        self.classifier.fit(X_train, y_train, epochs=epochs, batch_size=batch_size)

    def evaluate_deep_learning_model(self, X_test, y_test):
        evaluation = self.classifier.evaluate(X_test, y_test)
        return evaluation

# Integration into the existing workflow
def train_and_save_deep_learning_model():
    ai = DeepLearningAI()
    X_train, X_test, y_train, y_test = ai.generate

ai.configure_deep_learning_model(input_dim=20)
ai.train_deep_learning_model(X_train, y_train, epochs=10240, batch_size=10)
accuracy = ai.evaluate_deep_learning_model(X_test, y_test)
print

evaluation = ai.evaluate_deep_learning_model(X_test, y_test)
print(f'Deep Learning Model Accuracy: {evaluation[1]}')

    # Save the deep learning model
model_file = 'deep_learning_model.h5'
ai.classifier.save(model_file)
print(f'Model saved to {model_file}')

# Call the function to train and save the deep learning model
train_and_save_deep_learning_model()


import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report

# Load pre-labeled network traffic data (features and whether traffic was normal or an attack/anomaly)
network_data = pd.read_csv('network_traffic_data.csv')

# Features in the dataset
X = network_data.drop('label', axis=1)  # 'label' column has the anomaly labels
# Labels (0 for normal traffic, 1 for anomaly/attack)
y = network_data['label']

# Split dataset into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

# Initialize the model
model = RandomForestClassifier(n_estimators=100, random_state=0)

# Train the model
model.fit(X_train, y_train)

# Predict on test data
y_pred = model.predict(X_test)

# Evaluate the model
cm = confusion_matrix(y_test, y_pred)
report = classification_report(y_test, y_pred)
print("Confusion Matrix:")
print(cm)
print("Classification Report:")
print(report)

def chat_with_model(model, X_test):
    print("Chat with the model:")
    while True:
        user_input = input("You: ").strip()

        if user_input.lower() == 'exit':
            print("Model Chat: Goodbye! See you later!")
            break

        # Process user input (you might need to preprocess the input based on the model input requirements)
        user_input_features = process_user_input(user_input)

        # Use the model to predict a response
        model_response = model.predict(user_input_features)

        print("Model Chat:", model_response)

        def process_user_input(user_input):
            # Perform any necessary preprocessing on the user input to convert it into features for the model
            # This might involve tokenization, encoding, feature extraction, etc.
            # Return the processed features
            processed_input = preprocess_user_input(user_input)
        return processed_input
        
         # Configure the page
        st.set_page_config(
            page_title="Quantum AI Security Dashboard",
            page_icon="🔐",
            layout="wide",
            initial_sidebar_state="expanded"
         # Initialize session state variables if they don't exist
         if 'threat_level' not in st.session_state:
             st.session_state.threat_level = "Medium"
         if 'alerts' not in st.session_state:
         from datetime import datetime
             current_time = datetime.now().strftime("%H:%M:%S")
             st.session_state.alerts = [
                 {"time": current_time,
                  "message": "Unusual authentication patterns detected from IP 192.168.1.45"},
                 {"time": current_time,
                  "message": "Possible phishing attempt targeting finance department"},
                 {"time": current_time, "message": "Multiple failed login attempts on admin account"},
                 ])
         if 'network_data' not in st.session_state:
             network_data = generate_network_data(num_nodes=75, num_connections=120)
             st.session_state.network_data = network_data
         if 'analysis_running' not in st.session_state:
             st.session_state.analysis_running = False
         if 'last_analysis' not in st.session_state:
         from datetime import datetime
             st.session_state.last_analysis = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Main header
st.title("🔐 Quantum AI Security Dashboard")
st.subheader("Advanced Network Protection System")

# Main dashboard layout
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("System Status")

    # Status metrics
    metrics_col1, metrics_col2, metrics_col3 = st.columns(3)

    with metrics_col1:
        threat_color = {
            "Low": "green",
            "Medium": "orange",
            "High": "red",
            "Critical": "darkred"
        }
        st.metric("Threat Level", st.session_state.threat_level,
                  delta=None)

    with metrics_col2:
        st.metric("Protected Nodes", f"{np.random.randint(95, 100)}%", "+2%")

    with metrics_col3:
        st.metric("Quantum Security Score",
                  f"{np.random.randint(85, 99)}/100", "+5")

    # Run quantum analysis button
    if st.button("Run Quantum Analysis"):
        st.session_state.analysis_running = True

        # Create a progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()

        # Simulate processing with progress updates
        for i in range(101):
            progress_bar.progress(i)
            if i < 30:
                status_text.text(f"Initializing quantum circuits... ({i}%)")
            elif i < 60:
                status_text.text(f"Analyzing network patterns... ({i}%)")
            elif i < 90:
                status_text.text(f"Processing threat indicators... ({i}%)")
            else:
                status_text.text(f"Finalizing results... ({i}%)")
            time.sleep(0.05)

        # Update the network data and potentially detect threats
        st.session_state.network_data = generate_network_data()
        analysis_results = quantum_analysis_simulation(
            st.session_state.network_data)

        # Update threat level based on analysis
        st.session_state.threat_level = analysis_results["threat_level"]

        # Add any alerts
        if analysis_results["alerts"]:
            for alert in analysis_results["alerts"]:
                st.session_state.alerts.insert(
                    0, {"time": time.strftime("%H:%M:%S"), "message": alert})

        status_text.text("Analysis complete!")
        st.session_state.analysis_running = False
        st.session_state.last_analysis = time.strftime("%Y-%m-%d %H:%M:%S")

        # Force a rerun to update all components with new data
        st.rerun()

with col2:
    st.subheader("Recent Alerts")

    if not st.session_state.alerts:
        st.info("No recent alerts detected.")
    else:
        # Show only the 5 most recent alerts
        for i, alert in enumerate(st.session_state.alerts[:5]):
            with st.container():
                time_value = alert.get(
                    'time', datetime.now().strftime("%H:%M:%S"))
                message_value = alert if isinstance(
                    alert, str) else alert.get('message', 'Unknown alert')

                if isinstance(alert, dict) and 'time' in alert and 'message' in alert:
                    st.markdown(f"**{alert['time']}**: {alert['message']}")
                else:
                    st.markdown(f"**{time_value}**: {message_value}")

                if i < len(st.session_state.alerts) - 1:
                    st.divider()

# Additional dashboard sections
st.subheader("Network Overview")
st.write("Real-time visualization of network traffic and potential threats.")

# Last analysis timestamp
if st.session_state.last_analysis:
    st.caption(f"Last analysis: {st.session_state.last_analysis}")

# Info about available pages
st.markdown("""
## Available Sections
Use the sidebar to navigate between different sections of the dashboard:

- **Dashboard**: Main overview (current page)
- **Threats**: Detailed threat detection and analysis
- **Advanced Threat Analysis**: AI-powered network pattern analysis
- **Image Analysis**: Visual security threat detection
- **Mitigation Strategies**: Detailed recommendations for handling security threats
- **Isolation**: Network isolation and containment measures
- **Recovery**: System recovery recommendations
- **Education**: Learn about quantum security concepts
- **Security AI Chat**: Ask questions about cybersecurity
""")

# Footer with disclaimer
st.markdown("---")
st.caption("Disclaimer: This is a simulated security dashboard and does not use actual quantum computing technologies. It is intended for educational and demonstration purposes only.")
- **Education**: Learn about quantum security concepts
- **Security AI Chat**: Ask questions about cybersecurity
""")

# Footer with disclaimer
st.markdown("---")
st.caption("Disclaimer: This is a simulated security dashboard and does not use actual quantum computing technologies. It is intended for educational and demonstration purposes only.")
