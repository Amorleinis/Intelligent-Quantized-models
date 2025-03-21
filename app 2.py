import streamlit as st
import numpy as np
import time
from utils.data_generator import generate_network_data
from utils.quantum_simulation import quantum_analysis_simulation

# Configure the page
st.set_page_config(
    page_title="Quantum AI Security Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state variables if they don't exist
if 'threat_level' not in st.session_state:
    st.session_state.threat_level = "Medium"
if 'alerts' not in st.session_state:
    from datetime import datetime
    current_time = datetime.now().strftime("%H:%M:%S")
    st.session_state.alerts = [
        {"time": current_time, "message": "Unusual authentication patterns detected from IP 192.168.1.45"},
        {"time": current_time, "message": "Possible phishing attempt targeting finance department"},
        {"time": current_time, "message": "Multiple failed login attempts on admin account"}
    ]
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
        st.metric("Quantum Security Score", f"{np.random.randint(85, 99)}/100", "+5")
    
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
        analysis_results = quantum_analysis_simulation(st.session_state.network_data)
        
        # Update threat level based on analysis
        st.session_state.threat_level = analysis_results["threat_level"]
        
        # Add any alerts
        if analysis_results["alerts"]:
            for alert in analysis_results["alerts"]:
                st.session_state.alerts.insert(0, {"time": time.strftime("%H:%M:%S"), "message": alert})
        
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
        for i, alert in enumerate(st.session_state.alerts[:5]):  # Show only the 5 most recent alerts
            with st.container():
                time_value = alert.get('time', datetime.now().strftime("%H:%M:%S"))
                message_value = alert if isinstance(alert, str) else alert.get('message', 'Unknown alert')
                
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
