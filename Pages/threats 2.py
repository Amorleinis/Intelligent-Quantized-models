import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import time
from datetime import datetime, timedelta

from utils.data_generator import generate_threat_data
from utils.network_visualization import create_threat_heatmap
from utils.ml_models import anomaly_detection
from utils.quantum_simulation import quantum_analysis_simulation

def app():
    """Threat detection and analysis page."""
    st.title("🔍 Threat Detection")
    st.markdown("Advanced threat analysis and anomaly detection with simulated quantum computing")
    
    # Initialize data if not already present
    if 'threat_data' not in st.session_state:
        st.session_state.threat_data = generate_threat_data(num_threats=10)
        
    if 'network_data' not in st.session_state:
        from utils.data_generator import generate_network_data
        st.session_state.network_data = generate_network_data()
    
    if 'anomalies' not in st.session_state:
        st.session_state.anomalies = anomaly_detection(st.session_state.network_data)
    
    # Top controls row
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Threat Detection Controls")
        
        detection_mode = st.radio(
            "Select Detection Mode",
            options=["Standard", "Enhanced (Quantum-Simulated)", "Automatic"],
            horizontal=True
        )
    
    with col2:
        refresh_col1, refresh_col2 = st.columns(2)
        
        with refresh_col1:
            if st.button("Refresh Data"):
                with st.spinner("Refreshing threat data..."):
                    time.sleep(1)
                    st.session_state.threat_data = generate_threat_data(num_threats=10)
                    st.rerun()
        
        with refresh_col2:
            if st.button("Run Analysis"):
                with st.spinner(f"Running {'quantum-enhanced' if detection_mode=='Enhanced (Quantum-Simulated)' else 'standard'} analysis..."):
                    # Create a progress bar
                    progress_bar = st.progress(0)
                    for i in range(101):
                        time.sleep(0.02)
                        progress_bar.progress(i)
                    
                    # Run analysis
                    st.session_state.anomalies = anomaly_detection(st.session_state.network_data)
                    
                    if detection_mode == "Enhanced (Quantum-Simulated)":
                        analysis_results = quantum_analysis_simulation(st.session_state.network_data)
                        st.session_state.quantum_analysis = analysis_results
                    
                    st.success("Analysis complete!")
    
    # Threat visualization section
    st.subheader("Threat Distribution")
    
    # Create the threat heatmap
    threat_heatmap = create_threat_heatmap(st.session_state.threat_data)
    st.plotly_chart(threat_heatmap, use_container_width=True)
    
    # Anomaly detection results
    st.subheader("Detected Anomalies")
    
    if not st.session_state.anomalies:
        st.info("No anomalies detected in the current dataset.")
    else:
        # Convert anomalies to DataFrame for better display
        anomalies_df = pd.DataFrame(st.session_state.anomalies)
        
        # Add a severity column based on anomaly score (lower is more anomalous)
        if 'anomaly_score' in anomalies_df.columns:
            def get_severity(score):
                if score < -0.5:
                    return "Critical"
                elif score < -0.3:
                    return "High"
                elif score < -0.1:
                    return "Medium"
                else:
                    return "Low"
            
            anomalies_df['severity'] = anomalies_df['anomaly_score'].apply(get_severity)
        else:
            anomalies_df['severity'] = "Medium"  # Default if no score
        
        # Display the anomalies table
        st.dataframe(
            anomalies_df,
            column_config={
                "source_ip": st.column_config.Column("Source IP", help="Source IP address"),
                "target_ip": st.column_config.Column("Target IP", help="Target IP address"),
                "connection_type": st.column_config.Column("Protocol", help="Connection protocol"),
                "traffic_volume": st.column_config.Column("Traffic", help="Traffic volume"),
                "risk_score": st.column_config.NumberColumn("Risk Score", help="Risk assessment score", format="%.1f"),
                "anomaly_score": st.column_config.NumberColumn("Anomaly Score", help="Anomaly detection score (lower is more anomalous)", format="%.3f"),
                "severity": st.column_config.Column("Severity", help="Anomaly severity classification")
            },
            hide_index=True,
            use_container_width=True
        )
    
    # Threat details section
    st.subheader("Detailed Threat Analysis")
    
    # Display threat data table with more details
    if st.session_state.threat_data.empty:
        st.warning("No threats detected in the current dataset.")
    else:
        # Advanced filtering
        filter_col1, filter_col2, filter_col3 = st.columns(3)
        
        with filter_col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=[]
            )
        
        with filter_col2:
            status_filter = st.multiselect(
                "Filter by Status",
                options=["Mitigated", "In Progress", "Detected", "Failed"],
                default=[]
            )
        
        with filter_col3:
            type_filter = st.multiselect(
                "Filter by Threat Type",
                options=sorted(st.session_state.threat_data["Type"].unique()),
                default=[]
            )
        
        # Apply filters
        filtered_df = st.session_state.threat_data.copy()
        
        if severity_filter:
            filtered_df = filtered_df[filtered_df["Severity"].isin(severity_filter)]
        
        if status_filter:
            filtered_df = filtered_df[filtered_df["Status"].isin(status_filter)]
        
        if type_filter:
            filtered_df = filtered_df[filtered_df["Type"].isin(type_filter)]
        
        # Display the filtered table
        st.dataframe(
            filtered_df,
            column_config={
                "Timestamp": st.column_config.DatetimeColumn("Time", format="MMM DD, YYYY, HH:mm:ss"),
                "Source": st.column_config.Column("Source IP", help="Source of the threat"),
                "Target": st.column_config.Column("Target IP", help="Target of the threat"),
                "Type": st.column_config.Column("Threat Type", help="Classification of the threat"),
                "Severity": st.column_config.Column("Severity", help="Threat severity level"),
                "Status": st.column_config.Column("Status", help="Current mitigation status")
            },
            hide_index=True,
            use_container_width=True
        )
    
    # Enhanced quantum analysis results (if available)
    if detection_mode == "Enhanced (Quantum-Simulated)" and 'quantum_analysis' in st.session_state:
        st.subheader("Quantum-Enhanced Analysis Results")
        
        results = st.session_state.quantum_analysis
        
        # Display threat level
        threat_level = results.get('threat_level', 'Unknown')
        level_color = {
            'Low': 'green',
            'Medium': 'orange',
            'High': 'red',
            'Critical': 'darkred'
        }.get(threat_level, 'blue')
        
        st.markdown(f"**Overall Threat Level:** <span style='color:{level_color}'>{threat_level}</span>", unsafe_allow_html=True)
        
        # Display scenarios analyzed
        if 'scenarios' in results:
            st.markdown("**Analysis Scenarios:**")
            for scenario in results['scenarios']:
                st.markdown(f"- {scenario}")
        
        # Display alerts
        if results.get('alerts'):
            st.markdown("**Detected Issues:**")
            for alert in results['alerts']:
                st.warning(alert)
        else:
            st.success("No critical issues detected in quantum analysis.")
    
    # MITRE ATT&CK framework information (educational)
    with st.expander("About Threat Classification", expanded=False):
        st.markdown("""
        ### MITRE ATT&CK Framework
        
        The threats displayed in this dashboard are classified according to concepts similar to the MITRE ATT&CK framework, 
        a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
        
        Common threat categories include:
        
        - **Initial Access**: How attackers get into your network
        - **Execution**: Running malicious code
        - **Persistence**: Maintaining access
        - **Privilege Escalation**: Gaining higher-level permissions
        - **Defense Evasion**: Avoiding detection
        - **Credential Access**: Stealing passwords and access keys
        - **Discovery**: Learning about the environment
        - **Lateral Movement**: Moving through the network
        - **Collection**: Gathering data of interest
        - **Exfiltration**: Stealing data
        - **Command and Control**: Communicating with compromised systems
        
        In a quantum computing context, new threat vectors emerge related to the potential breaking of cryptographic systems.
        """)
    
    # Disclaimer about the simulation
    st.caption("Note: This is a simulated security dashboard for educational purposes. The 'quantum' analysis is a simulation and does not use actual quantum computing technologies.")

if __name__ == "__main__":
    app()
