import streamlit as st
import plotly.express as px
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import time

from utils.data_generator import generate_network_data, generate_threat_data
from utils.network_visualization import create_network_graph, create_traffic_timeline, create_risk_gauge
from utils.ml_models import predict_threat_probability
from utils.quantum_simulation import quantum_analysis_simulation

def app():
    """Main dashboard page function."""
    st.title("🔐 Security Dashboard")
    st.markdown("Real-time monitoring and threat detection powered by simulated quantum AI")
    
    # Initialize data if not already present
    if 'dashboard_network_data' not in st.session_state:
        st.session_state.dashboard_network_data = generate_network_data()
    
    if 'dashboard_threat_data' not in st.session_state:
        st.session_state.dashboard_threat_data = generate_threat_data()
    
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Security metrics at the top
    col1, col2, col3, col4 = st.columns(4)
    
    # Predict threat probability from the data
    threat_prediction = predict_threat_probability(st.session_state.dashboard_network_data)
    threat_level = threat_prediction['threat_level']
    
    # Set color based on threat level
    threat_color = {
        "Low": "green",
        "Medium": "orange",
        "High": "red",
        "Critical": "darkred"
    }
    
    with col1:
        st.metric(
            "Threat Level", 
            threat_level,
            delta=None
        )
    
    with col2:
        # Count detected vulnerabilities
        suspicious_connections = sum(1 for conn in st.session_state.dashboard_network_data['connections'] if conn['is_suspicious'])
        st.metric("Detected Vulnerabilities", suspicious_connections)
    
    with col3:
        # Compute security score (higher is better)
        security_score = 100 - (threat_prediction['overall_probability'] * 100)
        st.metric("Security Score", f"{security_score:.1f}/100")
    
    with col4:
        # Display time since last refresh
        st.metric("Last Refresh", st.session_state.last_refresh)
    
    # Network visualization
    st.subheader("Network Visualization")
    
    # Row for visualization controls
    control_col1, control_col2 = st.columns([3, 1])
    
    with control_col2:
        # Button to refresh data
        if st.button("Refresh Data"):
            with st.spinner("Refreshing network data..."):
                # Simulate processing time
                time.sleep(1)
                
                # Generate new data
                st.session_state.dashboard_network_data = generate_network_data()
                st.session_state.dashboard_threat_data = generate_threat_data()
                st.session_state.last_refresh = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Success message
                st.success("Data refreshed!")
    
    # Display network graph
    network_graph = create_network_graph(st.session_state.dashboard_network_data)
    st.plotly_chart(network_graph, use_container_width=True)
    
    # Display traffic timeline
    traffic_timeline = create_traffic_timeline(st.session_state.dashboard_network_data)
    st.plotly_chart(traffic_timeline, use_container_width=True)
    
    # Create two columns for threat analysis
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Recent Security Events")
        
        # Display the threat data table
        if st.session_state.dashboard_threat_data.empty:
            st.info("No security events detected in the current time period.")
        else:
            # Format the table
            styled_df = st.session_state.dashboard_threat_data.copy()
            
            # Add color-coding for severity
            def color_severity(val):
                colors = {
                    'Low': 'background-color: #e6f7e6',
                    'Medium': 'background-color: #fff7e6',
                    'High': 'background-color: #ffe6e6',
                    'Critical': 'background-color: #ffcccc'
                }
                return colors.get(val, '')
            
            # Display the table with custom styling
            st.dataframe(
                styled_df,
                column_config={
                    "Timestamp": st.column_config.DatetimeColumn(
                        "Time",
                        format="MMM DD, YYYY, HH:mm:ss"
                    ),
                    "Severity": st.column_config.Column(
                        "Severity",
                        help="Indicates the severity level of the threat"
                    ),
                    "Type": st.column_config.Column(
                        "Type",
                        help="Type of security event"
                    ),
                    "Status": st.column_config.Column(
                        "Status",
                        help="Current status of the threat mitigation"
                    )
                },
                hide_index=True,
                use_container_width=True
            )
    
    with col2:
        st.subheader("Risk Assessment")
        
        # Calculate overall risk level (0-100)
        risk_level = threat_prediction['overall_probability'] * 100
        
        # Create and display gauge chart
        gauge_chart = create_risk_gauge(risk_level)
        st.plotly_chart(gauge_chart, use_container_width=True)
        
        # Display top threats
        st.subheader("Top Threat Vectors")
        
        for threat_type, probability in threat_prediction['threat_types'].items():
            threat_percentage = probability * 100
            st.text(f"{threat_type}")
            st.progress(probability, text=f"{threat_percentage:.1f}%")
    
    # Bottom section with cards for actions
    st.subheader("Quick Actions")
    
    action_col1, action_col2, action_col3 = st.columns(3)
    
    with action_col1:
        st.markdown("""
        ### 🔍 Run Quantum Analysis
        Perform a deep analysis of network traffic and potential threats using simulated quantum computing algorithms.
        """)
        
        if st.button("Start Analysis", key="quantum_analysis"):
            with st.spinner("Running quantum analysis..."):
                # Simulate processing
                progress_bar = st.progress(0)
                
                for i in range(101):
                    time.sleep(0.05)
                    progress_bar.progress(i)
                
                # Run the analysis
                analysis_results = quantum_analysis_simulation(st.session_state.dashboard_network_data)
                
                # Display results
                st.success(f"Analysis complete! Threat level: {analysis_results['threat_level']}")
                
                if analysis_results['alerts']:
                    st.warning("Detected Issues:")
                    for alert in analysis_results['alerts']:
                        st.write(f"- {alert}")
                else:
                    st.info("No immediate threats detected.")
    
    with action_col2:
        st.markdown("""
        ### 🛡️ Isolation Protocol
        Simulate network isolation procedures to contain potential threats and prevent lateral movement.
        """)
        
        if st.button("Isolate Threats", key="isolate_threats"):
            # Check if there are any high-risk nodes
            high_risk_nodes = [node for node in st.session_state.dashboard_network_data['nodes'] 
                            if node['risk_score'] > 70]
            
            if high_risk_nodes:
                with st.spinner("Isolating high-risk nodes..."):
                    # Simulate processing
                    time.sleep(2)
                    
                    # Show isolated nodes
                    st.success(f"Isolated {len(high_risk_nodes)} high-risk nodes")
                    for node in high_risk_nodes[:3]:  # Show first 3
                        st.code(f"Node {node['id']} ({node['ip']}) isolated - Risk score: {node['risk_score']:.1f}")
                    
                    if len(high_risk_nodes) > 3:
                        st.text(f"...and {len(high_risk_nodes) - 3} more")
            else:
                st.info("No high-risk nodes detected that require isolation.")
    
    with action_col3:
        st.markdown("""
        ### 📊 Generate Report
        Create a comprehensive security report with findings and recommendations.
        """)
        
        if st.button("Generate Report", key="generate_report"):
            with st.spinner("Generating security report..."):
                # Simulate report generation
                time.sleep(2)
                
                st.success("Report generated successfully!")
                st.download_button(
                    label="Download Report",
                    data="This is a simulated security report. In a real application, this would be a PDF document with detailed findings.",
                    file_name="security_report.txt",
                    mime="text/plain"
                )
    
    # Footer with refresh time
    st.caption(f"Dashboard last updated: {st.session_state.last_refresh}")

if __name__ == "__main__":
    app()
