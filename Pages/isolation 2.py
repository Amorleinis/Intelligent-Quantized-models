import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import time
from datetime import datetime

from utils.data_generator import generate_network_data
from utils.network_visualization import create_network_graph

def app():
    """Network isolation and containment page."""
    st.title("🛡️ Network Isolation")
    st.markdown("Simulate network segmentation and threat containment procedures")
    
    # Initialize network data if not already present
    if 'isolation_network_data' not in st.session_state:
        st.session_state.isolation_network_data = generate_network_data()
    
    if 'isolated_nodes' not in st.session_state:
        st.session_state.isolated_nodes = []
    
    if 'isolation_history' not in st.session_state:
        st.session_state.isolation_history = []
    
    # Control panel
    st.subheader("Isolation Controls")
    
    # Two columns for controls
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Risk threshold slider for automatic isolation
        risk_threshold = st.slider(
            "Risk Score Threshold for Isolation",
            min_value=0,
            max_value=100,
            value=75,
            help="Nodes with risk scores above this threshold will be recommended for isolation"
        )
        
        # Selection method
        isolation_method = st.radio(
            "Isolation Method",
            options=["Manual Selection", "Risk-Based", "Quantum-Enhanced Analysis"],
            horizontal=True
        )
    
    with col2:
        # Action buttons
        if st.button("Reset Isolation"):
            st.session_state.isolated_nodes = []
            st.session_state.isolation_history.append({
                'time': datetime.now().strftime("%H:%M:%S"),
                'action': "Reset all isolations",
                'details': "All nodes reconnected to network"
            })
            st.success("All isolations have been reset")
        
        if st.button("Refresh Network Data"):
            with st.spinner("Refreshing network data..."):
                time.sleep(1)
                st.session_state.isolation_network_data = generate_network_data()
                st.session_state.isolated_nodes = []
                st.success("Network data refreshed")
    
    # Network visualization
    st.subheader("Network Visualization")
    
    # Display current network graph
    # First, make a copy and mark isolated nodes
    network_data = st.session_state.isolation_network_data.copy()
    
    # Mark nodes as inactive if they're isolated
    for node in network_data['nodes']:
        if node['id'] in st.session_state.isolated_nodes:
            node['active'] = False
    
    # Create and display the network graph
    network_graph = create_network_graph(network_data)
    st.plotly_chart(network_graph, use_container_width=True)
    
    # Isolation actions
    st.subheader("Isolation Actions")
    
    if isolation_method == "Manual Selection":
        # Create two columns
        select_col, info_col = st.columns([2, 1])
        
        with select_col:
            # Get list of nodes for selection
            nodes_for_selection = [
                f"Node {n['id']} ({n['ip']}) - {n['type']} - Risk: {n['risk_score']:.1f}"
                for n in network_data['nodes']
                if n['id'] not in st.session_state.isolated_nodes and n['active']
            ]
            
            # Select nodes to isolate
            selected_nodes = st.multiselect(
                "Select Nodes to Isolate",
                options=nodes_for_selection
            )
            
            # Button to execute isolation
            if st.button("Isolate Selected Nodes") and selected_nodes:
                # Extract node IDs from selection strings
                node_ids = [int(node.split()[1]) for node in selected_nodes]
                
                # Add to isolated nodes
                for node_id in node_ids:
                    if node_id not in st.session_state.isolated_nodes:
                        st.session_state.isolated_nodes.append(node_id)
                
                # Add to history
                st.session_state.isolation_history.append({
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'action': f"Manual isolation of {len(node_ids)} nodes",
                    'details': f"Isolated node IDs: {', '.join(map(str, node_ids))}"
                })
                
                st.success(f"Successfully isolated {len(node_ids)} nodes")
                time.sleep(1)
                st.rerun()
        
        with info_col:
            st.markdown("### Node Selection")
            st.markdown("""
            Select nodes from the list to isolate them from the network. This simulates:
            - Network segmentation
            - Container isolation
            - Virtual network separation
            """)
    
    elif isolation_method == "Risk-Based":
        # Find nodes above the risk threshold
        high_risk_nodes = [
            node for node in network_data['nodes']
            if node['risk_score'] >= risk_threshold and node['id'] not in st.session_state.isolated_nodes
        ]
        
        # Display information
        if high_risk_nodes:
            st.warning(f"Found {len(high_risk_nodes)} nodes with risk scores above threshold ({risk_threshold})")
            
            # Show table of high-risk nodes
            high_risk_df = pd.DataFrame([
                {
                    "ID": node['id'],
                    "IP Address": node['ip'],
                    "Type": node['type'],
                    "Risk Score": node['risk_score']
                }
                for node in high_risk_nodes
            ])
            
            st.dataframe(high_risk_df, hide_index=True, use_container_width=True)
            
            # Button to isolate high-risk nodes
            if st.button("Isolate High-Risk Nodes"):
                # Add nodes to isolated list
                node_ids = [node['id'] for node in high_risk_nodes]
                for node_id in node_ids:
                    if node_id not in st.session_state.isolated_nodes:
                        st.session_state.isolated_nodes.append(node_id)
                
                # Add to history
                st.session_state.isolation_history.append({
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'action': f"Risk-based isolation of {len(node_ids)} nodes",
                    'details': f"Isolated nodes with risk scores above {risk_threshold}"
                })
                
                # Success message and refresh
                st.success(f"Successfully isolated {len(node_ids)} high-risk nodes")
                time.sleep(1)
                st.rerun()
        else:
            st.success(f"No nodes found with risk scores above threshold ({risk_threshold})")
    
    elif isolation_method == "Quantum-Enhanced Analysis":
        # Simulate quantum analysis for isolation
        st.info("Performing simulated quantum analysis for optimal isolation strategy")
        
        with st.spinner("Running quantum circuit simulation..."):
            # Create progress bar
            progress_bar = st.progress(0)
            for i in range(101):
                time.sleep(0.02)
                progress_bar.progress(i)
        
        # Identify nodes for isolation based on "quantum" analysis
        # Here we simulate this by using a combination of factors
        suspicious_connections = [
            conn for conn in network_data['connections'] if conn['is_suspicious']
        ]
        
        suspicious_nodes = set()
        for conn in suspicious_connections:
            suspicious_nodes.add(conn['source'])
            suspicious_nodes.add(conn['target'])
        
        # Additional "quantum" factor (for simulation)
        quantum_factor = np.random.uniform(0.7, 1.3)
        
        # Calculate final isolation scores
        isolation_candidates = []
        for node in network_data['nodes']:
            if node['id'] not in st.session_state.isolated_nodes:
                quantum_score = node['risk_score'] * quantum_factor
                if node['id'] in suspicious_nodes:
                    quantum_score *= 1.5
                
                if quantum_score > risk_threshold:
                    isolation_candidates.append({
                        "ID": node['id'],
                        "IP Address": node['ip'],
                        "Type": node['type'],
                        "Risk Score": node['risk_score'],
                        "Quantum Risk Score": quantum_score,
                        "Connected to Suspicious": node['id'] in suspicious_nodes
                    })
        
        # Display candidates
        if isolation_candidates:
            st.warning(f"Quantum analysis identified {len(isolation_candidates)} nodes for isolation")
            
            # Convert to DataFrame
            candidates_df = pd.DataFrame(isolation_candidates)
            
            # Show the candidates table
            st.dataframe(candidates_df, hide_index=True, use_container_width=True)
            
            # Button to isolate nodes
            if st.button("Execute Quantum Isolation Strategy"):
                # Add nodes to isolated list
                node_ids = [node['ID'] for node in isolation_candidates]
                for node_id in node_ids:
                    if node_id not in st.session_state.isolated_nodes:
                        st.session_state.isolated_nodes.append(node_id)
                
                # Add to history
                st.session_state.isolation_history.append({
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'action': f"Quantum-enhanced isolation of {len(node_ids)} nodes",
                    'details': f"Isolated nodes with quantum risk scores above {risk_threshold}"
                })
                
                # Success message and refresh
                st.success(f"Successfully isolated {len(node_ids)} nodes using quantum-enhanced strategy")
                time.sleep(1)
                st.rerun()
        else:
            st.success(f"Quantum analysis found no nodes requiring isolation at threshold {risk_threshold}")
    
    # Display isolation history
    st.subheader("Isolation History")
    
    if not st.session_state.isolation_history:
        st.info("No isolation actions have been taken yet.")
    else:
        # Create history table
        history_df = pd.DataFrame(st.session_state.isolation_history)
        
        # Format columns
        st.dataframe(
            history_df,
            column_config={
                "time": st.column_config.Column("Time", help="When the action was taken"),
                "action": st.column_config.Column("Action", help="Type of isolation action"),
                "details": st.column_config.Column("Details", help="Additional information")
            },
            hide_index=True,
            use_container_width=True
        )
    
    # Current isolation status
    st.subheader("Current Isolation Status")
    
    if not st.session_state.isolated_nodes:
        st.info("No nodes are currently isolated.")
    else:
        # Calculate isolation metrics
        total_nodes = len(network_data['nodes'])
        isolated_percent = (len(st.session_state.isolated_nodes) / total_nodes) * 100
        
        # Show metrics
        metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
        
        with metrics_col1:
            st.metric("Isolated Nodes", f"{len(st.session_state.isolated_nodes)}/{total_nodes}")
        
        with metrics_col2:
            st.metric("Isolation Percentage", f"{isolated_percent:.1f}%")
        
        with metrics_col3:
            # Calculate average risk of isolated nodes
            isolated_nodes_data = [
                node for node in network_data['nodes']
                if node['id'] in st.session_state.isolated_nodes
            ]
            
            if isolated_nodes_data:
                avg_risk = np.mean([node['risk_score'] for node in isolated_nodes_data])
                st.metric("Avg. Isolated Risk", f"{avg_risk:.1f}")
            else:
                st.metric("Avg. Isolated Risk", "N/A")
        
        # Detailed information about isolated nodes
        isolated_nodes_df = pd.DataFrame([
            {
                "ID": node['id'],
                "IP Address": node['ip'],
                "Type": node['type'],
                "Risk Score": node['risk_score']
            }
            for node in network_data['nodes']
            if node['id'] in st.session_state.isolated_nodes
        ])
        
        st.dataframe(isolated_nodes_df, hide_index=True, use_container_width=True)
    
    # Educational component
    with st.expander("About Network Isolation", expanded=False):
        st.markdown("""
        ### Network Isolation Techniques
        
        Network isolation is a critical security measure that helps contain threats and prevent lateral movement within a network. Common isolation techniques include:
        
        #### 1. Network Segmentation
        - Creating separate network zones with distinct security rules
        - Using VLANs, subnets, and firewalls to separate segments
        - Implementing zero-trust network access (ZTNA) principles
        
        #### 2. Container Isolation
        - Using containerization to isolate applications and services
        - Implementing pod security policies in Kubernetes environments
        - Network policies to restrict container-to-container communication
        
        #### 3. Virtual Machine Isolation
        - Hypervisor-level security controls
        - Virtual network isolation
        - Resource isolation between VMs
        
        #### 4. Quantum-Resistant Segmentation (Future)
        - Network segmentation strategies resistant to quantum computing attacks
        - Quantum key distribution for secure network boundaries
        - Post-quantum cryptography for segment authentication
        
        Effective isolation should be implemented as part of a defense-in-depth strategy, combined with monitoring, access controls, and regular security assessments.
        """)
    
    # Disclaimer
    st.caption("Note: This is a simulated security dashboard for educational purposes. The 'quantum' analysis is a simulation and does not use actual quantum computing technologies.")

if __name__ == "__main__":
    app()
