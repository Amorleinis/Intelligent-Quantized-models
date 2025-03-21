import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
from datetime import datetime, timedelta

def create_network_graph(data):
    """
    Create a network graph visualization from network data.
    
    Args:
        data: Dictionary containing network data
    
    Returns:
        Plotly figure object
    """
    # Create a directed graph
    G = nx.DiGraph()
    
    # Add nodes to the graph
    for node in data['nodes']:
        # Only include active nodes
        if node['active']:
            # Determine node color based on risk score
            if node['risk_score'] < 30:
                color = 'green'
            elif node['risk_score'] < 70:
                color = 'orange'
            else:
                color = 'red'
                
            G.add_node(
                node['id'],
                label=f"{node['ip']} ({node['type']})",
                type=node['type'],
                security=node['security_level'],
                risk=node['risk_score'],
                color=color
            )
    
    # Add edges to the graph
    for conn in data['connections']:
        # Only add connections between active nodes
        if (conn['source'] in G.nodes and conn['target'] in G.nodes):
            # Determine edge color
            if conn['is_suspicious']:
                edge_color = 'red'
                width = 2
            else:
                edge_color = 'gray'
                width = 1
                
            G.add_edge(
                conn['source'],
                conn['target'],
                weight=conn['traffic_volume'],
                type=conn['connection_type'],
                suspicious=conn['is_suspicious'],
                color=edge_color,
                width=width
            )
    
    # Use spring layout for node positions
    pos = nx.spring_layout(G, seed=42)
    
    # Prepare node trace
    node_x = []
    node_y = []
    node_colors = []
    node_sizes = []
    node_texts = []
    
    for node, attrs in G.nodes(data=True):
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_colors.append(attrs['color'])
        
        # Size based on node type
        if attrs['type'] == 'server':
            size = 15
        elif attrs['type'] == 'firewall':
            size = 18
        else:
            size = 10
        node_sizes.append(size)
        
        # Create hover text
        node_texts.append(f"ID: {node}<br>IP: {attrs['label']}<br>Type: {attrs['type']}<br>Risk Score: {attrs['risk']:.1f}")
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        text=node_texts,
        marker=dict(
            color=node_colors,
            size=node_sizes,
            line=dict(width=1, color='#888')
        )
    )
    
    # Prepare edge traces (separate trace for each edge to have different colors)
    edge_traces = []
    
    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        
        edge_trace = go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            line=dict(width=edge[2]['width'], color=edge[2]['color']),
            mode='lines',
            hoverinfo='text',
            text=f"Connection: {edge[0]} → {edge[1]}<br>Type: {edge[2]['type']}<br>Traffic: {edge[2]['weight']} packets<br>{'⚠️ Suspicious' if edge[2]['suspicious'] else 'Normal'}"
        )
        edge_traces.append(edge_trace)
    
    # Create figure
    fig = go.Figure(
        data=edge_traces + [node_trace],
        layout=go.Layout(
            title=dict(
                text='Network Structure and Traffic',
                font=dict(size=16)
            ),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=500,
            template='plotly_white'
        )
    )
    
    return fig

def create_traffic_timeline(data):
    """
    Create a timeline visualization of network traffic.
    
    Args:
        data: Dictionary containing network data
    
    Returns:
        Plotly figure object
    """
    # Get traffic data from the input
    timestamps = data['traffic_data']['timestamps']
    values = data['traffic_data']['values']
    
    # Create a dataframe for the traffic data
    df = pd.DataFrame({
        'Timestamp': timestamps,
        'Traffic Volume': values
    })
    
    # Convert timestamp strings to datetime objects for proper plotting
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    
    # Create the line chart
    fig = px.line(
        df, 
        x='Timestamp', 
        y='Traffic Volume',
        title='Network Traffic (Last 24 hours)',
        template='plotly_white'
    )
    
    # Add attack annotations if they exist
    if 'attack_data' in data and len(data['attack_data']['timestamps']) > 0:
        attack_df = pd.DataFrame({
            'Timestamp': pd.to_datetime(data['attack_data']['timestamps']),
            'Type': data['attack_data']['types'],
            'Source': data['attack_data']['sources'],
            'Target': data['attack_data']['targets'],
            'Severity': data['attack_data']['severities']
        })
        
        # Add markers for attack events
        for i, row in attack_df.iterrows():
            # Find the closest point in the traffic data
            closest_idx = np.abs(df['Timestamp'] - row['Timestamp']).argmin()
            
            # Add a marker
            fig.add_trace(go.Scatter(
                x=[row['Timestamp']],
                y=[df.iloc[closest_idx]['Traffic Volume'] + 100],  # Slightly above the line
                mode='markers',
                marker=dict(
                    size=10,
                    color='red',
                    symbol='x'
                ),
                hoverinfo='text',
                hovertext=f"Attack Detected<br>Time: {row['Timestamp']}<br>Type: {row['Type']}<br>Severity: {row['Severity']}<br>Source: {row['Source']}<br>Target: {row['Target']}",
                showlegend=False
            ))
    
    # Update layout
    fig.update_layout(
        height=350,
        xaxis_title='Time',
        yaxis_title='Packets per Minute',
        hovermode='closest'
    )
    
    return fig

def create_threat_heatmap(threat_data):
    """
    Create a heatmap visualization of threat distribution.
    
    Args:
        threat_data: DataFrame containing threat information
    
    Returns:
        Plotly figure object
    """
    # Ensure we have threat data
    if threat_data.empty:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.update_layout(
            title=dict(text="No threat data available"),
            annotations=[
                dict(
                    text="No threats detected",
                    showarrow=False,
                    xref="paper",
                    yref="paper",
                    x=0.5,
                    y=0.5
                )
            ]
        )
        return fig
    
    # Create a pivot table of threat types vs. severity
    threat_counts = pd.crosstab(threat_data['Type'], threat_data['Severity'])
    
    # Ensure all severity levels are represented (for consistent heatmap)
    for severity in ['Low', 'Medium', 'High', 'Critical']:
        if severity not in threat_counts.columns:
            threat_counts[severity] = 0
    
    # Reorder severity columns
    threat_counts = threat_counts[['Low', 'Medium', 'High', 'Critical']]
    
    # Create the heatmap
    fig = px.imshow(
        threat_counts,
        labels=dict(x="Severity", y="Threat Type", color="Count"),
        x=threat_counts.columns,
        y=threat_counts.index,
        color_continuous_scale='Reds',
        title="Threat Distribution by Type and Severity"
    )
    
    # Update layout
    fig.update_layout(
        height=400,
        xaxis_title="Severity",
        yaxis_title="Threat Type",
        xaxis={'side': 'top'}
    )
    
    # Add text annotations with the count values
    for i in range(len(threat_counts.index)):
        for j in range(len(threat_counts.columns)):
            value = threat_counts.iloc[i, j]
            fig.add_annotation(
                x=j,
                y=i,
                text=str(value),
                showarrow=False,
                font=dict(color="white" if value > 2 else "black")
            )
    
    return fig

def create_risk_gauge(risk_level):
    """
    Create a gauge chart for displaying risk level.
    
    Args:
        risk_level: Numeric risk level (0-100)
    
    Returns:
        Plotly figure object
    """
    # Ensure risk level is within bounds
    risk_level = max(0, min(100, risk_level))
    
    # Determine color based on risk level
    if risk_level < 30:
        color = "green"
    elif risk_level < 70:
        color = "orange"
    else:
        color = "red"
    
    # Create the gauge chart
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_level,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Risk Level"},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 30], 'color': 'rgba(0, 250, 0, 0.3)'},
                {'range': [30, 70], 'color': 'rgba(255, 165, 0, 0.3)'},
                {'range': [70, 100], 'color': 'rgba(255, 0, 0, 0.3)'}
            ],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': risk_level
            }
        }
    ))
    
    # Update layout
    fig.update_layout(
        height=250,
        margin=dict(l=20, r=20, t=50, b=20)
    )
    
    return fig
