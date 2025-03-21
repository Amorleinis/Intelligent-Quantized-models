"""
Advanced Threat Analysis Page

This page provides advanced threat analysis capabilities using OpenAI's API
for natural language processing and reasoning to analyze network patterns.
"""

import streamlit as st
import pandas as pd
import json
from datetime import datetime
import os

# Import utility functions from the project
from utils.openai_integration import get_openai_client
from utils.data_generator import generate_network_data


class AdvancedThreatAnalysis:
    """Implements advanced threat analysis capabilities using OpenAI."""
    
    def __init__(self):
        """Initialize the advanced threat analysis module."""
        # Check if OpenAI API key is available
        self.openai_available = os.environ.get("OPENAI_API_KEY") is not None
        if self.openai_available:
            try:
                self.client = get_openai_client()
            except Exception as e:
                st.error(f"Error initializing OpenAI client: {e}")
                self.openai_available = False
    
    def analyze_network_pattern(self, network_data):
        """
        Analyze network traffic patterns to identify potential threats using OpenAI.
        
        Args:
            network_data: Dictionary containing network data
            
        Returns:
            Dictionary with analysis results and threat scores
        """
        if not self.openai_available:
            return self._simulate_network_analysis(network_data)
        
        try:
            # Prepare network data for OpenAI analysis
            # Extract key metrics that would be relevant for security analysis
            analysis_data = {
                "connections": len(network_data.get("connections", [])),
                "nodes": len(network_data.get("nodes", [])),
                "traffic_patterns": network_data.get("traffic_patterns", []),
                "unusual_connections": network_data.get("unusual_connections", []),
                "data_flow_volumes": network_data.get("data_flow_volumes", {})
            }
            
            # Convert to JSON string for the prompt
            analysis_json = json.dumps(analysis_data, indent=2)
            
            # Create prompt for OpenAI
            prompt = f"""
            Analyze the following network data for potential security threats:
            
            {analysis_json}
            
            Provide a security analysis in JSON format with the following structure:
            {{
                "threat_level": <number between 0-100>,
                "detected_patterns": [<list of suspicious patterns>],
                "recommendations": [<list of security recommendations>],
                "analysis_summary": "<detailed analysis>"
            }}
            
            Focus on identifying unusual patterns, potential data exfiltration,
            command and control communications, and other security threats.
            """
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in network traffic analysis."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            # Parse the response
            analysis_result = json.loads(response.choices[0].message.content)
            
            # Add timestamp to the analysis
            analysis_result["timestamp"] = datetime.now().isoformat()
            
            return analysis_result
            
        except Exception as e:
            st.error(f"Error during OpenAI threat analysis: {e}")
            # Fallback to simulated analysis
            return self._simulate_network_analysis(network_data)
    
    def _simulate_network_analysis(self, network_data):
        """
        Provide simulated network analysis when OpenAI is not available.
        
        Args:
            network_data: Dictionary containing network data
            
        Returns:
            Dictionary with simulated analysis results
        """
        # Simple simulation for demonstration purposes
        connections = len(network_data.get("connections", []))
        nodes = len(network_data.get("nodes", []))
        
        # Calculate a simulated threat level based on network complexity
        threat_level = min(85, (connections / max(1, nodes)) * 25)
        
        # Generate some simulated detected patterns
        detected_patterns = [
            "Multiple connections to unusual ports",
            "Periodic data bursts to external IPs",
            "Asymmetric traffic patterns between nodes"
        ]
        
        # Generate simulated recommendations
        recommendations = [
            "Implement additional monitoring on high-traffic nodes",
            "Review firewall rules for external connections",
            "Investigate nodes with unusual connection patterns"
        ]
        
        return {
            "threat_level": threat_level,
            "detected_patterns": detected_patterns,
            "recommendations": recommendations,
            "analysis_summary": "Simulated analysis detected unusual traffic patterns that may indicate potential security threats. Further investigation recommended.",
            "timestamp": datetime.now().isoformat(),
            "simulation_notice": "This analysis is simulated and not based on OpenAI processing."
        }


def app():
    """Main function for the advanced threat analysis page."""
    st.title("Advanced Threat Analysis")
    st.write("Analyze network patterns to identify potential security threats using AI.")
    
    # Initialize the analyzer
    analyzer = AdvancedThreatAnalysis()
    
    # Add sidebar options
    with st.sidebar:
        st.header("Analysis Options")
        
        analysis_type = st.selectbox(
            "Analysis Type",
            ["Network Pattern Analysis", "Traffic Flow Analysis", "Anomaly Detection"]
        )
        
        # Currently only network pattern analysis is implemented
        if analysis_type != "Network Pattern Analysis":
            st.info(f"{analysis_type} is coming soon!")
    
    # Add controls for analysis
    col1, col2 = st.columns([3, 1])
    
    with col2:
        if st.button("Generate Network Data", use_container_width=True):
            # Generate sample network data for analysis
            network_data = generate_network_data(num_nodes=50, num_connections=100)
            st.session_state.network_data = network_data
            st.success("Network data generated successfully!")
        
        if st.button("Analyze Network", use_container_width=True):
            if "network_data" not in st.session_state:
                st.warning("Please generate network data first.")
            else:
                with st.spinner("Analyzing network patterns..."):
                    # Perform the analysis
                    analysis_result = analyzer.analyze_network_pattern(st.session_state.network_data)
                    st.session_state.analysis_result = analysis_result
                    st.success("Analysis completed!")
    
    with col1:
        # Display network data visualization (placeholder)
        if "network_data" in st.session_state:
            st.subheader("Network Data Visualization")
            
            # Display some basic network stats
            network_data = st.session_state.network_data
            st.metric("Network Nodes", len(network_data.get("nodes", [])))
            st.metric("Network Connections", len(network_data.get("connections", [])))
            
            # TODO: Add more sophisticated network visualization
            st.info("Detailed network graph visualization coming soon!")
    
    # Display analysis results if available
    if "analysis_result" in st.session_state:
        st.markdown("---")
        st.header("Analysis Results")
        
        result = st.session_state.analysis_result
        
        # Create columns for threat level and timestamp
        col1, col2 = st.columns(2)
        
        with col1:
            # Display threat level with appropriate color
            threat_level = result['threat_level']
            color = "green"
            if threat_level > 70:
                color = "red"
            elif threat_level > 40:
                color = "orange"
                
            st.markdown(f"### Threat Level: <span style='color:{color}'>{threat_level:.1f}/100</span>", unsafe_allow_html=True)
        
        with col2:
            st.info(f"Analysis Time: {result['timestamp']}")
        
        # Display detected patterns
        st.subheader("Detected Patterns")
        for pattern in result["detected_patterns"]:
            st.markdown(f"• {pattern}")
        
        # Display recommendations
        st.subheader("Security Recommendations")
        for i, rec in enumerate(result["recommendations"]):
            st.markdown(f"### Recommendation {i+1}")
            st.markdown(f"• {rec}")
        
        # Display detailed analysis
        st.subheader("Analysis Summary")
        st.write(result["analysis_summary"])
        
        # Show simulation notice if present
        if "simulation_notice" in result:
            st.warning(result["simulation_notice"])


if __name__ == "__main__":
    app()