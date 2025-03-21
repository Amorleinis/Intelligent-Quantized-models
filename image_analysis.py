"""
Template for Security Image Analysis using OpenAI Vision

This template provides a foundation for implementing image analysis 
capabilities for security applications using OpenAI's vision capabilities.
"""

import streamlit as st
import base64
import json
from io import BytesIO
from datetime import datetime
import os
from PIL import Image

# Import utility functions from the project
from utils.openai_integration import get_openai_client


class SecurityImageAnalysis:
    """Implements security image analysis capabilities using OpenAI Vision."""
    
    def __init__(self):
        """Initialize the security image analysis module."""
        # Check if OpenAI API key is available
        self.openai_available = os.environ.get("OPENAI_API_KEY") is not None
        if self.openai_available:
            try:
                self.client = get_openai_client()
            except Exception as e:
                st.error(f"Error initializing OpenAI client: {e}")
                self.openai_available = False
    
    def analyze_image(self, image_data):
        """
        Analyze image for security-related content using OpenAI Vision.
        
        Args:
            image_data: Image data as bytes or file-like object
            
        Returns:
            Dictionary with analysis results
        """
        if not self.openai_available:
            return self._simulate_image_analysis()
        
        try:
            # Convert image to base64 for OpenAI API
            if isinstance(image_data, bytes):
                image_bytes = image_data
            else:
                # Assuming image_data is a file-like object
                image_bytes = image_data.getvalue()
            
            base64_image = base64.b64encode(image_bytes).decode('utf-8')
            
            # Call OpenAI API with vision capabilities
            response = self.client.chat.completions.create(
                model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a security analyst specializing in analyzing images for security threats. "
                                   "Identify potential risks, suspicious elements, or security concerns in the image. "
                                   "Provide detailed analysis and recommendations in JSON format."
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Analyze this image for security threats or concerns. Provide output in JSON format with these fields: "
                                        "threat_detected (boolean), threat_level (number 0-100), threats_identified (list), "
                                        "suspicious_elements (list), recommendations (list), and analysis_summary (text)."
                            },
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                            }
                        ]
                    }
                ],
                response_format={"type": "json_object"},
                max_tokens=500
            )
            
            # Parse the response
            analysis_result = json.loads(response.choices[0].message.content)
            
            # Add timestamp to the analysis
            analysis_result["timestamp"] = datetime.now().isoformat()
            
            return analysis_result
            
        except Exception as e:
            st.error(f"Error during OpenAI image analysis: {e}")
            # Fallback to simulated analysis
            return self._simulate_image_analysis()
    
    def _simulate_image_analysis(self):
        """
        Provide simulated image analysis when OpenAI is not available.
        
        Returns:
            Dictionary with simulated analysis results
        """
        # Simulated analysis for demonstration purposes
        return {
            "threat_detected": False,
            "threat_level": 15,
            "threats_identified": [],
            "suspicious_elements": [
                "Unidentified network equipment",
                "Potential unsecured access point"
            ],
            "recommendations": [
                "Verify identity of all equipment in server rooms",
                "Ensure proper access control for all network equipment",
                "Document all authorized devices with photos for comparison"
            ],
            "analysis_summary": "The image does not contain immediate security threats, but there are some elements that should be verified for proper security protocols.",
            "timestamp": datetime.now().isoformat(),
            "simulation_notice": "This analysis is simulated and not based on actual image processing."
        }


def create_image_analysis_ui():
    """
    Create the user interface for the image analysis module.
    
    This function should be called from a Streamlit page to render the UI.
    """
    st.title("Security Image Analysis")
    st.write("Upload security footage or images for AI-powered threat detection and analysis.")
    
    # Initialize the analyzer
    analyzer = SecurityImageAnalysis()
    
    # File uploader for images
    uploaded_file = st.file_uploader("Upload image for analysis", type=["jpg", "jpeg", "png"])
    
    if uploaded_file is not None:
        # Display the uploaded image
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded Image", use_column_width=True)
        
        # Add button to trigger analysis
        if st.button("Analyze Image"):
            with st.spinner("Analyzing image..."):
                # Reset uploaded file to beginning
                uploaded_file.seek(0)
                
                # Perform the analysis
                analysis_result = analyzer.analyze_image(uploaded_file)
                st.session_state.image_analysis_result = analysis_result
                st.success("Analysis completed!")
    
    # Display sample images for testing if no upload
    if uploaded_file is None:
        st.markdown("### Or use a sample image:")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Sample: Server Room"):
                # TODO: Replace with actual sample image implementation
                st.info("This is a placeholder for sample image functionality.")
                
                # Simulated result for demonstration
                st.session_state.image_analysis_result = analyzer._simulate_image_analysis()
                st.success("Analysis completed!")
        
        with col2:
            if st.button("Sample: Office Space"):
                # TODO: Replace with actual sample image implementation
                st.info("This is a placeholder for sample image functionality.")
                
                # Simulated result for demonstration
                simulated_result = analyzer._simulate_image_analysis()
                # Modify the simulation for variety
                simulated_result["threat_level"] = 35
                simulated_result["suspicious_elements"].append("Unattended computer with active session")
                st.session_state.image_analysis_result = simulated_result
                st.success("Analysis completed!")
    
    # Display analysis results if available
    if "image_analysis_result" in st.session_state:
        st.markdown("---")
        st.header("Analysis Results")
        
        result = st.session_state.image_analysis_result
        
        # Display threat level
        threat_color = "green"
        if result["threat_level"] > 70:
            threat_color = "red"
        elif result["threat_level"] > 30:
            threat_color = "orange"
            
        st.markdown(f"### Threat Level: <span style='color:{threat_color}'>{result['threat_level']}/100</span>", unsafe_allow_html=True)
        
        # Display if threats were detected
        if result["threat_detected"]:
            st.error("⚠️ Security threats detected!")
        else:
            st.success("✓ No immediate security threats detected")
        
        # Display threats if any
        if result["threats_identified"]:
            st.subheader("Identified Threats")
            for threat in result["threats_identified"]:
                st.markdown(f"• {threat}")
        
        # Display suspicious elements
        if result["suspicious_elements"]:
            st.subheader("Suspicious Elements")
            for element in result["suspicious_elements"]:
                st.markdown(f"• {element}")
        
        # Display recommendations
        st.subheader("Security Recommendations")
        for rec in result["recommendations"]:
            st.markdown(f"• {rec}")
        
        # Display analysis summary
        st.subheader("Analysis Summary")
        st.write(result["analysis_summary"])
        
        # Show timestamp
        st.info(f"Analysis performed at {result['timestamp']}")
        
        # Show simulation notice if present
        if "simulation_notice" in result:
            st.warning(result["simulation_notice"])


# This allows the template to be run as a standalone page for testing
if __name__ == "__main__":
    create_image_analysis_ui()