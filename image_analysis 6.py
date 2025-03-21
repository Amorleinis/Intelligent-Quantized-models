"""
Security Image Analysis Page

This page provides security image analysis capabilities using OpenAI's vision API
to detect potential security threats in images.
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


def app():
    """Main function for the security image analysis page."""
    st.title("Security Image Analysis")
    st.write("Upload security footage or images for AI-powered threat detection and analysis.")
    
    # Initialize the analyzer
    analyzer = SecurityImageAnalysis()
    
    # Add sidebar options
    with st.sidebar:
        st.header("Analysis Options")
        
        analysis_mode = st.radio(
            "Analysis Mode",
            ["Security Camera Footage", "Suspicious Attachments", "Physical Security"]
        )
        
        st.info(f"Mode: {analysis_mode}")
        st.caption("All modes use the same analysis engine but provide context-specific recommendations.")
    
    # File uploader for images
    uploaded_file = st.file_uploader("Upload image for analysis", type=["jpg", "jpeg", "png"])
    
    if uploaded_file is not None:
        # Display the uploaded image
        col1, col2 = st.columns([2, 1])
        
        with col1:
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded Image", use_column_width=True)
        
        with col2:
            st.subheader("Image Details")
            st.write(f"**Filename:** {uploaded_file.name}")
            st.write(f"**Format:** {image.format}")
            st.write(f"**Size:** {image.size}")
            
            # Add button to trigger analysis
            if st.button("Analyze Image", use_container_width=True):
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
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("Sample: Server Room", use_container_width=True):
                # Simulated result for demonstration
                st.session_state.image_analysis_result = analyzer._simulate_image_analysis()
                st.success("Analysis completed!")
                
                # Display a placeholder image
                st.image("https://via.placeholder.com/400x300?text=Server+Room+Sample", 
                        caption="Sample Server Room Image")
        
        with col2:
            if st.button("Sample: Office Space", use_container_width=True):
                # Simulated result for demonstration with modified values
                simulated_result = analyzer._simulate_image_analysis()
                simulated_result["threat_level"] = 35
                simulated_result["suspicious_elements"].append("Unattended computer with active session")
                st.session_state.image_analysis_result = simulated_result
                st.success("Analysis completed!")
                
                # Display a placeholder image
                st.image("https://via.placeholder.com/400x300?text=Office+Space+Sample", 
                        caption="Sample Office Space Image")
        
        with col3:
            if st.button("Sample: Entry Point", use_container_width=True):
                # Simulated result for demonstration with high threat
                simulated_result = analyzer._simulate_image_analysis()
                simulated_result["threat_detected"] = True
                simulated_result["threat_level"] = 75
                simulated_result["threats_identified"] = ["Unauthorized access attempt", "Security door propped open"]
                simulated_result["suspicious_elements"] = ["Unknown person", "Compromised access control"]
                simulated_result["analysis_summary"] = "The image shows clear evidence of a security breach with an entry door propped open and an unauthorized individual attempting to gain access."
                st.session_state.image_analysis_result = simulated_result
                st.success("Analysis completed!")
                
                # Display a placeholder image
                st.image("https://via.placeholder.com/400x300?text=Entry+Point+Sample", 
                        caption="Sample Entry Point Image")
    
    # Display analysis results if available
    if "image_analysis_result" in st.session_state:
        st.markdown("---")
        st.header("Analysis Results")
        
        result = st.session_state.image_analysis_result
        
        # Create columns for threat level and timestamp
        col1, col2 = st.columns(2)
        
        with col1:
            # Display threat level with appropriate color
            threat_level = result["threat_level"]
            color = "green"
            if threat_level > 70:
                color = "red"
            elif threat_level > 30:
                color = "orange"
                
            st.markdown(f"### Threat Level: <span style='color:{color}'>{threat_level}/100</span>", unsafe_allow_html=True)
        
        with col2:
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


if __name__ == "__main__":
    app()