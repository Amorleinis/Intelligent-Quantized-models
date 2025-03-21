"""
Template for External Threat Intelligence Feed Integration

This template provides a foundation for integrating external threat intelligence feeds
to enhance the security monitoring capabilities of the quantum security dashboard.
"""

import streamlit as st
import pandas as pd
import json
import requests
from datetime import datetime, timedelta
import os
import time


class ExternalThreatFeed:
    """
    Implements integration with external threat intelligence feeds.
    
    This class provides methods for connecting to various threat intelligence
    sources and integrating their data into the security dashboard.
    """
    
    def __init__(self):
        """Initialize the external threat feed module."""
        # Initialize API keys from environment variables
        self.api_keys = {
            "alienvault": os.environ.get("ALIENVAULT_API_KEY"),
            "virustotal": os.environ.get("VIRUSTOTAL_API_KEY"),
            "talosintelligence": os.environ.get("TALOSINTELLIGENCE_API_KEY"),
            "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY"),
            "threatfox": os.environ.get("THREATFOX_API_KEY"),
            # Add more threat intelligence services as needed
        }
        
        # Default feed settings
        if "threat_feed_settings" not in st.session_state:
            st.session_state.threat_feed_settings = {
                "enabled_feeds": {
                    "alienvault": False,
                    "virustotal": False,
                    "talosintelligence": False,
                    "abuseipdb": False,
                    "threatfox": False
                },
                "update_frequency": 60,  # minutes
                "last_update_time": None,
                "threat_categories": ["malware", "ransomware", "phishing", "ddos", "exploit"],
                "minimum_confidence": 70,  # 0-100
                "include_indicators": True
            }
        
        # Initialize threat feed cache
        if "threat_feed_cache" not in st.session_state:
            st.session_state.threat_feed_cache = {
                "alienvault": [],
                "virustotal": [],
                "talosintelligence": [],
                "abuseipdb": [],
                "threatfox": [],
                "combined": []
            }
    
    def update_settings(self, settings):
        """
        Update threat feed settings.
        
        Args:
            settings: Dictionary containing threat feed settings
        """
        # Update settings in session state
        st.session_state.threat_feed_settings.update(settings)
    
    def get_available_feeds(self):
        """
        Get list of available threat feeds.
        
        Returns:
            Dictionary mapping feed names to availability status
        """
        # Check which feeds have API keys
        available_feeds = {}
        for feed, api_key in self.api_keys.items():
            available_feeds[feed] = api_key is not None
        
        return available_feeds
    
    def check_update_needed(self):
        """
        Check if threat feeds need to be updated based on update frequency.
        
        Returns:
            Boolean indicating if update is needed
        """
        last_update = st.session_state.threat_feed_settings["last_update_time"]
        
        if last_update is None:
            return True
        
        frequency = st.session_state.threat_feed_settings["update_frequency"]
        time_diff = (datetime.now() - last_update).total_seconds() / 60
        
        return time_diff >= frequency
    
    def update_all_feeds(self, force=False):
        """
        Update all enabled threat feeds.
        
        Args:
            force: Force update regardless of update frequency
            
        Returns:
            Dictionary with update results
        """
        # Check if update is needed
        if not force and not self.check_update_needed():
            return {
                "status": "skipped",
                "message": "Update not needed based on frequency settings",
                "last_update": st.session_state.threat_feed_settings["last_update_time"]
            }
        
        # Get enabled feeds
        enabled_feeds = [feed for feed, enabled in 
                        st.session_state.threat_feed_settings["enabled_feeds"].items() 
                        if enabled]
        
        # Check if any feeds are enabled
        if not enabled_feeds:
            return {
                "status": "error",
                "message": "No threat feeds are enabled"
            }
        
        # Update each enabled feed
        results = {}
        for feed in enabled_feeds:
            if self.api_keys[feed] is not None:
                # Call the appropriate update method for this feed
                update_method = getattr(self, f"update_{feed}_feed", None)
                if update_method:
                    try:
                        results[feed] = update_method()
                    except Exception as e:
                        results[feed] = {
                            "status": "error",
                            "message": str(e)
                        }
                else:
                    results[feed] = {
                        "status": "error",
                        "message": f"Update method for {feed} not implemented"
                    }
            else:
                results[feed] = {
                    "status": "error",
                    "message": f"API key for {feed} not available"
                }
        
        # Update combined threat data
        self.combine_threat_data()
        
        # Update last update time
        st.session_state.threat_feed_settings["last_update_time"] = datetime.now()
        
        return {
            "status": "success",
            "message": "Threat feeds updated successfully",
            "details": results
        }
    
    def get_combined_threats(self):
        """
        Get combined threat data from all feeds.
        
        Returns:
            List of threat entries
        """
        # Check if update is needed
        if self.check_update_needed():
            self.update_all_feeds()
        
        return st.session_state.threat_feed_cache["combined"]
    
    def combine_threat_data(self):
        """
        Combine threat data from all feeds into a unified format.
        
        Returns:
            List of combined threat entries
        """
        all_threats = []
        
        # Get minimum confidence threshold
        min_confidence = st.session_state.threat_feed_settings["minimum_confidence"]
        
        # Process each feed's data
        for feed, threats in st.session_state.threat_feed_cache.items():
            # Skip the "combined" entry and feeds with no data
            if feed == "combined" or not threats:
                continue
                
            for threat in threats:
                # Check confidence threshold
                confidence = threat.get("confidence", 0)
                if confidence < min_confidence:
                    continue
                
                # Standardize the threat entry
                standardized_threat = {
                    "source": feed,
                    "timestamp": threat.get("timestamp", datetime.now().isoformat()),
                    "type": threat.get("type", "unknown"),
                    "confidence": confidence,
                    "description": threat.get("description", "No description available"),
                    "indicators": threat.get("indicators", []),
                    "references": threat.get("references", [])
                }
                
                all_threats.append(standardized_threat)
        
        # Sort by timestamp (newest first)
        all_threats.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Store in cache
        st.session_state.threat_feed_cache["combined"] = all_threats
        
        return all_threats
    
    def update_alienvault_feed(self):
        """
        Update threat data from AlienVault OTX.
        
        Returns:
            Dictionary with update results
        """
        # TODO: Implement actual API integration with AlienVault OTX
        # This would use the OTX DirectConnect API
        
        # For demonstration, simulate the API call with sample data
        api_key = self.api_keys["alienvault"]
        if api_key is None:
            return {
                "status": "error",
                "message": "AlienVault API key is not available"
            }
        
        # Simulate API request time
        time.sleep(0.5)
        
        # Generate sample threat data for demonstration
        sample_threats = [
            {
                "timestamp": datetime.now().isoformat(),
                "type": "malware",
                "confidence": 85,
                "description": "New TrickBot banking trojan variant identified",
                "indicators": [
                    {"type": "domain", "value": "example-malicious1.com"},
                    {"type": "ip", "value": "203.0.113.42"},
                    {"type": "file_hash", "value": "a94bf485d6a4b1b27c4267c0e74f2653"}
                ],
                "references": ["https://example.com/trickbot-analysis"]
            },
            {
                "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
                "type": "ransomware",
                "confidence": 92,
                "description": "Ryuk ransomware campaign targeting healthcare sector",
                "indicators": [
                    {"type": "domain", "value": "example-malicious2.com"},
                    {"type": "ip", "value": "198.51.100.23"},
                    {"type": "file_hash", "value": "b88d9130360c4a424c6155d5a3658a0c"}
                ],
                "references": ["https://example.com/ryuk-analysis"]
            }
        ]
        
        # Store in cache
        st.session_state.threat_feed_cache["alienvault"] = sample_threats
        
        return {
            "status": "success",
            "message": "AlienVault OTX feed updated successfully",
            "count": len(sample_threats)
        }
    
    def update_virustotal_feed(self):
        """
        Update threat data from VirusTotal.
        
        Returns:
            Dictionary with update results
        """
        # TODO: Implement actual API integration with VirusTotal
        # This would use the VirusTotal API v3
        
        # For demonstration, simulate the API call with sample data
        api_key = self.api_keys["virustotal"]
        if api_key is None:
            return {
                "status": "error",
                "message": "VirusTotal API key is not available"
            }
        
        # Simulate API request time
        time.sleep(0.5)
        
        # Generate sample threat data for demonstration
        sample_threats = [
            {
                "timestamp": datetime.now().isoformat(),
                "type": "malware",
                "confidence": 78,
                "description": "High-detection malicious document spreading Emotet",
                "indicators": [
                    {"type": "file_hash", "value": "c2d6c77e24734a2b32b33e4b88b8dd19"},
                    {"type": "file_name", "value": "invoice_march2025.doc"}
                ],
                "references": ["https://example.com/virustotal/sample1"]
            }
        ]
        
        # Store in cache
        st.session_state.threat_feed_cache["virustotal"] = sample_threats
        
        return {
            "status": "success",
            "message": "VirusTotal feed updated successfully",
            "count": len(sample_threats)
        }
    
    # Implement other feed update methods similarly
    # def update_talosintelligence_feed(self):
    # def update_abuseipdb_feed(self):
    # def update_threatfox_feed(self):
    
    def check_ioc_against_feeds(self, ioc_type, ioc_value):
        """
        Check if an indicator of compromise (IOC) is found in any threat feed.
        
        Args:
            ioc_type: Type of IOC (domain, ip, file_hash, etc.)
            ioc_value: Value of the IOC to check
            
        Returns:
            List of matching threats
        """
        matches = []
        
        # Check if we have combined threat data
        combined_threats = st.session_state.threat_feed_cache.get("combined", [])
        if not combined_threats:
            self.combine_threat_data()
            combined_threats = st.session_state.threat_feed_cache.get("combined", [])
        
        # Search for matches
        for threat in combined_threats:
            for indicator in threat.get("indicators", []):
                if indicator.get("type") == ioc_type and indicator.get("value") == ioc_value:
                    matches.append(threat)
                    break
        
        return matches


def create_threat_feed_ui():
    """
    Create the user interface for the external threat feed module.
    
    This function should be called from a Streamlit page to render the UI.
    """
    st.title("External Threat Intelligence")
    st.write("Connect to external threat intelligence feeds to enhance security monitoring.")
    
    # Initialize the threat feed module
    threat_feed = ExternalThreatFeed()
    
    # Create tabs for different sections
    tab1, tab2, tab3 = st.tabs(["Feed Settings", "Current Threats", "IOC Lookup"])
    
    with tab1:
        st.subheader("Threat Feed Settings")
        
        # Check available feeds
        available_feeds = threat_feed.get_available_feeds()
        
        # Load current settings
        settings = st.session_state.threat_feed_settings
        
        # API key status
        st.write("### API Key Status")
        
        for feed, available in available_feeds.items():
            feed_name = feed.capitalize()
            
            if available:
                st.success(f"✓ {feed_name} API key available")
            else:
                st.warning(f"⚠ {feed_name} API key not configured")
                st.info(f"To add {feed_name} integration, set the {feed.upper()}_API_KEY environment variable.")
        
        # Enable/disable feeds
        st.write("### Enabled Feeds")
        
        enabled_feeds = {}
        for feed, available in available_feeds.items():
            feed_name = feed.capitalize()
            current_state = settings["enabled_feeds"].get(feed, False)
            
            # Only allow enabling if API key is available
            if available:
                enabled = st.checkbox(f"Enable {feed_name}", value=current_state)
            else:
                st.checkbox(f"Enable {feed_name}", value=False, disabled=True)
                enabled = False
            
            enabled_feeds[feed] = enabled
        
        # Update frequency
        st.write("### Update Settings")
        
        update_freq = st.number_input("Update Frequency (minutes)", 
                                   min_value=5, max_value=1440, 
                                   value=settings["update_frequency"])
        
        # Threat categories
        st.write("### Threat Categories")
        
        all_categories = ["malware", "ransomware", "phishing", "ddos", "exploit", 
                        "botnet", "trojan", "backdoor", "vulnerability", "apt"]
        
        selected_categories = []
        for category in all_categories:
            if st.checkbox(category.capitalize(), 
                         value=category in settings["threat_categories"]):
                selected_categories.append(category)
        
        # Confidence threshold
        st.write("### Filtering")
        
        min_confidence = st.slider("Minimum Confidence Score", 
                                 min_value=0, max_value=100, 
                                 value=settings["minimum_confidence"])
        
        include_indicators = st.checkbox("Include Technical Indicators", 
                                      value=settings["include_indicators"])
        
        # Save button
        if st.button("Save Feed Settings"):
            # Update settings
            updated_settings = {
                "enabled_feeds": enabled_feeds,
                "update_frequency": update_freq,
                "threat_categories": selected_categories,
                "minimum_confidence": min_confidence,
                "include_indicators": include_indicators
            }
            
            threat_feed.update_settings(updated_settings)
            st.success("Threat feed settings saved successfully!")
    
    with tab2:
        st.subheader("Current Threat Intelligence")
        
        # Check if any feeds are enabled
        enabled_count = sum(1 for enabled in settings["enabled_feeds"].values() if enabled)
        
        if enabled_count == 0:
            st.warning("No threat feeds are currently enabled. Configure feeds in the settings tab.")
        else:
            # Add update button
            col1, col2 = st.columns([1, 4])
            with col1:
                if st.button("Update Feeds"):
                    with st.spinner("Updating threat feeds..."):
                        update_result = threat_feed.update_all_feeds(force=True)
                        
                        if update_result["status"] == "success":
                            st.success(update_result["message"])
                        else:
                            st.error(f"Error: {update_result['message']}")
            
            with col2:
                if settings["last_update_time"]:
                    st.info(f"Last updated: {settings['last_update_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    st.info("Feeds have not been updated yet")
            
            # Get combined threat data
            threats = threat_feed.get_combined_threats()
            
            if not threats:
                st.info("No threat intelligence data available. Click 'Update Feeds' to fetch the latest data.")
            else:
                # Display threat count
                st.metric("Active Threats", len(threats))
                
                # Create a table of threats
                threats_data = []
                for threat in threats:
                    threats_data.append({
                        "Source": threat["source"].capitalize(),
                        "Type": threat["type"].capitalize(),
                        "Confidence": f"{threat['confidence']}%",
                        "Timestamp": threat["timestamp"],
                        "Description": threat["description"]
                    })
                
                # Convert to DataFrame for display
                threats_df = pd.DataFrame(threats_data)
                
                # Display as table
                st.dataframe(threats_df, use_container_width=True)
                
                # Expandable section for indicator details
                if settings["include_indicators"]:
                    with st.expander("Technical Indicators"):
                        selected_threat = st.selectbox(
                            "Select threat to view indicators",
                            options=range(len(threats)),
                            format_func=lambda x: threats[x]["description"]
                        )
                        
                        # Display indicators for selected threat
                        if "indicators" in threats[selected_threat] and threats[selected_threat]["indicators"]:
                            indicators = threats[selected_threat]["indicators"]
                            
                            # Create indicator table
                            indicator_data = []
                            for indicator in indicators:
                                indicator_data.append({
                                    "Type": indicator["type"].capitalize(),
                                    "Value": indicator["value"]
                                })
                            
                            # Convert to DataFrame for display
                            indicators_df = pd.DataFrame(indicator_data)
                            
                            # Display as table
                            st.dataframe(indicators_df, use_container_width=True)
                        else:
                            st.info("No technical indicators available for this threat")
    
    with tab3:
        st.subheader("Indicator of Compromise (IOC) Lookup")
        st.write("Check if an indicator of compromise is found in threat intelligence feeds.")
        
        # IOC type selection
        ioc_type = st.selectbox(
            "IOC Type",
            options=["ip", "domain", "url", "file_hash", "email", "file_name"]
        )
        
        # IOC value input
        ioc_value = st.text_input(f"Enter {ioc_type} to check")
        
        # Lookup button
        if st.button("Check IOC") and ioc_value:
            with st.spinner(f"Checking {ioc_type} in threat feeds..."):
                # Check IOC against feeds
                matches = threat_feed.check_ioc_against_feeds(ioc_type, ioc_value)
                
                if matches:
                    st.error(f"⚠ This {ioc_type} was found in {len(matches)} threat reports!")
                    
                    # Display matching threats
                    for i, match in enumerate(matches):
                        with st.expander(f"Match {i+1}: {match['description']}"):
                            st.write(f"**Source:** {match['source'].capitalize()}")
                            st.write(f"**Type:** {match['type'].capitalize()}")
                            st.write(f"**Confidence:** {match['confidence']}%")
                            st.write(f"**Timestamp:** {match['timestamp']}")
                            
                            # Display references if available
                            if match.get("references"):
                                st.write("**References:**")
                                for ref in match["references"]:
                                    st.write(f"- [{ref}]({ref})")
                else:
                    st.success(f"✓ No matches found for this {ioc_type} in current threat intelligence")


# This allows the template to be run as a standalone page for testing
if __name__ == "__main__":
    create_threat_feed_ui()