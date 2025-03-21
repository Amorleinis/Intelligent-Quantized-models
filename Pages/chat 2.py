import streamlit as st
import time
import random
import os
from datetime import datetime

# OpenAI integration
from utils.openai_integration import generate_ai_response_with_openai

def get_system_status_info():
    """
    Retrieves current system status information from session state.
    
    Returns:
        Dictionary with system status information
    """
    status_info = {
        "threat_level": st.session_state.get("threat_level", "Low"),
        "alerts": st.session_state.get("alerts", []),
        "network_data": st.session_state.get("network_data", {}),
        "last_analysis": st.session_state.get("last_analysis", None)
    }
    return status_info

def generate_ai_response(query):
    """
    Generates an AI response to user queries about cybersecurity with context-awareness.
    Attempts to use OpenAI if an API key is available, otherwise falls back to simulated responses.
    
    Args:
        query: The user's question as a string
        
    Returns:
        A string response from the AI that incorporates system context
    """
    # Get current system status for context-aware responses
    system_status = get_system_status_info()
    threat_level = system_status["threat_level"]
    alerts = system_status["alerts"]
    network_data = system_status["network_data"]
    last_analysis = system_status["last_analysis"]
    
    # Check if OpenAI API key is available
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    
    # Use OpenAI if API key is available
    if openai_api_key:
        try:
            return generate_ai_response_with_openai(query, system_status)
        except Exception as e:
            st.error(f"Error using OpenAI API: {str(e)}")
            # Fall back to simulated responses on error
    
    # Fallback to simulated responses if OpenAI is not available
    # Simple keyword-based responses for demonstration
    query_lower = query.lower()
    
    # Add a slight delay to simulate processing
    time.sleep(1.5)
    
    # Check for context-specific queries about the system status
    if any(term in query_lower for term in ["status", "system status", "current status"]):
        response = f"The system currently has a {threat_level} threat level. "
        if alerts:
            response += f"There are {len(alerts)} active security alerts. "
            if len(alerts) > 0:
                most_recent = alerts[0] if isinstance(alerts[0], str) else alerts[0].get('message', 'Unknown alert')
                response += f"The most recent alert is about '{most_recent}'."
        else:
            response += "There are no active security alerts at the moment."
        
        if last_analysis:
            response += f" The last security analysis was performed at {last_analysis}."
            
        return response
    
    # Query about current threats or alerts
    elif any(term in query_lower for term in ["alerts", "current threats", "active threats", "warnings"]):
        if alerts and len(alerts) > 0:
            response = f"There are currently {len(alerts)} active security alerts:\n\n"
            for i, alert in enumerate(alerts):
                alert_message = alert if isinstance(alert, str) else alert.get('message', 'Unknown alert')
                alert_time = '' if isinstance(alert, str) else f" ({alert.get('time', '')})"
                response += f"{i+1}. {alert_message}{alert_time}\n"
            
            response += "\nI recommend reviewing these alerts in the Threats section of the dashboard for more details."
        else:
            response = "There are currently no active security alerts in the system. However, this doesn't mean you should let your guard down. Regular security assessments and proactive monitoring are still essential."
        
        return response
    
    # Query about the network
    elif any(term in query_lower for term in ["network", "connections", "topology", "nodes"]):
        if network_data:
            node_count = network_data.get("nodes", 0)
            connection_count = network_data.get("connections", 0)
            response = f"Your network currently has {node_count} nodes with {connection_count} connections between them. "
            
            if threat_level == "High":
                response += "The network is currently showing signs of unusual activity. I recommend reviewing the Network Visualization in the dashboard for more details."
            elif threat_level == "Medium":
                response += "There are some anomalies detected in the network traffic patterns. The Network Visualization section can help you identify potential issues."
            else:
                response += "Network traffic appears normal at this time. Regular monitoring is still recommended."
        else:
            response = "I don't have detailed information about your network structure at the moment. You can view the network visualization in the dashboard for a graphical representation."
        
        return response
    
    # Recommendations based on current threat level
    elif any(term in query_lower for term in ["recommend", "suggestion", "advice", "what should i do"]):
        if threat_level == "High":
            return ("Based on the current high threat level, I recommend immediate action:\n\n"
                   "1. Review all active alerts in the Threats section\n"
                   "2. Initiate network isolation procedures for affected systems\n"
                   "3. Activate your incident response plan\n"
                   "4. Consider taking critical systems offline until the threat is contained\n"
                   "5. Begin forensic analysis to determine the nature and extent of the potential breach\n\n"
                   "You can find specific instructions in the Isolation and Recovery sections of the dashboard.")
        elif threat_level == "Medium":
            return ("With the current medium threat level, I recommend these precautionary measures:\n\n"
                   "1. Investigate the alerts in the Threats section\n"
                   "2. Increase monitoring of critical systems and sensitive data access\n"
                   "3. Review recent user activity for any anomalies\n"
                   "4. Ensure all backups are current and functioning\n"
                   "5. Prepare isolation strategies in case the threat level increases\n\n"
                   "The dashboard's Threats section will provide more detailed information about potential issues.")
        else:
            return ("Even with the current low threat level, maintaining good security hygiene is important:\n\n"
                   "1. Continue regular security monitoring and scans\n"
                   "2. Ensure all systems are up-to-date with security patches\n"
                   "3. Review user access privileges regularly\n"
                   "4. Test backup and recovery procedures\n"
                   "5. Conduct ongoing security awareness training for all users\n\n"
                   "Prevention is always more effective than recovery.")
    
    # Check for greetings
    if any(greeting in query_lower for greeting in ["hello", "hi", "hey", "greetings"]):
        greeting_response = "Hello! I'm your Quantum Security Assistant. How can I help you with cybersecurity today?"
        
        # Add context about current system status
        if threat_level != "Low":
            greeting_response += f" I notice your system currently has a {threat_level} threat level. Would you like information about the current security situation?"
            
        return greeting_response
    
    # Context-aware responses to standard topics
    if "password" in query_lower:
        response = ("Strong passwords should be at least 12 characters long, include uppercase and lowercase letters, " 
                "numbers, and special characters. Consider using a password manager to generate and store unique " 
                "passwords for each account. Remember to change critical passwords regularly and never reuse passwords " 
                "across multiple sites.")
                
        # Add context based on system state
        if threat_level != "Low":
            response += f"\n\nGiven the current {threat_level} threat level, it's especially important to verify that passwords for critical systems haven't been compromised and consider changing them as a precaution."
            
        return response
                
    elif "phishing" in query_lower:
        response = ("Phishing attacks attempt to steal sensitive information by disguising as trustworthy entities. " 
                "Look for warning signs: unexpected requests for personal information, urgent language, " 
                "mismatched or suspicious URLs, and poor grammar or spelling. Always verify the source before " 
                "providing information or clicking links, and use multi-factor authentication when available.")
                
        # Add context if there are alerts related to phishing
        has_phishing_alerts = False
        for alert in alerts:
            alert_text = alert if isinstance(alert, str) else alert.get('message', '')
            if "phish" in alert_text.lower():
                has_phishing_alerts = True
                break
                
        if has_phishing_alerts:
            response += "\n\nImportantly, there are currently active alerts related to phishing attempts in your system. Review these alerts in the Threats section immediately."
            
        return response
                
    elif "vpn" in query_lower:
        return ("A Virtual Private Network (VPN) creates an encrypted connection to protect your online privacy. " 
                "VPNs help secure your data on public Wi-Fi, prevent tracking of your browsing activity, " 
                "and can bypass geo-restrictions. However, not all VPNs are equal - look for those with "
                "strong encryption, a no-logs policy, and good performance.")
                
    elif "ransomware" in query_lower:
        response = ("Ransomware is malware that encrypts your files and demands payment for the decryption key. " 
                "Prevention is key: keep regular backups stored offline, keep software updated, use reputable "
                "security software, be cautious of suspicious emails and links, and restrict user permissions. " 
                "If infected, isolate affected systems immediately and contact cybersecurity professionals.")
                
        # Add context based on current ransomware alerts
        has_ransomware_alerts = False
        for alert in alerts:
            alert_text = alert if isinstance(alert, str) else alert.get('message', '')
            if "ransom" in alert_text.lower():
                has_ransomware_alerts = True
                break
                
        if has_ransomware_alerts:
            response += "\n\nCAUTION: There are currently ransomware-related alerts in your system! Check the Threats section immediately and consider initiating your incident response plan."
        
        return response
                
    elif "firewall" in query_lower:
        response = ("A firewall is a network security device that monitors and filters incoming and outgoing traffic. " 
                "It acts as a barrier between a trusted network and untrusted networks like the internet. " 
                "Both hardware and software firewalls are important - ensure your operating system's built-in " 
                "firewall is active and consider additional protection for sensitive environments.")
                
        # Add network context
        if network_data and network_data.get("connections", 0) > 50:
            response += "\n\nYour network currently has a significant number of connections. Ensure your firewall rules are optimized to handle this level of traffic while maintaining security."
            
        return response
                
    elif "two-factor" in query_lower or "2fa" in query_lower or "mfa" in query_lower:
        response = ("Multi-factor authentication (MFA) adds an extra security layer by requiring two or more verification " 
                "methods. This typically combines something you know (password) with something you have (phone) or " 
                "something you are (biometrics). MFA significantly reduces the risk of unauthorized access even if " 
                "your password is compromised. Whenever possible, enable MFA on all important accounts.")
                
        # Add context based on threat level
        if threat_level != "Low":
            response += f"\n\nWith your current {threat_level} threat level, ensuring MFA is enabled on all critical systems should be a top priority. This can help prevent unauthorized access even if credentials have been compromised."
            
        return response
                
    elif "quantum" in query_lower and ("computing" in query_lower or "cryptography" in query_lower):
        return ("Quantum computing poses both threats and opportunities for cybersecurity. Future quantum computers " 
                "could break common encryption methods like RSA and ECC. To prepare, organizations should implement " 
                "crypto-agility, inventory cryptographic assets, and begin transitioning to quantum-resistant " 
                "algorithms. NIST is standardizing post-quantum cryptography methods that will be resistant to " 
                "quantum attacks.")
                
    elif "zero day" in query_lower or "0-day" in query_lower:
        response = ("Zero-day vulnerabilities are software flaws unknown to the vendor and without available patches. " 
                "These are particularly dangerous as attackers can exploit them before fixes are developed. " 
                "Defenses include: defense-in-depth strategies, keeping systems updated, network segmentation, " 
                "behavior-based detection, and limiting user privileges.")
                
        # Add context if there are potential zero-day alerts
        has_zeroday_alerts = False
        for alert in alerts:
            alert_text = alert if isinstance(alert, str) else alert.get('message', '')
            if "zero" in alert_text.lower() or "0-day" in alert_text.lower():
                has_zeroday_alerts = True
                break
                
        if has_zeroday_alerts:
            response += "\n\nWARNING: There are potential zero-day vulnerability alerts in your system. These require immediate attention as they represent a significant security risk."
            
        return response
                
    elif "social engineering" in query_lower:
        return ("Social engineering attacks manipulate people into divulging confidential information or performing " 
                "actions that compromise security. Common techniques include phishing, pretexting, baiting, and " 
                "tailgating. Protect yourself through awareness training, verifying identities through official " 
                "channels, questioning unusual requests, and following security procedures even when inconvenient.")
    
    # General response for other cybersecurity queries - now with context awareness
    elif any(term in query_lower for term in ["security", "cyber", "hack", "threat", "attack", "vulnerability", "breach", "encryption", "protect"]):
        # Base responses
        responses = [
            "Cybersecurity is a continuous process, not just a one-time solution. Regular updates, monitoring, and training are essential components of effective security.",
            "The human element is often the weakest link in security. Regular security awareness training for all users is crucial for maintaining a strong security posture.",
            "Defense in depth is a key principle in cybersecurity - using multiple layers of security controls throughout your systems and networks.",
            "Regular security assessments and penetration testing can help identify vulnerabilities before attackers do.",
            "For organizations, having an incident response plan is crucial. It's not just about prevention, but also about effective response when incidents occur."
        ]
        
        base_response = random.choice(responses)
        
        # Add context based on current system status
        if threat_level != "Low":
            base_response += f"\n\nWith your current {threat_level} threat level, I recommend reviewing the Threats section of the dashboard for detailed information about potential security issues."
        elif len(alerts) > 0:
            base_response += f"\n\nYou currently have {len(alerts)} security alerts that may require attention."
            
        return base_response
    
    # Default response - now with context awareness
    else:
        response = ("I'm your Quantum Security Assistant specialized in cybersecurity topics. I can answer questions about "
                "passwords, phishing, ransomware, firewalls, encryption, quantum security, and more. "
                "How can I help protect your digital security today?")
                
        # Add context about system status
        if threat_level != "Low" or len(alerts) > 0:
            response += f"\n\nI notice your system currently has a {threat_level} threat level"
            if len(alerts) > 0:
                response += f" with {len(alerts)} active alerts"
            response += ". You can ask me about 'current status' for more details."
            
        return response

def app():
    """Chat interface with the security AI assistant."""
    st.title("🤖 Security AI Assistant")
    st.markdown("Ask questions about cybersecurity, threats, and best practices")
    
    # Initialize chat history
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    
    # Sidebar with suggested questions
    with st.sidebar:
        # Context-aware system status questions
        st.subheader("System Status")
        system_questions = [
            "What is the current system status?",
            "What alerts are active right now?",
            "Tell me about my network",
            "What actions do you recommend based on current threats?"
        ]
        
        for question in system_questions:
            if st.button(question, key=f"sys_{question}"):
                # Add user question to history
                st.session_state.chat_history.append({
                    "role": "user",
                    "content": question,
                    "time": datetime.now().strftime("%H:%M")
                })
                
                # Generate and add AI response
                ai_response = generate_ai_response(question)
                st.session_state.chat_history.append({
                    "role": "assistant",
                    "content": ai_response,
                    "time": datetime.now().strftime("%H:%M")
                })
                
                # Force a rerun to show the updated chat immediately
                st.rerun()
        
        # General cybersecurity questions
        st.subheader("Cybersecurity Topics")
        suggestion_buttons = [
            "What is a strong password?",
            "How do I recognize phishing attacks?",
            "What is ransomware and how can I prevent it?",
            "What is quantum cryptography?",
            "How does multi-factor authentication work?",
            "What are zero-day vulnerabilities?",
            "How can I protect against social engineering?"
        ]
        
        for suggestion in suggestion_buttons:
            if st.button(suggestion, key=f"sugg_{suggestion}"):
                # Add user question to history
                st.session_state.chat_history.append({
                    "role": "user",
                    "content": suggestion,
                    "time": datetime.now().strftime("%H:%M")
                })
                
                # Generate and add AI response
                ai_response = generate_ai_response(suggestion)
                st.session_state.chat_history.append({
                    "role": "assistant",
                    "content": ai_response,
                    "time": datetime.now().strftime("%H:%M")
                })
                
                # Force a rerun to show the updated chat immediately
                st.rerun()
    
    # Chat container
    chat_container = st.container()
    
    # Display chat history
    with chat_container:
        for message in st.session_state.chat_history:
            if message["role"] == "user":
                st.markdown(f"""
                <div style="display: flex; flex-direction: row-reverse; margin-bottom: 10px;">
                    <div style="background-color: #1976D2; color: white; padding: 10px 15px; border-radius: 20px; max-width: 70%;">
                        {message["content"]}
                        <div style="font-size: 0.7em; color: rgba(255,255,255,0.7); text-align: right; margin-top: 5px;">
                            {message["time"]}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="display: flex; margin-bottom: 10px;">
                    <div style="background-color: #263238; color: white; padding: 10px 15px; border-radius: 20px; max-width: 70%;">
                        {message["content"]}
                        <div style="font-size: 0.7em; color: rgba(255,255,255,0.7); text-align: right; margin-top: 5px;">
                            {message["time"]}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
    # Input area
    user_input = st.chat_input("Ask a question about cybersecurity...")
    
    if user_input:
        # Add user message to history
        st.session_state.chat_history.append({
            "role": "user",
            "content": user_input,
            "time": datetime.now().strftime("%H:%M")
        })
        
        # Show "typing" indicator
        with chat_container:
            typing_placeholder = st.empty()
            typing_placeholder.markdown("*Assistant is typing...*")
            
            # Generate response with delay to simulate thinking
            ai_response = generate_ai_response(user_input)
            
            # Remove typing indicator
            typing_placeholder.empty()
            
            # Add AI response to history
            st.session_state.chat_history.append({
                "role": "assistant",
                "content": ai_response,
                "time": datetime.now().strftime("%H:%M")
            })
            
            # Force a rerun to show the updated chat
            st.rerun()
    
    # Clear chat button
    if st.session_state.chat_history:
        if st.button("Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()
    
    # OpenAI integration status
    if os.environ.get("OPENAI_API_KEY"):
        st.success("✅ OpenAI integration is active! The assistant will use OpenAI's powerful AI models to provide more dynamic and comprehensive responses.")
    else:
        st.warning("⚠️ OpenAI API key not detected. The assistant is using simulated responses. To enable AI-powered responses, set the OPENAI_API_KEY environment variable.")
        st.info("Click below to add your OpenAI API key for enhanced AI capabilities:")
        if st.button("Configure OpenAI Integration"):
            st.session_state.show_api_input = True
            
    if st.session_state.get("show_api_input", False):
        with st.form("openai_api_key_form"):
            api_key = st.text_input("Enter your OpenAI API key:", type="password")
            submit_button = st.form_submit_button("Save API Key")
            
            if submit_button and api_key:
                # In a real application, this would securely store the API key
                # For this demo, we're just setting it in the environment
                os.environ["OPENAI_API_KEY"] = api_key
                st.success("API key saved! The assistant will now use OpenAI for responses.")
                st.session_state.show_api_input = False
                st.rerun()
    
    # Information about the AI assistant
    with st.expander("About the Security AI Assistant"):
        st.markdown("""
        This is an AI assistant specialized in cybersecurity topics with context-awareness capabilities. 
        It can connect to OpenAI's GPT models to provide dynamic responses, or use simulated responses
        if an OpenAI API key is not available.
        
        ### Capabilities:
        - Answer questions about cybersecurity concepts and best practices
        - Provide guidance on threat prevention and detection
        - Explain security technologies and approaches
        - Offer advice on security incidents
        - **Context-Awareness**: Provides responses based on current system status, threat levels, and active alerts
        - **Personalized Recommendations**: Suggests actions tailored to your current security situation
        - **OpenAI Integration**: Uses OpenAI's advanced AI models when an API key is provided
        
        ### Limitations:
        - Without an OpenAI API key, responses are pre-programmed for a limited set of topics
        - System status integration is for demonstration purposes
        - Not a replacement for professional cybersecurity consultation
        
        ### Using Context-Aware Features:
        Try asking about "current status," "active alerts," "network information," or "recommendations" 
        to see how the assistant incorporates information from your security dashboard into its responses.
        """)

if __name__ == "__main__":
    app()