"""
Mitigation Strategies Page

This page provides detailed mitigation strategies and recommendations for handling
detected security threats, with prioritized action items and implementation guidance.
"""

import streamlit as st
import pandas as pd
import json
from datetime import datetime
import os

# Import utility functions from the project
from utils.openai_integration import get_openai_client, analyze_security_data
from utils.data_generator import generate_threat_data
from utils.quantum_simulation import generate_quantum_security_recommendations


class MitigationStrategies:
    """Implements detailed mitigation strategy recommendations."""
    
    def __init__(self):
        """Initialize the mitigation strategies module."""
        # Check if OpenAI API key is available
        self.openai_available = os.environ.get("OPENAI_API_KEY") is not None
        if self.openai_available:
            try:
                self.client = get_openai_client()
            except Exception as e:
                st.error(f"Error initializing OpenAI client: {e}")
                self.openai_available = False
    
    def generate_mitigation_strategies(self, threat_data, network_data=None):
        """
        Generate detailed mitigation strategies for detected threats using OpenAI.
        
        Args:
            threat_data: DataFrame or dict containing threat information
            network_data: Optional dictionary containing network data
            
        Returns:
            Dictionary with mitigation strategies, prioritized actions, and implementation timeline
        """
        if not self.openai_available:
            return self._generate_simulated_strategies(threat_data)
        
        try:
            # Convert threat data to a suitable format for analysis
            if isinstance(threat_data, pd.DataFrame):
                threats_for_analysis = threat_data.to_dict('records')
            else:
                threats_for_analysis = threat_data
            
            # Combine with network data if available
            analysis_data = {
                "threats": threats_for_analysis,
                "network_context": network_data if network_data else {}
            }
            
            # Convert to JSON string for the prompt
            analysis_json = json.dumps(analysis_data, indent=2)
            
            # Create prompt for OpenAI
            prompt = f"""
            Analyze the following security threat data and provide detailed mitigation strategies:
            
            {analysis_json}
            
            Provide a comprehensive mitigation plan in JSON format with the following structure:
            {{
                "immediate_actions": [
                    {{
                        "action": "<action description>",
                        "priority": "<high/medium/low>",
                        "rationale": "<why this action is needed>",
                        "implementation_steps": ["<step 1>", "<step 2>", ...]
                    }},
                    ...
                ],
                "short_term_strategies": [
                    {{
                        "strategy": "<strategy description>",
                        "timeframe": "<implementation timeframe in days/weeks>",
                        "resources_needed": ["<resource 1>", "<resource 2>", ...],
                        "expected_outcomes": ["<outcome 1>", "<outcome 2>", ...]
                    }},
                    ...
                ],
                "long_term_recommendations": [
                    {{
                        "recommendation": "<recommendation description>",
                        "strategic_impact": "<impact description>",
                        "implementation_considerations": ["<consideration 1>", "<consideration 2>", ...]
                    }},
                    ...
                ],
                "risk_assessment": {{
                    "residual_risk_level": "<high/medium/low>",
                    "confidence_level": "<percentage>",
                    "key_risk_factors": ["<factor 1>", "<factor 2>", ...]
                }},
                "compliance_considerations": ["<consideration 1>", "<consideration 2>", ...],
                "cost_benefit_analysis": "<analysis text>"
            }}
            
            Focus on practical, actionable mitigation strategies that address the specific threats identified.
            Provide a comprehensive approach covering immediate actions, short-term strategies, and long-term recommendations.
            """
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in threat mitigation and incident response."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=1500
            )
            
            # Parse the response
            mitigation_strategies = json.loads(response.choices[0].message.content)
            
            # Add timestamp to the strategies
            mitigation_strategies["timestamp"] = datetime.now().isoformat()
            
            return mitigation_strategies
            
        except Exception as e:
            st.error(f"Error generating mitigation strategies: {e}")
            # Fallback to simulated strategies
            return self._generate_simulated_strategies(threat_data)
    
    def _generate_simulated_strategies(self, threat_data):
        """
        Provide simulated mitigation strategies when OpenAI is not available.
        
        Args:
            threat_data: DataFrame or dict containing threat information
            
        Returns:
            Dictionary with simulated mitigation strategies
        """
        # Create some basic mitigation strategies based on common security practices
        immediate_actions = [
            {
                "action": "Isolate affected systems",
                "priority": "high",
                "rationale": "Prevent threat propagation across the network",
                "implementation_steps": [
                    "Identify affected systems using SIEM logs",
                    "Temporarily remove systems from the network",
                    "Create firewall rules to block suspicious IPs",
                    "Monitor for any attempts to reconnect"
                ]
            },
            {
                "action": "Update intrusion detection signatures",
                "priority": "high",
                "rationale": "Enhance detection capabilities for similar threats",
                "implementation_steps": [
                    "Download latest signature updates from vendor",
                    "Test signatures in a sandbox environment",
                    "Deploy to all network sensors",
                    "Verify detection capability with test cases"
                ]
            },
            {
                "action": "Perform emergency credential rotation",
                "priority": "medium",
                "rationale": "Mitigate risk from potentially compromised credentials",
                "implementation_steps": [
                    "Identify critical system credentials",
                    "Generate new credentials with enhanced complexity",
                    "Distribute through secure channels",
                    "Verify login capability with new credentials"
                ]
            }
        ]
        
        short_term_strategies = [
            {
                "strategy": "Deploy additional network monitoring at critical junctions",
                "timeframe": "1-2 weeks",
                "resources_needed": ["Network taps", "Packet analyzers", "Security analyst time"],
                "expected_outcomes": [
                    "Enhanced visibility into east-west traffic", 
                    "Earlier detection of suspicious activities", 
                    "Better threat hunting capabilities"
                ]
            },
            {
                "strategy": "Conduct targeted security awareness training",
                "timeframe": "2-3 weeks",
                "resources_needed": ["Training materials", "Employee time", "Training platform"],
                "expected_outcomes": [
                    "Improved user awareness of similar threats", 
                    "Reduced likelihood of successful social engineering", 
                    "Better reporting of suspicious activities"
                ]
            }
        ]
        
        long_term_recommendations = [
            {
                "recommendation": "Implement zero trust architecture",
                "strategic_impact": "Fundamental improvement in security posture through principle of least privilege",
                "implementation_considerations": [
                    "Significant infrastructure changes required",
                    "User experience impacts to be carefully managed",
                    "Phased rollout recommended",
                    "Integration with existing identity systems needed"
                ]
            },
            {
                "recommendation": "Develop an advanced threat detection program",
                "strategic_impact": "Capability to detect sophisticated threats that evade conventional detection",
                "implementation_considerations": [
                    "Specialized staff required",
                    "Technology investments needed",
                    "Process development for investigation and response",
                    "Integration with SIEM and other security tools"
                ]
            }
        ]
        
        # Return a comprehensive set of simulated mitigation strategies
        return {
            "immediate_actions": immediate_actions,
            "short_term_strategies": short_term_strategies,
            "long_term_recommendations": long_term_recommendations,
            "risk_assessment": {
                "residual_risk_level": "medium",
                "confidence_level": "75%",
                "key_risk_factors": [
                    "Exploitability of current vulnerabilities",
                    "Attack sophistication level",
                    "Time required to implement mitigations"
                ]
            },
            "compliance_considerations": [
                "Document all mitigation actions for audit purposes",
                "Verify alignment with regulatory requirements",
                "Update risk register and treatment plans",
                "Consider disclosure requirements if personal data is involved"
            ],
            "cost_benefit_analysis": "Implementation of these mitigation strategies requires moderate resource investment but provides substantial risk reduction. The immediate actions are low-cost, high-impact measures that should be prioritized. Long-term recommendations require more significant investment but provide strategic security improvements.",
            "timestamp": datetime.now().isoformat(),
            "simulation_notice": "This analysis is simulated and not based on OpenAI processing."
        }

    def prioritize_actions(self, mitigation_strategies, risk_threshold="medium"):
        """
        Prioritize mitigation actions based on risk level and urgency.
        
        Args:
            mitigation_strategies: Dictionary containing mitigation strategies
            risk_threshold: Minimum risk level to prioritize ('low', 'medium', 'high')
            
        Returns:
            List of prioritized actions
        """
        # Extract all actions from different timeframes
        all_actions = []
        
        # Process immediate actions
        for action in mitigation_strategies.get("immediate_actions", []):
            priority_score = {"high": 3, "medium": 2, "low": 1}.get(action.get("priority", "low"), 1)
            all_actions.append({
                "action": action.get("action"),
                "timeframe": "Immediate",
                "priority_score": priority_score,
                "details": action
            })
        
        # Process short-term strategies
        for strategy in mitigation_strategies.get("short_term_strategies", []):
            # Assign a slightly lower priority score to short-term actions
            priority_score = 2  # Medium priority by default for short-term
            all_actions.append({
                "action": strategy.get("strategy"),
                "timeframe": strategy.get("timeframe", "Short-term"),
                "priority_score": priority_score,
                "details": strategy
            })
        
        # Process long-term recommendations
        for recommendation in mitigation_strategies.get("long_term_recommendations", []):
            # Assign lowest priority score to long-term recommendations
            priority_score = 1  # Low priority by default for long-term
            all_actions.append({
                "action": recommendation.get("recommendation"),
                "timeframe": "Long-term",
                "priority_score": priority_score,
                "details": recommendation
            })
        
        # Sort actions by priority score (descending)
        prioritized_actions = sorted(all_actions, key=lambda x: x["priority_score"], reverse=True)
        
        # Filter based on risk threshold if needed
        if risk_threshold == "medium":
            prioritized_actions = [action for action in prioritized_actions if action["priority_score"] >= 2]
        elif risk_threshold == "high":
            prioritized_actions = [action for action in prioritized_actions if action["priority_score"] >= 3]
        
        return prioritized_actions

    def calculate_risk_reduction(self, mitigation_strategies):
        """
        Calculate the estimated risk reduction from implementing the mitigation strategies.
        
        Args:
            mitigation_strategies: Dictionary containing mitigation strategies
            
        Returns:
            Dictionary with risk reduction metrics
        """
        # Count the number of high, medium, and low priority actions
        high_priority_count = sum(1 for action in mitigation_strategies.get("immediate_actions", []) 
                                if action.get("priority") == "high")
        medium_priority_count = sum(1 for action in mitigation_strategies.get("immediate_actions", []) 
                                if action.get("priority") == "medium")
        
        # Calculate a weighted risk reduction score
        risk_reduction_score = (high_priority_count * 15) + (medium_priority_count * 8)
        
        # Cap the risk reduction percentage at 95%
        risk_reduction_percentage = min(95, risk_reduction_score)
        
        # Determine the new risk level based on the risk assessment
        residual_risk_level = mitigation_strategies.get("risk_assessment", {}).get("residual_risk_level", "medium")
        
        # Map the residual risk level to a numeric value
        residual_risk_value = {"low": 25, "medium": 50, "high": 75}.get(residual_risk_level, 50)
        
        return {
            "original_risk": 100,  # Assuming maximum risk before mitigation
            "residual_risk": max(5, 100 - risk_reduction_percentage),  # Minimum 5% residual risk
            "risk_reduction": risk_reduction_percentage,
            "confidence": int(mitigation_strategies.get("risk_assessment", {})
                          .get("confidence_level", "75%").rstrip("%"))
        }


def app():
    """Main function for the mitigation strategies page."""
    st.title("Mitigation Strategies")
    st.write("Detailed recommendations for handling detected security threats with prioritized action items.")
    
    # Initialize the mitigation strategies module
    mitigation = MitigationStrategies()
    
    # Add sidebar options
    with st.sidebar:
        st.header("Strategy Options")
        
        threat_scenario = st.selectbox(
            "Threat Scenario",
            ["Current Threats", "Ransomware Attack", "Data Breach", "Insider Threat", "DDoS Attack", "Advanced Persistent Threat"]
        )
        
        risk_tolerance = st.select_slider(
            "Risk Tolerance",
            options=["Minimal", "Conservative", "Balanced", "Tolerant", "Maximum"],
            value="Balanced"
        )
        
        st.divider()
        
        # Add options for displaying results
        display_options = st.multiselect(
            "Display Options",
            ["Immediate Actions", "Short-term Strategies", "Long-term Recommendations", 
             "Risk Assessment", "Compliance Considerations", "Cost-Benefit Analysis"],
            default=["Immediate Actions", "Short-term Strategies", "Risk Assessment"]
        )
        
        # Add button to generate strategies
        generate_button = st.button("Generate Mitigation Strategies", use_container_width=True)
    
    # Main content area
    if generate_button or "mitigation_strategies" in st.session_state:
        if generate_button:
            # Generate threat data based on selected scenario
            if threat_scenario == "Current Threats" and "network_data" in st.session_state:
                # Use current threats from session state if available
                with st.spinner("Analyzing current threats..."):
                    if "threat_data" in st.session_state:
                        threat_data = st.session_state.threat_data
                    else:
                        threat_data = generate_threat_data()
                    network_data = st.session_state.network_data
                    
                    # Generate mitigation strategies
                    mitigation_strategies = mitigation.generate_mitigation_strategies(threat_data, network_data)
                    st.session_state.mitigation_strategies = mitigation_strategies
            else:
                # Generate simulated threats based on the selected scenario
                with st.spinner(f"Analyzing {threat_scenario} scenario..."):
                    # Create specialized threat data for the scenario
                    if threat_scenario == "Ransomware Attack":
                        threat_data = {
                            "type": "Ransomware Attack",
                            "severity": "Critical",
                            "affected_systems": ["File Servers", "Employee Workstations", "Database Servers"],
                            "indicators": ["Encrypted Files", "Ransom Notes", "Unauthorized Access Attempts"],
                            "possible_vectors": ["Phishing Email", "Vulnerable VPN", "Compromised Credentials"]
                        }
                    elif threat_scenario == "Data Breach":
                        threat_data = {
                            "type": "Data Breach",
                            "severity": "High",
                            "affected_systems": ["Customer Database", "Financial Records", "HR Systems"],
                            "indicators": ["Unusual Data Access Patterns", "Large Data Transfers", "Unauthorized Queries"],
                            "possible_vectors": ["SQL Injection", "Stolen Credentials", "Insecure API"]
                        }
                    elif threat_scenario == "Insider Threat":
                        threat_data = {
                            "type": "Insider Threat",
                            "severity": "High",
                            "affected_systems": ["Intellectual Property Storage", "Financial Systems", "Customer Data"],
                            "indicators": ["Unusual Access Times", "Excessive Privilege Usage", "Large Downloads"],
                            "possible_vectors": ["Privileged User", "Terminated Employee", "Contractor Access"]
                        }
                    elif threat_scenario == "DDoS Attack":
                        threat_data = {
                            "type": "DDoS Attack",
                            "severity": "Medium",
                            "affected_systems": ["Web Servers", "DNS Infrastructure", "Network Edge Devices"],
                            "indicators": ["High Traffic Volume", "Service Degradation", "Unusual Traffic Patterns"],
                            "possible_vectors": ["Botnet", "Amplification Attack", "Application Layer Attack"]
                        }
                    elif threat_scenario == "Advanced Persistent Threat":
                        threat_data = {
                            "type": "Advanced Persistent Threat",
                            "severity": "Critical",
                            "affected_systems": ["Authentication Systems", "Domain Controllers", "Strategic Information Assets"],
                            "indicators": ["Unusual Lateral Movement", "Persistent Access", "Data Staging"],
                            "possible_vectors": ["Spear Phishing", "Supply Chain Compromise", "Zero-Day Exploitation"]
                        }
                    else:
                        threat_data = generate_threat_data()
                    
                    # Generate mitigation strategies
                    mitigation_strategies = mitigation.generate_mitigation_strategies(threat_data)
                    st.session_state.mitigation_strategies = mitigation_strategies
                    st.session_state.threat_scenario = threat_scenario
            
            # Calculate risk reduction metrics
            risk_metrics = mitigation.calculate_risk_reduction(mitigation_strategies)
            st.session_state.risk_metrics = risk_metrics
            
            # Prioritize actions based on risk tolerance
            risk_threshold = {
                "Minimal": "low",
                "Conservative": "low",
                "Balanced": "medium",
                "Tolerant": "medium",
                "Maximum": "high"
            }.get(risk_tolerance, "medium")
            
            prioritized_actions = mitigation.prioritize_actions(mitigation_strategies, risk_threshold)
            st.session_state.prioritized_actions = prioritized_actions
        
        # Display the results
        if "mitigation_strategies" in st.session_state:
            mitigation_strategies = st.session_state.mitigation_strategies
            risk_metrics = st.session_state.get("risk_metrics", {})
            prioritized_actions = st.session_state.get("prioritized_actions", [])
            
            # Display summary metrics
            st.header("Mitigation Strategy Summary")
            
            if "threat_scenario" in st.session_state:
                st.subheader(f"Scenario: {st.session_state.threat_scenario}")
            
            # Create metrics for risk reduction
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Original Risk", f"{risk_metrics.get('original_risk', 100)}%")
            
            with col2:
                st.metric("Risk Reduction", f"{risk_metrics.get('risk_reduction', 0)}%", 
                         delta=f"{risk_metrics.get('risk_reduction', 0)}%", delta_color="normal")
            
            with col3:
                residual_risk = risk_metrics.get('residual_risk', 100)
                st.metric("Residual Risk", f"{residual_risk}%", 
                         delta=f"-{100 - residual_risk}%", delta_color="inverse")
            
            with col4:
                st.metric("Confidence", f"{risk_metrics.get('confidence', 75)}%")
            
            # Display prioritized actions
            st.header("Prioritized Action Plan")
            
            if prioritized_actions:
                # Create a prioritized action table
                for i, action in enumerate(prioritized_actions[:10]):  # Show top 10 actions
                    priority_color = "red" if action["priority_score"] == 3 else "orange" if action["priority_score"] == 2 else "blue"
                    
                    with st.container():
                        st.markdown(f"### {i+1}. {action['action']}")
                        st.markdown(f"**Timeframe:** {action['timeframe']} • **Priority:** "
                                   f"<span style='color:{priority_color};font-weight:bold;'>"
                                   f"{'High' if action['priority_score'] == 3 else 'Medium' if action['priority_score'] == 2 else 'Low'}"
                                   f"</span>", unsafe_allow_html=True)
                        
                        # Show additional details based on action type
                        if action["timeframe"] == "Immediate":
                            st.markdown(f"**Rationale:** {action['details'].get('rationale', 'N/A')}")
                            
                            if "implementation_steps" in action["details"]:
                                with st.expander("Implementation Steps"):
                                    for step in action["details"]["implementation_steps"]:
                                        st.markdown(f"• {step}")
                        elif "expected_outcomes" in action["details"]:
                            with st.expander("Expected Outcomes"):
                                for outcome in action["details"].get("expected_outcomes", []):
                                    st.markdown(f"• {outcome}")
                        else:
                            st.markdown("See details in the full strategy below.")
                        
                        st.divider()
            else:
                st.info("No prioritized actions available. Try generating mitigation strategies first.")
            
            # Display detailed sections based on display options
            st.markdown("---")
            st.header("Detailed Mitigation Strategy")
            
            if "Immediate Actions" in display_options and "immediate_actions" in mitigation_strategies:
                st.subheader("Immediate Actions")
                
                for i, action in enumerate(mitigation_strategies["immediate_actions"]):
                    priority_color = "red" if action.get("priority") == "high" else "orange" if action.get("priority") == "medium" else "blue"
                    
                    with st.expander(f"{action.get('action')} (Priority: {action.get('priority', 'N/A')})"):
                        st.markdown(f"**Priority:** <span style='color:{priority_color};font-weight:bold;'>{action.get('priority', 'N/A')}</span>", 
                                   unsafe_allow_html=True)
                        st.markdown(f"**Rationale:** {action.get('rationale', 'N/A')}")
                        
                        if "implementation_steps" in action:
                            st.markdown("#### Implementation Steps")
                            for step in action["implementation_steps"]:
                                st.markdown(f"1. {step}")
            
            if "Short-term Strategies" in display_options and "short_term_strategies" in mitigation_strategies:
                st.subheader("Short-term Strategies")
                
                for i, strategy in enumerate(mitigation_strategies["short_term_strategies"]):
                    with st.expander(f"{strategy.get('strategy')} (Timeframe: {strategy.get('timeframe', 'N/A')})"):
                        st.markdown(f"**Timeframe:** {strategy.get('timeframe', 'N/A')}")
                        
                        if "resources_needed" in strategy:
                            st.markdown("#### Resources Needed")
                            for resource in strategy["resources_needed"]:
                                st.markdown(f"• {resource}")
                        
                        if "expected_outcomes" in strategy:
                            st.markdown("#### Expected Outcomes")
                            for outcome in strategy["expected_outcomes"]:
                                st.markdown(f"• {outcome}")
            
            if "Long-term Recommendations" in display_options and "long_term_recommendations" in mitigation_strategies:
                st.subheader("Long-term Recommendations")
                
                for i, recommendation in enumerate(mitigation_strategies["long_term_recommendations"]):
                    with st.expander(f"{recommendation.get('recommendation')}"):
                        st.markdown(f"**Strategic Impact:** {recommendation.get('strategic_impact', 'N/A')}")
                        
                        if "implementation_considerations" in recommendation:
                            st.markdown("#### Implementation Considerations")
                            for consideration in recommendation["implementation_considerations"]:
                                st.markdown(f"• {consideration}")
            
            if "Risk Assessment" in display_options and "risk_assessment" in mitigation_strategies:
                st.subheader("Risk Assessment")
                
                risk_assessment = mitigation_strategies["risk_assessment"]
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Residual Risk Level:** {risk_assessment.get('residual_risk_level', 'N/A')}")
                    st.markdown(f"**Confidence Level:** {risk_assessment.get('confidence_level', 'N/A')}")
                
                with col2:
                    if "key_risk_factors" in risk_assessment:
                        st.markdown("#### Key Risk Factors")
                        for factor in risk_assessment["key_risk_factors"]:
                            st.markdown(f"• {factor}")
            
            if "Compliance Considerations" in display_options and "compliance_considerations" in mitigation_strategies:
                st.subheader("Compliance Considerations")
                
                for consideration in mitigation_strategies["compliance_considerations"]:
                    st.markdown(f"• {consideration}")
            
            if "Cost-Benefit Analysis" in display_options and "cost_benefit_analysis" in mitigation_strategies:
                st.subheader("Cost-Benefit Analysis")
                st.write(mitigation_strategies["cost_benefit_analysis"])
            
            # Show timestamp and simulation notice
            st.caption(f"Analysis generated at: {mitigation_strategies.get('timestamp', 'N/A')}")
            
            if "simulation_notice" in mitigation_strategies:
                st.info(mitigation_strategies["simulation_notice"])
    else:
        # Show instructions when no analysis has been generated
        st.info("Select a threat scenario and options in the sidebar, then click 'Generate Mitigation Strategies' to get detailed recommendations.")
        
        # Explain the purpose of this page
        st.markdown("""
        ## Mitigation Strategy Analyzer
        
        This tool provides detailed, customized mitigation strategies for various security threat scenarios, including:
        
        - **Immediate actions** to take in response to security incidents
        - **Short-term strategies** to implement within days or weeks
        - **Long-term recommendations** to improve overall security posture
        - **Risk assessment** with residual risk analysis
        - **Compliance considerations** for regulatory requirements
        - **Cost-benefit analysis** to prioritize investments
        
        Try different threat scenarios to see tailored recommendations for each situation.
        """)


if __name__ == "__main__":
    app()