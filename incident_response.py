"""
Template for Automated Incident Response

This template provides a foundation for implementing automated incident response
workflows that can be triggered by security events.
"""

import streamlit as st
import pandas as pd
import json
from datetime import datetime, timedelta
import uuid
import time
import os

# Import utility functions from the project
from utils.openai_integration import get_openai_client


class IncidentResponseAutomation:
    """
    Implements automated incident response workflows.
    
    This class provides methods for managing and executing automated
    response workflows for various security incidents.
    """
    
    def __init__(self):
        """Initialize the incident response automation module."""
        # Check if OpenAI API key is available for enhanced response generation
        self.openai_available = os.environ.get("OPENAI_API_KEY") is not None
        if self.openai_available:
            try:
                self.client = get_openai_client()
            except Exception as e:
                st.error(f"Error initializing OpenAI client: {e}")
                self.openai_available = False
        
        # Initialize incident catalog
        if "incident_catalog" not in st.session_state:
            st.session_state.incident_catalog = self._init_incident_catalog()
        
        # Initialize response playbooks
        if "response_playbooks" not in st.session_state:
            st.session_state.response_playbooks = self._init_response_playbooks()
        
        # Initialize active incidents
        if "active_incidents" not in st.session_state:
            st.session_state.active_incidents = []
        
        # Initialize incident history
        if "incident_history" not in st.session_state:
            st.session_state.incident_history = []
    
    def _init_incident_catalog(self):
        """
        Initialize the catalog of incident types.
        
        Returns:
            Dictionary of incident types and their details
        """
        return {
            "data_breach": {
                "name": "Data Breach",
                "description": "Unauthorized access or exfiltration of sensitive data",
                "severity_levels": ["Low", "Medium", "High", "Critical"],
                "default_severity": "High",
                "default_playbook": "data_breach_response"
            },
            "ddos": {
                "name": "DDoS Attack",
                "description": "Distributed Denial of Service attack on network resources",
                "severity_levels": ["Low", "Medium", "High", "Critical"],
                "default_severity": "Medium",
                "default_playbook": "ddos_response"
            },
            "ransomware": {
                "name": "Ransomware Infection",
                "description": "Malicious encryption of data with ransom demand",
                "severity_levels": ["Medium", "High", "Critical"],
                "default_severity": "Critical",
                "default_playbook": "ransomware_response"
            },
            "unauthorized_access": {
                "name": "Unauthorized Access",
                "description": "Unauthorized login or privilege escalation",
                "severity_levels": ["Low", "Medium", "High", "Critical"],
                "default_severity": "Medium",
                "default_playbook": "unauthorized_access_response"
            },
            "phishing": {
                "name": "Phishing Campaign",
                "description": "Targeted phishing attack against organization",
                "severity_levels": ["Low", "Medium", "High"],
                "default_severity": "Medium",
                "default_playbook": "phishing_response"
            },
            "malware": {
                "name": "Malware Infection",
                "description": "Malicious software detected on systems",
                "severity_levels": ["Low", "Medium", "High", "Critical"],
                "default_severity": "Medium",
                "default_playbook": "malware_response"
            },
            "insider_threat": {
                "name": "Insider Threat",
                "description": "Malicious activity by authorized user",
                "severity_levels": ["Medium", "High", "Critical"],
                "default_severity": "High",
                "default_playbook": "insider_threat_response"
            },
            "zero_day": {
                "name": "Zero-Day Exploit",
                "description": "Attack using previously unknown vulnerability",
                "severity_levels": ["High", "Critical"],
                "default_severity": "Critical",
                "default_playbook": "zero_day_response"
            }
        }
    
    def _init_response_playbooks(self):
        """
        Initialize the library of response playbooks.
        
        Returns:
            Dictionary of playbooks and their steps
        """
        return {
            "data_breach_response": {
                "name": "Data Breach Response Playbook",
                "description": "Standard response for data breach incidents",
                "steps": [
                    {
                        "name": "Isolate affected systems",
                        "description": "Disconnect affected systems from the network to prevent further data exfiltration",
                        "automation_level": "Partial",
                        "estimated_time": 15  # minutes
                    },
                    {
                        "name": "Preserve evidence",
                        "description": "Create forensic image of affected systems for investigation",
                        "automation_level": "Partial",
                        "estimated_time": 60
                    },
                    {
                        "name": "Identify compromised data",
                        "description": "Determine what data was accessed or exfiltrated",
                        "automation_level": "Manual",
                        "estimated_time": 120
                    },
                    {
                        "name": "Patch vulnerability",
                        "description": "Apply security patches to prevent similar breaches",
                        "automation_level": "Partial",
                        "estimated_time": 45
                    },
                    {
                        "name": "Notification and reporting",
                        "description": "Notify affected parties and relevant authorities",
                        "automation_level": "Manual",
                        "estimated_time": 90
                    }
                ]
            },
            "ddos_response": {
                "name": "DDoS Attack Response",
                "description": "Response to mitigate Distributed Denial of Service attacks",
                "steps": [
                    {
                        "name": "Traffic analysis",
                        "description": "Analyze attack traffic patterns to identify attack type",
                        "automation_level": "Full",
                        "estimated_time": 10
                    },
                    {
                        "name": "Implement traffic filtering",
                        "description": "Configure network devices to filter malicious traffic",
                        "automation_level": "Full",
                        "estimated_time": 15
                    },
                    {
                        "name": "Scale resources",
                        "description": "Increase capacity to absorb attack traffic",
                        "automation_level": "Full",
                        "estimated_time": 20
                    },
                    {
                        "name": "Contact ISP",
                        "description": "Engage with Internet Service Provider for upstream filtering",
                        "automation_level": "Manual",
                        "estimated_time": 30
                    },
                    {
                        "name": "Post-attack analysis",
                        "description": "Document attack patterns and improve defenses",
                        "automation_level": "Manual",
                        "estimated_time": 60
                    }
                ]
            },
            # Define other playbooks similarly
            "ransomware_response": {
                "name": "Ransomware Response Playbook",
                "description": "Containment and recovery from ransomware incidents",
                "steps": [
                    {
                        "name": "Isolate infected systems",
                        "description": "Disconnect infected systems to prevent spread",
                        "automation_level": "Full",
                        "estimated_time": 10
                    },
                    {
                        "name": "Identify ransomware variant",
                        "description": "Determine the specific ransomware variant",
                        "automation_level": "Partial",
                        "estimated_time": 30
                    },
                    {
                        "name": "Assess backup availability",
                        "description": "Verify availability and integrity of backups",
                        "automation_level": "Full",
                        "estimated_time": 20
                    },
                    {
                        "name": "Restore from backups",
                        "description": "Restore systems and data from clean backups",
                        "automation_level": "Partial",
                        "estimated_time": 180
                    },
                    {
                        "name": "Investigate infection vector",
                        "description": "Determine how the ransomware entered the environment",
                        "automation_level": "Manual",
                        "estimated_time": 120
                    },
                    {
                        "name": "Strengthen defenses",
                        "description": "Apply security controls to prevent reinfection",
                        "automation_level": "Partial",
                        "estimated_time": 60
                    }
                ]
            }
            # Add more playbooks as needed
        }
    
    def get_incident_types(self):
        """
        Get the list of incident types.
        
        Returns:
            Dictionary of incident types
        """
        return st.session_state.incident_catalog
    
    def get_playbooks(self):
        """
        Get the list of response playbooks.
        
        Returns:
            Dictionary of playbooks
        """
        return st.session_state.response_playbooks
    
    def create_incident(self, incident_type, severity=None, details=None, assets_affected=None):
        """
        Create a new security incident.
        
        Args:
            incident_type: Type of incident from the catalog
            severity: Severity level (optional, uses default if not specified)
            details: Additional details about the incident
            assets_affected: List of affected assets
            
        Returns:
            Dictionary with incident details
        """
        # Get incident type details
        if incident_type not in st.session_state.incident_catalog:
            return {
                "status": "error",
                "message": f"Unknown incident type: {incident_type}"
            }
        
        incident_info = st.session_state.incident_catalog[incident_type]
        
        # Set severity
        if severity is None or severity not in incident_info["severity_levels"]:
            severity = incident_info["default_severity"]
        
        # Generate incident ID
        incident_id = str(uuid.uuid4())[:8]
        
        # Create incident record
        incident = {
            "id": incident_id,
            "type": incident_type,
            "name": incident_info["name"],
            "severity": severity,
            "details": details if details else "No additional details provided",
            "assets_affected": assets_affected if assets_affected else [],
            "creation_time": datetime.now(),
            "status": "Open",
            "playbook": incident_info["default_playbook"],
            "current_step": None,
            "completed_steps": [],
            "notes": [],
            "containment_time": None,
            "resolution_time": None
        }
        
        # Add to active incidents
        st.session_state.active_incidents.append(incident)
        
        return {
            "status": "success",
            "message": f"Incident {incident_id} created successfully",
            "incident": incident
        }
    
    def get_active_incidents(self):
        """
        Get list of active incidents.
        
        Returns:
            List of active incident records
        """
        return st.session_state.active_incidents
    
    def get_incident_history(self):
        """
        Get list of historical (resolved) incidents.
        
        Returns:
            List of historical incident records
        """
        return st.session_state.incident_history
    
    def get_incident(self, incident_id):
        """
        Get details of a specific incident.
        
        Args:
            incident_id: ID of the incident
            
        Returns:
            Incident record or None if not found
        """
        # Check active incidents
        for incident in st.session_state.active_incidents:
            if incident["id"] == incident_id:
                return incident
        
        # Check incident history
        for incident in st.session_state.incident_history:
            if incident["id"] == incident_id:
                return incident
        
        return None
    
    def update_incident(self, incident_id, updates):
        """
        Update an incident record.
        
        Args:
            incident_id: ID of the incident to update
            updates: Dictionary of fields to update
            
        Returns:
            Dictionary with update status
        """
        # Find the incident
        incident = None
        incident_index = None
        in_active = True
        
        for i, inc in enumerate(st.session_state.active_incidents):
            if inc["id"] == incident_id:
                incident = inc
                incident_index = i
                break
        
        if incident is None:
            # Check incident history
            for i, inc in enumerate(st.session_state.incident_history):
                if inc["id"] == incident_id:
                    incident = inc
                    incident_index = i
                    in_active = False
                    break
        
        if incident is None:
            return {
                "status": "error",
                "message": f"Incident {incident_id} not found"
            }
        
        # Apply updates
        for key, value in updates.items():
            if key in incident:
                incident[key] = value
        
        # Handle status changes
        if "status" in updates:
            if updates["status"] == "Contained" and not incident.get("containment_time"):
                incident["containment_time"] = datetime.now()
            elif updates["status"] == "Resolved" and not incident.get("resolution_time"):
                incident["resolution_time"] = datetime.now()
                
                # Move to history if resolved
                if in_active:
                    st.session_state.active_incidents.pop(incident_index)
                    st.session_state.incident_history.append(incident)
                    in_active = False
        
        # Update the incident in the appropriate list
        if in_active:
            st.session_state.active_incidents[incident_index] = incident
        else:
            st.session_state.incident_history[incident_index] = incident
        
        return {
            "status": "success",
            "message": f"Incident {incident_id} updated successfully",
            "incident": incident
        }
    
    def add_incident_note(self, incident_id, note):
        """
        Add a note to an incident.
        
        Args:
            incident_id: ID of the incident
            note: Note content
            
        Returns:
            Dictionary with update status
        """
        # Find the incident
        incident = self.get_incident(incident_id)
        
        if incident is None:
            return {
                "status": "error",
                "message": f"Incident {incident_id} not found"
            }
        
        # Create note with timestamp
        note_entry = {
            "time": datetime.now(),
            "content": note
        }
        
        # Add to incident notes
        updates = {
            "notes": incident["notes"] + [note_entry]
        }
        
        # Update the incident
        return self.update_incident(incident_id, updates)
    
    def get_playbook_steps(self, playbook_id):
        """
        Get steps for a specific playbook.
        
        Args:
            playbook_id: ID of the playbook
            
        Returns:
            List of playbook steps or None if not found
        """
        if playbook_id not in st.session_state.response_playbooks:
            return None
        
        return st.session_state.response_playbooks[playbook_id]["steps"]
    
    def start_playbook(self, incident_id):
        """
        Start executing a response playbook for an incident.
        
        Args:
            incident_id: ID of the incident
            
        Returns:
            Dictionary with operation status
        """
        # Find the incident
        incident = self.get_incident(incident_id)
        
        if incident is None:
            return {
                "status": "error",
                "message": f"Incident {incident_id} not found"
            }
        
        # Check if a playbook is assigned
        playbook_id = incident.get("playbook")
        if not playbook_id or playbook_id not in st.session_state.response_playbooks:
            return {
                "status": "error",
                "message": f"No valid playbook assigned to incident {incident_id}"
            }
        
        # Get playbook steps
        steps = self.get_playbook_steps(playbook_id)
        if not steps:
            return {
                "status": "error",
                "message": f"Playbook {playbook_id} has no steps"
            }
        
        # Set the current step to the first step
        updates = {
            "current_step": 0,
            "completed_steps": []
        }
        
        # Update the incident
        result = self.update_incident(incident_id, updates)
        
        # Add a note about starting the playbook
        playbook_name = st.session_state.response_playbooks[playbook_id]["name"]
        note = f"Started playbook: {playbook_name}"
        self.add_incident_note(incident_id, note)
        
        return {
            "status": "success",
            "message": f"Started playbook {playbook_name} for incident {incident_id}",
            "current_step": steps[0]
        }
    
    def complete_current_step(self, incident_id, note=None):
        """
        Mark the current playbook step as completed and advance to the next step.
        
        Args:
            incident_id: ID of the incident
            note: Optional note about step completion
            
        Returns:
            Dictionary with operation status
        """
        # Find the incident
        incident = self.get_incident(incident_id)
        
        if incident is None:
            return {
                "status": "error",
                "message": f"Incident {incident_id} not found"
            }
        
        # Check if a playbook is in progress
        current_step_index = incident.get("current_step")
        if current_step_index is None:
            return {
                "status": "error",
                "message": f"No playbook in progress for incident {incident_id}"
            }
        
        # Get playbook steps
        playbook_id = incident.get("playbook")
        steps = self.get_playbook_steps(playbook_id)
        if not steps:
            return {
                "status": "error",
                "message": f"Playbook {playbook_id} has no steps"
            }
        
        # Get current step
        current_step = steps[current_step_index]
        
        # Add to completed steps
        completed_steps = incident.get("completed_steps", [])
        completed_steps.append({
            "step_index": current_step_index,
            "step_name": current_step["name"],
            "completion_time": datetime.now()
        })
        
        # Add note if provided
        if note:
            self.add_incident_note(incident_id, note)
        
        # Determine next step
        next_step_index = current_step_index + 1
        if next_step_index >= len(steps):
            # All steps completed
            updates = {
                "current_step": None,
                "completed_steps": completed_steps,
                "status": "Contained"  # Mark as contained when playbook completed
            }
            
            result = self.update_incident(incident_id, updates)
            
            # Add note about playbook completion
            playbook_name = st.session_state.response_playbooks[playbook_id]["name"]
            completion_note = f"Completed all steps in playbook: {playbook_name}"
            self.add_incident_note(incident_id, completion_note)
            
            return {
                "status": "success",
                "message": f"Completed all steps in playbook for incident {incident_id}",
                "playbook_completed": True
            }
        else:
            # Move to next step
            updates = {
                "current_step": next_step_index,
                "completed_steps": completed_steps
            }
            
            result = self.update_incident(incident_id, updates)
            
            return {
                "status": "success",
                "message": f"Advanced to next step for incident {incident_id}",
                "next_step": steps[next_step_index]
            }
    
    def generate_incident_report(self, incident_id):
        """
        Generate a detailed incident report.
        
        Args:
            incident_id: ID of the incident
            
        Returns:
            Dictionary with report details
        """
        # Find the incident
        incident = self.get_incident(incident_id)
        
        if incident is None:
            return {
                "status": "error",
                "message": f"Incident {incident_id} not found"
            }
        
        # Basic report structure
        report = {
            "incident_id": incident_id,
            "incident_type": incident["name"],
            "severity": incident["severity"],
            "creation_time": incident["creation_time"].strftime("%Y-%m-%d %H:%M:%S"),
            "current_status": incident["status"],
            "details": incident["details"],
            "assets_affected": incident["assets_affected"],
            "playbook_used": None,
            "containment_time": None,
            "resolution_time": None,
            "time_to_containment": None,
            "time_to_resolution": None,
            "steps_taken": [],
            "notes": [note["content"] for note in incident["notes"]],
            "recommendations": []
        }
        
        # Add containment and resolution times if available
        if incident.get("containment_time"):
            report["containment_time"] = incident["containment_time"].strftime("%Y-%m-%d %H:%M:%S")
            
            # Calculate time to containment
            time_to_containment = (incident["containment_time"] - incident["creation_time"]).total_seconds() / 60
            report["time_to_containment"] = f"{time_to_containment:.1f} minutes"
        
        if incident.get("resolution_time"):
            report["resolution_time"] = incident["resolution_time"].strftime("%Y-%m-%d %H:%M:%S")
            
            # Calculate time to resolution
            time_to_resolution = (incident["resolution_time"] - incident["creation_time"]).total_seconds() / 60
            report["time_to_resolution"] = f"{time_to_resolution:.1f} minutes"
        
        # Add playbook information if available
        playbook_id = incident.get("playbook")
        if playbook_id and playbook_id in st.session_state.response_playbooks:
            playbook = st.session_state.response_playbooks[playbook_id]
            report["playbook_used"] = playbook["name"]
            
            # Add steps taken
            for completed_step in incident.get("completed_steps", []):
                report["steps_taken"].append({
                    "name": completed_step["step_name"],
                    "completion_time": completed_step["completion_time"].strftime("%Y-%m-%d %H:%M:%S")
                })
        
        # Generate recommendations with OpenAI if available
        if self.openai_available:
            try:
                recommendations = self._generate_ai_recommendations(incident)
                report["recommendations"] = recommendations
            except Exception as e:
                st.error(f"Error generating AI recommendations: {e}")
                # Fallback to basic recommendations
                report["recommendations"] = self._generate_basic_recommendations(incident)
        else:
            # Generate basic recommendations
            report["recommendations"] = self._generate_basic_recommendations(incident)
        
        return {
            "status": "success",
            "report": report
        }
    
    def _generate_ai_recommendations(self, incident):
        """
        Generate incident response recommendations using OpenAI.
        
        Args:
            incident: Incident record
            
        Returns:
            List of recommendations
        """
        try:
            # Prepare incident data for the AI prompt
            incident_data = {
                "incident_type": incident["name"],
                "severity": incident["severity"],
                "details": incident["details"],
                "assets_affected": incident["assets_affected"],
                "status": incident["status"],
                "notes": [note["content"] for note in incident.get("notes", [])]
            }
            
            # Convert to JSON for the prompt
            incident_json = json.dumps(incident_data, indent=2)
            
            # Create prompt for OpenAI
            prompt = f"""
            Analyze the following security incident and provide specific, actionable recommendations 
            to prevent similar incidents in the future:
            
            {incident_json}
            
            Provide 3-5 specific recommendations in JSON format with the following structure:
            [
                {{
                    "title": "Recommendation title",
                    "description": "Detailed description of the recommendation",
                    "priority": "High/Medium/Low",
                    "implementation_difficulty": "Easy/Moderate/Complex"
                }}
            ]
            
            Focus on concrete, practical steps that would prevent this type of security incident.
            """
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
                messages=[
                    {"role": "system", "content": "You are a cybersecurity incident response expert providing actionable recommendations."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            # Parse the response
            recommendations = json.loads(response.choices[0].message.content)
            
            return recommendations
            
        except Exception as e:
            st.error(f"Error generating AI recommendations: {e}")
            # Fallback to basic recommendations
            return self._generate_basic_recommendations(incident)
    
    def _generate_basic_recommendations(self, incident):
        """
        Generate basic incident response recommendations without AI.
        
        Args:
            incident: Incident record
            
        Returns:
            List of recommendations
        """
        # Basic recommendations based on incident type
        incident_type = incident.get("type")
        
        recommendations = []
        
        if incident_type == "data_breach":
            recommendations = [
                {
                    "title": "Enhance Data Access Controls",
                    "description": "Implement more stringent access controls for sensitive data, including multi-factor authentication and least privilege principles.",
                    "priority": "High",
                    "implementation_difficulty": "Moderate"
                },
                {
                    "title": "Improve Data Encryption",
                    "description": "Ensure all sensitive data is encrypted both at rest and in transit using industry-standard encryption protocols.",
                    "priority": "High",
                    "implementation_difficulty": "Moderate"
                },
                {
                    "title": "Implement Data Loss Prevention",
                    "description": "Deploy data loss prevention (DLP) tools to monitor and control data transfers and prevent unauthorized exfiltration.",
                    "priority": "Medium",
                    "implementation_difficulty": "Complex"
                }
            ]
        elif incident_type == "ransomware":
            recommendations = [
                {
                    "title": "Enhance Backup Strategy",
                    "description": "Implement a comprehensive 3-2-1 backup strategy with offline copies that cannot be affected by ransomware.",
                    "priority": "High",
                    "implementation_difficulty": "Moderate"
                },
                {
                    "title": "Email Security Training",
                    "description": "Conduct regular phishing awareness training for all employees to reduce the risk of ransomware entry points.",
                    "priority": "Medium",
                    "implementation_difficulty": "Easy"
                },
                {
                    "title": "Application Whitelisting",
                    "description": "Implement application whitelisting to prevent unauthorized executables from running on systems.",
                    "priority": "High",
                    "implementation_difficulty": "Complex"
                }
            ]
        elif incident_type == "ddos":
            recommendations = [
                {
                    "title": "Implement DDoS Protection Service",
                    "description": "Subscribe to a cloud-based DDoS protection service that can absorb and filter attack traffic before it reaches your infrastructure.",
                    "priority": "High",
                    "implementation_difficulty": "Moderate"
                },
                {
                    "title": "Traffic Baselining",
                    "description": "Establish normal traffic patterns to quickly identify and respond to anomalous traffic indicative of DDoS attacks.",
                    "priority": "Medium",
                    "implementation_difficulty": "Moderate"
                },
                {
                    "title": "Network Redundancy",
                    "description": "Implement redundant network paths and resources to maintain availability during partial DDoS attacks.",
                    "priority": "Medium",
                    "implementation_difficulty": "Complex"
                }
            ]
        else:
            # Generic recommendations for other incident types
            recommendations = [
                {
                    "title": "Security Awareness Training",
                    "description": "Conduct regular security awareness training for all employees to reduce human-factor security risks.",
                    "priority": "Medium",
                    "implementation_difficulty": "Easy"
                },
                {
                    "title": "Vulnerability Management",
                    "description": "Implement a comprehensive vulnerability management program including regular scanning and timely patching.",
                    "priority": "High",
                    "implementation_difficulty": "Moderate"
                },
                {
                    "title": "Enhanced Monitoring",
                    "description": "Improve security monitoring capabilities to detect suspicious activities earlier in the attack chain.",
                    "priority": "Medium",
                    "implementation_difficulty": "Moderate"
                }
            ]
        
        return recommendations


def create_incident_response_ui():
    """
    Create the user interface for the incident response module.
    
    This function should be called from a Streamlit page to render the UI.
    """
    st.title("Incident Response Automation")
    st.write("Manage security incidents and automate response workflows.")
    
    # Initialize the incident response module
    incident_response = IncidentResponseAutomation()
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["Active Incidents", "Create Incident", "Response Playbooks", "Incident History"])
    
    with tab1:
        st.subheader("Active Security Incidents")
        
        # Get active incidents
        active_incidents = incident_response.get_active_incidents()
        
        if not active_incidents:
            st.info("No active security incidents at this time.")
        else:
            # Display active incidents
            for i, incident in enumerate(active_incidents):
                # Create an expander for each incident
                with st.expander(f"{incident['name']} (ID: {incident['id']}) - {incident['severity']} Severity"):
                    # Display incident details
                    st.write(f"**Type:** {incident['name']}")
                    st.write(f"**Status:** {incident['status']}")
                    st.write(f"**Created:** {incident['creation_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                    st.write(f"**Details:** {incident['details']}")
                    
                    # Display affected assets if any
                    if incident['assets_affected']:
                        st.write("**Affected Assets:**")
                        for asset in incident['assets_affected']:
                            st.write(f"- {asset}")
                    
                    # Display playbook information
                    playbook_id = incident.get("playbook")
                    if playbook_id and playbook_id in st.session_state.response_playbooks:
                        playbook = st.session_state.response_playbooks[playbook_id]
                        st.write(f"**Response Playbook:** {playbook['name']}")
                        
                        # Display current step if a playbook is in progress
                        current_step_index = incident.get("current_step")
                        if current_step_index is not None:
                            steps = incident_response.get_playbook_steps(playbook_id)
                            if steps and current_step_index < len(steps):
                                current_step = steps[current_step_index]
                                st.write("**Current Step:**")
                                st.info(f"{current_step['name']}: {current_step['description']}")
                                
                                # Add button to complete current step
                                if st.button(f"Complete Current Step", key=f"complete_step_{incident['id']}"):
                                    result = incident_response.complete_current_step(incident['id'])
                                    if result['status'] == 'success':
                                        if result.get('playbook_completed'):
                                            st.success("All playbook steps completed!")
                                        else:
                                            st.success("Advanced to next step!")
                                        # Rerun to refresh the UI
                                        st.rerun()
                                    else:
                                        st.error(result['message'])
                        else:
                            # Button to start playbook if not already in progress
                            if st.button(f"Start Response Playbook", key=f"start_playbook_{incident['id']}"):
                                result = incident_response.start_playbook(incident['id'])
                                if result['status'] == 'success':
                                    st.success("Playbook started!")
                                    # Rerun to refresh the UI
                                    st.rerun()
                                else:
                                    st.error(result['message'])
                    
                    # Display notes
                    if incident.get("notes"):
                        st.write("**Incident Notes:**")
                        for note in incident["notes"]:
                            st.text(f"{note['time'].strftime('%Y-%m-%d %H:%M:%S')}: {note['content']}")
                    
                    # Add a note
                    new_note = st.text_area("Add a note", key=f"note_{incident['id']}")
                    if st.button("Add Note", key=f"add_note_{incident['id']}"):
                        if new_note:
                            result = incident_response.add_incident_note(incident['id'], new_note)
                            if result['status'] == 'success':
                                st.success("Note added!")
                                # Rerun to refresh the UI
                                st.rerun()
                            else:
                                st.error(result['message'])
                    
                    # Update incident status
                    status_options = ["Open", "Investigating", "Contained", "Resolved"]
                    new_status = st.selectbox("Update Status", options=status_options, 
                                             index=status_options.index(incident['status']),
                                             key=f"status_{incident['id']}")
                    
                    if new_status != incident['status']:
                        if st.button("Update Status", key=f"update_status_{incident['id']}"):
                            result = incident_response.update_incident(incident['id'], {"status": new_status})
                            if result['status'] == 'success':
                                st.success(f"Status updated to {new_status}!")
                                # Rerun to refresh the UI
                                st.rerun()
                            else:
                                st.error(result['message'])
                    
                    # Generate incident report
                    if st.button("Generate Incident Report", key=f"report_{incident['id']}"):
                        with st.spinner("Generating report..."):
                            report_result = incident_response.generate_incident_report(incident['id'])
                            if report_result['status'] == 'success':
                                report = report_result['report']
                                
                                # Display report in an expander
                                with st.expander("Incident Report"):
                                    st.write(f"## Incident Report: {report['incident_type']}")
                                    st.write(f"**Incident ID:** {report['incident_id']}")
                                    st.write(f"**Severity:** {report['severity']}")
                                    st.write(f"**Created:** {report['creation_time']}")
                                    st.write(f"**Current Status:** {report['current_status']}")
                                    
                                    if report['containment_time']:
                                        st.write(f"**Containment Time:** {report['containment_time']}")
                                        st.write(f"**Time to Containment:** {report['time_to_containment']}")
                                    
                                    if report['resolution_time']:
                                        st.write(f"**Resolution Time:** {report['resolution_time']}")
                                        st.write(f"**Time to Resolution:** {report['time_to_resolution']}")
                                    
                                    st.write(f"**Details:** {report['details']}")
                                    
                                    if report['assets_affected']:
                                        st.write("**Affected Assets:**")
                                        for asset in report['assets_affected']:
                                            st.write(f"- {asset}")
                                    
                                    if report['playbook_used']:
                                        st.write(f"**Response Playbook:** {report['playbook_used']}")
                                    
                                    if report['steps_taken']:
                                        st.write("**Steps Taken:**")
                                        for step in report['steps_taken']:
                                            st.write(f"- {step['name']} (Completed: {step['completion_time']})")
                                    
                                    if report['notes']:
                                        st.write("**Incident Notes:**")
                                        for note in report['notes']:
                                            st.write(f"- {note}")
                                    
                                    if report['recommendations']:
                                        st.write("## Recommendations")
                                        for rec in report['recommendations']:
                                            st.write(f"### {rec['title']} ({rec['priority']} Priority)")
                                            st.write(rec['description'])
                                            st.write(f"Implementation difficulty: {rec['implementation_difficulty']}")
                            else:
                                st.error(report_result['message'])
    
    with tab2:
        st.subheader("Create New Incident")
        
        # Get incident types
        incident_catalog = incident_response.get_incident_types()
        
        # Incident type selection
        incident_type_options = list(incident_catalog.keys())
        incident_type_names = [incident_catalog[t]["name"] for t in incident_type_options]
        
        selected_type_index = st.selectbox(
            "Incident Type",
            options=range(len(incident_type_options)),
            format_func=lambda x: incident_type_names[x]
        )
        
        selected_type = incident_type_options[selected_type_index]
        incident_info = incident_catalog[selected_type]
        
        # Severity selection
        severity = st.selectbox(
            "Severity",
            options=incident_info["severity_levels"],
            index=incident_info["severity_levels"].index(incident_info["default_severity"])
        )
        
        # Incident details
        details = st.text_area("Incident Details", 
                             placeholder="Provide details about the incident...")
        
        # Affected assets
        assets_input = st.text_area("Affected Assets (one per line)",
                                  placeholder="List affected systems, one per line...")
        
        assets_affected = [asset.strip() for asset in assets_input.split("\n") if asset.strip()]
        
        # Create button
        if st.button("Create Incident"):
            if not details:
                st.error("Please provide incident details.")
            else:
                result = incident_response.create_incident(
                    incident_type=selected_type,
                    severity=severity,
                    details=details,
                    assets_affected=assets_affected
                )
                
                if result["status"] == "success":
                    st.success(f"Incident created: ID {result['incident']['id']}")
                    # Switch to the active incidents tab
                    st.rerun()
                else:
                    st.error(result["message"])
    
    with tab3:
        st.subheader("Response Playbooks")
        
        # Get playbooks
        playbooks = incident_response.get_playbooks()
        
        # Playbook selection
        playbook_options = list(playbooks.keys())
        playbook_names = [playbooks[p]["name"] for p in playbook_options]
        
        selected_playbook_index = st.selectbox(
            "Select Playbook",
            options=range(len(playbook_options)),
            format_func=lambda x: playbook_names[x]
        )
        
        selected_playbook = playbook_options[selected_playbook_index]
        playbook = playbooks[selected_playbook]
        
        # Display playbook details
        st.write(f"**Description:** {playbook['description']}")
        
        # Display steps
        st.write("### Response Steps")
        for i, step in enumerate(playbook["steps"]):
            with st.expander(f"Step {i+1}: {step['name']}"):
                st.write(f"**Description:** {step['description']}")
                st.write(f"**Automation Level:** {step['automation_level']}")
                st.write(f"**Estimated Time:** {step['estimated_time']} minutes")
    
    with tab4:
        st.subheader("Incident History")
        
        # Get incident history
        incident_history = incident_response.get_incident_history()
        
        if not incident_history:
            st.info("No resolved incidents in history.")
        else:
            # Create a DataFrame for display
            history_data = []
            for incident in incident_history:
                history_data.append({
                    "ID": incident["id"],
                    "Type": incident["name"],
                    "Severity": incident["severity"],
                    "Created": incident["creation_time"].strftime("%Y-%m-%d %H:%M"),
                    "Resolved": incident.get("resolution_time", "N/A") if isinstance(incident.get("resolution_time"), str) 
                             else incident.get("resolution_time").strftime("%Y-%m-%d %H:%M") if incident.get("resolution_time") else "N/A",
                    "Details": incident["details"]
                })
            
            # Create DataFrame
            history_df = pd.DataFrame(history_data)
            
            # Display as table
            st.dataframe(history_df, use_container_width=True)
            
            # Allow selecting an incident to view details
            selected_incident_id = st.selectbox(
                "Select an incident to view details",
                options=[incident["id"] for incident in incident_history],
                format_func=lambda x: f"{x} - {next((inc['name'] for inc in incident_history if inc['id'] == x), '')}"
            )
            
            if selected_incident_id:
                # Find the selected incident
                selected_incident = next((inc for inc in incident_history if inc["id"] == selected_incident_id), None)
                
                if selected_incident:
                    # Display incident details
                    with st.expander(f"Details for Incident {selected_incident_id}", expanded=True):
                        st.write(f"**Type:** {selected_incident['name']}")
                        st.write(f"**Severity:** {selected_incident['severity']}")
                        st.write(f"**Created:** {selected_incident['creation_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        if selected_incident.get("containment_time"):
                            st.write(f"**Contained:** {selected_incident['containment_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        if selected_incident.get("resolution_time"):
                            st.write(f"**Resolved:** {selected_incident['resolution_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        st.write(f"**Details:** {selected_incident['details']}")
                        
                        # Display affected assets if any
                        if selected_incident['assets_affected']:
                            st.write("**Affected Assets:**")
                            for asset in selected_incident['assets_affected']:
                                st.write(f"- {asset}")
                        
                        # Display playbook information
                        playbook_id = selected_incident.get("playbook")
                        if playbook_id and playbook_id in playbooks:
                            st.write(f"**Response Playbook:** {playbooks[playbook_id]['name']}")
                        
                        # Display completed steps
                        if selected_incident.get("completed_steps"):
                            st.write("**Steps Completed:**")
                            for step in selected_incident["completed_steps"]:
                                st.write(f"- {step['step_name']} (Completed: {step['completion_time'].strftime('%Y-%m-%d %H:%M:%S')})")
                        
                        # Display notes
                        if selected_incident.get("notes"):
                            st.write("**Incident Notes:**")
                            for note in selected_incident["notes"]:
                                st.text(f"{note['time'].strftime('%Y-%m-%d %H:%M:%S')}: {note['content']}")
                        
                        # Generate incident report
                        if st.button(f"Generate Incident Report", key=f"history_report_{selected_incident_id}"):
                            with st.spinner("Generating report..."):
                                report_result = incident_response.generate_incident_report(selected_incident_id)
                                if report_result['status'] == 'success':
                                    # Display report in a new expander
                                    with st.expander("Incident Report"):
                                        report = report_result['report']
                                        st.write(f"## Incident Report: {report['incident_type']}")
                                        st.write(f"**Incident ID:** {report['incident_id']}")
                                        st.write(f"**Severity:** {report['severity']}")
                                        st.write(f"**Created:** {report['creation_time']}")
                                        
                                        if report['containment_time']:
                                            st.write(f"**Containment Time:** {report['containment_time']}")
                                            st.write(f"**Time to Containment:** {report['time_to_containment']}")
                                        
                                        if report['resolution_time']:
                                            st.write(f"**Resolution Time:** {report['resolution_time']}")
                                            st.write(f"**Time to Resolution:** {report['time_to_resolution']}")
                                        
                                        if report['recommendations']:
                                            st.write("## Recommendations")
                                            for rec in report['recommendations']:
                                                st.write(f"### {rec['title']} ({rec['priority']} Priority)")
                                                st.write(rec['description'])
                                                st.write(f"Implementation difficulty: {rec['implementation_difficulty']}")
                                else:
                                    st.error(report_result['message'])


# This allows the template to be run as a standalone page for testing
if __name__ == "__main__":
    create_incident_response_ui()