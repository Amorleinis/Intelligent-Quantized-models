"""
Template for Custom Notification System

This template provides a foundation for implementing a customizable notification system
that can alert security teams about potential threats through various channels.
"""

import streamlit as st
import pandas as pd
import json
from datetime import datetime
import time
import threading
import os


class NotificationSystem:
    """
    Implements a customizable notification system for security alerts.
    
    This class provides the foundation for sending notifications through
    various channels like email, SMS, or integration with platforms like
    Slack or Microsoft Teams.
    """
    
    def __init__(self):
        """Initialize the notification system."""
        # Initialize notification settings from session state or set defaults
        if "notification_settings" not in st.session_state:
            st.session_state.notification_settings = {
                "email_notifications": False,
                "email_addresses": [],
                "sms_notifications": False,
                "phone_numbers": [],
                "slack_notifications": False,
                "slack_webhook": "",
                "teams_notifications": False,
                "teams_webhook": "",
                "notification_threshold": 70,  # Threat level threshold (0-100)
                "notification_cooldown": 15,   # Minutes between notifications
                "last_notification_time": None
            }
        
        # Initialize notification history if not already in session state
        if "notification_history" not in st.session_state:
            st.session_state.notification_history = []
        
        # Set up notification queue
        if "notification_queue" not in st.session_state:
            st.session_state.notification_queue = []
    
    def update_settings(self, settings):
        """
        Update notification settings.
        
        Args:
            settings: Dictionary containing notification settings
        """
        # Update settings in session state
        st.session_state.notification_settings.update(settings)
    
    def check_threshold(self, threat_level):
        """
        Check if a threat level exceeds the notification threshold.
        
        Args:
            threat_level: Numeric threat level (0-100)
            
        Returns:
            Boolean indicating if the threshold is exceeded
        """
        return threat_level >= st.session_state.notification_settings["notification_threshold"]
    
    def check_cooldown(self):
        """
        Check if the notification cooldown period has elapsed.
        
        Returns:
            Boolean indicating if notifications can be sent
        """
        if st.session_state.notification_settings["last_notification_time"] is None:
            return True
        
        last_time = st.session_state.notification_settings["last_notification_time"]
        cooldown = st.session_state.notification_settings["notification_cooldown"]
        
        # Calculate minutes since last notification
        time_diff = (datetime.now() - last_time).total_seconds() / 60
        
        return time_diff >= cooldown
    
    def queue_notification(self, notification_data):
        """
        Add a notification to the queue for processing.
        
        Args:
            notification_data: Dictionary containing notification details
        """
        # Add timestamp if not provided
        if "timestamp" not in notification_data:
            notification_data["timestamp"] = datetime.now()
        
        # Add to queue
        st.session_state.notification_queue.append(notification_data)
    
    def process_notification_queue(self):
        """Process pending notifications in the queue."""
        if not st.session_state.notification_queue:
            return
        
        # Check if we can send notifications now
        if not self.check_cooldown():
            return
        
        # Process all notifications in the queue
        while st.session_state.notification_queue:
            notification = st.session_state.notification_queue.pop(0)
            
            # Send the notification through configured channels
            sent_channels = []
            
            # Email notifications
            if st.session_state.notification_settings["email_notifications"]:
                success = self._send_email_notification(notification)
                if success:
                    sent_channels.append("Email")
            
            # SMS notifications
            if st.session_state.notification_settings["sms_notifications"]:
                success = self._send_sms_notification(notification)
                if success:
                    sent_channels.append("SMS")
            
            # Slack notifications
            if st.session_state.notification_settings["slack_notifications"]:
                success = self._send_slack_notification(notification)
                if success:
                    sent_channels.append("Slack")
            
            # Microsoft Teams notifications
            if st.session_state.notification_settings["teams_notifications"]:
                success = self._send_teams_notification(notification)
                if success:
                    sent_channels.append("Teams")
            
            # Record notification in history
            notification["sent_channels"] = sent_channels
            notification["sent_time"] = datetime.now()
            st.session_state.notification_history.append(notification)
            
            # Update last notification time
            st.session_state.notification_settings["last_notification_time"] = datetime.now()
    
    def notify_security_threat(self, threat_data):
        """
        Create and process a notification for a security threat.
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            Boolean indicating if notification was queued
        """
        # Check if threat level meets threshold
        if not self.check_threshold(threat_data.get("threat_level", 0)):
            return False
        
        # Create notification data
        notification = {
            "title": "Security Threat Detected",
            "message": threat_data.get("summary", "Unknown security threat detected."),
            "threat_level": threat_data.get("threat_level", 0),
            "details": threat_data,
            "timestamp": datetime.now()
        }
        
        # Queue the notification
        self.queue_notification(notification)
        
        # Process the queue
        self.process_notification_queue()
        
        return True
    
    def _send_email_notification(self, notification):
        """
        Send an email notification.
        
        Args:
            notification: Dictionary containing notification details
            
        Returns:
            Boolean indicating success
        """
        # TODO: Implement actual email sending logic
        # This would typically use a library like smtplib or an email service API
        
        # For demonstration, we'll just simulate sending
        recipients = st.session_state.notification_settings["email_addresses"]
        if not recipients:
            return False
            
        # Log the simulated email for demonstration
        st.session_state.notification_log = st.session_state.get("notification_log", [])
        st.session_state.notification_log.append({
            "channel": "Email",
            "recipients": recipients,
            "subject": notification["title"],
            "body": notification["message"],
            "time": datetime.now().isoformat(),
            "simulated": True
        })
        
        return True
    
    def _send_sms_notification(self, notification):
        """
        Send an SMS notification.
        
        Args:
            notification: Dictionary containing notification details
            
        Returns:
            Boolean indicating success
        """
        # TODO: Implement actual SMS sending logic
        # This would typically use a service like Twilio
        
        # For demonstration, we'll just simulate sending
        recipients = st.session_state.notification_settings["phone_numbers"]
        if not recipients:
            return False
            
        # Log the simulated SMS for demonstration
        st.session_state.notification_log = st.session_state.get("notification_log", [])
        st.session_state.notification_log.append({
            "channel": "SMS",
            "recipients": recipients,
            "body": f"{notification['title']}: {notification['message']}",
            "time": datetime.now().isoformat(),
            "simulated": True
        })
        
        return True
    
    def _send_slack_notification(self, notification):
        """
        Send a Slack notification.
        
        Args:
            notification: Dictionary containing notification details
            
        Returns:
            Boolean indicating success
        """
        # TODO: Implement actual Slack integration
        # This would typically use Slack's webhook API
        
        webhook_url = st.session_state.notification_settings["slack_webhook"]
        if not webhook_url:
            return False
            
        # Log the simulated Slack notification for demonstration
        st.session_state.notification_log = st.session_state.get("notification_log", [])
        st.session_state.notification_log.append({
            "channel": "Slack",
            "webhook": webhook_url,
            "title": notification["title"],
            "message": notification["message"],
            "time": datetime.now().isoformat(),
            "simulated": True
        })
        
        return True
    
    def _send_teams_notification(self, notification):
        """
        Send a Microsoft Teams notification.
        
        Args:
            notification: Dictionary containing notification details
            
        Returns:
            Boolean indicating success
        """
        # TODO: Implement actual Teams integration
        # This would typically use Microsoft Teams' webhook API
        
        webhook_url = st.session_state.notification_settings["teams_webhook"]
        if not webhook_url:
            return False
            
        # Log the simulated Teams notification for demonstration
        st.session_state.notification_log = st.session_state.get("notification_log", [])
        st.session_state.notification_log.append({
            "channel": "Microsoft Teams",
            "webhook": webhook_url,
            "title": notification["title"],
            "message": notification["message"],
            "time": datetime.now().isoformat(),
            "simulated": True
        })
        
        return True


def create_notification_ui():
    """
    Create the user interface for the notification system.
    
    This function should be called from a Streamlit page to render the UI.
    """
    st.title("Security Notification System")
    st.write("Configure how and when security notifications are sent to your team.")
    
    # Initialize the notification system
    notification_system = NotificationSystem()
    
    # Create tabs for different sections
    tab1, tab2, tab3 = st.tabs(["Notification Settings", "Test Notifications", "Notification History"])
    
    with tab1:
        st.subheader("Notification Settings")
        
        # Load current settings
        settings = st.session_state.notification_settings
        
        # Notification channels
        st.write("### Notification Channels")
        
        # Email notifications
        email_enabled = st.checkbox("Enable Email Notifications", 
                                  value=settings["email_notifications"])
        
        if email_enabled:
            email_list = st.text_area("Email Addresses (one per line)", 
                                    value="\n".join(settings["email_addresses"]))
            email_addresses = [email.strip() for email in email_list.split("\n") if email.strip()]
        else:
            email_addresses = []
        
        # SMS notifications
        sms_enabled = st.checkbox("Enable SMS Notifications", 
                                value=settings["sms_notifications"])
        
        if sms_enabled:
            phone_list = st.text_area("Phone Numbers (one per line)", 
                                    value="\n".join(settings["phone_numbers"]))
            phone_numbers = [phone.strip() for phone in phone_list.split("\n") if phone.strip()]
        else:
            phone_numbers = []
        
        # Slack notifications
        slack_enabled = st.checkbox("Enable Slack Notifications", 
                                  value=settings["slack_notifications"])
        
        if slack_enabled:
            slack_webhook = st.text_input("Slack Webhook URL", 
                                        value=settings["slack_webhook"])
        else:
            slack_webhook = ""
        
        # Teams notifications
        teams_enabled = st.checkbox("Enable Microsoft Teams Notifications", 
                                  value=settings["teams_notifications"])
        
        if teams_enabled:
            teams_webhook = st.text_input("Microsoft Teams Webhook URL", 
                                        value=settings["teams_webhook"])
        else:
            teams_webhook = ""
        
        # Notification rules
        st.write("### Notification Rules")
        
        # Threat level threshold
        threshold = st.slider("Notification Threshold (Threat Level)", 
                            min_value=0, max_value=100, 
                            value=settings["notification_threshold"])
        
        # Cooldown period
        cooldown = st.number_input("Cooldown Period (minutes between notifications)", 
                                 min_value=1, max_value=1440, 
                                 value=settings["notification_cooldown"])
        
        # Save button
        if st.button("Save Notification Settings"):
            # Update settings
            updated_settings = {
                "email_notifications": email_enabled,
                "email_addresses": email_addresses,
                "sms_notifications": sms_enabled,
                "phone_numbers": phone_numbers,
                "slack_notifications": slack_enabled,
                "slack_webhook": slack_webhook,
                "teams_notifications": teams_enabled,
                "teams_webhook": teams_webhook,
                "notification_threshold": threshold,
                "notification_cooldown": cooldown
            }
            
            notification_system.update_settings(updated_settings)
            st.success("Notification settings saved successfully!")
    
    with tab2:
        st.subheader("Test Notifications")
        st.write("Send a test notification to verify your notification settings.")
        
        # Test notification form
        test_title = st.text_input("Test Notification Title", 
                                 value="Test Security Alert")
        
        test_message = st.text_area("Test Notification Message", 
                                  value="This is a test security alert from the Quantum Security Dashboard.")
        
        test_level = st.slider("Test Threat Level", 
                             min_value=0, max_value=100, value=75)
        
        # Send test button
        if st.button("Send Test Notification"):
            # Create test notification
            test_notification = {
                "title": test_title,
                "message": test_message,
                "threat_level": test_level,
                "details": {
                    "test": True,
                    "summary": test_message,
                    "threat_level": test_level
                }
            }
            
            # Queue the notification
            notification_system.queue_notification(test_notification)
            
            # Process the queue
            notification_system.process_notification_queue()
            
            st.success("Test notification sent!")
            
            # Show simulation note
            st.info("Note: In this template, notifications are simulated and not actually sent.")
    
    with tab3:
        st.subheader("Notification History")
        
        # Display notification history
        if not st.session_state.notification_history:
            st.info("No notifications have been sent yet.")
        else:
            # Convert history to DataFrame for display
            history_data = []
            for notification in st.session_state.notification_history:
                history_data.append({
                    "Time": notification.get("sent_time", notification.get("timestamp")),
                    "Title": notification.get("title", "Untitled"),
                    "Message": notification.get("message", "No message"),
                    "Threat Level": notification.get("threat_level", 0),
                    "Channels": ", ".join(notification.get("sent_channels", []))
                })
            
            # Create DataFrame
            history_df = pd.DataFrame(history_data)
            
            # Display as table
            st.dataframe(history_df)
            
            # Add button to clear history
            if st.button("Clear Notification History"):
                st.session_state.notification_history = []
                st.experimental_rerun()
        
        # Display notification log if it exists
        if "notification_log" in st.session_state and st.session_state.notification_log:
            st.subheader("Notification Delivery Log")
            
            # Convert log to DataFrame
            log_data = []
            for log_entry in st.session_state.notification_log:
                log_data.append({
                    "Time": log_entry.get("time"),
                    "Channel": log_entry.get("channel", "Unknown"),
                    "Recipients": str(log_entry.get("recipients", "")),
                    "Subject/Title": log_entry.get("subject", log_entry.get("title", "")),
                    "Simulated": log_entry.get("simulated", True)
                })
            
            # Create DataFrame
            log_df = pd.DataFrame(log_data)
            
            # Display as table
            st.dataframe(log_df)


# This allows the template to be run as a standalone page for testing
if __name__ == "__main__":
    create_notification_ui()