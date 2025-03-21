import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import time
from datetime import datetime, timedelta

from utils.data_generator import generate_network_data
from utils.quantum_simulation import generate_quantum_security_recommendations, quantum_analysis_simulation

def app():
    """Recovery recommendations and planning page."""
    st.title("🔄 Recovery & Mitigation")
    st.markdown("AI-powered recommendations for incident recovery and future mitigation")
    
    # Initialize session state variables
    if 'recovery_network_data' not in st.session_state:
        st.session_state.recovery_network_data = generate_network_data()
    
    if 'recovery_threat_assessment' not in st.session_state:
        st.session_state.recovery_threat_assessment = quantum_analysis_simulation(
            st.session_state.recovery_network_data
        )
    
    if 'recommendations' not in st.session_state:
        st.session_state.recommendations = generate_quantum_security_recommendations(
            st.session_state.recovery_network_data,
            st.session_state.recovery_threat_assessment
        )
    
    if 'recovery_plan' not in st.session_state:
        st.session_state.recovery_plan = []
    
    # Threat assessment section
    st.subheader("Current Threat Assessment")
    
    # Display threat level
    threat_level = st.session_state.recovery_threat_assessment.get('threat_level', 'Unknown')
    
    level_colors = {
        'Low': 'green',
        'Medium': 'orange',
        'High': 'red',
        'Critical': 'darkred'
    }
    
    st.markdown(
        f"**Status:** <span style='color:{level_colors.get(threat_level, 'gray')}'>{threat_level} Threat Level</span>",
        unsafe_allow_html=True
    )
    
    # Display any alerts
    alerts = st.session_state.recovery_threat_assessment.get('alerts', [])
    if alerts:
        st.warning("Active Alerts:")
        for alert in alerts:
            st.markdown(f"- {alert}")
    else:
        st.success("No active alerts detected.")
    
    # Recommendations section
    st.subheader("Security Recommendations")
    
    # Filter and sort options
    filter_col1, filter_col2 = st.columns(2)
    
    with filter_col1:
        priority_filter = st.multiselect(
            "Filter by Priority",
            options=["High", "Medium", "Low"],
            default=["High", "Medium"]
        )
    
    with filter_col2:
        category_filter = st.multiselect(
            "Filter by Category",
            options=sorted(set(rec["category"] for rec in st.session_state.recommendations)),
            default=[]
        )
    
    # Apply filters
    filtered_recommendations = st.session_state.recommendations.copy()
    
    if priority_filter:
        filtered_recommendations = [rec for rec in filtered_recommendations if rec["priority"] in priority_filter]
    
    if category_filter:
        filtered_recommendations = [rec for rec in filtered_recommendations if rec["category"] in category_filter]
    
    # Display recommendations as cards
    if not filtered_recommendations:
        st.info("No recommendations match your filter criteria.")
    else:
        for i, rec in enumerate(filtered_recommendations):
            with st.container():
                col1, col2 = st.columns([5, 1])
                
                with col1:
                    # Determine priority color
                    priority_color = {
                        "High": "red",
                        "Medium": "orange",
                        "Low": "green"
                    }.get(rec["priority"], "gray")
                    
                    st.markdown(f"#### {rec['title']}")
                    st.markdown(f"<span style='color:{priority_color}'><strong>{rec['priority']} Priority</strong></span> • {rec['category']} • {rec['implementation_time']}", unsafe_allow_html=True)
                    st.markdown(rec["description"])
                
                with col2:
                    # Add to recovery plan button
                    if rec["title"] not in [item["title"] for item in st.session_state.recovery_plan]:
                        if st.button("Add to Plan", key=f"add_rec_{i}"):
                            st.session_state.recovery_plan.append({
                                "title": rec["title"],
                                "priority": rec["priority"],
                                "category": rec["category"],
                                "implementation": rec["implementation_time"],
                                "status": "Planned",
                                "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            })
                            st.success(f"Added '{rec['title']}' to recovery plan")
                            time.sleep(0.5)
                            st.rerun()
                    else:
                        st.markdown("✅ In Plan")
            
            st.divider()
    
    # Recovery Plan section
    st.subheader("Your Recovery Plan")
    
    if not st.session_state.recovery_plan:
        st.info("Your recovery plan is empty. Add recommendations from above to create your plan.")
    else:
        # Plan statistics
        plan_df = pd.DataFrame(st.session_state.recovery_plan)
        
        # Show metrics
        metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
        
        with metrics_col1:
            st.metric("Total Actions", len(plan_df))
        
        with metrics_col2:
            if not plan_df.empty:
                high_priority = sum(1 for p in plan_df["priority"] if p == "High")
                st.metric("High Priority", high_priority)
            else:
                st.metric("High Priority", 0)
        
        with metrics_col3:
            if not plan_df.empty:
                completed = sum(1 for s in plan_df["status"] if s == "Completed")
                st.metric(
                    "Completed", 
                    f"{completed}/{len(plan_df)}", 
                    f"{int(completed/len(plan_df)*100)}%" if len(plan_df) > 0 else "0%"
                )
            else:
                st.metric("Completed", "0/0", "0%")
        
        # Recovery plan table
        st.markdown("### Action Items")
        
        # Add Edit and Status buttons to each row
        for i, item in enumerate(st.session_state.recovery_plan):
            with st.container():
                col1, col2, col3 = st.columns([4, 1, 1])
                
                with col1:
                    priority_color = {
                        "High": "red",
                        "Medium": "orange",
                        "Low": "green"
                    }.get(item["priority"], "gray")
                    
                    st.markdown(f"#### {item['title']}")
                    st.markdown(f"<span style='color:{priority_color}'><strong>{item['priority']}</strong></span> • {item['category']} • Status: {item['status']}", unsafe_allow_html=True)
                
                with col2:
                    if item["status"] != "Completed":
                        if st.button("Mark Complete", key=f"complete_{i}"):
                            st.session_state.recovery_plan[i]["status"] = "Completed"
                            st.success(f"Marked '{item['title']}' as completed")
                            time.sleep(0.5)
                            st.rerun()
                    else:
                        if st.button("Reopen", key=f"reopen_{i}"):
                            st.session_state.recovery_plan[i]["status"] = "In Progress"
                            st.info(f"Reopened '{item['title']}'")
                            time.sleep(0.5)
                            st.rerun()
                
                with col3:
                    if st.button("Remove", key=f"remove_{i}"):
                        removed_item = st.session_state.recovery_plan.pop(i)
                        st.warning(f"Removed '{removed_item['title']}' from plan")
                        time.sleep(0.5)
                        st.rerun()
            
            st.divider()
        
        # Option to clear plan
        if st.button("Clear Recovery Plan"):
            st.session_state.recovery_plan = []
            st.warning("Recovery plan has been cleared")
            time.sleep(0.5)
            st.rerun()
        
        # Export plan option
        if st.button("Export Recovery Plan"):
            plan_export = "\n".join([
                f"--- {item['title']} ---\n"
                f"Priority: {item['priority']}\n"
                f"Category: {item['category']}\n"
                f"Implementation: {item['implementation']}\n"
                f"Status: {item['status']}\n"
                for item in st.session_state.recovery_plan
            ])
            
            st.download_button(
                label="Download Plan",
                data=plan_export,
                file_name="security_recovery_plan.txt",
                mime="text/plain"
            )
    
    # Refresh recommendations button
    if st.button("Refresh Recommendations"):
        with st.spinner("Analyzing network and generating new recommendations..."):
            # Simulate processing time
            progress_bar = st.progress(0)
            for i in range(101):
                time.sleep(0.02)
                progress_bar.progress(i)
            
            # Generate new data and recommendations
            st.session_state.recovery_network_data = generate_network_data()
            st.session_state.recovery_threat_assessment = quantum_analysis_simulation(
                st.session_state.recovery_network_data
            )
            st.session_state.recommendations = generate_quantum_security_recommendations(
                st.session_state.recovery_network_data,
                st.session_state.recovery_threat_assessment
            )
            
            st.success("Generated new security recommendations")
            time.sleep(0.5)
            st.rerun()
    
    # Educational component
    with st.expander("About Security Recovery Strategy", expanded=False):
        st.markdown("""
        ### Effective Security Recovery Planning
        
        A robust security recovery strategy is critical for minimizing the impact of security incidents and returning to normal operations. Key components include:
        
        #### 1. Incident Response
        - Containment strategies to limit damage
        - Eradication of threats from systems
        - Evidence collection for forensic analysis
        
        #### 2. Recovery Actions
        - Restoration of systems from secure backups
        - Verification of system integrity
        - Staged recovery approach for critical systems first
        
        #### 3. Post-Incident Activities
        - Root cause analysis
        - Documentation of lessons learned
        - Implementation of preventive measures
        
        #### 4. Quantum-Resistant Planning (Future)
        - Preparation for quantum computing threats
        - Migration to post-quantum cryptography
        - Quantum key distribution implementation
        
        Regular testing and updating of recovery plans is essential to maintain their effectiveness as threats evolve.
        """)
    
    # Disclaimer about simulation
    st.caption("Note: This is a simulated security dashboard for educational purposes. The recommendations are generated using conventional algorithms labeled as 'quantum' for demonstration.")

if __name__ == "__main__":
    app()
