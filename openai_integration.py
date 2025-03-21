"""
OpenAI integration for the Quantum Security AI Assistant.
"""
import json
import os
from openai import OpenAI

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user

def get_openai_client():
    """
    Initialize and return an OpenAI client.
    Raises an exception if the API key is not available.
    """
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        raise ValueError("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")
    
    return OpenAI(api_key=openai_api_key)

def generate_ai_response_with_openai(query, system_status=None):
    """
    Generate a response using OpenAI's API, incorporating system status information.
    
    Args:
        query: User's question as a string
        system_status: Dictionary containing system status information (optional)
        
    Returns:
        A string response from the AI
    """
    try:
        client = get_openai_client()
        
        # Prepare system message with context
        system_content = """
        You are a Quantum Security AI Assistant specialized in cybersecurity. 
        Your responses should be helpful, accurate, and security-focused.
        """
        
        # Add system status information if available
        messages = [{"role": "system", "content": system_content}]
        
        if system_status:
            status_info = f"""
            Current system information:
            - Threat Level: {system_status.get('threat_level', 'Unknown')}
            - Active Alerts: {len(system_status.get('alerts', []))}
            - Network Status: {system_status.get('network_status', 'Unknown')}
            - Last Analysis: {system_status.get('last_analysis', 'Unknown')}
            
            Incorporate this information into your response when relevant.
            """
            messages.append({"role": "system", "content": status_info})
        
        # Add user query
        messages.append({"role": "user", "content": query})
        
        # Generate response from OpenAI
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            max_tokens=500,
            temperature=0.7,
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        # Fallback to simulated response if OpenAI integration fails
        return f"OpenAI integration error: {str(e)}. Please check your API key configuration."

def analyze_security_data(security_data):
    """
    Analyze security data using OpenAI to generate insights and recommendations.
    
    Args:
        security_data: Dictionary containing security-related data
        
    Returns:
        Dictionary with analysis results and recommendations
    """
    try:
        client = get_openai_client()
        
        # Format the security data for analysis
        data_description = json.dumps(security_data, indent=2)
        
        prompt = f"""
        Analyze the following security data and provide:
        1. A brief assessment of the current security situation
        2. Three specific recommendations based on the data
        3. Any potential vulnerabilities or risks that should be addressed
        
        Security Data:
        {data_description}
        
        Respond with JSON in this format:
        {{
            "assessment": "Brief assessment text",
            "recommendations": ["Rec 1", "Rec 2", "Rec 3"],
            "risks": ["Risk 1", "Risk 2"]
        }}
        """
        
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=1000,
            temperature=0.5,
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
        
    except Exception as e:
        # Return error information if analysis fails
        return {
            "assessment": f"Analysis error: {str(e)}",
            "recommendations": ["Check OpenAI API key configuration"],
            "risks": ["Unable to analyze security data"]
        }