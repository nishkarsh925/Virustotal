import streamlit as st
import requests

# Your VirusTotal API Key
VT_API_KEY = '4e6d4ab35e0fb46ff31d249d8acaccfb8b5a67489773cee7db60ad23c10b8891'  # Replace with your actual API key

def submit_file(file):
    """Submit a file to VirusTotal for analysis and return the analysis ID."""
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': VT_API_KEY
    }
    files = {'file': file}
    response = requests.post(url, headers=headers, files=files)
    return response.json()

def get_analysis_report(analysis_id):
    """Fetch the analysis report from VirusTotal using the analysis ID."""
    headers = {
        'x-apikey': VT_API_KEY
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)
    return response.json()

# Streamlit UI
st.title("Cyber Sphere")

uploaded_file = st.file_uploader("Upload a file to check its safety", type=["jpg", "jpeg", "png", "pdf", "docx", "zip", "exe"])

if uploaded_file is not None:
    st.write("File Name:", uploaded_file.name)

    if st.button("Check Safety"):
        # Submit the file for analysis
        submission_response = submit_file(uploaded_file)

        if 'data' in submission_response and 'id' in submission_response['data']:
            analysis_id = submission_response['data']['id']
            st.write("File submitted for analysis. Analysis ID:", analysis_id)

            # Fetch the analysis report
            report = get_analysis_report(analysis_id)
            st.write("Analysis Report:")
            st.json(report)  # Display the report in JSON format
        else:
            st.error("Error submitting file. Please try again.")
