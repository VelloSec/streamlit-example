import pandas as pd
import streamlit as st
import altair as alt
import requests
import matplotlib.pyplot as plt
from openai import OpenAIApi

# Load the data from the GitHub repository
@st.cache
def load_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    response = requests.get(url)
    data = response.json()
    return data

# Process the data and extract relevant information
def process_data(data):
    techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
    software = sorted(list(set(technique['x_mitre_products'][0] for technique in techniques if 'x_mitre_products' in technique)))
    tactics = sorted(list(set(tactic for technique in techniques for tactic in technique.get('kill_chain_phases', []) for tactic_obj in tactic.get('kill_chain_name', []))))
    groups = sorted(list(set(group for technique in techniques if 'x_mitre_groups' in technique for group in technique['x_mitre_groups'])))
    return techniques, software, tactics, groups

# Generate Altair chart
def generate_chart(df):
    chart = alt.Chart(df).mark_bar().encode(
        x='Count',
        y=alt.Y('Technique Name', sort='-x')
    )
    return chart

# Main function
def main():
    st.title('MITRE ATT&CK Techniques Browser')
    
    data = load_data()
    techniques, software, tactics, groups = process_data(data)
    
    selected_software = st.sidebar.selectbox('Software', software)
    selected_tactic = st.sidebar.selectbox('Tactic', tactics)
    selected_technique = st.sidebar.selectbox('Technique', [technique['name'] for technique in techniques])
    selected_group = st.sidebar.selectbox('APT Group', groups)
    
    filtered_techniques = techniques
    
    if selected_software:
        filtered_techniques = [technique for technique in filtered_techniques if 'x_mitre_products' in technique and selected_software in technique['x_mitre_products'][0]]
    
    if selected_tactic:
        filtered_techniques = [technique for technique in filtered_techniques if 'kill_chain_phases' in technique and any(tactic['kill_chain_name'] == selected_tactic for tactic_obj in technique['kill_chain_phases'] for tactic in tactic_obj.get('kill_chain_name', []))]
    
    if selected_technique:
        filtered_techniques = [technique for technique in filtered_techniques if technique['name'] == selected_technique]
    
    if selected_group:
        filtered_techniques = [technique for technique in filtered_techniques if 'x_mitre_groups' in technique and selected_group in technique['x_mitre_groups']]
    
    for technique in filtered_techniques:
        st.write('**Technique Name:**', technique['name'])
        st.write('**Technique ID:**', technique['external_references'][0]['external_id'])
        st.write('**Description:**', technique['description'])
        st.write('---')
    
    # Additional functionality using Altair and OpenAI
    if st.button('Generate Technique Chart'):
        df = pd.DataFrame({'Technique Name': [technique['name'] for technique in filtered_techniques],
                           'Count': [len(technique['external_references']) for technique in filtered_techniques]})
        chart = generate_chart(df)
        st.altair_chart(chart, use_container_width=True)
    
    if st.button('Generate Technique Description'):
        selected_technique = st.selectbox('Select a Technique', [technique['name'] for technique in filtered_techniques])
        technique_description = [technique['description'] for technique in filtered_techniques if technique['name'] == selected_technique]
        if technique_description:
            st.write('**Technique Description:**', technique_description[0])
        else:
            st.write('No technique description available for the selected technique.')
    
    if st.button('Get AI-Powered Insights'):
        openai_api_key = st.text_input('Enter OpenAI API Key', type='password')
        if openai_api_key:
            openai = OpenAIApi(api_key=openai_api_key)
            selected_technique = st.selectbox('Select a Technique', [technique['name'] for technique in filtered_techniques])
            response = openai.get_insights(selected_technique)
            if response:
                st.write('**AI-Powered Insights:**', response)
            else:
                st.write('No insights available for the selected technique.')
        else:
            st.write('Please enter your OpenAI API Key to use this feature.')

if __name__ == '__main__':
    main()
