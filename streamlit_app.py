import streamlit as st
import pandas as pd
import requests

@st.cache_data
def load_data():
    url = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-workbench-frontend/master/public/cti/stix/enterprise-attack.json'
    file = requests.get(url)
    data = file.json()
    return data

@st.cache_data
def filter_data(data, object_type):
    filtered = [obj for obj in data['objects'] if obj['type'] == object_type]
    return pd.json_normalize(filtered)

def main():
    data = load_data()
    tactics = filter_data(data, 'x-mitre-tactic')
    techniques = filter_data(data, 'attack-pattern')
    software = filter_data(data, 'malware') 
    groups = filter_data(data, 'intrusion-set') 

    search_term = st.text_input('Search')

    if search_term:
        techniques = techniques[techniques['name'].str.contains(search_term, case=False)]
        tactics = tactics[tactics['name'].str.contains(search_term, case=False)]
        software = software[software['name'].str.contains(search_term, case=False)]
        groups = groups[groups['name'].str.contains(search_term, case=False)]

    platform_choice = st.selectbox('Choose a Platform', ['All'] + list(techniques['x_mitre_platforms'].explode().unique()))
    software_choice = st.selectbox('Choose a Software', ['All'] + list(software['name']))
    group_choice = st.selectbox('Choose a Group', ['All'] + list(groups['name']))

    if platform_choice != 'All':
        techniques = techniques[techniques['x_mitre_platforms'].apply(lambda x: platform_choice in x)]
        tactics = tactics[tactics['x_mitre_platforms'].apply(lambda x: platform_choice in x if x else False)]

    if software_choice != 'All':
        techniques = techniques[techniques['software_labels'].apply(lambda x: software_choice in x if x else False)]

    if group_choice != 'All':
        techniques = techniques[techniques['group_labels'].apply(lambda x: group_choice in x if x else False)]

    tactic_choice = st.selectbox('Choose a Tactic', tactics['name'])
    tactic_data = tactics[tactics['name'] == tactic_choice]
    technique_choice = st.selectbox('Choose a Technique', techniques['name'])
    technique_data = techniques[techniques['name'] == technique_choice]
    
    st.write("Tactic Description:", tactic_data['description'].values[0])
    
    if 'x_mitre_mitigations' in tactic_data.columns:
        st.write("Tactic Mitigation:", tactic_data['x_mitre_mitigations'].values[0])
    
    if st.checkbox('Show Supplemental Information'):
        st.write("Technique Description:", technique_data['description'].values[0])
        
        if 'x_mitre_mitigations' in technique_data.columns:
            st.write("Mitigation:", technique_data['x_mitre_mitigations'].values[0])

if __name__ == "__main__":
    main()
