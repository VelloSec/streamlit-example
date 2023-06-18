import pandas as pd
import streamlit as st

# Load the data from the GitHub repository
@st.cache
def load_data():
    data = pd.read_json('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
    return data

# Process the data and extract relevant information
def process_data(data):
    techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
    software = sorted(list(set(technique['x_mitre_products'][0] for technique in techniques if 'x_mitre_products' in technique)))
    tactics = sorted(list(set(tactic for technique in techniques for tactic_obj in technique.get('kill_chain_phases', []) for tactic in tactic_obj.get('kill_chain_name', [])))))
    groups = sorted(list(set(group for technique in techniques if 'x_mitre_groups' in technique for group in technique['x_mitre_groups'])))
    
    return techniques, software, tactics, groups

# Display technique details and additional features
def display_technique_details(technique):
    st.write('**Technique Name:**', technique['name'])
    st.write('**Technique ID:**', technique['external_references'][0]['external_id'])
    st.write('**Description:**', technique['description'])
    
    if 'x_mitre_platforms' in technique:
        st.write('**Platforms:**', ', '.join(technique['x_mitre_platforms']))
    
    if 'x_mitre_data_sources' in technique:
        st.write('**Data Sources:**', ', '.join(technique['x_mitre_data_sources']))
    
    if 'x_mitre_detection' in technique:
        st.write('**Detection Recommendations:**', technique['x_mitre_detection'])
    
    if 'x_mitre_contributors' in technique:
        st.write('**Contributors:**', ', '.join(technique['x_mitre_contributors']))
    
    if 'x_mitre_domains' in technique:
        st.write('**Domains:**', ', '.join(technique['x_mitre_domains']))
    
    if 'x_mitre_impact_type' in technique:
        st.write('**Impact Type:**', technique['x_mitre_impact_type'])
    
    if 'x_mitre_permissions_required' in technique:
        st.write('**Permissions Required:**', ', '.join(technique['x_mitre_permissions_required']))
    
    if 'x_mitre_system_requirements' in technique:
        st.write('**System Requirements:**', technique['x_mitre_system_requirements'])
    
    if 'x_mitre_remote_support' in technique:
        st.write('**Remote Support:**', technique['x_mitre_remote_support'])
    
    # Add implementation for additional features
    
    st.write('---')

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
        filtered_techniques = [technique for technique in filtered_techniques if 'kill_chain_phases' in technique and any(tactic['kill_chain_name'] == selected_tactic for tactic_obj in technique['kill_chain_phases'] for tactic in tactic_obj['kill_chain_name'])]
    
    if selected_technique:
        filtered_techniques = [technique for technique in filtered_techniques if technique['name'] == selected_technique]
    
    if selected_group:
        filtered_techniques = [technique for technique in filtered_techniques if 'x_mitre_groups' in technique and selected_group in technique['x_mitre_groups']]
    
    for technique in filtered_techniques:
        display_technique_details(technique)

if __name__ == '__main__':
    main()
