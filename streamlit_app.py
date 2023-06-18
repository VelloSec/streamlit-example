import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt
import altair as alt

# Function to load data from the GitHub repository
@st.cache_data(allow_output_mutation=True)
def load_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    response = requests.get(url)
    data = response.json()
    return data

# Function to process the loaded data
@st.cache_data(allow_output_mutation=True)
def process_data(data):
    techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
    software = sorted(list(set(software for technique in techniques for software in technique.get('x_mitre_products', []))))
    tactics = sorted(list(set(tactic for technique in techniques for tactic in technique.get('kill_chain_phases', [])))))
    groups = sorted(list(set(group for technique in techniques for group in technique.get('x_mitre_groups', []))))
    return techniques, software, tactics, groups

# Function to filter and display the data
def filter_data(techniques, software, tactics, groups, selected_software, selected_tactic, selected_group):
    filtered_techniques = [technique for technique in techniques if
                           (selected_software is None or selected_software in technique.get('x_mitre_products', [])) and
                           (selected_tactic is None or selected_tactic in technique.get('kill_chain_phases', []))) and
                           (selected_group is None or selected_group in technique.get('x_mitre_groups', []))]

    return filtered_techniques

# Main function
def main():
    st.title("MITRE ATT&CK Navigator")
    data = load_data()
    techniques, software, tactics, groups = process_data(data)

    # Enable dynamic filtering of dropdowns
    selected_software = st.sidebar.selectbox('Select Software', options=[None] + software)
    selected_tactic = st.sidebar.selectbox('Select Tactic', options=[None] + tactics)
    selected_group = st.sidebar.selectbox('Select APT Group', options=[None] + groups)

    filtered_techniques = filter_data(techniques, software, tactics, groups, selected_software, selected_tactic, selected_group)

    st.markdown('### Techniques')
    for technique in filtered_techniques:
        st.write(f"- **{technique['name']}**")
        st.write(f"  - ID: {technique['external_references'][0]['external_id']}")
        st.write(f"  - Description: {technique['description']}")
        st.write('---')

    # Additional Features

    # 1. Display count of techniques per tactic using a bar chart
    tactic_counts = pd.DataFrame([(technique['kill_chain_phases'], 1) for technique in filtered_techniques], columns=['Tactic', 'Count'])
    tactic_chart = alt.Chart(tactic_counts).mark_bar().encode(
        x='Tactic',
        y='Count'
    )
    st.markdown('### Technique Count per Tactic')
    st.altair_chart(tactic_chart, use_container_width=True)

    # 2. Show a table of techniques with their associated software
    technique_table = pd.DataFrame([(technique['name'], technique['x_mitre_products']) for technique in filtered_techniques], columns=['Technique', 'Software'])
    st.markdown('### Techniques and Associated Software')
    st.dataframe(technique_table)

    # 3. Show a count of techniques per APT group using a bar chart
    group_counts = pd.DataFrame([(technique['x_mitre_groups'], 1) for technique in filtered_techniques], columns=['Group', 'Count'])
    group_chart = alt.Chart(group_counts).mark_bar().encode(
        x='Group',
        y='Count'
    )
    st.markdown('### Technique Count per APT Group')
    st.altair_chart(group_chart, use_container_width=True)

    # 4. Show a bar chart of software usage
    software_counts = pd.DataFrame([(software, len([technique for technique in filtered_techniques if software in technique.get('x_mitre_products', [])])) for software in software], columns=['Software', 'Count'])
    software_chart = alt.Chart(software_counts).mark_bar().encode(
        x='Software',
        y='Count'
    )
    st.markdown('### Software Usage')
    st.altair_chart(software_chart, use_container_width=True)

    # 5. Allow searching for specific techniques
    search_query = st.sidebar.text_input('Search Techniques')
    if search_query:
        filtered_techniques = [technique for technique in filtered_techniques if search_query.lower() in technique['name'].lower()]

    if len(filtered_techniques) == 0:
        st.warning("No techniques found for the selected filters.")

if __name__ == "__main__":
    main()
