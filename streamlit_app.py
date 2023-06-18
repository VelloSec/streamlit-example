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
    if response.status_code == 200:
        return response.json()
    else:
        st.error("Failed to load data from the MITRE ATT&CK repository.")

# Function to process the loaded data
@st.cache_data(allow_output_mutation=True)
def process_data(data):
    techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
    software = sorted(list(set(software for technique in techniques for software in technique.get('x_mitre_products', []))))
    groups = sorted(list(set(group for technique in techniques for group in technique.get('x_mitre_groups', []))))
    return techniques, software, groups

# Function to filter and display the data
def filter_data(techniques, software, groups, selected_software, selected_group):
    filtered_techniques = [technique for technique in techniques if
                           (selected_software is None or selected_software in technique.get('x_mitre_products', []))) and
                           (selected_group is None or selected_group in technique.get('x_mitre_groups', []))]

    return filtered_techniques

# Main function
def main():
    st.title("MITRE ATT&CK Navigator")
    data = load_data()
    if data is None:
        return

    techniques, software, groups = process_data(data)

    # Enable dynamic filtering of dropdowns
    selected_software = st.sidebar.selectbox('Select Software', options=[None] + software)
    selected_group = st.sidebar.selectbox('Select APT Group', options=[None] + groups)

    filtered_techniques = filter_data(techniques, software, groups, selected_software, selected_group)

    st.markdown('### Techniques')
    for technique in filtered_techniques:
        st.write(f"- **{technique['name']}**")
        st.write(f"  - ID: {technique['external_references'][0]['external_id']}")
        st.write(f"  - Description: {technique['description']}")
        st.write('---')

    # Additional Features

    # 1. Display count of techniques per software using a bar chart
    software_counts = pd.DataFrame([(technique['x_mitre_products'], 1) for technique in filtered_techniques], columns=['Software', 'Count'])
    software_chart = alt.Chart(software_counts).mark_bar().encode(
        x='Software',
        y='Count'
    )
    st.markdown('### Technique Count per Software')
    st.altair_chart(software_chart, use_container_width=True)

    # 2. Show a count of techniques per APT group using a bar chart
    group_counts = pd.DataFrame([(technique['x_mitre_groups'], 1) for technique in filtered_techniques], columns=['Group', 'Count'])
    group_chart = alt.Chart(group_counts).mark_bar().encode(
        x='Group',
        y='Count'
    )
    st.markdown('### Technique Count per APT Group')
    st.altair_chart(group_chart, use_container_width=True)

    # 3. Show a word cloud of technique descriptions
    technique_descriptions = " ".join(technique['description'] for technique in filtered_techniques)
    st.markdown('### Technique Descriptions Word Cloud')
    st.write(technique_descriptions)

    # 4. Allow searching for specific techniques
    search_query = st.sidebar.text_input('Search Techniques')
    if search_query:
        filtered_techniques = [technique for technique in filtered_techniques if search_query.lower() in technique['name'].lower()]

    if len(filtered_techniques) == 0:
        st.warning("No techniques found for the selected filters.")

if __name__ == "__main__":
    main()
