import json
import pandas as pd
import requests
import streamlit as st
import altair as alt

def load_data():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url)
    raw_data = response.json()
    
    techniques = []
    for obj in raw_data["objects"]:
        if obj['type'] == 'attack-pattern':
            techniques.append(obj)
            
    techniques_df = pd.json_normalize(techniques, 'kill_chain_phases', ['name', 'description', 'x_mitre_platforms', 'x_mitre_detection', 'x_mitre_mitigations'])

    return techniques_df

@st.cache_data(ttl=3600)
def fetch_and_cache_data():
    return load_data()

def main():
    st.title("MITRE ATT&CK Navigator")

    # Load data
    data = fetch_and_cache_data()

    # Filter options
    platforms = list(set([item for sublist in data['x_mitre_platforms'].dropna() for item in sublist]))
    platforms.sort()
    selected_platform = st.selectbox("Select a platform", ['All'] + platforms)

    if selected_platform != 'All':
        data = data[data['x_mitre_platforms'].apply(lambda x: selected_platform in x if x else False)]

    tactics = list(set([d['phase_name'] for d_list in data['kill_chain_phases'].dropna() for d in d_list]))
    tactics.sort()
    selected_tactic = st.selectbox("Select a Tactic", ['All'] + tactics)

    if selected_tactic != 'All':
        data = data[data['kill_chain_phases'].apply(lambda d_list: any(d['phase_name'] == selected_tactic for d in d_list))]

    techniques = list(set(data['name']))
    techniques.sort()
    selected_technique = st.selectbox("Select a Technique", ['All'] + techniques)

    if selected_technique != 'All':
        data = data[data['name'] == selected_technique]

    # Display filtered data
    if st.checkbox('Show raw data'):
        st.write(data)

    # Supplemental Information
    if st.checkbox('Show Supplemental Information'):
        technique_data = data[data['name'] == selected_technique]
        st.write("Description:", technique_data['description'].values[0])
        st.write("Detection:", technique_data['x_mitre_detection'].values[0])
        st.write("Mitigation:", technique_data['x_mitre_mitigations'].values[0])

    # Visualization
    st.altair_chart(
        alt.Chart(data)
            .mark_circle(size=60)
            .encode(
                x='phase_name:O',
                y='x_mitre_platforms:O',
                color='phase_name:N',
                tooltip=['name', 'description', 'phase_name', 'x_mitre_platforms']
            ).interactive(),
        use_container_width=True
    )

if __name__ == "__main__":
    main()
