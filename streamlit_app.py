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
            obj['tactic'] = [x['phase_name'] for x in obj.get('kill_chain_phases', []) if x['kill_chain_name'] == 'mitre-attack']
            techniques.append(obj)

    data = pd.json_normalize(techniques, 'x_mitre_platforms', ['name', 'description', 'tactic', 'x_mitre_detection', 'x_mitre_mitigations'], record_prefix='platform_')
    
    # Explode the tactic list into multiple rows
    data = data.explode('tactic')

    return data

@st.cache_data(ttl=3600)
def fetch_and_cache_data():
    return load_data()

def main():
    st.title("MITRE ATT&CK Navigator")

    # Load data
    data = fetch_and_cache_data()

    # Filter options
    platforms = list(set(data['platform_']))
    platforms.sort()
    selected_platform = st.selectbox("Select a platform", ['All'] + platforms)

    if selected_platform != 'All':
        data = data[data['platform_'] == selected_platform]

    tactics = list(set(data['tactic']))
    tactics.sort()
    selected_tactic = st.selectbox("Select a Tactic", ['All'] + tactics)

    if selected_tactic != 'All':
        data = data[data['tactic'] == selected_tactic]

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
                x='tactic:O',
                y='platform_:O',
                color='tactic:N',
                tooltip=['name', 'description', 'tactic', 'platform_']
            ).interactive(),
        use_container_width=True
    )

if __name__ == "__main__":
    main()
