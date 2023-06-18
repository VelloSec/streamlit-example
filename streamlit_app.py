import json
import pandas as pd
import requests
import streamlit as st

def load_data():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url)
    raw_data = response.json()

    techniques = []
    for obj in raw_data["objects"]:
        if obj['type'] == 'attack-pattern':
            obj['tactic'] = [x['phase_name'] for x in obj.get('kill_chain_phases', []) if x['kill_chain_name'] == 'mitre-attack']
            techniques.append(obj)

    data = pd.json_normalize(techniques)

    # Explode the tactic list into multiple rows
    data = data.explode('tactic')
    data['tactic'].fillna("Unknown", inplace=True)

    return data

@st.cache(ttl=3600)
def fetch_and_cache_data():
    return load_data()

def main():
    st.title("MITRE ATT&CK Navigator")

    # Load data
    data = fetch_and_cache_data()

    # Filter options
    platforms = list(set([platform for sublist in data['x_mitre_platforms'].dropna() for platform in sublist]))
    platforms.sort()
    selected_platform = st.selectbox("Select a platform", ['All'] + platforms)

    if selected_platform != 'All':
        data = data[data['x_mitre_platforms'].apply(lambda x: selected_platform in x if isinstance(x, list) else False)]

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
        if selected_technique != 'All':
            technique_data = data[data['name'] == selected_technique]
            st.write("Description:", technique_data['description'].values[0])
            st.write("Detection:", technique_data['x_mitre_detection'].values[0])
            st.write("Mitigation:", technique_data['x_mitre_mitigations'].values[0])
        else:
            tactic_data = data[data['tactic'] == selected_tactic]
            if not tactic_data.empty:
                st.write("Tactic Description:", tactic_data['description'].values[0])
                st.write("Tactic Detection:", tactic_data['x_mitre_detection'].values[0])
                st.write("Tactic Mitigation:", tactic_data['x_mitre_mitigations'].values[0])

if __name__ == "__main__":
    main()
