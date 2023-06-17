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
            
    techniques_df = pd.json_normalize(techniques)

    return techniques_df

@st.cache_data
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

    if st.checkbox('Show raw data'):
        st.write(data)

    # Visualization
    st.altair_chart(
        alt.Chart(data)
            .mark_circle(size=60)
            .encode(
                x='kill_chain_phases:O',
                y='x_mitre_platforms:O',
                color='kill_chain_phases:N',
                tooltip=['name', 'description', 'kill_chain_phases', 'x_mitre_platforms']
            ).interactive(),
        use_container_width=True
    )

if __name__ == "__main__":
    main()
