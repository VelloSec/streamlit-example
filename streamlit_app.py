import streamlit as st
import pandas as pd
import requests
import json

@st.cache
def load_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    file = requests.get(url)
    data = json.loads(file.text)
    return data['objects']

def process_data(data):
    attack_patterns = [obj for obj in data if obj['type'] == 'attack-pattern']
    df = pd.json_normalize(attack_patterns)
    
    platforms = sorted(list(set(platform for sublist in df['x_mitre_platforms'].dropna() for platform in sublist)))
    tactics = sorted(list(set(tactic for sublist in df['kill_chain_phases'].dropna() for tactic in sublist)))
    data_sources = sorted(list(set(source for sublist in df['x_mitre_data_sources'].dropna() for source in sublist)))
    return df, platforms, tactics, data_sources

def apply_filters(df, platforms, tactics, data_sources, search_term):
    if platforms:
        df = df[df['x_mitre_platforms'].apply(lambda x: bool(set(platforms) & set(x if x else [])))]
    if tactics:
        df = df[df['kill_chain_phases'].apply(lambda x: bool(set(tactics) & set(x if x else [])))]
    if data_sources:
        df = df[df['x_mitre_data_sources'].apply(lambda x: bool(set(data_sources) & set(x if x else [])))]
    if search_term:
        df = df[df['name'].str.contains(search_term, case=False)]
    return df

def main():
    st.title('Enterprise ATT&CK Matrix Explorer')

    data = load_data()
    df, platforms, tactics, data_sources = process_data(data)
    
    st.sidebar.header('Filters')
    platform_filter = st.sidebar.multiselect('Platform', platforms)
    tactic_filter = st.sidebar.multiselect('Tactic', tactics)
    data_source_filter = st.sidebar.multiselect('Data source', data_sources)
    search_term = st.sidebar.text_input('Search techniques')

    filtered_df = apply_filters(df, platform_filter, tactic_filter, data_source_filter, search_term)

    if not filtered_df.empty:
        st.write(filtered_df)
    else:
        st.write("No data to display. Please adjust filters.")

if __name__ == "__main__":
    main()
