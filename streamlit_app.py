import streamlit as st
import pandas as pd
import requests
import json

@st.cache_data
def load_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    file = requests.get(url)
    data = json.loads(file.text)
    return data['objects']

def process_data(data):
    attack_patterns = [obj for obj in data if obj['type'] == 'attack-pattern']
    df = pd.json_normalize(attack_patterns)

    software = sorted(list(set(software for sublist in df['x_mitre_platforms'].dropna() for software in sublist)))
    tactics = sorted(list(set(tactic for sublist in df['kill_chain_phases'].dropna() for phase in sublist for tactic in phase['kill_chain_name'])))

    return df, software, tactics

def apply_filters(df, software, tactics, search_term):
    if software:
        df = df[df['x_mitre_platforms'].apply(lambda x: bool(set(software) & set(x if x else [])))]
    if tactics:
        df = df[df['kill_chain_phases'].apply(lambda x: bool(set(tactics) & set(phase['kill_chain_name'] for phase in x if phase.get('kill_chain_name'))))]
    if search_term:
        df = df[df['name'].str.contains(search_term, case=False) | df['description'].str.contains(search_term, case=False)]
    return df

def main():
    st.title('Enterprise ATT&CK Matrix Explorer')

    data = load_data()
    df, software, tactics = process_data(data)

    st.sidebar.header('Filters')
    software_filter = st.sidebar.multiselect('Software', software)
    tactics_filter = st.sidebar.multiselect('Tactics', tactics)
    search_term = st.sidebar.text_input('Search TTPs')

    filtered_df = apply_filters(df, software_filter, tactics_filter, search_term)

    if not filtered_df.empty:
        st.dataframe(filtered_df[['name', 'description']])
    else:
        st.write('No results found.')

if __name__ == '__main__':
    main()
