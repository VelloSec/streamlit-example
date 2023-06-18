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
    data_sources = sorted(list(set(source for sublist in df['x_mitre_data_sources'].dropna() for source in sublist)))

    groups = []
    if 'x_mitre_groups' in df:
        groups = sorted(list(set(group for sublist in df['x_mitre_groups'].dropna() for group in sublist)))

    return df, software, groups, data_sources

def apply_filters(df, software, groups, data_sources, search_term):
    if software:
        df = df[df['x_mitre_platforms'].apply(lambda x: bool(set(software) & set(x if x else [])))]
    if groups:
        df = df[df['x_mitre_groups'].apply(lambda x: bool(set(groups) & set(x if x else [])))]
    if data_sources:
        df = df[df['x_mitre_data_sources'].apply(lambda x: bool(set(data_sources) & set(x if x else [])))]
    if search_term:
        df = df[df['name'].str.contains(search_term, case=False)]
    return df

def main():
    st.title('Enterprise ATT&CK Matrix Explorer')

    data = load_data()
    df, software, groups, data_sources = process_data(data)

    st.sidebar.header('Filters')
    software_filter = st.sidebar.multiselect('Software', software)
    groups_filter = st.sidebar.multiselect('Groups', groups)
    data_source_filter = st.sidebar.multiselect('Data Source', data_sources)
    search_term = st.sidebar.text_input('Search Techniques')

    filtered_df = apply_filters(df, software_filter, groups_filter, data_source_filter, search_term)

    if not filtered_df.empty:
        st.dataframe(filtered_df[['name', 'description']])
    else:
        st.write('No results found.')

if __name__ == '__main__':
    main()
