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
    tactics = sorted(list(set(phase['phase_name'] for sublist in df['kill_chain_phases'].dropna() for phase in sublist)))

    return df, software, tactics

def apply_filters(df, software, tactics, technique, search_term):
    if software:
        df = df[df['x_mitre_platforms'].apply(lambda x: bool(set(software) & set(x if x else [])))]
    if tactics:
        df = df[df['kill_chain_phases'].apply(lambda x: bool(set(tactics) & set(phase['phase_name'] for phase in x if phase.get('phase_name'))))]
    if technique:
        df = df[df['kill_chain_phases'].apply(lambda x: bool(set([technique]) & set(phase['kill_chain_name'] for phase in x if phase.get('kill_chain_name'))))]
    if search_term:
        df = df[df['name'].str.contains(search_term, case=False) | df['description'].str.contains(search_term, case=False)]
    return df

def get_supplemental_info(df, selected_row):
    supplemental_info = {}
    row = df.loc[selected_row]

    supplemental_info['Tactic'] = ', '.join([phase['phase_name'] for phase in row['kill_chain_phases']])
    supplemental_info['Techniques'] = ', '.join([phase['kill_chain_name'] for sublist in row['kill_chain_phases'] for phase in sublist if phase.get('kill_chain_name')])
    supplemental_info['Software'] = ', '.join(row['x_mitre_platforms'])
    supplemental_info['Groups'] = ', '.join(row['x_mitre_groups'])
    supplemental_info['Data Sources'] = ', '.join(row['x_mitre_data_sources'])

    return supplemental_info

def main():
    st.title('Enterprise ATT&CK Matrix Explorer')

    data = load_data()
    df, software, tactics = process_data(data)

    st.sidebar.header('Filters')
    software_filter = st.sidebar.multiselect('Software', software)
    tactics_filter = st.sidebar.multiselect('Tactics', tactics)
    selected_tactic = st.sidebar.selectbox('Selected Tactic', options=tactics_filter)
    technique_options = sorted(list(set(phase['kill_chain_name'] for sublist in df['kill_chain_phases'].dropna() for phase in sublist if phase.get('phase_name') == selected_tactic)))
    selected_technique = st.sidebar.selectbox('Selected Technique', options=technique_options, key=selected_tactic)
    search_term = st.sidebar.text_input('Search TTPs')

    filtered_df = apply_filters(df, software_filter, tactics_filter, selected_technique, search_term)

    if not filtered_df.empty:
        selected_row = st.radio('Select TTP', filtered_df.index)
        supplemental_info = get_supplemental_info(filtered_df, selected_row)

        st.subheader('Supplemental Information')
        st.write('**Tactic:**', supplemental_info['Tactic'])
        st.write('**Techniques:**', supplemental_info['Techniques'])
        st.write('**Software:**', supplemental_info['Software'])
        st.write('**Groups:**', supplemental_info['Groups'])
        st.write('**Data Sources:**', supplemental_info['Data Sources'])

        st.subheader('Filtered TTPs')
        st.dataframe(filtered_df[['name', 'description']])
    else:
        st.write('No results found.')

if __name__ == '__main__':
    main()
