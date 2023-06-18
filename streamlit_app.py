import streamlit as st
import pandas as pd

def load_data():
    data = pd.read_json('enterprise-attack.json')
    return data

def filter_data(data, software, tactics, techniques, groups, data_sources, initial_access):
    df = data.copy()
    
    if software:
        df = df[df['x_mitre_products'].apply(lambda x: any(item for item in x if software.lower() in item.lower()))]
    if tactics:
        df = df[df['kill_chain_phases'].apply(lambda x: any(item for item in x if tactics.lower() in item['phase_name'].lower()))]
    if techniques:
        df = df[df['name'].apply(lambda x: techniques.lower() in x.lower())]
    if groups:
        df = df[df['x_mitre_groups'].apply(lambda x: any(item for item in x if groups.lower() in item.lower()))]
    if data_sources:
        df = df[df['x_mitre_data_sources'].apply(lambda x: any(item for item in x if data_sources.lower() in item.lower()))]
    if initial_access:
        df = df[df['x_mitre_initial_access'].apply(lambda x: any(item for item in x if initial_access.lower() in item.lower()))]
    
    return df

def process_data(data):
    software = sorted(list(set(item for sublist in data['x_mitre_products'].dropna() for item in sublist)))
    tactics = sorted(list(set(item['phase_name'] for sublist in data['kill_chain_phases'].dropna() for item in sublist)))
    techniques = sorted(list(set(data['name'])))
    groups = sorted(list(set(item for sublist in data['x_mitre_groups'].dropna() for item in sublist)))
    data_sources = sorted(list(set(item for sublist in data['x_mitre_data_sources'].dropna() for item in sublist)))
    initial_access = sorted(list(set(item for sublist in data['x_mitre_initial_access'].dropna() for item in sublist)))
    
    return software, tactics, techniques, groups, data_sources, initial_access

def main():
    st.title("MITRE ATT&CK Navigator - Enterprise")

    data = load_data()
    software, tactics, techniques, groups, data_sources, initial_access = process_data(data)

    software_filter = st.sidebar.selectbox("Filter by Software:", ["All"] + software)
    tactic_filter = st.sidebar.selectbox("Filter by Tactic:", ["All"] + tactics)
    technique_filter = st.sidebar.selectbox("Filter by Technique:", ["All"] + techniques)
    group_filter = st.sidebar.selectbox("Filter by APT Group:", ["All"] + groups)
    data_source_filter = st.sidebar.selectbox("Filter by Data Source:", ["All"] + data_sources)
    initial_access_filter = st.sidebar.selectbox("Filter by Initial Access:", ["All"] + initial_access)
    
    filtered_data = filter_data(data, software_filter, tactic_filter, technique_filter, group_filter,
                                data_source_filter, initial_access_filter)

    st.markdown("### Techniques")
    st.write(filtered_data)

if __name__ == '__main__':
    main()
