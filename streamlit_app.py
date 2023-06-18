import streamlit as st
import pandas as pd
import requests

def load_data():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url)
    data = response.json()
    return data

def process_data(data):
    objects = data.get("objects", [])
    df = pd.DataFrame(objects)

    tactics = sorted(list(set(df["kill_chain_phases"].dropna())))
    techniques = sorted(list(set(df["name"])))
    groups = sorted(list(set(group for sublist in df["x_mitre_groups"].dropna() for group in sublist)))

    return df, tactics, techniques, groups

def filter_data(df, tactics_filter, technique_filter, group_filter):
    filtered_df = df.copy()
    
    if tactics_filter:
        filtered_df = filtered_df[filtered_df["kill_chain_phases"].apply(lambda x: any(tactic["kill_chain_name"] == tactics_filter for tactic in x))]
    
    if technique_filter:
        filtered_df = filtered_df[filtered_df["name"] == technique_filter]
    
    if group_filter:
        filtered_df = filtered_df[filtered_df["x_mitre_groups"].apply(lambda x: group_filter in x)]
    
    return filtered_df

def main():
    data = load_data()
    df, tactics, techniques, groups = process_data(data)
    
    st.title("MITRE ATT&CK Navigator")
    
    st.sidebar.header("Filters")
    tactics_filter = st.sidebar.selectbox("Tactics", [""] + tactics)
    technique_filter = st.sidebar.selectbox("Techniques", [""] + techniques)
    group_filter = st.sidebar.selectbox("APT Groups", [""] + groups)
    
    filtered_df = filter_data(df, tactics_filter, technique_filter, group_filter)
    
    st.sidebar.subheader("Selected Filters")
    st.sidebar.write("Tactics:", tactics_filter)
    st.sidebar.write("Technique:", technique_filter)
    st.sidebar.write("APT Group:", group_filter)
    
    if filtered_df.empty:
        st.warning("No techniques found with the selected filters.")
    else:
        st.success(f"Displaying {filtered_df.shape[0]} techniques.")
        st.dataframe(filtered_df)

if __name__ == "__main__":
    main()
