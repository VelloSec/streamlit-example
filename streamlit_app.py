import streamlit as st
import pandas as pd
import requests
from typing import List, Dict
import json

@st.cache
def load_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    file = requests.get(url)
    data = file.json()
    return data

def extract_techniques(data: Dict) -> pd.DataFrame:
    techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
    df = pd.json_normalize(techniques)
    return df

def get_platforms(df: pd.DataFrame) -> List[str]:
    platforms = set()
    for _, row in df.iterrows():
        if 'x_mitre_platforms' in row and isinstance(row['x_mitre_platforms'], list):
            platforms.update(row['x_mitre_platforms'])
    return sorted(list(platforms))

def main():
    st.title('Enterprise ATT&CK Matrix')

    data = load_data()
    df = extract_techniques(data)
    platforms = get_platforms(df)

    platform_filter = st.sidebar.multiselect('Platform', platforms, default=platforms)
    search_term = st.sidebar.text_input('Search techniques')

    filtered_df = df[df['x_mitre_platforms'].apply(lambda x: any(platform in x for platform in platform_filter))]

    if search_term:
        filtered_df = filtered_df[filtered_df['name'].str.contains(search_term, case=False)]
    
    st.write(filtered_df[['name', 'description', 'x_mitre_platforms']])

if __name__ == "__main__":
    main()
