import streamlit as st
import pandas as pd

@st.cache(allow_output_mutation=True)
def load_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    data = pd.read_json(url)
    return data

def process_data(data):
    techniques = data['objects']
    software = sorted(list(set(software for technique in techniques for software in technique.get('x_mitre_products', []))))
    tactics = sorted(list(set(tactic for technique in techniques for tactic in technique.get('x_mitre_tactics', []))))
    groups = sorted(list(set(group for technique in techniques for group in technique.get('x_mitre_groups', []))))
    data_sources = sorted(list(set(source for technique in techniques for source in technique.get('x_mitre_data_sources', []))))

    return techniques, software, tactics, groups, data_sources

def main():
    st.set_page_config(layout="wide")

    st.sidebar.title("Filters")

    data = load_data()
    techniques, software, tactics, groups, data_sources = process_data(data)

    with st.sidebar:
        st.subheader("Software")
        selected_software = st.selectbox("", software, key='software')

        st.subheader("Tactic")
        selected_tactic = st.selectbox("", tactics, key='tactic')

        st.subheader("APT Group")
        selected_group = st.selectbox("", groups, key='group')

        st.subheader("Data Source")
        selected_data_source = st.selectbox("", data_sources, key='data_source')

    filtered_techniques = techniques
    if selected_software:
        filtered_techniques = [technique for technique in filtered_techniques if selected_software in technique.get('x_mitre_products', [])]
    if selected_tactic:
        filtered_techniques = [technique for technique in filtered_techniques if selected_tactic in technique.get('x_mitre_tactics', [])]
    if selected_group:
        filtered_techniques = [technique for technique in filtered_techniques if selected_group in technique.get('x_mitre_groups', [])]
    if selected_data_source:
        filtered_techniques = [technique for technique in filtered_techniques if selected_data_source in technique.get('x_mitre_data_sources', [])]

    if filtered_techniques:
        st.header("Selected Techniques:")
        for technique in filtered_techniques:
            st.subheader(technique.get('name', ''))
            st.write("ID:", technique.get('external_references', [{}])[0].get('external_id', ''))
            st.write("Description:", technique.get('description', ''))
            st.write("Tactic:", technique.get('x_mitre_tactics', []))
            st.write("APT Group:", technique.get('x_mitre_groups', []))
            st.write("---")

        st.header("Analytics:")
        tactic_counts = pd.DataFrame([(technique.get('x_mitre_tactics', []), 1) for technique in filtered_techniques], columns=['Tactic', 'Count'])
        st.subheader("Tactic Counts")
        st.dataframe(tactic_counts)

        software_counts = pd.DataFrame([(technique.get('x_mitre_products', []), 1) for technique in filtered_techniques], columns=['Software', 'Count'])
        st.subheader("Software Counts")
        st.dataframe(software_counts)

if __name__ == "__main__":
    main()
