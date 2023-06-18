import streamlit as st
import pandas as pd
import altair as alt
import requests

@st.cache_data(allow_output_mutation=True)
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

def filter_dropdown(dropdown_label, options, selected_value):
    filtered_options = [""]
    if selected_value:
        filtered_options = [option for option in options if option != selected_value]
    return st.selectbox(dropdown_label, filtered_options, key=f"{dropdown_label}_dropdown")

def update_dropdowns(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, techniques, tactics, software, groups, data_sources):
    filtered_techniques = techniques

    if selected_tactic:
        filtered_techniques = [technique for technique in filtered_techniques if selected_tactic in technique.get('x_mitre_tactics', [])]
    if selected_technique:
        filtered_techniques = [technique for technique in filtered_techniques if selected_technique in technique.get('name', '')]
    if selected_group:
        filtered_techniques = [technique for technique in filtered_techniques if selected_group in technique.get('x_mitre_groups', [])]
    if selected_data_source:
        filtered_techniques = [technique for technique in filtered_techniques if selected_data_source in technique.get('x_mitre_data_sources', [])]
    if selected_software:
        filtered_techniques = [technique for technique in filtered_techniques if selected_software in technique.get('x_mitre_products', [])]

    return filtered_techniques

def main():
    st.set_page_config(layout="wide")

    st.title("MITRE ATT&CK Navigator")
    st.markdown("---")

    st.sidebar.title("Filters")

    data = load_data()
    techniques, software, tactics, groups, data_sources = process_data(data)

    selected_tactic = filter_dropdown("Tactic", tactics, None)
    selected_technique = filter_dropdown("Technique", [technique['name'] for technique in techniques], None)
    selected_group = filter_dropdown("APT Group", groups, None)
    selected_data_source = filter_dropdown("Data Source", data_sources, None)
    selected_software = filter_dropdown("Software", software, None)

    filtered_techniques = update_dropdowns(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, techniques, tactics, software, groups, data_sources)

    st.sidebar.subheader("Search")
    search_text = st.sidebar.text_input("Search by Technique Name", "")

    filtered_techniques = [technique for technique in filtered_techniques if search_text.lower() in technique.get('name', '').lower()]

    if filtered_techniques:
        st.sidebar.subheader("Supplemental Information")

        selected_technique = filtered_techniques[0]
        st.sidebar.markdown(f"**{selected_technique['name']}**")
        st.sidebar.markdown(f"[Mitre ATT&CK Link]({selected_technique['external_references'][0]['url']})")

    tactic_counts = pd.DataFrame([(technique['x_mitre_tactics'], 1) for technique in filtered_techniques], columns=['Tactic', 'Count'])

    st.header("Tactic Counts")
    st.dataframe(tactic_counts)

    chart = alt.Chart(tactic_counts).mark_bar().encode(
        x='Tactic',
        y='Count',
        tooltip=['Tactic', 'Count']
    ).interactive()

    st.altair_chart(chart, use_container_width=True)

if __name__ == "__main__":
    main()
