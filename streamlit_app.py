import streamlit as st
import pandas as pd
import altair as alt

# Load the data from the GitHub repository
@st.cache_data(allow_output_mutation=True)
def load_data():
    data_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    return pd.read_json(data_url)

# Process the data to extract relevant information
def process_data(data):
    techniques = data["objects"]
    software = sorted(list(set(technique.get('x_mitre_products', []) for technique in techniques)))
    tactics = sorted(list(set(tactic for technique in techniques for tactic in technique.get('x_mitre_tactics', [])))))
    groups = sorted(list(set(technique.get('x_mitre_groups', []) for technique in techniques)))
    data_sources = sorted(list(set(technique.get('x_mitre_data_sources', []) for technique in techniques)))
    return techniques, software, tactics, groups, data_sources

# Function to update the filtered techniques based on dropdown selections
def update_filtered_techniques(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, techniques):
    filtered_techniques = techniques.copy()
    if selected_tactic:
        filtered_techniques = [technique for technique in filtered_techniques if selected_tactic in technique.get('x_mitre_tactics', [])]
    if selected_technique:
        filtered_techniques = [technique for technique in filtered_techniques if selected_technique == technique.get('name')]
    if selected_group:
        filtered_techniques = [technique for technique in filtered_techniques if selected_group in technique.get('x_mitre_groups', [])]
    if selected_data_source:
        filtered_techniques = [technique for technique in filtered_techniques if selected_data_source in technique.get('x_mitre_data_sources', [])]
    if selected_software:
        filtered_techniques = [technique for technique in filtered_techniques if selected_software in technique.get('x_mitre_products', [])]
    return filtered_techniques

# Function to update the dropdown options and selected values
def update_dropdowns(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, tactics, techniques, software, groups, data_sources):
    if selected_tactic is None:
        selected_tactic = st.sidebar.selectbox("Select a Tactic", tactics)
    if selected_technique is None:
        selected_technique = st.sidebar.selectbox("Select a Technique", [technique.get('name', '') for technique in techniques])
    if selected_group is None:
        selected_group = st.sidebar.selectbox("Select an APT Group", groups)
    if selected_data_source is None:
        selected_data_source = st.sidebar.selectbox("Select a Data Source", data_sources)
    if selected_software is None:
        selected_software = st.sidebar.selectbox("Select a Software", software)
    return selected_tactic, selected_technique, selected_group, selected_data_source, selected_software

# Function to display the technique details in the right panel
def display_technique_details(technique):
    st.subheader(f"{technique['name']} ({technique['external_references'][0]['source_name']})")
    st.markdown(technique['description'])
    st.markdown(f"[Mitre ATT&CK Link]({technique['external_references'][0]['url']})")

# Function to display the tactic counts chart in the right panel
def display_tactic_counts(filtered_techniques):
    tactic_counts = pd.DataFrame([(technique.get('x_mitre_tactics', []), 1) for technique in filtered_techniques], columns=['Tactic', 'Count'])
    chart = alt.Chart(tactic_counts).mark_bar().encode(
        x='Count',
        y=alt.Y('Tactic:N', sort=alt.EncodingSortField(field='Count', op='sum', order='descending')),
    )
    st.subheader("Tactic Counts")
    st.altair_chart(chart, use_container_width=True)

# Main function
def main():
    # Load the data
    data = load_data()

    # Process the data
    techniques, software, tactics, groups, data_sources = process_data(data)

    # Initialize the selected values
    selected_tactic = None
    selected_technique = None
    selected_group = None
    selected_data_source = None
    selected_software = None

    # Update the dropdown options and selected values
    selected_tactic, selected_technique, selected_group, selected_data_source, selected_software = update_dropdowns(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, tactics, techniques, software, groups, data_sources)

    # Update the filtered techniques based on dropdown selections
    filtered_techniques = update_filtered_techniques(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, techniques)

    # Display the dropdowns and update the selections
    with st.sidebar:
        st.title("Filters")
        selected_tactic = st.selectbox("Select a Tactic", tactics, index=tactics.index(selected_tactic))
        selected_technique = st.selectbox("Select a Technique", [technique.get('name', '') for technique in techniques], index=techniques.index(selected_technique))
        selected_group = st.selectbox("Select an APT Group", groups, index=groups.index(selected_group))
        selected_data_source = st.selectbox("Select a Data Source", data_sources, index=data_sources.index(selected_data_source))
        selected_software = st.selectbox("Select a Software", software, index=software.index(selected_software))
    selected_tactic, selected_technique, selected_group, selected_data_source, selected_software = update_dropdowns(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, tactics, techniques, software, groups, data_sources)

    # Update the filtered techniques based on the updated dropdown selections
    filtered_techniques = update_filtered_techniques(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, techniques)

    # Display the filtered techniques
    if filtered_techniques:
        st.subheader("Filtered Techniques")
        for technique in filtered_techniques:
            display_technique_details(technique)
        display_tactic_counts(filtered_techniques)

# Run the app
if __name__ == '__main__':
    main()
