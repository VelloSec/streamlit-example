import streamlit as st
import pandas as pd
import altair as alt
import requests

# Function to load data from the GitHub repository
@st.cache
def load_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    data = pd.read_json(url)
    return data

# Function to process the loaded data and extract relevant information
def process_data(data):
    techniques = data['objects']
    software = sorted(list(set(software for technique in techniques for software in technique.get('x_mitre_products', []))))
    tactics = sorted(list(set(tactic for technique in techniques for tactic in technique.get('x_mitre_tactics', []))))
    groups = sorted(list(set(group for technique in techniques for group in technique.get('x_mitre_groups', []))))
    data_sources = sorted(list(set(source for technique in techniques for source in technique.get('x_mitre_data_sources', []))))

    return techniques, software, tactics, groups, data_sources

# Function to filter the techniques based on selected values from the dropdowns
def update_filtered_techniques(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, techniques):
    filtered_techniques = techniques

    if selected_tactic:
        filtered_techniques = filtered_techniques[filtered_techniques.apply(lambda x: selected_tactic in x.get('x_mitre_tactics', []), axis=1)]
    if selected_technique:
        filtered_techniques = filtered_techniques[filtered_techniques.apply(lambda x: x.get('name', '') == selected_technique, axis=1)]
    if selected_group:
        filtered_techniques = filtered_techniques[filtered_techniques.apply(lambda x: selected_group in x.get('x_mitre_groups', []), axis=1)]
    if selected_data_source:
        filtered_techniques = filtered_techniques[filtered_techniques.apply(lambda x: selected_data_source in x.get('x_mitre_data_sources', []), axis=1)]
    if selected_software:
        filtered_techniques = filtered_techniques[filtered_techniques.apply(lambda x: selected_software in x.get('x_mitre_products', []), axis=1)]

    return filtered_techniques

# Function to update the dropdown options based on the selected values
def update_dropdowns(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, tactics, techniques, software, groups, data_sources):
    if selected_tactic and selected_tactic not in tactics:
        selected_tactic = None
    if selected_technique and selected_technique not in [technique.get('name', '') for technique in techniques]:
        selected_technique = None
    if selected_group and selected_group not in groups:
        selected_group = None
    if selected_data_source and selected_data_source not in data_sources:
        selected_data_source = None
    if selected_software and selected_software not in software:
        selected_software = None

    return selected_tactic, selected_technique, selected_group, selected_data_source, selected_software

# Function to filter the dropdown options based on the selected values
def filter_dropdown(dropdown_label, options, selected_value):
    filtered_options = options.copy()
    if selected_value:
        filtered_options.remove(selected_value)
    return st.selectbox(dropdown_label, [""] + filtered_options, key=f"{dropdown_label}_dropdown")

# Function to display the technique details in the right panel
def display_technique_details(technique):
    st.subheader(f"{technique['name']} ({technique['external_references'][0]['source_name']})")
    st.markdown(technique['description'])
    st.markdown(f"[Mitre ATT&CK Link]({technique['external_references'][0]['url']})")

# Function to display the tactic counts chart
def display_tactic_counts(filtered_techniques):
    tactic_counts = pd.DataFrame([(technique.get('x_mitre_tactics', []), 1) for technique in filtered_techniques], columns=['Tactic', 'Count'])
    chart = alt.Chart(tactic_counts).mark_bar().encode(
        x='Tactic',
        y='Count',
        tooltip=['Tactic', 'Count']
    ).interactive()
    st.header("Tactic Counts")
    st.altair_chart(chart, use_container_width=True)

# Main function
def main():
    st.title("MITRE ATT&CK Navigator")

    # Load the data from the GitHub repository
    data = load_data()

    # Process the data to extract relevant information
    techniques, software, tactics, groups, data_sources = process_data(data)

    # Search box to filter techniques by name
    search_text = st.text_input("Search by Technique Name")
    filtered_techniques = update_filtered_techniques(None, None, None, None, None, techniques)
    if search_text:
        filtered_techniques = [technique for technique in filtered_techniques if search_text.lower() in technique.get('name', '').lower()]

    # Update the dropdown options and selected values
    selected_tactic = filter_dropdown("Tactic", tactics, None)
    selected_technique = filter_dropdown("Technique", [technique.get('name', '') for technique in techniques], None)
    selected_group = filter_dropdown("APT Group", groups, None)
    selected_data_source = filter_dropdown("Data Source", data_sources, None)
    selected_software = filter_dropdown("Software", software, None)
    selected_tactic, selected_technique, selected_group, selected_data_source, selected_software = update_dropdowns(
        selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, tactics, techniques, software, groups, data_sources
    )

    # Update the filtered techniques based on the selected dropdown values
    filtered_techniques = update_filtered_techniques(selected_tactic, selected_technique, selected_group, selected_data_source, selected_software, techniques)

    # Display the selected technique details
    if filtered_techniques is not None:
        st.sidebar.subheader("Selected Technique")
        selected_technique = st.sidebar.selectbox("Select a Technique", [technique.get('name', '') for technique in filtered_techniques])
        selected_technique = [technique for technique in filtered_techniques if technique.get('name', '') == selected_technique]
        if selected_technique:
            selected_technique = selected_technique[0]
            display_technique_details(selected_technique)

            # Display the tactic counts chart
            display_tactic_counts(filtered_techniques)

if __name__ == "__main__":
    main()
