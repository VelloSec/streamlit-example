import streamlit as st
import pandas as pd
from taxii2client.v20 import Server
from stix2 import TAXIICollectionSource, Filter

@st.cache(allow_output_mutation=True)
def load_data():
    # Establish TAXII2 Collection instance for Enterprise ATT&CK collection
    server = Server("https://cti-taxii.mitre.org/taxii/")
    api_root = server.api_roots[0]
    collection = api_root.collections[0]
    src = TAXIICollectionSource(collection)

    # Define Filters to retrieve only the required objects
    filter_objs = {"intrusion-set", "malware", "tool"}

    attack_data = []
    for obj_type in filter_objs:
        f = Filter("type", "=", obj_type)
        attack_data.extend(src.query([f]))

    return attack_data

def main():
    st.title("MITRE ATT&CK Navigator")

    # Load STIX data
    attack_data = load_data()

    # Create a DataFrame for better visualization
    attack_df = pd.DataFrame([item for item in attack_data])
    attack_df = attack_df[['type', 'name', 'description', 'aliases', 'created', 'modified']]

    # Display the DataFrame
    if st.checkbox('Show raw data'):
        st.write(attack_df)

    # Show specific types of data based on user's selection
    attack_types = attack_df['type'].unique().tolist()
    attack_types.sort()
    selected_type = st.selectbox("Select a type", attack_types)
    st.write(attack_df[attack_df['type'] == selected_type])

if __name__ == "__main__":
    main()
