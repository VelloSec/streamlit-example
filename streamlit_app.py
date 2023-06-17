
import requests
import json
from stix2 import parse
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st
import openai

# URL to the STIX data file in your GitHub repo
url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

def load_data():
    # Fetch the STIX data file
    response = requests.get(url)
    response.raise_for_status()  # Raise exception if the request failed

    # Parse the STIX data
    bundle_data = json.loads(response.text)
    if 'spec_version' in bundle_data:
        del bundle_data['spec_version']  # Remove the 'spec_version' field

    bundle = parse(bundle_data)

    # Extract entities from the bundle
    techniques = [obj for obj in bundle.objects if obj['type'] == 'attack-pattern']
    actors = [obj for obj in bundle.objects if obj['type'] == 'intrusion-set']
    software = [obj for obj in bundle.objects if obj['type'] == 'malware']
    relationships = [obj for obj in bundle.objects if obj['type'] == 'relationship']

    return techniques, actors, software, relationships

def main():
    st.title("MITRE ATT&CK Navigator")

    # Load STIX data
    techniques, actors, software, relationships = load_data()

    # Display data in a table
    if st.checkbox('Show raw data'):
        st.subheader('Techniques')
        st.write(techniques)
        st.subheader('Actors')
        st.write(actors)
        st.subheader('Software')
        st.write(software)

    # Select a specific technique
    selected_technique = st.selectbox("Select a technique", techniques)
    st.write("You selected: ", selected_technique)

    # Chat with GPT-3 about the selected technique
    chatGPT_api_key = st.text_input("Enter your OpenAI GPT-3 API Key", type="password")
    if st.button("Chat about the selected technique"):
        if not chatGPT_api_key:
            st.write("Please enter your OpenAI GPT-3 API Key")
        else:
            openai.api_key = chatGPT_api_key
            response = openai.Completion.create(
                engine="text-davinci-002",
                prompt=f"I want to learn about {selected_technique}",
                temperature=0.5,
                max_tokens=100
            )
            st.write(response.choices[0].text.strip())

if __name__ == "__main__":
    main()


