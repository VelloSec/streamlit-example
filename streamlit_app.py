import requests
import os
from collections import Counter
from stix2 import parse
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

# URL to the STIX data file in your GitHub repo
url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

@st.cache
def load_data():
    # Fetch the STIX data file
    response = requests.get(url)
    response.raise_for_status()  # Raise exception if the request failed

    # Parse the STIX data
    bundle = parse(response.text)

    # Extract entities from the bundle
    techniques = [obj for obj in bundle.objects if obj['type'] == 'attack-pattern']
    actors = [obj for obj in bundle.objects if obj['type'] == 'intrusion-set']
    software = [obj for obj in bundle.objects if obj['type'] == 'malware']
    relationships = [obj for obj in bundle.objects if obj['type'] == 'relationship']

    return techniques, actors, software, relationships

def generate_response(question, context, api_key):
    # Use the OpenAI API to generate a response to the question based on the context
    import openai
    openai.api_key = api_key
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=f"{context}\n{question}\nAnswer:",
        temperature=0.5,
        max_tokens=100
    )
    return response.choices[0].text.strip()

def main():
    st.title("MITRE ATT&CK Navigator")

    # User input for OpenAI API key
    api_key = st.text_input("Enter your OpenAI API Key", type="password")

    # Load data
    techniques, actors, software, relationships = load_data()

    # Visualization of the top 5 most common techniques used by actors
    actor_to_techs = [rel for rel in relationships if rel['source_ref'] in [actor['id'] for actor in actors]]
    technique_counts = Counter([rel['target_ref'] for rel in actor_to_techs])
    top_techniques = technique_counts.most_common(5)
    fig, ax = plt.subplots()
    ax.bar([tech[0] for tech in top_techniques], [tech[1] for tech in top_techniques])
    ax.set_xlabel('Technique')
    ax.set_ylabel('Count')
    ax.set_title('Top 5 most common techniques used by actors')
    st.pyplot(fig)

    # Search functionality
    query = st.text_input("Search for techniques, actors, or software")
    if query:
        st.subheader("Techniques")
        for technique in [t for t in techniques if query.lower() in t['name'].lower()]:
            st.write(technique['name'])

        st.subheader("Actors")
        for actor in [a for a in actors if query.lower() in a['name'].lower()]:
            st.write(actor['name'])

        st.subheader("Software")
        for soft in [s for s in software if query.lower() in s['name'].lower()]:
            st.write(soft['name'])

    # The currently viewed entities - replace this with the actual data based on your application's state
    current_entities = []  

    # GPT-3 Integration
    use_gpt = st.checkbox('Enable GPT-3', value=False)
    if use_gpt and api_key:
        question = st.text_input("Ask a question")
        if question:
            # Create the context based on the current view
            context = "\n".join([f"{entity['name']}: {entity['description']}" for entity in current_entities])

            # Generate the answer based on the context
            answer = generate_response(question, context, api_key)
            st.write(f"Answer: {answer}")

if __name__ == "__main__":
    main()

