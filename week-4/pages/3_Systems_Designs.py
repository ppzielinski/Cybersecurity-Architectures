
import streamlit as st
import os

st.set_page_config(layout="wide", initial_sidebar_state="expanded", page_title="Systems Architecture")
# Load available deployments
deployment_names = sorted([f.replace("_onprem.png", "").replace("_aws.png", "").replace("_azure.png", "")
                           for f in os.listdir("arch") if f.endswith(".png")])
deployment_names = sorted(set(deployment_names))  # unique names

env_map = {
    "On-Premises": "onprem",
    "AWS": "aws",
    "Azure": "azure"
}

# Streamlit UI
st.title("SEAS-8405: Simple Architecture Explorer")

selected_deployment = st.selectbox("Select a Deployment", deployment_names)
selected_env_label = st.radio("Choose an Environment", list(env_map.keys()), horizontal=True)

selected_env = env_map[selected_env_label]
image_filename = f"arch/{selected_deployment.lower().replace(' ', '_')}_{selected_env}.png"

if os.path.exists(image_filename):
    st.image(image_filename, caption=f"{selected_deployment} - {selected_env_label}", use_column_width=True) #, use_container_width=True)
else:
    st.warning(f"Diagram not found for {selected_deployment} in {image_filename}.")
