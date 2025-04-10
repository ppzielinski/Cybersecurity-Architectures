import streamlit as st

# Configure wide layout, if desired
st.set_page_config(page_title="SEAS-8405: Week-4", layout="wide")


def main():
    st.title("Welcome to My Cybersecurity Architectures App")
    st.write("""
    This is the **main page**. Use the sidebar to navigate to the other pages.

    **Instructions**:
    - Select any page from the sidebar on the left (e.g., "Defense in Depth", "Zero Trust", etc.).
    - Each page provides a detailed table or explanation of a specific architecture.
    - You can return here anytime by clicking **Home** in the sidebar.
    """)


if __name__ == "__main__":
    main()
