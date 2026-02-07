import streamlit as st
from modules.sherlock_runner import run_sherlock
from modules.image_analysis import analyze_image
from modules.report_generator import generate_report

st.set_page_config(page_title="OSINT Investigator", layout="wide")

st.title("🕵️ OSINT Investigator")

tab1, tab2, tab3 = st.tabs(["Username OSINT", "Image OSINT", "Report"])

with tab1:
    username = st.text_input("Username")
    if st.button("Run Sherlock"):
        if username:
            st.text_area("Results", run_sherlock(username), height=300)
        else:
            st.warning("Enter a username")

with tab2:
    image = st.file_uploader("Upload Image", type=["jpg","jpeg","png"])
    if image:
        st.text_area("EXIF Output", analyze_image(image), height=300)

with tab3:
    case = st.text_input("Case Name")
    if st.button("Generate Report"):
        if case:
            path = generate_report(case)
            st.success(f"Report saved: {path}")
        else:
            st.warning("Enter case name")
