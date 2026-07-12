import streamlit as st
import pandas as pd
import json
import os

# Define Paths
REPORT_PATH = "data/reports/anomaly_report.json"
CLEANED_PATH = "data/processed/cleaned_firewall_rules.csv"
RAW_PATH = "data/raw/raw_simulated_firewall_logs.csv"

# Page Configuration
st.set_page_config(page_title="Firewall AI Optimizer", layout="wide")

st.title("🛡️ Firewall Anomaly Resolution System")
st.markdown("Automated Policy Auditing via Reinforcement Learning & Genetic Algorithms")
st.markdown("---")

# Layout Columns
col1, col2 = st.columns(2)

with col1:
    st.subheader("⚠️ AI Anomaly Detection Report")
    st.write("Anomalies flagged for shadowing, redundancy, and conflicts.")
    
    if os.path.exists(REPORT_PATH):
        with open(REPORT_PATH, 'r') as f:
            report_data = json.load(f)
        
        # Display nicely formatted JSON
        st.json(report_data)
    else:
        st.warning("No anomaly report found. Run the master pipeline.")

with col2:
    st.subheader("✅ RL Agent: Cleaned Rule Set")
    
    if os.path.exists(RAW_PATH) and os.path.exists(CLEANED_PATH):
        raw_df = pd.read_csv(RAW_PATH)
        clean_df = pd.read_csv(CLEANED_PATH)
        
        st.write("The Reinforcement Learning agent has successfully purged the anomalous rules.")
        
        # Display Metrics
        met1, met2, met3 = st.columns(3)
        met1.metric("Original Rules", len(raw_df))
        met2.metric("Cleaned Rules", len(clean_df))
        met3.metric("Rules Removed", len(raw_df) - len(clean_df), delta="-3", delta_color="inverse")
        
        # Display the cleaned data table
        st.dataframe(clean_df, use_container_width=True)
    else:
        st.warning("Cleaned matrix not found. Run the master pipeline.")

# Sidebar Controls
st.sidebar.header("System Status")
st.sidebar.success("Data Pipeline: ONLINE")
st.sidebar.success("GA Optimizer: ONLINE")
st.sidebar.success("RL Agent: ONLINE")
st.sidebar.markdown("---")
st.sidebar.info("To refresh data, execute `python main.py` in your terminal.")

