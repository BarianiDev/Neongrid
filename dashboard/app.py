import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
from Neongrid.storage.db import get_events

st.set_page_config(page_title="NeonGrid SIEM", layout="wide")
st.title("NeonGrid - Security Dashboard")

if st.button("Event and alerts analysis"):
    from Neongrid.engine.rules import run_and_store
    new_alerts = run_and_store()
    st.success(f"{len(new_alerts)} new alert(s) generated")



scan_results = get_events(event_type="port_scan_result")
syslog_events = get_events(event_type="syslog_message")
alerts = get_events(event_type="alert")

col1, col2, col3 = st.columns(3)
col1.metric("Open ports", len(scan_results))
col2.metric("Receivied logs (syslog)", len(syslog_events))
col3.metric("Alerts", len(alerts))

st.subheader("Alerts")
if alerts:
    df_alerts = pd.DataFrame(alerts)
    cols = [c for c in ["timestamp", "rule", "severity", "mitre_id", "mitre_technique", "detail"] if c in df_alerts.columns]
    st.dataframe(df_alerts[cols], width="stretch")

else:
    st.info("None alerts")

st.subheader("Open ports")
if scan_results:
    df_ports = pd.DataFrame(scan_results)
    cols = [ c for c in ["timestamp", "target_ip", "port", "service", "risk", "description"] if c in df_ports.columns]
    st.dataframe(df_ports[cols], width="stretch")

    st.subheader("Risk Distribuction")
    st.bar_chart(df_ports["risk"].value_counts())

else:
    st.info("No scans yet")