
# AWS Credentials
AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID_HERE"
AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_ACCESS_KEY_HERE"

# AWS Configuration
AWS_REGION = "eu-north-1"
ATHENA_DATABASE = "default"
S3_RESULTS_BUCKET = "s3://sanjana-athena-query-results/"

import streamlit as st 
import pandas as pd
import boto3
import time
import plotly.express as px

# --- Page Configuration ---
st.set_page_config(
    page_title="Mini SIEM Dashboard",
    layout="wide"
)

# Increase global font size via custom CSS
st.markdown(
    """
    <style>
    html, body, [class*="css"]  {
        font-size: 20px !important;
    }
    .plotly-graph-div text {
        font-size: 20px !important;
    }
    .section-border {
        padding: 15px;
        border-radius: 12px;
        margin-bottom: 25px;
    }
    hr {
        border: none;
        border-top: 2px solid #ddd;
        margin: 25px 0;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# --- AWS Athena Configuration ---
ATHENA_DATABASE = 'default'
S3_RESULTS_BUCKET = 's3://sanjana-athena-query-results/'
AWS_REGION = 'eu-north-1'

# Initialize boto3 client
try:
    athena_client = boto3.client('athena', region_name=AWS_REGION)
except Exception as e:
    st.error(f"Error creating AWS client: {e}.")
    st.stop()

# --- Helper Function ---
@st.cache_data(ttl=300)
def run_athena_query(query, database, output_location):
    try:
        response = athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': database},
            ResultConfiguration={'OutputLocation': output_location}
        )
        qid = response['QueryExecutionId']

        while True:
            status = athena_client.get_query_execution(QueryExecutionId=qid)
            state = status['QueryExecution']['Status']['State']
            if state in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                break
            time.sleep(1)

        if state != 'SUCCEEDED':
            return pd.DataFrame()

        paginator = athena_client.get_paginator('get_query_results')
        results = paginator.paginate(QueryExecutionId=qid)
        rows = []
        metadata = results.build_full_result()['ResultSet']['ResultSetMetadata']['ColumnInfo']
        cols = [c['Name'] for c in metadata]

        for page in results:
            page_rows = page['ResultSet']['Rows'][1:]
            for r in page_rows:
                rows.append([item.get('VarCharValue', None) for item in r['Data']])

        df = pd.DataFrame(rows, columns=cols)

        for col in df.columns:
            if any(x in col for x in ['bytes', 'count', 'ports', 'attempts']):
                df[col] = pd.to_numeric(df[col], errors='ignore')

        return df

    except Exception:
        return pd.DataFrame()


# --- Dashboard Title (Centered) ---
st.markdown("<h1 style='text-align:center;'>Mini SIEM - VPC Flow Log Analysis</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align:center; font-size:26px;'>A dashboard for monitoring and visualizing network anomalies.</h3>", unsafe_allow_html=True)


# --- Queries ---
time_filter = "WHERE FROM_UNIXTIME(\"start\") > NOW() - INTERVAL '3' HOUR"

top_talkers_query = f"""
SELECT srcaddr, SUM(bytes) AS total_bytes
FROM vpc_flow_logs {time_filter}
GROUP BY srcaddr ORDER BY total_bytes DESC LIMIT 10;
"""

port_scan_query = f"""
SELECT srcaddr, COUNT(DISTINCT dstport) AS unique_ports_scanned
FROM vpc_flow_logs {time_filter} AND action = 'REJECT'
GROUP BY srcaddr HAVING COUNT(DISTINCT dstport) > 5
ORDER BY unique_ports_scanned DESC LIMIT 10;
"""

ddos_query = f"""
SELECT srcaddr, COUNT(*) AS connection_attempts
FROM vpc_flow_logs WHERE FROM_UNIXTIME(\"start\") > NOW() - INTERVAL '15' MINUTE
GROUP BY srcaddr HAVING COUNT(*) > 5
ORDER BY connection_attempts DESC LIMIT 10;
"""

traffic_status_query = f"""
SELECT action, COUNT(*) as flow_count
FROM vpc_flow_logs {time_filter}
GROUP BY action;
"""

traffic_over_time_query = f"""
SELECT date_trunc('minute', FROM_UNIXTIME(\"start\")) as time_bucket, COUNT(*) as flow_count
FROM vpc_flow_logs {time_filter}
GROUP BY 1 ORDER BY 1;
"""

recent_logs_query = """
SELECT FROM_UNIXTIME(\"start\") as flow_timestamp, srcaddr, dstaddr, dstport, protocol, action, bytes
FROM vpc_flow_logs ORDER BY \"start\" DESC LIMIT 50;
"""


# --- Live Traffic Overview Box ---
st.markdown("""
<div style='background-color:#ffe6f2; border: 2px solid #ffb3d9; padding: 15px; border-radius: 12px; 
text-align:center; font-size:28px; font-weight:bold; margin-bottom:20px; color:black;'>
Live Traffic Overview
</div>
""", unsafe_allow_html=True)


# --- Pie + Bar Chart (NO BORDER) ---
col1, col2 = st.columns(2)

# PIE CHART
with col1:
    st.subheader("Accepted vs Rejected Traffic")
    df_traffic_status = run_athena_query(traffic_status_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)

    if not df_traffic_status.empty:
        fig = px.pie(
            df_traffic_status,
            names='action',
            values='flow_count',
            color_discrete_map={'ACCEPT': 'lavender', 'REJECT': 'purple'},
            hole=0.35
        )
        fig.update_traces(
            textposition='inside',
            textfont=dict(size=22, color='black', family='Arial', weight='bold'),
            pull=[0.02, 0.02],
            insidetextorientation='radial'
        )
        fig.update_layout(
            margin=dict(l=30, r=150, t=50, b=20),
            legend=dict(
                x=1.15,
                y=0.5,
                bordercolor="black",
                borderwidth=1,
                font=dict(size=18),
            )
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data available.")

# BAR CHART
with col2:
    st.subheader("Top 10 Traffic Sources")
    df_top = run_athena_query(top_talkers_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)

    if not df_top.empty:
        fig = px.bar(
            df_top,
            x='srcaddr',
            y='total_bytes',
            labels={'srcaddr': 'Source IP', 'total_bytes': 'Total Bytes'},
            color_discrete_sequence=['#cc0066']  # dark pink
        )
        fig.update_layout(font_size=20)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No top talkers.")


# ---- Partition Line (Simple Line) ----
st.markdown("<hr>", unsafe_allow_html=True)


# --- Traffic Over Time (RED Line Chart) ---
st.markdown("<div class='section-border'>", unsafe_allow_html=True)
st.header("Traffic Volume Over Time")

df_time = run_athena_query(traffic_over_time_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)

if not df_time.empty:
    df_time['time_bucket'] = pd.to_datetime(df_time['time_bucket'])
    fig = px.line(
        df_time,
        x='time_bucket',
        y='flow_count',
        markers=True
    )
    fig.update_traces(line=dict(color='red', width=4))
    fig.update_layout(font_size=20)
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Not enough data.")

st.markdown("</div>", unsafe_allow_html=True)


# --- Anomaly Sections ---
st.header("Anomaly Detections")
col3, col4 = st.columns(2)

with col3:
    st.subheader("🚨 Potential DDoS Activity")
    df_ddos = run_athena_query(ddos_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_ddos.empty:
        st.warning("High connection frequency detected:")
        st.dataframe(df_ddos, use_container_width=True)
    else:
        st.success("No DDoS signs.")

with col4:
    st.subheader("🔍 Potential Port Scanning")
    df_scan = run_athena_query(port_scan_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_scan.empty:
        st.warning("Possible port scanning detected:")
        st.dataframe(df_scan, use_container_width=True)
    else:
        st.success("No scanning detected.")

# Logs
with st.expander("Show Recent Raw Logs"):
    st.subheader("Last 50 Flow Log Entries")
    df_logs = run_athena_query(recent_logs_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_logs.empty:
        st.dataframe(df_logs)
    else:
        st.info("No logs found.")

