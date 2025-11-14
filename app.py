import streamlit as st
import pandas as pd
import boto3
import time
import plotly.express as px

# --- Page Configuration ---
st.set_page_config(
    page_title="Mini SIEM Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- AWS Athena Configuration ---
ATHENA_DATABASE = 'default'
S3_RESULTS_BUCKET = 's3://sanjana-athena-query-results/' # MAKE SURE THIS IS YOUR BUCKET
AWS_REGION = 'eu-north-1' # MAKE SURE THIS IS YOUR REGION

# Initialize boto3 client for Athena
try:
    athena_client = boto3.client('athena', region_name=AWS_REGION)
except Exception as e:
    st.error(f"Error creating AWS client: {e}. Please ensure your AWS credentials and region are configured correctly.")
    st.stop()

# --- Helper Function to Run Athena Queries ---
@st.cache_data(ttl=300)
def run_athena_query(query, database, output_location):
    try:
        response = athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': database},
            ResultConfiguration={'OutputLocation': output_location}
        )
        query_execution_id = response['QueryExecutionId']

        while True:
            status_response = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
            status = status_response['QueryExecution']['Status']['State']
            if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                break
            time.sleep(1)

        if status == 'SUCCEEDED':
            results_paginator = athena_client.get_paginator('get_query_results')
            results_iter = results_paginator.paginate(
                QueryExecutionId=query_execution_id,
                PaginationConfig={'PageSize': 1000}
            )
            
            rows = []
            column_info = results_iter.build_full_result()['ResultSet']['ResultSetMetadata']['ColumnInfo']
            column_names = [col['Name'] for col in column_info]

            for results_page in results_iter:
                # The first row of each page is the header, skip it
                page_rows = results_page['ResultSet']['Rows'][1:]
                for row in page_rows:
                    rows.append([item.get('VarCharValue', None) for item in row['Data']])
            
            if not rows:
                return pd.DataFrame(columns=column_names)

            df = pd.DataFrame(rows, columns=column_names)
            
            # Convert appropriate columns to numeric types
            for col in df.columns:
                if 'bytes' in col or 'count' in col or 'ports' in col or 'attempts' in col:
                    df[col] = pd.to_numeric(df[col], errors='coerce')

            return df
        else:
            error_reason = status_response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown error')
            st.error(f"Athena query failed: {error_reason}")
            return pd.DataFrame()

    except Exception as e:
        st.error(f"An exception occurred while running the Athena query: {e}")
        return pd.DataFrame()

# --- Dashboard UI ---
st.title("🛡️ Mini SIEM - VPC Flow Log Analysis")
st.markdown("A dashboard for monitoring and visualizing network traffic anomalies in AWS.")

# --- Define Athena Queries ---
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
FROM vpc_flow_logs WHERE FROM_UNIXTIME("start") > NOW() - INTERVAL '15' MINUTE
GROUP BY srcaddr HAVING COUNT(*) > 5
ORDER BY connection_attempts DESC LIMIT 10;
"""

traffic_status_query = f"""
SELECT action, COUNT(*) as flow_count
FROM vpc_flow_logs {time_filter}
GROUP BY action;
"""

traffic_over_time_query = f"""
SELECT date_trunc('minute', FROM_UNIXTIME("start")) as time_bucket, COUNT(*) as flow_count
FROM vpc_flow_logs {time_filter}
GROUP BY 1 ORDER BY 1;
"""

recent_logs_query = """
SELECT FROM_UNIXTIME("start") as flow_timestamp, srcaddr, dstaddr, dstport, protocol, action, bytes
FROM vpc_flow_logs ORDER BY "start" DESC LIMIT 50;
"""

# --- Layout for Key Metrics and Charts ---

st.header("Live Traffic Overview")
col1, col2 = st.columns(2)

# Display Traffic Status Pie Chart
with col1:
    st.subheader("Accepted vs. Rejected Traffic")
    df_traffic_status = run_athena_query(traffic_status_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_traffic_status.empty:
        fig = px.pie(df_traffic_status, 
                     names='action', 
                     values='flow_count', 
                     title="Flow Status (Last 3 Hours)",
                     color_discrete_map={'ACCEPT':'green', 'REJECT':'red'})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No traffic status data available.")

# Display Top Talkers Bar Chart
with col2:
    st.subheader("Top 10 Traffic Sources")
    df_top_talkers = run_athena_query(top_talkers_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_top_talkers.empty:
        fig = px.bar(df_top_talkers, 
                     x='srcaddr', 
                     y='total_bytes', 
                     title="Top Sources by Bytes Transferred",
                     labels={'srcaddr': 'Source IP', 'total_bytes': 'Total Bytes'})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No significant traffic sources found.")

# Traffic Over Time Line Chart
st.header("Traffic Volume Over Time")
df_traffic_over_time = run_athena_query(traffic_over_time_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
if not df_traffic_over_time.empty:
    df_traffic_over_time['time_bucket'] = pd.to_datetime(df_traffic_over_time['time_bucket'])
    st.line_chart(df_traffic_over_time.rename(columns={'time_bucket':'index'}).set_index('index'))
else:
    st.info("Not enough data to display traffic trend.")

# Anomaly Detection Section
st.header("Anomaly Detections")
col3, col4 = st.columns(2)

# Display Potential DDoS Activity
with col3:
    st.subheader("🚨 Potential DDoS-like Activity")
    df_ddos = run_athena_query(ddos_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_ddos.empty:
        st.warning("High connection frequency detected:")
        st.dataframe(df_ddos, use_container_width=True)
    else:
        st.success("No high-frequency connection patterns detected.")

# Display Potential Port Scanning Activity
with col4:
    st.subheader("🔍 Potential Port Scanning")
    df_port_scan = run_athena_query(port_scan_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_port_scan.empty:
        st.warning("Potential port scanning detected:")
        st.dataframe(df_port_scan, use_container_width=True)
    else:
        st.success("No significant port scanning patterns detected.")

# Detailed Log Viewer
with st.expander("Show Recent Raw Flow Logs"):
    st.subheader("Last 50 Flow Log Entries")
    df_recent_logs = run_athena_query(recent_logs_query, ATHENA_DATABASE, S3_RESULTS_BUCKET)
    if not df_recent_logs.empty:
        st.dataframe(df_recent_logs)
    else:
        st.info("No recent logs found.")