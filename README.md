# Cloud Network Intrusion Detection  
### AWS Mini SIEM using VPC Flow Logs & Streamlit Dashboard

A lightweight **Mini SIEM (Security Information and Event Management)** system built on AWS to monitor, analyze, and visualize cloud network traffic using **VPC Flow Logs**.  
This project simulates how a **Security Operations Center (SOC)** detects suspicious activities such as port scanning, brute-force attempts, and abnormal traffic patterns in a cloud environment.

---

## Project Overview

Modern cloud environments generate massive volumes of network logs, but raw logs alone do not provide actionable security insights.  
This project bridges that gap by:

- Collecting **AWS VPC Flow Logs**
- Processing and structuring log data using **Python**
- Visualizing security insights through an interactive **Streamlit dashboard**
- Detecting potential intrusion patterns in near real-time

---

## Objectives

- Gain visibility into internal cloud network traffic  
- Detect suspicious behaviors such as:
  - Unauthorized port access
  - Repeated denied connections
  - Port scanning attempts
  - Abnormal traffic volume
- Demonstrate how cloud-native logs can be used for security monitoring

---

## System Architecture

### AWS Components
- VPC  
- Public Subnet  
- EC2 Instance (Traffic Generator)  
- VPC Flow Logs  
- S3 Bucket (Log Storage)  
- IAM Roles  

### Local / Application Components
- Python (Log Processing)
- Streamlit (Dashboard & Visualization)

### Workflow
1. EC2 instance generates network traffic  
2. VPC Flow Logs capture metadata (accepted & rejected traffic)  
3. Logs are stored in Amazon S3  
4. Python script fetches and parses logs  
5. Data is cleaned and structured into DataFrames  
6. Streamlit dashboard visualizes traffic and alerts  
7. Analyst identifies potential intrusions  

### Flowchart
[ EC2 Instance ]
        |
        v
[ VPC Flow Logs ]
        |
        v
[ Amazon S3 ]
        |
        v
[ Python Log Processor ]
        |
        v
[ Streamlit Mini SIEM Dashboard ]
        |
        v
[ Security Detection & Alerts ]

---

## Methodology

### Step 1: AWS Network Setup
- Create VPC and public subnet  
- Launch EC2 instance  
- Configure security groups  

### Step 2: Enable VPC Flow Logs
- Capture **ALL** traffic (Accepted + Rejected)
- Store logs in S3  

### Step 3: Data Processing
Python script performs:
- Log ingestion from S3  
- Parsing fields:
  - Source IP
  - Destination IP
  - Source & Destination ports
  - Action (ACCEPT / REJECT)
  - Byte count
- Conversion into CSV / Pandas DataFrame  

### Step 4: Dashboard Implementation
Built using **Streamlit**, featuring:
- Accepted vs Rejected traffic pie chart  
- Traffic volume over time  
- Top source IPs  
- Most targeted ports  
- Alerts for suspicious activity  

### Step 5: Threat Detection Logic
- High rejected packet rate  
- Single IP accessing multiple ports (Port Scanning)  
- Repeated connection attempts (Brute Force behavior)  
- Abnormal traffic spikes  

---

## Results & Analysis

Key observations from the dashboard:
- Certain IPs showed repeated denied connection attempts  
- Restricted ports were frequently targeted  
- Clear spikes in rejected traffic were visible  
- One or more IPs were flagged with port-scanning behavior  

These patterns closely resemble real-world reconnaissance and intrusion attempts.

---

## Live Dashboard

🔗 **Streamlit Dashboard:**  
https://aws-mini-siem-dashboard-s569rrkfas7xtmwqfw9nq8.streamlit.app/

---

## GitHub Repository

🔗 **Source Code:**  
https://github.com/MS123-D/aws-mini-siem-dashboard

---

## Future Enhancements

- Real-time log ingestion using CloudWatch Logs
- Automated alerting (Email / Slack)
- Threat intelligence enrichment
- Machine learning–based anomaly detection
- Integration with SOC workflows

---

## Author

**Meinam Sanjana Devi**  
BCA (Cybersecurity)  
Cloud Security | SIEM | Network Monitoring  

---

## Conclusion

This project demonstrates how AWS cloud-native services can be effectively leveraged to build a **scalable, lightweight SIEM solution**.  
It provides hands-on experience in **cloud security operations, log analysis, and intrusion detection**, making it a strong foundation for advanced SOC and cybersecurity research projects.

---

If you find this project useful, consider starring the repository!
