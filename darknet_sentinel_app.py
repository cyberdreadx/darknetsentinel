import streamlit as st
import random
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import re
from collections import defaultdict

# Page config
st.set_page_config(page_title="DarkNet Sentinel", page_icon="🛡️", layout="wide")

# Initialize session state
if 'logs_data' not in st.session_state:
    st.session_state.logs_data = []
if 'threat_stats' not in st.session_state:
    st.session_state.threat_stats = defaultdict(int)
if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False

# App title
st.title("🛡️ DarkNet Sentinel – AI Threat Monitor")
st.markdown("Advanced real-time system log analysis with ML-powered threat detection and comprehensive dashboard.")

# Create tabs for different views
tab1, tab2, tab3, tab4 = st.tabs(["🔍 Live Monitor", "📊 Dashboard", "⚙️ Settings", "📋 Reports"])

# Enhanced threat patterns with severity levels
THREAT_PATTERNS = {
    "CRITICAL": {
        "patterns": ["root access", "privilege escalation", "backdoor", "ransomware", "data exfiltration"],
        "color": "#ff0000",
        "score": 10
    },
    "HIGH": {
        "patterns": ["unauthorized", "failed login", "brute force", "malicious", "exploit"],
        "color": "#ff4500",
        "score": 8
    },
    "MEDIUM": {
        "patterns": ["suspicious", "anomaly", "unusual", "phishing", "spam"],
        "color": "#ffa500",
        "score": 5
    },
    "LOW": {
        "patterns": ["warning", "timeout", "retry", "slow response"],
        "color": "#ffff00",
        "score": 3
    }
}

# Enhanced log entries with more realistic scenarios
ENHANCED_LOG_ENTRIES = [
    "2024-01-15 10:30:15 - SSH: Accepted password for user1 from 192.168.0.1 port 22",
    "2024-01-15 10:30:45 - AUTH: Failed password for root from 10.0.0.5 port 22 (3 attempts)",
    "2024-01-15 10:31:02 - SECURITY: Unauthorized login attempt detected from 185.220.101.5",
    "2024-01-15 10:31:15 - SSH: Connection closed by authentic user from 192.168.0.1",
    "2024-01-15 10:31:30 - EMAIL: Possible phishing message detected in inbox",
    "2024-01-15 10:31:45 - SUDO: User admin added to sudoers group",
    "2024-01-15 10:32:00 - EXEC: Malicious command execution attempt blocked",
    "2024-01-15 10:32:15 - CRON: Normal activity - scheduled backup completed",
    "2024-01-15 10:32:30 - SSH: Login from known device (192.168.0.10)",
    "2024-01-15 10:32:45 - EMAIL: Message from trusted domain processed",
    "2024-01-15 10:33:00 - FIREWALL: Blocked suspicious traffic from 203.0.113.5",
    "2024-01-15 10:33:15 - DB: Database connection established successfully",
    "2024-01-15 10:33:30 - WEB: HTTP 404 error - potential directory traversal attempt",
    "2024-01-15 10:33:45 - SYSTEM: Memory usage normal (67%)",
    "2024-01-15 10:34:00 - NETWORK: Unusual network traffic pattern detected",
    "2024-01-15 10:34:15 - AUTH: User session expired - automatic logout",
    "2024-01-15 10:34:30 - BACKUP: Backup verification completed successfully",
    "2024-01-15 10:34:45 - VIRUS: Potential malware signature detected in file.exe",
    "2024-01-15 10:35:00 - API: Rate limit exceeded for IP 198.51.100.1",
    "2024-01-15 10:35:15 - SYSTEM: Service restart completed normally"
]

# Enhanced threat classification function
def classify_threat_advanced(log_line, custom_keywords=None):
    threat_level = "SAFE"
    threat_score = 0
    matched_patterns = []
    
    log_lower = log_line.lower()
    
    # Check predefined threat patterns
    for level, data in THREAT_PATTERNS.items():
        for pattern in data["patterns"]:
            if pattern in log_lower:
                if data["score"] > threat_score:
                    threat_level = level
                    threat_score = data["score"]
                matched_patterns.append(pattern)
    
    # Check custom keywords
    if custom_keywords:
        for keyword in custom_keywords:
            if keyword.lower() in log_lower:
                if threat_score < 6:  # Custom keywords are medium priority
                    threat_level = "MEDIUM"
                    threat_score = 6
                matched_patterns.append(keyword)
    
    return threat_level, threat_score, matched_patterns

# Function to extract IP addresses from logs
def extract_ip_addresses(log_line):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, log_line)

# Function to generate realistic timestamps
def generate_timestamp():
    base_time = datetime.now() - timedelta(hours=random.randint(0, 24))
    return base_time + timedelta(seconds=random.randint(0, 3600))

with tab1:
    st.header("🔍 Live Threat Monitor")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        monitor_button = st.button("🚀 Start Live Monitoring", type="primary")
        stop_button = st.button("⏹️ Stop Monitoring")
    
    with col2:
        monitoring_speed = st.selectbox("Speed", ["Fast", "Normal", "Slow"], index=1)
        speed_map = {"Fast": 0.5, "Normal": 1, "Slow": 2}
    
    with col3:
        log_limit = st.number_input("Log Limit", min_value=10, max_value=100, value=50)
    
    if stop_button:
        st.session_state.monitoring_active = False
        st.success("Monitoring stopped.")
    
    if monitor_button:
        st.session_state.monitoring_active = True
        st.session_state.logs_data = []
        st.session_state.threat_stats = defaultdict(int)
        
        # Create placeholders for real-time updates
        metrics_container = st.container()
        with metrics_container:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                critical_metric = st.empty()
            with col2:
                high_metric = st.empty()
            with col3:
                medium_metric = st.empty()
            with col4:
                total_metric = st.empty()
        
        log_container = st.container()
        chart_container = st.container()
        
        # Real-time monitoring simulation
        progress_bar = st.progress(0)
        for i in range(log_limit):
            if not st.session_state.monitoring_active:
                break
                
            # Generate log entry
            log_entry = random.choice(ENHANCED_LOG_ENTRIES)
            timestamp = generate_timestamp()
            
            # Get user keywords from settings tab
            user_keywords = st.session_state.get('custom_keywords', ['unauthorized', 'failed', 'malicious', 'phishing'])
            
            # Classify threat
            threat_level, threat_score, matched_patterns = classify_threat_advanced(log_entry, user_keywords)
            
            # Extract additional info
            ip_addresses = extract_ip_addresses(log_entry)
            
            # Store log data
            log_data = {
                'timestamp': timestamp,
                'log': log_entry,
                'threat_level': threat_level,
                'threat_score': threat_score,
                'matched_patterns': matched_patterns,
                'ip_addresses': ip_addresses
            }
            st.session_state.logs_data.append(log_data)
            st.session_state.threat_stats[threat_level] += 1
            
            # Update metrics
            with metrics_container:
                with col1:
                    critical_metric.metric("🔴 Critical", st.session_state.threat_stats['CRITICAL'])
                with col2:
                    high_metric.metric("🟠 High", st.session_state.threat_stats['HIGH'])
                with col3:
                    medium_metric.metric("🟡 Medium", st.session_state.threat_stats['MEDIUM'])
                with col4:
                    total_logs = len(st.session_state.logs_data)
                    total_metric.metric("📊 Total Logs", total_logs)
            
            # Display recent logs
            with log_container:
                st.subheader("Recent Activity")
                recent_logs = st.session_state.logs_data[-10:]
                for log_data in reversed(recent_logs):
                    threat_level = log_data['threat_level']
                    if threat_level != "SAFE":
                        color = THREAT_PATTERNS[threat_level]['color']
                        st.markdown(f"<div style='background-color: {color}20; padding: 10px; border-radius: 5px; margin: 5px 0;'>"
                                  f"<strong>{log_data['timestamp'].strftime('%H:%M:%S')}</strong> - "
                                  f"<span style='color: {color};'>[{threat_level}]</span> "
                                  f"{log_data['log']}</div>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<div style='background-color: #00ff0020; padding: 10px; border-radius: 5px; margin: 5px 0;'>"
                                  f"<strong>{log_data['timestamp'].strftime('%H:%M:%S')}</strong> - "
                                  f"<span style='color: #00ff00;'>[SAFE]</span> "
                                  f"{log_data['log']}</div>", unsafe_allow_html=True)
            
            # Update progress
            progress_bar.progress((i + 1) / log_limit)
            time.sleep(speed_map[monitoring_speed])
        
        st.success("🔍 Monitoring session completed!")

with tab2:
    st.header("📊 Threat Analysis Dashboard")
    
    if st.session_state.logs_data:
        # Create DataFrame for analysis
        df = pd.DataFrame(st.session_state.logs_data)
        
        # Summary statistics
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Threat Level Distribution")
            threat_counts = df['threat_level'].value_counts()
            fig = px.pie(values=threat_counts.values, names=threat_counts.index, 
                        title="Distribution of Threat Levels")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Threat Score Timeline")
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df_sorted = df.sort_values('timestamp')
            fig = px.line(df_sorted, x='timestamp', y='threat_score', 
                         title="Threat Score Over Time")
            st.plotly_chart(fig, use_container_width=True)
        
        # IP Address Analysis
        st.subheader("IP Address Activity")
        all_ips = []
        for ips in df['ip_addresses']:
            all_ips.extend(ips)
        
        if all_ips:
            ip_counts = pd.Series(all_ips).value_counts().head(10)
            fig = px.bar(x=ip_counts.index, y=ip_counts.values, 
                        title="Top 10 Most Active IP Addresses")
            st.plotly_chart(fig, use_container_width=True)
        
        # Threat pattern analysis
        st.subheader("Common Threat Patterns")
        all_patterns = []
        for patterns in df['matched_patterns']:
            all_patterns.extend(patterns)
        
        if all_patterns:
            pattern_counts = pd.Series(all_patterns).value_counts().head(10)
            fig = px.bar(x=pattern_counts.values, y=pattern_counts.index, 
                        orientation='h', title="Most Common Threat Patterns")
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No monitoring data available. Run the Live Monitor first to see analytics.")

with tab3:
    st.header("⚙️ Advanced Settings")
    
    # Custom keywords
    st.subheader("Custom Threat Keywords")
    custom_keywords_input = st.text_area(
        "Enter custom threat keywords (comma-separated):",
        value="unauthorized,failed,malicious,phishing,breach,exploit"
    )
    custom_keywords = [kw.strip().lower() for kw in custom_keywords_input.split(",") if kw.strip()]
    st.session_state.custom_keywords = custom_keywords
    
    # Threat level thresholds
    st.subheader("Threat Level Configuration")
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Current Threat Patterns:**")
        for level, data in THREAT_PATTERNS.items():
            st.write(f"**{level}** (Score: {data['score']})")
            st.write(f"Patterns: {', '.join(data['patterns'])}")
            st.write("---")
    
    with col2:
        st.write("**Alert Settings:**")
        enable_alerts = st.checkbox("Enable Real-time Alerts", value=True)
        alert_threshold = st.selectbox("Alert Threshold", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], index=1)
        auto_export = st.checkbox("Auto-export Reports", value=False)
        export_interval = st.slider("Export Interval (minutes)", 1, 60, 10)

with tab4:
    st.header("📋 Security Reports")
    
    if st.session_state.logs_data:
        # Generate summary report
        df = pd.DataFrame(st.session_state.logs_data)
        
        st.subheader("Security Summary Report")
        
        # Summary statistics
        total_logs = len(df)
        threat_logs = len(df[df['threat_level'] != 'SAFE'])
        threat_percentage = (threat_logs / total_logs) * 100 if total_logs > 0 else 0
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Logs Analyzed", total_logs)
        with col2:
            st.metric("Threats Detected", threat_logs)
        with col3:
            st.metric("Threat Percentage", f"{threat_percentage:.1f}%")
        
        # Detailed threat breakdown
        st.subheader("Detailed Threat Analysis")
        threat_summary = df[df['threat_level'] != 'SAFE'].groupby('threat_level').size().reset_index(name='count')
        if not threat_summary.empty:
            st.dataframe(threat_summary, use_container_width=True)
        
        # Export functionality
        st.subheader("Export Options")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📥 Download CSV Report"):
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"darknet_sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📊 Generate JSON Report"):
                json_data = df.to_json(orient='records', date_format='iso')
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"darknet_sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        # Recent high-priority threats
        st.subheader("Recent High-Priority Threats")
        high_priority = df[df['threat_level'].isin(['CRITICAL', 'HIGH'])].sort_values('timestamp', ascending=False).head(10)
        if not high_priority.empty:
            st.dataframe(high_priority[['timestamp', 'threat_level', 'log', 'matched_patterns']], use_container_width=True)
        else:
            st.info("No high-priority threats detected in recent activity.")
    else:
        st.info("No data available for reporting. Run the Live Monitor first.")

# Footer
st.markdown("---")
st.markdown("**DarkNet Sentinel** - Advanced AI-Powered Cybersecurity Monitoring | Built with Streamlit")
