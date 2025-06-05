import streamlit as st
import sqlite3
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from streamlit_autorefresh import st_autorefresh

# === Page Configuration ===
st.set_page_config(page_title="KAVACH - Cyber Threat Detection", layout="wide")

st.title("IntrudoTrap")

# === Auto Refresh Every 5 Seconds ===
st_autorefresh(interval=5000, key="realtime_dashboard")

# === Connect to SQLite Database ===
def get_db_connection():
    return sqlite3.connect("database/threat_logs.db", check_same_thread=False)

# === Fetch Data from Database ===
conn = get_db_connection()
cursor = conn.cursor()

# === Fetch Unique Threat Types (Fix applied) ===
cursor.execute("SELECT DISTINCT threat_type FROM logs")
threat_type_results = cursor.fetchall()
threat_types = [row[0] for row in threat_type_results] if threat_type_results else []

# === Fetch Alerts Data ===
cursor.execute("SELECT timestamp, threat_type, message FROM logs ORDER BY timestamp DESC LIMIT 50")
alerts = cursor.fetchall()

# === Ensure "blocked_ips" Table Exists ===
cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
conn.commit()

# === Fetch Blocked IPs ===
cursor.execute("SELECT * FROM blocked_ips")
blocked_ips = cursor.fetchall()

conn.close()

# === Initialize Real-Time Metrics ===
if 'packet_count' not in st.session_state:
    st.session_state.packet_count = 0
if 'threat_count' not in st.session_state:
    st.session_state.threat_count = 0
if 'start_time' not in st.session_state:
    st.session_state.start_time = datetime.now()
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = []

# === Simulated real-time data update ===
new_packets = np.random.randint(10, 50)
new_threats = np.random.randint(0, 5)

st.session_state.packet_count += new_packets
st.session_state.threat_count += new_threats

normal_packets = new_packets - new_threats  # Normal packets = Total - Attack packets

st.session_state.traffic_history.append({
    "timestamp": datetime.now(),
    "attack_packets": new_threats,
    "normal_packets": normal_packets
})

# === Create Tabs ===
tabs = st.tabs([
    "📊 Dashboard", "🚨 Alerts", "🚫 Blocked IPs", "ℹ️ Attack Info", "⚙️ Settings"
])

# === 📊 Dashboard Tab ===
with tabs[0]:
    st.subheader("📊 Real-Time Threat Monitoring Dashboard")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("📡 Total Packets", f"{st.session_state.packet_count:,}")
    col2.metric("🚨 Threats Detected", f"{st.session_state.threat_count:,}")

    # Calculate runtime
    runtime = datetime.now() - st.session_state.start_time
    hours, remainder = divmod(runtime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    runtime_str = f"{hours}h {minutes}m {seconds}s"
    col3.metric("⏳ System Runtime", runtime_str)

    # Attack percentage
    attack_percentage = (st.session_state.threat_count / max(st.session_state.packet_count, 1)) * 100
    col4.metric("⚠️ Attack Percentage", f"{attack_percentage:.2f}%")

    # === Line Graph: Attack Packets vs Normal Packets ===
    st.subheader("📈 Attack Packets vs Normal Packets Over Time")

    # Convert session data into DataFrame
    traffic_df = pd.DataFrame(st.session_state.traffic_history)
    
    if not traffic_df.empty:
        fig = px.line(traffic_df, x="timestamp", y=["attack_packets", "normal_packets"],
                      labels={"value": "Number of Packets", "timestamp": "Time"},
                      title="Attack Packets vs Normal Packets Over Time",
                      markers=True)

        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Waiting for data...")

# === 🚨 Alerts Tab with Filters ===
with tabs[1]:
    st.subheader("🚨 Security Alerts")

    # === Filters ===
    col1, col2, col3 = st.columns(3)

    # Filter by Threat Type (Fix applied)
    selected_threat_type = col1.selectbox("🔍 Select Threat Type", ["All"] + threat_types if threat_types else ["All"])

    # Filter by Date Range
    today = datetime.now().date()
    date_range = col2.date_input("📅 Select Date Range", [today - timedelta(days=7), today])

    # Filter by Severity
    severity_options = ["All", "Critical", "High", "Medium", "Low"]
    selected_severity = col3.selectbox("⚠️ Select Severity", severity_options)

    # === Apply Filters ===
    df_alerts = pd.DataFrame(alerts, columns=["Timestamp", "Threat Type", "Message"])
    df_alerts["Timestamp"] = pd.to_datetime(df_alerts["Timestamp"])

    # Apply Threat Type Filter
    if selected_threat_type != "All":
        df_alerts = df_alerts[df_alerts["Threat Type"] == selected_threat_type]

    # Apply Date Range Filter
    start_date, end_date = date_range
    df_alerts = df_alerts[(df_alerts["Timestamp"].dt.date >= start_date) & (df_alerts["Timestamp"].dt.date <= end_date)]

    # Apply Severity Filter
    severity_mapping = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}
    if selected_severity != "All":
        df_alerts = df_alerts[df_alerts["Threat Type"].str.contains(severity_mapping[selected_severity], case=False, na=False)]

    # Display Filtered Alerts
    if not df_alerts.empty:
        st.dataframe(df_alerts, use_container_width=True)
    else:
        st.info("✅ No matching alerts found.")

# === 🚫 Blocked IPs Tab ===
# === 🚫 Blocked IPs Tab ===
with tabs[2]:
    st.subheader("🚫 Blocked IP Addresses")
    
    # Create two columns for layout
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # === Blocklist Management ===
        st.subheader("📋 Blocklist Management")
        
        if blocked_ips:
            df_blocked = pd.DataFrame(blocked_ips, columns=["ID", "IP Address", "Blocked At"])
            
            # Display blocked IPs with action buttons
            st.dataframe(
                df_blocked,
                column_config={
                    "ID": None,  # Hide ID column
                    "IP Address": "IP Address",
                    "Blocked At": "Blocked At"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("✅ No blocked IPs.")
            
        # === Block History Stats ===
        st.subheader("📊 Block Statistics")
        
        if blocked_ips:
            # Convert to DataFrame for analysis
            df_stats = pd.DataFrame(blocked_ips, columns=["ID", "IP Address", "Blocked At"])
            df_stats["Blocked At"] = pd.to_datetime(df_stats["Blocked At"])
            
            # Group by date for time series
            df_daily = df_stats.set_index("Blocked At").resample('D').size().reset_index(name='Count')
            
            # Show time series chart
            fig = px.line(
                df_daily, 
                x="Blocked At", 
                y="Count",
                title="Block Frequency Over Time",
                labels={"Blocked At": "Date", "Count": "Blocks"},
                markers=True
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
            
            # Show top blocked IPs
            top_ips = df_stats["IP Address"].value_counts().head(5)
            st.write("🔝 Most Blocked IPs:")
            st.dataframe(top_ips, use_container_width=True)
        else:
            st.info("No block history available.")
    
    with col2:
        # === IP Actions Panel ===
        st.subheader("🛠️ IP Actions")
        
        # Manual IP Block
        with st.form("block_ip_form"):
            ip_to_block = st.text_input("Enter IP to block", placeholder="192.168.1.1")
            submit_block = st.form_submit_button("🚫 Block IP")
            
            if submit_block and ip_to_block:
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip_address) VALUES (?)", (ip_to_block,))
                    conn.commit()
                    st.success(f"✅ {ip_to_block} blocked successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error blocking IP: {e}")
                finally:
                    conn.close()
        
        # Unblock IP
        if blocked_ips:
            with st.form("unblock_ip_form"):
                ip_to_unblock = st.selectbox(
                    "Select IP to unblock",
                    [ip[1] for ip in blocked_ips]
                )
                submit_unblock = st.form_submit_button("✅ Unblock IP")
                
                if submit_unblock:
                    try:
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_to_unblock,))
                        conn.commit()
                        st.success(f"✅ {ip_to_unblock} unblocked successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error unblocking IP: {e}")
                    finally:
                        conn.close()
        
        # === Import/Export ===
        st.subheader("📁 Import/Export")
        
        # Export to CSV
        if blocked_ips:
            csv = df_blocked.to_csv(index=False).encode()
            st.download_button(
                label="📥 Export Blocklist (CSV)",
                data=csv,
                file_name="blocklist.csv",
                mime="text/csv"
            )
        
        # Export to JSON
        if blocked_ips:
            json_data = df_blocked.to_json(orient="records")
            st.download_button(
                label="📥 Export Blocklist (JSON)",
                data=json_data,
                file_name="blocklist.json",
                mime="application/json"
            )
        
        # Import Blocklist
        with st.expander("📤 Import Blocklist"):
            uploaded_file = st.file_uploader(
                "Choose CSV/JSON file",
                type=["csv", "json"],
                accept_multiple_files=False
            )
            
            if uploaded_file:
                try:
                    if uploaded_file.name.endswith('.csv'):
                        df_import = pd.read_csv(uploaded_file)
                    else:
                        df_import = pd.read_json(uploaded_file)
                    
                    if "IP Address" in df_import.columns:
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        
                        # Get existing IPs to avoid duplicates
                        cursor.execute("SELECT ip_address FROM blocked_ips")
                        existing_ips = [ip[0] for ip in cursor.fetchall()]
                        
                        # Insert new IPs
                        new_ips = [ip for ip in df_import["IP Address"].unique() if ip not in existing_ips]
                        
                        if new_ips:
                            cursor.executemany(
                                "INSERT OR IGNORE INTO blocked_ips (ip_address) VALUES (?)",
                                [(ip,) for ip in new_ips]
                            )
                            conn.commit()
                            st.success(f"✅ Added {len(new_ips)} new IPs to blocklist!")
                            st.rerun()
                        else:
                            st.info("No new IPs to add.")
                    else:
                        st.error("File must contain 'IP Address' column")
                except Exception as e:
                    st.error(f"Error importing blocklist: {e}")
                finally:
                    conn.close()
        
        # === Whitelist Management ===
        st.subheader("✅ Whitelist")
        
        # Ensure whitelist table exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
        
        # Add to whitelist
        with st.form("whitelist_form"):
            ip_to_whitelist = st.text_input("Enter IP to whitelist", placeholder="192.168.1.1")
            submit_whitelist = st.form_submit_button("➕ Add to Whitelist")
            
            if submit_whitelist and ip_to_whitelist:
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("INSERT OR IGNORE INTO whitelist (ip_address) VALUES (?)", (ip_to_whitelist,))
                    conn.commit()
                    st.success(f"✅ {ip_to_whitelist} added to whitelist!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error whitelisting IP: {e}")
                finally:
                    conn.close()
        
        # View whitelist
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM whitelist")
        whitelist_ips = [ip[0] for ip in cursor.fetchall()]
        conn.close()
        
        if whitelist_ips:
            with st.expander("View Whitelist"):
                st.dataframe(pd.DataFrame(whitelist_ips, columns=["Whitelisted IPs"]))
                
                # Remove from whitelist
                ip_to_remove = st.selectbox("Select IP to remove", whitelist_ips)
                if st.button("Remove from Whitelist"):
                    try:
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM whitelist WHERE ip_address = ?", (ip_to_remove,))
                        conn.commit()
                        st.success(f"✅ {ip_to_remove} removed from whitelist!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error removing from whitelist: {e}")
                    finally:
                        conn.close()
        else:
            st.info("No whitelisted IPs")
# === ℹ️ Attack Info Tab ===
with tabs[3]:
    st.subheader("ℹ️ Attack Information & Mitigation Strategies")

    attack_descriptions = {
        "DoS": "Denial of Service (DoS) attacks attempt to overload a system with excessive requests.",
        "DDoS": "Distributed Denial of Service (DDoS) attacks use multiple sources to attack a target.",
        "Ransomware": "A malware that encrypts files and demands payment to restore access.",
        "SQL Injection": "Attackers insert malicious SQL queries to manipulate a database.",
        "Phishing": "Tricks users into providing sensitive information via fake emails or websites.",
        "Brute Force": "A method that tries multiple password combinations to gain access.",
    }

    for attack, description in attack_descriptions.items():
        with st.expander(f"🛡️ {attack}"):
            st.write(description)

# === ⚙️ Settings Tab ===
with tabs[4]:
    st.subheader("⚙️ System Settings")
    packet_limit = st.number_input("Packet Limit", min_value=100, max_value=10000, value=1000, step=100)
    detection_sensitivity = st.slider("Detection Sensitivity", min_value=0.1, max_value=1.0, value=0.7, step=0.1)
    if st.button("Save Settings"):
        st.success("✅ Settings Saved Successfully!")

# === Sidebar Controls ===
st.sidebar.header("🔧 Controls")
if st.sidebar.button("🔄 Reset Data"):
    st.session_state.packet_count = 0
    st.session_state.threat_count = 0
    st.session_state.start_time = datetime.now()
    st.session_state.traffic_history = []
    st.sidebar.success("✅ Data Reset Successfully!")
