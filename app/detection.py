import re
import logging
import subprocess
import pandas as pd
import numpy as np
import scapy.all as scapy
import warnings
import tensorflow as tf
from tensorflow import keras
from joblib import load
from app.logger import log_threat  # ✅ Importing log_threat

warnings.filterwarnings("ignore")

# 🚀 Load Preprocessor & Model
try:
    preprocessor = load("./app/kddcup_preprocessor.joblib")
    model = keras.models.load_model("./app/dl_ids_model.h5")
    log_threat("INFO", "✅ Loaded preprocessor and model successfully")
except Exception as e:
    log_threat("ERROR", f"❌ Error loading model or preprocessor: {e}")
    exit(1)

# 🚀 Attack Categories Mapping
attack_mapping = {
    "back": "dos", "buffer_overflow": "u2r", "ftp_write": "r2l", "guess_passwd": "r2l",
    "imap": "r2l", "ipsweep": "probe", "land": "dos", "loadmodule": "u2r",
    "multihop": "r2l", "neptune": "dos", "nmap": "probe", "perl": "u2r",
    "phf": "r2l", "pod": "dos", "portsweep": "probe", "rootkit": "u2r",
    "satan": "probe", "smurf": "dos", "spy": "r2l", "teardrop": "dos",
    "warezclient": "r2l", "warezmaster": "r2l", "normal": "normal"
}

# 🚀 SQL Injection Detection Patterns
SQL_INJECTION_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # Common SQL Injection patterns
    r"(SELECT|UPDATE|DELETE|INSERT|DROP|UNION|OR|AND).*",  # SQL keywords
]

# 🚀 Utility Functions
def block_ip(ip):
    """Blocks an IP address using iptables."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        log_threat("IP Blocked", f"Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        log_threat("ERROR", f"Failed to block {ip}: {e}")

def get_protocol_type(proto_num):
    """Returns the protocol type (TCP, UDP, ICMP) from protocol number."""
    return {6: "tcp", 17: "udp", 1: "icmp"}.get(proto_num, "other")

def get_service(packet):
    """Identifies the service based on the destination port."""
    if scapy.TCP in packet:
        dport = packet[scapy.TCP].dport
    elif scapy.UDP in packet:
        dport = packet[scapy.UDP].dport
    else:
        return "other"

    service_map = {
        80: "http", 443: "https", 21: "ftp", 22: "ssh",
        23: "telnet", 25: "smtp", 53: "domain", 110: "pop3", 143: "imap"
    }
    return service_map.get(dport, "other")

# 🚀 Deep Learning Feature Extraction
def extract_packet_features(packet):
    """Extracts relevant network packet features for IDS model."""
    features = {col: 0 for col in preprocessor.feature_names_in_}

    if scapy.IP in packet:
        features["protocol_type"] = get_protocol_type(packet[scapy.IP].proto)
        features["src_bytes"] = len(packet)
        features["dst_bytes"] = 0  # Cannot track response packets in live traffic
        features["service"] = get_service(packet)

    if scapy.TCP in packet:
        flags_int = int(packet[scapy.TCP].flags)
        features["flag"] = "SYN" if flags_int & 0x02 else "FIN" if flags_int & 0x01 else "normal"
    else:
        features["flag"] = "normal"

    return features

def transform_packet_features(packet):
    """Transforms packet features using the preprocessor."""
    features_dict = extract_packet_features(packet)
    df_features = pd.DataFrame([features_dict])

    try:
        X_transformed = preprocessor.transform(df_features)
        return X_transformed.toarray() if hasattr(X_transformed, "toarray") else X_transformed
    except Exception as e:
        log_threat("ERROR", f"Preprocessing failed: {e}")
        return None

# 🚀 SQL Injection Detection
def detect_sql_injection(query):
    """Detects SQL injection attempts in user input."""
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            log_threat("SQL Injection", f"Detected malicious query: {query}")
            return True
    return False

# 🚀 Function to Print Malicious Packet Alert
def alert_malicious_packet(src_ip, dst_ip, attack_type, protocol, service, packet_size):
    print("\n🚨 ALERT: Malicious Packet Detected 🚨")
    print(f"🔴 Attacker IP: {src_ip}")
    print(f"🖥️ Destination IP (Your Machine): {dst_ip}")
    print(f"⚠️ Attack Type: {attack_type}")
    print(f"📡 Protocol: {protocol}")
    print(f"💻 Service: {service}")
    print(f"📦 Packet Size: {packet_size} bytes")
    print("-" * 60)

    log_threat("Intrusion Alert", f"Attack Detected - {attack_type} from {src_ip}")

# 🚀 Packet Processing for Threat Detection
def process_packet(packet):
    """Processes each network packet for anomaly detection."""
    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = get_protocol_type(packet[scapy.IP].proto)
        service = get_service(packet)
        packet_size = len(packet)

        # Deep Learning-Based Intrusion Detection
        features = transform_packet_features(packet)
        if features is not None:
            prediction = model.predict(features, verbose=0)
            attack_index = np.argmax(prediction)
            attack_type = list(attack_mapping.keys())[attack_index]
            attack_category = attack_mapping.get(attack_type, "unknown")

            if attack_category != "normal":
                alert_malicious_packet(src_ip, dst_ip, attack_category, protocol, service, packet_size)
                block_ip(src_ip)

        # SYN Flood Detection
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 2:  # SYN Packet
            alert_malicious_packet(src_ip, dst_ip, "SYN Flood", protocol, service, packet_size)

        # UDP Flood Detection
        if protocol == "udp" and packet.haslayer(scapy.UDP):
            alert_malicious_packet(src_ip, dst_ip, "UDP Flood", protocol, service, packet_size)

    # ARP Spoofing Detection
    if scapy.ARP in packet:
        alert_malicious_packet(packet[scapy.ARP].psrc, packet[scapy.ARP].pdst, "ARP Spoofing", "ARP", "ARP", len(packet))

# 🚀 Start Sniffing Network Traffic
def start_sniffing(interface=None, filter_ip=None):
    """Starts real-time network sniffing and anomaly detection."""
    print("🚀 Starting packet sniffing...")
    try:
        scapy.sniff(iface=interface, prn=process_packet, filter=f"dst host {filter_ip}" if filter_ip else None, store=False)
    except KeyboardInterrupt:
        print("🛑 Packet sniffing stopped.")

# 🚀 Main Execution
if __name__ == "__main__":
    print("🚀 Starting IDS system...")
    model.summary()
    start_sniffing()
