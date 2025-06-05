import sqlite3
from datetime import datetime
from app.firebase_config import db  # Ensure Firebase is set up

# 🚀 Connect to SQLite Database
conn = sqlite3.connect("database/threat_logs.db", check_same_thread=False)
cursor = conn.cursor()

# 🚀 Create Logs Table (Includes Full Malicious Packet Details)
cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        threat_type TEXT,
        attacker_ip TEXT,
        destination_ip TEXT,
        attack_type TEXT,
        protocol TEXT,
        service TEXT,
        packet_size INTEGER,
        message TEXT
    )
""")
conn.commit()

def log_threat(threat_type, message):
    """
    Logs general threats (e.g., SQL Injection) in SQLite & Firebase.

    Args:
        threat_type (str): Type of threat detected.
        message (str): Description of the detected threat.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ✅ Save to SQLite Database
    try:
        cursor.execute("""
            INSERT INTO logs (timestamp, threat_type, message) 
            VALUES (?, ?, ?)
        """, (timestamp, threat_type, message))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to log to SQLite: {e}")

    # ✅ Save to Firebase Firestore
    try:
        db.collection("threat_logs").add({
            "timestamp": timestamp,
            "threat_type": threat_type,
            "message": message
        })
    except Exception as e:
        print(f"[ERROR] Failed to log to Firebase: {e}")

    # ✅ Print Alert in Console
    print(f"[ALERT] {threat_type}: {message} ({timestamp})")

def log_malicious_packet(src_ip, dst_ip, attack_type, protocol, service, packet_size):
    """
    Logs details of a malicious packet to SQLite & Firebase.

    Args:
        src_ip (str): Attacker's IP address.
        dst_ip (str): Destination IP (your machine).
        attack_type (str): Type of attack detected.
        protocol (str): Network protocol (TCP, UDP, etc.).
        service (str): Affected network service.
        packet_size (int): Size of the malicious packet.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = (
        f"🚨 ALERT: Malicious Packet Detected \n"
        f"🕵️‍♂️ Attacker IP: {src_ip} \n"
        f"🛡 Destination IP (Your Machine): {dst_ip} \n"
        f"⚠ Attack Type: {attack_type} \n"
        f"📡 Protocol: {protocol}  |  🖧 Service: {service} \n"
        f"📦 Packet Size: {packet_size} bytes"
    )

    # ✅ Save to SQLite with all details
    try:
        cursor.execute("""
            INSERT INTO logs (timestamp, threat_type, attacker_ip, destination_ip, attack_type, protocol, service, packet_size, message) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, "Malicious Packet", src_ip, dst_ip, attack_type, protocol, service, packet_size, message))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to log malicious packet to SQLite: {e}")

    # ✅ Save to Firebase with full details
    try:
        db.collection("threat_logs").add({
            "timestamp": timestamp,
            "threat_type": "Malicious Packet",
            "attacker_ip": src_ip,
            "destination_ip": dst_ip,
            "attack_type": attack_type,
            "protocol": protocol,
            "service": service,
            "packet_size": packet_size,
            "message": message
        })
    except Exception as e:
        print(f"[ERROR] Failed to log malicious packet to Firebase: {e}")

    # ✅ Print Alert in Console
    print("-" * 60)
    print(message)
    print("-" * 60)
