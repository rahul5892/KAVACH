from flask import Flask, render_template, jsonify
import sqlite3
import matplotlib.pyplot as plt
import io
import base64
import pandas as pd

app = Flask(__name__)

# === Fetch Logs from Database ===
def get_logs():
    conn = sqlite3.connect("./database/threat_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10")
    logs = cursor.fetchall()
    conn.close()
    return logs

# === Fetch Anomaly Statistics ===
def get_anomaly_data():
    conn = sqlite3.connect("database/threat_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT threat_type, COUNT(*) FROM logs GROUP BY threat_type")
    anomaly_data = cursor.fetchall()
    conn.close()
    return anomaly_data

# === Fetch Attack Trends ===
def get_attack_trend():
    conn = sqlite3.connect("./database/threat_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT DATE(timestamp), COUNT(*) FROM logs GROUP BY DATE(timestamp) ORDER BY DATE(timestamp)")
    attack_trend_data = cursor.fetchall()
    conn.close()
    return attack_trend_data

# === Generate Pie Chart (Anomaly Distribution) ===
def generate_pie_chart():
    data = get_anomaly_data()
    if not data:
        return None

    labels = [row[0] for row in data]
    counts = [row[1] for row in data]

    fig, ax = plt.subplots(figsize=(5, 5))
    ax.pie(counts, labels=labels, autopct="%1.1f%%", startangle=140, colors=plt.cm.Paired.colors)
    ax.set_title("Anomaly Distribution")

    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode()

# === Generate Line Graph (Attack Trends) ===
def generate_line_chart():
    data = get_attack_trend()
    if not data:
        return None

    dates = [row[0] for row in data]
    attack_counts = [row[1] for row in data]

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.plot(dates, attack_counts, marker="o", linestyle="-", color="r", label="Attacks")
    ax.set_xlabel("Date")
    ax.set_ylabel("Number of Attacks")
    ax.set_title("Attack Trends Over Time")
    ax.legend()
    ax.grid()

    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode()

# === Flask Routes ===
@app.route("/")
def index():
    logs = get_logs()
    pie_chart = generate_pie_chart()
    line_chart = generate_line_chart()
    return render_template("dashboard.html", logs=logs, pie_chart=pie_chart, line_chart=line_chart)

@app.route("/refresh")
def refresh():
    return jsonify({"status": "success"})

if __name__ == "__main__":
    app.run(debug=True)
