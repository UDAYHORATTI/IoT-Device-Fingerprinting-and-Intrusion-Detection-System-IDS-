# IoT-Device-Fingerprinting-and-Intrusion-Detection-System-IDS-
The IoT Device Fingerprinting and Intrusion Detection System (IDS) aims to identify and monitor IoT devices in a network by fingerprinting their unique characteristics (e.g., MAC addresses, device behavior, traffic patterns) and detecting any unusual or potentially malicious behavior.
from scapy.all import sniff
import sqlite3
from datetime import datetime
from sklearn.ensemble import IsolationForest
import smtplib
from email.mime.text import MIMEText
from flask import Flask, render_template, request
import threading

# Flask app for real-time monitoring
app = Flask(__name__)

# Initialize an Isolation Forest model for anomaly detection
model = IsolationForest()

# SQLite database setup for logging
def init_db():
    conn = sqlite3.connect('iot_ids.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS device_logs (id INTEGER PRIMARY KEY, device_mac TEXT, timestamp TEXT, event TEXT)''')
    conn.commit()
    conn.close()

# Function to send email alerts
def send_alert(message):
    msg = MIMEText(message)
    msg['Subject'] = 'IoT Intrusion Alert'
    msg['From'] = 'your-email@example.com'
    msg['To'] = 'admin-email@example.com'

    with smtplib.SMTP('smtp.example.com') as server:
        server.login('your-email@example.com', 'your-password')
        server.sendmail(msg['From'], msg['To'], msg.as_string())

# Device fingerprinting and network traffic capture
def capture_traffic(packet):
    if packet.haslayer('Ether'):
        device_mac = packet[Ether].src
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Log the device activity
        conn = sqlite3.connect('iot_ids.db')
        c = conn.cursor()
        c.execute("INSERT INTO device_logs (device_mac, timestamp, event) VALUES (?, ?, ?)", (device_mac, timestamp, 'Device activity detected'))
        conn.commit()
        conn.close()

        # Detect anomaly using Isolation Forest
        features = [len(packet), packet.time]  # Example features (packet size and timestamp)
        anomaly = model.predict([features])

        if anomaly == -1:
            send_alert(f"Suspicious activity detected from MAC address: {device_mac}")

# Function to start packet sniffing
def start_sniffing():
    sniff(prn=capture_traffic, store=0, timeout=60)  # Sniff for 60 seconds

# Web interface route to show logs and alerts
@app.route('/')
def index():
    conn = sqlite3.connect('iot_ids.db')
    c = conn.cursor()
    c.execute("SELECT * FROM device_logs")
    logs = c.fetchall()
    conn.close()
    return render_template('index.html', logs=logs)

# Run Flask app for monitoring interface
if __name__ == "__main__":
    init_db()

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()

    app.run(debug=True)
