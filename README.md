# KAVACH 🔐

**KAVACH** is an AI-powered Cyber Threat Detection System designed to monitor, detect, and respond to malicious network activity in real-time. It features a live dashboard for visualizing threats and insights powered by machine learning models.

## 🚀 Features

- Real-time threat detection using AI
- Streamlit-based interactive dashboard
- Modular script-based architecture
- Easily extendable and customizable

## 🧠 How it Works

The system uses pre-trained models to analyze network data and identify patterns consistent with various cyber-attacks. Alerts and metrics are displayed on a user-friendly dashboard for quick response and monitoring.

## 📁 Project Structure

```
kavach/
├── index.html                 # Frontend UI (if applicable)
├── run_app.py                # Main CLI to run detection or dashboard
├── requirements.txt          # Python dependencies
├── setup.py                  # Setup configuration
├── scripts/
│   ├── start_detection.py    # Script to begin real-time threat detection
│   └── start_dashboard.py    # Script to launch the dashboard
```

## 🛠️ Installation

```bash
git clone https://github.com/sidhu1310/kavach.git
cd kavach
pip install -r requirements.txt
```

## ⚙️ Usage

Run the real-time threat detection system:

```bash
python run_app.py --detect
```

Launch the Streamlit dashboard:

```bash
python run_app.py --dashboard
```

## 📊 Dashboard

The dashboard provides:
- Live packet inspection
- Threat classification
- IP and Geo tracking
- Attack descriptions

## 🤖 AI & Detection

The detection system likely uses models trained on datasets like KDD Cup or NSL-KDD to classify traffic and detect intrusions.

## 🧪 Requirements

- Python 3.7+
- Streamlit
- Scapy (for packet sniffing)
- Other ML/DS libraries listed in `requirements.txt`

## 🧑‍💻 Contributing

Pull requests are welcome! If you find a bug or have a feature request, open an issue.

## 📄 License

MIT License. See `LICENSE` for more details.
