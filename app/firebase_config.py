import firebase_admin
from firebase_admin import credentials, firestore
import os

# Load Firebase credentials
firebase_config_path = os.path.join(os.path.dirname(__file__), "../config/firebase_config.json")

if not os.path.exists(firebase_config_path):
    raise FileNotFoundError("❌ Firebase config file missing: config/firebase_config.json")

cred = credentials.Certificate(firebase_config_path)
firebase_admin.initialize_app(cred)

# Firestore database reference
db = firestore.client()
