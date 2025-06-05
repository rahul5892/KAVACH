import argparse
import os

def main():
    parser = argparse.ArgumentParser(description="KAVACH - AI-powered Cyber Threat Detection")
    parser.add_argument("--detect", action="store_true", help="Start real-time threat detection")
    parser.add_argument("--dashboard", action="store_true", help="Start the Streamlit dashboard")
    args = parser.parse_args()

    if args.detect:
        print("🚀 Starting real-time threat detection...")
        os.system("python scripts/start_detection.py")
    elif args.dashboard:
        print("📊 Launching the dashboard...")
        os.system("python scripts/start_dashboard.py")
    else:
        print("❌ No valid option provided. Use --detect or --dashboard.")

if __name__ == "__main__":
    main()
