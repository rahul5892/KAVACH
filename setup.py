from setuptools import setup, find_packages

setup(
    name="KAVACH",
    version="1.0.0",
    author="Sidharth Kapurkar",
    author_email="sidharth.kapurkar@gmail.com",
    description="AI-powered Cyber Threat Detection system with real-time SQL Injection & Network Anomaly Detection.",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "tensorflow", "numpy", "pandas", "scapy", "sqlite3", "streamlit", "firebase-admin"
    ],
    entry_points={
        "console_scripts": [
            "start_detection=scripts.start_detection:start_sniffing",
            "start_dashboard=scripts.start_dashboard:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows"
    ],
    python_requires=">=3.8",
)
