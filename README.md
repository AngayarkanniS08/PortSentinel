Port Sentinel 🚀

Port Sentinel is a real-time network security monitor and active Intrusion Prevention System (IPS). It captures live network traffic to detect and automatically block suspicious activities—such as SYN scans, UDP scans, and Ping Sweeps—ensuring your infrastructure stays protected.
✨ Key Features

    Live Packet Sniffing: Captures and analyzes raw packets to monitor protocol-wise traffic in real-time.

    Rule-based Detection: Uses advanced thresholds to identify SYN scans, UDP scans, and ICMP ping sweeps.

    Active Prevention (Firewall): Integrated with iptables to automatically block IP addresses associated with high-severity threats in real-time.

    Interactive Dashboard: A web-based UI for monitoring real-time traffic updates, system health, and detailed alert logs.

    Threat Intelligence: Leverages the AbuseIPDB API to verify the reputation of external IP addresses and adjust severity levels.

🛠️ Tech Stack

    Backend: Python (Flask, Flask-SocketIO)

    Traffic Analysis: Dpkt

    Database: SQLAlchemy with SQLite for logging detections and user management

    Firewall Management: Linux iptables

    Deployment: Docker and Docker Compose

🚀 Getting Started
Prerequisites

    Linux OS: Required for full packet sniffing and iptables firewall control.

    Permissions: You must run the application with sudo or as a privileged container.

    Docker: Installed Docker and Docker Compose.

Installation & Setup

    Clone the Repository:
    Bash

git clone https://github.com/AngayarkanniS08/PortSentinel.git
cd PortSentinel

Configure Environment: Add your AbuseIPDB API key in core/engine.py to enable threat intelligence.

Run with Docker Compose:
Bash

    docker-compose up --build

    Note: The container uses network_mode: host and privileged: true to access your real network interface and manage the firewall.

    Access the Dashboard: Open http://localhost:5000 in your web browser.

🔮 Roadmap & Future Scope

    ML-Powered Prevention: Integration of unsupervised Machine Learning models (like Isolation Forest) to detect and prevent zero-day anomalies.

    Predictive Analytics: Implementing AI modules to analyze historical data and block potential threats before they escalate.

    Enhanced Alerting: Adding support for email notifications and detailed security reports.

🤝 Contributing

Contributions are welcome! If you have suggestions for new detection rules or prevention logic, please fork the repository and submit a pull request.
📄 License

This project is open-source. Please refer to the LICENSE file for details.