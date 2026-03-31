# 🧙 Spellcastr
### Network Recon & Traffic Analysis Suite
**By WizardWerks Enterprise Labs**

---

Spellcastr is a full-stack cybersecurity tool that combines active **network scanning** with live **packet capture and traffic analysis** in a single, unified web dashboard. Built in Python using Flask, Scapy, and python-nmap.

![Python](https://img.shields.io/badge/Python-3.10+-ffd000?style=flat-square&logo=python&logoColor=black)
![Flask](https://img.shields.io/badge/Flask-3.0-ff8c00?style=flat-square&logo=flask&logoColor=black)
![Scapy](https://img.shields.io/badge/Scapy-2.5-29aacc?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Screenshots

![Scanner](Screenshots/screenshot-scanner.png)
*Network Scanner — host discovery with risk assessment*

![Packets](Screenshots/screenshot-packets.png)
*Packet Analyzer — live traffic capture and protocol breakdown*

![Alerts](Screenshots/screenshot-alert.png)
*Alert Center — unified threat findings and remediation*

## Features

### Scanner Module
- Discovers live hosts on a target IP or CIDR range
- Identifies open ports across a configurable range
- Fingerprints services and OS (Deep Audit mode)
- Flags high-risk ports (RDP, Telnet, SMB, FTP, etc.)
- Four scan profiles: Quick Sweep, Standard, Deep Audit, Stealth
- Generates per-host risk ratings (HIGH / MEDIUM / LOW)
- Provides remediation recommendations per finding

### Packet Analyzer Module
- Live packet capture on any network interface via Scapy
- Real-time protocol classification: TCP, UDP, DNS, ICMP, ARP
- Anomaly detection:
  - SYN flood detection (threshold-based)
  - Port scan detection (unique destination port tracking)
  - ARP spoofing detection (MAC/IP consistency checking)
  - Dangerous port connection alerts (Telnet, RDP, VNC, etc.)
- Live packet feed with protocol color coding
- Protocol distribution bar chart (live updating)
- Traffic volume sparkline (packets/second over last 20s)

### Alert Center
- Unified alert panel aggregating findings from both modules
- Severity classification: High / Medium / Low
- Timestamped source attribution (Scanner vs Packet Analyzer)
- Auto-generated remediation suggestions

---

## Tech Stack

| Layer     | Technology                          |
|-----------|-------------------------------------|
| Backend   | Python 3.10+, Flask 3.0             |
| Realtime  | Flask-SocketIO + eventlet           |
| Scanning  | python-nmap (wraps system nmap)     |
| Capture   | Scapy 2.5                           |
| Frontend  | Vanilla HTML/CSS/JS + Socket.IO CDN |
| Fonts     | Press Start 2P, Share Tech Mono     |

---

## Installation

### Prerequisites

**System dependencies:**
```bash
# Linux (Debian/Ubuntu)
sudo apt update && sudo apt install nmap python3 python3-pip

# macOS
brew install nmap python3

# Windows (limited support — Scapy has restrictions on Windows)
# Install Npcap from https://npcap.com before running
```

**Python dependencies:**
```bash
pip install -r requirements.txt
```

### Running Spellcastr

> ⚠️ **Root/Admin privileges are required for live packet capture.**
> The scanner also benefits from elevated privileges for OS detection.

```bash
# Linux / macOS
sudo python app.py

# Windows (run terminal as Administrator)
python app.py
```

Then open your browser to: **http://127.0.0.1:5000**

---

## Usage

### Running a Network Scan

1. Navigate to the **[ SCANNER ]** tab
2. Enter a target IP address or CIDR range (e.g. `192.168.1.0/24`)
3. Select a scan profile:
   - **Quick Sweep** — Ping sweep only, no port scanning
   - **Standard Scan** — Service detection on specified port range (default)
   - **Deep Audit** — OS fingerprinting + service version detection (slower)
   - **Stealth Mode** — SYN scan with reduced timing to avoid detection
4. Set a port range (default: `1-1024`)
5. Click **▶ RUN SCAN**

Results populate the host table with open ports, detected services, and risk ratings. High-risk findings are automatically forwarded to the Alert Center.

### Live Packet Capture

1. Navigate to the **[ PACKETS ]** tab
2. Select a network interface from the buttons (loaded from your system)
3. Click **▶ START CAPTURE**
4. Watch packets populate the live feed in real time
5. Protocol distribution and traffic volume charts update automatically
6. Click **■ STOP CAPTURE** to end the session

### Alert Center

The **[ ALERTS ]** tab aggregates all findings from both modules:
- **HIGH** — Critical risk ports open, active SYN floods, ARP spoofing, dangerous connections
- **MEDIUM** — Database ports exposed, multiple risky services
- **LOW** — Informational findings

Remediation suggestions are generated automatically based on scan findings.

---

## Project Structure

```
spellcastr/
├── app.py                  # Flask application & SocketIO event handlers
├── requirements.txt        # Python dependencies
├── README.md
├── templates/
│   └── index.html          # Single-page dashboard UI
├── static/
│   ├── css/                # (reserved for future extracted stylesheets)
│   └── js/                 # (reserved for future extracted scripts)
└── utils/
    ├── __init__.py
    ├── scanner.py          # Network scanning via python-nmap
    └── capture.py          # Live packet capture via Scapy
```

---

## Ethical & Legal Notice

> **This tool is intended for use on networks and systems you own or have explicit written permission to test.**

Unauthorized network scanning or packet capture is illegal in most jurisdictions and violates computer fraud laws including the Computer Fraud and Abuse Act (CFAA) in the United States and equivalent laws internationally.

This tool is built for:
- Home lab environments
- Networks you own and administer
- Authorized penetration testing engagements
- Educational and learning purposes

Always obtain proper authorization before scanning or capturing traffic on any network.

---

## Roadmap

- [ ] PDF/JSON scan report export
- [ ] Scan history saved to SQLite database
- [ ] Custom alert thresholds via settings panel
- [ ] CVE lookup via NVD API for detected service versions
- [ ] Docker container for portable deployment
- [ ] Dark/light theme toggle

---

## License

MIT License — see `LICENSE` for details.

---

*Built with 🧙 and Python by WizardWerks Enterprise Labs*
