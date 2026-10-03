# 📡 NetMonitor Pro — Network Protocol Analyzer & 802.11 Wireless Security Sensor

**NetMonitor Pro** is an enterprise-grade Network Protocol Analyzer and Wireless Security Sensor built in Python. Designed for network engineering interviews, threat hunting, and packet telemetry analysis, it provides real-time packet parsing, flow tracking, threat detection (ARP spoofing, SYN floods, port scans), and 802.11 Deauthentication attack detection.

---

## 🌟 Key Features

- 🌐 **Deep Packet Inspection (DPI)**: Pure-Python binary parser for Ethernet frames, IPv4, TCP (SYN/ACK/FIN flags), UDP, ICMP, ARP, and DNS.
- 📶 **Wi-Fi 802.11 Security Sensor & Deauth Detector**:
  - Detects 802.11 Deauthentication and Disassociation flooding attacks in real time.
  - Audits Access Point **802.11w Protected Management Frames (PMF / MFP)** posture.
  - Includes a live Deauth attack simulation engine for testing and demonstration.
- 🚨 **Network Threat & Anomaly Detector**:
  - **ARP Poisoning / Spoofing**: Detects IP-MAC binding conflicts (MITM detection).
  - **TCP SYN Flooding**: Tracks unacknowledged SYN floods (DoS detection).
  - **Port Scanning Reconnaissance**: Identifies rapid multi-port probes.
  - **DNS Tunneling**: Identifies high-entropy / long DNS exfiltration queries.
- 🔄 **Conversation & Flow Telemetry**: Tracks TCP/UDP flows, calculating throughput (bps), packet rate (pps), and bytes transferred per conversation.
- 📊 **Cyber Emerald Dashboard**: Dark visual dashboard rendering live protocol distributions, real-time packet feeds, and security alerts.

---

## 📁 Architecture

```
netmonitor-pro/
├── main.py                     # Main sensor entry point
├── config.py                   # Thresholds & configuration settings
├── requirements.txt            # Python dependencies
├── core/
│   ├── packet_parser.py        # Pure-Python Ethernet/IP/TCP/UDP/ICMP/ARP parser
│   ├── wifi_security.py        # 802.11 Deauth flood detector & MFP auditor
│   ├── threat_detector.py       # ARP spoofing, SYN flood, & port scan detector
│   ├── flow_tracker.py         # Network conversation & throughput metrics
│   ├── pcap_reader.py          # PCAP file reader & synthetic trace generator
│   └── logger.py               # Central telemetry store
├── dashboard/
│   ├── server.py               # Flask REST API server
│   ├── templates/              # HTML UI templates
│   └── static/                 # Cyber emerald CSS & Chart.js scripts
├── sample_data/
│   └── network_capture.pcap    # Pre-generated sample PCAP trace
└── tests/
    └── test_netmonitor.py      # Unit test suite
```

---

## ⚡ Quickstart

### 1. Install Requirements
```bash
cd netmonitor-pro
pip install -r requirements.txt
```

### 2. Launch the Sensor & Dashboard
```bash
python3 main.py
```
Open your browser to: **`http://127.0.0.1:9090`**

---

## 💡 How to Talk About This Project in Your Network Engineering Interview

When presenting **NetMonitor Pro** during your interview, highlight the following networking concepts:

1. **Protocol Stack & Binary Parsing**:
   > *"I built a custom packet parser in Python that decodes binary headers from raw Ethernet frames up to Application-layer DNS queries. It parses IHL, TCP flags (SYN, ACK, FIN), and ARP operation codes without external binary wrappers."*

2. **802.11 Wireless Security & Deauthentication Attacks**:
   > *"I implemented an 802.11 Wireless Security Inspector that detects Deauthentication frame floods. In my analysis, I explain how legacy 802.11 management frames are unauthenticated and why adopting 802.11w Protected Management Frames (PMF/MFP) or WPA3 is critical to prevent Wi-Fi disassociation attacks."*

3. **Layer 2 & Layer 4 Threat Analysis**:
   > *"The tool maintains an active IP-to-MAC state table to catch ARP poisoning attempts (Layer 2 MITM), while simultaneously tracking TCP SYN-to-ACK ratios to detect SYN flood DoS attacks (Layer 4)."*
