"""
NetMonitor Pro - Configuration Settings
Network & Wireless Security Sensor
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Network Sensor Settings
SENSOR_HOST = "0.0.0.0"
SENSOR_PORT = 9090
DEFAULT_INTERFACE = "eth0"

# Wireless & Deauth Security Thresholds
DEAUTH_BURST_THRESHOLD = 10      # Deauth frames per second triggering attack alarm
DEAUTH_WINDOW_SECONDS = 5        # Time window for deauth rate calculation
ROGUE_AP_SIGNAL_DELTA = 25       # Signal strength delta for rogue AP detection
SUPPORT_80211W_MFP = True        # 802.11w Management Frame Protection check

# Threat Detection Thresholds
ARP_POISON_THRESHOLD = 3         # Duplicate IP-MAC mappings triggering ARP spoof alarm
SYN_FLOOD_THRESHOLD = 50         # SYN packets without ACK threshold
PORT_SCAN_PORT_COUNT = 15        # Unique ports scanned within 10 seconds

# Data Persistence & Sample Capture
SAMPLE_DATA_DIR = os.path.join(BASE_DIR, "sample_data")
SAMPLE_PCAP_FILE = os.path.join(SAMPLE_DATA_DIR, "network_capture.pcap")

# Dashboard UI Settings
DASHBOARD_REFRESH_RATE_MS = 2000
MAX_STORED_PACKETS = 5000
MAX_STORED_FLOWS = 1000
