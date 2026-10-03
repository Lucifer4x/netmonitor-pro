#!/usr/bin/env python3
"""
NetMonitor Pro - Network Traffic & Wireless Security Sensor
Main Entry Point
"""

import sys
import os
import time
import signal
import logging
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import SENSOR_HOST, SENSOR_PORT, SAMPLE_PCAP_FILE, MAX_STORED_PACKETS
from core.logger import TelemetryStore
from core.pcap_reader import PcapEngine
from dashboard.server import create_dashboard_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netmonitor.main")

BANNER = r"""
  _  _ _____ _____ __  __  ___  _  _ ___ _____ ___  ___   ___ ___  ___  
 | \| | __|_   _|  \/  |/ _ \| \| |_ _|_   _/ _ \| _ \ | _ \ _ \/ _ \ 
 | .` | _|  | | | |\/| | (_) | .` || |  | || (_) |   / |  _/   / (_) |
 |_|\_|___| |_| |_|  |_|\___/|_|\_|___| |_| \___/|_|_\ |_| |_|_\\___/ 
                                                                       
        >> Network Protocol & 802.11 Wireless Security Sensor <<
"""

def parse_args():
    parser = argparse.ArgumentParser(description="NetMonitor Pro - Network & Wireless Security Sensor")
    parser.add_argument("--host", default=SENSOR_HOST, help="Web dashboard host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=SENSOR_PORT, help="Web dashboard port (default: 9090)")
    parser.add_argument("--pcap", default=SAMPLE_PCAP_FILE, help="Path to PCAP file to load")
    return parser.parse_args()

def main():
    args = parse_args()
    print("\033[96m" + BANNER + "\033[0m")

    logger.info("Initializing NetMonitor Pro sensor engines...")
    telemetry_store = TelemetryStore(max_packets=MAX_STORED_PACKETS)
    pcap_engine = PcapEngine()

    # Load initial sample PCAP capture
    logger.info("Loading PCAP traffic capture: %s", args.pcap)
    packets = pcap_engine.read_pcap(args.pcap)
    for pkt in packets:
        telemetry_store.process_packet(pkt)

    # Background traffic playback loop (simulates continuous live capture)
    def traffic_playback_loop():
        idx = 0
        while True:
            time.sleep(1.0)
            if packets:
                pkt = packets[idx % len(packets)]
                pkt.timestamp = time.time()
                telemetry_store.process_packet(pkt)
                idx += 1

    playback_thread = threading.Thread(target=traffic_playback_loop, daemon=True)
    playback_thread.start()
    logger.info("Live packet replay engine active.")

    # Create & run dashboard
    app = create_dashboard_app(telemetry_store, pcap_engine)

    print("\n\033[92m==================================================================\033[0m")
    print(f"\033[92m [✔] SENSOR DASHBOARD ACTIVE : http://{args.host}:{args.port}\033[0m")
    print(f"\033[92m [✔] WIRELESS AUDIT ENGINE   : Active (802.11 Deauth & MFP Protection)\033[0m")
    print(f"\033[92m [✔] NETWORK THREAT SENSOR   : Active (ARP Spoofing, SYN Flood, Port Scan)\033[0m")
    print("\033[92m==================================================================\033[0m\n")

    def handle_signal(sig, frame):
        print("\nStopping NetMonitor Pro sensor...")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    log_werk = logging.getLogger('werkzeug')
    log_werk.setLevel(logging.WARNING)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
