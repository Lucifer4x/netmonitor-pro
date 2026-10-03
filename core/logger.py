"""
NetMonitor Pro - Telemetry & Event Store
Stores parsed packets, active network flows, threat alerts, and Wi-Fi security events.
"""

import time
import logging
import threading
from typing import List, Dict, Optional
from core.packet_parser import PacketInfo
from core.wifi_security import WifiSecurityInspector
from core.threat_detector import ThreatDetector
from core.flow_tracker import FlowTracker

logger = logging.getLogger("netmonitor.logger")

class TelemetryStore:
    """Thread-safe network telemetry and security event store."""

    def __init__(self, max_packets: int = 5000):
        self.max_packets = max_packets
        self._packets: List[PacketInfo] = []
        self._lock = threading.Lock()

        self.wifi_inspector = WifiSecurityInspector()
        self.threat_detector = ThreatDetector()
        self.flow_tracker = FlowTracker()

    def process_packet(self, pkt: PacketInfo) -> None:
        """Process a packet through all analytical modules."""
        with self._lock:
            self._packets.append(pkt)
            if len(self._packets) > self.max_packets:
                self._packets = self._packets[-self.max_packets:]

            # 1. Flow Tracking
            self.flow_tracker.update_flow(pkt)

            # 2. Threat Detection
            self.threat_detector.inspect_packet(pkt)

    def process_wifi_deauth(self, bssid: str, client: str, rate: float = 15.0) -> None:
        """Manually trigger/simulate 802.11 Deauth event for monitoring."""
        with self._lock:
            self.wifi_inspector.register_access_point(
                bssid=bssid,
                ssid="Corporate-Office-5G",
                channel=36,
                security_type="WPA2-Personal (Legacy)",
                mfp_required=False
            )
            for _ in range(12):
                self.wifi_inspector.inspect_80211_frame(
                    frame_type=0, frame_subtype=12,
                    bssid=bssid, client_mac=client, reason_code=7
                )

    def get_recent_packets(self, count: int = 50) -> List[dict]:
        """Get recent packets for dashboard display."""
        with self._lock:
            recent = list(reversed(self._packets[-count:]))
            return [
                {
                    "id": p.id,
                    "timestamp": time.strftime("%H:%M:%S", time.localtime(p.timestamp)) if p.timestamp > 0 else time.strftime("%H:%M:%S"),
                    "eth_src": p.eth_src,
                    "eth_dst": p.eth_dst,
                    "src_ip": p.src_ip or p.eth_src,
                    "dst_ip": p.dst_ip or p.eth_dst,
                    "protocol": p.protocol,
                    "frame_length": p.frame_length,
                    "info": p.info,
                }
                for p in recent
            ]

    def get_dashboard_summary(self) -> dict:
        """Get comprehensive dashboard statistics."""
        with self._lock:
            flow_summary = self.flow_tracker.get_telemetry_summary()
            threats = self.threat_detector.get_alerts()
            wifi_alerts = self.wifi_inspector.get_alerts()
            wifi_aps = self.wifi_inspector.get_ap_security_posture()

            return {
                "telemetry": flow_summary,
                "total_packets_stored": len(self._packets),
                "threat_alert_count": len(threats),
                "deauth_alert_count": len(wifi_alerts),
                "threats": threats[:10],
                "wifi_alerts": wifi_alerts[:10],
                "wifi_aps": wifi_aps,
            }
