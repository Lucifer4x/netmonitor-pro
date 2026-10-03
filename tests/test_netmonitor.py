"""
Unit tests for NetMonitor Pro.
"""

import unittest
from core.packet_parser import PacketParser, PacketInfo
from core.wifi_security import WifiSecurityInspector
from core.threat_detector import ThreatDetector
from core.flow_tracker import FlowTracker

class TestNetMonitorCore(unittest.TestCase):
    def test_packet_parser_ethernet(self):
        parser = PacketParser()
        raw_eth = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x00"
        raw_ip = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x02\xc0\xa8\x01\x01"
        raw_tcp = b"\x1f\x90\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"

        parsed = parser.parse_raw_ethernet(raw_eth + raw_ip + raw_tcp)
        self.assertEqual(parsed.protocol, "TCP")
        self.assertEqual(parsed.src_ip, "192.168.1.2")
        self.assertEqual(parsed.dst_ip, "192.168.1.1")
        self.assertEqual(parsed.src_port, 8080)
        self.assertEqual(parsed.dst_port, 80)
        self.assertTrue(parsed.tcp_flags["SYN"])

    def test_deauth_flood_detector(self):
        inspector = WifiSecurityInspector(burst_threshold=5, window_seconds=5)
        emitted_alerts = []
        for i in range(6):
            alert = inspector.inspect_80211_frame(
                frame_type=0, frame_subtype=12,
                bssid="00:11:22:33:44:55", client_mac="AA:BB:CC:DD:EE:FF",
                timestamp=100.0 + (i * 0.1)
            )
            if alert:
                emitted_alerts.append(alert)

        self.assertTrue(len(emitted_alerts) >= 1)
        self.assertEqual(emitted_alerts[0].target_bssid, "00:11:22:33:44:55")
        self.assertEqual(emitted_alerts[0].frame_type, "Deauthentication")

    def test_arp_spoof_detector(self):
        detector = ThreatDetector()
        pkt1 = PacketInfo(protocol="ARP", arp_opcode=2, arp_src_ip="192.168.1.1", arp_src_mac="00:11:22:33:44:55", eth_dst="FF:FF:FF:FF:FF:FF")
        detector.inspect_packet(pkt1)

        pkt2 = PacketInfo(protocol="ARP", arp_opcode=2, arp_src_ip="192.168.1.1", arp_src_mac="AA:BB:CC:DD:EE:FF", eth_dst="FF:FF:FF:FF:FF:FF")
        alerts = detector.inspect_packet(pkt2)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].threat_type, "ARP Spoofing / Poisoning")

    def test_flow_tracker(self):
        tracker = FlowTracker()
        pkt = PacketInfo(protocol="TCP", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80, frame_length=100)
        tracker.update_flow(pkt)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["src_ip"], "10.0.0.1")
        self.assertEqual(flows[0]["packet_count"], 1)

if __name__ == "__main__":
    unittest.main()
