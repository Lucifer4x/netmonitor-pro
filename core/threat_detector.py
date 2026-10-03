"""
NetMonitor Pro - Network Threat & Anomaly Detector
Detects ARP Spoofing/Poisoning, TCP SYN Floods, Port Scans, and DNS Tunneling.
"""

import time
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
from core.packet_parser import PacketInfo

logger = logging.getLogger("netmonitor.threats")

@dataclass
class ThreatAlert:
    """Network threat alert model."""
    id: int
    timestamp: str
    threat_type: str         # ARP Poisoning, TCP SYN Flood, Port Scan, DNS Tunneling
    source_ip: str
    target_ip: str
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    evidence: str
    mitigation: str
    cwe: str

class ThreatDetector:
    """Detects network-layer security threats in real-time."""

    def __init__(self, arp_threshold: int = 3, syn_threshold: int = 50, port_scan_threshold: int = 15):
        self.arp_threshold = arp_threshold
        self.syn_threshold = syn_threshold
        self.port_scan_threshold = port_scan_threshold

        self._counter = 0
        self._alerts: List[ThreatAlert] = []

        # ARP IP -> MAC binding table & history
        self._arp_table: Dict[str, str] = {}
        self._arp_conflicts: Dict[str, List[str]] = {}

        # SYN Flood tracking: src_ip -> list of timestamps
        self._syn_tracker: Dict[str, List[float]] = {}

        # Port Scan tracking: src_ip -> set of (dst_ip, dst_port, timestamp)
        self._scan_tracker: Dict[str, List[Tuple[str, int, float]]] = {}

    def inspect_packet(self, pkt: PacketInfo) -> List[ThreatAlert]:
        """Inspect a parsed packet for network threats."""
        new_alerts = []

        # 1. ARP Poisoning / Spoofing Check
        if pkt.protocol == "ARP":
            arp_alert = self._check_arp_spoofing(pkt)
            if arp_alert:
                new_alerts.append(arp_alert)

        # 2. TCP SYN Flood Check
        if pkt.protocol == "TCP" and pkt.tcp_flags.get("SYN") and not pkt.tcp_flags.get("ACK"):
            syn_alert = self._check_syn_flood(pkt)
            if syn_alert:
                new_alerts.append(syn_alert)

        # 3. Port Scan Check
        if pkt.protocol in ("TCP", "UDP") and pkt.dst_port > 0:
            scan_alert = self._check_port_scan(pkt)
            if scan_alert:
                new_alerts.append(scan_alert)

        # 4. DNS Tunneling Check
        if pkt.protocol == "DNS" and len(pkt.info) > 60:
            dns_alert = self._check_dns_tunneling(pkt)
            if dns_alert:
                new_alerts.append(dns_alert)

        return new_alerts

    def _check_arp_spoofing(self, pkt: PacketInfo) -> Optional[ThreatAlert]:
        if pkt.arp_opcode != 2:  # Only check ARP Replies
            return None

        ip = pkt.arp_src_ip
        mac = pkt.arp_src_mac

        if not ip or not mac or ip == "0.0.0.0":
            return None

        if ip in self._arp_table:
            known_mac = self._arp_table[ip]
            if known_mac.lower() != mac.lower():
                self._counter += 1
                alert = ThreatAlert(
                    id=self._counter,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    threat_type="ARP Spoofing / Poisoning",
                    source_ip=ip,
                    target_ip=pkt.eth_dst,
                    severity="CRITICAL",
                    description=f"IP {ip} MAC binding changed unexpectedly from {known_mac} to {mac}. Potential Man-in-the-Middle (MITM) ARP poisoning attack.",
                    evidence=f"Original MAC: {known_mac} | Claimed MAC: {mac}",
                    mitigation="Enable Dynamic ARP Inspection (DAI) on switch ports and configure static ARP entries for critical gateways.",
                    cwe="CWE-300 (Channel Accessible by Non-Endpoint)"
                )
                self._alerts.append(alert)
                logger.warning("ARP SPOOFING DETECTED: IP %s changed MAC from %s to %s", ip, known_mac, mac)
                return alert
        else:
            self._arp_table[ip] = mac
        return None

    def _check_syn_flood(self, pkt: PacketInfo) -> Optional[ThreatAlert]:
        now = time.time()
        src = pkt.src_ip

        if not src:
            return None

        if src not in self._syn_tracker:
            self._syn_tracker[src] = []

        self._syn_tracker[src].append(now)
        self._syn_tracker[src] = [t for t in self._syn_tracker[src] if now - t <= 5.0]

        if len(self._syn_tracker[src]) >= self.syn_threshold:
            # Avoid duplicate alert within 10s
            if not self._alerts or (now - time.mktime(time.strptime(self._alerts[-1].timestamp, "%Y-%m-%d %H:%M:%S")) > 10):
                self._counter += 1
                alert = ThreatAlert(
                    id=self._counter,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    threat_type="TCP SYN Flood (DoS)",
                    source_ip=src,
                    target_ip=pkt.dst_ip,
                    severity="HIGH",
                    description=f"High rate of unacknowledged TCP SYN packets ({len(self._syn_tracker[src])} SYNs / 5s) originating from {src}.",
                    evidence=f"SYN Packet Rate: {len(self._syn_tracker[src])} SYNs/5sec to target {pkt.dst_ip}",
                    mitigation="Enable SYN Cookies (tcp_syncookies) on target hosts and rate-limit TCP SYN connections at firewall.",
                    cwe="CWE-400 (Uncontrolled Resource Consumption)"
                )
                self._alerts.append(alert)
                return alert
        return None

    def _check_port_scan(self, pkt: PacketInfo) -> Optional[ThreatAlert]:
        now = time.time()
        src = pkt.src_ip
        dst = pkt.dst_ip
        port = pkt.dst_port

        if not src or not dst or port == 0:
            return None

        if src not in self._scan_tracker:
            self._scan_tracker[src] = []

        self._scan_tracker[src].append((dst, port, now))
        self._scan_tracker[src] = [item for item in self._scan_tracker[src] if now - item[2] <= 10.0]

        unique_ports = {item[1] for item in self._scan_tracker[src]}
        if len(unique_ports) >= self.port_scan_threshold:
            if not self._alerts or (now - time.mktime(time.strptime(self._alerts[-1].timestamp, "%Y-%m-%d %H:%M:%S")) > 15):
                self._counter += 1
                alert = ThreatAlert(
                    id=self._counter,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    threat_type="Port Scanning Reconnaissance",
                    source_ip=src,
                    target_ip=dst,
                    severity="MEDIUM",
                    description=f"Host {src} probed {len(unique_ports)} distinct ports on target network within 10 seconds.",
                    evidence=f"Unique ports targeted: {sorted(list(unique_ports))[:10]}...",
                    mitigation="Block port scanner IP at perimeter firewall and inspect host for reconnaissance tools (e.g., Nmap/Masscan).",
                    cwe="CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"
                )
                self._alerts.append(alert)
                return alert
        return None

    def _check_dns_tunneling(self, pkt: PacketInfo) -> Optional[ThreatAlert]:
        self._counter += 1
        alert = ThreatAlert(
            id=self._counter,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            threat_type="DNS Tunneling / Data Exfiltration",
            source_ip=pkt.src_ip or "Local Device",
            target_ip=pkt.dst_ip or "DNS Resolver",
            severity="HIGH",
            description=f"Abnormally long DNS query detected ({len(pkt.info)} chars). High entropy query indicates possible DNS data exfiltration or C2 tunnel.",
            evidence=f"DNS Query: {pkt.info[:80]}...",
            mitigation="Enforce DNS Sinkholing, inspect recursive DNS query lengths, and block unauthorized external DNS resolvers.",
            cwe="CWE-200 (Information Exposure Through DNS Queries)"
        )
        self._alerts.append(alert)
        return alert

    def get_alerts(self) -> List[dict]:
        """Get all threat alerts."""
        return [asdict(a) for a in reversed(self._alerts)]
