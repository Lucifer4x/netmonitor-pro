"""
NetMonitor Pro - Network Flow & Conversation Tracker
Tracks TCP/UDP conversations, bandwidth metrics, packet rates, and network performance.
"""

import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from core.packet_parser import PacketInfo

logger = logging.getLogger("netmonitor.flow")

@dataclass
class NetworkFlow:
    """Network flow/conversation record."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    last_time: float = 0.0
    tcp_syn_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0

    def duration_seconds(self) -> float:
        return max(0.1, self.last_time - self.start_time)

    def bytes_per_second(self) -> float:
        return self.total_bytes / self.duration_seconds()

    def packets_per_second(self) -> float:
        return self.packet_count / self.duration_seconds()

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "conversation": f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}",
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "formatted_bytes": self._format_bytes(self.total_bytes),
            "duration": f"{self.duration_seconds():.1f}s",
            "pps": round(self.packets_per_second(), 1),
            "bps": round(self.bytes_per_second() * 8, 1), # bits per second
            "last_active": time.strftime("%H:%M:%S", time.localtime(self.last_time))
        }

    @staticmethod
    def _format_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        else:
            return f"{b / (1024 * 1024):.1f} MB"

class FlowTracker:
    """Manages active network flow telemetry."""

    def __init__(self, max_flows: int = 1000):
        self.max_flows = max_flows
        self._flows: Dict[str, NetworkFlow] = {}
        self._start_time = time.time()
        self._total_packets = 0
        self._total_bytes = 0

    def update_flow(self, pkt: PacketInfo) -> NetworkFlow:
        """Update or create a network flow record from a packet."""
        self._total_packets += 1
        self._total_bytes += pkt.frame_length

        if pkt.protocol in ("ARP", "OTHER") or not pkt.src_ip:
            flow_key = f"LINK:{pkt.eth_src}->{pkt.eth_dst}:{pkt.protocol}"
            src_ip, dst_ip = pkt.eth_src, pkt.eth_dst
            src_port, dst_port = 0, 0
        else:
            flow_key = f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}:{pkt.protocol}"
            src_ip, dst_ip = pkt.src_ip, pkt.dst_ip
            src_port, dst_port = pkt.src_port, pkt.dst_port

        now = pkt.timestamp if pkt.timestamp > 0 else time.time()

        if flow_key in self._flows:
            flow = self._flows[flow_key]
            flow.packet_count += 1
            flow.total_bytes += pkt.frame_length
            flow.last_time = now
        else:
            flow = NetworkFlow(
                flow_id=flow_key,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=pkt.protocol,
                packet_count=1,
                total_bytes=pkt.frame_length,
                start_time=now,
                last_time=now
            )
            self._flows[flow_key] = flow

            # Prune if too large
            if len(self._flows) > self.max_flows:
                oldest_key = min(self._flows.keys(), key=lambda k: self._flows[k].last_time)
                del self._flows[oldest_key]

        if pkt.protocol == "TCP" and pkt.tcp_flags:
            if pkt.tcp_flags.get("SYN"): flow.tcp_syn_count += 1
            if pkt.tcp_flags.get("FIN"): flow.tcp_fin_count += 1
            if pkt.tcp_flags.get("RST"): flow.tcp_rst_count += 1

        return flow

    def get_flows(self) -> List[dict]:
        """Get all active flows ordered by activity."""
        sorted_flows = sorted(self._flows.values(), key=lambda f: f.last_time, reverse=True)
        return [f.to_dict() for f in sorted_flows]

    def get_telemetry_summary(self) -> dict:
        """Get global telemetry statistics."""
        uptime = time.time() - self._start_time
        pps = self._total_packets / max(1.0, uptime)
        bps = (self._total_bytes * 8) / max(1.0, uptime)

        protocol_dist = {}
        for flow in self._flows.values():
            protocol_dist[flow.protocol] = protocol_dist.get(flow.protocol, 0) + flow.packet_count

        return {
            "uptime_seconds": round(uptime, 1),
            "total_packets": self._total_packets,
            "total_bytes": self._total_bytes,
            "active_flows": len(self._flows),
            "packets_per_second": round(pps, 1),
            "bits_per_second": round(bps, 1),
            "protocol_distribution": protocol_dist
        }
